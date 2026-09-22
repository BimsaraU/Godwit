"""An instrumented object-store client. Data plane.

Two jobs, both load-bearing.

**Proof.** The free metadata tier is only free if it really does not touch table data.
"We did not mean to scan" is not evidence. :class:`ByteMeter` counts every byte that
crosses the object store, split into metadata and data, so a test can assert
``meter.data_bytes == 0`` after a full L-1 pass and mean it.

**Budget.** Invariant 6 says a path that can spend must refuse rather than overspend.
Bytes read are the spend, and this is where they are counted. An adapter checks its
estimate against the budget *before* opening anything, then reconciles against the
meter afterwards.

Classification is by file extension, and anything unrecognised counts as **data**.
Deny by default applies to accounting too: an unclassified read must not be free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import TracebackType
from typing import Final

from pyiceberg.io import FileIO, InputFile, InputStream, OutputFile

__all__ = ["ByteMeter", "MeteredFileIO", "ReadClass", "classify_location"]


class ReadClass(StrEnum):
    """What kind of file a read touched."""

    METADATA = "metadata"
    """Manifests, manifest lists, table metadata, Puffin statistics. The free tier."""

    DATA = "data"
    """Parquet, ORC, and anything we could not identify. The tier that costs money."""


_METADATA_SUFFIXES: Final[tuple[str, ...]] = (".avro", ".json", ".puffin", ".stats")
_DATA_SUFFIXES: Final[tuple[str, ...]] = (".parquet", ".orc")


def classify_location(location: str) -> ReadClass:
    """Classify one object-store location.

    Unknown extensions are ``DATA``. A new file type that turns out to be metadata is a
    conservative over-count, which shows up as a budget refusal; the other way round is
    a silent scan that the acceptance test would have caught and now does not.
    """
    lowered = location.lower().split("?", 1)[0]
    if lowered.endswith(_DATA_SUFFIXES):
        return ReadClass.DATA
    if lowered.endswith(_METADATA_SUFFIXES):
        return ReadClass.METADATA
    return ReadClass.DATA


@dataclass(slots=True)
class ByteMeter:
    """Running totals for one unit of work.

    Mutable on purpose, and therefore not a contract model: it is an instrument, not a
    fact about the world. Hand a fresh one to each adapter call you want to measure.
    """

    metadata_bytes: int = 0
    data_bytes: int = 0
    metadata_reads: int = 0
    data_reads: int = 0
    locations: list[str] = field(default_factory=list)
    """Every location opened, in order. Object-store paths, not customer values --
    but a path can contain a table name, so this is SCHEMA_NAME-class information and
    belongs in a test or a data-plane log, never in an alert."""

    def record_open(self, location: str) -> None:
        """Note that a location was opened, before any bytes moved."""
        self.locations.append(location)
        if classify_location(location) is ReadClass.DATA:
            self.data_reads += 1
        else:
            self.metadata_reads += 1

    def record_bytes(self, location: str, count: int) -> None:
        """Add ``count`` bytes to the right tier."""
        if count <= 0:
            return
        if classify_location(location) is ReadClass.DATA:
            self.data_bytes += count
        else:
            self.metadata_bytes += count

    @property
    def total_bytes(self) -> int:
        """Every byte read, both tiers."""
        return self.metadata_bytes + self.data_bytes


class _MeteredStream:
    """Wraps an input stream and charges every byte it yields to a meter."""

    def __init__(self, inner: InputStream, *, location: str, meter: ByteMeter) -> None:
        self._inner = inner
        self._location = location
        self._meter = meter

    def read(self, size: int = 0) -> bytes:
        """Read and charge.

        ``size <= 0`` means "the rest of the file" -- that is pyiceberg's convention,
        and its Avro reader relies on it by calling ``f.read()`` with no argument. A
        wrapper that forwarded a literal zero would hand back an empty buffer and the
        manifest would fail to parse a byte in.
        """
        chunk = self._inner.read() if size <= 0 else self._inner.read(size)
        self._meter.record_bytes(self._location, len(chunk))
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek. Seeking moves no bytes and costs nothing."""
        return self._inner.seek(offset, whence)

    def tell(self) -> int:
        """Current position."""
        return self._inner.tell()

    def close(self) -> None:
        """Close the underlying stream."""
        self._inner.close()

    def readable(self) -> bool:
        """Always true. pyarrow asks before it reads."""
        return True

    def seekable(self) -> bool:
        """Always true. pyarrow needs a seekable stream for Parquet footers."""
        return True

    @property
    def closed(self) -> bool:
        """Whether the underlying stream is closed. pyarrow checks this."""
        return bool(getattr(self._inner, "closed", False))

    def __enter__(self) -> _MeteredStream:
        """Enter the underlying stream's scope."""
        return self

    def __exit__(
        self,
        exctype: type[BaseException] | None,
        excinst: BaseException | None,
        exctb: TracebackType | None,
    ) -> None:
        """Leave the scope, closing the underlying stream."""
        self._inner.__exit__(exctype, excinst, exctb)


class _MeteredInputFile(InputFile):
    """An ``InputFile`` whose streams are metered."""

    def __init__(self, inner: InputFile, meter: ByteMeter) -> None:
        super().__init__(inner.location)
        self._inner = inner
        self._meter = meter

    def __len__(self) -> int:
        """Size of the underlying file in bytes."""
        return len(self._inner)

    def exists(self) -> bool:
        """Whether the underlying file exists."""
        return self._inner.exists()

    def open(self, seekable: bool = True) -> InputStream:
        """Open the underlying file and meter what comes out of it."""
        self._meter.record_open(self.location)
        return _MeteredStream(
            self._inner.open(seekable=seekable), location=self.location, meter=self._meter
        )


class MeteredFileIO(FileIO):
    """A ``FileIO`` that counts what it reads.

    Wrap a table's own ``FileIO`` with one of these and pass it wherever pyiceberg wants
    an ``io``. Reads are counted; writes are passed straight through, because writing a
    Puffin file is not a scan and charging it to the scan budget would be wrong.
    """

    def __init__(self, inner: FileIO, meter: ByteMeter | None = None) -> None:
        super().__init__(inner.properties)
        self._inner = inner
        self.meter = meter if meter is not None else ByteMeter()

    def new_input(self, location: str) -> InputFile:
        """A metered input file."""
        return _MeteredInputFile(self._inner.new_input(location), self.meter)

    def new_output(self, location: str) -> OutputFile:
        """An unmetered output file. Writes are not scans."""
        return self._inner.new_output(location)

    def delete(self, location: str | InputFile | OutputFile) -> None:
        """Delete through to the wrapped IO."""
        self._inner.delete(location)
