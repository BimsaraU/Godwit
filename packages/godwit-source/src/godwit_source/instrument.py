"""An object-store client that counts what it read, and what kind of thing it was.

DATA PLANE. Exists so "the metadata tier scans zero bytes of table data" is a test
assertion rather than a claim in a slide. Wrap whatever fetches bytes, run the metadata
path, then assert :meth:`IoLedger.data_bytes` is zero.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

__all__ = ["InstrumentedObjectStore", "IoLedger", "ObjectKind", "classify_path"]

_DATA_SUFFIXES = (".parquet", ".orc")
_METADATA_SUFFIXES = (".avro", ".json", ".puffin", ".stats", ".gz.metadata.json")


class ObjectKind(StrEnum):
    """What a byte range was. ``DATA`` bytes are rows; ``METADATA`` bytes are not."""

    DATA = "data"
    METADATA = "metadata"
    UNKNOWN = "unknown"


def classify_path(path: str) -> ObjectKind:
    """Classify by suffix first, then by Iceberg's directory convention.

    ``UNKNOWN`` is treated as data by :class:`IoLedger`, because an unrecognised object in
    a table's storage is far more likely to be rows than to be free metadata, and the
    conservative direction here is the one that fails a test rather than the one that
    quietly passes it.
    """
    lowered = path.lower().split("?", 1)[0]
    if lowered.endswith(_DATA_SUFFIXES):
        return ObjectKind.DATA
    if lowered.endswith(_METADATA_SUFFIXES):
        return ObjectKind.METADATA
    if "/metadata/" in lowered:
        return ObjectKind.METADATA
    if "/data/" in lowered:
        return ObjectKind.DATA
    return ObjectKind.UNKNOWN


@dataclass(slots=True)
class IoLedger:
    """Running totals per object kind, plus the read log for a failure message."""

    metadata_bytes: int = 0
    data_bytes: int = 0
    unknown_bytes: int = 0
    reads: list[tuple[str, ObjectKind, int]] = field(default_factory=list)

    def record(self, path: str, size: int) -> None:
        kind = classify_path(path)
        self.reads.append((path, kind, size))
        if kind is ObjectKind.DATA:
            self.data_bytes += size
        elif kind is ObjectKind.METADATA:
            self.metadata_bytes += size
        else:
            self.unknown_bytes += size

    @property
    def billable_bytes(self) -> int:
        """Data plus unknown. Unknown counts against you until it is classified."""
        return self.data_bytes + self.unknown_bytes

    def assert_no_data_bytes(self) -> None:
        if self.billable_bytes:
            offenders = [p for p, k, _ in self.reads if k is not ObjectKind.METADATA]
            raise AssertionError(
                f"metadata path read {self.billable_bytes} non-metadata bytes from {offenders}"
            )


class InstrumentedObjectStore:
    """Wraps a ``get(path) -> bytes`` callable and books every read against a ledger."""

    def __init__(self, get: Callable[[str], bytes], ledger: IoLedger | None = None) -> None:
        self._get = get
        self.ledger = ledger if ledger is not None else IoLedger()

    def get(self, path: str) -> bytes:
        payload = self._get(path)
        self.ledger.record(path, len(payload))
        return payload

    def get_many(self, paths: Sequence[str]) -> list[bytes]:
        return [self.get(p) for p in paths]
