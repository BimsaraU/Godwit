"""What the executor needs from a table, and the Iceberg implementation of it.

DATA PLANE. The split in :class:`ProbeSource` is the economic contract of this package:

* ``resolve_snapshot``, ``snapshot_chain``, ``delta`` and ``column_types`` are
  **metadata**. They read a catalog and manifests, never a data file. Polling them every
  minute is cheap and correct -- that is how streaming works here.
* ``read`` is the only method that touches table data, and it is only ever called after
  the plan has been checked against the access modes and the cost estimate against the
  budget. It reads the named columns and no others.

``bytes_read`` is an instrument, not an estimate: the Iceberg implementation routes every
data-file read through ``godwit_source.MeteredFileIO``, and the simulator counts the
bytes it generates. "Refusal happens before any bytes are read" is asserted against it.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

import pyarrow as pa
import pyarrow.parquet as pq
from godwit_contracts.common import Instant, SnapshotId
from godwit_contracts.source import LogicalType, SnapshotRef, SourceRef
from godwit_source import ByteMeter, IcebergAdapter, MeteredFileIO
from pyiceberg.catalog import Catalog
from pyiceberg.manifest import ManifestContent, ManifestEntryStatus
from pyiceberg.table import Table
from pyiceberg.table.snapshots import Operation

__all__ = [
    "DataFileRef",
    "Delta",
    "DeltaKind",
    "IcebergProbeSource",
    "ProbeSource",
    "logical_type_of",
]


_PARQUET_MAGIC: Final[bytes] = b"PAR1"
_PARQUET_TAIL: Final[int] = 8
"""A Parquet file ends with a four-byte footer length and the four-byte magic."""


class DeltaKind(StrEnum):
    """What happened to a table between two snapshots, from a sketch's point of view."""

    ADDITIVE = "additive"
    """Only appends. Sketching the added files and merging is exactly a full re-probe."""

    NO_LOGICAL_CHANGE = "no_logical_change"
    """Same snapshot, or only rewrites (compaction). No row was added or removed."""

    NON_ADDITIVE = "non_additive"
    """Rows were deleted or overwritten. A delta cannot un-count them: re-probe in full."""


@dataclass(frozen=True, slots=True)
class DataFileRef:
    """One data file a probe may read. **Data plane**: ``location`` can name a table."""

    location: str
    size_bytes: int
    record_count: int
    column_bytes: Mapping[str, int] = field(default_factory=dict)
    """Compressed bytes per column, keyed by column name, when the manifest records them."""

    def estimated_bytes(self, columns: Sequence[str]) -> int:
        """Upper bound on the bytes a projected read of this file moves.

        The projected columns' chunks plus everything in the file that is not a column
        chunk (footer, page indexes). Without per-column sizes, the whole file.
        """
        if not self.column_bytes:
            return self.size_bytes
        overhead = max(0, self.size_bytes - sum(self.column_bytes.values()))
        projected = sum(self.column_bytes.get(name, self.size_bytes) for name in set(columns))
        return min(self.size_bytes, overhead + projected)


@dataclass(frozen=True, slots=True)
class Delta:
    """The files a probe over ``(since, until]`` must read."""

    since: SnapshotId | None
    until: SnapshotRef
    kind: DeltaKind
    files: tuple[DataFileRef, ...]

    @property
    def record_count(self) -> int:
        """Rows in the delta, from manifests. A derived statistic about the data."""
        return sum(item.record_count for item in self.files)


@runtime_checkable
class ProbeSource(Protocol):
    """The table-facing half of the executor. See the module docstring for the split."""

    @property
    def bytes_read(self) -> int:
        """Bytes of table data read so far by this instance. Metadata is not counted."""
        ...

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        """The snapshot current at ``at``, or the newest. Metadata only."""
        ...

    def snapshot_chain(
        self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotId
    ) -> tuple[SnapshotRef, ...]:
        """Snapshots in ``(since, until]``, oldest first. Metadata only."""
        ...

    def delta(self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotRef) -> Delta:
        """The files added in ``(since, until]`` and what kind of change it was."""
        ...

    def column_types(self, source: SourceRef, snapshot: SnapshotRef) -> Mapping[str, LogicalType]:
        """Every column's logical type at ``snapshot``. **Data plane**: plain names."""
        ...

    def read(
        self, source: SourceRef, data_file: DataFileRef, *, columns: Sequence[str], batch_rows: int
    ) -> Iterator[pa.RecordBatch]:
        """Stream the named columns of one file. The only data read in the package."""
        ...


def logical_type_of(arrow_type: pa.DataType) -> LogicalType:
    """Map an Arrow type onto the contracts' source-neutral vocabulary."""
    checks: tuple[tuple[bool, LogicalType], ...] = (
        (pa.types.is_boolean(arrow_type), LogicalType.BOOL),
        (pa.types.is_integer(arrow_type), LogicalType.INT),
        (pa.types.is_floating(arrow_type), LogicalType.FLOAT),
        (pa.types.is_decimal(arrow_type), LogicalType.DECIMAL),
        (pa.types.is_date(arrow_type), LogicalType.DATE),
        (pa.types.is_timestamp(arrow_type), LogicalType.TIMESTAMP),
        (pa.types.is_string(arrow_type), LogicalType.STRING),
        (pa.types.is_large_string(arrow_type), LogicalType.STRING),
        (pa.types.is_binary(arrow_type), LogicalType.BINARY),
        (pa.types.is_large_binary(arrow_type), LogicalType.BINARY),
        (pa.types.is_struct(arrow_type), LogicalType.STRUCT),
        (pa.types.is_list(arrow_type) or pa.types.is_large_list(arrow_type), LogicalType.LIST),
        (pa.types.is_map(arrow_type), LogicalType.MAP),
    )
    return next((logical for matched, logical in checks if matched), LogicalType.UNKNOWN)


class IcebergProbeSource:
    """:class:`ProbeSource` over an Iceberg catalog.

    Snapshot resolution and history come from ``godwit_source.IcebergAdapter``. Manifests
    are walked here because the adapter keeps its file listing private, and because a
    probe needs two things the adapter's listing does not give: the snapshot that added
    each file (for deltas) and per-column sizes (for an estimate tighter than whole
    files). Every read -- manifests and data -- goes through ``MeteredFileIO``;
    ``bytes_read`` reports the data half.
    """

    def __init__(self, catalog: Catalog, *, meter: ByteMeter | None = None) -> None:
        self._catalog = catalog
        self.meter = meter if meter is not None else ByteMeter()
        self._adapter = IcebergAdapter(catalog, meter=self.meter)
        self._tables: dict[tuple[str, str], Table] = {}

    @property
    def bytes_read(self) -> int:
        """Data-file bytes moved through the meter."""
        return self.meter.data_bytes

    def _table(self, source: SourceRef) -> Table:
        identifier = (source.namespace.reveal(), source.table.reveal())
        table = self._catalog.load_table(identifier)
        table.io = MeteredFileIO(table.io, self.meter)
        self._tables[identifier] = table
        return table

    def _cached(self, source: SourceRef) -> Table:
        identifier = (source.namespace.reveal(), source.table.reveal())
        cached = self._tables.get(identifier)
        return cached if cached is not None else self._table(source)

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        """Delegates to the adapter. One catalog read."""
        return self._adapter.resolve_snapshot(source, at=at)

    def snapshot_chain(
        self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotId
    ) -> tuple[SnapshotRef, ...]:
        """The parent chain from ``until`` back to (not including) ``since``."""
        wanted = self._adapter.snapshot_delta(source, since=since, until=until)
        by_id = {ref.snapshot_id: ref for ref in self._adapter.list_snapshots(source)}
        return tuple(by_id[identifier] for identifier in wanted if identifier in by_id)

    def delta(self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotRef) -> Delta:
        """Classify the change from the snapshot summaries, then list the files."""
        if since is not None and since == until.snapshot_id:
            return Delta(since=since, until=until, kind=DeltaKind.NO_LOGICAL_CHANGE, files=())
        table = self._table(source)
        chain = self._adapter.snapshot_delta(source, since=since, until=until.snapshot_id)
        kind = DeltaKind.ADDITIVE
        if since is not None:
            root = table.snapshot_by_id(int(chain[0])) if chain else None
            reached_since = root is not None and str(root.parent_snapshot_id) == str(since)
            operations = {self._operation(table, identifier) for identifier in chain}
            if not reached_since or operations & {Operation.OVERWRITE, Operation.DELETE}:
                kind = DeltaKind.NON_ADDITIVE
            elif operations == {Operation.REPLACE}:
                return Delta(since=since, until=until, kind=DeltaKind.NO_LOGICAL_CHANGE, files=())
            elif Operation.REPLACE in operations:
                kind = DeltaKind.NON_ADDITIVE
        wanted = None if since is None or kind is DeltaKind.NON_ADDITIVE else set(chain)
        return Delta(
            since=since,
            until=until,
            kind=kind,
            files=self._files(table, until.snapshot_id, wanted),
        )

    @staticmethod
    def _operation(table: Table, identifier: SnapshotId) -> Operation | None:
        snapshot = table.snapshot_by_id(int(identifier))
        if snapshot is None or snapshot.summary is None:
            return None
        return snapshot.summary.operation

    @staticmethod
    def _files(
        table: Table, until: SnapshotId, added_in: set[SnapshotId] | None
    ) -> tuple[DataFileRef, ...]:
        snapshot = table.snapshot_by_id(int(until))
        if snapshot is None:
            return ()
        names = {item.field_id: item.name for item in table.schema().fields}
        found: list[DataFileRef] = []
        for manifest in snapshot.manifests(table.io):
            if manifest.content is not ManifestContent.DATA:
                # Merge-on-read delete files are not applied; see the package's known limits.
                continue
            for entry in manifest.fetch_manifest_entry(table.io, discard_deleted=True):
                if entry.status is ManifestEntryStatus.DELETED:
                    continue
                if added_in is not None and SnapshotId(str(entry.snapshot_id)) not in added_in:
                    continue
                data_file = entry.data_file
                sizes = data_file.column_sizes or {}
                found.append(
                    DataFileRef(
                        location=data_file.file_path,
                        size_bytes=data_file.file_size_in_bytes,
                        record_count=data_file.record_count,
                        column_bytes={
                            names[field_id]: size
                            for field_id, size in sizes.items()
                            if field_id in names
                        },
                    )
                )
        return tuple(sorted(found, key=lambda item: item.location))

    def column_types(self, source: SourceRef, snapshot: SnapshotRef) -> Mapping[str, LogicalType]:
        """From the table schema. Metadata only."""
        del snapshot
        schema = self._cached(source).schema().as_arrow()
        return {item.name: logical_type_of(item.type) for item in schema}

    def read(
        self, source: SourceRef, data_file: DataFileRef, *, columns: Sequence[str], batch_rows: int
    ) -> Iterator[pa.RecordBatch]:
        """Projected, batched Parquet read through the metered file IO.

        The footer is read by hand, to the byte, before the Parquet reader is opened.
        Left to itself the reader speculatively fetches the last 64 KiB of every file to
        find the footer -- on the golden fixture that is twenty times the projected
        column -- and the bytes actually moved would exceed an estimate built from the
        manifest's column sizes. With the footer supplied and pre-buffering off, a read
        moves the footer plus the projected column chunks and nothing else, which is
        exactly what :meth:`DataFileRef.estimated_bytes` charges for.
        """
        table = self._cached(source)
        with table.io.new_input(data_file.location).open() as stream:
            size = data_file.size_bytes
            stream.seek(size - _PARQUET_TAIL)
            tail = stream.read(_PARQUET_TAIL)
            if tail[4:] != _PARQUET_MAGIC:
                raise ValueError("not a Parquet file")
            footer_length = int.from_bytes(tail[:4], "little")
            stream.seek(size - _PARQUET_TAIL - footer_length)
            footer = stream.read(footer_length)
            metadata = pq.read_metadata(pa.BufferReader(_PARQUET_MAGIC + footer + tail))
            parquet = pq.ParquetFile(stream, metadata=metadata, pre_buffer=False)
            yield from parquet.iter_batches(batch_size=batch_rows, columns=list(columns))
