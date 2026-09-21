"""Iceberg source adapter.

DATA PLANE. Reads manifests and Puffin directly from object storage -- never through a
warehouse query engine, because routing a metadata read through a billed engine turns the
free tier into the expensive tier and puts row values through a third party's logs.

What the manifest gives us for free, per data file per column: ``record_count``,
``value_counts``, ``null_value_counts``, ``lower_bounds``, ``upper_bounds``,
``file_size_in_bytes``. Puffin adds an NDV from the Theta sketch blob.

**Bounds are row values.** The lower bound of a name column is a real person's name; of an
email column, a real email. Everything read from ``lower_bounds``/``upper_bounds`` is
``Tainted[DATA_VALUE]`` from the instant it is read, and for an ``OPAQUE`` column it is not
read into a structure at all -- only the counts are.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, Self, cast, runtime_checkable

from ._contracts import (
    ColumnAccessMode,
    CostBudget,
    CostBudgetExceeded,
    ProbeSpec,
    Tainted,
    data_value,
    derived_statistic,
)
from .access import AccessPolicy, keyed_hash
from .base import ProbeResult, SnapshotRef, assert_plan_is_blind_safe, require_readable
from .stats import ColumnBounds, ColumnCounts, ColumnMetadata, FileLayoutStats, SnapshotMetadata

__all__ = ["ArrowTable", "DataFileStats", "IcebergAdapter", "ManifestReader", "SchemaField"]


@runtime_checkable
class ArrowTable(Protocol):
    """The slice of ``pyarrow.Table`` this adapter uses.

    pyarrow ships no type information, so depending on it through a protocol keeps
    ``mypy --strict`` honest and states the coupling explicitly: four members, no more.
    """

    @property
    def num_rows(self) -> int: ...

    @property
    def column_names(self) -> list[str]: ...

    def column(self, name: str) -> object: ...

    def set_column(self, i: int, field_: str, column: object) -> Self: ...


@dataclass(frozen=True, slots=True)
class SchemaField:
    """One Iceberg schema field. ``field_id`` is how manifests key their statistics."""

    field_id: int
    name: str
    data_type: str


@dataclass(frozen=True, slots=True)
class DataFileStats:
    """A manifest entry, flattened. Everything here is free to read.

    ``lower_bounds`` and ``upper_bounds`` hold real row values, keyed by field id. They are
    plain here because this is the raw manifest record inside the data plane; they acquire
    taint the moment :class:`IcebergAdapter` lifts them into a :class:`ColumnBounds`, and
    for ``OPAQUE`` and ``BLIND`` columns they are never lifted at all.
    """

    path: str
    file_size_in_bytes: int
    record_count: int
    value_counts: Mapping[int, int] = field(default_factory=dict)
    null_value_counts: Mapping[int, int] = field(default_factory=dict)
    lower_bounds: Mapping[int, object] = field(default_factory=dict)
    upper_bounds: Mapping[int, object] = field(default_factory=dict)


class ManifestReader(Protocol):
    """The narrow slice of Iceberg this adapter needs.

    Injected rather than constructed so a fixture can drive the whole metadata tier with no
    catalog, no object store and provably zero data bytes. ``PyIcebergManifestReader``
    implements it against a REST catalog.
    """

    def snapshots(self, table: str) -> Sequence[SnapshotRef]: ...

    def schema(self, table: str, snapshot_id: str) -> Sequence[SchemaField]: ...

    def data_files(
        self, table: str, snapshot_id: str, *, delta_only: bool = True
    ) -> Sequence[DataFileStats]: ...

    def puffin_ndv(self, table: str, snapshot_id: str) -> Mapping[int, int]: ...


def _median(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0


def _merge_bound(current: object | None, candidate: object, *, take_min: bool) -> object:
    """Fold per-file bounds into a per-snapshot bound.

    Comparison falls back to text when the values are not mutually orderable, which happens
    on mixed or exotic types. Text order is wrong for numbers stored as strings, so the
    resulting bound is a hint for a detector, never an arithmetic input beyond the distance
    the detector reports.
    """
    if current is None:
        return candidate
    try:
        return min(current, candidate) if take_min else max(current, candidate)  # type: ignore[call-overload]
    except TypeError:
        left, right = str(current), str(candidate)
        return min(left, right) if take_min else max(left, right)


class IcebergAdapter:
    """``SourceAdapter`` over Iceberg. The full-strength tier."""

    name = "iceberg"

    def __init__(
        self,
        reader: ManifestReader,
        *,
        hash_key: bytes = b"",
        read_arrow: Callable[[str, Sequence[str]], ArrowTable] | None = None,
    ) -> None:
        self._reader = reader
        self._hash_key = hash_key
        self._read_arrow = read_arrow

    def list_snapshots(self, table: str) -> Sequence[SnapshotRef]:
        """Snapshots oldest first by commit time, ties broken by sequence number."""
        return sorted(
            self._reader.snapshots(table), key=lambda s: (s.commit_ms, s.sequence_number)
        )

    def read_metadata_stats(
        self,
        table: str,
        *,
        policy: AccessPolicy,
        since: str | None = None,
        until: str | None = None,
        delta_only: bool = True,
    ) -> list[SnapshotMetadata]:
        """Per-column statistics for each snapshot in the window, from metadata alone.

        ``delta_only`` restricts each snapshot's statistics to the files it added, which is
        what makes the series a series: full-table statistics move slowly and hide exactly
        the shifts we are looking for.
        """
        snapshots = self._window(table, since, until)
        return [self._snapshot_metadata(table, snap, policy, delta_only) for snap in snapshots]

    def _window(self, table: str, since: str | None, until: str | None) -> list[SnapshotRef]:
        snapshots = list(self.list_snapshots(table))
        if since is not None:
            ids = [s.snapshot_id for s in snapshots]
            if since not in ids:
                raise KeyError(f"snapshot {since!r} not in table history")
            snapshots = snapshots[ids.index(since) + 1 :]
        if until is not None:
            ids = [s.snapshot_id for s in snapshots]
            if until not in ids:
                raise KeyError(f"snapshot {until!r} not in table history")
            snapshots = snapshots[: ids.index(until) + 1]
        return snapshots

    def _snapshot_metadata(
        self, table: str, snap: SnapshotRef, policy: AccessPolicy, delta_only: bool
    ) -> SnapshotMetadata:
        schema = list(self._reader.schema(table, snap.snapshot_id))
        files = list(self._reader.data_files(table, snap.snapshot_id, delta_only=delta_only))
        ndv_by_field = self._reader.puffin_ndv(table, snap.snapshot_id)
        rows = sum(f.record_count for f in files)
        origin = f"iceberg.manifest[{table}@{snap.snapshot_id}]"

        columns: dict[str, ColumnMetadata] = {}
        for fld in schema:
            mode = policy.mode(fld.name)
            if mode is ColumnAccessMode.BLIND:
                # Not read then dropped: the bounds for this field are never touched.
                continue
            counts = self._counts(files, fld, rows, ndv_by_field, origin)
            bounds = self._bounds(files, fld, origin) if mode is ColumnAccessMode.OPEN else None
            columns[fld.name] = ColumnMetadata(
                table=table,
                column=fld.name,
                snapshot_id=snap.snapshot_id,
                access_mode=mode,
                data_type=fld.data_type,
                counts=counts,
                bounds=bounds,
            )

        sizes = [float(f.file_size_in_bytes) for f in files]
        layout = FileLayoutStats(
            file_count=len(files),
            total_bytes=int(sum(sizes)),
            median_file_bytes=_median(sizes),
            max_file_bytes=int(max(sizes, default=0)),
        )
        return SnapshotMetadata(
            table=table,
            snapshot_id=snap.snapshot_id,
            sequence_number=snap.sequence_number,
            commit_ms=snap.commit_ms,
            columns=columns,
            layout=layout,
            schema_columns=tuple(f.name for f in schema),
        )

    def _counts(
        self,
        files: Sequence[DataFileStats],
        fld: SchemaField,
        rows: int,
        ndv_by_field: Mapping[int, int],
        origin: str,
    ) -> ColumnCounts:
        nulls = sum(f.null_value_counts.get(fld.field_id, 0) for f in files)
        values = sum(f.value_counts.get(fld.field_id, 0) for f in files)
        ndv = ndv_by_field.get(fld.field_id)
        return ColumnCounts(
            row_count=derived_statistic(rows, origin),
            null_count=derived_statistic(nulls, origin),
            value_count=derived_statistic(values, origin),
            ndv=None if ndv is None else derived_statistic(ndv, f"{origin}.puffin"),
        )

    def _bounds(
        self, files: Sequence[DataFileStats], fld: SchemaField, origin: str
    ) -> ColumnBounds | None:
        lower: object | None = None
        upper: object | None = None
        for f in files:
            if fld.field_id in f.lower_bounds:
                lower = _merge_bound(lower, f.lower_bounds[fld.field_id], take_min=True)
            if fld.field_id in f.upper_bounds:
                upper = _merge_bound(upper, f.upper_bounds[fld.field_id], take_min=False)
        if lower is None and upper is None:
            return None
        return ColumnBounds(
            lower=None if lower is None else data_value(lower, f"{origin}.lower_bounds"),
            upper=None if upper is None else data_value(upper, f"{origin}.upper_bounds"),
        )

    def estimate_probe_bytes(self, spec: ProbeSpec, *, delta_only: bool = True) -> int:
        """Bytes a probe would read, from manifest file sizes. Costs nothing to compute."""
        files = self._reader.data_files(spec.table, spec.snapshot_id, delta_only=delta_only)
        return sum(f.file_size_in_bytes for f in files)

    def execute_probe(
        self,
        spec: ProbeSpec,
        *,
        policy: AccessPolicy,
        budget: CostBudget,
        delta_only: bool = True,
        aggregate: Callable[[ArrowTable], Mapping[str, float]] | None = None,
    ) -> ProbeResult:
        """Scan the snapshot delta's data files and return aggregates. Never rows.

        The budget is checked against the manifest's own file sizes *before* the first byte
        is fetched, so refusing costs nothing. Refusing is a normal outcome.

        ``OPAQUE`` columns are hashed inside this worker: Parquet has no server-side compute,
        so the value is materialised in data-plane memory and replaced before anything is
        aggregated. The raw value never reaches a result, a log or an exception.
        """
        columns = require_readable(policy, spec.columns)
        projections = policy.plan(columns)
        projected = tuple(p.column for p in projections)
        assert_plan_is_blind_safe(None, projected, policy, spec.columns)

        estimated = self.estimate_probe_bytes(spec, delta_only=delta_only)
        budget.check_bytes(estimated)
        budget.spend_query()

        if self._read_arrow is None:
            raise RuntimeError("IcebergAdapter needs read_arrow to execute a probe")
        opaque = {p.column for p in projections if p.mode is ColumnAccessMode.OPAQUE}
        if opaque and not self._hash_key:
            raise RuntimeError("OPAQUE columns require a data-plane hash key")

        files = self._reader.data_files(spec.table, spec.snapshot_id, delta_only=delta_only)
        aggregates: dict[str, Tainted[float]] = {}
        origin = f"iceberg.probe[{spec.table}@{spec.snapshot_id}]"
        bytes_read = 0
        rows_seen = 0
        extra: dict[str, float] = {}
        for data_file in files:
            budget.spend_bytes(data_file.file_size_in_bytes)
            table_chunk = self._read_arrow(data_file.path, projected)
            table_chunk = self._apply_opaque(table_chunk, opaque)
            bytes_read += data_file.file_size_in_bytes
            rows_seen += int(table_chunk.num_rows)
            if aggregate is not None:
                for key, value in aggregate(table_chunk).items():
                    extra[key] = extra.get(key, 0.0) + float(value)
        aggregates["row_count"] = derived_statistic(float(rows_seen), origin)
        for key, value in extra.items():
            aggregates[key] = derived_statistic(value, origin)

        return ProbeResult(
            spec=spec,
            sql=None,
            schema_names=projected,
            aggregates=aggregates,
            bytes_read=bytes_read,
            files_read=len(files),
        )

    def _apply_opaque(self, table_chunk: ArrowTable, opaque: set[str]) -> ArrowTable:
        """Replace every OPAQUE column with its keyed hash, in place, before aggregation."""
        if not opaque:
            return table_chunk
        import pyarrow as pa

        for name in opaque:
            if name not in table_chunk.column_names:
                continue
            values = cast("list[object]", table_chunk.column(name).to_pylist())  # type: ignore[attr-defined]
            hashed = [keyed_hash(v, self._hash_key) for v in values]
            table_chunk = table_chunk.set_column(
                table_chunk.column_names.index(name), name, pa.array(hashed, type=pa.string())
            )
        return table_chunk


def probe_or_refuse(
    adapter: IcebergAdapter, spec: ProbeSpec, *, policy: AccessPolicy, budget: CostBudget
) -> ProbeResult | None:
    """Run a probe, or return ``None`` when the budget says no.

    A convenience for callers that treat refusal as a scheduling outcome rather than an
    error, which per invariant 6 is what it is.
    """
    try:
        return adapter.execute_probe(spec, policy=policy, budget=budget)
    except CostBudgetExceeded:
        return None
