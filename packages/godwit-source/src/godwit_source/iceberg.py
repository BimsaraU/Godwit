"""The Iceberg adapter. DATA PLANE.

This is the adapter the product is designed around, because Iceberg gives away for free
what every other backend charges for. Per data file, per column, a manifest already
records the row count, the null count, the value count and the lower and upper bounds.
Puffin already records an NDV. Reading all of it costs a handful of Avro files.

**Manifests are read directly from object storage.** Never through a warehouse query
engine: routing a metadata read through Trino or Snowflake turns a free read into a
billed one, and the numbers we want are in the files, not in the engine.

READ THIS TWICE
---------------
Manifest **bounds are row values**. The lower bound of a name column is somebody's
name; of an email column, somebody's address. Iceberg truncates string bounds to
sixteen characters, which makes them a *prefix* of a real value and not one byte less
sensitive. Everything this module reads out of ``lower_bounds`` and ``upper_bounds``
becomes ``Tainted[DATA_VALUE]`` with ``Acquisition.ICEBERG_MANIFEST_BOUNDS`` at the
moment it is decoded, and it never loses that. Counts, by contrast, are aggregates and
become ``DERIVED_STATISTIC``. They live in separate fields of
:class:`~godwit_source.metadata.ColumnMetadata` so that no caller can confuse them.

This adapter is the origin point for most of the tainted values in Godwit. If it tags
lazily, nothing downstream can recover.
"""

from __future__ import annotations

import datetime as _dt
import statistics
from collections.abc import Iterable, Mapping, Sequence
from typing import Final

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq
from godwit_contracts.common import (
    Instant,
    ScalarValue,
    SnapshotId,
    Version,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.segment import Operator, Segment
from godwit_contracts.sketch import SketchBundle, SketchEnvelope, SketchKind
from godwit_contracts.source import (
    ColumnRef,
    LogicalType,
    SnapshotRef,
    SourceKind,
    SourceRef,
    TableProfile,
)
from godwit_contracts.taint import (
    Acquisition,
    Provenance,
    Sensitivity,
    Tainted,
    data_value,
    derived_statistic,
    schema_name,
)
from pyiceberg import types as iceberg_types
from pyiceberg.catalog import Catalog
from pyiceberg.conversions import from_bytes
from pyiceberg.manifest import DataFile, ManifestEntryStatus
from pyiceberg.schema import Schema
from pyiceberg.table import Table
from pyiceberg.table.snapshots import Snapshot
from pyiceberg.utils.datetime import (
    days_to_date,
    micros_to_time,
    micros_to_timestamp,
    micros_to_timestamptz,
)

from godwit_source.errors import (
    MetadataUnavailableError,
    UnsupportedProbeError,
    UnsupportedSourceError,
    sanitise_driver_error,
)
from godwit_source.metadata import ColumnMetadata, FileLayoutStats, SnapshotMetadata
from godwit_source.objectstore import ByteMeter, MeteredFileIO
from godwit_source.puffin import PuffinBlob, read_puffin, write_puffin
from godwit_source.scalars import scalar_le
from godwit_source.semantic import infer_pii_class, infer_role
from godwit_source.sketches import SketchBuilder, SketchContext

__all__ = ["METADATA_ONLY_KINDS", "THETA_BLOB_TYPE", "IcebergAdapter"]

THETA_BLOB_TYPE: Final[str] = "apache-datasketches-theta-v1"
"""The standard Puffin blob whose ``ndv`` property gives a column's distinct count."""

NDV_PROPERTY: Final[str] = "ndv"

METADATA_ONLY_KINDS: Final[frozenset[str]] = frozenset(
    {"column_bounds", "row_count", "freshness", "null_rate", "distinct_count"}
)
"""Probe kinds answerable from manifests alone. Invariant 5: try these before scanning.

``null_rate`` and ``distinct_count`` are here because Iceberg records null counts per
file and Puffin records an NDV. When the NDV blob is missing, ``distinct_count`` falls
through to a scan like anything else.
"""

_LOGICAL_TYPES: Final[tuple[tuple[type[iceberg_types.IcebergType], LogicalType], ...]] = (
    (iceberg_types.BooleanType, LogicalType.BOOL),
    (iceberg_types.IntegerType, LogicalType.INT),
    (iceberg_types.LongType, LogicalType.INT),
    (iceberg_types.FloatType, LogicalType.FLOAT),
    (iceberg_types.DoubleType, LogicalType.FLOAT),
    (iceberg_types.DecimalType, LogicalType.DECIMAL),
    (iceberg_types.DateType, LogicalType.DATE),
    (iceberg_types.TimestampType, LogicalType.TIMESTAMP),
    (iceberg_types.TimestamptzType, LogicalType.TIMESTAMP),
    (iceberg_types.StringType, LogicalType.STRING),
    (iceberg_types.UUIDType, LogicalType.STRING),
    (iceberg_types.BinaryType, LogicalType.BINARY),
    (iceberg_types.FixedType, LogicalType.BINARY),
    (iceberg_types.StructType, LogicalType.STRUCT),
    (iceberg_types.ListType, LogicalType.LIST),
    (iceberg_types.MapType, LogicalType.MAP),
)


class IcebergAdapter:
    """Reads Iceberg tables through a catalog, and their manifests through object storage.

    Satisfies ``godwit_contracts.protocols.SourceAdapter`` and adds the three methods
    the L-1 layer needs on top of it: :meth:`list_snapshots`,
    :meth:`read_metadata_stats` and :meth:`write_statistics`. The protocol is
    structural, so the extra methods cost nothing; they are not in the contract because
    no other package needs to call them.

    One adapter instance is one unit of measured work. The :class:`ByteMeter` is
    per-instance and cumulative, which is what makes ``meter.data_bytes == 0`` a
    meaningful assertion after a full metadata pass.
    """

    def __init__(
        self,
        catalog: Catalog,
        *,
        meter: ByteMeter | None = None,
        sketch_builder: SketchBuilder | None = None,
        worker_version: str = "godwit-source/0.1.0",
        profile_version: Version = 1,
    ) -> None:
        self._catalog = catalog
        self.meter = meter if meter is not None else ByteMeter()
        self._sketch_builder = sketch_builder
        self._worker_version = worker_version
        self._profile_version = profile_version

    # -- loading -----------------------------------------------------------------------

    def _load(self, source: SourceRef) -> Table:
        """Load a table and route every subsequent read through the meter."""
        if source.kind is not SourceKind.ICEBERG:
            raise UnsupportedSourceError(f"IcebergAdapter cannot read a {source.kind} source")
        identifier = (source.namespace.reveal(), source.table.reveal())
        try:
            table = self._catalog.load_table(identifier)
        except Exception as exc:
            raise sanitise_driver_error(exc, source_id=source.source_id) from None
        table.io = MeteredFileIO(table.io, self.meter)
        return table

    # -- snapshots ---------------------------------------------------------------------

    def _snapshot_ref(self, source: SourceRef, snapshot: Snapshot) -> SnapshotRef:
        """Iceberg's snapshot record, in our terms.

        ``timestamp_ms`` is the commit time and becomes ``committed_at``. Everything
        downstream uses it as the instant the metadata was observed, because universal
        rule 5 forbids reading a clock: a snapshot's own commit time is the only
        instant that is both real and reproducible.
        """
        return SnapshotRef(
            source_id=source.source_id,
            snapshot_id=SnapshotId(str(snapshot.snapshot_id)),
            sequence_number=max(0, snapshot.sequence_number or 0),
            committed_at=_dt.datetime.fromtimestamp(snapshot.timestamp_ms / 1000.0, tz=_dt.UTC),
            parent_snapshot_id=(
                None
                if snapshot.parent_snapshot_id is None
                else SnapshotId(str(snapshot.parent_snapshot_id))
            ),
        )

    def list_snapshots(
        self, source: SourceRef, *, limit: int | None = None
    ) -> tuple[SnapshotRef, ...]:
        """Every snapshot, oldest first, ordered by commit time then sequence number.

        Commit time alone is not a total order -- two commits can share a millisecond --
        so the sequence number breaks ties. Without a total order, "the previous
        snapshot" would be ambiguous and a baseline could flip between runs.
        """
        table = self._load(source)
        refs = sorted(
            (self._snapshot_ref(source, snapshot) for snapshot in table.metadata.snapshots),
            key=lambda ref: (ref.committed_at, ref.sequence_number),
        )
        return tuple(refs[-limit:]) if limit is not None else tuple(refs)

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        """The snapshot current at ``at``, or the newest when ``at`` is None."""
        refs = self.list_snapshots(source)
        if not refs:
            raise MetadataUnavailableError("table has no snapshots")
        if at is None:
            return refs[-1]
        eligible = [ref for ref in refs if ref.committed_at <= at]
        if not eligible:
            raise MetadataUnavailableError("no snapshot had been committed by that instant")
        return eligible[-1]

    def snapshot_delta(
        self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotId
    ) -> tuple[SnapshotId, ...]:
        """Snapshot ids in ``(since, until]``, walking the parent chain backwards.

        The parent chain rather than the commit-time order, because a branch or a
        cherry-pick can put a newer commit time on an older lineage. The chain is what
        Iceberg itself means by "since".
        """
        table = self._load(source)
        chain: list[SnapshotId] = []
        cursor: int | None = int(until)
        while cursor is not None:
            snapshot = table.snapshot_by_id(cursor)
            if snapshot is None:
                break
            identifier = SnapshotId(str(snapshot.snapshot_id))
            if since is not None and identifier == since:
                break
            chain.append(identifier)
            cursor = snapshot.parent_snapshot_id
        return tuple(reversed(chain))

    # -- metadata ----------------------------------------------------------------------

    def read_metadata_stats(
        self,
        source: SourceRef,
        snapshot: SnapshotRef,
        *,
        budget: CostBudget,
        since: SnapshotId | None = None,
    ) -> SnapshotMetadata:
        """Per-column statistics for one snapshot, or for the files added since ``since``.

        Zero bytes of table data are read. The cost charged against ``budget`` is the
        manifest bytes, estimated from ``manifest_length`` *before* anything is opened,
        so an overrun is a refusal rather than a surprise on the bill.
        """
        table = self._load(source)
        iceberg_snapshot = table.snapshot_by_id(int(snapshot.snapshot_id))
        if iceberg_snapshot is None:
            raise MetadataUnavailableError("snapshot is not present in this table's metadata")

        manifests = iceberg_snapshot.manifests(table.io)
        estimate = sum(manifest.manifest_length for manifest in manifests)
        budget.spend(CostSpend(bytes_scanned=estimate))

        wanted = (
            None
            if since is None
            else set(self.snapshot_delta(source, since=since, until=snapshot.snapshot_id))
        )
        try:
            files = tuple(self._data_files(table, iceberg_snapshot, wanted))
        except Exception as exc:
            raise sanitise_driver_error(exc, source_id=source.source_id) from None

        ndv_by_field = self._puffin_ndv(table, iceberg_snapshot)
        return self._assemble(
            source=source,
            snapshot=snapshot,
            schema=table.schema(),
            files=files,
            ndv_by_field=ndv_by_field,
            since=since,
        )

    def profile_table(
        self, source: SourceRef, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> TableProfile:
        """The L0 contract view. Catalog-derived; scans nothing."""
        return self.read_metadata_stats(source, snapshot, budget=budget).to_table_profile()

    # -- probes ------------------------------------------------------------------------

    def execute_probe(
        self, spec: ProbeSpec, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> SketchBundle:
        """Run one measurement over the delta's data files and return sketches.

        The budget is enforced **before** a byte is read: data-file sizes come from the
        manifest, the total is charged against the composed budget, and a refusal raises
        ``BudgetExceededError``, which invariant 6 says is a normal outcome and not a
        failure. Only then are the files opened, and only the columns the spec names.

        Never returns rows. The values it reads go straight into an injected
        :class:`~godwit_source.sketches.SketchBuilder` and are dropped.
        """
        if self._sketch_builder is None:
            raise UnsupportedProbeError(
                "this adapter was built without a SketchBuilder; A2 supplies one"
            )
        if not spec.sketches:
            raise UnsupportedProbeError("a probe spec must name at least one sketch kind")

        effective = CostBudget.compose(budget, spec.budget)
        table = self._load(source=spec.source)
        iceberg_snapshot = table.snapshot_by_id(int(snapshot.snapshot_id))
        if iceberg_snapshot is None:
            raise MetadataUnavailableError("snapshot is not present in this table's metadata")

        files = tuple(self._data_files(table, iceberg_snapshot, None))
        estimate = sum(data_file.file_size_in_bytes for data_file in files)
        effective.spend(CostSpend(bytes_scanned=estimate))

        before = self.meter.data_bytes
        column_names = [column.reveal() for column in spec.columns]
        predicate_names = [
            predicate.column.reveal()
            for predicate in spec.segment.predicates
            if predicate.column.reveal() not in column_names
        ]
        try:
            arrow = self._read_columns(table, files, column_names + predicate_names)
            arrow = _apply_segment(arrow, spec.segment)
        except Exception as exc:
            raise sanitise_driver_error(exc, source_id=spec.source.source_id) from None

        population = arrow.num_rows
        sketches: dict[str, SketchEnvelope] = {}
        for kind in spec.sketches:
            for index, name in enumerate(column_names):
                sketches[f"{kind.value}:{index}"] = self._build_sketch(
                    kind=kind,
                    spec=spec,
                    snapshot=snapshot,
                    column=name,
                    values=_value_table(arrow.column(name)),
                    population=population,
                )
            if not column_names:
                sketches[f"{kind.value}:table"] = self._build_sketch(
                    kind=kind,
                    spec=spec,
                    snapshot=snapshot,
                    column=None,
                    values=None,
                    population=population,
                )

        return SketchBundle(
            bundle_id=content_hash(
                canonical_json(
                    {
                        "probe_key": str(spec.key),
                        "snapshot_id": str(snapshot.snapshot_id),
                        "seed": spec.seed,
                    }
                ),
                prefix="bnd",
            ),
            probe_key=spec.key,
            source_id=spec.source.source_id,
            snapshot_id=snapshot.snapshot_id,
            sketches=sketches,
            cost_spent=CostSpend(bytes_scanned=self.meter.data_bytes - before),
            produced_at=spec.as_of,
            worker_version=self._worker_version,
            seed=spec.seed,
        )

    def _build_sketch(
        self,
        *,
        kind: SketchKind,
        spec: ProbeSpec,
        snapshot: SnapshotRef,
        column: str | None,
        values: pa.Table | None,
        population: int,
    ) -> SketchEnvelope:
        if self._sketch_builder is None:  # pragma: no cover -- checked by the caller
            raise UnsupportedProbeError("no SketchBuilder")
        return self._sketch_builder.build(
            kind=kind,
            params=spec.params,
            values=values,
            context=SketchContext(
                source_id=spec.source.source_id,
                snapshot_id=snapshot.snapshot_id,
                probe_key=spec.key,
                produced_at=spec.as_of,
                provenance=Provenance(
                    acquisition=Acquisition.SKETCH_SUMMARY,
                    source_id=spec.source.source_id,
                    table=spec.source.table.reveal(),
                    column=column,
                    snapshot_id=snapshot.snapshot_id,
                ),
                population=population,
            ),
        )

    def _read_columns(
        self, table: Table, files: Sequence[DataFile], columns: Sequence[str]
    ) -> pa.Table:
        """Read only the named columns of the named files, through the meter.

        Parquet is columnar, so projecting here is the real saving: the bytes charged
        are an upper bound taken from the manifest, and the bytes actually moved are
        usually far fewer. Files are opened through the table's (metered) ``FileIO``
        rather than by path, so a data read cannot slip past the instrument.
        """
        wanted = list(dict.fromkeys(columns))
        chunks: list[pa.Table] = []
        for data_file in files:
            with table.io.new_input(data_file.file_path).open() as stream:
                chunks.append(pq.read_table(stream, columns=wanted or None))
        if not chunks:
            return pa.table({name: pa.array([]) for name in wanted})
        return pa.concat_tables(chunks)

    # -- puffin ------------------------------------------------------------------------

    def write_statistics(
        self,
        source: SourceRef,
        snapshot: SnapshotRef,
        blobs: Sequence[PuffinBlob],
        *,
        location: str,
    ) -> str:
        """Write a Puffin file of Godwit blobs beside the table, and return its location.

        The file is **not** registered in the table's ``statistics`` metadata. pyiceberg
        0.12 types the registered blob type as a two-member ``Literal``, so registering
        a ``godwit-`` blob there makes the table's metadata unreadable by pyiceberg --
        including by us. Keeping our blobs in an unregistered sidecar preserves the
        property that matters, which is that every other engine ignores them, and
        loses nothing: we address the file by location. See
        ``docs/specs/puffin-blobs.md``.
        """
        table = self._load(source)
        payload = write_puffin(
            blobs,
            properties={
                "created-by": self._worker_version,
                "godwit.snapshot-id": str(snapshot.snapshot_id),
            },
        )
        try:
            output = table.io.new_output(location)
            with output.create(overwrite=True) as stream:
                stream.write(payload)
        except Exception as exc:
            raise sanitise_driver_error(exc, source_id=source.source_id) from None
        return location

    def read_statistics(self, source: SourceRef, *, location: str) -> tuple[PuffinBlob, ...]:
        """Read back a Puffin file written by :meth:`write_statistics`."""
        table = self._load(source)
        try:
            with table.io.new_input(location).open() as stream:
                return read_puffin(stream.read())
        except Exception as exc:
            raise sanitise_driver_error(exc, source_id=source.source_id) from None

    def _puffin_ndv(self, table: Table, snapshot: Snapshot) -> Mapping[int, int]:
        """NDV per field id, from the snapshot's registered theta sketches.

        A missing statistics file is normal and not an error: most tables have never
        had ``ANALYZE`` run on them. The NDV simply stays ``None`` and
        ``ndv_ratio_shift`` stays quiet, which is the honest outcome.
        """
        found: dict[int, int] = {}
        for statistics_file in table.metadata.statistics:
            if statistics_file.snapshot_id != snapshot.snapshot_id:
                continue
            try:
                with table.io.new_input(statistics_file.statistics_path).open() as stream:
                    blobs = read_puffin(stream.read())
            except (OSError, ValueError):
                continue
            for blob in blobs:
                if blob.blob_type != THETA_BLOB_TYPE or not blob.fields:
                    continue
                raw = blob.properties.get(NDV_PROPERTY)
                if raw is None:
                    continue
                try:
                    found[blob.fields[0]] = int(raw)
                except ValueError:
                    continue
        return found

    # -- assembly ----------------------------------------------------------------------

    def _data_files(
        self, table: Table, snapshot: Snapshot, wanted_snapshots: set[SnapshotId] | None
    ) -> Iterable[DataFile]:
        """Every live data file in the snapshot, or only those added by ``wanted_snapshots``."""
        for manifest in snapshot.manifests(table.io):
            for entry in manifest.fetch_manifest_entry(table.io, discard_deleted=True):
                if wanted_snapshots is not None:
                    added_by = SnapshotId(str(entry.snapshot_id))
                    if (
                        entry.status is not ManifestEntryStatus.ADDED
                        or added_by not in wanted_snapshots
                    ):
                        continue
                yield entry.data_file

    def _assemble(
        self,
        *,
        source: SourceRef,
        snapshot: SnapshotRef,
        schema: Schema,
        files: Sequence[DataFile],
        ndv_by_field: Mapping[int, int],
        since: SnapshotId | None,
    ) -> SnapshotMetadata:
        row_count = sum(data_file.record_count for data_file in files)
        columns = tuple(
            self._column_metadata(
                source=source,
                snapshot=snapshot,
                field=field,
                files=files,
                row_count=row_count,
                ndv=ndv_by_field.get(field.field_id),
            )
            for field in schema.fields
        )
        return SnapshotMetadata(
            source=source,
            snapshot=snapshot,
            columns=columns,
            row_count=derived_statistic(
                row_count,
                source_id=source.source_id,
                table=source.table.reveal(),
                snapshot_id=snapshot.snapshot_id,
                population=row_count,
            ),
            layout=_layout_stats(source, snapshot, files),
            is_delta=since is not None,
            baseline_snapshot_id=since,
            observed_at=snapshot.committed_at,
            profile_version=self._profile_version,
            scanned_bytes=0,
        )

    def _column_metadata(
        self,
        *,
        source: SourceRef,
        snapshot: SnapshotRef,
        field: iceberg_types.NestedField,
        files: Sequence[DataFile],
        row_count: int,
        ndv: int | None,
    ) -> ColumnMetadata:
        logical_type = _logical_type(field.field_type)
        lower = _reduce_bound(field, files, upper=False)
        upper = _reduce_bound(field, files, upper=True)
        nulls = _sum_counts(files, field.field_id, nulls=True)
        values = _sum_counts(files, field.field_id, nulls=False)

        ref = ColumnRef(
            source_id=source.source_id,
            table=schema_name(source.table.reveal(), source_id=source.source_id),
            column=schema_name(field.name, source_id=source.source_id, table=source.table.reveal()),
        )
        sample = [value for value in (lower, upper) if value is not None]
        pii_class = infer_pii_class(
            column_name=field.name, logical_type=logical_type, sample_values=sample
        )
        role = infer_role(
            column_name=field.name,
            logical_type=logical_type,
            pii_class=pii_class,
            distinct_estimate=ndv,
            row_count=row_count,
        )

        def bound(value: ScalarValue | None) -> Tainted[ScalarValue] | None:
            if value is None:
                return None
            return data_value(
                value,
                acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS,
                source_id=source.source_id,
                table=source.table.reveal(),
                column=field.name,
                snapshot_id=snapshot.snapshot_id,
                population=row_count,
            )

        def count(value: int | None) -> Tainted[int] | None:
            if value is None:
                return None
            return derived_statistic(
                value,
                source_id=source.source_id,
                table=source.table.reveal(),
                column=field.name,
                snapshot_id=snapshot.snapshot_id,
                population=row_count,
            )

        non_null = None if values is None else values - (nulls or 0)
        return ColumnMetadata(
            ref=ref,
            logical_type=logical_type,
            native_type=str(field.field_type),
            nullable=not field.required,
            role=role,
            pii_class=pii_class,
            row_count=count(row_count),
            null_count=count(nulls),
            value_count=count(non_null),
            distinct_estimate=count(ndv),
            lower_bound=bound(lower),
            upper_bound=bound(upper),
        )


# --------------------------------------------------------------------------------------
# Manifest arithmetic
# --------------------------------------------------------------------------------------


def _logical_type(field_type: iceberg_types.IcebergType) -> LogicalType:
    for iceberg_type, logical in _LOGICAL_TYPES:
        if isinstance(field_type, iceberg_type):
            return logical
    return LogicalType.UNKNOWN


def _decode_bound(field_type: iceberg_types.IcebergType, raw: bytes) -> ScalarValue | None:
    """Decode one manifest bound into a Python value.

    ``from_bytes`` returns the Iceberg physical representation, which for temporal types
    is an integer of microseconds or days. Leaving it as an integer would silently make
    a timestamp bound compare as a number against a date bound from another snapshot, so
    it is converted here, once, at the only place the raw bytes exist.

    Returns ``None`` when the type is not primitive -- a struct has no single bound --
    or when the bytes do not decode, which happens with a manifest written by a schema
    the table has since changed.
    """
    if not isinstance(field_type, iceberg_types.PrimitiveType):
        return None
    try:
        # Annotated as ``object``: ``from_bytes`` is a singledispatch whose declared
        # return type is a bare TypeVar, which a strict checker resolves to ``str``.
        # Narrowing it back from ``object`` is what lets the temporal branches below
        # be reachable rather than dead.
        decoded: object = from_bytes(field_type, raw)
    except (TypeError, ValueError, OverflowError):
        return None
    if isinstance(field_type, iceberg_types.TimestamptzType) and isinstance(decoded, int):
        return micros_to_timestamptz(decoded)
    if isinstance(field_type, iceberg_types.TimestampType) and isinstance(decoded, int):
        return micros_to_timestamp(decoded)
    if isinstance(field_type, iceberg_types.DateType) and isinstance(decoded, int):
        return days_to_date(decoded)
    if isinstance(field_type, iceberg_types.TimeType) and isinstance(decoded, int):
        return micros_to_time(decoded).isoformat()
    if isinstance(decoded, str | int | float | bool | bytes | _dt.date | _dt.datetime):
        return decoded
    return str(decoded)


def _reduce_bound(
    field: iceberg_types.NestedField, files: Sequence[DataFile], *, upper: bool
) -> ScalarValue | None:
    """The minimum lower bound, or maximum upper bound, across a snapshot's files.

    One file's bounds describe one file. A column's bound at a snapshot is the reduction
    over every live file, which is the number a human would call the table's min or max.
    """
    best: ScalarValue | None = None
    for data_file in files:
        source = data_file.upper_bounds if upper else data_file.lower_bounds
        raw = source.get(field.field_id) if source else None
        if raw is None:
            continue
        value = _decode_bound(field.field_type, raw)
        if value is None:
            continue
        if best is None:
            best = value
            continue
        ordered = scalar_le(best, value)
        if ordered is None:
            continue
        if ordered is upper:
            best = value
    return best


def _sum_counts(files: Sequence[DataFile], field_id: int, *, nulls: bool) -> int | None:
    """Sum a per-file count across a snapshot, or ``None`` if no file recorded it.

    ``None`` rather than ``0``: a writer that never records null counts and a column
    with no nulls look identical in the sum, and a detector must be able to tell them
    apart before it reports that a null rate changed.
    """
    total = 0
    seen = False
    for data_file in files:
        counts = data_file.null_value_counts if nulls else data_file.value_counts
        if not counts:
            continue
        value = counts.get(field_id)
        if value is None:
            continue
        seen = True
        total += value
    return total if seen else None


def _layout_stats(
    source: SourceRef, snapshot: SnapshotRef, files: Sequence[DataFile]
) -> FileLayoutStats | None:
    """File-count and file-size statistics. Aggregates over files, never over rows."""
    if not files:
        return None
    sizes = [float(data_file.file_size_in_bytes) for data_file in files]

    def statistic(value: float) -> Tainted[float]:
        return derived_statistic(
            value,
            source_id=source.source_id,
            table=source.table.reveal(),
            snapshot_id=snapshot.snapshot_id,
            population=len(files),
        )

    return FileLayoutStats(
        file_count=Tainted[int](
            value=len(files),
            sensitivity=Sensitivity.DERIVED_STATISTIC,
            provenance=Provenance(
                acquisition=Acquisition.COMPUTED_STATISTIC,
                source_id=source.source_id,
                table=source.table.reveal(),
                snapshot_id=snapshot.snapshot_id,
            ),
            population=len(files),
        ),
        total_bytes=Tainted[int](
            value=int(sum(sizes)),
            sensitivity=Sensitivity.DERIVED_STATISTIC,
            provenance=Provenance(
                acquisition=Acquisition.COMPUTED_STATISTIC,
                source_id=source.source_id,
                table=source.table.reveal(),
                snapshot_id=snapshot.snapshot_id,
            ),
            population=len(files),
        ),
        mean_file_bytes=statistic(statistics.fmean(sizes)),
        stdev_file_bytes=statistic(statistics.pstdev(sizes)),
    )


# --------------------------------------------------------------------------------------
# Segment translation
# --------------------------------------------------------------------------------------


def _value_table(values: pa.ChunkedArray) -> pa.Table:
    """Wrap a scanned column in the value/count convention sketch builders expect.

    A scan hands over raw values, so every count is one. The column exists anyway, so
    that a builder never has to ask which adapter it is talking to.
    """
    return pa.table({"value": values, "count": pa.array([1] * len(values))})


def _apply_segment(arrow: pa.Table, segment: Segment) -> pa.Table:
    """Filter an Arrow table down to a segment.

    The predicate values are revealed here. That is legitimate -- this is the data plane,
    and selecting rows is what a predicate is for -- and nothing revealed here survives
    the call: the filtered table goes to a sketch builder and the mask is dropped.
    """
    if segment.is_universe:
        return arrow
    mask: pa.ChunkedArray | None = None
    for predicate in segment.predicates:
        column = arrow.column(predicate.column.reveal())
        values = [value.reveal() for value in predicate.values]
        clause = _predicate_mask(column, predicate.op, values)
        mask = clause if mask is None else pc.and_(mask, clause)
    return arrow if mask is None else arrow.filter(mask)


def _predicate_mask(
    column: pa.ChunkedArray, operator: Operator, values: Sequence[ScalarValue]
) -> pa.ChunkedArray:
    match operator:
        case Operator.EQ:
            return pc.equal(column, values[0])
        case Operator.NE:
            return pc.not_equal(column, values[0])
        case Operator.LT:
            return pc.less(column, values[0])
        case Operator.LE:
            return pc.less_equal(column, values[0])
        case Operator.GT:
            return pc.greater(column, values[0])
        case Operator.GE:
            return pc.greater_equal(column, values[0])
        case Operator.IN:
            return pc.is_in(column, value_set=pa.array(list(values)))
        case Operator.NOT_IN:
            return pc.invert(pc.is_in(column, value_set=pa.array(list(values))))
        case Operator.IS_NULL:
            return pc.is_null(column)
        case Operator.NOT_NULL:
            return pc.is_valid(column)
        case Operator.BETWEEN:
            return pc.and_(pc.greater_equal(column, values[0]), pc.less_equal(column, values[1]))
        case Operator.PREFIX:
            return pc.starts_with(column, pattern=str(values[0]))
