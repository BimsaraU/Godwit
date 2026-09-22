"""The Postgres adapter. DATA PLANE.

Postgres maintains, for free and continuously, most of what a profiler would pay to
compute: ``pg_class.reltuples`` and ``relpages`` for size, and ``pg_stats`` for null
fraction, distinct count, most-common values with their frequencies, and histogram
boundaries. ``ANALYZE`` already sampled the table; we read its notes.

READ THIS TWICE
---------------
``pg_stats.most_common_vals`` **is a list of the actual most common values in the
column**, and ``histogram_bounds`` **is a list of the values that fell on each
percentile boundary**. On a twelve-row table the histogram boundaries are twelve
people. Both come back ``Tainted[DATA_VALUE]``, with ``Acquisition.PG_STATS_MCV`` and
``Acquisition.QUANTILE`` respectively. The frequencies beside them are aggregates and
are typed apart.

ZERO TABLE SCANS ON THE METADATA PATH
-------------------------------------
Every statement the metadata path issues reads a relation in :data:`CATALOG_RELATIONS`
and nothing else. That is asserted by a test, against a recording connection, rather
than asserted in a comment: the whole economic argument for L-1 rests on it.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Final

import sqlalchemy as sa
from godwit_contracts.common import (
    Instant,
    ScalarValue,
    SnapshotId,
    Version,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.probe import ProbeKind, ProbeSpec
from godwit_contracts.sketch import SketchBundle, SketchEnvelope
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
    Tainted,
    data_value,
    derived_statistic,
    schema_name,
)

from godwit_source.dbapi import (
    Connection,
    fetch,
    parse_pg_array,
    segment_clause,
    sql_dialect,
    table_ref,
    to_float,
)
from godwit_source.errors import (
    MetadataUnavailableError,
    UnsupportedProbeError,
    UnsupportedSourceError,
)
from godwit_source.metadata import ColumnMetadata, SnapshotMetadata
from godwit_source.pushdown import (
    EXACT_TIER,
    aggregate_statement,
    probe_acquisition,
    result_to_values,
)
from godwit_source.semantic import infer_pii_class, infer_role
from godwit_source.sketches import SketchBuilder, SketchContext

__all__ = ["CATALOG_RELATIONS", "PAGE_BYTES", "PostgresAdapter"]

CATALOG_RELATIONS: Final[frozenset[str]] = frozenset(
    {
        "pg_stats",
        "pg_class",
        "pg_namespace",
        "pg_stat_all_tables",
        "information_schema.columns",
    }
)
"""Every relation the metadata path is allowed to touch. The zero-scan test uses this."""

PAGE_BYTES: Final[int] = 8192
"""Postgres block size. ``relpages * PAGE_BYTES`` is the planner's own size estimate,
and it is what a scanning probe is charged against its budget before it runs."""

_DIALECT = sql_dialect()

_PG_STATS = sa.table(
    "pg_stats",
    sa.column("schemaname"),
    sa.column("tablename"),
    sa.column("attname"),
    sa.column("null_frac"),
    sa.column("n_distinct"),
    sa.column("most_common_vals"),
    sa.column("most_common_freqs"),
    sa.column("histogram_bounds"),
)
_PG_CLASS = sa.table(
    "pg_class",
    sa.column("oid"),
    sa.column("relname"),
    sa.column("relnamespace"),
    sa.column("reltuples"),
    sa.column("relpages"),
)
_PG_NAMESPACE = sa.table("pg_namespace", sa.column("oid"), sa.column("nspname"))
_PG_STAT_ALL_TABLES = sa.table(
    "pg_stat_all_tables",
    sa.column("schemaname"),
    sa.column("relname"),
    sa.column("last_analyze"),
    sa.column("last_autoanalyze"),
)
_INFORMATION_SCHEMA_COLUMNS = sa.table(
    "columns",
    sa.column("table_schema"),
    sa.column("table_name"),
    sa.column("column_name"),
    sa.column("data_type"),
    sa.column("is_nullable"),
    sa.column("ordinal_position"),
    schema="information_schema",
)

_LOGICAL_BY_PG_TYPE: Final[Mapping[str, LogicalType]] = {
    "boolean": LogicalType.BOOL,
    "smallint": LogicalType.INT,
    "integer": LogicalType.INT,
    "bigint": LogicalType.INT,
    "real": LogicalType.FLOAT,
    "double precision": LogicalType.FLOAT,
    "numeric": LogicalType.DECIMAL,
    "money": LogicalType.DECIMAL,
    "character varying": LogicalType.STRING,
    "character": LogicalType.STRING,
    "text": LogicalType.STRING,
    "uuid": LogicalType.STRING,
    "date": LogicalType.DATE,
    "timestamp with time zone": LogicalType.TIMESTAMP,
    "timestamp without time zone": LogicalType.TIMESTAMP,
    "bytea": LogicalType.BINARY,
    "json": LogicalType.STRUCT,
    "jsonb": LogicalType.STRUCT,
    "ARRAY": LogicalType.LIST,
}

_SCAN_KINDS: Final[frozenset[ProbeKind]] = frozenset(
    {
        ProbeKind.ROW_COUNT,
        ProbeKind.NULL_RATE,
        ProbeKind.DISTINCT_COUNT,
        ProbeKind.COLUMN_BOUNDS,
        ProbeKind.FRESHNESS,
        ProbeKind.QUANTILES,
        ProbeKind.CATEGORY_HISTOGRAM,
        ProbeKind.HEAVY_HITTERS,
    }
)


class PostgresAdapter:
    """Reads a Postgres database through a caller-supplied DB-API connection.

    Postgres keeps no snapshot history, so :meth:`resolve_snapshot` synthesises one from
    the last ``ANALYZE``: that is genuinely the instant the statistics describe, and
    hashing it with the row-count estimate gives a stable id that changes exactly when
    the statistics change. It is an honest pseudo-snapshot and it is documented as one.
    """

    def __init__(
        self,
        connection: Connection,
        *,
        sketch_builder: SketchBuilder | None = None,
        worker_version: str = "godwit-source/0.1.0",
        profile_version: Version = 1,
    ) -> None:
        self._connection = connection
        self._sketch_builder = sketch_builder
        self._worker_version = worker_version
        self._profile_version = profile_version

    # -- snapshots ---------------------------------------------------------------------

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        """A pseudo-snapshot describing the statistics currently in the catalog.

        ``committed_at`` is the later of ``last_analyze`` and ``last_autoanalyze``. When
        the table has never been analysed there is no honest instant available, so this
        falls back to the caller's injected ``at`` and raises if there is none -- rather
        than reading a clock, which universal rule 5 forbids, or inventing one, which
        would make every replay disagree.
        """
        self._require_postgres(source)
        namespace, table = source.namespace.reveal(), source.table.reveal()
        rows = fetch(
            self._connection,
            sa.select(
                _PG_STAT_ALL_TABLES.c.last_analyze,
                _PG_STAT_ALL_TABLES.c.last_autoanalyze,
                _PG_CLASS.c.reltuples,
                _PG_CLASS.c.relpages,
            )
            .select_from(
                _PG_STAT_ALL_TABLES.join(
                    _PG_CLASS, _PG_CLASS.c.relname == _PG_STAT_ALL_TABLES.c.relname
                ).join(_PG_NAMESPACE, _PG_NAMESPACE.c.oid == _PG_CLASS.c.relnamespace)
            )
            .where(
                _PG_STAT_ALL_TABLES.c.schemaname == namespace,
                _PG_STAT_ALL_TABLES.c.relname == table,
                _PG_NAMESPACE.c.nspname == namespace,
            ),
            dialect=_DIALECT,
            source_id=source.source_id,
        )
        if not rows:
            raise MetadataUnavailableError("table is not present in the Postgres catalog")
        last_analyze, last_autoanalyze, reltuples, _relpages = rows[0]
        analysed = _latest_instant(last_analyze, last_autoanalyze) or at
        if analysed is None:
            raise MetadataUnavailableError(
                "table has never been analysed and no instant was injected; run ANALYZE or pass at="
            )
        estimate = max(0, int(to_float(reltuples) or 0.0))
        return SnapshotRef(
            source_id=source.source_id,
            snapshot_id=SnapshotId(
                content_hash(
                    canonical_json(
                        {
                            "namespace": namespace,
                            "table": table,
                            "analysed_at": analysed.isoformat(),
                            "reltuples": estimate,
                        }
                    ),
                    prefix="pgs",
                )
            ),
            sequence_number=max(0, int(analysed.timestamp())),
            committed_at=analysed,
            row_count_estimate=derived_statistic(
                estimate,
                source_id=source.source_id,
                table=table,
                population=estimate,
            ),
        )

    def list_snapshots(
        self, source: SourceRef, *, limit: int | None = None
    ) -> tuple[SnapshotRef, ...]:
        """The one pseudo-snapshot Postgres can offer.

        Postgres keeps no statistics history: each ``ANALYZE`` overwrites the last. A
        metadata time-series over a Postgres source has to be accumulated by storing
        these snapshots as they are observed -- that is L5's job, not this adapter's.
        """
        del limit
        return (self.resolve_snapshot(source),)

    # -- metadata ----------------------------------------------------------------------

    def read_metadata_stats(
        self, source: SourceRef, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> SnapshotMetadata:
        """Per-column statistics out of ``pg_stats``. No table is touched.

        Nothing is charged against ``budget``: reading the catalog costs no table pages
        and inventing a price for it would put a false number in front of the
        orchestrator's bandit.
        """
        del budget
        self._require_postgres(source)
        table = source.table.reveal()
        row_count = (
            snapshot.row_count_estimate.reveal() if snapshot.row_count_estimate is not None else 0
        )
        shapes = self._column_shapes(source)
        statistics = self._column_statistics(source)
        columns = tuple(
            self._column_metadata(
                source=source,
                snapshot=snapshot,
                name=name,
                native_type=native_type,
                nullable=nullable,
                statistics=statistics.get(name),
                row_count=row_count,
            )
            for name, native_type, nullable in shapes
        )
        return SnapshotMetadata(
            source=source,
            snapshot=snapshot,
            columns=columns,
            row_count=derived_statistic(
                row_count,
                source_id=source.source_id,
                table=table,
                snapshot_id=snapshot.snapshot_id,
                population=row_count,
            ),
            layout=None,
            observed_at=snapshot.committed_at,
            profile_version=self._profile_version,
            scanned_bytes=0,
        )

    def profile_table(
        self, source: SourceRef, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> TableProfile:
        """The L0 contract view. Catalog-derived; scans nothing."""
        return self.read_metadata_stats(source, snapshot, budget=budget).to_table_profile()

    def _column_shapes(self, source: SourceRef) -> tuple[tuple[str, str, bool], ...]:
        rows = fetch(
            self._connection,
            sa.select(
                _INFORMATION_SCHEMA_COLUMNS.c.column_name,
                _INFORMATION_SCHEMA_COLUMNS.c.data_type,
                _INFORMATION_SCHEMA_COLUMNS.c.is_nullable,
            )
            .where(
                _INFORMATION_SCHEMA_COLUMNS.c.table_schema == source.namespace.reveal(),
                _INFORMATION_SCHEMA_COLUMNS.c.table_name == source.table.reveal(),
            )
            .order_by(_INFORMATION_SCHEMA_COLUMNS.c.ordinal_position),
            dialect=_DIALECT,
            source_id=source.source_id,
        )
        return tuple(
            (str(name), str(native), str(nullable).upper() == "YES")
            for name, native, nullable in rows
        )

    def _column_statistics(self, source: SourceRef) -> Mapping[str, tuple[object, ...]]:
        rows = fetch(
            self._connection,
            sa.select(
                _PG_STATS.c.attname,
                _PG_STATS.c.null_frac,
                _PG_STATS.c.n_distinct,
                sa.cast(_PG_STATS.c.most_common_vals, sa.Text).label("most_common_vals"),
                sa.cast(_PG_STATS.c.most_common_freqs, sa.Text).label("most_common_freqs"),
                sa.cast(_PG_STATS.c.histogram_bounds, sa.Text).label("histogram_bounds"),
            ).where(
                _PG_STATS.c.schemaname == source.namespace.reveal(),
                _PG_STATS.c.tablename == source.table.reveal(),
            ),
            dialect=_DIALECT,
            source_id=source.source_id,
        )
        return {str(row[0]): tuple(row[1:]) for row in rows}

    def _column_metadata(
        self,
        *,
        source: SourceRef,
        snapshot: SnapshotRef,
        name: str,
        native_type: str,
        nullable: bool,
        statistics: tuple[object, ...] | None,
        row_count: int,
    ) -> ColumnMetadata:
        logical_type = _LOGICAL_BY_PG_TYPE.get(native_type, LogicalType.UNKNOWN)
        null_frac, n_distinct, mcv_text, freq_text, histogram_text = (
            statistics if statistics is not None else (None, None, None, None, None)
        )

        most_common = tuple(
            _coerce(item, logical_type) for item in parse_pg_array(_as_text(mcv_text))
        )
        frequencies = tuple(_as_float(item) for item in parse_pg_array(_as_text(freq_text)))
        histogram = tuple(
            _coerce(item, logical_type) for item in parse_pg_array(_as_text(histogram_text))
        )
        if len(frequencies) != len(most_common):
            frequencies = ()

        def value(raw: ScalarValue, acquisition: Acquisition) -> Tainted[ScalarValue]:
            return data_value(
                raw,
                acquisition=acquisition,
                source_id=source.source_id,
                table=source.table.reveal(),
                column=name,
                snapshot_id=snapshot.snapshot_id,
                population=row_count,
            )

        def count(raw: int) -> Tainted[int]:
            return derived_statistic(
                raw,
                source_id=source.source_id,
                table=source.table.reveal(),
                column=name,
                snapshot_id=snapshot.snapshot_id,
                population=row_count,
            )

        pii_class = infer_pii_class(
            column_name=name,
            logical_type=logical_type,
            sample_values=[item for item in most_common if item is not None],
        )
        distinct = _distinct_estimate(n_distinct, row_count)
        return ColumnMetadata(
            ref=ColumnRef(
                source_id=source.source_id,
                table=schema_name(source.table.reveal(), source_id=source.source_id),
                column=schema_name(name, source_id=source.source_id, table=source.table.reveal()),
            ),
            logical_type=logical_type,
            native_type=native_type,
            nullable=nullable,
            role=infer_role(
                column_name=name,
                logical_type=logical_type,
                pii_class=pii_class,
                distinct_estimate=distinct,
                row_count=row_count,
            ),
            pii_class=pii_class,
            row_count=count(row_count),
            null_count=(
                None
                if null_frac is None
                else count(max(0, round((to_float(null_frac) or 0.0) * row_count)))
            ),
            value_count=(
                None
                if null_frac is None
                else count(max(0, row_count - round((to_float(null_frac) or 0.0) * row_count)))
            ),
            distinct_estimate=None if distinct is None else count(distinct),
            most_common_frequencies=tuple(
                derived_statistic(
                    frequency,
                    source_id=source.source_id,
                    table=source.table.reveal(),
                    column=name,
                    snapshot_id=snapshot.snapshot_id,
                    population=row_count,
                )
                for frequency in frequencies
                if frequency is not None
            )
            if all(frequency is not None for frequency in frequencies)
            else (),
            most_common_values=tuple(value(item, Acquisition.PG_STATS_MCV) for item in most_common),
            histogram_bounds=tuple(value(item, Acquisition.QUANTILE) for item in histogram),
        )

    # -- probes ------------------------------------------------------------------------

    def execute_probe(
        self, spec: ProbeSpec, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> SketchBundle:
        """Push one aggregation down as SQL. Never ``SELECT *``; never returns rows.

        The cost charged before the query runs is ``relpages * 8192`` -- the planner's
        own estimate of the table's size on disk, read for free from ``pg_class``. It is
        an upper bound for a sequential scan and it is what invariant 6 is enforced
        against here.
        """
        if self._sketch_builder is None:
            raise UnsupportedProbeError(
                "this adapter was built without a SketchBuilder; A2 supplies one"
            )
        if spec.kind not in _SCAN_KINDS:
            raise UnsupportedProbeError(f"PostgresAdapter cannot answer a {spec.kind} probe")
        if not spec.sketches:
            raise UnsupportedProbeError("a probe spec must name at least one sketch kind")
        self._require_postgres(spec.source)

        effective = CostBudget.compose(budget, spec.budget)
        estimated = self._table_bytes(spec.source)
        effective.spend(CostSpend(bytes_scanned=estimated))

        columns = [column.reveal() for column in spec.columns]
        predicate_columns = [predicate.column.reveal() for predicate in spec.segment.predicates]
        handle = table_ref(
            spec.source.namespace.reveal(),
            spec.source.table.reveal(),
            [*columns, *predicate_columns],
        )
        statement = aggregate_statement(
            handle=handle,
            kind=spec.kind,
            columns=columns,
            params=spec.params,
            where=segment_clause(handle, spec.segment),
            profile=EXACT_TIER,
        )
        rows = fetch(self._connection, statement, dialect=_DIALECT, source_id=spec.source.source_id)
        population, values = result_to_values(spec.kind, rows)

        sketches: dict[str, SketchEnvelope] = {}
        for kind in spec.sketches:
            name = f"{kind.value}:0" if columns else f"{kind.value}:table"
            sketches[name] = self._sketch_builder.build(
                kind=kind,
                params=spec.params,
                values=values,
                context=SketchContext(
                    source_id=spec.source.source_id,
                    snapshot_id=snapshot.snapshot_id,
                    probe_key=spec.key,
                    produced_at=spec.as_of,
                    provenance=Provenance(
                        acquisition=probe_acquisition(spec.kind),
                        source_id=spec.source.source_id,
                        table=spec.source.table.reveal(),
                        column=columns[0] if columns else None,
                        snapshot_id=snapshot.snapshot_id,
                    ),
                    population=population,
                ),
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
            cost_spent=CostSpend(bytes_scanned=estimated),
            produced_at=spec.as_of,
            worker_version=self._worker_version,
            seed=spec.seed,
        )

    def _table_bytes(self, source: SourceRef) -> int:
        rows = fetch(
            self._connection,
            sa.select(_PG_CLASS.c.relpages)
            .select_from(
                _PG_CLASS.join(_PG_NAMESPACE, _PG_NAMESPACE.c.oid == _PG_CLASS.c.relnamespace)
            )
            .where(
                _PG_CLASS.c.relname == source.table.reveal(),
                _PG_NAMESPACE.c.nspname == source.namespace.reveal(),
            ),
            dialect=_DIALECT,
            source_id=source.source_id,
        )
        if not rows:
            raise MetadataUnavailableError("table is not present in the Postgres catalog")
        return max(0, int(to_float(rows[0][0]) or 0.0)) * PAGE_BYTES

    @staticmethod
    def _require_postgres(source: SourceRef) -> None:
        if source.kind is not SourceKind.POSTGRES:
            raise UnsupportedSourceError(f"PostgresAdapter cannot read a {source.kind} source")


# --------------------------------------------------------------------------------------
# Catalog value handling
# --------------------------------------------------------------------------------------


def _latest_instant(*candidates: object) -> Instant | None:
    """The latest tz-aware datetime among the arguments, or ``None``.

    A naive datetime is discarded rather than assumed UTC. Postgres returns
    ``timestamptz`` as tz-aware; a naive one means the column was ``timestamp`` and its
    zone is genuinely unknown.
    """
    found: list[_dt.datetime] = [
        item
        for item in candidates
        if isinstance(item, _dt.datetime)
        and item.tzinfo is not None
        and item.tzinfo.utcoffset(item) is not None
    ]
    return max(found).astimezone(_dt.UTC) if found else None


def _distinct_estimate(n_distinct: object, row_count: int) -> int | None:
    """Turn ``pg_stats.n_distinct`` into a count.

    Postgres encodes two things in one column: a non-negative value is a count, and a
    negative value is the negated *fraction* of rows that are distinct, which is how it
    represents a cardinality that grows with the table. Reading the second as the first
    would report ``-1`` distinct values for a unique key.
    """
    if n_distinct is None:
        return None
    value = to_float(n_distinct)
    if value is None:
        return None
    if value >= 0:
        return int(value)
    return max(0, round(-value * row_count))


def _as_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _as_float(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None


def _coerce(text: str, logical_type: LogicalType) -> ScalarValue:
    """Give a ``pg_stats`` array member back its type.

    Everything arrives as text because ``anyarray`` had to be cast. A numeric column's
    most-common values should compare as numbers, not as strings, or ``'10' < '9'``
    quietly becomes true in a bounds comparison.
    """
    if text == "NULL":
        return None
    match logical_type:
        case LogicalType.INT:
            try:
                return int(text)
            except ValueError:
                return text
        case LogicalType.FLOAT:
            try:
                return float(text)
            except ValueError:
                return text
        case LogicalType.DECIMAL:
            try:
                return Decimal(text)
            except InvalidOperation:
                return text
        case LogicalType.BOOL:
            if text in ("t", "true", "f", "false"):
                return text in ("t", "true")
            return text
        case _:
            return text
