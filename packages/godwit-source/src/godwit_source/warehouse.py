"""The generic warehouse adapter. DATA PLANE. **The degraded tier -- say so.**

Snowflake, BigQuery, Redshift and their relatives expose a catalog through
``INFORMATION_SCHEMA``, and nothing else for free. That is a much weaker position than
Iceberg, and it is worth being blunt about what is lost:

* **No bounds.** ``INFORMATION_SCHEMA`` gives names, types and nullability. It does not
  give per-column minimums and maximums, so ``bounds_drift`` -- the detector that finds
  the injected drift in the golden fixture without reading a byte -- has nothing to work
  with here. Getting bounds costs a scan.
* **No per-column null counts.** Only a row-count estimate, and only sometimes.
* **No NDV.** ``ndv_ratio_shift`` is silent unless somebody pays for a scan.
* **No snapshot history.** There is no commit log to walk, so a metadata time-series has
  to be accumulated by storing what we observe, rather than read out of the catalog.

What survives at L-1 is ``schema_change`` and ``row_volume_anomaly``, and on some
backends only the first. Everything else moves into the paid tier, where scan cost
dominates and the orchestrator's budget does the rationing. A customer weighing Iceberg
against a warehouse should be told this number, not a diplomatic version of it.

The adapter takes a DB-API connection and a :class:`WarehouseProfile` describing the
backend's catalog names and approximate-aggregate spellings. It does not import a
vendor driver, and adding one would put a warehouse SDK inside the perimeter for no
gain.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

import sqlalchemy as sa
from godwit_contracts.common import (
    Instant,
    SnapshotId,
    Version,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.sketch import SketchBundle, SketchEnvelope
from godwit_contracts.source import (
    ColumnRef,
    LogicalType,
    SnapshotRef,
    SourceKind,
    SourceRef,
    TableProfile,
)
from godwit_contracts.taint import Provenance, derived_statistic, schema_name
from sqlalchemy.engine.interfaces import Dialect

from godwit_source.dbapi import (
    Connection,
    fetch,
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
    SqlProfile,
    aggregate_statement,
    probe_acquisition,
    result_to_values,
)
from godwit_source.semantic import infer_pii_class, infer_role
from godwit_source.sketches import SketchBuilder, SketchContext

__all__ = ["BIGQUERY", "SNOWFLAKE", "WarehouseProfile", "WarehouseSqlAdapter"]


@dataclass(frozen=True, slots=True)
class WarehouseProfile:
    """What one warehouse family calls the things this adapter needs.

    Two presets ship because the brief names two families. A third is a dataclass
    literal, not a code change, which is the point of it being data.
    """

    name: str
    sql: SqlProfile
    columns_relation: str = "INFORMATION_SCHEMA.COLUMNS"
    tables_relation: str = "INFORMATION_SCHEMA.TABLES"
    row_count_column: str | None = None
    """Column on the tables relation carrying a row-count estimate, when there is one.

    Snowflake has ``ROW_COUNT``. BigQuery's is on a different view entirely, so the
    preset leaves it ``None`` and the row count stays unknown rather than being guessed.
    """

    dialect: Dialect = field(default_factory=sql_dialect)
    """Only used to render SQL text. The ANSI subset this adapter emits is portable;
    the dialect decides quoting and parameter style, and the caller's driver reads it."""


SNOWFLAKE: Final[WarehouseProfile] = WarehouseProfile(
    name="snowflake",
    sql=SqlProfile(approx_distinct="approx_count_distinct", approx_quantile="approx_percentile"),
    row_count_column="row_count",
)

BIGQUERY: Final[WarehouseProfile] = WarehouseProfile(
    name="bigquery",
    sql=SqlProfile(approx_distinct="approx_count_distinct", approx_quantile="approx_quantiles"),
    row_count_column=None,
)

_LOGICAL_BY_SQL_TYPE: Final[Mapping[str, LogicalType]] = {
    "boolean": LogicalType.BOOL,
    "bool": LogicalType.BOOL,
    "int64": LogicalType.INT,
    "integer": LogicalType.INT,
    "bigint": LogicalType.INT,
    "smallint": LogicalType.INT,
    "number": LogicalType.DECIMAL,
    "numeric": LogicalType.DECIMAL,
    "decimal": LogicalType.DECIMAL,
    "float": LogicalType.FLOAT,
    "float64": LogicalType.FLOAT,
    "double": LogicalType.FLOAT,
    "real": LogicalType.FLOAT,
    "string": LogicalType.STRING,
    "text": LogicalType.STRING,
    "varchar": LogicalType.STRING,
    "char": LogicalType.STRING,
    "date": LogicalType.DATE,
    "datetime": LogicalType.TIMESTAMP,
    "timestamp": LogicalType.TIMESTAMP,
    "timestamp_ntz": LogicalType.TIMESTAMP,
    "timestamp_tz": LogicalType.TIMESTAMP,
    "timestamp_ltz": LogicalType.TIMESTAMP,
    "bytes": LogicalType.BINARY,
    "binary": LogicalType.BINARY,
    "array": LogicalType.LIST,
    "struct": LogicalType.STRUCT,
    "record": LogicalType.STRUCT,
    "variant": LogicalType.STRUCT,
}


class WarehouseSqlAdapter:
    """Reads a Snowflake- or BigQuery-style warehouse through a DB-API connection.

    Read the module docstring before using this in a comparison: the free signal is
    genuinely weaker than Iceberg's and scan cost dominates.
    """

    def __init__(
        self,
        connection: Connection,
        *,
        profile: WarehouseProfile = SNOWFLAKE,
        sketch_builder: SketchBuilder | None = None,
        bytes_per_row_estimate: int = 256,
        worker_version: str = "godwit-source/0.1.0",
        profile_version: Version = 1,
    ) -> None:
        self._connection = connection
        self._profile = profile
        self._sketch_builder = sketch_builder
        self._bytes_per_row = max(1, bytes_per_row_estimate)
        self._worker_version = worker_version
        self._profile_version = profile_version

    # -- snapshots ---------------------------------------------------------------------

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        """A pseudo-snapshot, because a warehouse table has no commit log.

        ``at`` is required. There is no catalog field that honestly says when the
        current contents came to be -- ``LAST_ALTERED`` is DDL, not data -- so rather
        than reading a clock or misusing a DDL timestamp, the caller injects the instant
        it is observing at. Universal rule 5 makes that the caller's decision to record.
        """
        self._require_warehouse(source)
        if at is None:
            raise MetadataUnavailableError(
                "a warehouse table has no commit history; pass at= with the instant "
                "you are observing at"
            )
        row_count = self._row_count_estimate(source)
        return SnapshotRef(
            source_id=source.source_id,
            snapshot_id=SnapshotId(
                content_hash(
                    canonical_json(
                        {
                            "backend": self._profile.name,
                            "namespace": source.namespace.reveal(),
                            "table": source.table.reveal(),
                            "observed_at": at.isoformat(),
                            "row_count": row_count,
                        }
                    ),
                    prefix="whs",
                )
            ),
            sequence_number=max(0, int(at.timestamp())),
            committed_at=at,
            row_count_estimate=(
                None
                if row_count is None
                else derived_statistic(
                    row_count,
                    source_id=source.source_id,
                    table=source.table.reveal(),
                    population=row_count,
                )
            ),
        )

    # -- metadata ----------------------------------------------------------------------

    def read_metadata_stats(
        self, source: SourceRef, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> SnapshotMetadata:
        """Names, types and nullability from ``INFORMATION_SCHEMA``. Nothing else is free.

        Every ``ColumnMetadata`` comes back with no bounds, no null count and no NDV.
        That is not a gap to be filled in later with a guess: those fields being
        ``None`` is what tells a detector it has nothing to say, and a fabricated zero
        would make ``null_rate_shift`` report a change that never happened.
        """
        del budget
        self._require_warehouse(source)
        row_count = (
            snapshot.row_count_estimate.reveal()
            if snapshot.row_count_estimate is not None
            else None
        )
        columns = tuple(
            self._column_metadata(
                source=source,
                snapshot=snapshot,
                name=name,
                native_type=native_type,
                nullable=nullable,
                row_count=row_count,
            )
            for name, native_type, nullable in self._column_shapes(source)
        )
        return SnapshotMetadata(
            source=source,
            snapshot=snapshot,
            columns=columns,
            row_count=(
                None
                if row_count is None
                else derived_statistic(
                    row_count,
                    source_id=source.source_id,
                    table=source.table.reveal(),
                    snapshot_id=snapshot.snapshot_id,
                    population=row_count,
                )
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

    def _columns_table(self) -> sa.TableClause:
        schema, _, relation = self._profile.columns_relation.rpartition(".")
        return sa.table(
            relation,
            sa.column("table_schema"),
            sa.column("table_name"),
            sa.column("column_name"),
            sa.column("data_type"),
            sa.column("is_nullable"),
            sa.column("ordinal_position"),
            schema=schema or None,
        )

    def _tables_table(self) -> sa.TableClause:
        schema, _, relation = self._profile.tables_relation.rpartition(".")
        columns: list[sa.ColumnClause[object]] = [
            sa.column("table_schema"),
            sa.column("table_name"),
        ]
        if self._profile.row_count_column is not None:
            columns.append(sa.column(self._profile.row_count_column))
        return sa.table(relation, *columns, schema=schema or None)

    def _column_shapes(self, source: SourceRef) -> tuple[tuple[str, str, bool], ...]:
        handle = self._columns_table()
        rows = fetch(
            self._connection,
            sa.select(handle.c.column_name, handle.c.data_type, handle.c.is_nullable)
            .where(
                handle.c.table_schema == source.namespace.reveal(),
                handle.c.table_name == source.table.reveal(),
            )
            .order_by(handle.c.ordinal_position),
            dialect=self._profile.dialect,
            source_id=source.source_id,
        )
        if not rows:
            raise MetadataUnavailableError("table is not present in INFORMATION_SCHEMA")
        return tuple(
            (str(name), str(native), str(nullable).upper() == "YES")
            for name, native, nullable in rows
        )

    def _row_count_estimate(self, source: SourceRef) -> int | None:
        if self._profile.row_count_column is None:
            return None
        handle = self._tables_table()
        rows = fetch(
            self._connection,
            sa.select(handle.c[self._profile.row_count_column]).where(
                handle.c.table_schema == source.namespace.reveal(),
                handle.c.table_name == source.table.reveal(),
            ),
            dialect=self._profile.dialect,
            source_id=source.source_id,
        )
        if not rows or rows[0][0] is None:
            return None
        return max(0, int(to_float(rows[0][0]) or 0.0))

    def _column_metadata(
        self,
        *,
        source: SourceRef,
        snapshot: SnapshotRef,
        name: str,
        native_type: str,
        nullable: bool,
        row_count: int | None,
    ) -> ColumnMetadata:
        logical_type = _LOGICAL_BY_SQL_TYPE.get(
            native_type.split("(", maxsplit=1)[0].strip().casefold(), LogicalType.UNKNOWN
        )
        pii_class = infer_pii_class(column_name=name, logical_type=logical_type)
        return ColumnMetadata(
            ref=ColumnRef(
                source_id=source.source_id,
                table=schema_name(source.table.reveal(), source_id=source.source_id),
                column=schema_name(name, source_id=source.source_id, table=source.table.reveal()),
            ),
            logical_type=logical_type,
            native_type=native_type,
            nullable=nullable,
            role=infer_role(column_name=name, logical_type=logical_type, pii_class=pii_class),
            pii_class=pii_class,
            row_count=(
                None
                if row_count is None
                else derived_statistic(
                    row_count,
                    source_id=source.source_id,
                    table=source.table.reveal(),
                    column=name,
                    snapshot_id=snapshot.snapshot_id,
                    population=row_count,
                )
            ),
        )

    # -- probes ------------------------------------------------------------------------

    def execute_probe(
        self, spec: ProbeSpec, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> SketchBundle:
        """Push one approximate aggregation down as SQL.

        The budget is charged before the query runs, against the crudest honest estimate
        available: the catalog's row count times ``bytes_per_row_estimate``. When the
        catalog has no row count -- BigQuery -- there is no estimate to charge, and the
        probe is refused rather than run blind. Invariant 6 says refusing is a normal
        outcome; running an unbounded query against a per-byte biller is not.
        """
        if self._sketch_builder is None:
            raise UnsupportedProbeError(
                "this adapter was built without a SketchBuilder; A2 supplies one"
            )
        if not spec.sketches:
            raise UnsupportedProbeError("a probe spec must name at least one sketch kind")
        self._require_warehouse(spec.source)

        row_count = self._row_count_estimate(spec.source)
        if row_count is None:
            raise UnsupportedProbeError(
                f"{self._profile.name} exposes no row-count estimate, so a scan cannot be "
                "bounded before it runs; supply a bounded segment and a catalog that does"
            )
        estimated = row_count * self._bytes_per_row
        CostBudget.compose(budget, spec.budget).spend(CostSpend(bytes_scanned=estimated))

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
            profile=self._profile.sql,
        )
        rows = fetch(
            self._connection,
            statement,
            dialect=self._profile.dialect,
            source_id=spec.source.source_id,
        )
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

    @staticmethod
    def _require_warehouse(source: SourceRef) -> None:
        if source.kind not in (SourceKind.DUCKDB, SourceKind.PARQUET, SourceKind.POSTGRES):
            raise UnsupportedSourceError(
                f"WarehouseSqlAdapter addresses SQL-reachable sources; {source.kind} is not one"
            )
