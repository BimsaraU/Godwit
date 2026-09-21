"""Generic SQL warehouse adapter (Snowflake, BigQuery and friends).

DATA PLANE. **This is the degraded tier, and it should be sold as one.** Without Iceberg
manifests there are no free per-column bounds, no free null counts per commit and no Puffin
NDV. ``INFORMATION_SCHEMA`` gives types, a stale row count and little else, so almost every
signal has to be bought with a scan, and scan cost dominates the economics of the whole
product on this path. The free L-1 tier is roughly: schema change, row volume, and nothing
else. Tell the customer that before they choose it.

What this adapter does *not* do is fake the missing signal by scanning on the metadata path.
A metadata read that silently bills is worse than an absent one.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ._contracts import ColumnAccessMode, CostBudget, ProbeSpec, derived_statistic
from .access import AccessPolicy
from .base import (
    ProbeResult,
    SnapshotRef,
    assert_plan_is_blind_safe,
    require_readable,
    safe_backend_error,
)
from .stats import ColumnCounts, ColumnMetadata, SnapshotMetadata

__all__ = ["ApproxDialect", "WarehouseSqlAdapter"]

_INFO_SCHEMA_SQL = """
SELECT column_name, data_type
  FROM {catalog}INFORMATION_SCHEMA.COLUMNS
 WHERE table_schema = {schema_lit} AND table_name = {table_lit}
 ORDER BY ordinal_position
"""


class ApproxDialect:
    """Per-backend names for the approximate aggregates and the keyed hash.

    Defaults are ANSI-ish and work on Snowflake; BigQuery wants ``APPROX_COUNT_DISTINCT``
    and ``TO_HEX(SHA256(...))``. Supplying a dialect is cheaper than an abstraction layer.
    """

    def __init__(
        self,
        *,
        approx_count_distinct: str = "APPROX_COUNT_DISTINCT",
        hash_expr: str = "SHA2(CONCAT({key}, CAST({col} AS STRING)), 256)",
        quote: str = '"',
    ) -> None:
        self.approx_count_distinct = approx_count_distinct
        self.hash_expr = hash_expr
        self.quote = quote

    def quoted(self, name: str) -> str:
        escaped = name.replace(self.quote, self.quote * 2)
        return f"{self.quote}{escaped}{self.quote}"


class WarehouseSqlAdapter:
    """``SourceAdapter`` over a DB-API connection. Metadata is INFORMATION_SCHEMA only."""

    name = "warehouse-sql"

    def __init__(
        self,
        query: Callable[[str, Mapping[str, Any]], Sequence[Mapping[str, Any]]],
        *,
        dialect: ApproxDialect | None = None,
        catalog: str | None = None,
        hash_key_sql: str = ":godwit_key",
    ) -> None:
        self._query = query
        self._dialect = dialect or ApproxDialect()
        self._catalog = f"{catalog}." if catalog else ""
        self._hash_key_sql = hash_key_sql

    def list_snapshots(self, table: str) -> Sequence[SnapshotRef]:
        """No snapshot history without Iceberg. The caller supplies its own ordering key."""
        del table
        return ()

    def _split(self, table: str) -> tuple[str, str]:
        schema, _, name = table.rpartition(".")
        return (schema or "public", name)

    @staticmethod
    def _literal(value: str) -> str:
        """Single-quoted SQL literal. Only ever called with catalog identifiers we read back
        from INFORMATION_SCHEMA or that the operator configured -- never with row data."""
        return "'" + value.replace("'", "''") + "'"

    def read_metadata_stats(
        self,
        table: str,
        *,
        policy: AccessPolicy,
        snapshot_id: str,
        since: str | None = None,
        until: str | None = None,
    ) -> list[SnapshotMetadata]:
        """Types and column list, and honestly nothing more.

        Row counts are deliberately absent rather than estimated: warehouse row-count views
        are stale by hours on every engine worth naming, and a stale denominator turns every
        rate detector into a noise generator.
        """
        del since, until
        schema, name = self._split(table)
        sql = _INFO_SCHEMA_SQL.format(
            catalog=self._catalog,
            schema_lit=self._literal(schema),
            table_lit=self._literal(name),
        )
        try:
            rows = self._query(sql, {})
        except Exception as exc:
            raise safe_backend_error(
                exc, backend="warehouse", context="information_schema"
            ) from None

        origin = f"information_schema[{table}@{snapshot_id}]"
        all_columns = [str(r["column_name"]) for r in rows]
        columns: dict[str, ColumnMetadata] = {}
        for row in rows:
            column = str(row["column_name"])
            mode = policy.mode(column)
            if mode is ColumnAccessMode.BLIND:
                continue
            columns[column] = ColumnMetadata(
                table=table,
                column=column,
                snapshot_id=snapshot_id,
                access_mode=mode,
                data_type=str(row["data_type"]),
                counts=ColumnCounts(row_count=derived_statistic(0, origin)),
            )
        return [
            SnapshotMetadata(
                table=table,
                snapshot_id=snapshot_id,
                sequence_number=0,
                commit_ms=0,
                columns=columns,
                layout=None,
                schema_columns=tuple(all_columns),
            )
        ]

    def build_probe_sql(self, spec: ProbeSpec, *, policy: AccessPolicy) -> str:
        """Pushdown aggregate SQL with approximate distinct counts. Never ``SELECT *``."""
        require_readable(policy, spec.columns)
        dialect = self._dialect
        selects = ["COUNT(*) AS row_count"]
        for column in spec.columns:
            mode = policy.mode(column)
            quoted = dialect.quoted(column)
            expr = (
                dialect.hash_expr.format(key=self._hash_key_sql, col=quoted)
                if mode is ColumnAccessMode.OPAQUE
                else quoted
            )
            selects.append(f"COUNT({expr}) AS {dialect.quoted(column + '__non_null')}")
            selects.append(
                f"{dialect.approx_count_distinct}({expr}) AS {dialect.quoted(column + '__ndv')}"
            )
        schema, name = self._split(spec.table)
        target = f"{self._catalog}{dialect.quoted(schema)}.{dialect.quoted(name)}"
        return f"SELECT {', '.join(selects)} FROM {target}"

    def execute_probe(
        self,
        spec: ProbeSpec,
        *,
        policy: AccessPolicy,
        budget: CostBudget,
        estimated_bytes: int = 0,
    ) -> ProbeResult:
        """Run the pushdown aggregate.

        ``estimated_bytes`` comes from the engine's own dry-run facility where one exists
        (BigQuery returns it for free). Where it does not, the caller passes its best
        estimate; passing nothing means the byte budget cannot protect this query and only
        the query budget applies. Say so in the runbook rather than pretending otherwise.
        """
        sql = self.build_probe_sql(spec, policy=policy)
        assert_plan_is_blind_safe(sql, (), policy, list(spec.columns))
        if estimated_bytes:
            budget.check_bytes(estimated_bytes)
        budget.spend_query()
        try:
            rows = self._query(sql, {})
        except Exception as exc:
            raise safe_backend_error(exc, backend="warehouse", context="probe") from None
        if estimated_bytes:
            budget.spend_bytes(estimated_bytes)
        origin = f"warehouse.probe[{spec.table}@{spec.snapshot_id}]"
        record = rows[0] if rows else {}
        return ProbeResult(
            spec=spec,
            sql=sql,
            schema_names=tuple(str(k) for k in record),
            aggregates={
                str(k): derived_statistic(float(v), origin)
                for k, v in record.items()
                if v is not None
            },
            bytes_read=estimated_bytes,
            files_read=0,
        )
