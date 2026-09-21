"""PostgreSQL source adapter.

DATA PLANE. The metadata path reads ``pg_stats``, ``pg_class.reltuples`` and
``information_schema.columns``, and scans no table -- there is a test that asserts the
generated SQL never touches the user table at all.

**``pg_stats.most_common_vals`` is literally a list of the most common actual values in the
column**, and ``histogram_bounds`` is a list of real values at the quantile boundaries. Both
are ``Tainted[DATA_VALUE]`` on read. For an ``OPAQUE`` column they are discarded inside the
row loop, before they are placed in any structure, so there is never an object holding them
that someone could forget to redact.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ._contracts import (
    ColumnAccessMode,
    CostBudget,
    ProbeSpec,
    Tainted,
    data_value,
    derived_statistic,
)
from .access import AccessPolicy
from .base import (
    ProbeResult,
    SnapshotRef,
    assert_plan_is_blind_safe,
    require_readable,
    safe_backend_error,
)
from .stats import ColumnCounts, ColumnMetadata, CommonValue, SnapshotMetadata

__all__ = ["PostgresAdapter", "QueryFn"]

QueryFn = Callable[[str, Mapping[str, Any]], Sequence[Mapping[str, Any]]]
"""``(sql, params) -> rows``. Injected so the adapter is testable and so the SQL text is
always available to assert on."""

_STATS_SQL = """
SELECT s.attname,
       s.null_frac,
       s.n_distinct,
       s.most_common_vals::text[] AS most_common_vals,
       s.most_common_freqs,
       s.histogram_bounds::text[] AS histogram_bounds,
       c.data_type
  FROM pg_stats AS s
  JOIN information_schema.columns AS c
    ON c.table_schema = s.schemaname
   AND c.table_name = s.tablename
   AND c.column_name = s.attname
 WHERE s.schemaname = %(schema)s
   AND s.tablename = %(table)s
   AND s.attname = ANY(%(columns)s)
 ORDER BY s.attname
"""

_RELTUPLES_SQL = """
SELECT GREATEST(c.reltuples, 0)::bigint AS row_count
  FROM pg_class AS c
  JOIN pg_namespace AS n ON n.oid = c.relnamespace
 WHERE n.nspname = %(schema)s AND c.relname = %(table)s
"""

_SCHEMA_SQL = """
SELECT column_name, data_type
  FROM information_schema.columns
 WHERE table_schema = %(schema)s AND table_name = %(table)s
 ORDER BY ordinal_position
"""


def _split_table(table: str) -> tuple[str, str]:
    schema, _, name = table.rpartition(".")
    return (schema or "public", name)


class PostgresAdapter:
    """``SourceAdapter`` over PostgreSQL. Free statistics, pushdown probes."""

    name = "postgres"

    def __init__(self, query: QueryFn, *, hash_key_param: str = "godwit_key") -> None:
        self._query = query
        self._hash_key_param = hash_key_param

    def list_snapshots(self, table: str) -> Sequence[SnapshotRef]:
        """Postgres has no snapshot history.

        Returning an empty sequence rather than inventing one keeps the caller honest: a
        Postgres metadata series is built by calling :meth:`read_metadata_stats` repeatedly
        with an externally supplied ``snapshot_id``, and there is no wall-clock read here
        that could make two replays differ.
        """
        del table
        return ()

    def schema(self, table: str) -> dict[str, str]:
        """Column name to SQL type, from ``information_schema``. No table access."""
        schema, name = _split_table(table)
        rows = self._query(_SCHEMA_SQL, {"schema": schema, "table": name})
        return {str(r["column_name"]): str(r["data_type"]) for r in rows}

    def read_metadata_stats(
        self,
        table: str,
        *,
        policy: AccessPolicy,
        snapshot_id: str,
        since: str | None = None,
        until: str | None = None,
    ) -> list[SnapshotMetadata]:
        """One snapshot's worth of free statistics. ``snapshot_id`` is supplied, not read
        from a clock, so a replay of the same catalog state reproduces the same series."""
        del since, until
        schema, name = _split_table(table)
        all_columns = self.schema(table)
        readable = [c for c in all_columns if not policy.is_blind(c)]
        if not readable:
            return [
                SnapshotMetadata(
                    table=table,
                    snapshot_id=snapshot_id,
                    sequence_number=0,
                    commit_ms=0,
                    columns={},
                    schema_columns=tuple(all_columns),
                )
            ]

        params = {"schema": schema, "table": name, "columns": readable}
        # The column list is the plan here: pg_stats is filtered server-side by attname, so
        # a BLIND column's statistics are never fetched, not fetched and discarded.
        assert_plan_is_blind_safe(repr(readable), readable, policy, list(all_columns))
        try:
            rows = self._query(_STATS_SQL, params)
            reltuples = self._query(_RELTUPLES_SQL, {"schema": schema, "table": name})
        except Exception as exc:
            raise safe_backend_error(exc, backend="postgres", context="pg_stats read") from None

        row_count = int(reltuples[0]["row_count"]) if reltuples else 0
        origin = f"pg_stats[{table}@{snapshot_id}]"
        columns: dict[str, ColumnMetadata] = {}
        for row in rows:
            column = str(row["attname"])
            mode = policy.mode(column)
            if mode is ColumnAccessMode.BLIND:  # pragma: no cover - filtered by the query
                continue
            columns[column] = self._column_metadata(
                table, snapshot_id, column, mode, row, row_count, origin
            )

        return [
            SnapshotMetadata(
                table=table,
                snapshot_id=snapshot_id,
                sequence_number=0,
                commit_ms=0,
                columns=columns,
                schema_columns=tuple(all_columns),
            )
        ]

    def _column_metadata(
        self,
        table: str,
        snapshot_id: str,
        column: str,
        mode: ColumnAccessMode,
        row: Mapping[str, Any],
        row_count: int,
        origin: str,
    ) -> ColumnMetadata:
        null_frac = float(row.get("null_frac") or 0.0)
        n_distinct = float(row.get("n_distinct") or 0.0)
        # Negative n_distinct is a ratio of row count, per the pg_stats contract.
        ndv = round(-n_distinct * row_count) if n_distinct < 0 else round(n_distinct)

        common: tuple[CommonValue, ...] = ()
        histogram: tuple[Tainted[object], ...] = ()
        if mode is ColumnAccessMode.OPEN:
            common = self._common_values(row, origin)
            histogram = tuple(
                data_value(v, f"{origin}.histogram_bounds")
                for v in (row.get("histogram_bounds") or [])
            )
        # For OPAQUE the branch above never ran: most_common_vals and histogram_bounds are
        # dropped here, inside the loop, and never enter a structure.

        return ColumnMetadata(
            table=table,
            column=column,
            snapshot_id=snapshot_id,
            access_mode=mode,
            data_type=str(row.get("data_type", "unknown")),
            counts=ColumnCounts(
                row_count=derived_statistic(row_count, origin),
                null_count=derived_statistic(round(null_frac * row_count), origin),
                value_count=derived_statistic(round((1.0 - null_frac) * row_count), origin),
                ndv=derived_statistic(max(ndv, 0), f"{origin}.n_distinct"),
            ),
            bounds=None,
            common_values=common,
            histogram_bounds=histogram,
        )

    @staticmethod
    def _common_values(row: Mapping[str, Any], origin: str) -> tuple[CommonValue, ...]:
        values = list(row.get("most_common_vals") or [])
        freqs = list(row.get("most_common_freqs") or [])
        return tuple(
            CommonValue(
                value=data_value(value, f"{origin}.most_common_vals"),
                frequency=derived_statistic(float(freq), f"{origin}.most_common_freqs"),
            )
            for value, freq in zip(values, freqs, strict=False)
        )

    def build_probe_sql(self, spec: ProbeSpec, *, policy: AccessPolicy) -> str:
        """Aggregation pushdown. Never ``SELECT *``, never a bare column in the output.

        Every projected column is wrapped in an aggregate, so the result set has one row by
        construction: there is no shape of this query that could return rows.
        """
        require_readable(policy, spec.columns)
        projections = policy.plan(spec.columns)
        selects = ["count(*) AS row_count"]
        for proj in projections:
            selects.append(f'count({proj.sql}) AS "{proj.column}__non_null"')
            selects.append(f'count(DISTINCT {proj.sql}) AS "{proj.column}__ndv"')
        schema, name = _split_table(spec.table)
        return f'SELECT {", ".join(selects)} FROM "{schema}"."{name}"'

    def execute_probe(
        self,
        spec: ProbeSpec,
        *,
        policy: AccessPolicy,
        budget: CostBudget,
    ) -> ProbeResult:
        """Run the pushdown aggregate. One query, one row, no values.

        ``OPAQUE`` columns are aggregated through the keyed-hash expression built by
        :class:`~godwit_source.access.AccessPolicy`, so the server never returns the value
        and the key never leaves the data plane.
        """
        sql = self.build_probe_sql(spec, policy=policy)
        assert_plan_is_blind_safe(sql, (), policy, list(spec.columns))
        budget.spend_query()
        try:
            rows = self._query(sql, {})
        except Exception as exc:
            raise safe_backend_error(exc, backend="postgres", context="probe") from None
        origin = f"postgres.probe[{spec.table}@{spec.snapshot_id}]"
        record = rows[0] if rows else {}
        aggregates = {
            str(k): derived_statistic(float(v), origin)
            for k, v in record.items()
            if v is not None
        }
        return ProbeResult(
            spec=spec,
            sql=sql,
            schema_names=tuple(str(k) for k in record),
            aggregates=aggregates,
            bytes_read=0,
            files_read=0,
        )
