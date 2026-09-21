"""WarehouseSqlAdapter: the degraded tier, and honest about it."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from godwit_source._contracts import (
    ColumnAccessMode,
    CostBudget,
    CostBudgetExceeded,
    PiiClass,
    ProbeSpec,
)
from godwit_source.access import AccessPolicy, BlindColumnError, ColumnClassification
from godwit_source.warehouse import ApproxDialect, WarehouseSqlAdapter

INFO_ROWS = [
    {"column_name": "order_id", "data_type": "NUMBER"},
    {"column_name": "customer_email", "data_type": "TEXT"},
    {"column_name": "device_id", "data_type": "TEXT"},
    {"column_name": "internal_notes", "data_type": "TEXT"},
]


class RecordingQuery:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def __call__(self, sql: str, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        self.statements.append(sql)
        if "INFORMATION_SCHEMA" in sql:
            return INFO_ROWS
        return [{"row_count": 7.0, "device_id__ndv": 3.0}]


def policy() -> AccessPolicy:
    return AccessPolicy(
        [
            ColumnClassification("order_id", PiiClass.NON_PII, confirmed=True,
                                 requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-1"),
            ColumnClassification("customer_email", PiiClass.DIRECT_IDENTIFIER, confirmed=True,
                                 requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-2"),
            ColumnClassification("device_id", PiiClass.DIRECT_IDENTIFIER, confirmed=True,
                                 input_space_bits=80.0),
            ColumnClassification("internal_notes", PiiClass.FREE_TEXT, confirmed=True),
        ]
    )


def test_metadata_path_reads_information_schema_only() -> None:
    query = RecordingQuery()
    WarehouseSqlAdapter(query).read_metadata_stats(
        "sales.orders", policy=policy(), snapshot_id="s1"
    )
    assert len(query.statements) == 1
    assert "INFORMATION_SCHEMA.COLUMNS" in query.statements[0]
    assert "sales" not in query.statements[0].split("FROM")[1].split("WHERE")[0]


def test_degraded_tier_reports_no_row_count() -> None:
    """Stale warehouse row-count views turn every rate detector into a noise generator, so
    the adapter reports nothing rather than something wrong."""
    snap = WarehouseSqlAdapter(RecordingQuery()).read_metadata_stats(
        "sales.orders", policy=policy(), snapshot_id="s1"
    )[0]
    assert snap.layout is None
    assert snap.columns["order_id"].counts.row_count.unwrap("test") == 0
    assert snap.columns["order_id"].counts.ndv is None
    assert snap.columns["order_id"].bounds is None


def test_blind_column_absent_from_metadata_and_sql() -> None:
    adapter = WarehouseSqlAdapter(RecordingQuery())
    snap = adapter.read_metadata_stats("sales.orders", policy=policy(), snapshot_id="s1")[0]
    assert "internal_notes" not in snap.columns

    spec = ProbeSpec(
        table="sales.orders",
        columns=("order_id", "device_id"),
        snapshot_id="s1",
        version="1",
        seed=0,
    )
    sql = adapter.build_probe_sql(spec, policy=policy())
    assert "internal_notes" not in sql


def test_probe_sql_hashes_opaque_and_uses_approximate_distinct() -> None:
    adapter = WarehouseSqlAdapter(RecordingQuery())
    spec = ProbeSpec(
        table="sales.orders",
        columns=("order_id", "device_id"),
        snapshot_id="s1",
        version="1",
        seed=0,
    )
    sql = adapter.build_probe_sql(spec, policy=policy())
    assert "APPROX_COUNT_DISTINCT" in sql
    assert "SHA2" in sql
    assert 'COUNT("device_id")' not in sql
    assert sql.startswith("SELECT COUNT(*) AS row_count")


def test_dialect_is_swappable_without_an_abstraction_layer() -> None:
    bigquery = ApproxDialect(
        approx_count_distinct="APPROX_COUNT_DISTINCT",
        hash_expr="TO_HEX(SHA256(CONCAT({key}, CAST({col} AS STRING))))",
        quote="`",
    )
    adapter = WarehouseSqlAdapter(RecordingQuery(), dialect=bigquery, catalog="proj")
    spec = ProbeSpec(
        table="sales.orders", columns=("device_id",), snapshot_id="s1", version="1", seed=0
    )
    sql = adapter.build_probe_sql(spec, policy=policy())
    assert "TO_HEX(SHA256(" in sql
    assert "`device_id`" in sql
    assert "FROM proj.`sales`.`orders`" in sql


def test_probe_refuses_blind_column() -> None:
    adapter = WarehouseSqlAdapter(RecordingQuery())
    spec = ProbeSpec(
        table="sales.orders", columns=("internal_notes",), snapshot_id="s1", version="1", seed=0
    )
    with pytest.raises(BlindColumnError):
        adapter.build_probe_sql(spec, policy=policy())


def test_byte_budget_applies_only_when_an_estimate_exists() -> None:
    adapter = WarehouseSqlAdapter(RecordingQuery())
    spec = ProbeSpec(
        table="sales.orders", columns=("order_id",), snapshot_id="s1", version="1", seed=0
    )
    with pytest.raises(CostBudgetExceeded):
        adapter.execute_probe(
            spec,
            policy=policy(),
            budget=CostBudget(max_bytes=1_000, max_queries=5),
            estimated_bytes=10_000,
        )
    # No estimate means only the query budget can protect this call. Documented, not hidden.
    result = adapter.execute_probe(
        spec, policy=policy(), budget=CostBudget(max_bytes=1_000, max_queries=5)
    )
    assert result.bytes_read == 0


def test_driver_errors_are_replaced() -> None:
    def exploding(sql: str, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        raise RuntimeError("invalid identifier (customer_email)=(ada@example.org)")

    with pytest.raises(RuntimeError) as excinfo:
        WarehouseSqlAdapter(exploding).read_metadata_stats(
            "sales.orders", policy=policy(), snapshot_id="s1"
        )
    assert "ada@example.org" not in str(excinfo.value)
