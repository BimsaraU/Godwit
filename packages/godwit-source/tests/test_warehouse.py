"""The warehouse adapter, and an honest account of what it cannot do.

These tests exist as much to pin the degradation as to check the code. A customer
choosing between Iceberg and Snowflake should be able to read this file and see exactly
which detectors go quiet.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Sequence
from decimal import Decimal

import pytest
from godwit_contracts.common import SourceId
from godwit_contracts.cost import CostBudget
from godwit_contracts.errors import BudgetExceededError
from godwit_contracts.probe import ProbeId, ProbeKind, ProbeSpec
from godwit_contracts.segment import Segment
from godwit_contracts.sketch import SketchKind
from godwit_contracts.source import LogicalType, PiiClass, SourceKind, SourceRef
from godwit_contracts.taint import schema_name
from godwit_source.detectors import bounds_drift, ndv_ratio_shift, null_rate_shift, schema_change
from godwit_source.errors import MetadataUnavailableError, UnsupportedProbeError
from godwit_source.warehouse import BIGQUERY, SNOWFLAKE, WarehouseSqlAdapter

from .conftest import RecordingConnection, StubSketchBuilder

SOURCE_ID = SourceId("wh")
OBSERVED = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)

SOURCE = SourceRef(
    source_id=SOURCE_ID,
    kind=SourceKind.DUCKDB,
    catalog="warehouse",
    namespace=schema_name("analytics", source_id=SOURCE_ID),
    table=schema_name("orders", source_id=SOURCE_ID),
)

BUDGET = CostBudget(
    bytes_scanned=100_000_000,
    wall_seconds=60.0,
    usd=Decimal("1"),
    llm_tokens=0,
    train_seconds=0.0,
)

COLUMNS: Sequence[Sequence[object]] = [
    ("order_id", "STRING", "NO"),
    ("customer_email", "STRING", "YES"),
    ("amount", "NUMBER(18,2)", "YES"),
    ("created_at", "TIMESTAMP_NTZ", "YES"),
]


def snowflake_connection(row_count: int = 5000) -> RecordingConnection:
    return RecordingConnection(script=[[(row_count,)], list(COLUMNS)])


def test_information_schema_is_the_only_free_source() -> None:
    connection = snowflake_connection()
    adapter = WarehouseSqlAdapter(connection, profile=SNOWFLAKE)
    snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED)
    adapter.read_metadata_stats(SOURCE, snapshot, budget=BUDGET)

    for statement in connection.sql:
        targets = {
            match.group(1).replace('"', "").upper()
            for match in re.finditer(r"FROM\s+([\w.\"]+)", statement, flags=re.IGNORECASE)
        }
        assert targets <= {"INFORMATION_SCHEMA.COLUMNS", "INFORMATION_SCHEMA.TABLES"}


def test_the_free_tier_has_no_bounds_no_nulls_and_no_ndv() -> None:
    """The degradation, stated as a test rather than as a caveat in a slide.

    Every one of these being ``None`` is load-bearing: a fabricated zero would make
    ``null_rate_shift`` report a change that never happened.
    """
    adapter = WarehouseSqlAdapter(snowflake_connection(), profile=SNOWFLAKE)
    snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED)
    metadata = adapter.read_metadata_stats(SOURCE, snapshot, budget=BUDGET)

    for column in metadata.columns:
        assert column.lower_bound is None
        assert column.upper_bound is None
        assert column.null_count is None
        assert column.distinct_estimate is None
        assert column.most_common_values == ()
    assert metadata.layout is None
    assert metadata.scanned_bytes == 0


def test_the_detectors_that_survive_the_degraded_tier() -> None:
    """``schema_change`` still works. ``bounds_drift`` and friends go quiet."""
    history = []
    for index in range(3):
        adapter = WarehouseSqlAdapter(snowflake_connection(5000 + index), profile=SNOWFLAKE)
        snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED + _dt.timedelta(days=7 * index))
        history.append(adapter.read_metadata_stats(SOURCE, snapshot, budget=BUDGET))

    assert bounds_drift(history, code_version="wh", seed=1) == ()
    assert null_rate_shift(history, code_version="wh", seed=1) == ()
    assert ndv_ratio_shift(history, code_version="wh", seed=1) == ()
    assert schema_change(history, code_version="wh", seed=1) == ()

    shrunk = [*history[:2], history[2].model_copy(update={"columns": history[2].columns[:2]})]
    assert len(schema_change(shrunk, code_version="wh", seed=1)) == 1


def test_types_and_pii_classes_are_still_inferred() -> None:
    """Names and types are free everywhere, so L0 is not degraded -- only L-1 is."""
    adapter = WarehouseSqlAdapter(snowflake_connection(), profile=SNOWFLAKE)
    snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED)
    metadata = adapter.read_metadata_stats(SOURCE, snapshot, budget=BUDGET)

    types = {column.ref.column.reveal(): column.logical_type for column in metadata.columns}
    assert types["amount"] is LogicalType.DECIMAL
    assert types["created_at"] is LogicalType.TIMESTAMP
    assert types["order_id"] is LogicalType.STRING

    classes = {column.ref.column.reveal(): column.pii_class for column in metadata.columns}
    assert classes["customer_email"] is PiiClass.DIRECT_IDENTIFIER
    assert classes["amount"] is PiiClass.FINANCIAL


def test_a_snapshot_needs_an_injected_instant() -> None:
    """There is no catalog field that honestly dates a warehouse table's contents."""
    adapter = WarehouseSqlAdapter(snowflake_connection(), profile=SNOWFLAKE)
    with pytest.raises(MetadataUnavailableError, match="no commit history"):
        adapter.resolve_snapshot(SOURCE)


def test_the_snapshot_id_changes_when_the_row_count_does() -> None:
    first = WarehouseSqlAdapter(snowflake_connection(5000), profile=SNOWFLAKE).resolve_snapshot(
        SOURCE, at=OBSERVED
    )
    same = WarehouseSqlAdapter(snowflake_connection(5000), profile=SNOWFLAKE).resolve_snapshot(
        SOURCE, at=OBSERVED
    )
    moved = WarehouseSqlAdapter(snowflake_connection(6000), profile=SNOWFLAKE).resolve_snapshot(
        SOURCE, at=OBSERVED
    )
    assert first.snapshot_id == same.snapshot_id
    assert first.snapshot_id != moved.snapshot_id


def test_bigquery_has_no_row_count_and_says_so(stub_builder: StubSketchBuilder) -> None:
    """A probe that cannot be bounded before it runs is refused, not attempted.

    BigQuery bills per byte scanned. Running an unbounded query against a per-byte
    biller because we had no estimate is exactly the failure invariant 6 exists to stop.
    """
    connection = RecordingConnection(script=[list(COLUMNS)])
    adapter = WarehouseSqlAdapter(connection, profile=BIGQUERY, sketch_builder=stub_builder)
    snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED)
    assert snapshot.row_count_estimate is None

    with pytest.raises(UnsupportedProbeError, match="no row-count estimate"):
        adapter.execute_probe(_probe(ProbeKind.ROW_COUNT), snapshot, budget=BUDGET)


def _probe(kind: ProbeKind, *, columns: tuple[str, ...] = ()) -> ProbeSpec:
    return ProbeSpec(
        probe_id=ProbeId("wh-probe"),
        kind=kind,
        spec_version=1,
        source=SOURCE,
        columns=tuple(schema_name(name, source_id=SOURCE_ID, table="orders") for name in columns),
        segment=Segment(),
        sketches=(SketchKind.THETA,),
        params={},
        budget=BUDGET,
        seed=11,
        as_of=OBSERVED,
    )


def test_an_approximate_aggregate_is_used_where_one_exists(
    stub_builder: StubSketchBuilder,
) -> None:
    """Snowflake's ``approx_count_distinct``, not an exact ``count(DISTINCT ...)``."""
    connection = RecordingConnection(script=[[(5000,)], [(5000,)], [(4321,)]])
    adapter = WarehouseSqlAdapter(connection, profile=SNOWFLAKE, sketch_builder=stub_builder)
    snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED)
    bundle = adapter.execute_probe(
        _probe(ProbeKind.DISTINCT_COUNT, columns=("customer_email",)), snapshot, budget=BUDGET
    )

    pushdown = connection.sql[-1]
    assert "approx_count_distinct" in pushdown.lower()
    assert "count(distinct" not in pushdown.lower()
    assert bundle.sketches["theta:0"].population == 4321


def test_a_warehouse_probe_refuses_rather_than_overspends(
    stub_builder: StubSketchBuilder,
) -> None:
    connection = RecordingConnection(script=[[(5000,)], [(5000,)]])
    adapter = WarehouseSqlAdapter(
        connection, profile=SNOWFLAKE, sketch_builder=stub_builder, bytes_per_row_estimate=1024
    )
    snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED)
    tight = BUDGET.model_copy(update={"bytes_scanned": 1000})
    with pytest.raises(BudgetExceededError, match="bytes_scanned"):
        adapter.execute_probe(_probe(ProbeKind.ROW_COUNT), snapshot, budget=tight)
    assert stub_builder.calls == []


def test_a_missing_table_is_reported_not_invented() -> None:
    adapter = WarehouseSqlAdapter(RecordingConnection(script=[[(5000,)], []]), profile=SNOWFLAKE)
    snapshot = adapter.resolve_snapshot(SOURCE, at=OBSERVED)
    with pytest.raises(MetadataUnavailableError, match="INFORMATION_SCHEMA"):
        adapter.read_metadata_stats(SOURCE, snapshot, budget=BUDGET)
