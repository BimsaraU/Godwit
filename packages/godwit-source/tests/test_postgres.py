"""The Postgres adapter: free statistics, zero scans, and two more leak paths.

``pg_stats.most_common_vals`` and ``histogram_bounds`` are the reason this adapter needs
as much care as the Iceberg one. They are advertised as statistics and they are lists of
customer values.

The zero-scan claim is checked against a recording connection rather than a database:
every statement the metadata path issues is captured and its target relation checked
against :data:`CATALOG_RELATIONS`. A live Postgres could not prove this any better and
would need docker to prove it at all.
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
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.sketch import SketchKind
from godwit_contracts.source import PiiClass, SourceKind, SourceRef
from godwit_contracts.taint import Acquisition, Sensitivity, data_value, schema_name
from godwit_source.dbapi import parse_pg_array
from godwit_source.errors import SanitisedDriverError, UnsupportedProbeError, UnsupportedSourceError
from godwit_source.postgres import CATALOG_RELATIONS, PAGE_BYTES, PostgresAdapter
from hypothesis import given, settings
from hypothesis import strategies as st

from .conftest import RecordingConnection, StubSketchBuilder

# Hypothesis' default 200 ms per-example deadline is a wall-clock check, and a
# wall-clock check is exactly the nondeterminism universal rule 5 forbids: these
# tests fail on a loaded machine and pass on a quiet one, which is a flake rather
# than a finding. Deadlines are off; what the property asserts is unchanged.
NO_DEADLINE = settings(deadline=None)

SOURCE_ID = SourceId("pg")
ANALYSED = _dt.datetime(2024, 1, 1, 12, 0, tzinfo=_dt.UTC)

SOURCE = SourceRef(
    source_id=SOURCE_ID,
    kind=SourceKind.POSTGRES,
    catalog="local",
    namespace=schema_name("godwit_golden_pii", source_id=SOURCE_ID),
    table=schema_name("customers", source_id=SOURCE_ID),
)

BUDGET = CostBudget(
    bytes_scanned=10_000_000,
    wall_seconds=60.0,
    usd=Decimal("1"),
    llm_tokens=0,
    train_seconds=0.0,
)

SNAPSHOT_ROWS: Sequence[Sequence[object]] = [(ANALYSED, None, 12.0, 1)]

COLUMN_ROWS: Sequence[Sequence[object]] = [
    ("customer_ssn", "text", "NO"),
    ("patient_hiv_status", "text", "YES"),
    ("salary_2024", "bigint", "YES"),
    ("merchant_name", "text", "YES"),
]

STATS_ROWS: Sequence[Sequence[object]] = [
    ("customer_ssn", 0.0, -1.0, "{100-40-1000,111-51-1077}", "{0.5,0.5}", "{100-40-1000}"),
    (
        "patient_hiv_status",
        0.0,
        3.0,
        "{negative,unknown,positive}",
        "{0.5,0.3,0.2}",
        None,
    ),
    ("salary_2024", 0.25, -0.5, "{41000,75100}", "{0.6,0.4}", "{41000,58050,75100}"),
    ("merchant_name", 0.0, 2.0, "{ACME_CORP}", "{0.9}", None),
]


def scripted() -> RecordingConnection:
    """A connection that answers the three metadata queries in the order they are asked."""
    return RecordingConnection(script=[list(SNAPSHOT_ROWS), list(COLUMN_ROWS), list(STATS_ROWS)])


def relations(sql: str) -> set[str]:
    """Every relation named after FROM or JOIN in one statement."""
    return {
        match.group(1).strip('"').replace('"', "")
        for match in re.finditer(r"(?:FROM|JOIN)\s+([\w.\"]+)", sql, flags=re.IGNORECASE)
    }


# --------------------------------------------------------------------------------------
# Zero table scans
# --------------------------------------------------------------------------------------


def test_the_metadata_path_touches_only_catalog_relations() -> None:
    """The economic argument for L-1, asserted.

    Every relation the metadata path reads is a catalog relation. Not "mostly", and not
    "except for a quick count": a single ``SELECT count(*)`` here would turn the free
    tier into a billed one on every table in the warehouse.
    """
    connection = scripted()
    adapter = PostgresAdapter(connection)
    snapshot = adapter.resolve_snapshot(SOURCE)
    metadata = adapter.read_metadata_stats(SOURCE, snapshot, budget=BUDGET)

    assert metadata.scanned_bytes == 0
    assert connection.sql, "the adapter issued no statements at all"
    for statement in connection.sql:
        touched = relations(statement)
        assert touched, f"could not parse the target of {statement!r}"
        assert touched <= CATALOG_RELATIONS, f"{statement!r} reads {touched - CATALOG_RELATIONS}"
        assert "customers" not in statement, "the customer table itself was queried"


def test_no_statement_selects_star() -> None:
    connection = scripted()
    adapter = PostgresAdapter(connection)
    adapter.read_metadata_stats(SOURCE, adapter.resolve_snapshot(SOURCE), budget=BUDGET)
    for statement in connection.sql:
        assert "SELECT *" not in statement.upper().replace("\n", " ")


# --------------------------------------------------------------------------------------
# Taint
# --------------------------------------------------------------------------------------


def test_most_common_values_are_tainted_as_the_leak_path_they_are() -> None:
    connection = scripted()
    adapter = PostgresAdapter(connection)
    metadata = adapter.read_metadata_stats(SOURCE, adapter.resolve_snapshot(SOURCE), budget=BUDGET)

    ssn = metadata.column("customer_ssn")
    assert ssn is not None
    assert len(ssn.most_common_values) == 2
    for value in ssn.most_common_values:
        assert value.sensitivity is Sensitivity.DATA_VALUE
        assert value.provenance.acquisition is Acquisition.PG_STATS_MCV
    assert {value.reveal() for value in ssn.most_common_values} == {
        "100-40-1000",
        "111-51-1077",
    }


def test_histogram_bounds_are_tainted_as_quantiles() -> None:
    """The median salary of a twelve-person team is nearly one person's salary."""
    connection = scripted()
    adapter = PostgresAdapter(connection)
    metadata = adapter.read_metadata_stats(SOURCE, adapter.resolve_snapshot(SOURCE), budget=BUDGET)

    salary = metadata.column("salary_2024")
    assert salary is not None
    assert [value.reveal() for value in salary.histogram_bounds] == [41000, 58050, 75100]
    for value in salary.histogram_bounds:
        assert value.sensitivity is Sensitivity.DATA_VALUE
        assert value.provenance.acquisition is Acquisition.QUANTILE


def test_frequencies_are_statistics_not_values() -> None:
    connection = scripted()
    adapter = PostgresAdapter(connection)
    metadata = adapter.read_metadata_stats(SOURCE, adapter.resolve_snapshot(SOURCE), budget=BUDGET)
    status = metadata.column("patient_hiv_status")
    assert status is not None
    assert [value.reveal() for value in status.most_common_frequencies] == [0.5, 0.3, 0.2]
    for frequency in status.most_common_frequencies:
        assert frequency.sensitivity is Sensitivity.DERIVED_STATISTIC


def test_column_names_drive_a_first_pass_pii_class() -> None:
    connection = scripted()
    adapter = PostgresAdapter(connection)
    metadata = adapter.read_metadata_stats(SOURCE, adapter.resolve_snapshot(SOURCE), budget=BUDGET)
    classes = {column.ref.column.reveal(): column.pii_class for column in metadata.columns}
    assert classes["customer_ssn"] is PiiClass.DIRECT_IDENTIFIER
    assert classes["patient_hiv_status"] is PiiClass.HEALTH
    assert classes["salary_2024"] is PiiClass.FINANCIAL


# --------------------------------------------------------------------------------------
# Catalog arithmetic
# --------------------------------------------------------------------------------------


def test_negative_n_distinct_is_a_fraction_of_rows() -> None:
    """Postgres encodes two different things in ``n_distinct``. Reading one as the
    other reports a unique key as having minus one distinct value."""
    connection = scripted()
    adapter = PostgresAdapter(connection)
    metadata = adapter.read_metadata_stats(SOURCE, adapter.resolve_snapshot(SOURCE), budget=BUDGET)
    ssn = metadata.column("customer_ssn")
    status = metadata.column("patient_hiv_status")
    assert ssn is not None
    assert status is not None
    assert ssn.distinct_estimate is not None
    assert ssn.distinct_estimate.reveal() == 12
    assert status.distinct_estimate is not None
    assert status.distinct_estimate.reveal() == 3


def test_null_counts_come_from_the_fraction_and_the_row_estimate() -> None:
    connection = scripted()
    adapter = PostgresAdapter(connection)
    metadata = adapter.read_metadata_stats(SOURCE, adapter.resolve_snapshot(SOURCE), budget=BUDGET)
    salary = metadata.column("salary_2024")
    assert salary is not None
    assert salary.null_count is not None
    assert salary.null_count.reveal() == 3
    assert salary.value_count is not None
    assert salary.value_count.reveal() == 9


def test_the_pseudo_snapshot_is_stable_and_dated_by_analyze() -> None:
    """Postgres keeps no history, so the snapshot is the statistics themselves."""
    first = PostgresAdapter(scripted()).resolve_snapshot(SOURCE)
    second = PostgresAdapter(scripted()).resolve_snapshot(SOURCE)
    assert first.snapshot_id == second.snapshot_id
    assert first.committed_at == ANALYSED
    assert first.row_count_estimate is not None
    assert first.row_count_estimate.reveal() == 12


def test_an_unanalysed_table_refuses_rather_than_invents_an_instant() -> None:
    connection = RecordingConnection(script=[[(None, None, 0.0, 0)]])
    with pytest.raises(Exception, match="never been analysed"):
        PostgresAdapter(connection).resolve_snapshot(SOURCE)


def test_an_unanalysed_table_accepts_an_injected_instant() -> None:
    connection = RecordingConnection(script=[[(None, None, 5.0, 1)]])
    snapshot = PostgresAdapter(connection).resolve_snapshot(SOURCE, at=ANALYSED)
    assert snapshot.committed_at == ANALYSED


def test_a_non_postgres_source_is_refused() -> None:
    iceberg = SOURCE.model_copy(update={"kind": SourceKind.ICEBERG})
    with pytest.raises(UnsupportedSourceError):
        PostgresAdapter(scripted()).resolve_snapshot(iceberg)


# --------------------------------------------------------------------------------------
# Probes
# --------------------------------------------------------------------------------------


def probe(kind: ProbeKind, *, columns: tuple[str, ...], budget: CostBudget) -> ProbeSpec:
    return ProbeSpec(
        probe_id=ProbeId("test"),
        kind=kind,
        spec_version=1,
        source=SOURCE,
        columns=tuple(
            schema_name(name, source_id=SOURCE_ID, table="customers") for name in columns
        ),
        segment=Segment(
            predicates=(
                Predicate(
                    column=schema_name("merchant_name", source_id=SOURCE_ID, table="customers"),
                    op=Operator.EQ,
                    values=(data_value("ACME_CORP", acquisition=Acquisition.SEGMENT_PREDICATE),),
                ),
            )
        ),
        sketches=(SketchKind.FREQUENT_ITEMS,),
        params={"top_k": 5},
        budget=budget,
        seed=3,
        as_of=ANALYSED,
    )


def test_a_probe_pushes_down_an_aggregate_and_returns_no_rows(
    stub_builder: StubSketchBuilder,
) -> None:
    connection = RecordingConnection(
        script=[
            list(SNAPSHOT_ROWS),
            [(4,)],
            [("ACME_CORP", 3), ("vendor_11", 1)],
        ]
    )
    adapter = PostgresAdapter(connection, sketch_builder=stub_builder)
    snapshot = adapter.resolve_snapshot(SOURCE)
    bundle = adapter.execute_probe(
        probe(ProbeKind.HEAVY_HITTERS, columns=("merchant_name",), budget=BUDGET),
        snapshot,
        budget=BUDGET,
    )

    pushdown = connection.sql[-1]
    assert "GROUP BY" in pushdown.upper()
    assert "LIMIT" in pushdown.upper()
    assert "SELECT *" not in pushdown.upper()
    assert "ACME_CORP" not in pushdown, "the predicate value must be bound, not inlined"

    assert bundle.cost_spent.bytes_scanned == 4 * PAGE_BYTES
    assert set(bundle.sketches) == {"frequent_items:0"}
    kind, values, population = stub_builder.calls[0]
    assert kind is SketchKind.FREQUENT_ITEMS
    assert values is not None
    assert values.column("value").to_pylist() == ["ACME_CORP", "vendor_11"]
    assert values.column("count").to_pylist() == [3, 1]
    assert population == 4


def test_a_heavy_hitter_probe_is_tainted_as_one(stub_builder: StubSketchBuilder) -> None:
    """On an identifier column the heavy hitters ARE the PII, so the provenance says so."""
    connection = RecordingConnection(
        script=[list(SNAPSHOT_ROWS), [(4,)], [("dev-0000-a4f7723b", 1)]]
    )
    adapter = PostgresAdapter(connection, sketch_builder=stub_builder)
    bundle = adapter.execute_probe(
        probe(ProbeKind.HEAVY_HITTERS, columns=("device_id",), budget=BUDGET),
        adapter.resolve_snapshot(SOURCE),
        budget=BUDGET,
    )
    envelope = bundle.sketches["frequent_items:0"]
    assert envelope.provenance.acquisition is Acquisition.COUNT_MIN_HEAVY_HITTER


def test_a_probe_refuses_rather_than_overspends(stub_builder: StubSketchBuilder) -> None:
    """Invariant 6. The estimate comes from ``relpages`` before the query runs."""
    connection = RecordingConnection(script=[list(SNAPSHOT_ROWS), [(1000,)]])
    tight = BUDGET.model_copy(update={"bytes_scanned": 1024})
    adapter = PostgresAdapter(connection, sketch_builder=stub_builder)
    with pytest.raises(BudgetExceededError, match="bytes_scanned"):
        adapter.execute_probe(
            probe(ProbeKind.HEAVY_HITTERS, columns=("merchant_name",), budget=BUDGET),
            adapter.resolve_snapshot(SOURCE),
            budget=tight,
        )
    assert len(connection.sql) == 2, "the aggregate must not have been issued"
    assert stub_builder.calls == []


def test_a_probe_without_a_builder_refuses() -> None:
    adapter = PostgresAdapter(scripted())
    with pytest.raises(UnsupportedProbeError, match="SketchBuilder"):
        adapter.execute_probe(
            probe(ProbeKind.ROW_COUNT, columns=(), budget=BUDGET),
            adapter.resolve_snapshot(SOURCE),
            budget=BUDGET,
        )


def test_an_unsupported_probe_kind_refuses(stub_builder: StubSketchBuilder) -> None:
    adapter = PostgresAdapter(scripted(), sketch_builder=stub_builder)
    snapshot = adapter.resolve_snapshot(SOURCE)
    with pytest.raises(UnsupportedProbeError, match="cannot answer"):
        adapter.execute_probe(
            probe(ProbeKind.GRAPH_DEGREE, columns=("merchant_name",), budget=BUDGET),
            snapshot,
            budget=BUDGET,
        )


# --------------------------------------------------------------------------------------
# Driver exceptions
# --------------------------------------------------------------------------------------


class ExplodingConnection:
    """A connection whose driver raises with a row in the message."""

    def cursor(self) -> ExplodingConnection:
        return self

    def execute(self, _operation: str, _parameters: object = ()) -> object:
        raise RuntimeError(
            'duplicate key value violates unique constraint "customers_pkey" '
            "DETAIL: Key (customer_ssn)=(100-40-1000) already exists."
        )

    def fetchall(self) -> Sequence[Sequence[object]]:
        return []

    def close(self) -> None:
        return None


def test_a_driver_exception_never_reaches_the_caller_verbatim() -> None:
    adapter = PostgresAdapter(ExplodingConnection())
    with pytest.raises(SanitisedDriverError) as raised:
        adapter.resolve_snapshot(SOURCE)

    assert "100-40-1000" not in str(raised.value)
    assert "customers_pkey" not in str(raised.value)
    assert raised.value.classification == "constraint_violation"
    assert "100-40-1000" in raised.value.original.reveal()
    assert raised.value.original.sensitivity is Sensitivity.DATA_VALUE


# --------------------------------------------------------------------------------------
# The array literal parser
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        (None, ()),
        ("", ()),
        ("{}", ()),
        ("{a,b,c}", ("a", "b", "c")),
        ('{"a,b",c}', ("a,b", "c")),
        ('{"say \\"hi\\"",x}', ('say "hi"', "x")),
        ("{ACME_CORP}", ("ACME_CORP",)),
        ("not an array", ()),
    ],
)
def test_pg_array_literals_parse(literal: str | None, expected: tuple[str, ...]) -> None:
    assert parse_pg_array(literal) == expected


@NO_DEADLINE
@given(
    members=st.lists(
        st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), max_size=12),
        min_size=1,
        max_size=6,
    )
)
def test_quoted_members_round_trip(members: list[str]) -> None:
    """Quote and escape every member, then parse it back.

    The case that matters is ``IN ('a,b')`` against ``IN ('a','b')``: without escaping,
    a single value containing a comma and two separate values are indistinguishable.
    """
    escaped = [item.replace("\\", "\\\\").replace('"', '\\"') for item in members]
    literal = "{" + ",".join(f'"{item}"' for item in escaped) + "}"
    assert list(parse_pg_array(literal)) == members
