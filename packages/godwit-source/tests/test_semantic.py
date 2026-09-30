"""Semantic profiling with no LLM in sight.

Invariant 7 says the LLM is out of the detection path; invariant 4 says its cost scales
with hypotheses, not data. Both mean the catalog has to stand on its own. These tests
pin what "on its own" buys: roles from names, types and cardinality; PII classes that
err towards restriction; and join edges from approximate inclusion dependency.

The join-edge tests are the ones worth reading. An edge is a *claim* that one column's
values are a subset of another's, and it is made from two catalog facts -- a distinct
count and a pair of bounds -- neither of which is proof. That is why an edge carries a
confidence and why confirming one costs budget somebody else decides to spend.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from godwit_contracts.common import ScalarValue, SnapshotId, SourceId
from godwit_contracts.source import (
    ColumnRef,
    ColumnRole,
    LogicalType,
    PiiClass,
    SnapshotRef,
    SourceKind,
    SourceRef,
)
from godwit_contracts.taint import Acquisition, data_value, derived_statistic, schema_name
from godwit_source.metadata import ColumnMetadata, SnapshotMetadata
from godwit_source.semantic import (
    infer_join_edges,
    infer_pii_class,
    infer_role,
    pii_restrictiveness,
)

SOURCE_ID = SourceId("sem")
OBSERVED = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)


# --------------------------------------------------------------------------------------
# Role inference
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "logical_type", "distinct", "rows", "expected"),
    [
        ("is_fraud", LogicalType.BOOL, 2, 1000, ColumnRole.LABEL),
        ("label", LogicalType.INT, 2, 1000, ColumnRole.LABEL),
        ("created_at", LogicalType.TIMESTAMP, 900, 1000, ColumnRole.EVENT_TIME),
        ("event_ts", LogicalType.INT, 900, 1000, ColumnRole.EVENT_TIME),
        ("order_id", LogicalType.STRING, 1000, 1000, ColumnRole.ENTITY_ID),
        ("merchant_id", LogicalType.STRING, 40, 1000, ColumnRole.JOIN_KEY),
        ("country", LogicalType.STRING, 12, 1000, ColumnRole.GEO),
        ("device_id", LogicalType.STRING, 800, 1000, ColumnRole.DEVICE),
        ("notes", LogicalType.STRING, 990, 1000, ColumnRole.FREE_TEXT),
        ("amount", LogicalType.FLOAT, 900, 1000, ColumnRole.AMOUNT),
        ("status", LogicalType.STRING, 4, 1000, ColumnRole.CATEGORY),
        ("latency_ms", LogicalType.FLOAT, 900, 1000, ColumnRole.MEASURE),
        ("mystery", LogicalType.BINARY, None, None, ColumnRole.UNKNOWN),
    ],
)
def test_roles_are_inferred_from_name_type_and_cardinality(
    name: str,
    logical_type: LogicalType,
    distinct: int | None,
    rows: int | None,
    expected: ColumnRole,
) -> None:
    assert (
        infer_role(
            column_name=name,
            logical_type=logical_type,
            distinct_estimate=distinct,
            row_count=rows,
        )
        is expected
    )


def test_an_identifier_falls_back_to_join_key_without_cardinality() -> None:
    """Unknown cardinality means the weaker claim, not the more interesting one."""
    assert infer_role(column_name="order_id", logical_type=LogicalType.STRING) is (
        ColumnRole.JOIN_KEY
    )


def test_a_unique_direct_identifier_is_an_entity() -> None:
    """An email column with near-unique values identifies entities, whatever it is called."""
    assert (
        infer_role(
            column_name="customer_email",
            logical_type=LogicalType.STRING,
            pii_class=PiiClass.DIRECT_IDENTIFIER,
            distinct_estimate=995,
            row_count=1000,
        )
        is ColumnRole.ENTITY_ID
    )


def test_geography_beats_category() -> None:
    """``country`` is low-cardinality, but a feature builder treats geo differently."""
    assert (
        infer_role(
            column_name="country",
            logical_type=LogicalType.STRING,
            distinct_estimate=8,
            row_count=1000,
        )
        is ColumnRole.GEO
    )


# --------------------------------------------------------------------------------------
# PII classification
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("customer_ssn", PiiClass.DIRECT_IDENTIFIER),
        ("full_name", PiiClass.DIRECT_IDENTIFIER),
        ("email", PiiClass.DIRECT_IDENTIFIER),
        ("patient_hiv_status", PiiClass.HEALTH),
        ("salary_2024", PiiClass.FINANCIAL),
        ("device_id", PiiClass.QUASI_IDENTIFIER),
        ("cohort", PiiClass.QUASI_IDENTIFIER),
        ("notes", PiiClass.SENSITIVE_ATTRIBUTE),
        ("api_key", PiiClass.CREDENTIAL),
        ("widget_count", PiiClass.UNKNOWN),
    ],
)
def test_pii_classes_come_from_column_names(name: str, expected: PiiClass) -> None:
    assert infer_pii_class(column_name=name, logical_type=LogicalType.STRING) is expected


def test_an_unnamed_column_is_classified_by_the_shape_of_its_values() -> None:
    """The case names miss: ``col_7``, full of email addresses."""
    assert (
        infer_pii_class(
            column_name="col_7",
            logical_type=LogicalType.STRING,
            sample_values=["aoife.brennan@northfield-bank.test"],
        )
        is PiiClass.DIRECT_IDENTIFIER
    )
    assert (
        infer_pii_class(
            column_name="col_8", logical_type=LogicalType.STRING, sample_values=["100-40-1000"]
        )
        is PiiClass.DIRECT_IDENTIFIER
    )


def test_the_more_restrictive_verdict_wins() -> None:
    """Name says quasi-identifier, values say direct. Deny by default takes the higher."""
    found = infer_pii_class(
        column_name="cohort",
        logical_type=LogicalType.STRING,
        sample_values=["aoife.brennan@northfield-bank.test"],
    )
    assert pii_restrictiveness(found) >= pii_restrictiveness(PiiClass.DIRECT_IDENTIFIER)


def test_nothing_is_ever_classified_as_harmless() -> None:
    """``NONE`` is a grant, and this function is not confident enough to issue one."""
    for name in ("widget_count", "col_1", "x", ""):
        assert infer_pii_class(column_name=name, logical_type=LogicalType.INT) is not PiiClass.NONE


def test_unknown_outranks_everything() -> None:
    """The gate denies what it cannot classify, so UNKNOWN must sort highest."""
    assert pii_restrictiveness(PiiClass.UNKNOWN) > pii_restrictiveness(PiiClass.CREDENTIAL)
    assert pii_restrictiveness(PiiClass.NONE) == 0


# --------------------------------------------------------------------------------------
# Join edges
# --------------------------------------------------------------------------------------


def table(
    name: str,
    columns: list[tuple[str, ColumnRole, int, tuple[ScalarValue, ScalarValue]]],
) -> SnapshotMetadata:
    source = SourceRef(
        source_id=SOURCE_ID,
        kind=SourceKind.ICEBERG,
        catalog="sem",
        namespace=schema_name("ns", source_id=SOURCE_ID),
        table=schema_name(name, source_id=SOURCE_ID),
    )
    return SnapshotMetadata(
        source=source,
        snapshot=SnapshotRef(
            source_id=SOURCE_ID,
            snapshot_id=SnapshotId(f"snap_{name}"),
            sequence_number=1,
            committed_at=OBSERVED,
        ),
        columns=tuple(
            ColumnMetadata(
                ref=ColumnRef(
                    source_id=SOURCE_ID,
                    table=schema_name(name, source_id=SOURCE_ID),
                    column=schema_name(column, source_id=SOURCE_ID, table=name),
                ),
                logical_type=LogicalType.STRING,
                native_type="string",
                nullable=False,
                role=role,
                distinct_estimate=derived_statistic(
                    distinct, source_id=SOURCE_ID, table=name, column=column
                ),
                lower_bound=data_value(
                    bounds[0],
                    acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS,
                    source_id=SOURCE_ID,
                    table=name,
                    column=column,
                ),
                upper_bound=data_value(
                    bounds[1],
                    acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS,
                    source_id=SOURCE_ID,
                    table=name,
                    column=column,
                ),
            )
            for column, role, distinct, bounds in columns
        ),
        observed_at=OBSERVED,
    )


def test_an_inclusion_dependency_becomes_an_edge() -> None:
    """``orders.customer_id`` looks like a subset of ``customers.customer_id``."""
    orders = table("orders", [("customer_id", ColumnRole.JOIN_KEY, 400, ("c_0001", "c_0900"))])
    customers = table(
        "customers", [("customer_id", ColumnRole.ENTITY_ID, 1000, ("c_0000", "c_0999"))]
    )

    edges = infer_join_edges([orders, customers], observed_at=OBSERVED)
    assert edges
    best = edges[0]
    assert best.left.table.reveal() == "orders"
    assert best.right.table.reveal() == "customers"
    assert best.confidence > 0.8
    assert "ndv_inclusion" in best.inferred_from
    assert "name_affinity" in best.inferred_from
    assert best.left_to_right_cardinality is not None


def test_an_edge_records_how_and_never_what() -> None:
    """``inferred_from`` explains the inference. It must not quote a value."""
    orders = table("orders", [("customer_id", ColumnRole.JOIN_KEY, 400, ("c_0001", "c_0900"))])
    customers = table(
        "customers", [("customer_id", ColumnRole.ENTITY_ID, 1000, ("c_0000", "c_0999"))]
    )
    for edge in infer_join_edges([orders, customers], observed_at=OBSERVED):
        assert "c_0001" not in edge.inferred_from
        assert "c_0999" not in edge.inferred_from
        assert set(edge.inferred_from.split("+")) <= {
            "ndv_inclusion",
            "bounds_containment",
            "name_affinity",
        }


def test_disjoint_bounds_do_not_produce_a_confident_edge() -> None:
    orders = table("orders", [("customer_id", ColumnRole.JOIN_KEY, 400, ("z_0001", "z_0900"))])
    customers = table(
        "customers", [("widget_key", ColumnRole.ENTITY_ID, 1000, ("a_0000", "a_0999"))]
    )
    assert infer_join_edges([orders, customers], observed_at=OBSERVED) == ()


def test_only_joinable_roles_are_considered() -> None:
    """A free-text column with overlapping bounds is not a join candidate."""
    left = table("a", [("notes", ColumnRole.FREE_TEXT, 10, ("aaa", "zzz"))])
    right = table("b", [("notes", ColumnRole.FREE_TEXT, 100, ("aaa", "zzz"))])
    assert infer_join_edges([left, right], observed_at=OBSERVED) == ()


def test_edges_are_deterministic() -> None:
    tables = [
        table("orders", [("customer_id", ColumnRole.JOIN_KEY, 400, ("c_0001", "c_0900"))]),
        table("customers", [("customer_id", ColumnRole.ENTITY_ID, 1000, ("c_0000", "c_0999"))]),
        table("refunds", [("customer_id", ColumnRole.JOIN_KEY, 50, ("c_0100", "c_0500"))]),
    ]
    first = infer_join_edges(tables, observed_at=OBSERVED)
    second = infer_join_edges(tables, observed_at=OBSERVED)
    assert [
        (edge.left.column.reveal(), edge.right.table.reveal(), edge.confidence) for edge in first
    ] == [
        (edge.left.column.reveal(), edge.right.table.reveal(), edge.confidence) for edge in second
    ]
    assert list(first) == sorted(first, key=lambda edge: -edge.confidence)
