"""Semantic profiling without an LLM, and candidate join edges from metadata alone."""

from __future__ import annotations

from godwit_source._contracts import (
    ColumnAccessMode,
    PiiClass,
    SemanticRole,
    data_value,
    derived_statistic,
)
from godwit_source.access import AccessPolicy
from godwit_source.iceberg import IcebergAdapter
from godwit_source.profile import (
    candidate_join_edges,
    profile_column,
    profile_snapshot,
    value_format,
)
from godwit_source.stats import ColumnBounds, ColumnCounts, ColumnMetadata, SnapshotMetadata


def meta(
    column: str,
    data_type: str,
    *,
    rows: int = 1_000_000,
    ndv: int | None = None,
    mode: ColumnAccessMode = ColumnAccessMode.OPEN,
    lower: object | None = None,
    upper: object | None = None,
    table: str = "t",
) -> ColumnMetadata:
    bounds = None
    if lower is not None or upper is not None:
        bounds = ColumnBounds(
            lower=None if lower is None else data_value(lower, "fixture"),
            upper=None if upper is None else data_value(upper, "fixture"),
        )
    return ColumnMetadata(
        table=table,
        column=column,
        snapshot_id="s1",
        access_mode=mode,
        data_type=data_type,
        counts=ColumnCounts(
            row_count=derived_statistic(rows, "fixture"),
            ndv=None if ndv is None else derived_statistic(ndv, "fixture"),
        ),
        bounds=bounds,
    )


def test_value_format_names_the_shape_without_keeping_the_value() -> None:
    assert value_format("ada@example.org") == "email"
    assert value_format("d0f41a2c-9b7e-4d15-83aa-000000000001") == "uuid"
    assert value_format("+14155550123") == "e164_phone"
    assert value_format("2026-09-21") == "iso_date"
    assert value_format("not a thing at all") is None


def test_roles_from_name_type_and_cardinality() -> None:
    assert profile_column(meta("created_at", "timestamp")).semantic_role is SemanticRole.TIMESTAMP
    assert profile_column(meta("is_flagged", "boolean")).semantic_role is SemanticRole.BOOLEAN_FLAG
    assert (
        profile_column(meta("txn_id", "string", ndv=1_000_000)).semantic_role
        is SemanticRole.ENTITY_ID
    )
    assert (
        profile_column(meta("merchant_id", "string", ndv=4_000)).semantic_role
        is SemanticRole.FOREIGN_KEY
    )
    assert profile_column(meta("amount", "double")).semantic_role is SemanticRole.AMOUNT
    assert (
        profile_column(meta("channel", "string", ndv=6)).semantic_role is SemanticRole.CATEGORY
    )


def test_pii_first_pass_from_names() -> None:
    assert profile_column(meta("password_hash", "string")).pii_class is PiiClass.SECRET
    assert profile_column(meta("internal_notes", "string")).pii_class is PiiClass.FREE_TEXT
    assert profile_column(meta("customer_email", "string")).pii_class is PiiClass.DIRECT_IDENTIFIER
    assert profile_column(meta("date_of_birth", "date")).pii_class is PiiClass.QUASI_IDENTIFIER
    assert (
        profile_column(meta("hiv_status", "string")).pii_class is PiiClass.SENSITIVE_ATTRIBUTE
    )


def test_unrecognised_column_is_unknown_and_therefore_blind() -> None:
    """The whole chain: no signal -> UNKNOWN -> an AccessPolicy resolves it to BLIND."""
    profile = profile_column(meta("zzz_col_47", "string", ndv=500_000))
    assert profile.pii_class is PiiClass.UNKNOWN
    assert AccessPolicy([]).mode(profile.column) is ColumnAccessMode.BLIND


def test_format_promotes_an_innocuous_name_to_direct_identifier() -> None:
    """``contact`` says nothing; a bound that looks like an email says everything."""
    profile = profile_column(meta("contact", "string", lower="ada@example.org"))
    assert profile.value_format == "email"
    assert profile.pii_class is PiiClass.DIRECT_IDENTIFIER


def test_opaque_column_yields_no_format_because_no_bound_exists() -> None:
    profile = profile_column(
        meta("device_id", "string", mode=ColumnAccessMode.OPAQUE, lower="d0f4", ndv=900_000)
    )
    assert profile.value_format is None
    assert profile.pii_class is PiiClass.DIRECT_IDENTIFIER, "the name still carries it"


def snapshot(table: str, *columns: ColumnMetadata) -> SnapshotMetadata:
    return SnapshotMetadata(
        table=table,
        snapshot_id="s1",
        sequence_number=1,
        commit_ms=0,
        columns={c.column: c for c in columns},
        schema_columns=tuple(c.column for c in columns),
    )


def test_join_edges_found_between_opaque_identifier_columns() -> None:
    """No value is needed to propose the shared-attribute graph, which is the point: those
    columns are all direct identifiers and none of them will ever be OPEN."""
    accounts = snapshot(
        "accounts",
        meta("device_id", "string", ndv=900_000, mode=ColumnAccessMode.OPAQUE, table="accounts"),
    )
    logins = snapshot(
        "logins",
        meta("device_id", "string", ndv=880_000, mode=ColumnAccessMode.OPAQUE, table="logins"),
    )
    edges = candidate_join_edges([accounts, logins])
    assert len(edges) == 1
    edge = edges[0]
    assert {edge.left_table, edge.right_table} == {"accounts", "logins"}
    assert edge.containment > 0.9
    assert any("name affinity" in r for r in edge.reasons)


def test_join_edges_skip_same_table_and_mismatched_types() -> None:
    a = snapshot("a", meta("user_id", "string", ndv=1000, table="a"),
                 meta("user_id_copy", "string", ndv=1000, table="a"))
    b = snapshot("b", meta("user_id", "bigint", ndv=1000, table="b"))
    assert candidate_join_edges([a, b]) == []


def test_profiles_the_golden_snapshot_without_an_llm(
    adapter: IcebergAdapter, policy: AccessPolicy
) -> None:
    snap = adapter.read_metadata_stats("prod.payments", policy=policy)[0]
    profiles = {p.column: p for p in profile_snapshot(snap)}
    assert profiles["txn_id"].semantic_role is SemanticRole.ENTITY_ID
    assert profiles["created_at"].semantic_role is SemanticRole.TIMESTAMP
    assert profiles["amount"].semantic_role is SemanticRole.AMOUNT
    assert profiles["customer_email"].pii_class is PiiClass.DIRECT_IDENTIFIER
    assert profiles["customer_email"].value_format == "email"
    assert "notes" not in profiles, "BLIND columns are not even profiled"
