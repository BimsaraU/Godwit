"""PostgresAdapter: zero table scans on the metadata path, no rows on the probe path."""

from __future__ import annotations

import re
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
from godwit_source.postgres import PostgresAdapter

SCHEMA_ROWS = [
    {"column_name": "user_id", "data_type": "bigint"},
    {"column_name": "email", "data_type": "text"},
    {"column_name": "country", "data_type": "character varying"},
    {"column_name": "password_hash", "data_type": "text"},
    {"column_name": "signup_source", "data_type": "text"},
]

STATS_ROWS = [
    {
        "attname": "country",
        "null_frac": 0.02,
        "n_distinct": 24.0,
        "most_common_vals": ["GB", "US", "DE"],
        "most_common_freqs": [0.41, 0.33, 0.08],
        "histogram_bounds": ["AU", "GB", "US"],
        "data_type": "character varying",
    },
    {
        "attname": "email",
        "null_frac": 0.0,
        "n_distinct": -0.98,
        "most_common_vals": ["ada.lovelace@example.org", "grace.hopper@example.org"],
        "most_common_freqs": [0.001, 0.0008],
        "histogram_bounds": ["aaron@example.org", "zoe@example.org"],
        "data_type": "text",
    },
    {
        "attname": "user_id",
        "null_frac": 0.0,
        "n_distinct": -1.0,
        "most_common_vals": None,
        "most_common_freqs": None,
        "histogram_bounds": ["1", "500000"],
        "data_type": "bigint",
    },
]


class RecordingQuery:
    """Records every SQL statement so a test can assert on what was actually sent."""

    def __init__(self, probe_row: Mapping[str, Any] | None = None) -> None:
        self.statements: list[str] = []
        self._probe_row = probe_row or {"row_count": 12.0}

    def __call__(self, sql: str, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        self.statements.append(sql)
        if "information_schema.columns" in sql and "pg_stats" not in sql:
            return SCHEMA_ROWS
        if "pg_stats" in sql:
            wanted = set(params["columns"])
            return [r for r in STATS_ROWS if r["attname"] in wanted]
        if "pg_class" in sql:
            return [{"row_count": 500_000}]
        return [self._probe_row]


def policy_for(*, email_open: bool = False) -> AccessPolicy:
    return AccessPolicy(
        [
            ColumnClassification("user_id", PiiClass.NON_PII, confirmed=True,
                                 requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-1"),
            ColumnClassification(
                "email", PiiClass.DIRECT_IDENTIFIER, confirmed=True,
                requested_mode=ColumnAccessMode.OPEN if email_open else None,
                guardrail_id="G-2" if email_open else None,
                input_space_bits=64.0,
            ),
            ColumnClassification("country", PiiClass.QUASI_IDENTIFIER, confirmed=True,
                                 requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-3"),
            ColumnClassification("password_hash", PiiClass.SECRET, confirmed=True),
            # signup_source is deliberately unclassified: it must resolve to BLIND.
        ]
    )


def test_metadata_path_never_touches_the_user_table() -> None:
    """The acceptance is structural: every statement names a catalog relation, none names
    the table being profiled."""
    query = RecordingQuery()
    adapter = PostgresAdapter(query)
    adapter.read_metadata_stats(
        "public.users", policy=policy_for(), snapshot_id="2026-09-21T00:00Z"
    )

    assert query.statements
    for sql in query.statements:
        assert re.search(r"\bFROM\s+pg_stats\b|\bFROM\s+pg_class\b|information_schema", sql)
        assert not re.search(r'\bFROM\s+"?public"?\."?users"?', sql)


def test_blind_columns_are_never_requested_from_pg_stats() -> None:
    query = RecordingQuery()
    PostgresAdapter(query).read_metadata_stats(
        "public.users", policy=policy_for(), snapshot_id="s1"
    )
    stats_calls = [s for s in query.statements if "pg_stats" in s]
    assert stats_calls
    # The filter is server-side on attname, so the statistics for a BLIND column are never
    # fetched -- not fetched and then dropped.
    assert "ANY(%(columns)s)" in stats_calls[0]


def test_most_common_vals_are_tainted_when_open() -> None:
    adapter = PostgresAdapter(RecordingQuery())
    snap = adapter.read_metadata_stats(
        "public.users", policy=policy_for(email_open=True), snapshot_id="s1"
    )[0]
    common = snap.columns["email"].common_values
    assert common
    raw = common[0].value.unwrap("test asserts most_common_vals were tagged")
    assert raw == "ada.lovelace@example.org"
    assert "ada.lovelace" not in repr(common[0])


def test_most_common_vals_are_discarded_for_opaque() -> None:
    """The values are dropped inside the row loop, before entering any structure -- there is
    never an object holding them that someone downstream could forget to redact."""
    adapter = PostgresAdapter(RecordingQuery())
    snap = adapter.read_metadata_stats("public.users", policy=policy_for(), snapshot_id="s1")[0]
    email = snap.columns["email"]
    assert email.access_mode is ColumnAccessMode.OPAQUE
    assert email.common_values == ()
    assert email.histogram_bounds == ()
    assert email.counts.ndv is not None, "the derived statistic survives"


def test_negative_n_distinct_is_read_as_a_ratio() -> None:
    adapter = PostgresAdapter(RecordingQuery())
    snap = adapter.read_metadata_stats("public.users", policy=policy_for(), snapshot_id="s1")[0]
    ndv = snap.columns["email"].counts.ndv
    assert ndv is not None
    assert ndv.unwrap("test") == 490_000  # 0.98 * 500_000


def test_blind_and_secret_columns_are_absent_from_the_result() -> None:
    adapter = PostgresAdapter(RecordingQuery())
    snap = adapter.read_metadata_stats("public.users", policy=policy_for(), snapshot_id="s1")[0]
    assert "password_hash" not in snap.columns
    assert "signup_source" not in snap.columns
    assert "signup_source" in snap.schema_columns


def test_probe_sql_never_selects_star_and_never_returns_rows() -> None:
    adapter = PostgresAdapter(RecordingQuery())
    spec = ProbeSpec(
        table="public.users",
        columns=("user_id", "email", "country"),
        snapshot_id="s1",
        version="1",
        seed=0,
    )
    sql = adapter.build_probe_sql(spec, policy=policy_for())
    assert "*" not in sql.replace("count(*)", "")
    assert sql.count("count(") == 1 + 2 * 3
    # email is OPAQUE, so it is aggregated through the keyed hash and never selected raw.
    assert 'count("email")' not in sql
    assert "hmac" in sql


def test_probe_refuses_a_blind_column() -> None:
    adapter = PostgresAdapter(RecordingQuery())
    spec = ProbeSpec(
        table="public.users", columns=("signup_source",), snapshot_id="s1", version="1", seed=0
    )
    with pytest.raises(BlindColumnError):
        adapter.build_probe_sql(spec, policy=policy_for())


def test_probe_respects_the_query_budget() -> None:
    adapter = PostgresAdapter(RecordingQuery())
    spec = ProbeSpec(
        table="public.users", columns=("user_id",), snapshot_id="s1", version="1", seed=0
    )
    budget = CostBudget(max_bytes=1 << 30, max_queries=1)
    adapter.execute_probe(spec, policy=policy_for(), budget=budget)
    with pytest.raises(CostBudgetExceeded):
        adapter.execute_probe(spec, policy=policy_for(), budget=budget)


def test_driver_errors_are_replaced_not_scrubbed() -> None:
    """A Postgres error routinely quotes the offending row. The original is dropped whole."""

    def exploding(sql: str, params: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
        if "pg_stats" in sql:
            raise RuntimeError("duplicate key value violates ... (email)=(ada@example.org)")
        return SCHEMA_ROWS

    adapter = PostgresAdapter(exploding)
    with pytest.raises(RuntimeError) as excinfo:
        adapter.read_metadata_stats("public.users", policy=policy_for(), snapshot_id="s1")
    message = str(excinfo.value)
    assert "ada@example.org" not in message
    assert "detail withheld" in message
