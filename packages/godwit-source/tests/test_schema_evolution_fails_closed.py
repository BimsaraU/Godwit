"""A column added mid-replay is never read until a classification is recorded.

This is the scenario the brief singles out: a migration introduces ``customer_email_v2``,
nobody has classified it, and the only safe behaviour is to fail closed. The fixture adds
that column at snapshot s09.
"""

from __future__ import annotations

import pytest
from conftest import payments_policy

from godwit_source._contracts import ColumnAccessMode, CostBudget, ProbeSpec
from godwit_source.access import BlindColumnError
from godwit_source.iceberg import IcebergAdapter

NEW_COLUMN = "customer_email_v2"


def test_new_column_is_blind_for_every_snapshot_until_classified(
    adapter: IcebergAdapter,
) -> None:
    policy = payments_policy()
    history = adapter.read_metadata_stats("prod.payments", policy=policy)

    appeared_in_schema = [s.snapshot_id for s in history if NEW_COLUMN in s.schema_columns]
    assert appeared_in_schema == ["s09", "s10"], "the fixture must actually evolve"

    for snap in history:
        assert NEW_COLUMN not in snap.columns
    assert policy.mode(NEW_COLUMN) is ColumnAccessMode.BLIND


def test_schema_change_is_the_only_thing_that_reports_the_new_column(
    adapter: IcebergAdapter,
) -> None:
    """The name travels as DATA_VALUE in exactly one place, so a human can classify it."""
    from godwit_source.detectors import schema_change

    policy = payments_policy()
    history = adapter.read_metadata_stats("prod.payments", policy=policy, until="s09")
    candidate = schema_change(history)[0]
    added = candidate.evidence["added_columns"]
    assert added.unwrap("test reads the tagged column name") == (NEW_COLUMN,)


def test_probing_the_unclassified_column_is_refused(adapter: IcebergAdapter) -> None:
    spec = ProbeSpec(
        table="prod.payments",
        columns=(NEW_COLUMN,),
        snapshot_id="s10",
        version="1",
        seed=0,
    )
    with pytest.raises(BlindColumnError):
        adapter.execute_probe(
            spec, policy=payments_policy(), budget=CostBudget(max_bytes=1 << 40, max_queries=10)
        )


def test_classification_unlocks_it_and_nothing_else_changes(adapter: IcebergAdapter) -> None:
    """Once a human confirms the classification, the column becomes readable -- OPAQUE,
    because it is a direct identifier -- and the earlier snapshots are unaffected."""
    policy = payments_policy(classify_new_column=True)
    history = adapter.read_metadata_stats("prod.payments", policy=policy)

    assert policy.mode(NEW_COLUMN) is ColumnAccessMode.OPAQUE
    by_id = {s.snapshot_id: s for s in history}
    assert NEW_COLUMN not in by_id["s08"].columns
    assert NEW_COLUMN in by_id["s09"].columns
    assert by_id["s09"].columns[NEW_COLUMN].bounds is None, "OPAQUE yields no bound"
    assert by_id["s09"].columns[NEW_COLUMN].counts.ndv is not None
