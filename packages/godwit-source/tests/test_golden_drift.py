"""ACCEPTANCE: find the injected drift, at the right snapshot, reading no table data.

The golden fixture documents its own drift. Between ``snap_1`` and ``snap_2`` the
``amount`` column stops being lognormal within ``country = 'PT' AND status = 'refund'``
and becomes uniform over 400 to 900. An L-1 detector cannot see the segment -- segments
cost a scan -- but it does not need to: the change drags the table's ``amount`` upper
bound from 326 to 900, and the manifest already recorded that.

Three claims are tested here, and all three are the brief's:

1. The drift is found, on the right column, at ``snap_2`` and not before.
2. ``country = 'US'``, the fixture's false-positive control, is never flagged.
3. Not one byte of table data was read to do it, proved by an instrumented
   object-store client rather than by inspection.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from godwit_contracts.cost import CostBudget
from godwit_contracts.discovery import Candidate
from godwit_contracts.source import SourceRef
from godwit_source.detectors import run_metadata_detectors
from godwit_source.iceberg import IcebergAdapter
from godwit_source.metadata import SnapshotMetadata
from godwit_source.objectstore import ByteMeter

CODE_VERSION = "test-golden"
SEED = 20240117


def _history(
    adapter: IcebergAdapter, source: SourceRef, budget: CostBudget, *, upto: int
) -> list[SnapshotMetadata]:
    snapshots = adapter.list_snapshots(source)[:upto]
    return [adapter.read_metadata_stats(source, snapshot, budget=budget) for snapshot in snapshots]


def test_three_snapshots_are_visible(
    golden_adapter: IcebergAdapter, golden_source: SourceRef
) -> None:
    snapshots = golden_adapter.list_snapshots(golden_source)
    assert len(snapshots) == 3
    assert [snapshot.sequence_number for snapshot in snapshots] == [1, 2, 3]
    assert snapshots[0].parent_snapshot_id is None
    assert snapshots[1].parent_snapshot_id == snapshots[0].snapshot_id


def test_metadata_carries_bounds_and_counts_apart(
    golden_adapter: IcebergAdapter, golden_source: SourceRef, generous_budget: CostBudget
) -> None:
    """Bounds are DATA_VALUE, counts are DERIVED_STATISTIC, in separate fields."""
    snapshot = golden_adapter.list_snapshots(golden_source)[0]
    metadata = golden_adapter.read_metadata_stats(golden_source, snapshot, budget=generous_budget)

    amount = metadata.column("amount")
    assert amount is not None
    assert amount.lower_bound is not None
    assert amount.upper_bound is not None
    assert amount.lower_bound.sensitivity.value == "data_value"
    assert amount.lower_bound.provenance.acquisition.value == "iceberg_manifest_bounds"
    assert amount.row_count is not None
    assert amount.row_count.sensitivity.value == "derived_statistic"
    assert amount.row_count.reveal() == 6000
    assert metadata.scanned_bytes == 0


def test_drift_is_found_at_snapshot_two_and_not_before(
    golden_adapter: IcebergAdapter,
    golden_source: SourceRef,
    generous_budget: CostBudget,
    golden_manifest: Mapping[str, Any],
) -> None:
    assert golden_manifest["documented_drift"]["introduced_at_snapshot"] == "snap_2"

    early = run_metadata_detectors(
        _history(golden_adapter, golden_source, generous_budget, upto=2),
        code_version=CODE_VERSION,
        seed=SEED,
    )
    assert early == (), "nothing should be reported between snapshot 0 and snapshot 1"

    full = _history(golden_adapter, golden_source, generous_budget, upto=3)
    found = run_metadata_detectors(full, code_version=CODE_VERSION, seed=SEED)

    assert found, "the injected drift at snap_2 was not found"
    columns = {
        column.reveal()
        for candidate in found
        for evidence in candidate.evidence
        for column in evidence.columns
    }
    assert columns == {"amount"}, f"expected only the amount column to be flagged, got {columns}"

    latest = full[-1].snapshot.snapshot_id
    for candidate in found:
        assert candidate.lineage.snapshot_id == latest
        assert candidate.lineage.detector == "metadata.bounds_drift"
        assert candidate.lineage.code_version == CODE_VERSION
        assert candidate.lineage.seed == SEED


def test_the_false_positive_control_is_not_flagged(
    golden_adapter: IcebergAdapter,
    golden_source: SourceRef,
    generous_budget: CostBudget,
    golden_manifest: Mapping[str, Any],
) -> None:
    """``country = 'US'`` must never appear in a candidate.

    L-1 works at column granularity and cannot express a country segment at all, so the
    control is safe by construction. The test states it anyway: it is the property the
    fixture exists to check, and a future detector that started emitting value-bearing
    segments would break it loudly.
    """
    control = golden_manifest["documented_drift"]["unchanged_controls"][0]["predicates"][0]
    assert control[0] == "country"

    found = run_metadata_detectors(
        _history(golden_adapter, golden_source, generous_budget, upto=3),
        code_version=CODE_VERSION,
        seed=SEED,
    )
    for candidate in found:
        for predicate in candidate.segment.predicates:
            assert predicate.column.reveal() != "country"
            assert predicate.values == (), "an L-1 segment must not quote a row value"


def test_zero_bytes_of_table_data_were_read(
    golden_adapter: IcebergAdapter,
    golden_source: SourceRef,
    golden_meter: ByteMeter,
    generous_budget: CostBudget,
) -> None:
    """The acceptance criterion, measured rather than asserted."""
    found = run_metadata_detectors(
        _history(golden_adapter, golden_source, generous_budget, upto=3),
        code_version=CODE_VERSION,
        seed=SEED,
    )
    assert found

    assert golden_meter.data_bytes == 0, (
        f"L-1 read {golden_meter.data_bytes} bytes of table data from "
        f"{golden_meter.data_reads} data files"
    )
    assert golden_meter.data_reads == 0
    assert golden_meter.metadata_bytes > 0, "the metadata path read nothing at all"
    assert all(not location.endswith(".parquet") for location in golden_meter.locations)


def test_detectors_are_deterministic(
    golden_adapter: IcebergAdapter, golden_source: SourceRef, generous_budget: CostBudget
) -> None:
    """Invariant 7 at L-1: same history, same seed, same candidates, same order."""
    history = _history(golden_adapter, golden_source, generous_budget, upto=3)
    first = run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED)
    second = run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED)

    assert _ids(first) == _ids(second)
    assert [candidate.model_dump_json() for candidate in first] == [
        candidate.model_dump_json() for candidate in second
    ]


def _ids(candidates: Sequence[Candidate]) -> list[str]:
    return [str(candidate.candidate_id) for candidate in candidates]


def test_profile_table_renders_the_contract_type(
    golden_adapter: IcebergAdapter, golden_source: SourceRef, generous_budget: CostBudget
) -> None:
    snapshot = golden_adapter.list_snapshots(golden_source)[-1]
    profile = golden_adapter.profile_table(golden_source, snapshot, budget=generous_budget)

    assert {column.ref.column.reveal() for column in profile.columns} == {
        "order_id",
        "customer_email",
        "country",
        "status",
        "amount",
        "created_at",
    }
    roles = {column.ref.column.reveal(): column.role.value for column in profile.columns}
    # join_key, not entity_id: the golden table carries no Puffin NDV, so cardinality
    # is unknown and the weaker of the two claims is the honest one.
    assert roles["order_id"] == "join_key"
    assert roles["created_at"] == "event_time"
    assert roles["country"] == "geo"
    assert roles["amount"] == "amount"

    pii = {column.ref.column.reveal(): column.pii_class.value for column in profile.columns}
    assert pii["customer_email"] == "direct_identifier"
