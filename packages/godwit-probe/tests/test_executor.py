"""The executor: refusal before reading, near-zero no-change, deltas, cancellation, truth.

The simulator's statistics are known in closed form, so these tests check the bundles
against the generating distributions rather than against another implementation.
"""

from __future__ import annotations

import math
import re
import statistics

import pytest
from _probe_support import AMOUNT, COUNTRY, orders, predicate, segment, simulator
from godwit_contracts import CostBudget, Operator, ProbeKind, SketchKind
from godwit_probe import (
    CancelFlag,
    CancelReason,
    ExecutionMode,
    ProbeStatus,
    RefusalReason,
    bundle_id,
)
from godwit_probe.source import DeltaKind
from godwit_probe.testing import SyntheticCommit, generous_budget
from godwit_sketch import CategoryHistogram, KllQuantile, NullRate, ThetaNdv, decode_envelope


def test_budget_refusal_happens_before_any_byte_is_read() -> None:
    sim = simulator()
    spec = sim.spec(ProbeKind.QUANTILES, ["amount"])
    outcome = sim.run(spec, budget=generous_budget(bytes_scanned=1000))
    assert outcome.status is ProbeStatus.REFUSED
    assert outcome.refusal is not None
    assert outcome.refusal.reason is RefusalReason.BUDGET
    assert outcome.refusal.estimated_cost is not None
    assert outcome.refusal.estimated_cost.bytes_scanned > 1000
    assert outcome.estimated_cost.bytes_scanned > 1000
    assert sim.source.bytes_read == 0
    assert sim.source.reads == []
    assert outcome.cost_spent.bytes_scanned == 0
    assert sim.state.last_snapshot(spec.key) is None


def test_the_spec_budget_is_composed_with_the_callers() -> None:
    sim = simulator()
    tight = generous_budget(bytes_scanned=10)
    spec = sim.spec(ProbeKind.QUANTILES, ["amount"], budget=tight)
    outcome = sim.run(spec, budget=generous_budget())
    assert outcome.status is ProbeStatus.REFUSED
    assert sim.source.reads == []


def test_the_estimate_is_exact_on_the_simulator_and_an_upper_bound_by_construction() -> None:
    sim = simulator()
    outcome = sim.run(sim.spec(ProbeKind.QUANTILES, ["amount"]))
    assert outcome.status is ProbeStatus.COMPLETED
    assert outcome.cost_spent.bytes_scanned == outcome.estimated_cost.bytes_scanned
    assert outcome.bundle is not None
    assert outcome.bundle.cost_spent == outcome.cost_spent


def test_only_planned_columns_are_read() -> None:
    sim = simulator()
    sim.run(
        sim.spec(
            ProbeKind.QUANTILES,
            ["amount"],
            segment=segment(predicate("country", Operator.EQ, "PT")),
        )
    )
    assert sim.source.reads
    assert {columns for _, columns in sim.source.reads} == {("amount", "country")}


def test_a_no_change_probe_costs_one_catalog_read_and_says_so() -> None:
    sim = simulator()
    spec = sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["country"])
    first = sim.run(spec)
    assert first.status is ProbeStatus.COMPLETED
    reads, calls, spent = len(sim.source.reads), sim.source.metadata_calls, sim.source.bytes_read
    again = sim.run(spec)
    assert again.status is ProbeStatus.NO_CHANGE
    assert again.bundle is None
    assert again.cost_spent.bytes_scanned == 0
    assert again.estimated_cost.bytes_scanned == 0
    assert again.snapshot_id == first.snapshot_id
    assert len(sim.source.reads) == reads
    assert sim.source.bytes_read == spent
    assert sim.source.metadata_calls == calls + 1


def test_incremental_probes_read_only_the_delta() -> None:
    table = orders()
    sim = simulator(table, visible_commits=1)
    spec = sim.spec(ProbeKind.NULL_RATE, ["amount"])
    first = sim.run(spec)
    sim.source.publish()
    second = sim.run(spec)
    assert first.status is second.status is ProbeStatus.COMPLETED
    assert second.since_snapshot_id == first.snapshot_id
    assert first.bundle is not None
    assert second.bundle is not None
    first_rows = decode_envelope(first.bundle.sketches["exact_count:0"]).population
    second_rows = decode_envelope(second.bundle.sketches["exact_count:0"]).population
    assert first_rows == table.rows_between(None, 0)
    assert second_rows == table.rows_between(0, 1)
    assert second.cost_spent.bytes_scanned == pytest.approx(first.cost_spent.bytes_scanned)


def test_full_mode_ignores_the_incremental_state() -> None:
    table = orders()
    sim = simulator(table)
    spec = sim.spec(ProbeKind.NULL_RATE, ["amount"])
    sim.run(spec)
    outcome = sim.run(spec, mode=ExecutionMode.FULL)
    assert outcome.status is ProbeStatus.COMPLETED
    assert outcome.bundle is not None
    rows = decode_envelope(outcome.bundle.sketches["exact_count:0"]).population
    assert rows == table.rows_between(None, 2)


def test_an_overwrite_forces_a_full_rescan_and_says_so() -> None:
    table = orders(
        commits=(
            SyntheticCommit(rows=10_000),
            SyntheticCommit(rows=4_000, operation=DeltaKind.NON_ADDITIVE),
        )
    )
    sim = simulator(table, visible_commits=1)
    spec = sim.spec(ProbeKind.NULL_RATE, ["amount"])
    sim.run(spec)
    sim.source.publish()
    outcome = sim.run(spec)
    assert outcome.full_rescan
    assert outcome.bundle is not None
    assert decode_envelope(outcome.bundle.sketches["exact_count:0"]).population == 4_000


def test_a_compaction_commit_is_no_change() -> None:
    table = orders(
        commits=(
            SyntheticCommit(rows=10_000),
            SyntheticCommit(rows=0, operation=DeltaKind.NO_LOGICAL_CHANGE),
        )
    )
    sim = simulator(table, visible_commits=1)
    spec = sim.spec(ProbeKind.NULL_RATE, ["amount"])
    sim.run(spec)
    sim.source.publish()
    outcome = sim.run(spec)
    assert outcome.status is ProbeStatus.NO_CHANGE
    assert outcome.snapshot_id == table.snapshot_id(1)
    assert sim.state.last_snapshot(spec.key) == table.snapshot_id(1)


def test_cancellation_stops_at_a_batch_boundary_and_records_partial_cost() -> None:
    sim = simulator(batch_rows=1_000)
    flag = CancelFlag()
    calls = 0

    class CancelAfterThree:
        def cancelled(self) -> CancelReason | None:
            nonlocal calls
            calls += 1
            if calls >= 3:
                flag.cancel()
            return flag.cancelled()

    spec = sim.spec(ProbeKind.QUANTILES, ["amount"])
    outcome = sim.run(spec, cancel=CancelAfterThree())
    assert outcome.status is ProbeStatus.CANCELLED
    assert outcome.cancel_reason is CancelReason.REQUESTED
    assert outcome.bundle is None
    assert 0 < outcome.cost_spent.bytes_scanned < outcome.estimated_cost.bytes_scanned
    assert sim.state.last_snapshot(spec.key) is None


def test_same_spec_same_snapshot_gives_byte_identical_bundles() -> None:
    spec_a = simulator().spec(ProbeKind.QUANTILES, ["amount"], sketches=[SketchKind.KLL])
    first = simulator().run(spec_a)
    second = simulator(batch_rows=777).run(spec_a)
    assert first.bundle is not None
    assert second.bundle is not None
    assert first.bundle.model_dump_json() == second.bundle.model_dump_json()
    assert first.bundle.bundle_id == bundle_id(spec_a.key, None, first.snapshot_id, spec_a.seed)
    assert first.bundle.produced_at == orders().snapshot(2).committed_at


def test_bundles_recover_the_generating_statistics() -> None:
    table = orders(commits=(SyntheticCommit(rows=60_000),))
    sim = simulator(table)
    spec = sim.spec(
        ProbeKind.QUANTILES,
        ["amount", "country"],
        sketches=[SketchKind.EXACT_COUNT, SketchKind.THETA],
    )
    outcome = sim.run(spec)
    assert outcome.bundle is not None
    nulls = decode_envelope(outcome.bundle.sketches["exact_count:0"])
    assert isinstance(nulls, NullRate)
    assert nulls.population == 60_000
    assert nulls.rate() == pytest.approx(AMOUNT.null_fraction, abs=0.005)
    distinct = decode_envelope(outcome.bundle.sketches["theta:1"])
    assert isinstance(distinct, ThetaNdv)
    assert distinct.estimate() == pytest.approx(len(COUNTRY.categories))

    quantiles = sim.run(sim.spec(ProbeKind.QUANTILES, ["amount"], params={"k": 200}))
    assert quantiles.bundle is not None
    kll = decode_envelope(quantiles.bundle.sketches["kll:0"])
    assert isinstance(kll, KllQuantile)
    # Lognormal(3.2, 0.7): the median is exp(3.2). Rank error is about 1% at k=200.
    median = math.exp(AMOUNT.mean)
    assert kll.rank(median) == pytest.approx(0.5, abs=0.02)

    shares = sim.run(sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["country"]))
    assert shares.bundle is not None
    histogram = decode_envelope(shares.bundle.sketches["frequent_items:0"])
    assert isinstance(histogram, CategoryHistogram)
    counts = {key.reveal(): count for key, count in histogram.categories()}
    total = sum(counts.values())
    for category, probability in zip(COUNTRY.categories, COUNTRY.probabilities(), strict=True):
        assert counts[f"s:{category}"] / total == pytest.approx(probability, abs=0.01)


def test_segment_row_count_matches_an_exact_count_of_the_generated_rows() -> None:
    table = orders(commits=(SyntheticCommit(rows=40_000),))
    sim = simulator(table)
    where = segment(
        predicate("country", Operator.EQ, "PT"), predicate("status", Operator.EQ, "refund")
    )
    outcome = sim.run(sim.spec(ProbeKind.ROW_COUNT, [], segment=where))
    assert outcome.bundle is not None
    counted = decode_envelope(outcome.bundle.sketches["exact_count:table"]).population

    source = simulator(table).source
    ref = table.source_ref()
    delta = source.delta(ref, since=None, until=table.snapshot(0))
    exact = 0
    for data_file in delta.files:
        for batch in source.read(ref, data_file, columns=["country", "status"], batch_rows=10_000):
            rows = batch.to_pylist()
            exact += sum(1 for row in rows if row["country"] == "PT" and row["status"] == "refund")
    assert counted == exact


def test_universe_row_count_comes_from_manifests_for_free() -> None:
    table = orders()
    sim = simulator(table)
    outcome = sim.run(sim.spec(ProbeKind.ROW_COUNT, []))
    assert outcome.metadata_only
    assert outcome.cost_spent.bytes_scanned == 0
    assert sim.source.reads == []
    assert outcome.bundle is not None
    assert decode_envelope(outcome.bundle.sketches["exact_count:table"]).population == (
        table.rows_between(None, 2)
    )


def test_drift_in_the_third_commit_is_visible_in_its_delta_only() -> None:
    table = orders()
    sim = simulator(table, visible_commits=0)
    spec = sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["country"])
    shares: list[float] = []
    for _ in table.commits:
        sim.source.publish()
        outcome = sim.run(spec)
        assert outcome.bundle is not None
        histogram = decode_envelope(outcome.bundle.sketches["frequent_items:0"])
        assert isinstance(histogram, CategoryHistogram)
        counts = {key.reveal(): count for key, count in histogram.categories()}
        shares.append(counts["s:PT"] / sum(counts.values()))
    assert shares[0] == pytest.approx(0.03, abs=0.01)
    assert shares[1] == pytest.approx(0.03, abs=0.01)
    assert shares[2] == pytest.approx(0.18, abs=0.01)
    assert statistics.fmean(shares[:2]) < shares[2] / 3


def test_graph_degree_over_opaque_identifiers_completes() -> None:
    sim = simulator(orders(commits=(SyntheticCommit(rows=5_000),)))
    outcome = sim.run(sim.spec(ProbeKind.GRAPH_DEGREE, ["email", "device_id"]))
    assert outcome.status is ProbeStatus.COMPLETED
    assert outcome.bundle is not None
    envelope = outcome.bundle.sketches["count_min:graph"]
    assert envelope.population == 5_000
    # Neither the raw identifiers nor the column-level digests appear in the payload:
    # the stored keys are the sketch key's digests of the column key's digests.
    assert b"user-" not in envelope.payload
    assert b"dev-" not in envelope.payload
    assert re.search(rb"h_[0-9a-f]{32}", envelope.payload) is None


def test_unreachable_budget_is_not_widened_by_retrying() -> None:
    sim = simulator()
    spec = sim.spec(ProbeKind.QUANTILES, ["amount"])
    tight: CostBudget = generous_budget(bytes_scanned=1)
    first = sim.run(spec, budget=tight)
    second = sim.run(spec, budget=tight)
    assert first.status is second.status is ProbeStatus.REFUSED
    assert first.refusal == second.refusal
