"""ACCEPTANCE: batch and streaming over the same data produce identical bundles.

Streaming here is what it is in production: a writer commits, the poller sees a new
snapshot in the catalog and probes the delta. Batch is a backfill over the same history
in one call. Both go through ``advance``; the test compares bundle JSON byte for byte and
the resulting ``TimeHierarchy`` series by canonical bytes.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from _probe_support import orders, simulator
from godwit_contracts import ProbeKind, ProbeSpec, SketchKind
from godwit_probe import CatalogPoller, ProbeStatus, SketchSeries, backfill
from godwit_probe.testing import ProbeSimulator, SyntheticCommit, generous_budget
from godwit_sketch import NullRate, ThetaNdv, decode_envelope
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

SKETCHES = (
    SketchKind.KLL,
    SketchKind.THETA,
    SketchKind.HLL,
    SketchKind.EXACT_COUNT,
)


def _specs(sim: ProbeSimulator) -> tuple[ProbeSpec, ...]:
    return (
        sim.spec(ProbeKind.QUANTILES, ["amount"], sketches=SKETCHES, params={"k": 64}),
        sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["country", "status"]),
        sim.spec(ProbeKind.HEAVY_HITTERS, ["device_id"], params={"capacity": 32}),
    )


def test_streaming_and_backfill_bundles_are_byte_identical() -> None:
    table = orders(
        commits=tuple(SyntheticCommit(rows=r) for r in (7_000, 3_000, 11_000, 1, 5_000, 9_000)),
        rows_per_file=4_000,
        block_rows=1_500,
    )
    live = simulator(table, visible_commits=0, batch_rows=700)
    poller = CatalogPoller(live.executor, live.state)
    streamed: dict[str, list[str]] = {}
    for _ in table.commits:
        live.source.publish()
        for spec in _specs(live):
            for outcome in poller.poll(spec, budget=generous_budget()):
                assert outcome.status is ProbeStatus.COMPLETED
                assert outcome.bundle is not None
                streamed.setdefault(str(spec.key), []).append(outcome.bundle.model_dump_json())
        # A poll with nothing new is a catalog read and nothing else.
        before = live.source.bytes_read
        for spec in _specs(live):
            (idle,) = poller.poll(spec, budget=generous_budget())
            assert idle.status is ProbeStatus.NO_CHANGE
        assert live.source.bytes_read == before

    batch = simulator(table, batch_rows=4_096)
    for spec in _specs(batch):
        outcomes = backfill(batch.executor, batch.state, spec, budget=generous_budget())
        assert len(outcomes) == len(table.commits)
        bundles = [o.bundle.model_dump_json() for o in outcomes if o.bundle is not None]
        assert bundles == streamed[str(spec.key)]


def test_both_modes_feed_identical_time_hierarchies() -> None:
    table = orders(
        commits=tuple(SyntheticCommit(rows=r) for r in (2_000, 2_000, 2_000, 2_000)),
        rows_per_file=1_500,
    )
    live = simulator(table, visible_commits=0)
    spec = live.spec(ProbeKind.QUANTILES, ["amount"], sketches=SKETCHES, params={"k": 64})
    poller = CatalogPoller(live.executor, live.state)
    base, epoch = _dt.timedelta(minutes=10), table.epoch
    streaming = SketchSeries(base=base, epoch=epoch)
    for _ in table.commits:
        live.source.publish()
        for outcome in poller.poll(spec, budget=generous_budget()):
            assert outcome.bundle is not None
            streaming.add(outcome.bundle)

    batch = simulator(table)
    outcomes = backfill(batch.executor, batch.state, spec, budget=generous_budget())
    reversed_bundles = [o.bundle for o in reversed(outcomes) if o.bundle is not None]
    batch_series = SketchSeries.from_bundles(reversed_bundles, base=base, epoch=epoch)
    assert streaming.canonical_bytes() == batch_series.canonical_bytes()


def test_exact_sketches_merged_over_deltas_equal_one_full_probe() -> None:
    table = orders(commits=tuple(SyntheticCommit(rows=r) for r in (4_000, 6_000, 5_000)))
    sim = simulator(table)
    spec = sim.spec(
        ProbeKind.DISTINCT_COUNT, ["country"], sketches=[SketchKind.THETA, SketchKind.EXACT_COUNT]
    )
    deltas = backfill(sim.executor, sim.state, spec, budget=generous_budget())
    full = simulator(table).run(spec)
    assert full.bundle is not None
    for name, cls in (("theta:0", ThetaNdv), ("exact_count:0", NullRate)):
        parts = [decode_envelope(o.bundle.sketches[name]) for o in deltas if o.bundle]
        merged = parts[0]
        for part in parts[1:]:
            assert isinstance(part, cls)
            merged = merged.merge(part)
        assert merged.encode() == decode_envelope(full.bundle.sketches[name]).encode()


def test_a_refusal_mid_history_stops_without_skipping_a_commit() -> None:
    table = orders(commits=tuple(SyntheticCommit(rows=r) for r in (2_000, 50_000, 2_000)))
    sim = simulator(table)
    spec = sim.spec(ProbeKind.NULL_RATE, ["amount"])
    first = sim.run(spec, budget=generous_budget(bytes_scanned=10**9))
    assert first.status is ProbeStatus.COMPLETED
    sim.state.advance(spec.key, table.snapshot_id(0))
    outcomes = backfill(sim.executor, sim.state, spec, budget=generous_budget(bytes_scanned=50_000))
    assert [o.status for o in outcomes] == [ProbeStatus.REFUSED]
    assert sim.state.last_snapshot(spec.key) == table.snapshot_id(0)


@pytest.mark.parametrize("batch_rows", [1, 333, 100_000])
def test_batch_size_never_changes_a_bundle(batch_rows: int) -> None:
    table = orders(commits=(SyntheticCommit(rows=3_000),), rows_per_file=1_000, block_rows=700)
    reference = simulator(table).run(
        simulator(table).spec(ProbeKind.QUANTILES, ["amount"], sketches=SKETCHES)
    )
    other = simulator(table, batch_rows=batch_rows)
    outcome = other.run(other.spec(ProbeKind.QUANTILES, ["amount"], sketches=SKETCHES))
    assert reference.bundle is not None
    assert outcome.bundle is not None
    assert outcome.bundle.model_dump_json() == reference.bundle.model_dump_json()


@settings(max_examples=12, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    rows=st.lists(st.integers(min_value=1, max_value=1_500), min_size=1, max_size=5),
    schedule=st.lists(st.integers(min_value=1, max_value=3), min_size=1, max_size=5),
    batch_rows=st.integers(min_value=1, max_value=2_000),
)
def test_any_poll_schedule_gives_the_backfill_bundles(
    rows: list[int], schedule: list[int], batch_rows: int
) -> None:
    """However commits bunch up between polls, each commit gets the same bundle."""
    table = orders(
        commits=tuple(SyntheticCommit(rows=r) for r in rows), rows_per_file=700, block_rows=300
    )
    live = simulator(table, visible_commits=0, batch_rows=batch_rows)
    spec = live.spec(ProbeKind.QUANTILES, ["amount"], sketches=SKETCHES, params={"k": 32})
    poller = CatalogPoller(live.executor, live.state)
    streamed: list[str] = []
    for step in [*schedule, len(rows)]:
        live.source.publish(step)
        streamed += [
            o.bundle.model_dump_json()
            for o in poller.poll(spec, budget=generous_budget())
            if o.bundle is not None
        ]
    batch = simulator(table)
    expected = [
        o.bundle.model_dump_json()
        for o in backfill(batch.executor, batch.state, spec, budget=generous_budget())
        if o.bundle is not None
    ]
    assert streamed == expected
    assert len(expected) == len(rows)
