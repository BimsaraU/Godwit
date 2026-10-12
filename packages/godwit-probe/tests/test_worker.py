"""The worker runtime: SKIP LOCKED claims, leases, idempotent writes, cancellation, limits.

Runs on SQLite by default, so ``make test`` needs no Docker. Set ``GODWIT_PROBE_PG_URL``
to a Postgres URL to run the same tests against ``FOR UPDATE SKIP LOCKED`` and the
per-source advisory lock for real.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import os
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from _probe_support import MODES, orders, simulator
from godwit_contracts import CostBudget, CostSpend, ProbeKind, ProbeSpec, SourceId, SourceRef
from godwit_probe import (
    CancelToken,
    ErrorCode,
    ExecutionMode,
    JobQueue,
    ProbeExecutor,
    ProbeOutcome,
    ProbeStatus,
    ProbeWorker,
    WorkerPool,
    make_engine,
)
from godwit_probe.testing import (
    FailurePoint,
    ProbeSimulator,
    SyntheticCommit,
    SyntheticSource,
    access_map,
    generous_budget,
)
from godwit_probe.worker import Heartbeat, JobState, metadata
from sqlalchemy import Engine


class ManualClock:
    def __init__(self) -> None:
        self.at = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
        self._lock = threading.Lock()

    def now(self) -> _dt.datetime:
        with self._lock:
            return self.at

    def advance(self, delta: _dt.timedelta) -> None:
        with self._lock:
            self.at += delta


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    url = os.environ.get("GODWIT_PROBE_PG_URL") or f"sqlite:///{(tmp_path / 'q.db').as_posix()}"
    built = make_engine(url)
    metadata.drop_all(built)
    metadata.create_all(built)
    yield built
    built.dispose()


def spec_for(sim: ProbeSimulator, probe_id: str = "p-1") -> ProbeSpec:
    return sim.spec(ProbeKind.NULL_RATE, ["amount"], probe_id=probe_id)


def executor_on(sim: ProbeSimulator, jobs: JobQueue) -> ProbeExecutor:
    """An executor over the simulator whose incremental state lives in the queue's DB."""
    return ProbeExecutor(sim.source, access=sim.access, state=jobs.state)


def test_enqueue_is_idempotent_on_the_probe_id(engine: Engine) -> None:
    jobs = JobQueue(engine)
    sim = simulator()
    assert jobs.enqueue(spec_for(sim), budget=generous_budget()) == "p-1"
    assert jobs.enqueue(spec_for(sim), budget=generous_budget()) == "p-1"
    assert jobs.pending() == 1


def test_a_drained_queue_stores_one_bundle_and_advances_the_state(engine: Engine) -> None:
    jobs = JobQueue(engine)
    sim = simulator()
    spec = spec_for(sim)
    jobs.enqueue(spec, budget=generous_budget())
    worker = ProbeWorker(jobs, lambda _s: executor_on(sim, jobs), worker_id="w-1")
    WorkerPool([worker]).run_until_idle(jobs)
    record = jobs.job("p-1")
    assert record is not None
    assert record.state is JobState.DONE
    assert record.outcome_status is ProbeStatus.COMPLETED
    assert len(jobs.bundles(spec.key)) == 1
    assert jobs.state.last_snapshot(spec.key) == orders().snapshot_id(2)


def test_the_next_job_for_the_same_probe_is_incremental(engine: Engine) -> None:
    jobs = JobQueue(engine)
    table = orders()
    sim = simulator(table, visible_commits=2)
    worker = ProbeWorker(jobs, lambda _s: executor_on(sim, jobs), worker_id="w-1")
    jobs.enqueue(spec_for(sim, "p-1"), budget=generous_budget())
    WorkerPool([worker]).run_until_idle(jobs)
    sim.source.publish()
    jobs.enqueue(spec_for(sim, "p-2"), budget=generous_budget())
    WorkerPool([worker]).run_until_idle(jobs)
    stored = jobs.bundles(spec_for(sim).key)
    assert [bundle.snapshot_id for bundle in stored] == [table.snapshot_id(1), table.snapshot_id(2)]
    populations = [bundle.sketches["exact_count:0"].population for bundle in stored]
    assert populations == [table.rows_between(None, 1), table.rows_between(1, 2)]


def test_redelivery_after_a_lost_lease_is_idempotent(engine: Engine) -> None:
    clock = ManualClock()
    jobs = JobQueue(engine, clock=clock, lease=_dt.timedelta(minutes=1))
    sim = simulator()
    spec = spec_for(sim)
    jobs.enqueue(spec, budget=generous_budget())

    first = jobs.claim("w-dies")
    assert first is not None
    late = executor_on(sim, jobs).execute(first.spec, budget=first.budget)
    clock.advance(_dt.timedelta(minutes=2))  # w-dies stalls past its lease
    second = jobs.claim("w-2")
    assert second is not None
    assert (second.job_id, second.attempt) == (first.job_id, 2)
    outcome = executor_on(sim, jobs).execute(second.spec, budget=second.budget)
    jobs.complete(second.job_id, "w-2", outcome)
    jobs.complete(first.job_id, "w-dies", late)  # the stalled worker wakes up

    assert len(jobs.bundles(spec.key)) == 1
    record = jobs.job(first.job_id)
    assert record is not None
    assert record.state is JobState.DONE
    assert jobs.heartbeat(first.job_id, "w-dies") is Heartbeat.LOST


def test_a_heartbeat_extends_the_lease(engine: Engine) -> None:
    clock = ManualClock()
    jobs = JobQueue(engine, clock=clock, lease=_dt.timedelta(minutes=1))
    jobs.enqueue(spec_for(simulator()), budget=generous_budget())
    assert jobs.claim("w-1") is not None
    clock.advance(_dt.timedelta(seconds=50))
    assert jobs.heartbeat("p-1", "w-1") is Heartbeat.OK
    clock.advance(_dt.timedelta(seconds=50))
    assert jobs.claim("w-2") is None


def test_cancelling_a_queued_job_never_runs_it(engine: Engine) -> None:
    jobs = JobQueue(engine)
    sim = simulator()
    jobs.enqueue(spec_for(sim), budget=generous_budget())
    jobs.request_cancel("p-1")
    assert jobs.claim("w-1") is None
    record = jobs.job("p-1")
    assert record is not None
    assert record.state is JobState.CANCELLED
    assert sim.source.reads == []


def test_cancelling_a_running_job_records_its_partial_cost(engine: Engine) -> None:
    jobs = JobQueue(engine)
    sim = simulator(batch_rows=1_000)
    spec = spec_for(sim)
    jobs.enqueue(spec, budget=generous_budget())

    def executor_for(_source: object) -> ProbeExecutor:
        jobs.request_cancel("p-1")  # arrives while the job is running
        return executor_on(sim, jobs)

    worker = ProbeWorker(jobs, executor_for, worker_id="w-1", heartbeat_every=2)
    assert worker.run_once()
    record = jobs.job("p-1")
    assert record is not None
    assert record.state is JobState.CANCELLED
    assert record.outcome_status is ProbeStatus.CANCELLED
    assert record.cost_json is not None
    assert CostSpend.model_validate_json(record.cost_json).bytes_scanned > 0
    assert jobs.bundles(spec.key) == ()
    assert jobs.state.last_snapshot(spec.key) is None


def test_failures_are_retried_then_recorded_by_code(engine: Engine) -> None:
    jobs = JobQueue(engine, max_attempts=3)
    sim = simulator()
    sim.source.inject(FailurePoint.DELTA, lambda: RuntimeError("boom"))
    jobs.enqueue(spec_for(sim), budget=generous_budget())
    worker = ProbeWorker(jobs, lambda _s: executor_on(sim, jobs), worker_id="w-1")
    WorkerPool([worker]).run_until_idle(jobs)
    record = jobs.job("p-1")
    assert record is not None
    assert record.state is JobState.FAILED
    assert record.attempts == 3
    assert record.error_code is ErrorCode.SOURCE_UNAVAILABLE


class Gauge:
    """Wraps executors and records the peak number running at once, per source."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.live: dict[str, int] = {}
        self.peak: dict[str, int] = {}

    def wrap(self, inner: ProbeExecutor) -> Measured:
        return Measured(self, inner)


class Measured:
    def __init__(self, gauge: Gauge, inner: ProbeExecutor) -> None:
        self._gauge = gauge
        self._inner = inner

    def execute(
        self,
        spec: ProbeSpec,
        *,
        budget: CostBudget,
        mode: ExecutionMode,
        cancel: CancelToken | None = None,
    ) -> ProbeOutcome:
        gauge, source = self._gauge, str(spec.source.source_id)
        with gauge._lock:
            gauge.live[source] = gauge.live.get(source, 0) + 1
            gauge.peak[source] = max(gauge.peak.get(source, 0), gauge.live[source])
        try:
            threading.Event().wait(0.05)
            return self._inner.execute(spec, budget=budget, mode=mode, cancel=cancel)
        finally:
            with gauge._lock:
                gauge.live[source] -= 1


def test_per_source_limit_holds_across_two_pools(engine: Engine) -> None:
    """Two pools, six workers, one customer database allowed two probes at a time."""
    base = orders(commits=(SyntheticCommit(rows=2_000),))
    busy = dataclasses.replace(base, source_id=SourceId("busy-db"))
    quiet = dataclasses.replace(base, name="refunds", source_id=SourceId("quiet-db"))
    source = SyntheticSource([busy])
    other = SyntheticSource([quiet])
    gauge = Gauge()
    pools = []
    for pool in ("a", "b"):
        jobs = JobQueue(engine, per_source_limit=2)
        busy_exec = ProbeExecutor(
            source, access=access_map(busy, MODES, at=busy.epoch), state=jobs.state
        )
        quiet_exec = ProbeExecutor(
            other, access=access_map(quiet, MODES, at=quiet.epoch), state=jobs.state
        )

        def executor_for(
            ref: SourceRef, b: ProbeExecutor = busy_exec, q: ProbeExecutor = quiet_exec
        ) -> Measured:
            return gauge.wrap(b if str(ref.source_id) == "busy-db" else q)

        pools.append(
            WorkerPool([ProbeWorker(jobs, executor_for, worker_id=f"{pool}-{i}") for i in range(3)])
        )
    producer = JobQueue(engine, per_source_limit=2)
    busy_sim = ProbeSimulator(busy, modes=MODES)
    quiet_sim = ProbeSimulator(quiet, modes=MODES)
    for index in range(8):
        producer.enqueue(
            busy_sim.spec(ProbeKind.NULL_RATE, ["amount"], probe_id=f"busy-{index}", seed=index),
            budget=generous_budget(),
        )
    for index in range(3):
        producer.enqueue(
            quiet_sim.spec(ProbeKind.NULL_RATE, ["amount"], probe_id=f"quiet-{index}", seed=index),
            budget=generous_budget(),
        )
    threads = [threading.Thread(target=pool.run_until_idle, args=(producer,)) for pool in pools]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert producer.pending() == 0
    assert gauge.peak["busy-db"] <= 2
    assert gauge.peak["quiet-db"] >= 1
