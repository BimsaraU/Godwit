"""The worker runtime: a Postgres jobs table, a pool, leases, cancellation, idempotency.

DATA PLANE. No Kafka, no Celery: a jobs table claimed with
``SELECT ... FOR UPDATE SKIP LOCKED``, which lets any number of workers in any number of
pools pull from one queue without ever claiming the same row twice.

DELIVERY
--------
At least once. A claim is a *lease* (``lease_until``); a worker that dies stops
heart-beating, its lease expires, and the next claim picks the job up again. Running a
probe twice is harmless because the write is idempotent: bundles are keyed on
``(probe_key, since_snapshot_id, snapshot_id)`` and inserted with ``ON CONFLICT DO
NOTHING``, and the incremental state advances in the **same transaction** as the bundle
write -- so "bundle stored" and "state advanced" are one fact, never two.

CANCELLATION
------------
``request_cancel`` on a queued job cancels it outright. On a running job it sets a flag
the worker reads at its next heartbeat, which happens every few batches through the
executor's :class:`~godwit_probe.executor.CancelToken`. The probe stops at a batch
boundary and the job records the partial cost it had already spent. A heartbeat that
finds the lease taken by someone else stops the probe the same way.

PER-SOURCE CONCURRENCY
----------------------
One pool must not saturate a customer's database. A claim skips any job whose source
already has ``per_source_limit`` live leases. On Postgres the count is taken under
``pg_advisory_xact_lock(hashtext(source_id))``, which serialises claims *for one source*
across every pool, so two pools racing for the last slot cannot both win. On SQLite
(tests, single host) ``BEGIN IMMEDIATE`` serialises every claim instead.

THE CLOCK
---------
Leases need a clock. :class:`SystemClock` is the one place in this package that reads
the wall clock, and it only decides *when a lease expires*: nothing it returns enters a
bundle, an outcome or a key. Tests inject a manual clock.

WHAT THE TABLES HOLD
--------------------
``spec_json`` is the ``ProbeSpec`` exactly as the orchestrator wrote it, including its
tainted segment predicate values. Treat the jobs table with the same care as the pattern
store. ``error_code`` holds a member of :class:`~godwit_probe.errors.ErrorCode` and
never a message; every database call here goes through
:func:`~godwit_probe.errors.guarded`, because a SQLAlchemy error renders its bound
parameters -- which would include the spec.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from godwit_contracts import CostBudget, ProbeKey, ProbeSpec, SketchBundle, SnapshotId, SourceRef
from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Connection,
    Engine,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    create_engine,
    event,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.dialects import postgresql, sqlite

from godwit_probe.errors import ErrorCode, ProbeError, Stage, guarded
from godwit_probe.executor import (
    CancelReason,
    ExecutionMode,
    ProbeExecutor,
    ProbeOutcome,
    ProbeStatus,
)
from godwit_probe.telemetry import Event, Field, ProbeTelemetry, SafeId, SafeValue

__all__ = [
    "ClaimedJob",
    "Clock",
    "Heartbeat",
    "JobQueue",
    "JobRecord",
    "JobState",
    "ProbeWorker",
    "SqlProbeState",
    "SystemClock",
    "WorkerPool",
    "make_engine",
    "metadata",
]

_US: Final[int] = 1_000_000

metadata = MetaData()

jobs = Table(
    "godwit_probe_jobs",
    metadata,
    Column(
        "seq", BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    ),
    Column("job_id", String(128), nullable=False, unique=True),
    Column("probe_key", String(64), nullable=False),
    Column("source_id", String(256), nullable=False, index=True),
    Column("spec_json", Text, nullable=False),
    Column("budget_json", Text, nullable=False),
    Column("mode", String(16), nullable=False),
    Column("state", String(16), nullable=False, index=True),
    Column("priority", Integer, nullable=False, default=0),
    Column("attempts", Integer, nullable=False, default=0),
    Column("max_attempts", Integer, nullable=False, default=3),
    Column("lease_owner", String(128), nullable=True),
    Column("lease_until_us", BigInteger, nullable=True),
    Column("cancel_requested", Boolean, nullable=False, default=False),
    Column("outcome_status", String(16), nullable=True),
    Column("error_code", String(32), nullable=True),
    Column("cost_json", Text, nullable=True),
)

bundles = Table(
    "godwit_probe_bundles",
    metadata,
    Column("probe_key", String(64), primary_key=True),
    Column("since_snapshot_id", String(128), primary_key=True),
    Column("snapshot_id", String(128), primary_key=True),
    Column("bundle_id", String(64), nullable=False),
    Column("bundle_json", Text, nullable=False),
    Column("outcome_json", Text, nullable=False),
)

probe_state = Table(
    "godwit_probe_state",
    metadata,
    Column("probe_key", String(64), primary_key=True),
    Column("last_snapshot_id", String(128), nullable=False),
)


class JobState(StrEnum):
    """Where a job is in its life."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    CANCELLED = "cancelled"
    FAILED = "failed"


class Heartbeat(StrEnum):
    """What a heartbeat found."""

    OK = "ok"
    CANCEL = "cancel"
    LOST = "lost"


class Clock(Protocol):
    """Where lease timing comes from."""

    def now(self) -> _dt.datetime:
        """The current instant, tz-aware."""
        ...


class SystemClock:
    """The wall clock. Lease timing only; see the module docstring."""

    def now(self) -> _dt.datetime:
        """The current UTC instant."""
        return _dt.datetime.now(_dt.UTC)


def make_engine(url: str) -> Engine:
    """An engine for the queue. On SQLite, every transaction is ``BEGIN IMMEDIATE``."""
    if not url.startswith("sqlite"):
        return create_engine(url)
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 60})

    def on_connect(dbapi_connection: sqlite3.Connection, _record: object) -> None:
        dbapi_connection.isolation_level = None

    def on_begin(connection: Connection) -> None:
        connection.exec_driver_sql("BEGIN IMMEDIATE")

    event.listen(engine, "connect", on_connect)
    event.listen(engine, "begin", on_begin)
    return engine


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    """A job this worker now holds a lease on."""

    job_id: str
    spec: ProbeSpec
    budget: CostBudget
    mode: ExecutionMode
    attempt: int


@dataclass(frozen=True, slots=True)
class JobRecord:
    """A job row, for inspection. No spec: it holds tainted values."""

    job_id: str
    state: JobState
    attempts: int
    outcome_status: ProbeStatus | None
    error_code: ErrorCode | None
    cost_json: str | None


def _us(value: _dt.datetime) -> int:
    delta = value.astimezone(_dt.UTC) - _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)
    return delta // _dt.timedelta(microseconds=1)


class SqlProbeState:
    """The incremental state, in the queue's database. Satisfies ``ProbeState``."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def last_snapshot(self, probe_key: ProbeKey) -> SnapshotId | None:
        """See ``ProbeState``."""

        def read() -> SnapshotId | None:
            with self._engine.connect() as conn:
                value = conn.execute(
                    select(probe_state.c.last_snapshot_id).where(
                        probe_state.c.probe_key == str(probe_key)
                    )
                ).scalar_one_or_none()
            return None if value is None else SnapshotId(value)

        return guarded(Stage.STORE, ErrorCode.STORE_FAILED, read)

    def advance(self, probe_key: ProbeKey, snapshot_id: SnapshotId) -> None:
        """See ``ProbeState``."""

        def write() -> None:
            with self._engine.begin() as conn:
                _upsert_state(conn, probe_key, snapshot_id)

        guarded(Stage.STORE, ErrorCode.STORE_FAILED, write)


def _insert_ignore(conn: Connection, values: dict[str, str]) -> None:
    dialect = conn.dialect.name
    if dialect == "postgresql":
        conn.execute(postgresql.insert(bundles).values(**values).on_conflict_do_nothing())
    else:
        conn.execute(sqlite.insert(bundles).values(**values).on_conflict_do_nothing())


def _upsert_state(conn: Connection, probe_key: ProbeKey, snapshot_id: SnapshotId) -> None:
    values = {"probe_key": str(probe_key), "last_snapshot_id": str(snapshot_id)}
    if conn.dialect.name == "postgresql":
        statement = postgresql.insert(probe_state).values(**values)
        conn.execute(
            statement.on_conflict_do_update(
                index_elements=["probe_key"], set_={"last_snapshot_id": str(snapshot_id)}
            )
        )
    else:
        lite = sqlite.insert(probe_state).values(**values)
        conn.execute(
            lite.on_conflict_do_update(
                index_elements=["probe_key"], set_={"last_snapshot_id": str(snapshot_id)}
            )
        )


class JobQueue:
    """The Postgres jobs table and the bundle store beside it."""

    def __init__(
        self,
        engine: Engine,
        *,
        clock: Clock | None = None,
        lease: _dt.timedelta = _dt.timedelta(minutes=5),
        per_source_limit: int = 2,
        max_attempts: int = 3,
    ) -> None:
        if per_source_limit < 1:
            raise ValueError("per_source_limit must be at least 1")
        self._engine = engine
        self._clock = clock if clock is not None else SystemClock()
        self._lease_us = lease // _dt.timedelta(microseconds=1)
        self._limit = per_source_limit
        self._max_attempts = max_attempts
        self.state = SqlProbeState(engine)

    def create_schema(self) -> None:
        """Create the three tables if they do not exist."""
        guarded(Stage.STORE, ErrorCode.STORE_FAILED, lambda: metadata.create_all(self._engine))

    def _now(self) -> int:
        return _us(self._clock.now())

    # -- producer side ------------------------------------------------------------------

    def enqueue(
        self,
        spec: ProbeSpec,
        *,
        budget: CostBudget,
        mode: ExecutionMode = ExecutionMode.INCREMENTAL,
        priority: int = 0,
    ) -> str:
        """Queue a probe. The job id is the spec's ``probe_id``; enqueueing twice is a no-op."""
        job_id = str(spec.probe_id)

        def write() -> None:
            with self._engine.begin() as conn:
                exists = conn.execute(
                    select(jobs.c.seq).where(jobs.c.job_id == job_id)
                ).scalar_one_or_none()
                if exists is not None:
                    return
                conn.execute(
                    jobs.insert().values(
                        job_id=job_id,
                        probe_key=str(spec.key),
                        source_id=str(spec.source.source_id),
                        spec_json=spec.model_dump_json(),
                        budget_json=budget.model_dump_json(),
                        mode=mode.value,
                        state=JobState.QUEUED.value,
                        priority=priority,
                        attempts=0,
                        max_attempts=self._max_attempts,
                        cancel_requested=False,
                    )
                )

        guarded(Stage.STORE, ErrorCode.STORE_FAILED, write)
        return job_id

    def request_cancel(self, job_id: str) -> None:
        """Cancel a queued job now, or ask a running one to stop at its next heartbeat."""

        def write() -> None:
            with self._engine.begin() as conn:
                conn.execute(
                    update(jobs)
                    .where(jobs.c.job_id == job_id, jobs.c.state == JobState.QUEUED.value)
                    .values(state=JobState.CANCELLED.value)
                )
                conn.execute(
                    update(jobs)
                    .where(jobs.c.job_id == job_id, jobs.c.state == JobState.RUNNING.value)
                    .values(cancel_requested=True)
                )

        guarded(Stage.STORE, ErrorCode.STORE_FAILED, write)

    # -- worker side --------------------------------------------------------------------

    def claim(self, worker_id: str) -> ClaimedJob | None:
        """Lease the next claimable job whose source has a free slot, or return None."""
        return guarded(Stage.STORE, ErrorCode.STORE_FAILED, lambda: self._claim(worker_id))

    def _claim(self, worker_id: str) -> ClaimedJob | None:
        skipped: set[str] = set()
        while True:
            now = self._now()
            with self._engine.begin() as conn:
                live = and_(jobs.c.state == JobState.RUNNING.value, jobs.c.lease_until_us > now)
                saturated = (
                    select(jobs.c.source_id)
                    .where(live)
                    .group_by(jobs.c.source_id)
                    .having(func.count() >= self._limit)
                )
                claimable = or_(
                    jobs.c.state == JobState.QUEUED.value,
                    and_(jobs.c.state == JobState.RUNNING.value, jobs.c.lease_until_us <= now),
                )
                candidate = (
                    select(jobs)
                    .where(claimable, jobs.c.source_id.not_in(saturated))
                    .order_by(jobs.c.priority.desc(), jobs.c.seq)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                if skipped:
                    candidate = candidate.where(jobs.c.source_id.not_in(sorted(skipped)))
                row = conn.execute(candidate).mappings().first()
                if row is None:
                    return None
                if row["attempts"] >= row["max_attempts"]:
                    conn.execute(
                        update(jobs)
                        .where(jobs.c.seq == row["seq"])
                        .values(state=JobState.FAILED.value, lease_owner=None)
                    )
                    continue
                if conn.dialect.name == "postgresql":
                    conn.execute(
                        select(func.pg_advisory_xact_lock(func.hashtext(row["source_id"])))
                    )
                    running = conn.execute(
                        select(func.count())
                        .select_from(jobs)
                        .where(live, jobs.c.source_id == row["source_id"])
                    ).scalar_one()
                    if running >= self._limit:
                        skipped.add(row["source_id"])
                        continue
                conn.execute(
                    update(jobs)
                    .where(jobs.c.seq == row["seq"])
                    .values(
                        state=JobState.RUNNING.value,
                        lease_owner=worker_id,
                        lease_until_us=now + self._lease_us,
                        attempts=jobs.c.attempts + 1,
                    )
                )
                return ClaimedJob(
                    job_id=row["job_id"],
                    spec=ProbeSpec.model_validate_json(row["spec_json"]),
                    budget=CostBudget.model_validate_json(row["budget_json"]),
                    mode=ExecutionMode(row["mode"]),
                    attempt=row["attempts"] + 1,
                )

    def heartbeat(self, job_id: str, worker_id: str) -> Heartbeat:
        """Extend the lease, and report whether to stop."""

        def beat() -> Heartbeat:
            with self._engine.begin() as conn:
                row = conn.execute(
                    select(jobs.c.lease_owner, jobs.c.cancel_requested, jobs.c.state).where(
                        jobs.c.job_id == job_id
                    )
                ).first()
                if row is None or row.lease_owner != worker_id or row.state != "running":
                    return Heartbeat.LOST
                conn.execute(
                    update(jobs)
                    .where(jobs.c.job_id == job_id)
                    .values(lease_until_us=self._now() + self._lease_us)
                )
                return Heartbeat.CANCEL if row.cancel_requested else Heartbeat.OK

        return guarded(Stage.STORE, ErrorCode.STORE_FAILED, beat)

    def complete(self, job_id: str, worker_id: str, outcome: ProbeOutcome) -> None:
        """Store the bundle, advance the state and close the job, in one transaction.

        The bundle and the state are written even if the lease has since moved to another
        worker: both writes are idempotent, and the other worker would write the same
        thing. Only the job row is left to its current owner.
        """

        def write() -> None:
            with self._engine.begin() as conn:
                if outcome.bundle is not None:
                    _insert_ignore(
                        conn,
                        {
                            "probe_key": str(outcome.probe_key),
                            "since_snapshot_id": str(outcome.since_snapshot_id or ""),
                            "snapshot_id": str(outcome.snapshot_id),
                            "bundle_id": outcome.bundle.bundle_id,
                            "bundle_json": outcome.bundle.model_dump_json(),
                            "outcome_json": outcome.model_dump_json(exclude={"bundle"}),
                        },
                    )
                if outcome.covers_snapshot:
                    _upsert_state(conn, outcome.probe_key, outcome.snapshot_id)
                final = (
                    JobState.CANCELLED if outcome.status is ProbeStatus.CANCELLED else JobState.DONE
                )
                conn.execute(
                    update(jobs)
                    .where(jobs.c.job_id == job_id, jobs.c.lease_owner == worker_id)
                    .values(
                        state=final.value,
                        outcome_status=outcome.status.value,
                        cost_json=outcome.cost_spent.model_dump_json(),
                        lease_owner=None,
                    )
                )

        guarded(Stage.STORE, ErrorCode.STORE_FAILED, write)

    def fail(self, job_id: str, worker_id: str, code: ErrorCode) -> None:
        """Record a failure by code. Retried until ``max_attempts``, then failed."""

        def write() -> None:
            with self._engine.begin() as conn:
                row = conn.execute(
                    select(jobs.c.attempts, jobs.c.max_attempts).where(
                        jobs.c.job_id == job_id, jobs.c.lease_owner == worker_id
                    )
                ).first()
                if row is None:
                    return
                retry = row.attempts < row.max_attempts
                conn.execute(
                    update(jobs)
                    .where(jobs.c.job_id == job_id)
                    .values(
                        state=(JobState.QUEUED if retry else JobState.FAILED).value,
                        error_code=code.value,
                        lease_owner=None,
                        lease_until_us=None,
                    )
                )

        guarded(Stage.STORE, ErrorCode.STORE_FAILED, write)

    # -- inspection ---------------------------------------------------------------------

    def pending(self) -> int:
        """Jobs queued or running."""

        def read() -> int:
            with self._engine.connect() as conn:
                return int(
                    conn.execute(
                        select(func.count())
                        .select_from(jobs)
                        .where(jobs.c.state.in_([JobState.QUEUED.value, JobState.RUNNING.value]))
                    ).scalar_one()
                )

        return guarded(Stage.STORE, ErrorCode.STORE_FAILED, read)

    def job(self, job_id: str) -> JobRecord | None:
        """One job's status, without its spec."""

        def read() -> JobRecord | None:
            with self._engine.connect() as conn:
                row = conn.execute(select(jobs).where(jobs.c.job_id == job_id)).mappings().first()
            if row is None:
                return None
            return JobRecord(
                job_id=row["job_id"],
                state=JobState(row["state"]),
                attempts=row["attempts"],
                outcome_status=(
                    None if row["outcome_status"] is None else ProbeStatus(row["outcome_status"])
                ),
                error_code=None if row["error_code"] is None else ErrorCode(row["error_code"]),
                cost_json=row["cost_json"],
            )

        return guarded(Stage.STORE, ErrorCode.STORE_FAILED, read)

    def bundles(self, probe_key: ProbeKey) -> tuple[SketchBundle, ...]:
        """Every stored bundle for a probe key, oldest snapshot first by insertion key."""

        def read() -> tuple[SketchBundle, ...]:
            with self._engine.connect() as conn:
                rows = conn.execute(
                    select(bundles.c.bundle_json)
                    .where(bundles.c.probe_key == str(probe_key))
                    .order_by(bundles.c.snapshot_id)
                ).all()
            return tuple(SketchBundle.model_validate_json(row.bundle_json) for row in rows)

        return guarded(Stage.STORE, ErrorCode.STORE_FAILED, read)


class _JobCancelToken:
    """Heart-beats every ``every`` polls; stops the probe on cancel or a lost lease."""

    def __init__(self, queue: JobQueue, job_id: str, worker_id: str, every: int) -> None:
        self._queue = queue
        self._job_id = job_id
        self._worker_id = worker_id
        self._every = every
        self._polls = 0

    def cancelled(self) -> CancelReason | None:
        self._polls += 1
        if self._polls % self._every:
            return None
        beat = self._queue.heartbeat(self._job_id, self._worker_id)
        if beat is Heartbeat.CANCEL:
            return CancelReason.REQUESTED
        if beat is Heartbeat.LOST:
            return CancelReason.LEASE_LOST
        return None


class ProbeWorker:
    """Claims one job at a time and runs it to an outcome."""

    def __init__(
        self,
        queue: JobQueue,
        executor_for: Callable[[SourceRef], ProbeExecutor],
        *,
        worker_id: str,
        telemetry: ProbeTelemetry | None = None,
        heartbeat_every: int = 4,
    ) -> None:
        self._queue = queue
        self._executor_for = executor_for
        self.worker_id = worker_id
        self._telemetry = telemetry if telemetry is not None else ProbeTelemetry()
        self._every = max(1, heartbeat_every)

    def run_once(self) -> bool:
        """Claim and run one job. False when nothing was claimable."""
        job = self._queue.claim(self.worker_id)
        if job is None:
            return False
        fields: dict[Field, SafeValue] = {
            Field.JOB: SafeId.of("job", job.job_id),
            Field.WORKER: SafeId.of("wrk", self.worker_id),
            Field.ATTEMPT: job.attempt,
        }
        self._telemetry.event(Event.JOB_CLAIMED, fields)
        token = _JobCancelToken(self._queue, job.job_id, self.worker_id, self._every)
        executor = self._executor_for(job.spec.source)
        failure: ProbeError | None = None
        outcome: ProbeOutcome | None = None
        try:
            outcome = executor.execute(job.spec, budget=job.budget, mode=job.mode, cancel=token)
        except ProbeError as error:
            failure = error
        if failure is not None:
            self._queue.fail(job.job_id, self.worker_id, failure.code)
            self._telemetry.event(
                Event.JOB_FAILED, {**fields, Field.CODE: failure.code, Field.STAGE: failure.stage}
            )
            return True
        if outcome is not None:
            self._queue.complete(job.job_id, self.worker_id, outcome)
            self._telemetry.event(
                Event.JOB_FINISHED,
                {**fields, Field.STATUS: outcome.status, Field.REASON: outcome.reason},
            )
        return True


class WorkerPool:
    """A few :class:`ProbeWorker` threads over one queue."""

    def __init__(self, workers: Sequence[ProbeWorker]) -> None:
        if not workers:
            raise ValueError("a pool needs at least one worker")
        self._workers = tuple(workers)

    def run_until_idle(self, queue: JobQueue, *, idle_wait: float = 0.01) -> None:
        """Run until the queue has nothing queued or running. For tests and batch drains.

        A worker that finds nothing claimable while jobs are still pending -- their
        sources are at the concurrency limit -- waits and tries again rather than exiting.
        """
        pause = threading.Event()

        def drain(worker: ProbeWorker) -> None:
            while worker.run_once() or queue.pending():
                pause.wait(idle_wait)

        threads = [threading.Thread(target=drain, args=(worker,)) for worker in self._workers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def run(self, stop: threading.Event, *, idle_wait: float = 1.0) -> None:
        """Run until ``stop`` is set, waiting ``idle_wait`` seconds when idle."""

        def loop(worker: ProbeWorker) -> None:
            while not stop.is_set():
                if not worker.run_once():
                    stop.wait(idle_wait)

        threads = [threading.Thread(target=loop, args=(worker,)) for worker in self._workers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
