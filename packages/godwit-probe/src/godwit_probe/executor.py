"""The probe executor: ProbeSpec in, ProbeOutcome (and usually a SketchBundle) out.

DATA PLANE. One call does, in this order and never out of it:

1. **Resolve** the snapshot to measure up to -- the one given, the spec's, or the newest
   -- and the snapshot to measure *from*: the last one this probe key covered
   (incremental, the default), or none (full).
2. **Stop early if nothing changed.** Same snapshot: one catalog read, zero bytes,
   status ``NO_CHANGE``. A compaction-only commit: the same, after one manifest walk.
3. **List the delta** from manifests. A delete or overwrite in the range cannot be
   subtracted from a sketch, so the probe re-measures the whole snapshot and says so
   (``full_rescan``).
4. **Plan** against the access modes (:mod:`godwit_probe.plan`). An unsatisfiable spec
   is ``REFUSED`` with a reason.
5. **Estimate** from manifest sizes and **refuse** if the estimate does not fit the
   budget -- before a single data byte is read. ``REFUSED`` with the estimate attached,
   so the orchestrator can learn what the probe would have cost.
6. **Execute** file by file, batch by batch, into sketches. Between batches: check
   cancellation and the actual bytes against the budget. A cancelled probe reports what
   it had already spent.
7. **Serialise** into a ``SketchBundle`` whose every field is a function of
   (spec, since, until, data): ``produced_at`` is the snapshot's commit instant, not a
   clock, so batch and streaming produce byte-identical bundles.

The executor does not advance the incremental state. Whoever persists the bundle does
that, after the bundle is durable -- see :mod:`godwit_probe.stream` and
:mod:`godwit_probe.worker`.

Anything a dependency raises becomes a :class:`~godwit_probe.errors.ProbeError`; see
that module for why nothing of the original survives.
"""

from __future__ import annotations

import functools
import itertools
import threading
from collections.abc import Generator, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Final, Protocol, Self, runtime_checkable

import pyarrow as pa
from godwit_contracts import (
    CostBudget,
    CostSpend,
    Guardrail,
    LogicalType,
    ProbeId,
    ProbeKey,
    ProbeKind,
    ProbeSpec,
    SketchBundle,
    SketchEnvelope,
    SnapshotId,
    SnapshotRef,
    SourceId,
    canonical_json,
    content_hash,
)
from godwit_contracts.common import GodwitModel
from godwit_guard import AccessModeMap, verify_arrow_schema
from godwit_sketch import BaseSketch, NullRate, SketchContext
from pydantic import model_validator

from godwit_probe.accumulate import Accumulator
from godwit_probe.engine import QueryEngine
from godwit_probe.errors import ErrorCode, ProbeError, Stage, guarded, guarded_iter
from godwit_probe.keyring import ProbeKeyring
from godwit_probe.plan import (
    ROW_COUNT_FIELD,
    KeyPermission,
    PlannedSketch,
    ProbePlan,
    Refusal,
    RefusalReason,
    plan_probe,
)
from godwit_probe.source import DataFileRef, Delta, DeltaKind, ProbeSource
from godwit_probe.state import ProbeState
from godwit_probe.telemetry import Event, Field, ProbeTelemetry, SafeId, SafeValue

__all__ = [
    "DEFAULT_BATCH_ROWS",
    "WORKER_VERSION",
    "CancelFlag",
    "CancelReason",
    "CancelToken",
    "CostModel",
    "ExecutionMode",
    "ProbeExecutor",
    "ProbeOutcome",
    "ProbeStatus",
    "bundle_id",
]

WORKER_VERSION: Final[str] = "godwit-probe/0.1.0"
DEFAULT_BATCH_ROWS: Final[int] = 65_536


class ExecutionMode(StrEnum):
    """Where a probe measures from when no explicit ``since`` is given."""

    INCREMENTAL = "incremental"
    """From the last snapshot this probe key covered. The default."""

    FULL = "full"
    """From the beginning of the table."""


class ProbeStatus(StrEnum):
    """How a probe run ended. Only ``COMPLETED`` carries a bundle."""

    COMPLETED = "completed"
    NO_CHANGE = "no_change"
    REFUSED = "refused"
    CANCELLED = "cancelled"


class CancelReason(StrEnum):
    """Why a running probe stopped before finishing."""

    REQUESTED = "requested"
    BUDGET_EXHAUSTED = "budget_exhausted"
    LEASE_LOST = "lease_lost"


@runtime_checkable
class CancelToken(Protocol):
    """Polled between batches. Returning a reason stops the probe cleanly."""

    def cancelled(self) -> CancelReason | None:
        """A reason to stop now, or None to carry on."""
        ...


class CancelFlag:
    """A thread-safe token another thread can set."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Ask the probe to stop at the next batch boundary."""
        self._event.set()

    def cancelled(self) -> CancelReason | None:
        """See :class:`CancelToken`."""
        return CancelReason.REQUESTED if self._event.is_set() else None


@dataclass(frozen=True, slots=True)
class CostModel:
    """Turns bytes into money for ``CostSpend.usd``. Ours, not the customer's bill."""

    usd_per_gib: Decimal = Decimal(0)

    def spend(self, bytes_scanned: int) -> CostSpend:
        """The spend for reading ``bytes_scanned`` bytes. No clock: wall time is not charged."""
        usd = (Decimal(bytes_scanned) * self.usd_per_gib / Decimal(2**30)).quantize(
            Decimal("0.000001")
        )
        return CostSpend(bytes_scanned=bytes_scanned, usd=usd)


class ProbeOutcome(GodwitModel):
    """Everything one probe run produced, including the runs that produced no bundle.

    The contract's ``SketchBundle`` cannot say *refused*, *cancelled* or *nothing
    changed*, cannot carry the snapshot a delta started from, and cannot record a
    plain-key permission. This model wraps it and carries those. See
    ``docs/change-requests/CR-A6-sketch-bundle-cannot-say-why.md``.

    Nothing here is a row value. Refusals name columns by position; costs are numbers;
    the bundle is the contract type and carries its own taint.
    """

    status: ProbeStatus
    probe_id: ProbeId
    probe_key: ProbeKey
    kind: ProbeKind
    source_id: SourceId
    since_snapshot_id: SnapshotId | None
    snapshot_id: SnapshotId
    bundle: SketchBundle | None = None
    refusal: Refusal | None = None
    cancel_reason: CancelReason | None = None
    estimated_cost: CostSpend
    cost_spent: CostSpend
    full_rescan: bool = False
    metadata_only: bool = False
    files_read: int = 0
    permissions: tuple[KeyPermission, ...] = ()

    @model_validator(mode="after")
    def _status_matches_payload(self) -> Self:
        expected = {
            ProbeStatus.COMPLETED: (True, False, False),
            ProbeStatus.NO_CHANGE: (False, False, False),
            ProbeStatus.REFUSED: (False, True, False),
            ProbeStatus.CANCELLED: (False, False, True),
        }[self.status]
        actual = (self.bundle is not None, self.refusal is not None, self.cancel_reason is not None)
        if actual != expected:
            raise ValueError(f"a {self.status.value} outcome has the wrong payload")
        return self

    @property
    def covers_snapshot(self) -> bool:
        """True when the incremental state may advance to ``snapshot_id``.

        A completed probe measured up to it; a no-change probe proved there was nothing
        to measure. A refused or cancelled probe measured nothing, so the next run must
        start from the same place.
        """
        return self.status in (ProbeStatus.COMPLETED, ProbeStatus.NO_CHANGE)

    @property
    def reason(self) -> StrEnum | None:
        """The refusal or cancel reason, for labels."""
        if self.refusal is not None:
            return self.refusal.reason
        return self.cancel_reason


def bundle_id(probe_key: ProbeKey, since: SnapshotId | None, until: SnapshotId, seed: int) -> str:
    """The idempotency key of a bundle: one per (probe, snapshot range, seed)."""
    payload = {"probe_key": str(probe_key), "since": since or "", "until": str(until), "seed": seed}
    return content_hash(canonical_json(payload), prefix="bnd")


@dataclass(frozen=True, slots=True)
class _Run:
    spec: ProbeSpec
    since: SnapshotId | None
    until: SnapshotRef

    def outcome(
        self,
        status: ProbeStatus,
        *,
        estimated: CostSpend | None = None,
        spent: CostSpend | None = None,
        **extra: object,
    ) -> ProbeOutcome:
        return ProbeOutcome.model_validate(
            {
                "status": status,
                "probe_id": self.spec.probe_id,
                "probe_key": self.spec.key,
                "kind": self.spec.kind,
                "source_id": self.spec.source.source_id,
                "since_snapshot_id": self.since,
                "snapshot_id": self.until.snapshot_id,
                "estimated_cost": estimated or CostSpend.zero(),
                "cost_spent": spent or CostSpend.zero(),
                **extra,
            }
        )


class ProbeExecutor:
    """Executes probe specs against one :class:`ProbeSource`. Stateless between calls.

    ``access`` is the resolved access-mode map for the tables this executor may touch,
    from ``godwit_guard.AccessControl.mode_map``. ``keyring`` is required for any OPAQUE
    column; without it such probes are refused. ``state`` supplies the last probed
    snapshot for incremental runs; it is read, never written, here.
    """

    def __init__(
        self,
        source: ProbeSource,
        *,
        access: AccessModeMap,
        state: ProbeState,
        keyring: ProbeKeyring | None = None,
        guardrails: Sequence[Guardrail] = (),
        telemetry: ProbeTelemetry | None = None,
        cost_model: CostModel | None = None,
        batch_rows: int = DEFAULT_BATCH_ROWS,
        worker_version: str = WORKER_VERSION,
    ) -> None:
        if batch_rows < 1:
            raise ValueError("batch_rows must be positive")
        self.source = source
        self._access = access
        self._state = state
        self._keyring = keyring
        self._guardrails = tuple(guardrails)
        self._telemetry = telemetry if telemetry is not None else ProbeTelemetry()
        self._cost = cost_model if cost_model is not None else CostModel()
        self._batch_rows = batch_rows
        self._worker_version = worker_version

    # -- entry point ------------------------------------------------------------------

    def execute(
        self,
        spec: ProbeSpec,
        *,
        budget: CostBudget,
        mode: ExecutionMode = ExecutionMode.INCREMENTAL,
        since: SnapshotId | None = None,
        until: SnapshotRef | None = None,
        cancel: CancelToken | None = None,
    ) -> ProbeOutcome:
        """Run one probe. Refusal, no-change and cancellation are outcomes, not errors.

        Raises :class:`~godwit_probe.errors.ProbeError` -- and only that -- when a
        dependency fails.
        """
        fields: dict[Field, SafeValue] = {
            Field.PROBE: SafeId(str(spec.key)),
            Field.SOURCE: SafeId.of("src", str(spec.source.source_id)),
            Field.KIND: spec.kind,
            Field.MODE: mode,
        }
        with self._telemetry.span(Event.PROBE, fields) as span:
            try:
                outcome = self._execute(
                    spec, budget=budget, mode=mode, since=since, until=until, cancel=cancel
                )
            except ProbeError as error:
                if span is not None:
                    span.fail(error.code)
                self._telemetry.event(
                    Event.PROBE_FAILED, {**fields, Field.CODE: error.code, Field.STAGE: error.stage}
                )
                self._telemetry.outcome(status=error.code, kind=spec.kind, reason=error.stage)
                raise
            if span is not None:
                span.set(Field.STATUS, outcome.status)
                span.set(Field.BYTES_READ, outcome.cost_spent.bytes_scanned)
                if outcome.reason is not None:
                    span.set(Field.REASON, outcome.reason)
        self._report(outcome, fields)
        return outcome

    def _report(self, outcome: ProbeOutcome, fields: Mapping[Field, SafeValue]) -> None:
        event = {
            ProbeStatus.COMPLETED: Event.PROBE_COMPLETED,
            ProbeStatus.NO_CHANGE: Event.PROBE_NO_CHANGE,
            ProbeStatus.REFUSED: Event.PROBE_REFUSED,
            ProbeStatus.CANCELLED: Event.PROBE_CANCELLED,
        }[outcome.status]
        detail: dict[Field, SafeValue] = {
            **fields,
            Field.STATUS: outcome.status,
            Field.REASON: outcome.reason,
            Field.BYTES_ESTIMATED: outcome.estimated_cost.bytes_scanned,
            Field.BYTES_READ: outcome.cost_spent.bytes_scanned,
            Field.FILES: outcome.files_read,
            Field.FULL_RESCAN: outcome.full_rescan,
            Field.SNAPSHOT: SafeId.of("snp", str(outcome.snapshot_id)),
            Field.SINCE: (
                SafeId.of("snp", str(outcome.since_snapshot_id))
                if outcome.since_snapshot_id
                else None
            ),
        }
        self._telemetry.event(event, detail)
        self._telemetry.outcome(status=outcome.status, kind=outcome.kind, reason=outcome.reason)
        self._telemetry.bytes_read(amount=outcome.cost_spent.bytes_scanned, kind=outcome.kind)

    # -- the seven steps ----------------------------------------------------------------

    def _execute(
        self,
        spec: ProbeSpec,
        *,
        budget: CostBudget,
        mode: ExecutionMode,
        since: SnapshotId | None,
        until: SnapshotRef | None,
        cancel: CancelToken | None,
    ) -> ProbeOutcome:
        target = until or spec.snapshot
        if target is None:
            target = guarded(
                Stage.RESOLVE,
                ErrorCode.SOURCE_UNAVAILABLE,
                lambda: self.source.resolve_snapshot(spec.source, at=None),
            )
        start = since
        if start is None and mode is ExecutionMode.INCREMENTAL:
            start = self._state.last_snapshot(spec.key)
        run = _Run(spec=spec, since=start, until=target)
        if start is not None and start == target.snapshot_id:
            return run.outcome(ProbeStatus.NO_CHANGE)

        delta = self._delta(spec, start, target)
        if delta.kind is DeltaKind.NO_LOGICAL_CHANGE:
            return run.outcome(ProbeStatus.NO_CHANGE)
        full_rescan = start is not None and delta.since is None

        types = guarded(
            Stage.SCHEMA,
            ErrorCode.SOURCE_UNAVAILABLE,
            lambda: self.source.column_types(spec.source, target),
        )
        plan = guarded(Stage.PLAN, ErrorCode.PLAN_VIOLATION, lambda: self._plan(spec, types))
        if isinstance(plan, Refusal):
            return run.outcome(ProbeStatus.REFUSED, refusal=plan, full_rescan=full_rescan)

        estimate = self._cost.spend(
            0
            if plan.metadata_only
            else sum(item.estimated_bytes(plan.read_columns) for item in delta.files)
        )
        effective = CostBudget.compose(budget, spec.budget)
        if not effective.can_afford(estimate):
            refusal = Refusal(
                reason=RefusalReason.BUDGET, estimated_cost=estimate, budget=effective
            )
            return run.outcome(
                ProbeStatus.REFUSED, estimated=estimate, refusal=refusal, full_rescan=full_rescan
            )
        return self._scan(
            run,
            plan,
            delta,
            estimate=estimate,
            budget=effective,
            cancel=cancel,
            full_rescan=full_rescan,
        )

    def _delta(self, spec: ProbeSpec, start: SnapshotId | None, target: SnapshotRef) -> Delta:
        def listing(since: SnapshotId | None) -> Delta:
            return guarded(
                Stage.LIST,
                ErrorCode.SOURCE_UNAVAILABLE,
                lambda: self.source.delta(spec.source, since=since, until=target),
            )

        delta = listing(start)
        if delta.kind is DeltaKind.NON_ADDITIVE and start is not None:
            return listing(None)
        return delta

    def _plan(self, spec: ProbeSpec, types: Mapping[str, LogicalType]) -> ProbePlan | Refusal:
        return plan_probe(
            spec,
            access=self._access,
            column_types=types,
            keyring=self._keyring,
            guardrails=self._guardrails,
        )

    def _scan(
        self,
        run: _Run,
        plan: ProbePlan,
        delta: Delta,
        *,
        estimate: CostSpend,
        budget: CostBudget,
        cancel: CancelToken | None,
        full_rescan: bool,
    ) -> ProbeOutcome:
        accumulators = guarded(
            Stage.SKETCH,
            ErrorCode.SKETCH_FAILED,
            lambda: [Accumulator(item, keyring=self._keyring) for item in plan.sketches],
        )
        before = self.source.bytes_read
        files_read = 0

        def stopped(reason: CancelReason) -> ProbeOutcome:
            return run.outcome(
                ProbeStatus.CANCELLED,
                estimated=estimate,
                spent=self._cost.spend(self.source.bytes_read - before),
                cancel_reason=reason,
                files_read=files_read,
                full_rescan=full_rescan,
                permissions=plan.permissions,
            )

        if plan.metadata_only:
            rows = NullRate(nulls=0, total=delta.record_count)
            envelopes = {
                item.planned.name: self._serialise(run, item.planned, rows) for item in accumulators
            }
            return self._completed(
                run, plan, envelopes, estimate=estimate, spent=0, files=0, full=full_rescan
            )

        engine = guarded(Stage.QUERY, ErrorCode.QUERY_FAILED, lambda: QueryEngine(self._keyring))
        try:
            for data_file in delta.files:
                if cancel is not None and (reason := cancel.cancelled()) is not None:
                    return stopped(reason)
                with closing(self._file_results(run, plan, engine, data_file)) as results:
                    for result in results:
                        guarded(
                            Stage.SKETCH,
                            ErrorCode.SKETCH_FAILED,
                            functools.partial(_feed, accumulators, result),
                        )
                        if self.source.bytes_read - before > budget.bytes_scanned:
                            return stopped(CancelReason.BUDGET_EXHAUSTED)
                        if cancel is not None and (reason := cancel.cancelled()) is not None:
                            return stopped(reason)
                files_read += 1
        finally:
            engine.close()

        envelopes = {
            item.planned.name: self._serialise(run, item.planned, item.sketch())
            for item in accumulators
        }
        return self._completed(
            run,
            plan,
            envelopes,
            estimate=estimate,
            spent=self.source.bytes_read - before,
            files=files_read,
            full=full_rescan,
        )

    def _file_results(
        self, run: _Run, plan: ProbePlan, engine: QueryEngine, data_file: DataFileRef
    ) -> Generator[pa.RecordBatch]:
        """One file's query results, with both ends of the query checked against the plan.

        The *input* check proves the source handed over only the planned columns -- a
        BLIND column in the file's batches would mean it was read, and that is a defect
        even if the query never touched it. The *output* check is
        ``godwit_guard.verify_arrow_schema``, run on the first result batch before any
        sketch sees a value.
        """
        source = run.spec.source
        raw = guarded_iter(
            Stage.READ,
            ErrorCode.SCAN_FAILED,
            self.source.read(
                source, data_file, columns=plan.read_columns, batch_rows=self._batch_rows
            ),
        )
        first = next(raw, None)
        if first is None:
            return
        if not set(first.schema.names) <= set(plan.read_columns) or set(first.schema.names) & set(
            plan.blind_columns
        ):
            raise ProbeError(ErrorCode.PLAN_VIOLATION, stage=Stage.READ)
        results = guarded_iter(
            Stage.QUERY,
            ErrorCode.QUERY_FAILED,
            engine.run(
                plan,
                itertools.chain([first], raw),
                schema=first.schema,
                batch_rows=self._batch_rows,
            ),
        )
        checked = False
        with closing(results):
            for result in results:
                if not checked:
                    self._check_output(run, plan, result.schema)
                    checked = True
                yield result

    def _check_output(self, run: _Run, plan: ProbePlan, schema: pa.Schema) -> None:
        names = tuple(schema.names)
        if names != plan.output_fields:
            raise ProbeError(ErrorCode.PLAN_VIOLATION, stage=Stage.QUERY)
        data_fields = [name for name in names if name != ROW_COUNT_FIELD]
        source = run.spec.source
        guarded(
            Stage.QUERY,
            ErrorCode.PLAN_VIOLATION,
            lambda: verify_arrow_schema(
                data_fields,
                self._access,
                source_id=str(source.source_id),
                table=source.table.reveal(),
            ),
        )

    def _serialise(self, run: _Run, planned: PlannedSketch, sketch: BaseSketch) -> SketchEnvelope:
        column = planned.columns[0].name if len(planned.columns) == 1 else None
        context = SketchContext(
            source_id=run.spec.source.source_id,
            snapshot_id=run.until.snapshot_id,
            produced_for=run.spec.key,
            produced_at=run.until.committed_at,
            table=run.spec.source.table.reveal(),
            column=column,
        )
        return guarded(Stage.SERIALISE, ErrorCode.SKETCH_FAILED, lambda: sketch.serialise(context))

    def _completed(
        self,
        run: _Run,
        plan: ProbePlan,
        envelopes: Mapping[str, SketchEnvelope],
        *,
        estimate: CostSpend,
        spent: int,
        files: int,
        full: bool,
    ) -> ProbeOutcome:
        cost = self._cost.spend(spent)
        bundle = guarded(
            Stage.SERIALISE,
            ErrorCode.SKETCH_FAILED,
            lambda: SketchBundle(
                bundle_id=bundle_id(run.spec.key, run.since, run.until.snapshot_id, run.spec.seed),
                probe_key=run.spec.key,
                source_id=run.spec.source.source_id,
                snapshot_id=run.until.snapshot_id,
                sketches=dict(envelopes),
                cost_spent=cost,
                produced_at=run.until.committed_at,
                worker_version=self._worker_version,
                seed=run.spec.seed,
            ),
        )
        return run.outcome(
            ProbeStatus.COMPLETED,
            estimated=estimate,
            spent=cost,
            bundle=bundle,
            files_read=files,
            full_rescan=full,
            metadata_only=plan.metadata_only,
            permissions=plan.permissions,
        )


def _feed(accumulators: Sequence[Accumulator], batch: pa.RecordBatch) -> None:
    for accumulator in accumulators:
        accumulator.feed(batch)
