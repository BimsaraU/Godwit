"""Streaming is catalog polling. Batch is the same loop run over history.

DATA PLANE. There is no streaming engine here, on purpose. Tables written by Flink or
Kafka Connect commit an Iceberg snapshot every minute or few, so a "stream" is a
sequence of small commits, and the cheap, correct way to follow it is to poll the
*catalog* -- one metadata read -- and probe the delta when a new snapshot appears.
Latency equals commit cadence. Data is never polled.

Both modes go through :func:`advance`, which walks the commits in ``(last, newest]`` one
at a time and runs the executor once per commit, so each commit's rows land in one
bundle stamped with that commit's instant:

* :class:`CatalogPoller` calls it whenever the catalog shows something new.
* :func:`backfill` calls it once over the whole history.

Same specs, same deltas, same code: the bundles are byte-identical, and
:class:`SketchSeries` folds them into ``godwit_sketch.TimeHierarchy``, which is itself
order-independent, so the resulting series is byte-identical too. The acceptance test
drives both and compares bytes.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable, Mapping

from godwit_contracts import CostBudget, Instant, ProbeSpec, SketchBundle, SnapshotId
from godwit_sketch import TimeHierarchy, decode_envelope

from godwit_probe.errors import ErrorCode, Stage, guarded
from godwit_probe.executor import ProbeExecutor, ProbeOutcome, ProbeStatus
from godwit_probe.state import ProbeState
from godwit_probe.telemetry import Event, Field, ProbeTelemetry, SafeId

__all__ = ["CatalogPoller", "SketchSeries", "advance", "backfill"]


def advance(
    executor: ProbeExecutor,
    state: ProbeState,
    spec: ProbeSpec,
    *,
    budget: CostBudget,
    until: SnapshotId | None = None,
) -> tuple[ProbeOutcome, ...]:
    """Probe every commit after the last covered snapshot, one commit per run.

    Stops at the first run that does not cover its snapshot -- a refusal or a
    cancellation -- so the incremental state never skips a commit: the next call resumes
    from exactly where this one stopped. The budget is shared across the commits.
    """
    source = executor.source
    newest = guarded(
        Stage.RESOLVE,
        ErrorCode.SOURCE_UNAVAILABLE,
        lambda: source.resolve_snapshot(spec.source, at=None),
    )
    last = state.last_snapshot(spec.key)
    target = until or newest.snapshot_id
    if last == target:
        outcome = executor.execute(spec, budget=budget, since=last, until=newest)
        return (outcome,)
    chain = guarded(
        Stage.RESOLVE,
        ErrorCode.SOURCE_UNAVAILABLE,
        lambda: source.snapshot_chain(spec.source, since=last, until=target),
    )
    outcomes: list[ProbeOutcome] = []
    remaining = budget
    for snapshot in chain:
        outcome = executor.execute(
            spec, budget=remaining, since=state.last_snapshot(spec.key), until=snapshot
        )
        outcomes.append(outcome)
        if not outcome.covers_snapshot:
            break
        state.advance(spec.key, snapshot.snapshot_id)
        if not remaining.can_afford(outcome.cost_spent):
            break
        remaining = remaining.spend(outcome.cost_spent)
    return tuple(outcomes)


def backfill(
    executor: ProbeExecutor,
    state: ProbeState,
    spec: ProbeSpec,
    *,
    budget: CostBudget,
    until: SnapshotId | None = None,
) -> tuple[ProbeOutcome, ...]:
    """The batch path: every commit from the start of history, in one call."""
    return advance(executor, state, spec, budget=budget, until=until)


class CatalogPoller:
    """Follows a set of specs by polling the catalog. Metadata reads only until a commit.

    ``poll`` is meant to be called on the commit cadence. It is idempotent: polling
    twice with no new commit costs two catalog reads and returns ``NO_CHANGE`` twice.
    """

    def __init__(
        self,
        executor: ProbeExecutor,
        state: ProbeState,
        *,
        telemetry: ProbeTelemetry | None = None,
    ) -> None:
        self._executor = executor
        self._state = state
        self._telemetry = telemetry if telemetry is not None else ProbeTelemetry()

    def poll(self, spec: ProbeSpec, *, budget: CostBudget) -> tuple[ProbeOutcome, ...]:
        """Probe whatever was committed since the last poll."""
        outcomes = advance(self._executor, self._state, spec, budget=budget)
        completed = sum(1 for o in outcomes if o.status is ProbeStatus.COMPLETED)
        self._telemetry.event(
            Event.POLL,
            {
                Field.PROBE: SafeId(str(spec.key)),
                Field.SKETCHES: completed,
                Field.BYTES_READ: sum(o.cost_spent.bytes_scanned for o in outcomes),
            },
        )
        return outcomes


class SketchSeries:
    """One ``TimeHierarchy`` per sketch name, fed from bundles. **Data plane.**

    Bundles are placed at their ``produced_at`` -- the commit instant of the snapshot
    they measured -- so a bundle lands in the same window whichever mode produced it.
    """

    def __init__(self, *, base: _dt.timedelta, epoch: Instant) -> None:
        self._base = base
        self._epoch = epoch
        self._series: dict[str, TimeHierarchy] = {}

    def add(self, bundle: SketchBundle) -> None:
        """Append every sketch in a bundle."""
        for name in sorted(bundle.sketches):
            envelope = bundle.sketches[name]
            sketch = decode_envelope(envelope)
            hierarchy = self._series.get(name)
            if hierarchy is None:
                hierarchy = TimeHierarchy(
                    sketch_cls=type(sketch),
                    params=dict(envelope.params),
                    base=self._base,
                    epoch=self._epoch,
                )
                self._series[name] = hierarchy
            hierarchy.append(at=bundle.produced_at, sketch=sketch)

    @classmethod
    def from_bundles(
        cls, bundles: Iterable[SketchBundle], *, base: _dt.timedelta, epoch: Instant
    ) -> SketchSeries:
        """Build a series from bundles in any order."""
        series = cls(base=base, epoch=epoch)
        for bundle in bundles:
            series.add(bundle)
        return series

    def hierarchy(self, name: str) -> TimeHierarchy:
        """The hierarchy for one sketch name."""
        return self._series[name]

    def canonical_bytes(self) -> Mapping[str, bytes]:
        """Every hierarchy's canonical bytes, by sketch name. Equal bytes, equal series."""
        return {name: self._series[name].canonical_bytes() for name in sorted(self._series)}
