"""The snapshot-ordered replay driver: history fed forward, one snapshot at a time.

At each step the handler sees exactly what existed then. No future snapshots, no future
labels, no future schema. That is not a convention the handler is trusted to respect -- the
driver constructs the view, and it checks afterwards that nothing came back naming a
snapshot the handler could not have seen.

WHY THERE ARE TWO DIGESTS
-------------------------
``ReplayRun.digest`` is the strict one. It includes candidate ids, and a candidate id
hashes the Iceberg snapshot id. Iceberg mints a fresh snapshot id on every commit, so two
*separate materialisations* of the same data produce different candidate ids for the same
finding. Within one materialisation the strict digest is exactly what the acceptance
criterion asks for: replay twice, compare, and any difference at all is a bug.

``ReplayRun.content_digest`` is the portable one. It names step index, period key, segment
key, detector, detector version and the statistics, and it excludes every identifier that
a reload would renumber. It is what champion/challenger diffs across two materialisations
and what a CI run on a freshly loaded dataset can assert against a recorded value.

Neither digest includes an Iceberg ``committed_at``: that is the wall-clock moment the
loader ran, which differs on every machine. Replay's own clock comes from the data's event
times -- see ``LoadedDataset.clock_instants``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from godwit_contracts.common import (
    CandidateId,
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    RunId,
    SnapshotId,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.discovery import Candidate, Label, LabelSet
from godwit_contracts.errors import BudgetExceededError
from godwit_contracts.source import SnapshotRef
from godwit_contracts.taint import Sensitivity
from godwit_source.detectors import DEFAULT_CONFIG, DetectorConfig, run_metadata_detectors
from godwit_source.metadata import SnapshotMetadata
from pydantic import Field

from godwit_replay.clock import VirtualClock, forbid_wall_clock
from godwit_replay.errors import FutureKnowledgeError
from godwit_replay.leak import DEFAULT_MAX_SENSITIVITY

__all__ = [
    "MetadataOnlyHandler",
    "ReplayConfig",
    "ReplayHandler",
    "ReplayRun",
    "ReplayVerdict",
    "ReplayView",
    "StepOutcome",
    "replay",
]

_STAT_PRECISION: Final[int] = 12
"""Decimal places the portable digest rounds statistics to.

Twelve, not seventeen. A float that differs in its last bit between two BLAS builds is not
a behaviour change, and a digest that says it is would cry wolf on every upgrade. Twelve
places is far tighter than any statistic in the system is meaningful to.
"""


class ReplayVerdict(StrEnum):
    """How a run ended. Three of the four are failures and one of those is normal."""

    PASSED = "passed"
    FAILED_LEAK = "failed_leak"
    """The egress audit found something. The run's findings are recorded before it fails."""

    FAILED_FUTURE = "failed_future"
    """A handler named a snapshot or a label it could not have seen."""

    REFUSED_BUDGET = "refused_budget"
    """The run stopped because it ran out of budget. Invariant 6: a normal outcome."""


class ReplayConfig(GodwitModel):
    """Everything that can change what a replay produces, in one hashable object.

    Two configurations differing in any field here are two different experiments, which is
    what makes champion/challenger meaningful: the diff names the config digests it
    compared and a reader can tell whether they were supposed to differ.
    """

    name: str = Field(default="default", description="Label for this arm of an experiment.")
    seed: int
    code_version: str
    small_cell_threshold: NonNegInt = 20
    max_sensitivity: Sensitivity = DEFAULT_MAX_SENSITIVITY
    detector: DetectorConfig = DEFAULT_CONFIG
    reveal_values_in_output: bool = Field(
        default=False,
        description="THE LEAKY KNOB. True renders tainted values into reports instead of "
        "their redacted labels. It exists so the harness can demonstrate that its own "
        "audit catches a leak. The audit runs either way and fails the run either way.",
    )
    max_periods: int | None = Field(
        default=None, description="Stop after this many snapshots. None means all of them."
    )

    def digest(self) -> ContentHash:
        """Stable hash of this configuration."""
        return content_hash(
            canonical_json(
                {
                    "seed": self.seed,
                    "code_version": self.code_version,
                    "small_cell_threshold": int(self.small_cell_threshold),
                    "max_sensitivity": self.max_sensitivity.value,
                    "detector": self.detector.model_dump(mode="json"),
                    "reveal_values_in_output": self.reveal_values_in_output,
                    "max_periods": self.max_periods,
                }
            ),
            prefix="cfg",
        )


@dataclass(frozen=True, slots=True)
class ReplayView:
    """What a handler is allowed to know at one step. Built by the driver, never by a handler.

    ``history`` ends at the current snapshot and contains nothing after it. ``labels`` has
    already been filtered by ``LabelSet.visible_as_of(instant=now)``, so a handler cannot
    accidentally read the future by forgetting to pass an instant -- it never holds the
    ``LabelSet`` at all.
    """

    step_index: int
    now: Instant
    period_key: str
    snapshot: SnapshotRef
    history: tuple[SnapshotMetadata, ...]
    labels: tuple[Label, ...]
    labels_are_exhaustive: bool
    budget: CostBudget
    config: ReplayConfig

    @property
    def visible_snapshot_ids(self) -> frozenset[SnapshotId]:
        """Every snapshot id this view could legitimately name."""
        return frozenset(item.snapshot.snapshot_id for item in self.history)


@runtime_checkable
class ReplayHandler(Protocol):
    """The system under test, reduced to one method.

    LAWS
    ----
    1. Pure in the view. Same view, same candidates, same order. No clock -- the driver
       enforces this by guarding wall-clock access while ``observe`` runs.
    2. Emits nothing that names a snapshot outside ``view.visible_snapshot_ids``. The
       driver checks, and a violation fails the whole run rather than the step.
    3. Reads labels only from ``view.labels``, which is already filtered to the present.
    4. Refuses rather than exceeds ``view.budget``, and lets ``BudgetExceededError`` out:
       the driver records the refusal as an outcome, not as a crash.
    """

    @property
    def name(self) -> str:
        """Stable handler name. Goes into the run record and both digests."""
        ...

    def observe(self, view: ReplayView) -> tuple[Candidate, ...]:
        """React to one step of history."""
        ...


@dataclass(frozen=True, slots=True)
class MetadataOnlyHandler:
    """The L-1 handler: A1's six metadata detectors over the visible history.

    This is the whole system the kill criterion runs against before Wave 2 exists. It
    reads no table data -- every statistic comes out of Iceberg manifests -- which is why
    the verdict command can run end to end on a real public dataset today.
    """

    code_version: str
    name: str = "metadata-only"

    def observe(self, view: ReplayView) -> tuple[Candidate, ...]:
        """Run the six detectors over everything visible so far."""
        return run_metadata_detectors(
            view.history,
            code_version=self.code_version,
            seed=view.config.seed,
            config=view.config.detector,
        )


class StepOutcome(GodwitModel):
    """What one step produced. No tainted value: this is a record, not a finding."""

    step_index: NonNegInt
    period_key: str
    now: Instant
    snapshot_id: SnapshotId
    candidate_ids: tuple[CandidateId, ...]
    visible_label_count: NonNegInt
    scanned_bytes: NonNegInt
    cost: CostSpend = Field(default_factory=CostSpend.zero)


class ReplayRun(GodwitModel):
    """One complete replay: what it saw, what it emitted, what it cost, whether it holds up."""

    run_id: RunId
    dataset: str
    handler: str
    config_digest: ContentHash
    config: ReplayConfig
    steps: tuple[StepOutcome, ...]
    candidates: tuple[Candidate, ...]
    verdict: ReplayVerdict = ReplayVerdict.PASSED
    total_cost: CostSpend = Field(default_factory=CostSpend.zero)
    digest: ContentHash
    content_digest: ContentHash
    refusal: str | None = Field(
        default=None,
        description="Why the run stopped early, in our own words. Never a driver message.",
    )

    @property
    def passed(self) -> bool:
        """True when nothing saw the future and the budget held.

        A leak is not visible here: leaks are a property of the *report*, which is the
        artifact that actually leaves. See ``godwit_replay.verdict.build_report``.
        """
        return self.verdict is ReplayVerdict.PASSED

    def ranked(self) -> tuple[Candidate, ...]:
        """Candidates by descending score, ties broken by id. Deterministic, always."""
        return tuple(
            sorted(self.candidates, key=lambda item: (-item.score, str(item.candidate_id)))
        )

    def first_surfaced(self) -> Mapping[str, Instant]:
        """Earliest step instant at which each segment key was surfaced.

        The input to time-to-detection. Keyed by segment key, which is a hash, so this
        mapping carries no row value.
        """
        by_step = {outcome.step_index: outcome.now for outcome in self.steps}
        found: dict[str, Instant] = {}
        step_of: dict[CandidateId, int] = {}
        for outcome in self.steps:
            for candidate_id in outcome.candidate_ids:
                step_of.setdefault(candidate_id, outcome.step_index)
        for candidate in self.candidates:
            step = step_of.get(candidate.candidate_id)
            if step is None:
                continue
            key = str(candidate.segment.key)
            when = by_step[step]
            if key not in found or when < found[key]:
                found[key] = when
        return found


def _candidate_identity(candidate: Candidate) -> Mapping[str, Any]:
    """The portable identity of one candidate: no minted ids, no commit times."""
    return {
        "segment": str(candidate.segment.key),
        "detector": candidate.lineage.detector,
        "detector_version": int(candidate.lineage.detector_version),
        "probe_key": str(candidate.lineage.probe_key),
        "seed": candidate.lineage.seed,
        "score": round(candidate.score, _STAT_PRECISION),
        "evidence": [
            {
                "kind": item.kind.value,
                "statistic": round(item.statistic.reveal(), _STAT_PRECISION),
                "baseline": (
                    None
                    if item.baseline is None
                    else round(item.baseline.reveal(), _STAT_PRECISION)
                ),
                "p_value": (
                    None if item.p_value is None else round(item.p_value.reveal(), _STAT_PRECISION)
                ),
                "population": item.population,
                "sketch_names": list(item.sketch_names),
            }
            for item in candidate.evidence
        ],
    }


def _digests(
    *,
    dataset: str,
    handler: str,
    config_digest: ContentHash,
    steps: Sequence[StepOutcome],
    candidates: Sequence[Candidate],
) -> tuple[ContentHash, ContentHash]:
    by_id = {candidate.candidate_id: candidate for candidate in candidates}
    strict = canonical_json(
        {
            "dataset": dataset,
            "handler": handler,
            "config": str(config_digest),
            "steps": [
                {
                    "index": int(outcome.step_index),
                    "period": outcome.period_key,
                    "now": outcome.now.isoformat(),
                    "labels": int(outcome.visible_label_count),
                    "candidates": [str(item) for item in outcome.candidate_ids],
                }
                for outcome in steps
            ],
        }
    )
    portable = canonical_json(
        {
            "dataset": dataset,
            "handler": handler,
            "config": str(config_digest),
            "steps": [
                {
                    "index": int(outcome.step_index),
                    "period": outcome.period_key,
                    "now": outcome.now.isoformat(),
                    "labels": int(outcome.visible_label_count),
                    "findings": sorted(
                        canonical_json(_candidate_identity(by_id[item]))
                        for item in outcome.candidate_ids
                        if item in by_id
                    ),
                }
                for outcome in steps
            ],
        }
    )
    return (
        content_hash(strict, prefix="rpl"),
        content_hash(portable, prefix="rpc"),
    )


def _reject_future_knowledge(candidates: Sequence[Candidate], view: ReplayView) -> None:
    """Refuse anything naming a snapshot this step could not have seen."""
    visible = view.visible_snapshot_ids
    for candidate in candidates:
        if candidate.lineage.snapshot_id not in visible:
            raise FutureKnowledgeError(
                f"step {view.step_index}: a candidate's lineage names snapshot "
                f"{candidate.lineage.snapshot_id}, which was not visible at "
                f"{view.now.isoformat()}"
            )
        baseline = candidate.lineage.baseline_snapshot_id
        if baseline is not None and baseline not in visible:
            raise FutureKnowledgeError(
                f"step {view.step_index}: a candidate's baseline names snapshot {baseline}, "
                "which was not visible yet"
            )
        for item in candidate.evidence:
            if item.snapshot_id not in visible:
                raise FutureKnowledgeError(
                    f"step {view.step_index}: evidence names snapshot {item.snapshot_id}, "
                    "which was not visible yet"
                )
        if candidate.created_at > view.now:
            raise FutureKnowledgeError(
                f"step {view.step_index}: a candidate is dated {candidate.created_at.isoformat()}, "
                f"after the step instant {view.now.isoformat()}"
            )


def replay(
    *,
    dataset: str,
    history: Sequence[SnapshotMetadata],
    clock_instants: Sequence[Instant],
    period_keys: Sequence[str],
    handler: ReplayHandler,
    config: ReplayConfig,
    budget: CostBudget,
    labels: LabelSet | None = None,
    guard_wall_clock: bool = True,
) -> ReplayRun:
    """Feed ``history`` forward one snapshot at a time and score what came out.

    ``history`` is oldest first and must be the same length as ``clock_instants`` and
    ``period_keys``: one snapshot, one instant, one period, one step. The instants come
    from the data's own event times rather than from Iceberg commit times, which is what
    makes a run reproducible on another machine.

    Returns a :class:`ReplayRun` in every case, including failure. A run that leaked or
    saw the future comes back with its findings attached and ``passed`` False; it does not
    raise, because a failing run is evidence and evidence has to be readable. The one
    exception is :func:`assert_passed`, which is what a test calls when it wants the raise.
    """
    if not (len(history) == len(clock_instants) == len(period_keys)):
        raise ValueError("history, clock_instants and period_keys must be the same length")
    if not history:
        raise ValueError("replay needs at least one snapshot")

    limit = len(history) if config.max_periods is None else min(len(history), config.max_periods)
    clock = VirtualClock(list(clock_instants[:limit]))
    remaining = budget
    outcomes: list[StepOutcome] = []
    seen: dict[CandidateId, Candidate] = {}
    spent = CostSpend.zero()
    refusal: str | None = None
    verdict = ReplayVerdict.PASSED

    for index in range(limit):
        now = clock.advance_to(index)
        visible_history = tuple(history[: index + 1])
        current = visible_history[-1]
        visible_labels = () if labels is None else labels.visible_as_of(instant=now)
        view = ReplayView(
            step_index=index,
            now=now,
            period_key=period_keys[index],
            snapshot=current.snapshot,
            history=visible_history,
            labels=visible_labels,
            labels_are_exhaustive=False if labels is None else labels.coverage_at(instant=now),
            budget=remaining,
            config=config,
        )
        step_cost = CostSpend(bytes_scanned=int(current.scanned_bytes))
        try:
            remaining = remaining.spend(step_cost)
        except BudgetExceededError as exc:
            refusal = f"budget refused at step {index}: {exc}"
            verdict = ReplayVerdict.REFUSED_BUDGET
            break
        spent = spent + step_cost

        try:
            if guard_wall_clock:
                with forbid_wall_clock():
                    emitted = handler.observe(view)
            else:
                emitted = handler.observe(view)
        except BudgetExceededError as exc:
            refusal = f"handler refused at step {index}: {exc}"
            verdict = ReplayVerdict.REFUSED_BUDGET
            break

        try:
            _reject_future_knowledge(emitted, view)
        except FutureKnowledgeError as exc:
            refusal = str(exc)
            verdict = ReplayVerdict.FAILED_FUTURE
            outcomes.append(
                StepOutcome(
                    step_index=index,
                    period_key=period_keys[index],
                    now=now,
                    snapshot_id=current.snapshot.snapshot_id,
                    candidate_ids=(),
                    visible_label_count=len(visible_labels),
                    scanned_bytes=int(current.scanned_bytes),
                    cost=step_cost,
                )
            )
            break

        for candidate in emitted:
            seen.setdefault(candidate.candidate_id, candidate)
        outcomes.append(
            StepOutcome(
                step_index=index,
                period_key=period_keys[index],
                now=now,
                snapshot_id=current.snapshot.snapshot_id,
                candidate_ids=tuple(
                    sorted({candidate.candidate_id for candidate in emitted}, key=str)
                ),
                visible_label_count=len(visible_labels),
                scanned_bytes=int(current.scanned_bytes),
                cost=step_cost,
            )
        )

    candidates = tuple(seen[key] for key in sorted(seen, key=str))
    config_digest = config.digest()
    strict, portable = _digests(
        dataset=dataset,
        handler=handler.name,
        config_digest=config_digest,
        steps=outcomes,
        candidates=candidates,
    )
    return ReplayRun(
        run_id=RunId(strict.replace("rpl_", "run_")),
        dataset=dataset,
        handler=handler.name,
        config_digest=config_digest,
        config=config,
        steps=tuple(outcomes),
        candidates=candidates,
        verdict=verdict,
        total_cost=spent,
        digest=strict,
        content_digest=portable,
        refusal=refusal,
    )
