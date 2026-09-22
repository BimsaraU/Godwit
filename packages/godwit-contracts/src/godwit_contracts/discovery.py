"""Discovery: evidence, candidates, patterns, explanations, feedback and labels.

Everything in this module travels from the data plane to the control plane, and some of
it goes on to a human or an LLM. Every field that can hold a data-derived value is
``Tainted``. There are no exceptions and there is no "it is only a summary" field.

The two things worth reading carefully:

* ``Lineage`` is invariant 7 made concrete. A pattern that cannot produce its lineage
  cannot be reproduced, and a pattern that cannot be reproduced cannot be defended to a
  regulator.
* ``Label`` and ``LabelSet`` carry two timestamps, not one, and reading labels requires
  an explicit "as of" instant with no default. Every leakage bug in supervised learning
  is, underneath, someone reading a label that did not exist yet.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    CandidateId,
    GodwitModel,
    Instant,
    NonNegInt,
    PatternId,
    Probability,
    ProbeKey,
    SnapshotId,
    SourceId,
    Version,
)
from godwit_contracts.segment import Segment
from godwit_contracts.taint import Sensitivity, Tainted

__all__ = [
    "Alert",
    "AlertQueue",
    "Candidate",
    "CoverageScope",
    "Evidence",
    "EvidenceKind",
    "Explanation",
    "Feedback",
    "Label",
    "LabelSet",
    "LabelValue",
    "Lineage",
    "Pattern",
    "PatternLifecycle",
    "Severity",
    "Verdict",
    "label_index",
]

type LabelValue = bool | int | float | str


class EvidenceKind(StrEnum):
    """What kind of statistical claim a piece of evidence makes."""

    SEGMENT_DIVERGENCE = "segment_divergence"
    DISTRIBUTION_SHIFT = "distribution_shift"
    RATE_CHANGE = "rate_change"
    CARDINALITY_SHIFT = "cardinality_shift"
    HEAVY_HITTER_SHIFT = "heavy_hitter_shift"
    NULL_RATE_SHIFT = "null_rate_shift"
    FRESHNESS_STALL = "freshness_stall"
    GRAPH_ANOMALY = "graph_anomaly"
    JOIN_DEGRADATION = "join_degradation"
    RESIDUAL_STRUCTURE = "residual_structure"
    """Structure left in a prediction model's residuals. The loop that closes the
    product: prediction errors feed discovery."""


class Evidence(GodwitModel):
    """One measured claim, with everything needed to judge whether it is real.

    ``statistic`` and ``baseline`` are derived statistics: they contain no row value.
    ``segment`` does contain row values, in its predicates, which is why a piece of
    evidence is never safe merely because its numbers are aggregates.
    """

    kind: EvidenceKind
    probe_key: ProbeKey
    snapshot_id: SnapshotId
    baseline_snapshot_id: SnapshotId | None = None

    segment: Segment
    columns: tuple[Tainted[str], ...] = ()

    statistic: Tainted[float]
    baseline: Tainted[float] | None = None
    effect_size: Tainted[float] | None = None
    p_value: Tainted[float] | None = None
    population: NonNegInt | None = Field(
        default=None,
        description="Rows behind the statistic. None means unknown, which small-cell "
        "suppression must treat as too small to disclose.",
    )

    sketch_names: tuple[str, ...] = Field(
        default=(),
        description="Which sketches in the bundle this claim was computed from.",
    )

    @model_validator(mode="after")
    def _numbers_are_statistics(self) -> Self:
        numeric: list[tuple[str, Tainted[float] | None]] = [
            ("statistic", self.statistic),
            ("baseline", self.baseline),
            ("effect_size", self.effect_size),
            ("p_value", self.p_value),
        ]
        for field, value in numeric:
            if value is None:
                continue
            if value.sensitivity is not Sensitivity.DERIVED_STATISTIC:
                raise ValueError(
                    f"Evidence.{field} must be a DERIVED_STATISTIC. A number that is a "
                    "row value (a bound, a quantile over a tiny population) belongs in "
                    "the segment or in a dedicated tainted field."
                )
        for index, column in enumerate(self.columns):
            if column.sensitivity is not Sensitivity.SCHEMA_NAME:
                raise ValueError(f"Evidence.columns[{index}] must be tainted SCHEMA_NAME")
        return self


class Lineage(GodwitModel):
    """The reproduction recipe. Invariant 7.

    Given these five fields and the code at ``code_version``, the whole LLM layer can be
    deleted and the pattern still comes back identical. If you cannot fill this in, you
    do not have a pattern; you have an anecdote.
    """

    probe_key: ProbeKey
    snapshot_id: SnapshotId
    baseline_snapshot_id: SnapshotId | None = None
    detector: str = Field(description="Detector name, e.g. 'segment_divergence'.")
    detector_version: Version
    code_version: str = Field(description="Git describe or equivalent build identifier.")
    seed: int


class Candidate(GodwitModel):
    """A detector's raw output, before deduplication and multiple-testing control.

    Candidates are cheap and numerous. Most die in L5. Nothing here has been reviewed by
    a human, so nothing here should be shown to one without going through the gate.
    """

    candidate_id: CandidateId
    source_id: SourceId
    segment: Segment
    evidence: tuple[Evidence, ...] = Field(min_length=1)
    score: float = Field(
        description="Detector-local ranking score. Not comparable across "
        "detectors until L5 calibrates it."
    )
    lineage: Lineage
    created_at: Instant

    @model_validator(mode="after")
    def _evidence_agrees_with_lineage(self) -> Self:
        for index, item in enumerate(self.evidence):
            if item.snapshot_id != self.lineage.snapshot_id:
                raise ValueError(
                    f"evidence[{index}] is from snapshot {item.snapshot_id} but lineage "
                    f"says {self.lineage.snapshot_id}; a candidate is one snapshot"
                )
        return self


class PatternLifecycle(StrEnum):
    """Where a pattern is in its life. Lifecycle is owned by L5, the pattern store."""

    PROPOSED = "proposed"
    CONFIRMED = "confirmed"
    EXPLAINED_AWAY = "explained_away"
    """L3 found a deploy, campaign, holiday or DQ failure that accounts for it."""
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    EXPIRED = "expired"
    SUPPRESSED = "suppressed"
    """Real, but a human said stop showing it."""


class Pattern(GodwitModel):
    """A deduplicated, FDR-controlled claim with a life of its own.

    A pattern is also a *feature*: ``godwit-features`` turns a confirmed pattern into a
    ``FeatureSpec`` that the prediction engine can train on. That is the single idea the
    product rests on -- a discovered pattern is a feature.
    """

    pattern_id: PatternId
    source_id: SourceId
    segment: Segment
    candidates: tuple[CandidateId, ...] = Field(min_length=1)
    representative: Candidate

    lifecycle: PatternLifecycle = PatternLifecycle.PROPOSED
    first_seen: Instant
    last_seen: Instant

    q_value: Probability | None = Field(
        default=None,
        description="Benjamini-Hochberg adjusted significance, after FDR control over "
        "the whole probe space. A raw p-value here would be a lie by omission: we test "
        "thousands of hypotheses per snapshot.",
    )
    dedup_group: str | None = None
    name: Tainted[str] | None = Field(
        default=None,
        description="Human-readable name, usually LLM-produced. Tainted: a name like "
        "'ACME_CORP refunds spiked' quotes a row value.",
    )

    @model_validator(mode="after")
    def _times_are_ordered(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen precedes first_seen")
        return self


class Explanation(GodwitModel):
    """Why we think a pattern matters, in words. Produced by L9, never trusted by L2.

    Invariant 7: deleting every explanation in the system must not change a single
    pattern or prediction. Explanations are for humans; they are not evidence.
    """

    pattern_id: PatternId
    text: Tainted[str]
    produced_by: str = Field(description="'llm' or 'template'. Both are gated the same.")
    model_name: str | None = None
    prompt_digest: str | None = Field(
        default=None,
        description="Hash of the prompt, for reproducing what the LLM was asked.",
    )
    payload_digest: str | None = Field(
        default=None,
        description="Digest of the SafePayload the LLM saw. Proves what it was told.",
    )
    created_at: Instant

    @model_validator(mode="after")
    def _text_is_not_a_statistic(self) -> Self:
        if self.text.sensitivity is Sensitivity.DERIVED_STATISTIC:
            raise ValueError(
                "explanation text can echo tokens and segment values; it is at least "
                "TOKEN, never a derived statistic"
            )
        return self


class Verdict(StrEnum):
    """What a human reviewer concluded."""

    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    EXPLAINED_AWAY = "explained_away"
    NEEDS_MORE = "needs_more"
    DUPLICATE = "duplicate"


class Feedback(GodwitModel):
    """A human's verdict on a pattern. The only ground truth discovery ever gets."""

    pattern_id: PatternId
    verdict: Verdict
    reviewer_id: str = Field(description="Our identifier for the reviewer, not their name.")
    decided_at: Instant
    notes: Tainted[str] | None = Field(
        default=None,
        description="Free text a human typed. Assume they pasted a row, because they did.",
    )
    confidence: Probability | None = None


class AlertQueue(StrEnum):
    """The two queues from the objective function. They have different economics.

    ``OPERATIONAL``: about 50 a day, target precision at or above 30% after 90-day
    label reconciliation. ``DISCOVERY``: about 5 a week, target at least one
    confirmed-novel pattern a month.
    """

    OPERATIONAL = "operational"
    DISCOVERY = "discovery"


class Severity(StrEnum):
    """How loudly to shout."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(GodwitModel):
    """A pattern routed to a human queue.

    An alert is not yet an egress. It becomes one when godwit-guard clears it for a
    destination and writes an ``EgressRecord``; ``egress_record_id`` is filled in then.
    """

    alert_id: str
    pattern_id: PatternId
    queue: AlertQueue
    severity: Severity
    title: Tainted[str]
    body: Tainted[str] | None = None
    segment: Segment
    created_at: Instant
    egress_record_id: str | None = Field(
        default=None,
        description="Set once this alert has actually left the perimeter. None means it "
        "has not been cleared, and it must not be delivered anywhere.",
    )


class CoverageScope(GodwitModel):
    """What a set of labels actually covers.

    Half-labelled data is the normal case. The dangerous mistake is treating "no label"
    as "negative". This type forces the label producer to say which population was
    exhaustively labelled and over what window, so the trainer can tell an unlabelled
    row apart from a negative one.
    """

    entity_type: str
    population: Segment = Field(
        default_factory=Segment,
        description="Which rows were in scope. Empty means the whole table.",
    )
    complete_from: Instant
    complete_to: Instant
    is_exhaustive: bool = Field(
        description="True only if every in-scope entity in the window has a label. If "
        "this is False, absence of a label means nothing at all."
    )
    note: str = ""

    @model_validator(mode="after")
    def _window_is_ordered(self) -> Self:
        if self.complete_to < self.complete_from:
            raise ValueError("complete_to precedes complete_from")
        return self


class Label(GodwitModel):
    """One label, with the two timestamps that matter.

    ``event_time`` is when the thing happened. ``label_time`` is when we learned about
    it -- a chargeback lands sixty days after the transaction. Training on a label at
    its event time leaks sixty days of future knowledge into the model. They are
    separate fields because they are separate facts, and no convenience constructor
    collapses them.
    """

    entity_id: Tainted[str]
    value: Tainted[LabelValue]
    event_time: Instant
    label_time: Instant
    source: str = Field(description="Where the label came from, e.g. 'chargeback_feed'.")
    confidence: Probability | None = None

    @model_validator(mode="after")
    def _label_follows_event(self) -> Self:
        if self.label_time < self.event_time:
            raise ValueError(
                "label_time precedes event_time: a label cannot be known before the "
                "event it describes"
            )
        for field, value in (("entity_id", self.entity_id), ("value", self.value)):
            if value.sensitivity is Sensitivity.DERIVED_STATISTIC:
                raise ValueError(f"Label.{field} is a row value, not a statistic")
        return self


class LabelSet(GodwitModel):
    """Labels plus their coverage. Reading them requires an explicit instant.

    There is no ``all()``, no ``labels`` property that returns everything, and no
    default for ``instant``. Asking "what did we know on this date" is the only
    supported question, because it is the only one that cannot leak the future.
    """

    coverage: CoverageScope
    labels: tuple[Label, ...] = ()

    def visible_as_of(self, *, instant: Instant) -> tuple[Label, ...]:
        """Labels whose ``label_time`` is at or before ``instant``.

        ``instant`` is keyword-only and has no default. That is deliberate: the most
        common leakage bug in the industry is a training pipeline that quietly used
        "now" and therefore trained on labels that did not exist at prediction time.
        """
        return tuple(label for label in self.labels if label.label_time <= instant)

    def coverage_at(self, *, instant: Instant) -> bool:
        """True if ``instant`` falls inside an exhaustively labelled window.

        When this is False, an unlabelled entity is *unknown*, not negative. A trainer
        that treats unknown as negative on non-exhaustive coverage is training on noise
        it invented.
        """
        return (
            self.coverage.is_exhaustive
            and self.coverage.complete_from <= instant <= self.coverage.complete_to
        )


def label_index(labels: Sequence[Label]) -> Mapping[str, Label]:
    """Index labels by revealed entity id. Data-plane use only.

    This calls ``reveal()``. It exists so that the one legitimate unwrap in training has
    a name and a docstring rather than being scattered inline.
    """
    return {label.entity_id.reveal(): label for label in labels}
