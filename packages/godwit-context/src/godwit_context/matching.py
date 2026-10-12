"""The matching engine: how strongly does a context event explain a candidate?

A match has a STRENGTH in [0, 1], never a yes/no. It is built from five components, each
of which is kept on the ``Match`` so that "why was this suppressed?" has an answer that
does not need a debugger:

``temporal``        Did the event happen when the change happened, allowing for this
                    context type's lead and lag? Zero outside the window.
``overlap``         Does the event touch what changed -- the same source, the same
                    columns, the same segment? Zero for a different source.
``prior``           How often has this context type explained this detector family on
                    this source before? Plain counts, shrunk towards 0.5 (``priors.py``).
``specificity``     A narrow, short event is more informative than a broad, long one. A
                    three-month global campaign "explains" everything a little.
``counterfactual``  Did comparable segments the event did NOT touch change the same way?
                    If they did, the event is not the explanation (see below).

    strength = temporal x overlap x (w_prior*prior + w_spec*specificity + w_cf*cf_credit)

and a CONTRADICTED or INCONSISTENT counterfactual additionally multiplies the strength
by ``contradiction_penalty``. Temporal alignment and scope overlap are gates: an event that
did not happen then, or did not touch this, explains nothing however good its history.

THE COUNTERFACTUAL CHECK
------------------------
A deploy at 14:00 on source A and a refund spike on source A at 15:00 line up perfectly.
If sources B, C and D -- which the deploy never touched -- show the same refund spike at
the same time, the deploy did not cause it. Something bigger did, and suppressing it
would be a confident wrong answer.

Peers are COMPARABLE when they have the same detector family, the same segment structure
(the same predicate columns, whatever the values) and were observed inside the
candidate's window. A peer is UNTOUCHED when the event's scope does not reach it. A peer
has CHANGED when its effect has the same sign as the candidate's and at least
``change_fraction`` of its magnitude.

    touched_rate   = changed / observed among touched peers, counting the candidate
    untouched_rate = changed / observed among untouched peers

The event discriminates if the untouched peers mostly did not move. The verdict is
CONTRADICTED when ``untouched_rate >= contradict_ratio * touched_rate``, SUPPORTED
otherwise, and UNTESTABLE when fewer than ``min_untouched`` untouched peers were observed.
UNTESTABLE earns partial credit: absence of a check is not evidence for the explanation,
and it is not evidence against it either.

The same peers give the mirror-image check. An event that touched several OTHER
comparable peers and moved almost none of them (fewer than ``consistency_floor`` of at
least ``min_touched``) is INCONSISTENT: a holiday that closed every shop in a country does
not explain one shop's spike when the rest were flat. Both CONTRADICTED and INCONSISTENT
downgrade the match.

Untouched peers that another aligned event of the SAME type touches are excluded as
confounded: on New Year's Day a German source is a control for nothing.

Peers come from two places: explicit ``PeerObservation`` values (every hypothesis a
detector examined, significant or not -- the only source of "did NOT change"), and the
other candidates in the same batch (which changed, by construction).
"""

from __future__ import annotations

import datetime as _dt
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Self

from godwit_contracts import (
    Candidate,
    GodwitModel,
    Instant,
    Probability,
    Segment,
    Sensitivity,
    SourceId,
    Tainted,
)
from pydantic import Field, model_validator

from godwit_context._unwrap import column_name, predicate_hash, statistic
from godwit_context.events import ContextEvent, ContextType

__all__ = [
    "Counterfactual",
    "CounterfactualPolicy",
    "CounterfactualVerdict",
    "Match",
    "MatchPolicy",
    "OverlapTier",
    "PeerObservation",
    "PriorFn",
    "StrengthWeights",
    "Subject",
    "TemporalPolicy",
    "Window",
    "detector_family",
    "match_candidate",
    "scope_overlap",
    "specificity",
    "subject_of_candidate",
    "subject_of_peer",
    "temporal_proximity",
]

_DAY: Final = _dt.timedelta(days=1)
_HOUR: Final = _dt.timedelta(hours=1)


class TemporalPolicy(GodwitModel):
    """How far before and after an event it can explain a change.

    ``lead`` is anticipation (pre-holiday shopping starts before the holiday). ``lag`` is
    delay (a campaign's traffic arrives hours after launch). Within either, credit decays
    with ``half_life``; beyond them it is zero.
    """

    lead: _dt.timedelta = _dt.timedelta(0)
    lag: _dt.timedelta = _DAY
    half_life: _dt.timedelta = 12 * _HOUR

    @model_validator(mode="after")
    def _positive(self) -> Self:
        if self.half_life <= _dt.timedelta(0):
            raise ValueError("half_life must be positive")
        if self.lead < _dt.timedelta(0) or self.lag < _dt.timedelta(0):
            raise ValueError("lead and lag cannot be negative")
        return self


DEFAULT_TEMPORAL: Final[Mapping[ContextType, TemporalPolicy]] = {
    ContextType.DEPLOY: TemporalPolicy(lead=_dt.timedelta(0), lag=2 * _DAY, half_life=12 * _HOUR),
    ContextType.CAMPAIGN: TemporalPolicy(lead=_DAY, lag=7 * _DAY, half_life=2 * _DAY),
    ContextType.HOLIDAY: TemporalPolicy(lead=2 * _DAY, lag=2 * _DAY, half_life=_DAY),
    ContextType.BUSINESS_CALENDAR: TemporalPolicy(lead=_DAY, lag=3 * _DAY, half_life=_DAY),
    ContextType.DATA_QUALITY: TemporalPolicy(lead=_dt.timedelta(0), lag=3 * _DAY, half_life=_DAY),
    ContextType.MARKET: TemporalPolicy(lead=_dt.timedelta(0), lag=3 * _DAY, half_life=_DAY),
    ContextType.ANNOTATION: TemporalPolicy(lag=_dt.timedelta(0), half_life=_HOUR),
}


class StrengthWeights(GodwitModel):
    """How the three soft components combine. They must sum to one."""

    prior: Probability = 0.3
    specificity: Probability = 0.3
    counterfactual: Probability = 0.4
    contradiction_penalty: Probability = 0.25

    @model_validator(mode="after")
    def _sum_to_one(self) -> Self:
        if not math.isclose(self.prior + self.specificity + self.counterfactual, 1.0):
            raise ValueError("prior, specificity and counterfactual weights must sum to 1")
        return self


class CounterfactualPolicy(GodwitModel):
    min_untouched: int = Field(default=3, ge=1)
    min_touched: int = Field(default=2, ge=1)
    consistency_floor: Probability = 0.25
    change_fraction: Probability = 0.5
    contradict_ratio: Probability = 0.5
    untestable_credit: Probability = 0.5
    peer_tolerance: _dt.timedelta = _dt.timedelta(0)


class MatchPolicy(GodwitModel):
    """Everything that tunes matching. Pure data, so a deployment can version it."""

    temporal: Mapping[ContextType, TemporalPolicy] = Field(
        default_factory=lambda: dict(DEFAULT_TEMPORAL)
    )
    weights: StrengthWeights = Field(default_factory=StrengthWeights)
    counterfactual: CounterfactualPolicy = Field(default_factory=CounterfactualPolicy)
    default_window: _dt.timedelta = _DAY
    window_by_source: Mapping[SourceId, _dt.timedelta] = Field(default_factory=dict)
    """How long one probe window is per source. A candidate's change happened somewhere
    in ``[created_at - window, created_at]``. See CR-A8-candidate-has-no-window."""


class Window(GodwitModel):
    start: Instant
    end: Instant

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.end < self.start:
            raise ValueError("Window.end precedes start")
        return self


class PeerObservation(GodwitModel):
    """One comparable measurement, changed or not. The only way to say "did NOT move".

    Typically one per hypothesis a detector examined in the same run -- A7 reports every
    test it ran, significant or not.
    """

    source_id: SourceId
    segment: Segment
    columns: tuple[Tainted[str], ...] = ()
    family: str
    observed_at: Instant
    effect: Tainted[float]

    @model_validator(mode="after")
    def _effect_is_statistic(self) -> Self:
        if self.effect.sensitivity is not Sensitivity.DERIVED_STATISTIC:
            raise ValueError("PeerObservation.effect must be a DERIVED_STATISTIC")
        return self


@dataclass(frozen=True)
class Subject:
    """What a candidate or peer looks like to the matcher. Holds no row value: columns
    are canonical schema names and predicates are hashes."""

    key: tuple[str, str]
    source_id: SourceId
    predicates: frozenset[str]
    structure: frozenset[str]
    columns: frozenset[str]
    family: str
    window: Window
    effect: float | None


def detector_family(candidate: Candidate) -> str:
    """The claim, not the code: sorted evidence kinds, as godwit-store dedups on."""
    return "+".join(sorted({item.kind.value for item in candidate.evidence}))


def _segment_parts(segment: Segment) -> tuple[frozenset[str], frozenset[str]]:
    predicates = frozenset(predicate_hash(p) for p in segment.predicates)
    structure = frozenset(column_name(p.column) for p in segment.predicates)
    return predicates, structure


def _candidate_effect(candidate: Candidate) -> float | None:
    effects = [
        statistic(item.effect_size) for item in candidate.evidence if item.effect_size is not None
    ]
    return max(effects, key=abs) if effects else None


def subject_of_candidate(candidate: Candidate, window: Window) -> Subject:
    predicates, structure = _segment_parts(candidate.segment)
    columns = frozenset(column_name(c) for item in candidate.evidence for c in item.columns)
    return Subject(
        key=(str(candidate.source_id), str(candidate.segment.key)),
        source_id=candidate.source_id,
        predicates=predicates,
        structure=structure,
        columns=columns | structure,
        family=detector_family(candidate),
        window=window,
        effect=_candidate_effect(candidate),
    )


def subject_of_peer(peer: PeerObservation) -> Subject:
    predicates, structure = _segment_parts(peer.segment)
    columns = frozenset(column_name(c) for c in peer.columns)
    return Subject(
        key=(str(peer.source_id), str(peer.segment.key)),
        source_id=peer.source_id,
        predicates=predicates,
        structure=structure,
        columns=columns | structure,
        family=peer.family,
        window=Window(start=peer.observed_at, end=peer.observed_at),
        effect=statistic(peer.effect),
    )


# --------------------------------------------------------------------------------------
# Components
# --------------------------------------------------------------------------------------


def temporal_proximity(window: Window, event: ContextEvent, policy: TemporalPolicy) -> float:
    """1.0 when the window meets the event; decaying credit within lead or lag; else 0."""
    if window.end < event.start:
        gap, limit = event.start - window.end, policy.lead
    elif window.start > event.end:
        gap, limit = window.start - event.end, policy.lag
    else:
        return 1.0
    if gap > limit:
        return 0.0
    return float(0.5 ** (gap / policy.half_life))


class OverlapTier(StrEnum):
    """How an event's scope relates to a subject, from closest to none."""

    SEGMENT = "segment"
    """The event names this segment, or one this segment refines."""
    COLUMN = "column"
    """The event names a column this subject is about."""
    SOURCE = "source"
    """The event covers this whole source."""
    COARSER = "coarser"
    """The event names a sub-segment of this subject: it explains part of the change."""
    GLOBAL = "global"
    """The event covers every source, unrestricted."""
    OUT_OF_SCOPE = "out_of_scope"
    """Same source, but the event names other columns or segments."""
    DISJOINT = "disjoint"
    """A different source."""


TIER_SCORE: Final[Mapping[OverlapTier, float]] = {
    OverlapTier.SEGMENT: 1.0,
    OverlapTier.COLUMN: 0.9,
    OverlapTier.SOURCE: 0.8,
    OverlapTier.COARSER: 0.7,
    OverlapTier.GLOBAL: 0.6,
    OverlapTier.OUT_OF_SCOPE: 0.0,
    OverlapTier.DISJOINT: 0.0,
}

UNTOUCHED: Final = frozenset({OverlapTier.OUT_OF_SCOPE, OverlapTier.DISJOINT})


@dataclass(frozen=True)
class _EventView:
    """An event's scope, reduced to canonical names and predicate hashes once."""

    event: ContextEvent
    sources: frozenset[SourceId]
    columns: frozenset[str]
    segments: tuple[frozenset[str], ...]

    @classmethod
    def of(cls, event: ContextEvent) -> _EventView:
        return cls(
            event=event,
            sources=frozenset(event.scope.source_ids),
            columns=frozenset(column_name(c) for c in event.scope.columns),
            segments=tuple(_segment_parts(s)[0] for s in event.scope.segments),
        )


def scope_overlap(view: _EventView, subject: Subject) -> OverlapTier:
    """Where ``subject`` sits relative to the event's scope."""
    if view.sources and subject.source_id not in view.sources:
        return OverlapTier.DISJOINT
    if not (view.columns or view.segments):
        return OverlapTier.SOURCE if view.sources else OverlapTier.GLOBAL
    found: list[OverlapTier] = []
    for predicates in view.segments:
        if predicates <= subject.predicates:
            found.append(OverlapTier.SEGMENT if predicates else OverlapTier.SOURCE)
        elif subject.predicates < predicates:
            found.append(OverlapTier.COARSER)
    if view.columns & subject.columns:
        found.append(OverlapTier.COLUMN)
    if not found:
        return OverlapTier.OUT_OF_SCOPE
    return max(found, key=TIER_SCORE.__getitem__)


def specificity(event: ContextEvent) -> float:
    """Narrow and short beats broad and long. In (0, 1]."""
    scope = event.scope
    if scope.segments:
        breadth = 1.0
    elif scope.columns:
        breadth = 0.85
    elif scope.source_ids:
        breadth = 0.7
    else:
        breadth = 0.3
    breadth /= 1.0 + 0.5 * math.log(max(1, len(scope.source_ids)))
    days = event.duration / _DAY
    return breadth / (1.0 + days / 30.0)


class CounterfactualVerdict(StrEnum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    """Untouched peers moved as much as touched ones: something bigger did it."""
    INCONSISTENT = "inconsistent"
    """The event touched other comparable peers and almost none of them moved."""
    UNTESTABLE = "untestable"


_DOWNGRADE: Final = frozenset(
    {CounterfactualVerdict.CONTRADICTED, CounterfactualVerdict.INCONSISTENT}
)


class Counterfactual(GodwitModel):
    """The counterfactual check's result, with the counts behind it."""

    verdict: CounterfactualVerdict
    touched_observed: int
    touched_changed: int
    untouched_observed: int
    untouched_changed: int
    confounded: int = Field(
        default=0, description="Untouched peers excluded because a same-type event hit them."
    )


def _changed(peer: Subject, effect: float, fraction: float) -> bool:
    if peer.effect is None or peer.effect * effect <= 0:
        return False
    return abs(peer.effect) >= fraction * abs(effect)


def counterfactual(
    view: _EventView,
    subject: Subject,
    peers: Sequence[Subject],
    policy: CounterfactualPolicy,
    confounders: Sequence[_EventView] = (),
) -> Counterfactual:
    """Did comparable peers the event did NOT touch change the same way?

    ``confounders`` are other events of the same context type aligned with this window.
    A peer they touch is not a control: on New Year's Day a German source is untouched
    by the US holiday and touched by its own, so its drop says nothing about either.
    """
    effect = subject.effect
    touched = [1, 1]  # the candidate itself: observed, and changed
    untouched = [0, 0]
    confounded = 0
    if effect is not None and effect != 0.0:
        lo = subject.window.start - policy.peer_tolerance
        hi = subject.window.end + policy.peer_tolerance
        for peer in peers:
            comparable = (
                peer.key != subject.key
                and peer.family == subject.family
                and peer.structure == subject.structure
                and lo <= peer.window.end
                and peer.window.start <= hi
            )
            if not comparable:
                continue
            bucket = touched
            if scope_overlap(view, peer) in UNTOUCHED:
                if any(scope_overlap(c, peer) not in UNTOUCHED for c in confounders):
                    confounded += 1
                    continue
                bucket = untouched
            bucket[0] += 1
            bucket[1] += int(_changed(peer, effect, policy.change_fraction))
    others_seen, others_moved = touched[0] - 1, touched[1] - 1
    if effect is None or effect == 0.0:
        verdict = CounterfactualVerdict.UNTESTABLE
    elif (
        others_seen >= policy.min_touched and others_moved / others_seen < policy.consistency_floor
    ):
        verdict = CounterfactualVerdict.INCONSISTENT
    elif untouched[0] < policy.min_untouched:
        verdict = CounterfactualVerdict.UNTESTABLE
    elif untouched[1] / untouched[0] >= policy.contradict_ratio * (touched[1] / touched[0]):
        verdict = CounterfactualVerdict.CONTRADICTED
    else:
        verdict = CounterfactualVerdict.SUPPORTED
    return Counterfactual(
        verdict=verdict,
        touched_observed=touched[0],
        touched_changed=touched[1],
        untouched_observed=untouched[0],
        untouched_changed=untouched[1],
        confounded=confounded,
    )


# --------------------------------------------------------------------------------------
# The match
# --------------------------------------------------------------------------------------


class Match(GodwitModel):
    """One context event's claim on one candidate. Contains no row value."""

    event_id: str
    context_type: ContextType
    kind: str
    strength: Probability
    temporal: Probability
    tier: OverlapTier
    overlap: Probability
    prior: Probability
    specificity: Probability
    counterfactual: Counterfactual
    downgraded: bool = Field(
        description="True when the counterfactual check contradicted the match and its "
        "strength was cut. The match is kept: a downgraded explanation is still context."
    )


type PriorFn = Callable[[ContextType, str, SourceId], float]
"""``PriorBook.prior`` or anything shaped like it."""


def match_candidate(
    subject: Subject,
    events: Sequence[ContextEvent],
    *,
    peers: Sequence[Subject],
    prior: PriorFn,
    policy: MatchPolicy,
) -> tuple[Match, ...]:
    """Every event aligned with ``subject``, strongest first. None are discarded."""
    weights = policy.weights
    out: list[Match] = []
    aligned: list[tuple[float, _EventView]] = []
    for event in events:
        temporal_policy = policy.temporal.get(event.context_type, TemporalPolicy())
        temporal = temporal_proximity(subject.window, event, temporal_policy)
        if temporal > 0.0:
            aligned.append((temporal, _EventView.of(event)))
    for temporal, view in aligned:
        event = view.event
        tier = scope_overlap(view, subject)
        overlap = TIER_SCORE[tier]
        if temporal * overlap == 0.0:
            continue
        p = prior(event.context_type, subject.family, subject.source_id)
        spec = specificity(event)
        confounders = [
            other
            for _, other in aligned
            if other.event.context_type is event.context_type
            and other.event.event_id != event.event_id
        ]
        check = counterfactual(view, subject, peers, policy.counterfactual, confounders)
        credit = {
            CounterfactualVerdict.SUPPORTED: 1.0,
            CounterfactualVerdict.UNTESTABLE: policy.counterfactual.untestable_credit,
            CounterfactualVerdict.CONTRADICTED: 0.0,
            CounterfactualVerdict.INCONSISTENT: 0.0,
        }[check.verdict]
        evidence = weights.prior * p + weights.specificity * spec + weights.counterfactual * credit
        strength = temporal * overlap * evidence
        downgraded = check.verdict in _DOWNGRADE
        if downgraded:
            strength *= weights.contradiction_penalty
        out.append(
            Match(
                event_id=event.event_id,
                context_type=event.context_type,
                kind=event.kind,
                strength=min(1.0, strength),
                temporal=temporal,
                tier=tier,
                overlap=overlap,
                prior=p,
                specificity=spec,
                counterfactual=check,
                downgraded=downgraded,
            )
        )
    return tuple(sorted(out, key=lambda m: (-m.strength, m.event_id)))
