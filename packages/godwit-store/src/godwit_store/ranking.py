"""Queue ranking. Pure functions, no database, no LLM, no clock.

Two queues with different economics (the objective function):

``OPERATIONAL``   about 50 alerts a day, target precision at or above 30% after 90-day
                  label reconciliation. Optimised for **being right now**.
``DISCOVERY``     about 5 items a week, target at least one confirmed-novel pattern a
                  month. Optimised for **being new**.

Ranking the same list twice with the same inputs gives the same order, including ties,
which are broken by ``pattern_id``. That matters more than it sounds: a queue that
reshuffles between two page loads makes reviewers lose their place, and a
non-deterministic order cannot be tested at all.

**No LLM input at this layer** (deliverable 9). The LLM names and explains patterns
after the fact; if it also ranked them, deleting the LLM layer would change which alerts
a human saw, and invariant 7 says it must not.

THE FIVE SIGNALS
----------------
``strength``        how big and how significant the finding is.
``recency``         how recently it was last supported, decayed exponentially.
``novelty``         how unlike everything already in the store it is.
``explained_away``  whether L3 found a deploy, campaign or holiday behind it.
``feedback prior``  how often findings of this shape turned out to be real.

The feedback prior is a Laplace-smoothed confirmation rate over the pattern's
*structure group*, not over the pattern itself: a brand-new pattern has no history of
its own, and the useful question is whether findings that look like it have been worth
reviewing. Smoothing matters -- without it, one rejection of one new shape would bury
every future instance of it at a confirmation rate of exactly zero.

THE TWO QUEUES USE THE SAME PARTS DIFFERENTLY
---------------------------------------------
Operational multiplies strength by recency: an old finding, however strong, is not an
alert. Discovery multiplies novelty by the square root of strength: a weak finding
nobody has seen before is worth five minutes, and a strong finding of a shape confirmed
forty times is not a discovery, it is a Tuesday.
"""

from __future__ import annotations

import datetime as _dt
import math
from collections.abc import Sequence
from typing import Final

from godwit_contracts import (
    AlertQueue,
    GodwitModel,
    Instant,
    NonNegInt,
    PatternId,
    PatternLifecycle,
    Probability,
)
from pydantic import Field

from godwit_store.fdr import ValidationStatus

__all__ = [
    "DEFAULT_WEIGHTS",
    "DISCOVERY_CAPACITY_PER_WEEK",
    "OPERATIONAL_CAPACITY_PER_DAY",
    "RankedPattern",
    "RankingInputs",
    "RankingWeights",
    "feedback_prior",
    "is_eligible",
    "novelty",
    "rank",
    "recency",
    "score_discovery",
    "score_operational",
    "strength",
]

OPERATIONAL_CAPACITY_PER_DAY: Final[int] = 50
"""Human review capacity. ``k`` in "precision@k", and therefore the only number that
makes precision a meaningful target rather than a knob."""

DISCOVERY_CAPACITY_PER_WEEK: Final[int] = 5
"""The other queue's capacity. Five a week, because a discovery item costs an
investigation, not a glance."""

_OPEN_STATES: Final[frozenset[PatternLifecycle]] = frozenset(
    {PatternLifecycle.PROPOSED, PatternLifecycle.CONFIRMED, PatternLifecycle.EXPLAINED_AWAY}
)


class RankingWeights(GodwitModel):
    """The tunable parts, in one object so an operator can see all of them at once.

    Defaults are stated, not discovered: nothing here was fitted to data, and pretending
    otherwise would be worse than admitting these are judgements. They are exposed so
    that a deployment which measures its own precision can adjust them deliberately
    rather than by editing code.
    """

    recency_half_life: _dt.timedelta = Field(
        default=_dt.timedelta(days=3),
        description="How fast an unsupported finding falls down the operational queue. "
        "Three days: roughly when 'this is happening' becomes 'this happened'.",
    )
    explained_away_penalty: Probability = Field(
        default=0.05,
        description="Multiplier for a pattern L3 explained. Not zero -- an explanation "
        "can be wrong, and a finding that vanishes cannot be re-examined -- but small "
        "enough that it never displaces an unexplained one.",
    )
    unvalidated_discovery_penalty: Probability = Field(
        default=0.25,
        description="Multiplier for a discovery item that did not reproduce on the "
        "holdout. The discovery queue tolerates what the operational queue refuses "
        "outright, because its job is to look at things that are not yet established.",
    )
    strength_floor: Probability = Field(
        default=0.01,
        description="Strength a pattern keeps when it has no q-value at all. Small, so "
        "an unadjusted finding sorts below every adjusted one rather than above them.",
    )


DEFAULT_WEIGHTS: Final[RankingWeights] = RankingWeights()


class RankingInputs(GodwitModel):
    """Everything the ranking functions may look at. Deliberately a closed list.

    Every field is one of our identifiers, a count, a statistic or a state. None of it
    is tainted and none of it came from an LLM. A future signal that cannot be expressed
    here needs a decision about whether it belongs in a ranking at all, which is exactly
    why the input type is explicit rather than a row.
    """

    pattern_id: PatternId
    structure_key: str
    lifecycle: PatternLifecycle
    validation_status: ValidationStatus
    explained_away: bool = False
    suppressed: bool = False

    q_value: Probability | None = None
    detector_score: float = Field(
        default=0.0,
        description="The detector's own ranking score, already calibrated across "
        "detectors by the store. Used only to break ties within a q-value.",
    )
    population: NonNegInt | None = None

    first_seen: Instant
    last_seen: Instant
    as_of: Instant = Field(
        description="The instant the ranking is computed at. Injected -- nothing here "
        "reads a clock, so a queue can be recomputed for any past moment and audited."
    )

    group_confirmations: NonNegInt = Field(
        default=0, description="Confirmed patterns sharing this structure key."
    )
    group_rejections: NonNegInt = Field(
        default=0, description="Rejected patterns sharing this structure key."
    )
    group_size: NonNegInt = Field(
        default=1,
        description="How many patterns share this structure key, this one included. "
        "Drives novelty: the fortieth instance of a shape is not a discovery.",
    )


class RankedPattern(GodwitModel):
    """One ranked item: the score, and the parts it was built from.

    The components are returned rather than discarded, so that "why is this at the top"
    is answerable without re-running the ranker. That is the first thing an operator
    asks and the first thing a regression test needs.
    """

    pattern_id: PatternId
    queue: AlertQueue
    rank_score: float
    strength: float
    recency: float
    novelty: float
    feedback_prior: float
    eligible: bool
    ineligible_reason: str | None = None


def strength(inputs: RankingInputs, *, weights: RankingWeights = DEFAULT_WEIGHTS) -> float:
    """How significant the finding is, in [0, 1].

    Driven by the **adjusted** q-value, never the raw p-value: thousands of hypotheses
    were tested per snapshot and ranking by raw significance would put the noise at the
    top by construction. A pattern with no q-value has not been through FDR control and
    gets the floor rather than the benefit of the doubt.
    """
    if inputs.q_value is None:
        return weights.strength_floor
    return max(weights.strength_floor, 1.0 - inputs.q_value)


def recency(inputs: RankingInputs, *, weights: RankingWeights = DEFAULT_WEIGHTS) -> float:
    """Exponential decay of time since the pattern was last supported, in (0, 1].

    A finding last seen at ``as_of`` scores 1.0; one last seen a half-life ago scores
    0.5. Future ``last_seen`` values -- which a backfill can produce -- are clamped to
    1.0 rather than allowed to exceed it.
    """
    half_life = weights.recency_half_life.total_seconds()
    if half_life <= 0.0:
        raise ValueError("recency_half_life must be positive")
    age = (inputs.as_of - inputs.last_seen).total_seconds()
    if age <= 0.0:
        return 1.0
    return float(0.5 ** (age / half_life))


def novelty(inputs: RankingInputs) -> float:
    """How unlike everything already in the store this pattern is, in (0, 1].

    ``1 / group_size``: the first instance of a shape scores 1.0, the tenth scores 0.1.
    Shape, not segment -- the same divergence in a different country is not a new
    discovery, and the structure key is what makes those two the same shape while their
    signatures differ.
    """
    return 1.0 / float(max(1, inputs.group_size))


def feedback_prior(inputs: RankingInputs) -> float:
    """Laplace-smoothed confirmation rate for this pattern's shape, in (0, 1).

    ``(confirmations + 1) / (confirmations + rejections + 2)``. With no history at all
    it is exactly 0.5 -- no opinion -- which is the honest starting point for a shape
    nobody has judged.
    """
    confirmations = float(inputs.group_confirmations)
    rejections = float(inputs.group_rejections)
    return (confirmations + 1.0) / (confirmations + rejections + 2.0)


def is_eligible(inputs: RankingInputs, queue: AlertQueue) -> tuple[bool, str | None]:
    """Whether a pattern may appear in ``queue``, and why not when it may not.

    The operational queue takes only ``VALIDATED`` patterns. A candidate that did not
    reproduce on the holdout slice never reaches it, whatever its q-value says
    (deliverable 3) -- and neither does one from a run that reserved no holdout, because
    "we did not look" is not evidence of anything.
    """
    if inputs.suppressed:
        return False, "suppressed"
    if inputs.lifecycle not in _OPEN_STATES:
        return False, f"lifecycle:{inputs.lifecycle.value}"
    if (
        queue is AlertQueue.OPERATIONAL
        and inputs.validation_status is not ValidationStatus.VALIDATED
    ):
        return False, f"validation:{inputs.validation_status.value}"
    return True, None


def score_operational(inputs: RankingInputs, *, weights: RankingWeights = DEFAULT_WEIGHTS) -> float:
    """Rank score for the operational queue: strong, recent and historically real.

    Multiplicative rather than a weighted sum, so that a zero in any one factor is
    decisive. An explained-away finding does not get to compensate with a large effect
    size, and a finding from six weeks ago does not get to compensate with a tiny
    q-value.
    """
    penalty = weights.explained_away_penalty if inputs.explained_away else 1.0
    return (
        strength(inputs, weights=weights)
        * recency(inputs, weights=weights)
        * feedback_prior(inputs)
        * penalty
    )


def score_discovery(inputs: RankingInputs, *, weights: RankingWeights = DEFAULT_WEIGHTS) -> float:
    """Rank score for the discovery queue: new first, with enough signal to be worth it.

    ``sqrt(strength)`` rather than ``strength``: the discovery queue should not be a
    second operational queue sorted the same way. Taking the root flattens the
    significance axis so that novelty dominates, while still keeping a finding with no
    signal at all off the list.

    An unvalidated finding is penalised here rather than excluded. Five items a week is
    an investigation budget, and something that did not reproduce is sometimes precisely
    what is worth investigating.
    """
    penalty = weights.explained_away_penalty if inputs.explained_away else 1.0
    if inputs.validation_status is not ValidationStatus.VALIDATED:
        penalty *= weights.unvalidated_discovery_penalty
    return (
        novelty(inputs)
        * math.sqrt(strength(inputs, weights=weights))
        * feedback_prior(inputs)
        * penalty
    )


def rank(
    items: Sequence[RankingInputs],
    *,
    queue: AlertQueue,
    weights: RankingWeights = DEFAULT_WEIGHTS,
    capacity: int | None = None,
    include_ineligible: bool = False,
) -> tuple[RankedPattern, ...]:
    """Rank a population for one queue, highest first, deterministically.

    Ties are broken by ``pattern_id``, so two runs over the same inputs produce the same
    order down to the last row. ``capacity`` truncates to the queue's human capacity --
    ``k`` in precision@k -- and is applied after ineligible items are dropped, so a
    suppressed pattern never consumes a slot.

    ``include_ineligible`` returns everything with ``eligible`` and
    ``ineligible_reason`` filled in, for the "why is this not in my queue" screen. It
    never changes the order of the eligible items.
    """
    scorer = score_operational if queue is AlertQueue.OPERATIONAL else score_discovery
    ranked: list[RankedPattern] = []
    for item in items:
        eligible, reason = is_eligible(item, queue)
        ranked.append(
            RankedPattern(
                pattern_id=item.pattern_id,
                queue=queue,
                rank_score=scorer(item, weights=weights) if eligible else 0.0,
                strength=strength(item, weights=weights),
                recency=recency(item, weights=weights),
                novelty=novelty(item),
                feedback_prior=feedback_prior(item),
                eligible=eligible,
                ineligible_reason=reason,
            )
        )

    eligible_items = sorted(
        (entry for entry in ranked if entry.eligible),
        key=lambda entry: (-entry.rank_score, str(entry.pattern_id)),
    )
    if capacity is not None:
        eligible_items = eligible_items[:capacity]
    if not include_ineligible:
        return tuple(eligible_items)
    rejected = sorted(
        (entry for entry in ranked if not entry.eligible),
        key=lambda entry: str(entry.pattern_id),
    )
    return tuple(eligible_items) + tuple(rejected)
