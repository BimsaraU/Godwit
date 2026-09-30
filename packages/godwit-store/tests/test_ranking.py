"""Queue ranking: determinism, eligibility, and the two queues pulling apart.

Ranking is pure -- no database, no clock, no LLM -- so most of this needs no fixtures at
all. The last few tests go through the store, because eligibility depends on
suppression and lifecycle, which are stored facts.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from _store_support import CandidateSpec
from godwit_contracts import (
    AlertQueue,
    Feedback,
    Instant,
    PatternId,
    PatternLifecycle,
    RunId,
    SnapshotId,
    Verdict,
)
from godwit_store.fdr import HoldoutKind, HoldoutPolicy, HypothesisFamily, ValidationStatus
from godwit_store.ranking import (
    DEFAULT_WEIGHTS,
    OPERATIONAL_CAPACITY_PER_DAY,
    RankingInputs,
    RankingWeights,
    feedback_prior,
    novelty,
    rank,
    recency,
    score_discovery,
    score_operational,
    strength,
)
from godwit_store.store import PatternStore
from sqlalchemy.orm import Session


def _inputs(pattern_id: str, at: Instant, **overrides: Any) -> RankingInputs:
    """One ranking input with sane defaults, overridden by keyword.

    ``**overrides`` rather than twelve named parameters: this helper is called from
    twenty tests and each one varies exactly one thing, so naming the other eleven at
    every call site would bury the variable under the constants.
    """
    age: _dt.timedelta = overrides.pop("age", _dt.timedelta(0))
    defaults: dict[str, Any] = {
        "pattern_id": PatternId(pattern_id),
        "structure_key": "shp_default",
        "lifecycle": PatternLifecycle.PROPOSED,
        "validation_status": ValidationStatus.VALIDATED,
        "explained_away": False,
        "suppressed": False,
        "q_value": 0.01,
        "first_seen": at - age - _dt.timedelta(days=1),
        "last_seen": at - age,
        "as_of": at,
        "group_confirmations": 0,
        "group_rejections": 0,
        "group_size": 1,
    }
    return RankingInputs(**{**defaults, **overrides})


# ------------------------------------------------------------------------------------
# The five signals
# ------------------------------------------------------------------------------------


def test_strength_comes_from_the_adjusted_q_not_the_raw_p(at: Instant) -> None:
    """Thousands of hypotheses were tested; ranking by raw significance ranks the noise."""
    assert strength(_inputs("p1", at, q_value=0.001)) > strength(_inputs("p2", at, q_value=0.4))


def test_a_pattern_with_no_q_value_gets_the_floor(at: Instant) -> None:
    """Unadjusted means "not yet through FDR control", not "benefit of the doubt"."""
    assert strength(_inputs("p1", at, q_value=None)) == DEFAULT_WEIGHTS.strength_floor


def test_recency_halves_over_the_half_life(at: Instant) -> None:
    fresh = recency(_inputs("p1", at, age=_dt.timedelta(0)))
    aged = recency(_inputs("p2", at, age=DEFAULT_WEIGHTS.recency_half_life))
    assert fresh == 1.0
    assert abs(aged - 0.5) < 1e-9


def test_a_backfilled_future_last_seen_is_clamped(at: Instant) -> None:
    assert recency(_inputs("p1", at, age=-_dt.timedelta(days=5))) == 1.0


def test_novelty_falls_as_a_shape_becomes_familiar(at: Instant) -> None:
    assert novelty(_inputs("p1", at, group_size=1)) == 1.0
    assert novelty(_inputs("p2", at, group_size=10)) == 0.1


def test_the_feedback_prior_starts_at_no_opinion(at: Instant) -> None:
    """With no history the prior is exactly 0.5. Laplace smoothing, and the honest start."""
    assert feedback_prior(_inputs("p1", at)) == 0.5


def test_one_rejection_does_not_bury_a_whole_shape(at: Instant) -> None:
    """Without smoothing, a single rejection sets the rate to zero for ever."""
    prior = feedback_prior(_inputs("p1", at, group_rejections=1))
    assert 0.0 < prior < 0.5


def test_a_confirmed_shape_is_ranked_above_a_rejected_one(at: Instant) -> None:
    good = score_operational(_inputs("p1", at, group_confirmations=9))
    bad = score_operational(_inputs("p2", at, group_rejections=9))
    assert good > bad


# ------------------------------------------------------------------------------------
# The two queues
# ------------------------------------------------------------------------------------


def test_the_operational_queue_prefers_recent_over_merely_strong(at: Instant) -> None:
    """An old finding, however significant, is not an alert."""
    old_and_strong = _inputs("p_old", at, q_value=0.0001, age=_dt.timedelta(days=30))
    recent_and_weaker = _inputs("p_new", at, q_value=0.05, age=_dt.timedelta(0))
    assert score_operational(recent_and_weaker) > score_operational(old_and_strong)


def test_the_discovery_queue_prefers_new_over_strong(at: Instant) -> None:
    """A strong finding of a shape confirmed forty times is not a discovery."""
    familiar_and_strong = _inputs("p_known", at, q_value=0.0001, group_size=40)
    novel_and_weaker = _inputs("p_novel", at, q_value=0.05, group_size=1)
    assert score_discovery(novel_and_weaker) > score_discovery(familiar_and_strong)


def test_the_two_queues_disagree_about_the_same_population(at: Instant) -> None:
    """If they agreed, one of them would be redundant and the economics would be wrong."""
    population = [
        _inputs("p_novel", at, q_value=0.05, group_size=1, structure_key="shp_a"),
        _inputs("p_known", at, q_value=0.0001, group_size=40, structure_key="shp_b"),
    ]
    operational = rank(population, queue=AlertQueue.OPERATIONAL)
    discovery = rank(population, queue=AlertQueue.DISCOVERY)
    assert operational[0].pattern_id == PatternId("p_known")
    assert discovery[0].pattern_id == PatternId("p_novel")


def test_an_explained_away_pattern_sinks_without_vanishing(at: Instant) -> None:
    """An explanation can be wrong, and a finding that vanishes cannot be re-examined."""
    explained = _inputs("p1", at, explained_away=True)
    plain = _inputs("p2", at)
    assert 0.0 < score_operational(explained) < score_operational(plain)


# ------------------------------------------------------------------------------------
# Eligibility
# ------------------------------------------------------------------------------------


def test_an_unvalidated_pattern_never_reaches_the_operational_queue(at: Instant) -> None:
    """Whatever its q-value says. Deliverable 3, at the point it actually bites."""
    unvalidated = _inputs(
        "p1", at, q_value=0.0000001, validation_status=ValidationStatus.UNVALIDATED
    )
    assert rank([unvalidated], queue=AlertQueue.OPERATIONAL) == ()
    listed = rank([unvalidated], queue=AlertQueue.OPERATIONAL, include_ineligible=True)
    assert listed[0].ineligible_reason == "validation:unvalidated"


def test_not_tested_is_barred_too(at: Instant) -> None:
    """ "We did not look" is not evidence. A run with no holdout cannot page anyone."""
    not_tested = _inputs("p1", at, validation_status=ValidationStatus.NOT_TESTED)
    assert rank([not_tested], queue=AlertQueue.OPERATIONAL) == ()


def test_the_discovery_queue_tolerates_unvalidated_at_a_discount(at: Instant) -> None:
    """Five items a week is an investigation budget; something that did not reproduce is
    sometimes exactly what is worth investigating."""
    unvalidated = _inputs("p1", at, validation_status=ValidationStatus.UNVALIDATED)
    validated = _inputs("p2", at, validation_status=ValidationStatus.VALIDATED)
    assert rank([unvalidated], queue=AlertQueue.DISCOVERY) != ()
    assert score_discovery(unvalidated) < score_discovery(validated)


def test_a_suppressed_pattern_is_in_neither_queue(at: Instant) -> None:
    suppressed = _inputs("p1", at, suppressed=True)
    assert rank([suppressed], queue=AlertQueue.OPERATIONAL) == ()
    assert rank([suppressed], queue=AlertQueue.DISCOVERY) == ()


def test_a_closed_pattern_is_not_ranked(at: Instant) -> None:
    rejected = _inputs("p1", at, lifecycle=PatternLifecycle.REJECTED)
    listed = rank([rejected], queue=AlertQueue.OPERATIONAL, include_ineligible=True)
    assert listed[0].ineligible_reason == "lifecycle:rejected"


def test_capacity_is_applied_after_ineligible_items_are_dropped(at: Instant) -> None:
    """A suppressed pattern must not consume one of the fifty slots."""
    population = [
        _inputs("p_suppressed", at, q_value=0.00001, suppressed=True),
        *(
            _inputs(f"p{index:02d}", at, q_value=0.01 + index / 1000, structure_key=f"shp{index}")
            for index in range(3)
        ),
    ]
    ranked = rank(population, queue=AlertQueue.OPERATIONAL, capacity=2)
    assert len(ranked) == 2
    assert all(entry.pattern_id != PatternId("p_suppressed") for entry in ranked)


# ------------------------------------------------------------------------------------
# Determinism
# ------------------------------------------------------------------------------------


def test_ties_are_broken_by_pattern_id(at: Instant) -> None:
    """A queue that reshuffles between two page loads makes reviewers lose their place."""
    population = [_inputs(name, at) for name in ("p_c", "p_a", "p_b")]
    first = rank(population, queue=AlertQueue.OPERATIONAL)
    second = rank(list(reversed(population)), queue=AlertQueue.OPERATIONAL)
    assert [entry.pattern_id for entry in first] == ["p_a", "p_b", "p_c"]
    assert first == second


def test_the_components_are_returned_so_the_order_can_be_explained(at: Instant) -> None:
    """ "Why is this at the top" is the first thing an operator asks."""
    (entry,) = rank([_inputs("p1", at)], queue=AlertQueue.OPERATIONAL)
    assert entry.rank_score == entry.strength * entry.recency * entry.feedback_prior


def test_the_weights_are_data_not_code(at: Instant) -> None:
    """Nothing here was fitted; the defaults are judgements, and are adjustable as such."""
    impatient = RankingWeights(recency_half_life=_dt.timedelta(hours=6))
    aged = _inputs("p1", at, age=_dt.timedelta(days=3))
    assert score_operational(aged, weights=impatient) < score_operational(aged)


def test_the_capacity_constants_match_the_objective_function() -> None:
    assert OPERATIONAL_CAPACITY_PER_DAY == 50


# ------------------------------------------------------------------------------------
# Through the store
# ------------------------------------------------------------------------------------


def test_the_store_assembles_the_inputs_and_the_ranking_stays_pure(
    session: Session, at: Instant
) -> None:
    """The store's only job here is to gather facts; the arithmetic has no session."""
    store = PatternStore(session)
    report = store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId("run_1"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=2,
            declared_at=at,
        ),
        candidates=[
            CandidateSpec(candidate_id="c1", created_at=at).build(),
            CandidateSpec(
                candidate_id="c2", created_at=at, pairs=(("country", "ES"),), p_value=0.4
            ).build(),
        ],
        holdout=HoldoutPolicy(
            kind=HoldoutKind.TIME_SLICE, time_from=at, time_to=at + _dt.timedelta(days=1)
        ),
        holdout_candidates=[
            CandidateSpec(candidate_id="h1", created_at=at).build(),
        ],
        at=at,
    )
    assert len(report.patterns_created) == 2

    operational = store.queue(queue=AlertQueue.OPERATIONAL, at=at)
    assert len(operational) == 1, "only the candidate that reproduced on the holdout"

    discovery = store.queue(queue=AlertQueue.DISCOVERY, at=at)
    assert len(discovery) == 2, "the discovery queue sees both, at a discount"


def test_a_rejected_pattern_leaves_the_queue(session: Session, at: Instant) -> None:
    store = PatternStore(session)
    report = store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId("run_1"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=1,
            declared_at=at,
        ),
        candidates=[CandidateSpec(candidate_id="c1", created_at=at).build()],
        holdout=HoldoutPolicy(
            kind=HoldoutKind.TIME_SLICE, time_from=at, time_to=at + _dt.timedelta(days=1)
        ),
        holdout_candidates=[CandidateSpec(candidate_id="h1", created_at=at).build()],
        at=at,
    )
    pattern_id = report.patterns_created[0]
    assert len(store.queue(queue=AlertQueue.OPERATIONAL, at=at)) == 1

    store.record_feedback(
        Feedback(
            pattern_id=pattern_id,
            verdict=Verdict.REJECTED,
            reviewer_id="analyst_7",
            decided_at=at + _dt.timedelta(hours=1),
        )
    )
    assert store.queue(queue=AlertQueue.OPERATIONAL, at=at) == ()
