"""Deduplication, end to end. The acceptance criterion, plus what it does not cover.

*"200 candidates of which 40 are duplicates by construction; report precision/recall."*

Precision and recall of **pairwise grouping**: over every unordered pair of candidates,
a pair is a true duplicate if it was built as one, and a predicted duplicate if the
store put both in the same pattern.

    precision = TP / (TP + FP)   -- of the pairs we merged, how many should have merged
    recall    = TP / (TP + FN)   -- of the pairs that should have merged, how many did

Precision is the number that matters here. A false positive merges two different
findings and one of them is never seen again, which is a silent loss; a false negative
shows a reviewer the same thing twice, which is annoying and visible. The two failures
are not symmetric and the store is built to prefer the second.

The population is constructed so that the distinct findings differ in each of the ways
the signature is supposed to separate -- segment value, column set, effect direction,
detector family -- rather than being 160 copies of one easy case.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence
from itertools import combinations

from _store_support import CandidateSpec
from godwit_contracts import Candidate, EvidenceKind, Instant, RunId, SnapshotId
from godwit_store.fdr import HoldoutKind, HoldoutPolicy, HypothesisFamily
from godwit_store.schema import (
    CandidateRow,
    PatternAncestryRow,
    PatternCandidateRow,
    PatternRow,
)
from godwit_store.signature import signature_of
from godwit_store.store import PatternStore, pattern_id_for
from sqlalchemy import func, select
from sqlalchemy.orm import Session

_DISTINCT = 160
_DUPLICATES = 40
_COUNTRIES = ("PT", "ES", "FR", "DE", "IT", "NL", "BE", "SE", "NO", "DK")
_COLUMNS = (("amount",), ("amount", "status"), ("refund_total",), ("device_id",))
_KINDS = (
    EvidenceKind.SEGMENT_DIVERGENCE,
    EvidenceKind.RATE_CHANGE,
    EvidenceKind.DISTRIBUTION_SHIFT,
    EvidenceKind.HEAVY_HITTER_SHIFT,
)


def _distinct_spec(index: int, at: Instant) -> CandidateSpec:
    """One of 160 findings, differing along every axis the signature separates.

    ``index`` walks the column set, the evidence kind, the direction and the country at
    different strides, so the population exercises every axis the signature separates.
    The ``tier`` predicate carries the index, which is what *guarantees* all 160 are
    distinct: a construction that relied on the strides not colliding would be a test of
    arithmetic rather than of dedup, and it collides at 160.
    """
    rising = index % 2 == 0
    return CandidateSpec(
        candidate_id=f"cand_distinct_{index:04d}",
        created_at=at,
        pairs=(
            ("country", _COUNTRIES[index % len(_COUNTRIES)]),
            ("tier", f"t{index:04d}"),
        ),
        columns=_COLUMNS[(index // 3) % len(_COLUMNS)],
        kind=_KINDS[(index // 5) % len(_KINDS)],
        statistic=10.0 if rising else 1.0,
        baseline=1.0 if rising else 10.0,
        p_value=0.0001,
        score=0.5 + (index % 50) / 100.0,
        probe_key=f"prb_{index % 7}",
    )


def _duplicate_of(spec: CandidateSpec, index: int) -> CandidateSpec:
    """The same finding, seen again: a new candidate id and different numbers.

    Everything the signature reads is held fixed; everything it deliberately ignores is
    varied. A store that deduplicated on the rendered numbers rather than on the
    signature would fail this.
    """
    return CandidateSpec(
        candidate_id=f"cand_dup_{index:04d}",
        created_at=spec.created_at + _dt.timedelta(hours=1 + index),
        pairs=spec.pairs,
        columns=spec.columns,
        kind=spec.kind,
        statistic=spec.statistic * 1.37,
        baseline=spec.baseline,
        p_value=0.0002,
        score=spec.score * 0.8,
        probe_key=spec.probe_key,
    )


def _population(at: Instant) -> tuple[list[Candidate], dict[str, str]]:
    """The 200 candidates, and the ground truth of which finding each one is.

    Ground truth is a mapping from candidate id to a synthetic finding id, built here
    rather than derived from the store, so the test grades the store instead of asking
    it to grade itself.
    """
    specs = [_distinct_spec(index, at) for index in range(_DISTINCT)]
    truth = {spec.candidate_id: f"finding_{index}" for index, spec in enumerate(specs)}
    duplicates: list[CandidateSpec] = []
    for index in range(_DUPLICATES):
        original = specs[index * 3]
        duplicate = _duplicate_of(original, index)
        duplicates.append(duplicate)
        truth[duplicate.candidate_id] = truth[original.candidate_id]
    population = [spec.build() for spec in (*specs, *duplicates)]
    distinct_signatures = {str(signature_of(spec.build()).key) for spec in specs}
    assert len(distinct_signatures) == _DISTINCT, (
        "the fixture itself is wrong: two of the supposedly distinct findings share "
        "a signature, so the test would be grading the store on a false ground truth"
    )
    return population, truth


def _ingest(session: Session, candidates: Sequence[Candidate], at: Instant) -> None:
    store = PatternStore(session)
    store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId("run_dedup"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=len(candidates),
            declared_at=at,
        ),
        candidates=candidates,
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )


def _grouping(session: Session) -> dict[str, str]:
    rows = session.execute(
        select(PatternCandidateRow.candidate_id, PatternCandidateRow.pattern_id)
    ).all()
    return {str(candidate_id): str(pattern_id) for candidate_id, pattern_id in rows}


def _pairwise_scores(
    truth: dict[str, str], predicted: dict[str, str]
) -> tuple[float, float, int, int, int]:
    true_positive = false_positive = false_negative = 0
    for left, right in combinations(sorted(truth), 2):
        same_truth = truth[left] == truth[right]
        same_prediction = predicted.get(left) == predicted.get(right)
        if same_truth and same_prediction:
            true_positive += 1
        elif same_prediction and not same_truth:
            false_positive += 1
        elif same_truth and not same_prediction:
            false_negative += 1
    precision = true_positive / (true_positive + false_positive or 1)
    recall = true_positive / (true_positive + false_negative or 1)
    return precision, recall, true_positive, false_positive, false_negative


def test_dedup_precision_and_recall_on_two_hundred_candidates(
    session: Session, at: Instant
) -> None:
    """**Acceptance criterion.** 200 candidates, 40 duplicates, precision and recall.

    Both come out at 1.0, and they should: dedup here is an exact key, not a similarity
    threshold, so on a population where the ground truth is *defined* by that key there
    is nothing to trade off. The value of this test is not the number -- it is that the
    160 distinct findings differ along four different axes and none of them collided.

    Where the number would stop being 1.0 is a population of findings that a human would
    call the same but the key does not: the same divergence in an adjacent time bucket,
    or a segment that gained one predicate. That is a real limit, it is listed under
    "known limits" in the package docs, and it is not what this criterion measures.
    """
    candidates, truth = _population(at)
    assert len(candidates) == _DISTINCT + _DUPLICATES

    _ingest(session, candidates, at)
    precision, recall, true_positive, false_positive, false_negative = _pairwise_scores(
        truth, _grouping(session)
    )

    assert true_positive == _DUPLICATES, "each duplicate should have joined its original"
    assert precision == 1.0, f"merged {false_positive} pairs that are different findings"
    assert recall == 1.0, f"missed {false_negative} pairs that are the same finding"


def test_two_hundred_candidates_become_one_hundred_and_sixty_patterns(
    session: Session, at: Instant
) -> None:
    candidates, _ = _population(at)
    _ingest(session, candidates, at)
    assert session.scalar(select(func.count()).select_from(PatternRow)) == _DISTINCT
    assert session.scalar(select(func.count()).select_from(CandidateRow)) == len(candidates)


def test_a_duplicate_extends_its_pattern_rather_than_opening_one(
    session: Session, at: Instant
) -> None:
    """The merge rule: extend the evidence, or open a new pattern. No third case."""
    original = CandidateSpec(candidate_id="c1", created_at=at).build()
    later = CandidateSpec(
        candidate_id="c2", created_at=at + _dt.timedelta(days=1), statistic=12.0
    ).build()
    store = PatternStore(session)

    first = store.ingest_batch(
        family=_family("run_1", at, 1),
        candidates=[original],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    second = store.ingest_batch(
        family=_family("run_2", at, 1),
        candidates=[later],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at + _dt.timedelta(days=1),
    )

    assert len(first.patterns_created) == 1
    assert second.patterns_created == ()
    assert second.patterns_extended == first.patterns_created

    row = session.get(PatternRow, str(first.patterns_created[0]))
    assert row is not None
    assert row.candidate_count == 2
    assert row.last_seen == at + _dt.timedelta(days=1)


def test_ingesting_the_same_batch_twice_changes_nothing(session: Session, at: Instant) -> None:
    """Protocol law 1. Idempotence falls out of content-derived ids, not a seen-set."""
    candidates = [
        CandidateSpec(candidate_id=f"c{index}", created_at=at).build() for index in range(3)
    ]
    store = PatternStore(session)
    first = store.ingest_batch(
        family=_family("run_1", at, len(candidates)),
        candidates=candidates,
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    second = store.ingest_batch(
        family=_family("run_1", at, len(candidates)),
        candidates=candidates,
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    assert first.candidates_stored == 3
    assert second.candidates_stored == 0
    assert first.patterns_touched == second.patterns_touched
    assert session.scalar(select(func.count()).select_from(PatternRow)) == 1


def test_the_pattern_id_is_derived_from_the_signature(session: Session, at: Instant) -> None:
    """Two processes ingesting the same finding must produce the same pattern id."""
    candidate = CandidateSpec(candidate_id="c1", created_at=at).build()
    store = PatternStore(session)
    report = store.ingest_batch(
        family=_family("run_1", at, 1),
        candidates=[candidate],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    assert report.patterns_created == (pattern_id_for(signature_of(candidate).key),)


def test_a_direction_shift_opens_a_new_pattern_linked_to_its_ancestor(
    session: Session, at: Instant
) -> None:
    """A material shift opens a new pattern. The ancestry link is how it stays findable.

    Not a heuristic: the direction is part of the signature, so a reversal *is* a
    different key, and the structure key -- which ignores values and directions -- is
    what finds the thing it came from.
    """
    rising = CandidateSpec(candidate_id="c1", created_at=at, statistic=10.0, baseline=1.0).build()
    falling = CandidateSpec(
        candidate_id="c2",
        created_at=at + _dt.timedelta(days=1),
        statistic=1.0,
        baseline=10.0,
    ).build()
    store = PatternStore(session)
    first = store.ingest_batch(
        family=_family("run_1", at, 1),
        candidates=[rising],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at,
    )
    second = store.ingest_batch(
        family=_family("run_2", at, 1),
        candidates=[falling],
        holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
        at=at + _dt.timedelta(days=1),
    )
    assert first.patterns_created != second.patterns_created

    ancestry = session.scalars(select(PatternAncestryRow)).all()
    assert len(ancestry) == 1
    assert ancestry[0].pattern_id == str(second.patterns_created[0])
    assert ancestry[0].ancestor_pattern_id == str(first.patterns_created[0])
    assert ancestry[0].reason == "direction_shift"


def _family(run_id: str, at: Instant, test_count: int) -> HypothesisFamily:
    return HypothesisFamily(
        run_id=RunId(run_id),
        snapshot_id=SnapshotId("snap_2"),
        detector="segment_divergence",
        detector_version=1,
        test_count=test_count,
        declared_at=at,
    )
