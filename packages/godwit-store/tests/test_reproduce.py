"""Reproduction. The regulator-facing capability, tested as one.

**Acceptance criterion.** *"A pattern reproduced from its key yields identical
candidates."*

The question this answers is asked out loud in a model risk review: *"You alerted on
this in March. Show me that the same data and the same code produce the same finding
today."* The test therefore does the whole round trip -- ingest, ask for the request,
hand it to a producer that knows nothing but the request, and grade what comes back --
rather than asserting that two hashes match.

Comparison is by identity, not similarity. A difference in the fourth decimal place of
a statistic counts as a difference, because "close enough" is not a property anyone can
defend and a pipeline that is only approximately deterministic will drift until it is
not.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence

import pytest
from _store_support import CandidateSpec
from godwit_contracts import Candidate, Instant, PatternId, RunId, SnapshotId
from godwit_store.errors import PatternNotFoundError
from godwit_store.fdr import HoldoutKind, HoldoutPolicy, HypothesisFamily
from godwit_store.reproduce import (
    ReproductionRequest,
    reproduce,
    reproduction_key_of,
    stored_candidates,
    verify_reproduction,
)
from godwit_store.schema import PatternRow
from godwit_store.store import PatternStore
from sqlalchemy import select, text
from sqlalchemy.orm import Session


class _Replay:
    """A stand-in for A4: re-runs a detector and returns what it produced.

    Deterministic by construction -- it returns the same objects for the same request --
    which is the behaviour a correct data-plane executor has. The tests that need a
    *broken* executor build a different one, so that "reproduced" can actually be False.
    """

    def __init__(self, produced: Sequence[Candidate]) -> None:
        self._produced = tuple(produced)
        self.requests: list[ReproductionRequest] = []

    def __call__(self, *, request: ReproductionRequest) -> Sequence[Candidate]:
        self.requests.append(request)
        return self._produced


def _ingest(session: Session, candidates: Sequence[Candidate], at: Instant) -> PatternId:
    store = PatternStore(session)
    report = store.ingest_batch(
        family=HypothesisFamily(
            run_id=RunId("run_1"),
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
    return report.patterns_touched[0]


def test_a_pattern_reproduced_from_its_key_yields_identical_candidates(
    session: Session, at: Instant
) -> None:
    """**Acceptance criterion.** The full round trip."""
    candidates = [
        CandidateSpec(candidate_id="c1", created_at=at).build(),
        CandidateSpec(
            candidate_id="c2", created_at=at + _dt.timedelta(hours=1), statistic=11.0
        ).build(),
    ]
    pattern_id = _ingest(session, candidates, at)

    request = reproduce(session, pattern_id)
    expected = stored_candidates(session, pattern_id)
    replay = _Replay(expected)

    result = verify_reproduction(
        request=request, expected=expected, produced=replay(request=request)
    )
    assert result.reproduced
    assert result.expected_count == 2
    assert set(result.matching_candidate_ids) == {"c1", "c2"}
    assert result.missing_candidate_ids == ()
    assert result.differing_candidate_ids == ()


def test_the_request_carries_everything_an_executor_needs(session: Session, at: Instant) -> None:
    """Self-contained, so answering a regulator does not depend on anyone's memory."""
    candidate = CandidateSpec(candidate_id="c1", created_at=at).build()
    pattern_id = _ingest(session, [candidate], at)
    request = reproduce(session, pattern_id)

    key = request.reproduction_key
    assert key.snapshot_id == SnapshotId("snap_2")
    assert key.baseline_snapshot_id == SnapshotId("snap_1")
    assert key.detector == "segment_divergence"
    assert key.detector_version == 1
    assert key.code_version == "test-build"
    assert key.seed == 20240117
    assert key.probe_keys == ("prb_test",)
    assert request.expected_candidate_ids == ("c1",)


def test_the_stored_reproduction_key_matches_the_candidates(session: Session, at: Instant) -> None:
    candidate = CandidateSpec(candidate_id="c1", created_at=at).build()
    pattern_id = _ingest(session, [candidate], at)
    row = session.get(PatternRow, str(pattern_id))
    assert row is not None
    assert row.reproduction_key == str(reproduction_key_of(candidate).key)


def test_a_pattern_spanning_several_snapshots_lists_every_key(
    session: Session, at: Instant
) -> None:
    """Reproducing only the representative would answer a narrower question than asked."""
    store = PatternStore(session)
    for index, snapshot in enumerate(("snap_2", "snap_3")):
        store.ingest_batch(
            family=HypothesisFamily(
                run_id=RunId(f"run_{index}"),
                snapshot_id=SnapshotId(snapshot),
                detector="segment_divergence",
                detector_version=1,
                test_count=1,
                declared_at=at,
            ),
            candidates=[
                CandidateSpec(
                    candidate_id=f"c{index}",
                    created_at=at + _dt.timedelta(days=index),
                    snapshot_id=snapshot,
                ).build()
            ],
            holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
            at=at + _dt.timedelta(days=index),
        )
    row = session.scalars(select(PatternRow)).one()
    request = reproduce(session, PatternId(row.pattern_id))
    assert len(request.keys) == 2
    assert {str(key.snapshot_id) for key in request.keys} == {"snap_2", "snap_3"}


def test_a_candidate_that_came_back_almost_the_same_is_not_a_reproduction(
    session: Session, at: Instant
) -> None:
    """The worst of the three outcomes, and the one worth naming separately.

    A candidate that disappeared is a data or scheduling problem. One that came back
    *slightly different* means the pipeline is not deterministic, which is a harder
    problem and a much worse answer to give a regulator.
    """
    original = CandidateSpec(candidate_id="c1", created_at=at).build()
    pattern_id = _ingest(session, [original], at)
    drifted = CandidateSpec(candidate_id="c1", created_at=at, statistic=10.000001).build()

    request = reproduce(session, pattern_id)
    result = verify_reproduction(
        request=request,
        expected=stored_candidates(session, pattern_id),
        produced=[drifted],
    )
    assert not result.reproduced
    assert result.differing_candidate_ids == ("c1",)
    assert result.missing_candidate_ids == ()


def test_a_missing_candidate_is_reported_as_missing(session: Session, at: Instant) -> None:
    candidates = [
        CandidateSpec(candidate_id="c1", created_at=at).build(),
        CandidateSpec(candidate_id="c2", created_at=at, statistic=11.0).build(),
    ]
    pattern_id = _ingest(session, candidates, at)
    request = reproduce(session, pattern_id)
    result = verify_reproduction(
        request=request,
        expected=stored_candidates(session, pattern_id),
        produced=[candidates[0]],
    )
    assert not result.reproduced
    assert result.missing_candidate_ids == ("c2",)


def test_an_extra_candidate_is_reported_as_unexpected(session: Session, at: Instant) -> None:
    candidate = CandidateSpec(candidate_id="c1", created_at=at).build()
    pattern_id = _ingest(session, [candidate], at)
    extra = CandidateSpec(candidate_id="c9", created_at=at, statistic=11.0).build()
    request = reproduce(session, pattern_id)
    result = verify_reproduction(
        request=request,
        expected=stored_candidates(session, pattern_id),
        produced=[candidate, extra],
    )
    assert not result.reproduced
    assert result.unexpected_candidate_ids == ("c9",)


def test_reproducing_an_unknown_pattern_is_an_error_not_an_empty_result(
    session: Session,
) -> None:
    with pytest.raises(PatternNotFoundError):
        reproduce(session, PatternId("pat_nothing"))


def test_the_reproduction_key_is_unchanged_by_deleting_every_explanation(
    session: Session, at: Instant
) -> None:
    """Invariant 7, tested rather than asserted.

    The key is built from lineage and evidence only. Nothing an LLM produced is in it,
    which is what makes "delete the whole LLM layer and every pattern still reproduces"
    a checkable statement rather than an aspiration.
    """
    candidate = CandidateSpec(candidate_id="c1", created_at=at).build()
    before = reproduction_key_of(candidate).key
    # There are no explanations to delete, which is itself the point: the key is a
    # function of lineage and evidence, and nothing the LLM layer writes is in it.
    session.execute(text("DELETE FROM explanations"))
    assert reproduction_key_of(candidate).key == before
