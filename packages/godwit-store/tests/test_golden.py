"""The shared golden fixtures, ingested end to end.

``tests/golden/candidates.json`` is what nineteen other agents build against. Ingesting
it here is the check that the store agrees with everyone else about what a candidate is,
including the parts that are easy to get quietly wrong: the segment key, the taint
classes, and the fact that the second candidate's population of 34 is *above* the
default small-cell threshold and is still not safe to show.

The two golden candidates come from two different detectors -- ``category_share_shift``
and ``quantile_shift`` -- so they are two runs. A test family is per detector, and
pooling them would be the exact mistake ``HypothesisFamily`` exists to prevent.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from godwit_contracts import AlertQueue, Candidate, Instant, RunId, SnapshotId
from godwit_store.fdr import HoldoutKind, HoldoutPolicy, HypothesisFamily
from godwit_store.reproduce import reproduce, stored_candidates, verify_reproduction
from godwit_store.schema import CandidateRow, PatternRow
from godwit_store.signature import signature_of, structural_rendering
from godwit_store.store import PatternStore
from sqlalchemy import select
from sqlalchemy.orm import Session


@pytest.fixture
def golden_candidates(golden_json: Callable[[str], Any]) -> tuple[Candidate, ...]:
    """The two golden candidates, validated through the contract."""
    payload = golden_json("candidates.json")
    return tuple(Candidate.model_validate(item) for item in payload["candidates"])


@pytest.fixture
def golden_leaks(golden_json: Callable[[str], Any]) -> tuple[str, ...]:
    payload = golden_json("pii_torture/expected_leaks.json")
    return tuple(payload["must_never_appear_in_any_egress"])


def _ingest_golden(
    session: Session, candidates: tuple[Candidate, ...], at: Instant
) -> PatternStore:
    store = PatternStore(session)
    for candidate in candidates:
        store.ingest_batch(
            family=HypothesisFamily(
                run_id=RunId(f"run_{candidate.lineage.detector}"),
                snapshot_id=SnapshotId("snap_2"),
                detector=candidate.lineage.detector,
                detector_version=candidate.lineage.detector_version,
                test_count=120,
                declared_at=at,
            ),
            candidates=[candidate],
            holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
            at=at,
        )
    return store


def test_the_golden_candidates_validate_and_ingest(
    session: Session, golden_candidates: tuple[Candidate, ...], at: Instant
) -> None:
    _ingest_golden(session, golden_candidates, at)
    assert session.scalars(select(CandidateRow.candidate_id)).all() == [
        "cand_golden_0001",
        "cand_golden_0002",
    ]
    assert len(session.scalars(select(PatternRow)).all()) == 2


def test_the_two_golden_findings_do_not_deduplicate_together(
    golden_candidates: tuple[Candidate, ...],
) -> None:
    """``country = PT`` and ``country = PT AND status = refund`` are different segments.

    The second is a strict refinement of the first, and a human might well call them
    one story. The store does not, because the segment keys differ -- a real limit,
    written up under "known limits", and the conservative side of the trade: showing a
    reviewer two related findings is recoverable, merging two different ones is not.
    """
    first, second = golden_candidates
    assert signature_of(first).key != signature_of(second).key


def test_the_stored_q_values_are_adjusted_not_raw(
    session: Session, golden_candidates: tuple[Candidate, ...], at: Instant
) -> None:
    """A raw p-value reported as significance is a lie by omission (protocol law 3)."""
    _ingest_golden(session, golden_candidates, at)
    rows = session.scalars(select(CandidateRow).order_by(CandidateRow.candidate_id)).all()
    for row in rows:
        assert row.p_value is not None
        assert row.q_value is not None
        assert row.q_value > row.p_value, "120 hypotheses were declared, so q must exceed p"


def test_a_population_of_thirty_four_is_still_not_safe_to_show(
    session: Session, golden_candidates: tuple[Candidate, ...], at: Instant
) -> None:
    """The point of the second golden candidate, and it is worth restating.

    Thirty-four is above the default small-cell threshold of twenty, so suppression by
    population alone would let it through. What makes it unsafe is that its predicates
    quote ``PT`` and ``refund`` -- real column values. The store keeps the whole segment
    in a tainted payload for exactly that reason.
    """
    _, refined = golden_candidates
    assert refined.segment.population == 34
    _ingest_golden(session, golden_candidates, at)
    row = session.get(CandidateRow, "cand_golden_0002")
    assert row is not None
    assert row.payload_sensitivity == "data_value"
    assert row.population == 34


def test_no_safe_view_exposes_a_golden_segment_value(
    session: Session, golden_candidates: tuple[Candidate, ...], at: Instant
) -> None:
    """The safe views are the "make the safe query the easy one" claim, checked.

    Rendering every row of ``candidates_safe`` and ``patterns_safe`` to text must not
    produce ``PT`` or ``refund`` as a *value*. Searched as a quoted JSON string rather
    than as a bare substring, because ``PT`` occurs inside plenty of hashes by chance
    and a test that fails at random is worse than no test.
    """
    _ingest_golden(session, golden_candidates, at)
    for view in ("candidates_safe", "patterns_safe"):
        rows = session.execute(select("*").select_from(_text_table(view))).all()
        rendered = "\n".join(str(row) for row in rows)
        assert "'PT'" not in rendered
        assert "'refund'" not in rendered


def test_the_golden_rendering_leaks_nothing_from_the_torture_list(
    golden_candidates: tuple[Candidate, ...], golden_leaks: tuple[str, ...]
) -> None:
    """Cross-checking one fixture against another. A backstop, and labelled as one."""
    for candidate in golden_candidates:
        rendering = structural_rendering(candidate)
        assert not [leak for leak in golden_leaks if leak in rendering]


def test_a_golden_pattern_reproduces_from_its_key(
    session: Session, golden_candidates: tuple[Candidate, ...], at: Instant
) -> None:
    store = _ingest_golden(session, golden_candidates, at)
    pattern_id = store.queue(queue=AlertQueue.DISCOVERY, at=at, include_ineligible=True)[
        0
    ].pattern_id
    request = reproduce(session, pattern_id)
    expected = stored_candidates(session, pattern_id)
    result = verify_reproduction(request=request, expected=expected, produced=expected)
    assert result.reproduced


def _text_table(name: str) -> Any:
    from sqlalchemy import table

    return table(name)
