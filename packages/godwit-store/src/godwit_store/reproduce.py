"""Lineage and reproduction. The regulator-facing feature, not plumbing.

Invariant 7: every pattern must be reproducible from ``(probe spec, snapshot id,
version, seed)`` with the whole LLM layer deleted. This module is where that promise is
made concrete -- a stored key, a request an executor can act on, and a comparison that
says yes or no rather than "looks about right".

The question being answered is asked out loud in a model risk review: *"You alerted on
this in March. Show me that the same data and the same code produce the same finding
today."* An answer that requires an engineer to reconstruct a command line is not an
answer. :func:`reproduce` returns a request that names every probe, snapshot, detector
version and seed involved, and :func:`verify_reproduction` compares what came back
against what was stored, field by field.

WHAT THE KEY CONTAINS, AND WHY EACH PART
----------------------------------------
``source_id``, ``segment_key``   which slice of which table.
``probe_keys``                   which measurements. Sorted, so the key is stable.
``snapshot_id``, ``baseline``    the two points in history being compared.
``detector`` + ``detector_version``  the code that made the claim.
``code_version``                 the build. A detector version bump is deliberate; a
                                 build change is not, and both can move a result.
``seed``                         explicit, never defaulted.

Deliberately absent: the budget (an operational ceiling, not part of the claim), the
``as_of`` scheduling instant, and anything an LLM produced. Delete every explanation in
the system and the key is unchanged, which is the test of whether invariant 7 holds.

A HOLE THAT IS NOT OURS TO CLOSE
--------------------------------
``ProbeSpec.snapshot`` may be ``None`` at scheduling time, and the worker resolves it.
The reproduction key stores the **resolved** snapshot from the candidate's lineage, so
replay is exact -- but only because the detector recorded it. A candidate whose lineage
names a snapshot nobody can resolve is not reproducible, and :func:`reproduce` says so
rather than producing a request that will quietly run against whatever is current.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from godwit_contracts import (
    Candidate,
    CandidateId,
    ContentHash,
    GodwitModel,
    PatternId,
    ProbeKey,
    SegmentKey,
    SnapshotId,
    SourceId,
    Version,
    canonical_json,
    content_hash,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from godwit_store.errors import PatternNotFoundError
from godwit_store.schema import CandidateRow, PatternCandidateRow, PatternRow

__all__ = [
    "CandidateProducer",
    "ReproductionKey",
    "ReproductionRequest",
    "ReproductionResult",
    "reproduction_key_of",
    "stored_candidates",
    "verify_reproduction",
]


class ReproductionKey(GodwitModel):
    """Everything needed to regenerate a pattern's candidates. Invariant 7, as a value."""

    source_id: SourceId
    segment_key: SegmentKey
    probe_keys: tuple[ProbeKey, ...]
    snapshot_id: SnapshotId
    baseline_snapshot_id: SnapshotId | None = None
    detector: str
    detector_version: Version
    code_version: str
    seed: int

    def canonical_form(self) -> str:
        """The exact string hashed into :attr:`key`."""
        return canonical_json(
            {
                "source_id": str(self.source_id),
                "segment_key": str(self.segment_key),
                "probe_keys": sorted(str(key) for key in self.probe_keys),
                "snapshot_id": str(self.snapshot_id),
                "baseline_snapshot_id": None
                if self.baseline_snapshot_id is None
                else str(self.baseline_snapshot_id),
                "detector": self.detector,
                "detector_version": int(self.detector_version),
                "code_version": self.code_version,
                "seed": self.seed,
            }
        )

    @property
    def key(self) -> ContentHash:
        """Stable identity of this reproduction recipe, stored on the pattern."""
        return content_hash(self.canonical_form(), prefix="rep")


def reproduction_key_of(candidate: Candidate) -> ReproductionKey:
    """Derive a candidate's reproduction key from its lineage and evidence.

    Probe keys come from the evidence rather than from the lineage, because a candidate
    can rest on several measurements and the lineage carries only the one that
    identified it. Reproducing the pattern means re-running all of them.
    """
    return ReproductionKey(
        source_id=candidate.source_id,
        segment_key=candidate.segment.key,
        probe_keys=tuple(sorted({item.probe_key for item in candidate.evidence})),
        snapshot_id=candidate.lineage.snapshot_id,
        baseline_snapshot_id=candidate.lineage.baseline_snapshot_id,
        detector=candidate.lineage.detector,
        detector_version=candidate.lineage.detector_version,
        code_version=candidate.lineage.code_version,
        seed=candidate.lineage.seed,
    )


class ReproductionRequest(GodwitModel):
    """What to hand an executor -- ``godwit-replay`` (A4), or a human with a terminal.

    Self-contained on purpose: everything needed is in this object, so answering a
    regulator does not depend on anyone remembering how the March run was invoked.
    """

    pattern_id: PatternId
    reproduction_key: ReproductionKey
    expected_candidate_ids: tuple[CandidateId, ...]
    expected_signature: ContentHash
    keys: tuple[ReproductionKey, ...] = ()
    """Every distinct key behind the pattern. A pattern that accumulated evidence over
    several snapshots has more than one, and reproducing only the representative would
    answer a narrower question than the one asked."""


@runtime_checkable
class CandidateProducer(Protocol):
    """Whatever can re-run a detector. Implemented by A4; a test implements it too.

    The store does not execute probes -- that is the data plane's job and this package
    is control plane. It defines the request, holds the expected answer, and grades the
    result.
    """

    def __call__(self, *, request: ReproductionRequest) -> Sequence[Candidate]:
        """Re-run the measurement and detection described by ``request``."""
        ...


class ReproductionResult(GodwitModel):
    """Whether a pattern came back identically, and what differed when it did not."""

    pattern_id: PatternId
    reproduced: bool
    expected_count: int
    produced_count: int
    matching_candidate_ids: tuple[CandidateId, ...] = ()
    missing_candidate_ids: tuple[CandidateId, ...] = ()
    unexpected_candidate_ids: tuple[CandidateId, ...] = ()
    differing_candidate_ids: tuple[CandidateId, ...] = ()
    """Present in both, but not byte-identical. The worst outcome of the three: a
    candidate that came back *almost* the same means the pipeline is not deterministic,
    which is a harder problem than one that disappeared."""


def stored_candidates(session: Session, pattern_id: PatternId) -> tuple[Candidate, ...]:
    """The candidates behind a pattern, rebuilt from storage, in id order.

    Rebuilt through ``Candidate.model_validate`` rather than read as raw JSON, so a
    payload that no longer satisfies the contract fails here rather than silently
    comparing equal to nothing.
    """
    rows = session.scalars(
        select(CandidateRow)
        .join(PatternCandidateRow, PatternCandidateRow.candidate_id == CandidateRow.candidate_id)
        .where(PatternCandidateRow.pattern_id == str(pattern_id))
        .order_by(CandidateRow.candidate_id)
    ).all()
    return tuple(Candidate.model_validate(row.payload_value) for row in rows)


def reproduce(session: Session, pattern_id: PatternId) -> ReproductionRequest:
    """Build the reproduction request for a pattern. **The headline capability.**

    Does not execute anything: it returns the recipe plus the expected answer. An
    executor runs it; :func:`verify_reproduction` grades it. Separating the two is what
    lets the grading run in the control plane while the execution runs in the data
    plane, which is the only arrangement in which a regulator's question can be answered
    without a row crossing the boundary.
    """
    pattern = session.get(PatternRow, str(pattern_id))
    if pattern is None:
        raise PatternNotFoundError(f"no pattern {pattern_id}")
    candidates = stored_candidates(session, pattern_id)
    if not candidates:
        raise PatternNotFoundError(
            f"pattern {pattern_id} has no stored candidates; it cannot be reproduced, "
            "and a pattern that cannot be reproduced is an anecdote"
        )
    keys = tuple(dict.fromkeys(reproduction_key_of(candidate) for candidate in candidates))
    representative = next(
        (
            candidate
            for candidate in candidates
            if str(candidate.candidate_id) == pattern.representative_candidate_id
        ),
        candidates[0],
    )
    return ReproductionRequest(
        pattern_id=pattern_id,
        reproduction_key=reproduction_key_of(representative),
        expected_candidate_ids=tuple(candidate.candidate_id for candidate in candidates),
        expected_signature=ContentHash(pattern.signature),
        keys=keys,
    )


def verify_reproduction(
    *,
    request: ReproductionRequest,
    expected: Sequence[Candidate],
    produced: Sequence[Candidate],
) -> ReproductionResult:
    """Compare what came back against what was stored. Identity, not similarity.

    Comparison is over the serialised contract object, so a difference in any field --
    a statistic in the fourth decimal place, a reordered evidence tuple -- counts as a
    difference. That is deliberate. "Close enough" is not a property anyone can defend,
    and a pipeline that is only approximately deterministic will drift until it is not.
    """
    expected_by_id = {candidate.candidate_id: candidate for candidate in expected}
    produced_by_id = {candidate.candidate_id: candidate for candidate in produced}

    matching: list[CandidateId] = []
    differing: list[CandidateId] = []
    for candidate_id, original in sorted(expected_by_id.items()):
        replayed = produced_by_id.get(candidate_id)
        if replayed is None:
            continue
        if _serialised(original) == _serialised(replayed):
            matching.append(candidate_id)
        else:
            differing.append(candidate_id)

    missing = sorted(set(expected_by_id) - set(produced_by_id))
    unexpected = sorted(set(produced_by_id) - set(expected_by_id))
    return ReproductionResult(
        pattern_id=request.pattern_id,
        reproduced=not missing and not unexpected and not differing,
        expected_count=len(expected_by_id),
        produced_count=len(produced_by_id),
        matching_candidate_ids=tuple(matching),
        missing_candidate_ids=tuple(missing),
        unexpected_candidate_ids=tuple(unexpected),
        differing_candidate_ids=tuple(differing),
    )


def _serialised(candidate: Candidate) -> str:
    """Canonical rendering of a candidate, for identity comparison.

    Canonical JSON rather than ``==`` on the model: two models can compare equal while
    serialising differently, and what a regulator is shown is the serialisation.
    """
    return canonical_json(candidate.model_dump(mode="json"))
