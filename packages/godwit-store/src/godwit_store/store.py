"""The pattern store: ingest, dedup, merge, false-discovery control, queues.

THE FAILURE THIS PREVENTS
-------------------------
A system testing thousands of hypotheses an hour produces findings that are
statistically significant and meaningless, and reports the same finding for ever. Alert
fatigue kills this product faster than poor accuracy does. Everything in this module is
one of the three answers to that: deduplicate, control the error rate, and let a human
say "stop showing me this" in a way that sticks and can be undone.

INGEST, IN ORDER
----------------
1. **Validate the run.** A detector run declares its test family and its holdout before
   its candidates are looked at. A run that cannot say how many hypotheses it examined
   is refused (:class:`~godwit_store.errors.UnboundedHypothesisFamilyError`), because
   absorbing it would understate every q-value in the batch.
2. **Adjust.** Benjamini-Hochberg over the declared family, storing raw ``p`` and
   adjusted ``q`` side by side. Both, always: the raw value is what the detector
   claimed and the adjusted one is what it means.
3. **Reconcile the holdout.** A candidate that did not reproduce on the reserved slice
   is ``UNVALIDATED`` and never reaches the operational queue, whatever its q says.
4. **Deduplicate.** By signature -- source, normalised segment key, column set, detector
   family, effect direction. An arriving candidate either extends a pattern's evidence
   or opens a new one; there is no third case.
5. **Suppress.** If a human dismissed this signature and has not lifted it, the
   candidate is stored and the pattern is not reopened.
6. **Age.** Every open pattern of the source that this run did not support has its
   unsupported-window count incremented. Three windows and it expires, automatically.

Every step is deterministic. Candidates are processed in ``candidate_id`` order, ids are
content-derived, and nothing reads a clock: ``at`` is injected into every entry point.
Ingesting the same batch twice touches the same patterns and creates nothing new
(protocol law 1).

WHAT THIS MODULE IS NOT
-----------------------
It is not an egress boundary. It holds tainted payloads and hands them back as contract
objects, which is what protocol law 5 means by "reads that cross to a UI or an alert
must go through the gate first". Nothing here renders a value for a human, and nothing
here should learn to.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from godwit_contracts import (
    AlertQueue,
    AuditEvent,
    Candidate,
    CandidateId,
    ContentHash,
    Feedback,
    GodwitModel,
    Instant,
    NonNegInt,
    Pattern,
    PatternId,
    PatternLifecycle,
    Plane,
    Segment,
    Sensitivity,
    SnapshotId,
    SourceId,
    Verdict,
    canonical_json,
    content_hash,
)
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from godwit_store.errors import PatternNotFoundError, StoreIntegrityError
from godwit_store.fdr import (
    HoldoutKind,
    HoldoutPolicy,
    HypothesisFamily,
    ValidationStatus,
    benjamini_hochberg,
    reconcile_holdout,
)
from godwit_store.ledger import append_audit
from godwit_store.lifecycle import (
    DEFAULT_STALE_WINDOWS,
    TransitionEvidence,
    lifecycle_for_verdict,
    transition,
)
from godwit_store.ranking import (
    DEFAULT_WEIGHTS,
    RankedPattern,
    RankingInputs,
    RankingWeights,
    rank,
)
from godwit_store.reproduce import reproduction_key_of
from godwit_store.schema import (
    CandidateRow,
    DetectorRunRow,
    FeedbackRow,
    PatternAncestryRow,
    PatternCandidateRow,
    PatternRow,
    SuppressionRow,
)
from godwit_store.signature import (
    CandidateSignature,
    embed_candidate,
    signature_of,
    structure_key,
)

__all__ = [
    "IngestReport",
    "PatternStore",
    "pattern_id_for",
]

_OPEN_STATES: Final[tuple[str, ...]] = (
    PatternLifecycle.PROPOSED.value,
    PatternLifecycle.CONFIRMED.value,
    PatternLifecycle.EXPLAINED_AWAY.value,
)

_SEGMENT_ACQUISITION: Final[str] = "segment_predicate"


def pattern_id_for(signature: ContentHash) -> PatternId:
    """The pattern id a signature maps to. Derived, never minted.

    Content-derived rather than a UUID so that ingesting the same finding twice, in two
    processes, at two times, produces one pattern with one id -- the idempotence
    protocol law 1 asks for, without a "have I seen this" check that can race.
    """
    return PatternId(str(content_hash(str(signature), prefix="pat")))


class IngestReport(GodwitModel):
    """What one ingest actually did. Returned so a caller can assert on it.

    Counts rather than ids for the bulk numbers, ids for the things a caller acts on.
    ``suppressed`` and ``unvalidated`` are separate from ``rejected_by_fdr`` on purpose:
    three different reasons a finding did not become an alert, and collapsing them would
    make "why is my queue empty" unanswerable.
    """

    run_id: str
    candidates_seen: NonNegInt
    candidates_stored: NonNegInt
    patterns_created: tuple[PatternId, ...] = ()
    patterns_extended: tuple[PatternId, ...] = ()
    patterns_reopened: tuple[PatternId, ...] = ()
    suppressed: NonNegInt = 0
    unvalidated: NonNegInt = 0
    rejected_by_fdr: NonNegInt = 0
    aged: NonNegInt = 0

    @property
    def patterns_touched(self) -> tuple[PatternId, ...]:
        """Created and extended, in id order. What ``ingest`` returns."""
        return tuple(sorted(set(self.patterns_created) | set(self.patterns_extended)))


class PatternStore:
    """Persistence, dedup, FDR control and lifecycle for patterns. L5.

    Implements ``godwit_contracts.protocols.PatternStore``. The protocol's four methods
    are the narrow interface; ``ingest_batch`` is the wide one, and the narrow ``ingest``
    is a safe-defaulting wrapper over it -- see that method's docstring for what "safe
    default" costs.
    """

    __slots__ = ("_actor", "_session", "_stale_windows", "_weights")

    def __init__(
        self,
        session: Session,
        *,
        actor: str = "godwit-store",
        weights: RankingWeights = DEFAULT_WEIGHTS,
        stale_windows: int = DEFAULT_STALE_WINDOWS,
    ) -> None:
        self._session = session
        self._actor = actor
        self._weights = weights
        self._stale_windows = stale_windows

    # -- protocol surface -----------------------------------------------------------

    def ingest(self, candidates: Sequence[Candidate]) -> tuple[PatternId, ...]:
        """Deduplicate, group and persist. Returns the patterns touched.

        The protocol signature carries no run metadata, so this wrapper supplies the
        **safest** defaults rather than the most convenient ones:

        * ``test_count`` is the number of candidates supplied, which is correct only if
          the detector emitted one per hypothesis. It is the least conservative honest
          choice available with no other information.
        * The holdout is ``NONE``, so every candidate is ``NOT_TESTED`` and **none of
          them reaches the operational queue**.

        That second point is the cost, and it is deliberate. A store that let an
        unvalidated finding into a 50-a-day alert queue because the caller used the
        short signature would be optimising for the wrong thing. Use
        :meth:`ingest_batch` for anything that is meant to page a human.
        """
        if not candidates:
            return ()
        first = candidates[0]
        family = HypothesisFamily(
            run_id=first.lineage.snapshot_id + ":" + first.lineage.detector,  # type: ignore[arg-type]
            snapshot_id=first.lineage.snapshot_id,
            detector=first.lineage.detector,
            detector_version=first.lineage.detector_version,
            test_count=len(candidates),
            declared_at=first.created_at,
        )
        report = self.ingest_batch(
            family=family,
            candidates=candidates,
            holdout=HoldoutPolicy(kind=HoldoutKind.NONE),
            at=first.created_at,
        )
        return report.patterns_touched

    def get(self, pattern_id: PatternId) -> Pattern | None:
        """One pattern, rebuilt as a contract object, or None."""
        row = self._session.get(PatternRow, str(pattern_id))
        if row is None:
            return None
        return self._rebuild_pattern(row)

    def list_open(self, *, snapshot_id: SnapshotId, limit: int) -> tuple[Pattern, ...]:
        """Open patterns last supported by a snapshot, ranked. Deterministic ordering.

        Ordered by q-value ascending then pattern id, so two calls return the same list
        in the same order. Ranking for a *queue* is :meth:`queue`; this is the raw
        listing the orchestrator reads.
        """
        rows = self._session.scalars(
            select(PatternRow)
            .where(PatternRow.last_snapshot_id == str(snapshot_id))
            .where(PatternRow.lifecycle.in_(_OPEN_STATES))
            .order_by(PatternRow.q_value.nulls_last(), PatternRow.pattern_id)
            .limit(limit)
        ).all()
        return tuple(self._rebuild_pattern(row) for row in rows)

    def record_feedback(self, feedback: Feedback) -> Pattern:
        """Apply a human verdict and return the updated pattern.

        A rejection also creates a **suppression** on the pattern's signature, so the
        same finding stops arriving next week rather than being re-created by the next
        snapshot's candidate. That is the difference between rejecting an alert and
        dismissing a finding, and it is reversible with :meth:`unsuppress`.
        """
        row = self._session.get(PatternRow, str(feedback.pattern_id))
        if row is None:
            raise PatternNotFoundError(f"no pattern {feedback.pattern_id}")

        feedback_id = _feedback_id(feedback)
        if self._session.get(FeedbackRow, feedback_id) is None:
            self._session.add(
                FeedbackRow(
                    feedback_id=feedback_id,
                    pattern_id=str(feedback.pattern_id),
                    verdict=feedback.verdict.value,
                    reviewer_id=feedback.reviewer_id,
                    confidence=feedback.confidence,
                    decided_at=feedback.decided_at,
                    payload_value=feedback.model_dump(mode="json"),
                    payload_sensitivity=Sensitivity.DATA_VALUE.value,
                    payload_acquisition="user_supplied",
                    payload_population=None,
                )
            )
        if feedback.verdict is Verdict.CONFIRMED:
            row.confirmations += 1
        elif feedback.verdict is Verdict.REJECTED:
            row.rejections += 1

        target = lifecycle_for_verdict(feedback.verdict)
        if target is not None and target is not PatternLifecycle(row.lifecycle):
            transition(
                self._session,
                pattern_id=feedback.pattern_id,
                to_state=target,
                evidence=TransitionEvidence(
                    feedback_id=feedback_id,
                    context_ref=feedback_id if target is PatternLifecycle.EXPLAINED_AWAY else None,
                    duplicate_of=(
                        PatternId(row.pattern_id) if target is PatternLifecycle.DUPLICATE else None
                    ),
                    reason=f"verdict:{feedback.verdict.value}",
                ),
                actor=feedback.reviewer_id,
                at=feedback.decided_at,
                action=f"feedback:{feedback.verdict.value}",
            )
        if feedback.verdict is Verdict.REJECTED:
            self.suppress(
                signature=ContentHash(row.signature),
                pattern_id=PatternId(row.pattern_id),
                reason=f"dismissed by {feedback.reviewer_id}",
                actor=feedback.reviewer_id,
                at=feedback.decided_at,
            )
        self._session.flush()
        return self._rebuild_pattern(row)

    # -- the wide ingest -------------------------------------------------------------

    def ingest_batch(
        self,
        *,
        family: HypothesisFamily,
        candidates: Sequence[Candidate],
        holdout: HoldoutPolicy,
        at: Instant,
        holdout_candidates: Sequence[Candidate] = (),
        source_id: SourceId | None = None,
    ) -> IngestReport:
        """Ingest one detector run, with its declared test family and holdout.

        ``holdout_candidates`` are what the *same detector at the same version* produced
        when re-run on the reserved slice. They are matched by signature, not by score:
        reproducing a finding weakly is still reproducing it, and demanding a similar
        effect size would be re-testing on the holdout, which is the thing a holdout
        exists to prevent.
        """
        ordered = sorted(candidates, key=lambda candidate: str(candidate.candidate_id))
        self._check_run(family=family, candidates=ordered)
        resolved_source = source_id or (ordered[0].source_id if ordered else SourceId(""))
        self._record_run(
            family=family,
            holdout=holdout,
            candidates=ordered,
            source_id=resolved_source,
        )

        adjusted = self._adjust(family=family, candidates=ordered)
        validation = reconcile_holdout(
            generated=[signature_of(candidate).key for candidate in ordered],
            reproduced=[signature_of(candidate).key for candidate in holdout_candidates],
            policy=holdout,
        )

        report_created: list[PatternId] = []
        report_extended: list[PatternId] = []
        report_reopened: list[PatternId] = []
        stored = 0
        suppressed_count = 0
        unvalidated_count = 0
        rejected_count = 0
        touched_patterns: set[str] = set()

        for candidate in ordered:
            signature = signature_of(candidate)
            status = validation.get(signature.key, ValidationStatus.NOT_TESTED)
            p_value, q_value, rejected = adjusted.get(
                str(candidate.candidate_id), (None, None, None)
            )
            if status is ValidationStatus.UNVALIDATED:
                unvalidated_count += 1
            if rejected is False:
                rejected_count += 1

            if self._store_candidate(
                candidate=candidate,
                signature=signature,
                family=family,
                status=status,
                p_value=p_value,
                q_value=q_value,
                rejected=rejected,
                at=at,
            ):
                stored += 1

            if self._is_suppressed(signature.key):
                suppressed_count += 1
                continue

            pattern_id = pattern_id_for(signature.key)
            existing = self._session.get(PatternRow, str(pattern_id))
            if existing is None:
                self._create_pattern(
                    pattern_id=pattern_id,
                    candidate=candidate,
                    signature=signature,
                    status=status,
                    q_value=q_value,
                    at=at,
                )
                report_created.append(pattern_id)
            else:
                if self._extend_pattern(
                    row=existing,
                    candidate=candidate,
                    status=status,
                    q_value=q_value,
                    at=at,
                ):
                    report_reopened.append(pattern_id)
                report_extended.append(pattern_id)
            touched_patterns.add(str(pattern_id))
            self._link_candidate(pattern_id=pattern_id, candidate=candidate, at=at)

        aged = self._age_untouched(source_id=resolved_source, touched=touched_patterns)
        self._session.flush()
        return IngestReport(
            run_id=str(family.run_id),
            candidates_seen=len(ordered),
            candidates_stored=stored,
            patterns_created=tuple(sorted(set(report_created))),
            patterns_extended=tuple(sorted(set(report_extended))),
            patterns_reopened=tuple(sorted(set(report_reopened))),
            suppressed=suppressed_count,
            unvalidated=unvalidated_count,
            rejected_by_fdr=rejected_count,
            aged=aged,
        )

    # -- suppression -----------------------------------------------------------------

    def suppress(
        self,
        *,
        signature: ContentHash,
        reason: str,
        actor: str,
        at: Instant,
        pattern_id: PatternId | None = None,
    ) -> str:
        """Stop a signature from reopening a pattern. Recorded and reversible.

        Suppression is by **signature**, not by pattern id. Dismissing a finding should
        silence the instance of it that next week's snapshot produces, and those are
        different patterns only in the sense that they arrived on different days.
        """
        active = self._active_suppression(signature)
        if active is not None:
            return active.suppression_id
        suppression_id = str(
            content_hash(
                canonical_json({"signature": str(signature), "at": at.isoformat()}),
                prefix="sup",
            )
        )
        self._session.add(
            SuppressionRow(
                suppression_id=suppression_id,
                signature=str(signature),
                pattern_id=None if pattern_id is None else str(pattern_id),
                reason=reason,
                actor=actor,
                created_at=at,
                lifted_at=None,
                lifted_by=None,
            )
        )
        self._audit(
            action="suppress",
            subject_kind="signature",
            subject_id=str(signature),
            actor=actor,
            at=at,
            detail={"reason": reason},
        )
        self._session.flush()
        return suppression_id

    def unsuppress(self, *, signature: ContentHash, actor: str, at: Instant) -> bool:
        """Lift a suppression. Returns False when there was nothing to lift.

        The row is updated rather than deleted, so "who silenced this, when, and who
        turned it back on" stays answerable. The audit ledger records both ends.
        """
        active = self._active_suppression(signature)
        if active is None:
            return False
        active.lifted_at = at
        active.lifted_by = actor
        self._audit(
            action="unsuppress",
            subject_kind="signature",
            subject_id=str(signature),
            actor=actor,
            at=at,
            detail={"suppression_id": active.suppression_id},
        )
        self._session.flush()
        return True

    # -- queues -----------------------------------------------------------------------

    def queue(
        self,
        *,
        queue: AlertQueue,
        at: Instant,
        source_id: SourceId | None = None,
        capacity: int | None = None,
        include_ineligible: bool = False,
    ) -> tuple[RankedPattern, ...]:
        """Rank the open population for one queue. Pure ranking, no LLM input.

        The ranking itself is in :mod:`godwit_store.ranking` and takes no session: this
        method's only job is to assemble the inputs, which is what makes the ranking
        testable without a database and auditable without a debugger.
        """
        statement = select(PatternRow).where(PatternRow.lifecycle.in_(_OPEN_STATES))
        if source_id is not None:
            statement = statement.where(PatternRow.source_id == str(source_id))
        rows = self._session.scalars(statement.order_by(PatternRow.pattern_id)).all()
        group_stats = self._group_stats()
        suppressed = self._suppressed_signatures()

        inputs = [
            RankingInputs(
                pattern_id=PatternId(row.pattern_id),
                structure_key=row.structure_key,
                lifecycle=PatternLifecycle(row.lifecycle),
                validation_status=ValidationStatus(row.validation_status),
                explained_away=row.explained_away,
                suppressed=row.signature in suppressed,
                q_value=row.q_value,
                detector_score=row.score,
                population=row.population,
                first_seen=row.first_seen,
                last_seen=row.last_seen,
                as_of=at,
                group_confirmations=group_stats.get(row.structure_key, (0, 0, 1))[0],
                group_rejections=group_stats.get(row.structure_key, (0, 0, 1))[1],
                group_size=group_stats.get(row.structure_key, (0, 0, 1))[2],
            )
            for row in rows
        ]
        return rank(
            inputs,
            queue=queue,
            weights=self._weights,
            capacity=capacity,
            include_ineligible=include_ineligible,
        )

    # -- internals ---------------------------------------------------------------------

    def _check_run(self, *, family: HypothesisFamily, candidates: Sequence[Candidate]) -> None:
        if family.test_count < len(candidates):
            raise StoreIntegrityError(
                f"run {family.run_id} declared {family.test_count} tests but emitted "
                f"{len(candidates)} candidates; a detector must report every hypothesis "
                "it examined, not only the ones that survived its own filter"
            )
        for candidate in candidates:
            if candidate.lineage.snapshot_id != family.snapshot_id:
                raise StoreIntegrityError(
                    f"candidate {candidate.candidate_id} is from snapshot "
                    f"{candidate.lineage.snapshot_id} but the run declared "
                    f"{family.snapshot_id}; one run is one snapshot"
                )
            if candidate.lineage.detector != family.detector:
                raise StoreIntegrityError(
                    f"candidate {candidate.candidate_id} names detector "
                    f"{candidate.lineage.detector!r}, the run declared "
                    f"{family.detector!r}; a test family is per detector"
                )

    def _record_run(
        self,
        *,
        family: HypothesisFamily,
        holdout: HoldoutPolicy,
        candidates: Sequence[Candidate],
        source_id: SourceId,
    ) -> None:
        if self._session.get(DetectorRunRow, str(family.run_id)) is not None:
            return
        lineage = candidates[0].lineage if candidates else None
        self._session.add(
            DetectorRunRow(
                run_id=str(family.run_id),
                snapshot_id=str(family.snapshot_id),
                source_id=str(source_id),
                detector=family.detector,
                detector_version=int(family.detector_version),
                code_version="" if lineage is None else lineage.code_version,
                seed=0 if lineage is None else lineage.seed,
                family_key=str(family.key),
                test_count=family.test_count,
                emitted_count=len(candidates),
                q_target=family.q_target,
                holdout_kind=holdout.kind.value,
                holdout_key=str(holdout.key),
                holdout_spec=holdout.model_dump(mode="json"),
                declared_at=family.declared_at,
            )
        )
        self._session.flush()

    def _adjust(
        self, *, family: HypothesisFamily, candidates: Sequence[Candidate]
    ) -> Mapping[str, tuple[float | None, float | None, bool | None]]:
        """Run BH over the candidates that carry a p-value.

        A candidate with no p-value is not silently given one. It is stored with
        ``p_value`` and ``q_value`` null, which makes its ranking strength the floor:
        an unadjusted finding sorts below every adjusted one rather than above them.
        """
        indexed = [
            (str(candidate.candidate_id), _candidate_p_value(candidate)) for candidate in candidates
        ]
        testable = [(cid, p) for cid, p in indexed if p is not None]
        results: dict[str, tuple[float | None, float | None, bool | None]] = {
            cid: (None, None, None) for cid, p in indexed if p is None
        }
        if not testable:
            return results
        adjusted = benjamini_hochberg(
            [p for _, p in testable],
            q_target=family.q_target,
            test_count=family.test_count,
        )
        for (cid, raw_p), test in zip(testable, adjusted, strict=True):
            results[cid] = (raw_p, test.q_value, test.rejected)
        return results

    def _store_candidate(
        self,
        *,
        candidate: Candidate,
        signature: CandidateSignature,
        family: HypothesisFamily,
        status: ValidationStatus,
        p_value: float | None,
        q_value: float | None,
        rejected: bool | None,
        at: Instant,
    ) -> bool:
        if self._session.get(CandidateRow, str(candidate.candidate_id)) is not None:
            return False
        evidence = candidate.evidence[0]
        self._session.add(
            CandidateRow(
                candidate_id=str(candidate.candidate_id),
                run_id=str(family.run_id),
                source_id=str(candidate.source_id),
                snapshot_id=str(candidate.lineage.snapshot_id),
                baseline_snapshot_id=None
                if candidate.lineage.baseline_snapshot_id is None
                else str(candidate.lineage.baseline_snapshot_id),
                segment_key=str(candidate.segment.key),
                signature=str(signature.key),
                structure_key=str(structure_key(candidate)),
                family=",".join(signature.family),
                direction=signature.direction.value,
                score=candidate.score,
                p_value=p_value,
                q_value=q_value,
                fdr_rejected=rejected,
                validation_status=status.value,
                population=candidate.segment.population,
                detector=candidate.lineage.detector,
                detector_version=int(candidate.lineage.detector_version),
                code_version=candidate.lineage.code_version,
                seed=candidate.lineage.seed,
                probe_key=str(evidence.probe_key),
                created_at=candidate.created_at,
                ingested_at=at,
                payload_value=candidate.model_dump(mode="json"),
                payload_sensitivity=Sensitivity.DATA_VALUE.value,
                payload_acquisition=_SEGMENT_ACQUISITION,
                payload_population=candidate.segment.population,
            )
        )
        return True

    def _create_pattern(
        self,
        *,
        pattern_id: PatternId,
        candidate: Candidate,
        signature: CandidateSignature,
        status: ValidationStatus,
        q_value: float | None,
        at: Instant,
    ) -> None:
        shape = str(structure_key(candidate))
        self._session.add(
            PatternRow(
                pattern_id=str(pattern_id),
                signature=str(signature.key),
                structure_key=shape,
                source_id=str(candidate.source_id),
                segment_key=str(candidate.segment.key),
                family=",".join(signature.family),
                direction=signature.direction.value,
                lifecycle=PatternLifecycle.PROPOSED.value,
                first_seen=candidate.created_at,
                last_seen=candidate.created_at,
                last_snapshot_id=str(candidate.lineage.snapshot_id),
                windows_without_support=0,
                score=candidate.score,
                q_value=q_value,
                population=candidate.segment.population,
                candidate_count=1,
                validation_status=status.value,
                explained_away=False,
                confirmations=0,
                rejections=0,
                representative_candidate_id=str(candidate.candidate_id),
                reproduction_key=str(reproduction_key_of(candidate).key),
                dedup_group=shape,
                embedding=embed_candidate(candidate),
                embedding_sensitivity=Sensitivity.SCHEMA_NAME.value,
                payload_value=candidate.segment.model_dump(mode="json"),
                payload_sensitivity=Sensitivity.DATA_VALUE.value,
                payload_acquisition=_SEGMENT_ACQUISITION,
                payload_population=candidate.segment.population,
            )
        )
        self._session.flush()
        self._link_ancestor(pattern_id=pattern_id, candidate=candidate, shape=shape, at=at)
        self._audit(
            action="pattern_created",
            subject_kind="pattern",
            subject_id=str(pattern_id),
            actor=self._actor,
            at=at,
            detail={"signature": str(signature.key), "structure_key": shape},
            to_state=PatternLifecycle.PROPOSED.value,
        )

    def _link_ancestor(
        self, *, pattern_id: PatternId, candidate: Candidate, shape: str, at: Instant
    ) -> None:
        """Link a new pattern to the most recent one of the same shape.

        This is what "a material shift in direction or segment opens a new pattern
        linked to its ancestor" means in practice. The shift is not detected by a
        heuristic: a different direction or a different segment produces a different
        *signature*, which is why a new pattern exists at all, while the *structure key*
        is unchanged, which is how the ancestor is found.
        """
        ancestor = self._session.scalars(
            select(PatternRow)
            .where(PatternRow.structure_key == shape)
            .where(PatternRow.source_id == str(candidate.source_id))
            .where(PatternRow.pattern_id != str(pattern_id))
            .order_by(PatternRow.last_seen.desc(), PatternRow.pattern_id)
            .limit(1)
        ).first()
        if ancestor is None:
            return
        reason = "family_shift"
        if ancestor.segment_key != str(candidate.segment.key):
            reason = "segment_shift"
        elif ancestor.direction != signature_of(candidate).direction.value:
            reason = "direction_shift"
        self._session.add(
            PatternAncestryRow(
                pattern_id=str(pattern_id),
                ancestor_pattern_id=ancestor.pattern_id,
                reason=reason,
                linked_at=at,
            )
        )

    def _extend_pattern(
        self,
        *,
        row: PatternRow,
        candidate: Candidate,
        status: ValidationStatus,
        q_value: float | None,
        at: Instant,
    ) -> bool:
        """Fold a new candidate into an existing pattern. Returns True if it reopened it.

        The pattern keeps its **strongest** q-value and its **latest** last-seen. Taking
        the strongest rather than the newest is the right side of the trade: a pattern
        that was overwhelmingly significant in March and marginal in April is still a
        real finding, and a store that overwrote the evidence would lose the reason it
        was ever raised.
        """
        reopened = False
        if PatternLifecycle(row.lifecycle) is PatternLifecycle.EXPIRED:
            transition(
                self._session,
                pattern_id=PatternId(row.pattern_id),
                to_state=PatternLifecycle.PROPOSED,
                evidence=TransitionEvidence(
                    candidate_id=str(candidate.candidate_id),
                    reason="a supporting candidate arrived",
                ),
                actor=self._actor,
                at=at,
                action="reopen",
            )
            reopened = True
        row.candidate_count += 1
        row.windows_without_support = 0
        if candidate.created_at > row.last_seen:
            row.last_seen = candidate.created_at
            row.last_snapshot_id = str(candidate.lineage.snapshot_id)
        row.first_seen = min(row.first_seen, candidate.created_at)
        row.score = max(row.score, candidate.score)
        if q_value is not None:
            row.q_value = q_value if row.q_value is None else min(row.q_value, q_value)
        if candidate.segment.population is not None:
            row.population = candidate.segment.population
        if status is ValidationStatus.VALIDATED:
            row.validation_status = status.value
        return reopened

    def _link_candidate(self, *, pattern_id: PatternId, candidate: Candidate, at: Instant) -> None:
        key = (str(pattern_id), str(candidate.candidate_id))
        if self._session.get(PatternCandidateRow, key) is not None:
            return
        row = self._session.get(PatternRow, str(pattern_id))
        self._session.add(
            PatternCandidateRow(
                pattern_id=str(pattern_id),
                candidate_id=str(candidate.candidate_id),
                added_at=at,
                is_representative=row is not None
                and row.representative_candidate_id == str(candidate.candidate_id),
            )
        )

    def _age_untouched(self, *, source_id: SourceId, touched: set[str]) -> int:
        """Increment the unsupported-window count for every open pattern this run missed.

        Staleness is a property of runs, not of the calendar: a source probed hourly and
        a source probed weekly should not age at the same rate just because a clock
        ticked. That is also why nothing here reads one.
        """
        statement = (
            update(PatternRow)
            .where(PatternRow.source_id == str(source_id))
            .where(PatternRow.lifecycle.in_(_OPEN_STATES))
            .values(windows_without_support=PatternRow.windows_without_support + 1)
        )
        if touched:
            statement = statement.where(PatternRow.pattern_id.not_in(sorted(touched)))
        result = self._session.execute(statement)
        return int(getattr(result, "rowcount", 0) or 0)

    def _is_suppressed(self, signature: ContentHash) -> bool:
        return self._active_suppression(signature) is not None

    def _active_suppression(self, signature: ContentHash) -> SuppressionRow | None:
        return self._session.scalars(
            select(SuppressionRow)
            .where(SuppressionRow.signature == str(signature))
            .where(SuppressionRow.lifted_at.is_(None))
            .order_by(SuppressionRow.created_at.desc(), SuppressionRow.suppression_id)
            .limit(1)
        ).first()

    def _suppressed_signatures(self) -> frozenset[str]:
        return frozenset(
            self._session.scalars(
                select(SuppressionRow.signature).where(SuppressionRow.lifted_at.is_(None))
            )
        )

    def _group_stats(self) -> Mapping[str, tuple[int, int, int]]:
        """Confirmations, rejections and size per structure key, in one query."""
        rows = self._session.execute(
            select(
                PatternRow.structure_key,
                func.sum(PatternRow.confirmations),
                func.sum(PatternRow.rejections),
                func.count(),
            ).group_by(PatternRow.structure_key)
        ).all()
        return {
            str(shape): (int(confirmations or 0), int(rejections or 0), int(size or 1))
            for shape, confirmations, rejections, size in rows
        }

    def _audit(
        self,
        *,
        action: str,
        subject_kind: str,
        subject_id: str,
        actor: str,
        at: Instant,
        detail: Mapping[str, str] | None = None,
        to_state: str | None = None,
    ) -> None:
        digest = None
        if detail is not None:
            digest = content_hash(canonical_json(dict(detail)), prefix="dtl")
        event = AuditEvent(
            event_id=str(
                content_hash(
                    canonical_json(
                        {
                            "action": action,
                            "subject": subject_id,
                            "at": at.isoformat(),
                            "actor": actor,
                        }
                    ),
                    prefix="aud",
                )
            ),
            occurred_at=at,
            actor=actor,
            action=action,
            subject_kind=subject_kind,
            subject_id=subject_id,
            plane=Plane.CONTROL,
            detail_digest=digest,
            correlation_id=None,
        )
        append_audit(self._session, event, to_state=to_state)

    def _rebuild_pattern(self, row: PatternRow) -> Pattern:
        """Rebuild a contract ``Pattern`` from storage.

        The representative candidate is loaded in full, because ``Pattern.representative``
        is a whole ``Candidate`` and a pattern without its evidence cannot be judged.
        Everything tainted comes back tainted; nothing is rendered.
        """
        candidate_ids = tuple(
            CandidateId(value)
            for value in self._session.scalars(
                select(PatternCandidateRow.candidate_id)
                .where(PatternCandidateRow.pattern_id == row.pattern_id)
                .order_by(PatternCandidateRow.candidate_id)
            )
        )
        representative_row = self._session.get(CandidateRow, row.representative_candidate_id)
        if representative_row is None:
            raise StoreIntegrityError(
                f"pattern {row.pattern_id} names a representative candidate that is not "
                "stored; the pattern cannot be rebuilt or reproduced"
            )
        representative = Candidate.model_validate(representative_row.payload_value)
        return Pattern(
            pattern_id=PatternId(row.pattern_id),
            source_id=SourceId(row.source_id),
            segment=Segment.model_validate(row.payload_value),
            candidates=candidate_ids or (representative.candidate_id,),
            representative=representative,
            lifecycle=PatternLifecycle(row.lifecycle),
            first_seen=row.first_seen,
            last_seen=row.last_seen,
            q_value=row.q_value,
            dedup_group=row.dedup_group,
            name=None,
        )


def _candidate_p_value(candidate: Candidate) -> float | None:
    """The candidate's p-value: the smallest one its evidence reports.

    Smallest, because a candidate makes one claim supported by several measurements and
    its significance is that of its strongest support. Combining them properly -- Fisher,
    Stouffer -- assumes independence that adjacent probes over the same segment do not
    have, and a wrong combination is worse than a conservative choice.
    """
    values = [float(item.p_value.value) for item in candidate.evidence if item.p_value is not None]
    return min(values) if values else None


def _feedback_id(feedback: Feedback) -> str:
    """Content-addressed feedback id, so re-delivering a verdict is idempotent."""
    return str(
        content_hash(
            canonical_json(
                {
                    "pattern_id": str(feedback.pattern_id),
                    "reviewer_id": feedback.reviewer_id,
                    "verdict": feedback.verdict.value,
                    "decided_at": feedback.decided_at.isoformat(),
                }
            ),
            prefix="fbk",
        )
    )
