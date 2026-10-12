"""Residual routing: explained candidates stop here, the unexplained residual proceeds.

For each candidate the router ranks every aligned context event (``matching.py``) and
keeps all of them -- competing explanations are recorded, never collapsed to one. If the
strongest match reaches the source's threshold the candidate is EXPLAINED, with that
match attached; otherwise it PROCEEDS to L5 with its matches recorded as context.

Every EXPLAINED decision is an automatic suppression, so every one is:

* logged: an audit event in A3's hash-chained ledger, carrying the decision id and a
  digest of the decision (ids and derived numbers only);
* reversible: ``reverse(decision_id, ...)`` appends a new PROCEED decision that points at
  the one it reverses, writes its own audit event, and takes the success back out of the
  learned prior. Nothing is updated in place.

HANDING OFF TO L5
-----------------
A PROCEED candidate is ingested as normal. An EXPLAINED one need not be ingested at all;
if it is (so that a human can see what was explained away), move its pattern to
``EXPLAINED_AWAY`` with ``context_ref = decision.decision_id`` -- godwit-store requires a
``context_ref`` for that transition and this id is what it should be.

Determinism: no clock, no randomness. ``at`` is injected; candidates are routed in the
order given; matches are ordered by (strength desc, event id).
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Final

from godwit_contracts import (
    AuditEvent,
    Candidate,
    CandidateId,
    GodwitModel,
    Instant,
    Plane,
    Probability,
    SourceId,
    canonical_json,
    content_hash,
)
from godwit_contracts.common import is_safe_identifier
from pydantic import Field

from godwit_context.audit import AuditSink
from godwit_context.events import ContextEvent, ContextType
from godwit_context.matching import (
    Match,
    MatchPolicy,
    PeerObservation,
    Subject,
    Window,
    match_candidate,
    subject_of_candidate,
    subject_of_peer,
)
from godwit_context.priors import Outcome, PriorBook

__all__ = [
    "DECISION_SUBJECT",
    "ContextRouter",
    "Route",
    "RoutingDecision",
    "RoutingPolicy",
    "UnknownDecisionError",
]

DECISION_SUBJECT: Final = "candidate"


class Route(StrEnum):
    EXPLAINED = "explained"
    PROCEED = "proceed"


class RoutingPolicy(GodwitModel):
    """The suppression threshold, per source. Higher means suppress less."""

    threshold: Probability = 0.5
    per_source: Mapping[SourceId, Probability] = Field(default_factory=dict)

    def threshold_for(self, source_id: SourceId) -> float:
        return self.per_source.get(source_id, self.threshold)


class RoutingDecision(GodwitModel):
    """What happened to one candidate, and why. Contains no row value."""

    decision_id: str
    candidate_id: CandidateId
    source_id: SourceId
    family: str
    route: Route
    threshold: Probability
    matches: tuple[Match, ...] = Field(
        description="Every aligned explanation, strongest first. Never collapsed."
    )
    decided_at: Instant
    actor: str
    reverses: str | None = Field(
        default=None, description="The decision this one reverses, if it is a reversal."
    )
    reason: str | None = Field(
        default=None, description="A reason code for a reversal. A plain identifier."
    )

    @property
    def explanation(self) -> Match | None:
        """The attached explanation: the best match, when the candidate was EXPLAINED."""
        return self.matches[0] if self.route is Route.EXPLAINED else None


class UnknownDecisionError(KeyError):
    """No decision with that id, or it is not a suppression that can be reversed."""


class ContextRouter:
    """Routes candidates and keeps the decision log. One per orchestrator run."""

    def __init__(
        self,
        *,
        audit: AuditSink,
        priors: PriorBook | None = None,
        policy: MatchPolicy | None = None,
        routing: RoutingPolicy | None = None,
        actor: str = "a8",
    ) -> None:
        self._audit = audit
        self._priors = priors if priors is not None else PriorBook()
        self._policy = policy if policy is not None else MatchPolicy()
        self._routing = routing if routing is not None else RoutingPolicy()
        self._actor = actor
        self._log: list[RoutingDecision] = []
        self._by_id: dict[str, RoutingDecision] = {}

    # ----------------------------------------------------------------------------------

    def window_for(self, candidate: Candidate) -> Window:
        span = self._policy.window_by_source.get(candidate.source_id, self._policy.default_window)
        return Window(start=candidate.created_at - span, end=candidate.created_at)

    def route(
        self,
        candidates: Sequence[Candidate],
        *,
        events: Iterable[ContextEvent],
        at: Instant,
        peers: Sequence[PeerObservation] = (),
        windows: Mapping[CandidateId, Window] | None = None,
    ) -> tuple[RoutingDecision, ...]:
        """Route a batch. Other candidates in the batch serve as peers for each other."""
        events = tuple(events)
        windows = windows or {}
        subjects = [
            subject_of_candidate(c, windows.get(c.candidate_id) or self.window_for(c))
            for c in candidates
        ]
        # A detector's own observation of a segment wins over the batch candidate for the
        # same segment: one measurement, counted once.
        pool: dict[tuple[tuple[str, str], str], Subject] = {}
        for item in [subject_of_peer(p) for p in peers] + subjects:
            pool.setdefault((item.key, item.family), item)
        out: list[RoutingDecision] = []
        for candidate, subject in zip(candidates, subjects, strict=True):
            own = [e for e in events if e.derived_from != candidate.candidate_id]
            others = [s for s in pool.values() if s.key != subject.key]
            matches = match_candidate(
                subject, own, peers=others, prior=self._priors.prior, policy=self._policy
            )
            out.append(self._decide(candidate, subject, matches, at))
        return tuple(out)

    def _decide(
        self, candidate: Candidate, subject: Subject, matches: tuple[Match, ...], at: Instant
    ) -> RoutingDecision:
        threshold = self._routing.threshold_for(candidate.source_id)
        previous = self.current(candidate.candidate_id)
        overruled = previous is not None and previous.reverses is not None
        explained = not overruled and bool(matches) and matches[0].strength >= threshold
        route = Route.EXPLAINED if explained else Route.PROCEED
        decision = RoutingDecision(
            decision_id=_decision_id(candidate.candidate_id, route, at, None),
            candidate_id=candidate.candidate_id,
            source_id=candidate.source_id,
            family=subject.family,
            route=route,
            threshold=threshold,
            matches=matches,
            decided_at=at,
            actor=self._actor,
        )
        self._record(decision)
        if explained:
            # Learn from the winner only. A losing match was not shown to be wrong, only
            # less specific, and a candidate that proceeds teaches nothing until a human
            # looks. Counting either against a context lets one busy week drag its prior
            # down until it can never win again. Humans teach through reverse() and
            # verdict().
            best = matches[0]
            self._priors.observe(
                best.context_type, subject.family, candidate.source_id, Outcome.EXPLAINED, at=at
            )
            self._audit_decision(decision, action="context_explain", from_state=None)
        return decision

    def verdict(
        self,
        decision_id: str,
        *,
        explained_by: ContextType | None,
        actor: str,
        at: Instant,
    ) -> None:
        """A human's verdict on a candidate that PROCEEDED with context attached.

        ``explained_by`` names the context type that did explain it after all; ``None``
        says the anomaly was genuine, so every aligned context type failed to explain it.
        Only the learned prior changes: the decision itself stays as it was made.
        """
        decision = self._by_id.get(decision_id)
        if decision is None or decision.route is not Route.PROCEED or not decision.matches:
            raise UnknownDecisionError(decision_id)
        if not is_safe_identifier(actor):
            raise ValueError("actor must be a plain identifier, not free text")
        for context_type in sorted({m.context_type for m in decision.matches}):
            outcome = Outcome.EXPLAINED if context_type is explained_by else Outcome.NOT_EXPLAINED
            self._priors.observe(context_type, decision.family, decision.source_id, outcome, at=at)
        self._audit.append(
            AuditEvent(
                event_id=_decision_id(decision.candidate_id, decision.route, at, decision_id),
                occurred_at=at,
                actor=actor,
                action="context_verdict",
                subject_kind=DECISION_SUBJECT,
                subject_id=str(decision.candidate_id),
                plane=Plane.CONTROL,
                correlation_id=decision_id,
            ),
            to_state="explained" if explained_by is not None else "genuine",
        )

    def reverse(self, decision_id: str, *, actor: str, reason: str, at: Instant) -> RoutingDecision:
        """Undo an automatic suppression. The candidate proceeds; the record remains.

        A reversal sticks: routing the same candidate id again later records its matches
        but does not suppress it a second time.
        """
        original = self._by_id.get(decision_id)
        if original is None or original.route is not Route.EXPLAINED:
            raise UnknownDecisionError(decision_id)
        if self.current(original.candidate_id) is not original:
            raise UnknownDecisionError(f"{decision_id} is no longer the current decision")
        if not (is_safe_identifier(actor) and is_safe_identifier(reason)):
            raise ValueError("actor and reason must be plain identifiers, not free text")
        reversal = original.model_copy(
            update={
                "decision_id": _decision_id(original.candidate_id, Route.PROCEED, at, decision_id),
                "route": Route.PROCEED,
                "decided_at": at,
                "actor": actor,
                "reverses": decision_id,
                "reason": reason,
            }
        )
        self._record(reversal)
        best = original.matches[0]
        self._priors.observe(
            best.context_type, original.family, original.source_id, Outcome.REVERSED, at=at
        )
        self._audit_decision(reversal, action="context_reverse", from_state=Route.EXPLAINED.value)
        return reversal

    def _record(self, decision: RoutingDecision) -> None:
        self._log.append(decision)
        self._by_id[decision.decision_id] = decision

    def _audit_decision(
        self, decision: RoutingDecision, *, action: str, from_state: str | None
    ) -> None:
        self._audit.append(
            AuditEvent(
                event_id=decision.decision_id,
                occurred_at=decision.decided_at,
                actor=decision.actor,
                action=action,
                subject_kind=DECISION_SUBJECT,
                subject_id=str(decision.candidate_id),
                plane=Plane.CONTROL,
                detail_digest=content_hash(decision.model_dump_json(), prefix="ctxd"),
                correlation_id=decision.reverses,
            ),
            from_state=from_state,
            to_state=decision.route.value,
        )

    # ----------------------------------------------------------------------------------

    @property
    def decisions(self) -> tuple[RoutingDecision, ...]:
        """Every decision, oldest first, reversals included."""
        return tuple(self._log)

    def current(self, candidate_id: CandidateId) -> RoutingDecision | None:
        """The latest decision for a candidate."""
        for decision in reversed(self._log):
            if decision.candidate_id == candidate_id:
                return decision
        return None

    def history(self, candidate_id: CandidateId) -> tuple[RoutingDecision, ...]:
        return tuple(d for d in self._log if d.candidate_id == candidate_id)


def _decision_id(
    candidate_id: CandidateId, route: Route, at: _dt.datetime, reverses: str | None
) -> str:
    return str(
        content_hash(
            canonical_json([str(candidate_id), route.value, at.isoformat(), reverses or ""]),
            prefix="ctxr",
        )
    )
