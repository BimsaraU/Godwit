"""Learned context: which context types have explained which detector families, where.

Plain statistics. No model, no LLM. For each (context type, detector family, source) we
count how often an event of that type was aligned with a candidate (``offered``) and how
often it ended up being the explanation that stuck (``explained``). A reversal by a human
takes the success back.

The estimate is a Beta-smoothed rate with hierarchical back-off, so a source with no
history borrows from the family, and a family with no history borrows from the type:

    p_type   = (k_type   + a * 0.5)      / (n_type   + a)
    p_family = (k_family + a * p_type)   / (n_family + a)
    p_source = (k_source + a * p_family) / (n_source + a)

with pseudo-count ``a`` (default 4). With no history at all the prior is 0.5: neither for
nor against.

Persistence is A3's audit ledger: every observation is one append-only, hash-chained
event (subject ``context_prior``, subject id ``type|family|source``, ``to_state`` the
outcome). ``PriorBook.load`` replays them. A ledger of observations rather than a table
of counts means the prior on any date can be reconstructed exactly, which is what an
auditor asking "why did it suppress this in March" needs.
"""

from __future__ import annotations

from collections import defaultdict
from enum import StrEnum
from typing import Final

from godwit_contracts import AuditEvent, Instant, Plane, SourceId, canonical_json, content_hash

from godwit_context.audit import AuditSink
from godwit_context.events import ContextType

__all__ = ["PRIOR_SUBJECT", "Outcome", "PriorBook"]

PRIOR_SUBJECT: Final = "context_prior"


class Outcome(StrEnum):
    EXPLAINED = "explained"
    NOT_EXPLAINED = "not_explained"
    REVERSED = "reversed"


class PriorBook:
    """Counts, with an optional ledger behind them."""

    def __init__(
        self, *, sink: AuditSink | None = None, pseudo_count: float = 4.0, actor: str = "a8"
    ) -> None:
        if pseudo_count <= 0:
            raise ValueError("pseudo_count must be positive")
        self._sink = sink
        self._a = pseudo_count
        self._actor = actor
        self._offered: defaultdict[tuple[str, ...], float] = defaultdict(float)
        self._explained: defaultdict[tuple[str, ...], float] = defaultdict(float)
        self._seq = 0

    @classmethod
    def load(cls, sink: AuditSink, *, pseudo_count: float = 4.0, actor: str = "a8") -> PriorBook:
        """Rebuild from the ledger, then keep appending to it."""
        book = cls(sink=None, pseudo_count=pseudo_count, actor=actor)
        for record in sink.records(subject_kind=PRIOR_SUBJECT):
            context_type, family, source_id = record.subject_id.split("|", 2)
            book._apply(
                ContextType(context_type),
                family,
                SourceId(source_id),
                Outcome(record.to_state or ""),
            )
        book._sink = sink
        return book

    def observe(
        self,
        context_type: ContextType,
        family: str,
        source_id: SourceId,
        outcome: Outcome,
        *,
        at: Instant,
    ) -> None:
        self._apply(context_type, family, source_id, outcome)
        if self._sink is None:
            return
        subject = f"{context_type.value}|{family}|{source_id}"
        self._sink.append(
            AuditEvent(
                event_id=str(
                    content_hash(
                        canonical_json([subject, outcome.value, at.isoformat(), self._seq]),
                        prefix="ctxp",
                    )
                ),
                occurred_at=at,
                actor=self._actor,
                action="context_prior_observe",
                subject_kind=PRIOR_SUBJECT,
                subject_id=subject,
                plane=Plane.CONTROL,
            ),
            to_state=outcome.value,
        )

    def _apply(
        self, context_type: ContextType, family: str, source_id: SourceId, outcome: Outcome
    ) -> None:
        self._seq += 1
        for key in self._keys(context_type, family, source_id):
            if outcome is Outcome.REVERSED:
                self._explained[key] = max(0.0, self._explained[key] - 1.0)
                continue
            self._offered[key] += 1.0
            if outcome is Outcome.EXPLAINED:
                self._explained[key] += 1.0

    @staticmethod
    def _keys(
        context_type: ContextType, family: str, source_id: SourceId
    ) -> tuple[tuple[str, ...], ...]:
        return (
            (context_type.value,),
            (context_type.value, family),
            (context_type.value, family, str(source_id)),
        )

    def prior(self, context_type: ContextType, family: str, source_id: SourceId) -> float:
        """Shrunk explanation rate. 0.5 with no history."""
        estimate = 0.5
        for key in self._keys(context_type, family, source_id):
            n, k = self._offered[key], self._explained[key]
            estimate = (k + self._a * estimate) / (n + self._a)
        return estimate

    def counts(
        self, context_type: ContextType, family: str, source_id: SourceId
    ) -> tuple[float, float]:
        """(offered, explained) at the most specific level."""
        key = (context_type.value, family, str(source_id))
        return self._offered[key], self._explained[key]
