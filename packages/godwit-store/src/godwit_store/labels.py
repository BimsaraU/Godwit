"""The label ledger, and the one rule that makes it safe: reads require an instant.

Every leakage bug in supervised learning is, underneath, someone reading a label that
did not exist yet. A chargeback lands sixty days after the transaction; a model trained
on that label at the transaction's event time knows sixty days of future and scores
beautifully in evaluation. It then fails the day it is deployed, and the failure looks
like drift rather than like the bug it is.

THE API HAS NO CONVENIENCE OVERLOAD
-----------------------------------
:meth:`LabelLedger.visible_as_of` takes ``instant`` keyword-only, with no default.
There is no ``all()``, no ``latest()``, no ``labels`` property, and no
``as_of=None`` meaning "now". Every read path in this module -- rows, counts,
aggregates, the per-entity lookup, the ``LabelSet`` builder -- filters on
``label_time <= instant``, because a leak needs only one unfiltered route and an API
with six routes and five filters is an API with a leak.

A4 (replay), A12 (subtractor) and A13 (prediction) will use whatever is easiest here.
That is why the easiest thing is the correct one.

COVERAGE IS NOT THE SAME QUESTION AS VISIBILITY
-----------------------------------------------
*Visibility* asks "did we know this on that date". *Coverage* asks "was this population
exhaustively labelled over that window", and it is what distinguishes an unlabelled
entity that is a negative from one that is simply unknown. Precision and AUC over an
uncovered region are not conservative estimates; they are numbers about a population
nobody promised to have labelled. :meth:`assert_covered` refuses to produce them.

THE ENTITY PSEUDONYM
--------------------
Labels are indexed by ``entity_key``, a BLAKE2b digest of the entity id rather than the
id itself, so that a plain identifier does not sit in an index that every query touches.
It is a **pseudonym, not an anonymisation**: over a small or guessable id space it is
enumerable in seconds, exactly as ``SegmentKey`` is. It is a reduction in exposure, not
a protection, and it is documented as one.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Final

from godwit_contracts import (
    CoverageScope,
    GodwitModel,
    Instant,
    Label,
    LabelSet,
    NonNegInt,
    Segment,
    Sensitivity,
    Tainted,
    canonical_json,
    content_hash,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from godwit_store.errors import UncoveredRegionError
from godwit_store.schema import LabelCoverageRow, LabelRow

__all__ = [
    "CoverageVerdict",
    "LabelLedger",
    "entity_pseudonym",
]

_LABEL_ACQUISITION: Final[str] = "user_supplied"
"""Labels arrive from a human process or an upstream feed. Either way they are row
values: ``Acquisition.USER_SUPPLIED`` carries a DATA_VALUE floor, which is correct."""


def entity_pseudonym(entity_id: Tainted[str]) -> str:
    """Stable digest of an entity id, for indexing and joining.

    A pseudonym, not an anonymisation -- see the module docstring. ``.value`` is read
    rather than ``.reveal()``: this is a one-way transform into a column that is used
    as a key, not a disclosure of the identifier to anything that could act on it.

    Deterministic and unsalted, because two independently written processes must
    produce the same key for the same entity or the ledger cannot be joined at all.
    That is the same trade ``segment_key`` makes, with the same consequence: anyone who
    can enumerate the id space can invert it.
    """
    if entity_id.sensitivity is Sensitivity.DERIVED_STATISTIC:
        raise ValueError("an entity id is a row value, not a statistic")
    return str(content_hash(canonical_json({"entity": str(entity_id.value)}), prefix="ent"))


class CoverageVerdict(GodwitModel):
    """Whether a region is trustworthy enough to report a metric over.

    ``covered`` is the answer to "may I compute precision here". ``exhaustive`` is the
    stronger claim that absence of a label means negative rather than unknown; a region
    can be covered by a non-exhaustive declaration, in which case unlabelled entities
    are unknown and a trainer that treats them as negatives is training on noise it
    invented.
    """

    entity_type: str
    instant: Instant | None = None
    window_from: Instant | None = None
    window_to: Instant | None = None
    covered: bool
    exhaustive: bool
    coverage_ids: tuple[str, ...] = ()
    reason: str = ""


class LabelLedger:
    """Point-in-time-correct reads over the label tables.

    Holds a session and nothing else. Every method that returns labels takes
    ``instant`` keyword-only and has no default; that is the whole design.
    """

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- writes ------------------------------------------------------------------

    def record_coverage(
        self,
        coverage: CoverageScope,
        *,
        coverage_id: str,
        source: str,
        at: Instant,
    ) -> str:
        """Declare what a batch of labels covers. Returns the coverage id.

        The population ``Segment`` goes into the tainted payload: its predicates quote
        real values, exactly as every other segment in the system does.
        """
        row = LabelCoverageRow(
            coverage_id=coverage_id,
            entity_type=coverage.entity_type,
            segment_key=str(coverage.population.key),
            complete_from=coverage.complete_from,
            complete_to=coverage.complete_to,
            is_exhaustive=coverage.is_exhaustive,
            source=source,
            declared_at=at,
            payload_value=coverage.model_dump(mode="json"),
            payload_sensitivity=Sensitivity.DATA_VALUE.value,
            payload_acquisition="segment_predicate",
            payload_population=coverage.population.population,
        )
        self._session.add(row)
        self._session.flush()
        return coverage_id

    def record_labels(
        self,
        labels: Iterable[Label],
        *,
        entity_type: str,
        coverage_id: str | None,
        at: Instant,
    ) -> int:
        """Append labels. Returns how many were written.

        ``label_id`` is derived from the label's own content, so re-ingesting the same
        label twice is a no-op rather than a duplicate -- the same idempotence rule the
        candidate ingest follows, for the same reason.
        """
        written = 0
        for label in labels:
            label_id = _label_id(label, entity_type=entity_type)
            if self._session.get(LabelRow, label_id) is not None:
                continue
            self._session.add(
                LabelRow(
                    label_id=label_id,
                    entity_type=entity_type,
                    entity_key=entity_pseudonym(label.entity_id),
                    coverage_id=coverage_id,
                    event_time=label.event_time,
                    label_time=label.label_time,
                    source=label.source,
                    confidence=label.confidence,
                    recorded_at=at,
                    payload_value=label.model_dump(mode="json"),
                    payload_sensitivity=Sensitivity.DATA_VALUE.value,
                    payload_acquisition=_LABEL_ACQUISITION,
                    payload_population=None,
                )
            )
            written += 1
        self._session.flush()
        return written

    # -- reads, all of which require an instant -----------------------------------

    def visible_as_of(
        self,
        *,
        instant: Instant,
        entity_type: str,
        entity_keys: Sequence[str] | None = None,
        limit: int = 100_000,
    ) -> tuple[Label, ...]:
        """Labels whose ``label_time`` is at or before ``instant``. Oldest first.

        ``instant`` is keyword-only and has no default, and there is no other method
        that returns a label. Asking "what did we know on this date" is the only
        supported question because it is the only one that cannot leak the future.
        """
        statement = (
            select(LabelRow)
            .where(LabelRow.entity_type == entity_type)
            .where(LabelRow.label_time <= instant)
        )
        if entity_keys is not None:
            statement = statement.where(LabelRow.entity_key.in_(list(entity_keys)))
        statement = statement.order_by(LabelRow.label_time, LabelRow.label_id).limit(limit)
        return tuple(
            Label.model_validate(row.payload_value) for row in self._session.scalars(statement)
        )

    def latest_for_entity(
        self, *, instant: Instant, entity_type: str, entity_key: str
    ) -> Label | None:
        """The most recent label for one entity that existed at ``instant``.

        Ordered by ``label_time`` descending *after* the filter, never before it: the
        obvious wrong implementation takes the newest row and then checks it, which
        returns nothing when a future label exists rather than returning the one that
        was current.
        """
        row = self._session.scalars(
            select(LabelRow)
            .where(LabelRow.entity_type == entity_type)
            .where(LabelRow.entity_key == entity_key)
            .where(LabelRow.label_time <= instant)
            .order_by(LabelRow.label_time.desc(), LabelRow.label_id.desc())
            .limit(1)
        ).first()
        return None if row is None else Label.model_validate(row.payload_value)

    def count_as_of(self, *, instant: Instant, entity_type: str) -> int:
        """How many labels existed at ``instant``.

        Filtered like every other read. An aggregate is a read: "how many labels will
        this entity eventually have" is future knowledge even though it quotes nothing.
        """
        return int(
            self._session.scalar(
                select(func.count())
                .select_from(LabelRow)
                .where(LabelRow.entity_type == entity_type)
                .where(LabelRow.label_time <= instant)
            )
            or 0
        )

    def label_set(
        self,
        *,
        instant: Instant,
        entity_type: str,
        coverage_id: str,
    ) -> LabelSet:
        """Build a contract ``LabelSet`` containing only labels visible at ``instant``.

        The filter is applied here as well as inside ``LabelSet.visible_as_of``. Two
        filters is not redundancy: a ``LabelSet`` gets passed around, serialised and
        handed to a trainer, and one that carries future labels in its ``labels`` tuple
        is one attribute access away from leaking them.
        """
        coverage_row = self._session.get(LabelCoverageRow, coverage_id)
        if coverage_row is None:
            raise UncoveredRegionError(
                f"no coverage declaration {coverage_id}; a label set without one cannot "
                "say whether an unlabelled entity is a negative or an unknown"
            )
        coverage = CoverageScope.model_validate(coverage_row.payload_value)
        labels = self.visible_as_of(instant=instant, entity_type=entity_type)
        return LabelSet(coverage=coverage, labels=labels)

    # -- coverage ------------------------------------------------------------------

    def coverage_at(
        self, *, instant: Instant, entity_type: str, segment_key: str | None = None
    ) -> CoverageVerdict:
        """Whether ``instant`` falls inside a declared coverage window."""
        statement = (
            select(LabelCoverageRow)
            .where(LabelCoverageRow.entity_type == entity_type)
            .where(LabelCoverageRow.complete_from <= instant)
            .where(LabelCoverageRow.complete_to >= instant)
        )
        if segment_key is not None:
            statement = statement.where(LabelCoverageRow.segment_key == segment_key)
        rows = list(self._session.scalars(statement.order_by(LabelCoverageRow.coverage_id)))
        return _verdict(
            entity_type=entity_type,
            rows=rows,
            instant=instant,
            window_from=None,
            window_to=None,
        )

    def coverage_over(
        self,
        *,
        entity_type: str,
        window_from: Instant,
        window_to: Instant,
        segment_key: str | None = None,
    ) -> CoverageVerdict:
        """Whether a whole period is covered, not merely one instant inside it.

        A metric is reported over a period, so this is the question that actually gets
        asked. Coverage of the period requires a single declaration spanning it: two
        adjacent windows with a one-day gap do not cover the period, and stitching them
        together silently is how "we have labels for that quarter" becomes true in a
        dashboard and false in reality.
        """
        if window_to < window_from:
            raise ValueError("window_to precedes window_from")
        statement = (
            select(LabelCoverageRow)
            .where(LabelCoverageRow.entity_type == entity_type)
            .where(LabelCoverageRow.complete_from <= window_from)
            .where(LabelCoverageRow.complete_to >= window_to)
        )
        if segment_key is not None:
            statement = statement.where(LabelCoverageRow.segment_key == segment_key)
        rows = list(self._session.scalars(statement.order_by(LabelCoverageRow.coverage_id)))
        return _verdict(
            entity_type=entity_type,
            rows=rows,
            instant=None,
            window_from=window_from,
            window_to=window_to,
        )

    def assert_covered(
        self,
        *,
        entity_type: str,
        window_from: Instant,
        window_to: Instant,
        segment_key: str | None = None,
        require_exhaustive: bool = True,
    ) -> CoverageVerdict:
        """Refuse to let a metric be computed over an uncovered region.

        Call this before reporting precision, recall or AUC. ``require_exhaustive``
        defaults to True because precision counts negatives, and counting an unknown as
        a negative inflates every precision number that has ever been reported that way.
        """
        verdict = self.coverage_over(
            entity_type=entity_type,
            window_from=window_from,
            window_to=window_to,
            segment_key=segment_key,
        )
        if not verdict.covered or (require_exhaustive and not verdict.exhaustive):
            raise UncoveredRegionError(
                f"{entity_type} is not "
                f"{'exhaustively ' if require_exhaustive else ''}covered from "
                f"{window_from.isoformat()} to {window_to.isoformat()}: {verdict.reason}. "
                "A metric over an uncovered region is a number about a population "
                "nobody promised to have labelled."
            )
        return verdict


def _verdict(
    *,
    entity_type: str,
    rows: Sequence[LabelCoverageRow],
    instant: Instant | None,
    window_from: Instant | None,
    window_to: Instant | None,
) -> CoverageVerdict:
    if not rows:
        return CoverageVerdict(
            entity_type=entity_type,
            instant=instant,
            window_from=window_from,
            window_to=window_to,
            covered=False,
            exhaustive=False,
            reason="no coverage declaration spans this region",
        )
    exhaustive = any(row.is_exhaustive for row in rows)
    return CoverageVerdict(
        entity_type=entity_type,
        instant=instant,
        window_from=window_from,
        window_to=window_to,
        covered=True,
        exhaustive=exhaustive,
        coverage_ids=tuple(row.coverage_id for row in rows),
        reason=""
        if exhaustive
        else "covered but not exhaustive: an unlabelled entity here is unknown, not negative",
    )


def _label_id(label: Label, *, entity_type: str) -> str:
    """Content-addressed label id, so ingest is idempotent.

    Derived from the entity pseudonym and the two timestamps rather than from the
    label's value: re-delivering the same fact must not create a second row, and a feed
    that re-sends a corrected value for the same event at the same label time is a
    correction, which the caller has to handle explicitly rather than by accident.
    """
    return str(
        content_hash(
            canonical_json(
                {
                    "entity_type": entity_type,
                    "entity": entity_pseudonym(label.entity_id),
                    "event_time": label.event_time.isoformat(),
                    "label_time": label.label_time.isoformat(),
                    "source": label.source,
                }
            ),
            prefix="lbl",
        )
    )


def coverage_scope(
    *,
    entity_type: str,
    complete_from: Instant,
    complete_to: Instant,
    is_exhaustive: bool,
    population: Segment | None = None,
    note: str = "",
) -> CoverageScope:
    """Build a ``CoverageScope`` without importing half the contracts at a call site."""
    return CoverageScope(
        entity_type=entity_type,
        population=population if population is not None else Segment(),
        complete_from=complete_from,
        complete_to=complete_to,
        is_exhaustive=is_exhaustive,
        note=note,
    )


def label_payload_count(session: Session, *, entity_type: str) -> NonNegInt:
    """Total labels stored for an entity type, ignoring visibility.

    **Not a point-in-time read.** It answers an operational question -- how much is in
    the ledger -- and must never be used to decide what a model may train on. It is
    named to be conspicuous and returns a count, never a label, so there is nothing here
    a training path could accidentally consume.
    """
    total: Any = session.scalar(
        select(func.count()).select_from(LabelRow).where(LabelRow.entity_type == entity_type)
    )
    return int(total or 0)
