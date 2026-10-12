"""Context events: the mundane reasons the world changed.

A context event is a deploy, a campaign, a holiday, a month end, a pipeline failure, a
market move or an analyst's note, with a time span and a scope. It is the thing a
candidate is matched against.

What is tainted here, and why:

* ``label`` is free text from outside Godwit -- a deploy description, a campaign name,
  an analyst note. It is ``USER_SUPPLIED`` and therefore ``DATA_VALUE``: assume someone
  pasted a row into it, because someone did.
* ``scope.columns`` are customer column names (``SCHEMA_NAME``, leak path 9).
* ``scope.segments`` carry predicate values (``DATA_VALUE``, leak path 4).

Everything else -- ids, types, instants, ``kind`` -- is minted by Godwit or by a context
source adapter and contains no row value. ``kind`` is validated as a plain identifier so
that nobody can smuggle a campaign name into it.
"""

from __future__ import annotations

import datetime as _dt
from enum import StrEnum
from typing import Self

from godwit_contracts import (
    CandidateId,
    GodwitModel,
    Instant,
    Segment,
    Sensitivity,
    SourceId,
    Tainted,
    canonical_json,
    content_hash,
)
from godwit_contracts.common import is_safe_identifier
from pydantic import Field, model_validator

__all__ = [
    "ContextEvent",
    "ContextScope",
    "ContextType",
    "event_id_for",
]


class ContextType(StrEnum):
    """The families of mundane explanation. Each has its own lead and lag."""

    DEPLOY = "deploy"
    CAMPAIGN = "campaign"
    HOLIDAY = "holiday"
    BUSINESS_CALENDAR = "business_calendar"
    DATA_QUALITY = "data_quality"
    MARKET = "market"
    ANNOTATION = "annotation"


class ContextScope(GodwitModel):
    """What a context event touches.

    Empty ``source_ids`` means global: the event touches every source (a market crash,
    a global campaign). Non-empty ``columns`` or ``segments`` narrow the event inside
    its sources: a deploy that only changed the refunds pipeline touches the refund
    columns, not the whole table.
    """

    source_ids: tuple[SourceId, ...] = ()
    columns: tuple[Tainted[str], ...] = ()
    segments: tuple[Segment, ...] = ()

    @model_validator(mode="after")
    def _columns_are_schema_names(self) -> Self:
        for index, column in enumerate(self.columns):
            if column.sensitivity is not Sensitivity.SCHEMA_NAME:
                raise ValueError(f"ContextScope.columns[{index}] must be tainted SCHEMA_NAME")
        return self

    @property
    def is_global(self) -> bool:
        """True when the event is not restricted to any source."""
        return not self.source_ids

    @property
    def is_restricted(self) -> bool:
        """True when the event names columns or segments inside its sources."""
        return bool(self.columns or self.segments)


class ContextEvent(GodwitModel):
    """One reason the world might have changed, over ``[start, end]``.

    ``end`` equal to ``start`` is an instant event (a deploy). ``permanent`` marks
    analyst annotations: they are never pruned and apply to every future match.
    ``derived_from`` is set when the event was made from a candidate (an L-1 schema
    change), so that the candidate is never matched against itself.
    """

    event_id: str
    context_type: ContextType
    kind: str = Field(
        description="Godwit-minted sub-kind, e.g. 'holiday.us.thanksgiving' or "
        "'business.quarter_end'. A plain identifier, never free text."
    )
    origin: str = Field(description="Which context source produced this event.")
    start: Instant
    end: Instant
    scope: ContextScope = Field(default_factory=ContextScope)
    label: Tainted[str] | None = None
    permanent: bool = False
    derived_from: CandidateId | None = None

    @model_validator(mode="after")
    def _well_formed(self) -> Self:
        if self.end < self.start:
            raise ValueError("ContextEvent.end precedes start")
        for field, value in (("kind", self.kind), ("origin", self.origin)):
            if not is_safe_identifier(value):
                raise ValueError(f"ContextEvent.{field} must be a plain identifier")
        if self.label is not None and self.label.sensitivity is Sensitivity.DERIVED_STATISTIC:
            raise ValueError("ContextEvent.label is free text; it is never a statistic")
        return self

    @property
    def duration(self) -> _dt.timedelta:
        """How long the event lasts. Zero for an instant event."""
        return self.end - self.start


def event_id_for(*parts: str) -> str:
    """Deterministic event id from the adapter's own identifying parts.

    The parts may include a hash of imported text; they never include the text itself.
    """
    return str(content_hash(canonical_json(list(parts)), prefix="ctx"))
