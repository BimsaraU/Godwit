"""``@context``: a custom explained-away source for the context layer (A8). L3.

A context source lists the mundane reasons the world changed -- a deploy, a campaign, a
holiday, a pipeline failure -- so that L3 can explain a drift away before a human is
paged about it. A plugin reads them from wherever they live (a deploy tracker, a
marketing calendar, an incident system) and returns :class:`ContextRecord` values with
plain fields. The base turns each into a ``godwit_context.ContextEvent``, and the part
that is easy to get wrong is done there:

* ``label`` is free text from outside Godwit. It becomes ``Tainted`` USER_SUPPLIED,
  which is DATA_VALUE: assume someone pasted a row into the campaign name, because
  someone did.
* ``columns`` are customer column names and become ``Tainted`` SCHEMA_NAME.
* ``key`` -- the backend's own id for the event -- is hashed into the event id and never
  stored. Use an opaque id, not a title: a hash of a short title is enumerable.
* ``kind`` must be a plain identifier (``deploy.payments``); free text is refused.
* events are filtered to the requested window and sorted, so the output is a pure
  function of what the backend returned -- which is what A8's replay needs.

The instance satisfies ``godwit_context.ContextSource`` and drops straight into
``collect_events`` and the router.
"""

from __future__ import annotations

import abc
import datetime as _dt
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Self

from godwit_context import ContextEvent, ContextScope, ContextType, event_id_for
from godwit_contracts.common import SourceId, is_safe_identifier, require_utc
from godwit_contracts.taint import Acquisition, data_value, schema_name

from godwit_sdk.capabilities import Capabilities, ResourceLimits
from godwit_sdk.errors import PluginFailedError
from godwit_sdk.plugin import (
    DEFAULT_REQUIREMENT,
    PluginBase,
    PluginKind,
    decorator_for,
)

__all__ = ["ContextBase", "ContextRecord", "context"]


@dataclass(frozen=True, slots=True)
class ContextRecord:
    """One event as the backend describes it. Plain fields; the base taints them."""

    key: str
    context_type: ContextType
    kind: str
    start: _dt.datetime
    end: _dt.datetime | None = None
    label: str | None = None
    source_ids: tuple[str, ...] = ()
    columns: tuple[str, ...] = field(default=())
    permanent: bool = False


class ContextBase(PluginBase, abc.ABC):
    """Base class for ``@context`` plugins. Implements ``godwit_context.ContextSource``."""

    SDK_METHODS = ("events", "name")

    @abc.abstractmethod
    def fetch(self, *, start: _dt.datetime, end: _dt.datetime) -> Iterable[ContextRecord]:
        """Records that may overlap ``[start, end]``. Over-returning is fine; the base filters."""

    @classmethod
    @abc.abstractmethod
    def for_conformance(cls, records: Sequence[ContextRecord]) -> Self:
        """An instance whose backend holds exactly ``records``.

        See ``SourceBase.for_conformance``: build the code path the real backend uses.
        """

    @property
    def name(self) -> str:
        """``ContextSource.name``: the plugin's qualified name."""
        return self.plugin_info().qualified_name

    def events(self, *, start: _dt.datetime, end: _dt.datetime) -> tuple[ContextEvent, ...]:
        """``ContextSource.events``: tainted, windowed, sorted, deduplicated."""
        records = tuple(self.runner.iterate("fetch", lambda: self.fetch(start=start, end=end)))
        built = {event.event_id: event for event in map(self._event, records)}
        return tuple(
            sorted(
                (e for e in built.values() if e.end >= start and e.start <= end),
                key=lambda e: (e.start, e.event_id),
            )
        )

    def _event(self, record: ContextRecord) -> ContextEvent:
        origin = self.name

        def bad(classification: str) -> PluginFailedError:
            return PluginFailedError(
                origin,
                stage="fetch",
                error_type="ContextRecord",
                classification=classification,
                original=None,
            )

        if not isinstance(record, ContextRecord):
            raise bad("not_a_context_record")
        if not is_safe_identifier(record.kind):
            raise bad("kind_is_not_a_plain_identifier")
        try:
            start = require_utc(record.start)
            end = require_utc(record.end) if record.end is not None else start
        except ValueError:
            raise bad("naive_datetime") from None
        if end < start:
            raise bad("end_precedes_start")
        label = None
        if record.label is not None:
            label = data_value(record.label, acquisition=Acquisition.USER_SUPPLIED)
        return ContextEvent(
            event_id=event_id_for(origin, record.key),
            context_type=record.context_type,
            kind=record.kind,
            origin=origin,
            start=start,
            end=end,
            scope=ContextScope(
                source_ids=tuple(SourceId(s) for s in record.source_ids),
                columns=tuple(schema_name(c) for c in record.columns),
            ),
            label=label,
            permanent=record.permanent,
        )


def context[C: ContextBase](
    *,
    name: str,
    namespace: str,
    version: str,
    summary: str = "",
    requires_sdk: str = DEFAULT_REQUIREMENT,
    capabilities: Capabilities | None = None,
    limits: ResourceLimits | None = None,
) -> Callable[[type[C]], type[C]]:
    """Register a :class:`ContextBase` subclass as a context-source plugin."""

    return decorator_for(
        PluginKind.CONTEXT,
        ContextBase,
        None,
        name=name,
        namespace=namespace,
        version=version,
        summary=summary,
        requires_sdk=requires_sdk,
        capabilities=capabilities,
        limits=limits,
    )
