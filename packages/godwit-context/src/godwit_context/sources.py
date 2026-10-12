"""Context source adapters: the small interface deployments implement to add their own.

A context source has a name and answers one question: which events overlap
``[start, end]``? Built-in sources:

* ``StaticSource`` -- a fixed list. Campaign calendars, market and macro feeds and
  anything else imported in bulk land here, via ``import_records`` (generic API import)
  or ``import_csv``.
* ``parse_deploy_webhook`` -- one deploy or release event from a CI/CD webhook body.
* ``data_quality_from_candidates`` -- schema migrations found by A1's metadata detectors,
  turned into DATA_QUALITY context. Pipeline failures and late partitions come in
  through ``import_records`` with ``ContextType.DATA_QUALITY``.
* ``AnnotationBook`` -- manual analyst annotations, which are permanent.
* ``HolidaySource`` and ``BusinessCalendarSource`` live in their own modules.

Imported free text (a deploy description, a campaign name, an analyst note) becomes a
``Tainted`` ``USER_SUPPLIED`` label. Error messages from this module name the field that
was wrong and never echo its value: an import file is customer-adjacent text and an error
message is a log line.
"""

from __future__ import annotations

import csv
import datetime as _dt
import io
from collections.abc import Iterable, Mapping, Sequence
from typing import Final, Protocol, runtime_checkable

from godwit_contracts import (
    Acquisition,
    AuditEvent,
    Candidate,
    Instant,
    Operator,
    Plane,
    Predicate,
    Segment,
    SourceId,
    Tainted,
    canonical_json,
    content_hash,
    data_value,
    require_utc,
    schema_name,
)
from godwit_contracts.common import is_safe_identifier

from godwit_context.audit import AuditSink
from godwit_context.events import ContextEvent, ContextScope, ContextType, event_id_for

__all__ = [
    "DEFAULT_DQ_DETECTORS",
    "AnnotationBook",
    "ContextImportError",
    "ContextSource",
    "StaticSource",
    "collect_events",
    "data_quality_from_candidates",
    "import_csv",
    "import_records",
    "parse_deploy_webhook",
]


@runtime_checkable
class ContextSource(Protocol):
    """Anything that can list the context events overlapping a window."""

    @property
    def name(self) -> str: ...

    def events(self, *, start: _dt.datetime, end: _dt.datetime) -> tuple[ContextEvent, ...]: ...


class ContextImportError(ValueError):
    """An imported record was malformed. The message names the field, never the value."""


def _overlapping(
    events: Iterable[ContextEvent], start: _dt.datetime, end: _dt.datetime
) -> tuple[ContextEvent, ...]:
    return tuple(
        sorted(
            (e for e in events if e.end >= start and e.start <= end),
            key=lambda e: (e.start, e.event_id),
        )
    )


class StaticSource:
    """A fixed set of events. Duplicate ids collapse to one."""

    def __init__(self, name: str, events: Iterable[ContextEvent]) -> None:
        self._name = name
        self._events = {e.event_id: e for e in events}

    @property
    def name(self) -> str:
        return self._name

    def events(self, *, start: _dt.datetime, end: _dt.datetime) -> tuple[ContextEvent, ...]:
        return _overlapping(self._events.values(), start, end)


# --------------------------------------------------------------------------------------
# Generic import
# --------------------------------------------------------------------------------------


def _text(record: Mapping[str, object], field: str) -> str | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ContextImportError(f"field {field!r} must be text")
    return value.strip()


def _list(record: Mapping[str, object], field: str) -> tuple[str, ...]:
    value = record.get(field)
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(";") if part.strip())
    if isinstance(value, Sequence) and all(isinstance(v, str) for v in value):
        return tuple(str(v).strip() for v in value)
    raise ContextImportError(f"field {field!r} must be text or a list of text")


def _instant(record: Mapping[str, object], field: str) -> _dt.datetime | None:
    value = record.get(field)
    if value is None or value == "":
        return None
    if isinstance(value, _dt.datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = _dt.datetime.fromisoformat(value.strip())
        except ValueError:
            raise ContextImportError(f"field {field!r} is not an ISO-8601 instant") from None
    else:
        raise ContextImportError(f"field {field!r} must be an ISO-8601 instant")
    try:
        return require_utc(parsed)
    except ValueError:
        raise ContextImportError(f"field {field!r} has no timezone") from None


def _segment(record: Mapping[str, object]) -> tuple[Segment, ...]:
    """``segment`` is ``col=value&col2=value2`` or a mapping. Values are strings."""
    raw = record.get("segment")
    if raw is None or raw == "":
        return ()
    pairs: list[tuple[str, str]]
    if isinstance(raw, str):
        pairs = []
        for part in raw.split("&"):
            column, sep, value = part.partition("=")
            if not sep or not column.strip():
                raise ContextImportError("field 'segment' must be col=value&col=value")
            pairs.append((column.strip(), value.strip()))
    elif isinstance(raw, Mapping) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
    ):
        pairs = [(str(k), str(v)) for k, v in raw.items()]
    else:
        raise ContextImportError("field 'segment' must be text or a mapping of text")
    predicates = tuple(
        Predicate(
            column=schema_name(column),
            op=Operator.EQ,
            values=(data_value(value, acquisition=Acquisition.USER_SUPPLIED, column=column),),
        )
        for column, value in pairs
    )
    return (Segment(predicates=predicates),)


def import_records(
    records: Iterable[Mapping[str, object]],
    *,
    context_type: ContextType,
    origin: str,
) -> tuple[ContextEvent, ...]:
    """Generic API import. One event per record.

    Fields: ``start`` (required, ISO-8601 with a timezone), ``end`` (defaults to
    ``start``), ``kind`` (a plain identifier; defaults to ``imported``), ``source_ids``
    and ``columns`` (lists, or ``;``-separated text; empty ``source_ids`` means global),
    ``segment`` (``col=value&col2=value2`` or a mapping), ``label`` (free text, tainted)
    and ``id`` (the upstream system's id; only its hash is kept).
    """
    if not is_safe_identifier(origin):
        raise ContextImportError("origin must be a plain identifier")
    out: list[ContextEvent] = []
    for index, record in enumerate(records):
        try:
            out.append(_one_record(record, context_type=context_type, origin=origin))
        except ContextImportError as error:
            raise ContextImportError(f"record {index}: {error}") from None
    return tuple(out)


def _one_record(
    record: Mapping[str, object], *, context_type: ContextType, origin: str
) -> ContextEvent:
    start = _instant(record, "start")
    if start is None:
        raise ContextImportError("field 'start' is required")
    end = _instant(record, "end") or start
    if end < start:
        raise ContextImportError("field 'end' precedes 'start'")
    sub_kind = _text(record, "kind") or "imported"
    kind = f"{context_type.value}.{sub_kind}"
    if not is_safe_identifier(kind):
        raise ContextImportError("field 'kind' must be a plain identifier")
    label_text = _text(record, "label")
    label: Tainted[str] | None = (
        None
        if label_text is None
        else data_value(label_text, acquisition=Acquisition.USER_SUPPLIED)
    )
    source_ids = tuple(sorted(SourceId(s) for s in _list(record, "source_ids")))
    columns = tuple(schema_name(c) for c in _list(record, "columns"))
    upstream = _text(record, "id")
    identity = str(
        content_hash(
            canonical_json(
                upstream
                if upstream is not None
                else {k: str(v) for k, v in sorted(record.items(), key=lambda kv: kv[0])}
            )
        )
    )
    return ContextEvent(
        event_id=event_id_for(origin, context_type.value, identity),
        context_type=context_type,
        kind=kind,
        origin=origin,
        start=start,
        end=end,
        scope=ContextScope(source_ids=source_ids, columns=columns, segments=_segment(record)),
        label=label,
    )


def import_csv(text: str, *, context_type: ContextType, origin: str) -> tuple[ContextEvent, ...]:
    """CSV import. A header row names the same fields as ``import_records``."""
    return import_records(
        list(csv.DictReader(io.StringIO(text))), context_type=context_type, origin=origin
    )


def parse_deploy_webhook(payload: Mapping[str, object]) -> ContextEvent:
    """One deploy or release from a webhook body.

    Accepts ``deployed_at`` or ``started_at`` for the start, ``finished_at`` for the end,
    ``deploy_id`` or ``id``, ``description`` as the label, and the scope fields of
    ``import_records``. A rollback is a deploy too: it changes behaviour from its own time.
    """
    record = {
        "id": payload.get("deploy_id", payload.get("id")),
        "start": payload.get("deployed_at", payload.get("started_at")),
        "end": payload.get("finished_at"),
        "kind": payload.get("kind", "release"),
        "source_ids": payload.get("source_ids"),
        "columns": payload.get("columns"),
        "segment": payload.get("segment"),
        "label": payload.get("description"),
    }
    (event,) = import_records([record], context_type=ContextType.DEPLOY, origin="deploy_webhook")
    return event


# --------------------------------------------------------------------------------------
# Data quality, from A1's metadata detectors
# --------------------------------------------------------------------------------------

DEFAULT_DQ_DETECTORS: Final[Mapping[str, str]] = {
    "metadata.schema_change": "data_quality.schema_migration",
}
"""A1 detector name -> context kind. Only events that ARE data-quality incidents belong
here: a row-volume anomaly may be a late partition or may be fraud, so it is a candidate
to be explained, not context to explain with."""


def data_quality_from_candidates(
    candidates: Iterable[Candidate],
    *,
    detectors: Mapping[str, str] = DEFAULT_DQ_DETECTORS,
) -> tuple[ContextEvent, ...]:
    """Turn A1 schema-change candidates into DATA_QUALITY context for their source.

    The event starts at the candidate's ``created_at`` and remembers the candidate it came
    from, so the router never lets a schema change explain itself away.
    """
    out: list[ContextEvent] = []
    for candidate in candidates:
        kind = detectors.get(candidate.lineage.detector)
        if kind is None:
            continue
        out.append(
            ContextEvent(
                event_id=event_id_for("a1_metadata", kind, str(candidate.candidate_id)),
                context_type=ContextType.DATA_QUALITY,
                kind=kind,
                origin="a1_metadata",
                start=candidate.created_at,
                end=candidate.created_at,
                scope=ContextScope(source_ids=(candidate.source_id,)),
                derived_from=candidate.candidate_id,
            )
        )
    return tuple(out)


# --------------------------------------------------------------------------------------
# Analyst annotations
# --------------------------------------------------------------------------------------


class AnnotationBook:
    """Manual analyst annotations. Permanent: once written, they apply for ever.

    Every annotation is audited (who, when, which event id) through the sink. The note
    itself is tainted ``USER_SUPPLIED`` and is not in the audit record.
    """

    name: Final = "annotations"

    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink
        self._events: dict[str, ContextEvent] = {}

    def annotate(
        self,
        *,
        author: str,
        at: Instant,
        start: Instant,
        end: Instant,
        source_ids: Sequence[SourceId] = (),
        columns: Sequence[str] = (),
        segment: Mapping[str, str] | None = None,
        note: str | None = None,
        kind: str = "analyst",
    ) -> ContextEvent:
        """Record that ``[start, end]`` on these sources has a known, mundane cause."""
        if not is_safe_identifier(author):
            raise ContextImportError("author must be a reviewer id, not a name")
        record: dict[str, object] = {
            "start": start,
            "end": end,
            "kind": kind,
            "source_ids": list(source_ids),
            "columns": list(columns),
            "segment": dict(segment) if segment else None,
            "label": note,
            "id": f"{author}|{at.isoformat()}|{len(self._events)}",
        }
        (event,) = import_records([record], context_type=ContextType.ANNOTATION, origin=self.name)
        event = event.model_copy(update={"permanent": True})
        self._events[event.event_id] = event
        self._sink.append(
            AuditEvent(
                event_id=event_id_for("annotate", event.event_id),
                occurred_at=at,
                actor=author,
                action="context_annotate",
                subject_kind="context_event",
                subject_id=event.event_id,
                plane=Plane.CONTROL,
            ),
            to_state="permanent",
        )
        return event

    def events(self, *, start: _dt.datetime, end: _dt.datetime) -> tuple[ContextEvent, ...]:
        return _overlapping(self._events.values(), start, end)

    def get(self, event_id: str) -> ContextEvent | None:
        return self._events.get(event_id)


def collect_events(
    sources: Iterable[ContextSource], *, start: _dt.datetime, end: _dt.datetime
) -> tuple[ContextEvent, ...]:
    """Every event from every source overlapping ``[start, end]``, deduplicated by id."""
    found = {e.event_id: e for source in sources for e in source.events(start=start, end=end)}
    return tuple(sorted(found.values(), key=lambda e: (e.start, e.event_id)))
