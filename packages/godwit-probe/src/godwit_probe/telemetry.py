"""Logs, traces and metrics that cannot carry a customer value.

DATA PLANE. ``LOG`` and ``TELEMETRY`` are egress destinations (``Destination`` in the
contracts), and they are the two that people forget. This module is the only way this
package emits either, and it is built so that the wrong thing does not type-check.

THE TYPE-LEVEL RULE
-------------------
Every field key is a member of :class:`Field`, and every field value is a
:data:`SafeValue`: a ``bool``, an ``int``, a ``float``, a member of one of *our* enums,
a :class:`SafeId`, or ``None``. A plain ``str`` is not in that union, and neither is a
``Tainted[...]`` -- so ``telemetry.event(Event.X, {Field.Y: column_name})`` is a mypy
error, not a review comment. ``tests/typing_cases/must_fail.py`` proves it by running
mypy.

THE RUNTIME RULE
----------------
Type hints are not enforced at runtime, so every value is checked again on the way out.
Anything outside the union is replaced by the marker ``"<refused>"`` and counted; it is
never rendered, not even its type name. Refusing to log is better than crashing a probe
over a log line, and a counter makes the refusal visible.

WHAT IS NOT LOGGED, ON PURPOSE
------------------------------
No row counts and no populations. "segment X (n=3)" re-identifies without quoting a
value, and a log line saying a segment probe read three rows is that sentence. Bytes and
file counts are logged: they measure what the probe cost, not how many people matched.

OpenTelemetry spans are opened with ``record_exception=False`` and
``set_status_on_exception=False``. The defaults attach the exception message to the span
as an event, and an exception message is where a driver puts the row.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from enum import StrEnum
from typing import Final

from godwit_contracts.common import content_hash
from opentelemetry.metrics import MeterProvider
from opentelemetry.trace import Span, Status, StatusCode, TracerProvider

__all__ = [
    "REFUSED_MARKER",
    "Event",
    "Field",
    "Metric",
    "ProbeTelemetry",
    "SafeId",
    "SafeValue",
    "SpanHandle",
]

REFUSED_MARKER: Final[str] = "<refused>"
_INSTRUMENTATION: Final[str] = "godwit-probe"


class Event(StrEnum):
    """Every log event and span name this package emits."""

    PROBE = "probe.execute"
    PROBE_REFUSED = "probe.refused"
    PROBE_NO_CHANGE = "probe.no_change"
    PROBE_CANCELLED = "probe.cancelled"
    PROBE_COMPLETED = "probe.completed"
    PROBE_FAILED = "probe.failed"
    POLL = "probe.poll"
    JOB_CLAIMED = "job.claimed"
    JOB_FINISHED = "job.finished"
    JOB_FAILED = "job.failed"
    JOB_LEASE_LOST = "job.lease_lost"


class Field(StrEnum):
    """Every field key. Reviewed as a list, because a key can be a disclosure too."""

    PROBE = "probe"
    SOURCE = "source"
    SNAPSHOT = "snapshot"
    SINCE = "since"
    KIND = "kind"
    STATUS = "status"
    REASON = "reason"
    CODE = "code"
    STAGE = "stage"
    MODE = "mode"
    BYTES_ESTIMATED = "bytes_estimated"
    BYTES_READ = "bytes_read"
    FILES = "files"
    SKETCHES = "sketches"
    JOB = "job"
    WORKER = "worker"
    ATTEMPT = "attempt"
    FULL_RESCAN = "full_rescan"


class Metric(StrEnum):
    """Every metric instrument."""

    OUTCOMES = "godwit.probe.outcomes"
    BYTES_READ = "godwit.probe.bytes_read"
    TELEMETRY_REFUSALS = "godwit.probe.telemetry_refusals"


_SAFE_ID: Final[re.Pattern[str]] = re.compile(r"\A[a-z]{2,8}_[0-9a-f]{8,64}\Z")


class SafeId:
    """An identifier rendered as ``prefix_hexdigits`` -- the only string a log may hold.

    Our own identifiers (probe keys, bundle ids) already have this shape. Anything else
    -- a source id, a snapshot id, a job id, all of which *we* minted but which are
    free-form strings -- goes through :meth:`of`, which hashes it. The hash is a stable
    handle for correlating log lines, and it cannot echo characters, which is the point:
    a snapshot id of ``41000`` and a salary of ``41000`` are the same five characters.
    """

    __slots__ = ("_text",)

    def __init__(self, text: str) -> None:
        if not _SAFE_ID.match(text):
            raise ValueError("a SafeId must look like prefix_hexdigits; use SafeId.of()")
        self._text = text

    @classmethod
    def of(cls, prefix: str, value: str) -> SafeId:
        """A stable, non-echoing handle for one of our free-form identifiers."""
        return cls(content_hash(value, prefix=prefix)[: len(prefix) + 1 + 16])

    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"SafeId({self._text})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SafeId) and other._text == self._text

    def __hash__(self) -> int:
        return hash(self._text)


type SafeValue = bool | int | float | StrEnum | SafeId | None
"""The only values a log field, span attribute or metric may carry. No ``str``."""


def _render(value: object) -> bool | int | float | str | None:
    """The runtime half of the rule. Returns the marker for anything outside the union."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, SafeId):
        return str(value)
    return REFUSED_MARKER


class SpanHandle:
    """Adds attributes to, and sets the status of, one open span. Same rules as a log."""

    __slots__ = ("_owner", "_span")

    def __init__(self, span: Span, owner: ProbeTelemetry) -> None:
        self._span = span
        self._owner = owner

    def set(self, field: Field, value: SafeValue) -> None:
        """Set one attribute."""
        rendered = self._owner.checked(value)
        if rendered is not None:
            self._span.set_attribute(field.value, rendered)

    def fail(self, reason: StrEnum) -> None:
        """Mark the span failed with a vocabulary member as the description."""
        self._span.set_status(Status(StatusCode.ERROR, reason.value))


class ProbeTelemetry:
    """The single emitter for logs, spans and metrics in this package.

    Providers are passed in rather than read from OpenTelemetry's globals, so that a test
    can install in-memory exporters without fighting the process-wide provider, and so
    that a worker does not silently export to whatever a library configured.
    """

    def __init__(
        self,
        *,
        logger: logging.Logger | None = None,
        tracer_provider: TracerProvider | None = None,
        meter_provider: MeterProvider | None = None,
    ) -> None:
        self._logger = logger if logger is not None else logging.getLogger("godwit_probe")
        self._tracer = (
            tracer_provider.get_tracer(_INSTRUMENTATION) if tracer_provider is not None else None
        )
        meter = meter_provider.get_meter(_INSTRUMENTATION) if meter_provider is not None else None
        self._outcomes = meter.create_counter(Metric.OUTCOMES.value) if meter else None
        self._bytes = meter.create_counter(Metric.BYTES_READ.value, unit="By") if meter else None
        self._refusals = meter.create_counter(Metric.TELEMETRY_REFUSALS.value) if meter else None
        self.refused_values = 0

    def checked(self, value: object) -> bool | int | float | str | None:
        rendered = _render(value)
        if rendered == REFUSED_MARKER and not isinstance(value, StrEnum | SafeId):
            self.refused_values += 1
            if self._refusals is not None:
                self._refusals.add(1)
        return rendered

    def event(self, name: Event, fields: Mapping[Field, SafeValue]) -> None:
        """Emit one structured log line: ``{"event": ..., <field>: <value>, ...}``."""
        record: dict[str, bool | int | float | str | None] = {"event": name.value}
        for key in sorted(fields, key=lambda item: item.value):
            record[Field(key).value] = self.checked(fields[key])
        self._logger.info(json.dumps(record, sort_keys=True, allow_nan=False))

    @contextmanager
    def span(self, name: Event, fields: Mapping[Field, SafeValue]) -> Iterator[SpanHandle | None]:
        """Open a span, or yield None when no tracer provider was configured."""
        if self._tracer is None:
            yield None
            return
        with self._tracer.start_as_current_span(
            name.value, record_exception=False, set_status_on_exception=False
        ) as span:
            handle = SpanHandle(span, self)
            for key, value in fields.items():
                handle.set(key, value)
            yield handle

    def outcome(self, *, status: StrEnum, kind: StrEnum, reason: StrEnum | None) -> None:
        """Count one probe outcome. Labels are enum members only."""
        if self._outcomes is None:
            return
        labels = {"status": status.value, "kind": kind.value}
        if reason is not None:
            labels["reason"] = reason.value
        self._outcomes.add(1, labels)

    def bytes_read(self, *, amount: int, kind: StrEnum) -> None:
        """Record bytes read by one probe."""
        if self._bytes is not None:
            self._bytes.add(amount, {"kind": kind.value})
