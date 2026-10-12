"""The plugin-facing logger. Safe by construction; the only logger the SDK hands out.

A plugin author's first debugging instinct is ``print(row)`` or
``log.info(f"read {value}")``. Either one copies a customer value into a log, and a log
is an egress destination (``Destination.LOG``) that the gate allows *nothing* through.
So the logger a plugin gets from :attr:`PluginBase.log` has two rules, one checked by
mypy and one checked at runtime:

1. **The event is a literal label.** ``event`` is typed :class:`typing.LiteralString`,
   so pyright rejects ``log.info(f"read {value}")``. **mypy does not**: it treats
   ``LiteralString`` as ``str``. The check that holds under every type checker is the
   runtime one -- the event must look like ``probe.page_fetched`` (lowercase, digits,
   dots and underscores, at most 64 characters) or it is replaced by ``"<refused>"``.
   A customer name, an email or a sentence fails that shape; a single lowercase word
   would pass it, which is why values belong in fields, never in the event.
2. **Fields are numbers, flags, our enums, or tainted.** A field value is a ``bool``,
   ``int``, ``float``, ``None``, a member of a :class:`~enum.StrEnum` (your own
   vocabulary), or a :class:`~godwit_contracts.taint.Tainted` -- which is rendered as
   ``<withheld:data_value>`` and never unwrapped. A plain ``str`` is not in the union, so
   ``log.info("x", name=name)`` is a mypy error (``tests/typing_cases/must_fail.py``
   proves it); at runtime it renders ``"<refused>"``.

There is deliberately no way to get the underlying :class:`logging.Logger` from this
object, and no ``exc_info``: an exception message is where a driver puts the row. If a
plugin imports :mod:`logging` itself, the conformance kit's static check fails it.

Records go to the standard logger ``godwit.plugins.<namespace>.<name>`` as one JSON
object per line, so an operator configures handlers in the usual way.
"""

from __future__ import annotations

import json
import logging
import math
import re
from enum import StrEnum
from typing import Any, Final, LiteralString

from godwit_contracts.taint import Tainted

__all__ = ["LogValue", "PluginLogger"]

type LogValue = bool | int | float | StrEnum | Tainted[Any] | None
"""What a log field may hold. Note what is absent: ``str``."""

_REFUSED: Final[str] = "<refused>"
_EVENT: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){0,7}\Z")
_EVENT_MAX: Final[int] = 64


def _render(value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if isinstance(value, Tainted):
        return f"<withheld:{value.sensitivity.value}>"
    return _REFUSED


class PluginLogger:
    """Structured, value-free logging for one plugin. See the module docstring."""

    __slots__ = ("__plugin", "__sink")

    def __init__(self, plugin: str) -> None:
        self.__plugin = plugin
        self.__sink = logging.getLogger(f"godwit.plugins.{plugin}")

    def __repr__(self) -> str:
        return f"<PluginLogger {self.__plugin}>"

    def debug(self, event: LiteralString, /, **fields: LogValue) -> None:
        """Log at DEBUG."""
        self.__emit(logging.DEBUG, event, fields)

    def info(self, event: LiteralString, /, **fields: LogValue) -> None:
        """Log at INFO."""
        self.__emit(logging.INFO, event, fields)

    def warning(self, event: LiteralString, /, **fields: LogValue) -> None:
        """Log at WARNING."""
        self.__emit(logging.WARNING, event, fields)

    def error(self, event: LiteralString, /, **fields: LogValue) -> None:
        """Log at ERROR. There is no ``exc_info``; see the module docstring."""
        self.__emit(logging.ERROR, event, fields)

    def __emit(self, level: int, event: str, fields: dict[str, LogValue]) -> None:
        if not self.__sink.isEnabledFor(level):
            return
        safe_event = event if len(event) <= _EVENT_MAX and _EVENT.match(event) else _REFUSED
        record: dict[str, object] = {"plugin": self.__plugin, "event": safe_event}
        record.update({key: _render(value) for key, value in sorted(fields.items())})
        self.__sink.log(level, "%s", json.dumps(record, sort_keys=True))
