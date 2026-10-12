"""Capturing everything a plugin could leak through: logs, stdout, stderr, warnings.

The leak test is a backstop, not the control -- the control is that tainted values are
typed and the SDK hands a plugin only the safe logger. But it is the backstop that
catches the plugin author who printed a row anyway, so it captures every channel a
Python process writes text to on its own:

* every :mod:`logging` record, at every level, from every logger that propagates;
* ``sys.stdout`` and ``sys.stderr`` (``print``, ``traceback.print_exc``);
* every warning, whatever the filters said.

Writes straight to file descriptors 1 and 2 (``os.write``) are not captured; the static
check refuses ``os.write`` instead.
"""

from __future__ import annotations

import contextlib
import io
import logging
import warnings
from collections.abc import Iterator
from dataclasses import dataclass, field

__all__ = ["Capture", "capture_egress"]


@dataclass(slots=True)
class Capture:
    """What was written while the capture was open, plus anything added by hand."""

    records: list[str] = field(default_factory=list)
    stdout: io.StringIO = field(default_factory=io.StringIO)
    stderr: io.StringIO = field(default_factory=io.StringIO)
    extra: list[str] = field(default_factory=list)

    def add(self, text: str) -> None:
        """Include ``text`` (an error message, a rendered result) in the scan."""
        self.extra.append(text)

    def text(self) -> str:
        """Everything captured, as one string."""
        return "\n".join(
            [*self.records, self.stdout.getvalue(), self.stderr.getvalue(), *self.extra]
        )

    def leaked(self, sentinels: tuple[str, ...]) -> tuple[str, ...]:
        """The sentinels that appear in what was captured."""
        rendered = self.text()
        return tuple(value for value in sentinels if value in rendered)


class _Collector(logging.Handler):
    def __init__(self, sink: list[str]) -> None:
        super().__init__(level=logging.NOTSET)
        self._sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        self._sink.append(f"{record.name} {record.levelname} {record.getMessage()}")
        if record.exc_info and record.exc_info[1] is not None:
            self._sink.append(repr(record.exc_info[1]))


@contextlib.contextmanager
def capture_egress() -> Iterator[Capture]:
    """Capture logs, stdout, stderr and warnings for the duration of the block."""
    capture = Capture()
    root = logging.getLogger()
    handler = _Collector(capture.records)
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        with (
            warnings.catch_warnings(record=True) as caught,
            contextlib.redirect_stdout(capture.stdout),
            contextlib.redirect_stderr(capture.stderr),
        ):
            warnings.simplefilter("always")
            try:
                yield capture
            finally:
                capture.records.extend(str(item.message) for item in caught)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)
