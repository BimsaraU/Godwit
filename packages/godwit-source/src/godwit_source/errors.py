"""Errors this package raises, and the one place driver exceptions are defused.

``SourceAdapter`` law 5: *driver exceptions are never propagated verbatim. They contain
rows.* A Postgres unique-violation message quotes the offending key. A pyarrow cast
error quotes the offending value. Letting one of those reach a log line, a trace span
or an alert is exactly the leak the taint system exists to prevent.

So: every adapter catches whatever the driver threw, calls :func:`sanitise_driver_error`
and raises the result. The original text survives as ``Tainted[str]`` with
``Acquisition.DRIVER_EXCEPTION``, which makes it DATA_VALUE by the acquisition floor and
therefore unreadable without an explicit ``reveal()`` inside the perimeter.
"""

from __future__ import annotations

import re
from typing import Final

from godwit_contracts.taint import Acquisition, Tainted, data_value

__all__ = [
    "DRIVER_ERROR_CLASSES",
    "MetadataUnavailableError",
    "SanitisedDriverError",
    "SourceError",
    "UnsupportedProbeError",
    "UnsupportedSourceError",
    "sanitise_driver_error",
]


class SourceError(Exception):
    """Base for every failure raised by godwit-source."""


class MetadataUnavailableError(SourceError):
    """The catalog could not answer a metadata question we require.

    Raised rather than guessed. A fabricated statistic is worse than a missing one:
    a detector cannot tell the difference, and a fabricated baseline produces a
    confident false pattern.
    """


class UnsupportedSourceError(SourceError):
    """This adapter cannot address the source it was handed."""


class UnsupportedProbeError(SourceError):
    """This adapter cannot answer this ``ProbeKind``. See the package's known limits."""


DRIVER_ERROR_CLASSES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("permission_denied", re.compile(r"permission denied|not authorized|access denied", re.I)),
    ("object_not_found", re.compile(r"does not exist|not found|no such (table|file|column)", re.I)),
    ("constraint_violation", re.compile(r"violates .*constraint|duplicate key", re.I)),
    ("type_conversion", re.compile(r"invalid input syntax|cannot cast|could not convert", re.I)),
    ("timeout", re.compile(r"timeout|timed out|canceling statement", re.I)),
    ("connection", re.compile(r"connection|could not connect|server closed", re.I)),
    ("syntax", re.compile(r"syntax error", re.I)),
)
"""Fixed classification vocabulary, matched against the driver text but never echoing it.

The left-hand side is the *only* thing that ever reaches a message. Adding a class here
means adding a constant string, never a capture group: a regex group would pipe driver
text straight back into the thing we are defusing.
"""


class SanitisedDriverError(SourceError):
    """A driver failure with its text removed.

    ``str(self)`` renders the classification and the driver's exception *type name* and
    nothing else. The original message is available as :attr:`original`, tainted
    DATA_VALUE, for code inside the perimeter that has a reason to look.
    """

    def __init__(self, classification: str, driver_type: str, original: Tainted[str]) -> None:
        self.classification = classification
        self.driver_type = driver_type
        self.original = original
        super().__init__(f"{driver_type} classified as {classification}; message withheld")


def sanitise_driver_error(
    exc: BaseException,
    *,
    source_id: str | None = None,
    table: str | None = None,
) -> SanitisedDriverError:
    """Turn a driver exception into one that is safe to raise, log and trace.

    ``table`` lands in the tainted value's provenance, not in the message: a table name
    is a SCHEMA_NAME disclosure on its own and the gate decides whether it travels.
    """
    text = str(exc)
    classification = "unclassified"
    for name, pattern in DRIVER_ERROR_CLASSES:
        if pattern.search(text):
            classification = name
            break
    return SanitisedDriverError(
        classification,
        type(exc).__name__,
        data_value(
            text,
            acquisition=Acquisition.DRIVER_EXCEPTION,
            source_id=source_id,
            table=table,
        ),
    )
