"""Segments, and the exact normalisation behind ``segment_key``.

A segment is ``(column, operator, value)`` repeated. The value is a real customer
value, which is why every predicate value is ``Tainted``. Segments travel inside every
candidate, pattern and alert, so getting this type wrong leaks data everywhere at once.

``segment_key`` must be byte-identical across independently written implementations --
the detector that finds a segment and the store that dedups it are written by different
agents who cannot talk to each other. The normalisation below is therefore specified to
the character, and ``tests/golden/segment_key_vectors.json`` pins it with test vectors.

THE NORMALISATION, IN FULL
==========================

Step 1 -- column name
    NFC-normalise, strip leading and trailing whitespace, then ``str.casefold()``.
    SQL identifiers are case-insensitive in practice and two agents must not disagree
    about ``Country`` versus ``country``.

Step 2 -- operator
    The lowercase ``Operator`` enum value. Nothing else.

Step 3 -- each value, rendered by :func:`canonical_scalar`, with a one-letter type tag
    so that ``1`` (int) and ``"1"`` (str) never collide::

        None            n:
        bool            b:true          b:false
        int             i:-42           i:0
        float           f:1.5   f:nan   f:inf   f:-inf      (-0.0 renders as f:0.0)
        Decimal         d:1.23  d:100   d:0                 (normalised, never sci-notation)
        bytes           y:deadbeef                          (lowercase hex)
        date            t:2024-01-31
        datetime        T:2024-01-31T12:00:00.000000Z       (UTC, always 6 fraction digits)
        str             s:<NFC text, case preserved>

    Values are data: case is preserved. Naive datetimes are rejected. Decimal NaN and
    Infinity are rejected.

Step 4 -- value group, by operator arity
    ``IS_NULL`` / ``NOT_NULL``   -> ``""`` (no values)
    single-value operators       -> the rendered scalar
    ``BETWEEN``                  -> ``[lo,hi]``, order preserved, it is meaningful
    ``IN`` / ``NOT_IN``          -> ``[a,b,c]``, duplicates removed, members sorted by
                                    Unicode code point of their rendered form

    Inside a bracketed group each member is escaped: ``\\`` -> ``\\\\``, then each of
    ``,`` ``[`` ``]`` gains a leading ``\\``. Without this, ``IN ('a,b')`` and
    ``IN ('a','b')`` would produce the same key.

Step 5 -- predicate
    The three-element JSON array ``[column, operator, value_group]``.

Step 6 -- segment
    The JSON array of predicate arrays, with exact duplicates removed and the rest
    sorted by Unicode code point of the three elements in order. Rendered with
    :func:`godwit_contracts.common.canonical_json`: no whitespace, ``ensure_ascii``
    false, keys sorted.

Step 7 -- key
    ``"seg_" + blake2b(canonical.encode("utf-8"), digest_size=16).hexdigest()``.

An empty segment means "the whole population" and canonicalises to ``[]``.
"""

from __future__ import annotations

import datetime as _dt
import math
import unicodedata
from decimal import Decimal
from enum import StrEnum
from typing import Final, Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    GodwitModel,
    NonNegInt,
    ScalarValue,
    SegmentKey,
    canonical_json,
    content_hash,
)
from godwit_contracts.taint import Sensitivity, Tainted

__all__ = [
    "Operator",
    "Predicate",
    "Segment",
    "canonical_column",
    "canonical_scalar",
    "canonical_segment",
    "segment_key",
]


class Operator(StrEnum):
    """The complete predicate vocabulary. Adding one changes every segment_key, so it
    is a contract change, not an implementation detail."""

    EQ = "eq"
    NE = "ne"
    LT = "lt"
    LE = "le"
    GT = "gt"
    GE = "ge"
    IN = "in"
    NOT_IN = "not_in"
    IS_NULL = "is_null"
    NOT_NULL = "not_null"
    BETWEEN = "between"
    PREFIX = "prefix"


_NULLARY: Final[frozenset[Operator]] = frozenset({Operator.IS_NULL, Operator.NOT_NULL})
_SET_VALUED: Final[frozenset[Operator]] = frozenset({Operator.IN, Operator.NOT_IN})
_UTC_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S.%f"


def canonical_column(name: str) -> str:
    """Normalise a column name for keying: NFC, stripped, casefolded."""
    return unicodedata.normalize("NFC", name).strip().casefold()


def canonical_scalar(value: ScalarValue) -> str:
    """Render one predicate value into its tagged canonical form. See module docstring."""
    if value is None:
        return "n:"
    if isinstance(value, bool):
        # Must precede the int branch: bool is a subclass of int.
        return "b:true" if value else "b:false"
    if isinstance(value, int):
        return f"i:{value:d}"
    if isinstance(value, float):
        return f"f:{_canonical_float(value)}"
    if isinstance(value, Decimal):
        return f"d:{_canonical_decimal(value)}"
    if isinstance(value, bytes):
        return f"y:{value.hex()}"
    if isinstance(value, _dt.datetime):
        # Must precede date: datetime is a subclass of date.
        return f"T:{_canonical_datetime(value)}"
    if isinstance(value, _dt.date):
        return f"t:{value.isoformat()}"
    if isinstance(value, str):
        return f"s:{unicodedata.normalize('NFC', value)}"
    raise TypeError(f"{type(value)!r} is not a canonicalisable predicate value")


def _canonical_float(value: float) -> str:
    if math.isnan(value):
        return "nan"
    if math.isinf(value):
        return "inf" if value > 0 else "-inf"
    if value == 0.0:
        return "0.0"  # collapses -0.0
    return repr(value)


def _canonical_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("Decimal NaN and Infinity cannot appear in a segment predicate")
    if value == 0:
        return "0"
    return format(value.normalize(), "f")


def _canonical_datetime(value: _dt.datetime) -> str:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("naive datetime cannot appear in a segment predicate")
    return value.astimezone(_dt.UTC).strftime(_UTC_FORMAT) + "Z"


def _escape_member(rendered: str) -> str:
    escaped = rendered.replace("\\", "\\\\")
    for char in (",", "[", "]"):
        escaped = escaped.replace(char, "\\" + char)
    return escaped


class Predicate(GodwitModel):
    """One ``(column, operator, values)`` triple.

    ``column`` is SCHEMA_NAME-tainted; ``values`` are DATA_VALUE-tainted, or TOKEN once
    the gate has substituted them. A predicate value can never be a derived statistic:
    if it were, it would not be selecting rows.
    """

    column: Tainted[str]
    op: Operator
    values: tuple[Tainted[ScalarValue], ...] = ()

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        if self.column.sensitivity is not Sensitivity.SCHEMA_NAME:
            raise ValueError("Predicate.column must be tainted SCHEMA_NAME")
        for value in self.values:
            if value.sensitivity not in (Sensitivity.DATA_VALUE, Sensitivity.TOKEN):
                raise ValueError(
                    "Predicate values are row values: they must be tainted DATA_VALUE, "
                    "or TOKEN after the gate has substituted them"
                )
        expected = _expected_arity(self.op)
        if expected is not None and len(self.values) != expected:
            raise ValueError(f"operator {self.op} takes {expected} value(s)")
        if self.op in _SET_VALUED and not self.values:
            raise ValueError(f"operator {self.op} needs at least one value")
        return self

    def canonical_form(self) -> list[str]:
        """The three-element array this predicate contributes to the segment key."""
        return [
            canonical_column(self.column.reveal()),
            self.op.value,
            self._canonical_values(),
        ]

    def _canonical_values(self) -> str:
        rendered = [canonical_scalar(value.reveal()) for value in self.values]
        if self.op in _NULLARY:
            return ""
        if self.op is Operator.BETWEEN:
            return "[" + ",".join(_escape_member(item) for item in rendered) + "]"
        if self.op in _SET_VALUED:
            unique = sorted(set(rendered))
            return "[" + ",".join(_escape_member(item) for item in unique) + "]"
        return rendered[0]


def _expected_arity(op: Operator) -> int | None:
    if op in _NULLARY:
        return 0
    if op is Operator.BETWEEN:
        return 2
    if op in _SET_VALUED:
        return None
    return 1


class Segment(GodwitModel):
    """A slice of a population, identified by a stable key.

    The key is a pseudonym, not an anonymisation: see the ``SegmentKey`` warning in
    ``godwit_contracts.common``. Carry ``population`` wherever you can, because
    small-cell suppression needs it and "unknown" has to mean "unsafe".
    """

    predicates: tuple[Predicate, ...] = ()
    population: NonNegInt | None = Field(
        default=None,
        description="Rows matching this segment, when known. None means unknown, "
        "which small-cell rules must treat as too small to disclose.",
    )

    def canonical_form(self) -> str:
        """The exact string that is hashed into :attr:`key`."""
        return canonical_segment(self)

    @property
    def key(self) -> SegmentKey:
        """The stable dedup and join key for this segment."""
        return segment_key(self)

    @property
    def is_universe(self) -> bool:
        """True when this segment selects the whole population."""
        return not self.predicates


def canonical_segment(segment: Segment) -> str:
    """Render a segment to its canonical JSON string. See the module docstring."""
    forms = [predicate.canonical_form() for predicate in segment.predicates]
    deduped = {tuple(form): form for form in forms}
    ordered = [deduped[key] for key in sorted(deduped)]
    return canonical_json(ordered)


def segment_key(segment: Segment) -> SegmentKey:
    """Hash a segment's canonical form into its stable key."""
    return SegmentKey(content_hash(canonical_segment(segment), prefix="seg"))
