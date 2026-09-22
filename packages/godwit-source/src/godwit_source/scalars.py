"""Comparing and measuring column bounds without leaking them.

A bound is a row value. Every function here takes revealed bounds, runs in the data
plane, and returns a number that carries nothing of the original: an ordering, a
position on a numeric axis, a similarity in [0, 1]. That is what lets ``bounds_drift``
report how far a bound moved without reporting what it moved to.

``ScalarValue`` spans nine Python types and most of the pairs are not comparable. Rather
than wrap comparisons in ``try: ... except TypeError``, which quietly turns a type bug
into a silent "no drift", each function narrows explicitly and returns ``None`` for
"cannot say".
"""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal, InvalidOperation

from godwit_contracts.common import ScalarValue

__all__ = ["as_axis", "prefix_similarity", "scalar_le"]


def scalar_le(left: ScalarValue, right: ScalarValue) -> bool | None:
    """``left <= right``, or ``None`` when the two are not comparable.

    ``bool`` is handled before ``int`` throughout, because ``True == 1`` in Python and a
    flag column compared against a count column is a bug we would rather see as
    ``None`` than as a confident answer.
    """
    if isinstance(left, bool) or isinstance(right, bool):
        return left <= right if isinstance(left, bool) and isinstance(right, bool) else None
    if isinstance(left, _dt.datetime) and isinstance(right, _dt.datetime):
        if (left.tzinfo is None) != (right.tzinfo is None):
            return None
        return left <= right
    if isinstance(left, _dt.datetime) or isinstance(right, _dt.datetime):
        return None
    if isinstance(left, _dt.date) and isinstance(right, _dt.date):
        return left <= right
    if isinstance(left, str) and isinstance(right, str):
        return left <= right
    if isinstance(left, bytes) and isinstance(right, bytes):
        return left <= right
    if isinstance(left, int | float | Decimal) and isinstance(right, int | float | Decimal):
        return bool(left <= right)
    return None


def as_axis(value: ScalarValue) -> float | None:
    """Place a bound on a numeric axis, or return ``None`` if it does not belong on one.

    Timestamps become POSIX seconds and dates become ordinal days, so a freshness stall
    and an amount spike are measurable by the same arithmetic. Strings and bytes have no
    axis; :func:`prefix_similarity` measures those instead.

    Naive datetimes are rejected rather than assumed UTC. Assuming a timezone is how two
    snapshots taken by two writers end up an hour apart for no reason.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            return None
        return value.timestamp()
    if isinstance(value, _dt.date):
        return float(value.toordinal())
    if isinstance(value, Decimal):
        try:
            return float(value)
        except (OverflowError, ValueError, InvalidOperation):
            return None
    if isinstance(value, int | float):
        return float(value)
    return None


def prefix_similarity(left: str, right: str) -> float:
    """Shared leading characters over the longer string, in [0, 1].

    The string analogue of "how far did this bound move". Two identical bounds score
    1.0; two bounds that diverge at the first character score 0.0. It is a crude
    measure and it is meant to be: its job is to survive Iceberg's 16-character bound
    truncation and to produce a number instead of a name.
    """
    if not left and not right:
        return 1.0
    longest = max(len(left), len(right))
    shared = 0
    for left_char, right_char in zip(left, right, strict=False):
        if left_char != right_char:
            break
        shared += 1
    return shared / longest
