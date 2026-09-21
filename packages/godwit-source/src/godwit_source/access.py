"""Column access modes, resolved at plan time.

DATA PLANE. This module decides, before a single byte is read, whether a column may appear
in a projection at all (``OPEN``), may appear only wrapped in a keyed hash (``OPAQUE``), or
may not appear anywhere (``BLIND``). Nothing here filters results after the fact: a value
that was read has already been through process memory, a query log and possibly a driver
error message, so the only control that counts is the one applied to the plan.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from ._contracts import ColumnAccessMode, PiiClass

__all__ = [
    "MIN_OPAQUE_ENTROPY_BITS",
    "AccessPolicy",
    "BlindColumnError",
    "ColumnClassification",
    "Projection",
    "keyed_hash",
]

MIN_OPAQUE_ENTROPY_BITS = 30.0
"""Below this, a keyed hash is enumerable: an attacker hashes the whole input space and
joins. A four-digit PIN is 13.3 bits, an ISO country code about 7.8, a date of birth over a
century about 15.2. Such a column must be bucketed or blinded, never hashed and called safe.
"""


class BlindColumnError(RuntimeError):
    """Raised when a plan tries to touch a BLIND column. Not catchable-and-continue."""


@dataclass(frozen=True, slots=True)
class ColumnClassification:
    """What the system knows about one column's sensitivity.

    ``confirmed`` means a human signed it off. An unconfirmed classification -- including
    the first-pass guess produced by :mod:`godwit_source.profile` -- does not unlock
    anything: it is advisory input to A5 and to a reviewer.
    """

    column: str
    pii_class: PiiClass
    confirmed: bool = False
    requested_mode: ColumnAccessMode | None = None
    guardrail_id: str | None = None
    input_space_bits: float | None = None


def _bits_from_ndv(ndv: int | None) -> float | None:
    """Estimate input-space entropy from observed distinct count.

    ponytail: NDV is a proxy for the plausible input space, not the input space itself.
    It tracks the cases that matter (PINs, country codes, dates of birth all have small
    NDV), and it is free from Puffin/pg_stats. Replace with a per-class declared input
    space if a column ever appears whose NDV is large but whose domain is guessable.
    """
    if ndv is None or ndv <= 1:
        return None if ndv is None else 0.0
    return math.log2(ndv)


@dataclass(frozen=True, slots=True)
class Projection:
    """One column as it will appear in a generated query."""

    column: str
    mode: ColumnAccessMode
    sql: str


class AccessPolicy:
    """Resolves access modes and builds projections. Fails closed, always.

    Resolution order:

    1. Column has no classification, or an unconfirmed one -> ``BLIND``.
    2. Classification says ``SECRET`` or ``FREE_TEXT`` -> ``BLIND``, overriding any request.
    3. Requested ``OPEN`` without a recorded guardrail id -> ``OPAQUE`` if the column can
       carry a keyed hash, otherwise ``BLIND``.
    4. Identifiers default to ``OPAQUE``, subject to the minimum-entropy check.
    5. ``OPAQUE`` that fails the entropy check -> ``BLIND``.
    """

    def __init__(
        self,
        classifications: Iterable[ColumnClassification] = (),
        *,
        ndv_by_column: Mapping[str, int] | None = None,
        min_opaque_bits: float = MIN_OPAQUE_ENTROPY_BITS,
        hash_sql_template: str = "encode(hmac({col}::text, :godwit_key, 'sha256'), 'hex')",
    ) -> None:
        self._by_column = {c.column: c for c in classifications}
        self._ndv = dict(ndv_by_column or {})
        self._min_bits = min_opaque_bits
        self._hash_sql_template = hash_sql_template

    def classification(self, column: str) -> ColumnClassification | None:
        return self._by_column.get(column)

    def mode(self, column: str) -> ColumnAccessMode:
        """Resolve one column. An unknown column is BLIND; that is the whole point."""
        cls = self._by_column.get(column)
        if cls is None or not cls.confirmed:
            return ColumnAccessMode.BLIND
        if cls.pii_class in (PiiClass.SECRET, PiiClass.FREE_TEXT, PiiClass.UNKNOWN):
            return ColumnAccessMode.BLIND

        requested = cls.requested_mode
        if requested is ColumnAccessMode.OPEN:
            if cls.guardrail_id:
                return ColumnAccessMode.OPEN
            requested = ColumnAccessMode.OPAQUE
        if requested is None:
            requested = (
                ColumnAccessMode.OPEN
                if cls.pii_class is PiiClass.NON_PII
                else ColumnAccessMode.OPAQUE
            )
        if requested is ColumnAccessMode.OPEN:
            return ColumnAccessMode.OPEN

        bits = cls.input_space_bits
        if bits is None:
            bits = _bits_from_ndv(self._ndv.get(column))
        if bits is None or bits < self._min_bits:
            return ColumnAccessMode.BLIND
        return ColumnAccessMode.OPAQUE

    def is_blind(self, column: str) -> bool:
        return self.mode(column) is ColumnAccessMode.BLIND

    def assert_readable(self, column: str) -> ColumnAccessMode:
        mode = self.mode(column)
        if mode is ColumnAccessMode.BLIND:
            raise BlindColumnError(f"column {column!r} is BLIND and must never be read")
        return mode

    def plan(self, columns: Iterable[str]) -> list[Projection]:
        """Projections for the readable columns. BLIND columns are dropped from the plan.

        Dropping happens here, in the plan, which is why the resulting SQL and Arrow schema
        can be asserted on directly -- there is no later step that could have leaked.
        """
        out: list[Projection] = []
        for col in columns:
            mode = self.mode(col)
            if mode is ColumnAccessMode.BLIND:
                continue
            sql = (
                self._hash_sql_template.format(col=f'"{col}"')
                if mode is ColumnAccessMode.OPAQUE
                else f'"{col}"'
            )
            out.append(Projection(column=col, mode=mode, sql=sql))
        return out

    def metadata_readable(self, column: str) -> bool:
        """May this column's *values* (bounds, most_common_vals) be surfaced at all?

        ``OPEN`` only. An ``OPAQUE`` column still yields derived statistics -- how many
        distinct, how the count moved -- but never a bound and never a common value.
        """
        return self.mode(column) is ColumnAccessMode.OPEN


def keyed_hash(value: object, key: bytes, *, digest_bytes: int = 16) -> str:
    """HMAC-SHA256 of a value's text form, truncated. Key stays in the data plane.

    Used where the backend cannot hash for us -- Parquet has no server-side compute, so an
    Iceberg probe reads the column into a data-plane worker and hashes it there. The raw
    value never leaves that worker and is never placed in any emitted structure.
    """
    payload = b"\x00" if value is None else str(value).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()[: digest_bytes * 2]
