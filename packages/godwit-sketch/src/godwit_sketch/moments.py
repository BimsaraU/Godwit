"""Scalar summaries: :class:`Moments` and :class:`NullRate`.

MOMENTS HOLDS ROW VALUES. The brief groups Moments with HLL and Theta as a sketch that
carries no value out of a row. That is true of the count, the mean, the variance, the
skew and the kurtosis -- and false of the minimum and the maximum, which the brief also
asks for. The contracts are explicit about it:

    A mean is a derived statistic; the *maximum* of a column is not, because the
    maximum IS some row's value.

So :class:`Moments` is value-bearing, declares ``DATA_VALUE``, and returns its extremes
as :class:`~godwit_contracts.taint.Tainted`. Everything else it computes is a genuine
aggregate and comes back as a plain float.

This is also why :func:`~godwit_sketch.features.extract_features` exports no extreme and
nothing derived from one. Exporting ``max`` alongside ``mean``, ``stddev`` and ``count``
would be no better than exporting ``max`` directly: any function of the maximum plus
quantities the vector already carries solves back to the maximum. There is no
standardised, scale-free rearrangement that fixes this, so the extremes are simply
absent from the vector. See that module's layout table.

:class:`NullRate` is two counts and nothing else, so it is a derived statistic and is
exactly mergeable.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Mapping, Sequence
from typing import ClassVar, Final, Self

from godwit_contracts.sketch import ErrorBound, SketchKind
from godwit_contracts.taint import Acquisition, Sensitivity, Tainted, data_value

from godwit_sketch.base import (
    BaseSketch,
    ItemFlavour,
    MergeExactness,
    ParamValue,
    SketchItem,
    register,
)
from godwit_sketch.codec import decode_header, encode_container, read_exact

__all__ = ["Moments", "NullRate"]

_F64: Final[struct.Struct] = struct.Struct(">d")

_MIN_FOR_VARIANCE: Final[int] = 2
_MIN_FOR_SKEW: Final[int] = 3
_MIN_FOR_KURTOSIS: Final[int] = 4
"""Central moments need this many observations before they mean anything.

Below them the statistic is NaN rather than a number, because a "skewness" computed
from two rows is not a small-sample estimate, it is an artefact.
"""

_FLOAT_EPSILON: Final[float] = 1e-12
"""Documented accumulation error for the moment merge. See :meth:`Moments.error_bound`."""


@register
class Moments(BaseSketch):
    """Count, sum, extremes and the first four central moments.

    Carries ``(n, mean, M2, M3, M4, min, max)`` and merges with the Chan-Golub-LeVeque
    parallel formulas. Those, rather than raw power sums: summing ``x**4`` over a
    payments column and subtracting produces catastrophic cancellation once the mean is
    large relative to the spread, which is the normal case for money. The central-moment
    form stays accurate there.

    Merge exactness is :attr:`~godwit_sketch.base.MergeExactness.BOUNDED`, for a reason
    that has nothing to do with sketching: **floating-point addition is not
    associative.** ``(a+b)+c`` and ``a+(b+c)`` differ in the last bits, so the exact
    equality contract law 1 asks for cannot hold for any float-valued summary. The
    estimates agree to within accumulated rounding, and
    :class:`~godwit_sketch.hierarchy.TimeHierarchy` folds in a canonical order, so the
    hierarchy is byte-identical regardless.

    Takes no parameters: there is nothing to tune, and an empty parameter mapping means
    any two instances are mergeable.
    """

    KIND: ClassVar[SketchKind] = SketchKind.EXACT_COUNT
    CODEC: ClassVar[str] = "godwit-moments-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = True
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.BOUNDED
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.NUMERIC
    ACQUISITION: ClassVar[Acquisition] = Acquisition.COMPUTED_STATISTIC
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DATA_VALUE

    __slots__ = ("_m2", "_m3", "_m4", "_max", "_mean", "_min", "_n", "_nonfinite")

    def __init__(
        self,
        *,
        n: int,
        mean: float,
        m2: float,
        m3: float,
        m4: float,
        minimum: float | None,
        maximum: float | None,
        nonfinite: int,
    ) -> None:
        self._n = n
        self._mean = mean
        self._m2 = m2
        self._m3 = m3
        self._m4 = m4
        self._min = minimum
        self._max = maximum
        self._nonfinite = nonfinite

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """The empty summary. Merging it with anything returns that thing."""
        del params
        return cls(n=0, mean=0.0, m2=0.0, m3=0.0, m4=0.0, minimum=None, maximum=None, nonfinite=0)

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from numeric observations, by Welford update."""
        sketch = cls.identity(params)
        for item in items:
            if item is None or isinstance(item, tuple):
                continue
            try:
                sketch.update(float(item))
            except (TypeError, ValueError):
                continue
        return sketch

    def update(self, value: float) -> None:
        """Add one observation by Welford's online update. Mutates in place.

        Non-finite values are counted separately and excluded: one NaN in a payments
        column would otherwise turn every moment into NaN, which looks like a bug in
        this package rather than what it is, a data-quality signal.
        """
        if not math.isfinite(value):
            self._nonfinite += 1
            return
        n1 = self._n
        self._n += 1
        delta = value - self._mean
        delta_n = delta / self._n
        delta_n2 = delta_n * delta_n
        term = delta * delta_n * n1
        self._mean += delta_n
        self._m4 += (
            term * delta_n2 * (self._n * self._n - 3 * self._n + 3)
            + 6 * delta_n2 * self._m2
            - 4 * delta_n * self._m3
        )
        self._m3 += term * delta_n * (self._n - 2) - 3 * delta_n * self._m2
        self._m2 += term
        self._min = value if self._min is None else min(self._min, value)
        self._max = value if self._max is None else max(self._max, value)

    # -- identity -----------------------------------------------------------------------

    @property
    def params(self) -> Mapping[str, ParamValue]:
        """No parameters: any two Moments sketches are mergeable."""
        return {}

    @property
    def population(self) -> int:
        """Finite observations. Excludes nulls and non-finite values."""
        return self._n

    def nonfinite_count(self) -> int:
        """Observations excluded as NaN or infinite. A data-quality signal."""
        return self._nonfinite

    # -- statistics ---------------------------------------------------------------------

    def mean(self) -> float:
        """Arithmetic mean. An aggregate, so a plain float -- but see the small-cell note.

        Over a population of one the mean *is* that row's value, which is why
        :func:`~godwit_sketch.features.extract_features` blanks it below the small-cell
        threshold. This accessor does not: it is a data-plane accessor and the caller is
        expected to know its population.
        """
        return self._mean if self._n else math.nan

    def total(self) -> float:
        """Sum of the observations."""
        return self._mean * self._n

    def sum_of_squares(self) -> float:
        """Sum of squared observations, recovered from the central form."""
        return self._m2 + self._n * self._mean * self._mean if self._n else math.nan

    def variance(self, *, sample: bool = True) -> float:
        """Variance. Sample (``n-1``) by default, population when ``sample`` is False."""
        if self._n < _MIN_FOR_VARIANCE:
            return math.nan
        return self._m2 / (self._n - 1 if sample else self._n)

    def stddev(self, *, sample: bool = True) -> float:
        """Standard deviation."""
        variance = self.variance(sample=sample)
        if math.isnan(variance) or variance < 0:
            return math.nan
        return math.sqrt(variance)

    def skewness(self) -> float:
        """Population skewness. NaN below three observations or on a constant column."""
        if self._n < _MIN_FOR_SKEW or self._m2 <= 0:
            return math.nan
        return math.sqrt(self._n) * self._m3 / math.pow(self._m2, 1.5)

    def kurtosis(self) -> float:
        """Excess kurtosis: zero for a normal distribution."""
        if self._n < _MIN_FOR_KURTOSIS or self._m2 <= 0:
            return math.nan
        return self._n * self._m4 / (self._m2 * self._m2) - 3.0

    def coefficient_of_variation(self) -> float:
        """Standard deviation over the mean. Scale-free, so comparable across snapshots."""
        if not self._n or self._mean == 0:
            return math.nan
        return self.stddev() / abs(self._mean)

    def minimum(self) -> Tainted[float]:
        """The smallest value seen. A row's value, so ``Tainted`` DATA_VALUE."""
        return data_value(
            math.nan if self._min is None else self._min,
            acquisition=Acquisition.COMPUTED_STATISTIC,
            population=self._n,
        )

    def maximum(self) -> Tainted[float]:
        """The largest value seen. A row's value, so ``Tainted`` DATA_VALUE."""
        return data_value(
            math.nan if self._max is None else self._max,
            acquisition=Acquisition.COMPUTED_STATISTIC,
            population=self._n,
        )

    def error_bound(self) -> ErrorBound:
        """Exact up to floating-point accumulation. Nothing here is sampled."""
        return ErrorBound(
            kind="relative",
            epsilon=_FLOAT_EPSILON,
            note="moments are computed exactly; the bound is accumulated IEEE-754 "
            "rounding in the Chan parallel merge, not sampling error",
        )

    # -- the monoid ---------------------------------------------------------------------

    def merge(self, other: Self) -> Self:
        """Chan-Golub-LeVeque parallel combination of two moment summaries.

        The operands are put in a canonical order first, and that is load-bearing. The
        Chan formulas are asymmetric -- they compute the combined mean as *this* mean
        plus a correction -- so evaluating them as ``(a, b)`` and as ``(b, a)`` rounds
        differently in the last bits and returns two sketches that are mathematically
        equal and not byte-equal. Ordering by the encoded state makes the evaluation
        order a function of the contents, so ``a.merge(b)`` and ``b.merge(a)`` run the
        identical sequence of floating-point operations and commutativity holds exactly.

        Associativity still does not, because no re-ordering can make float addition
        associative. That is why this kind is BOUNDED.
        """
        self.require_mergeable(other)
        if not other._n:
            return self._copy_with_nonfinite(other._nonfinite)
        if not self._n:
            return other._copy_with_nonfinite(self._nonfinite)
        if self.encode() > other.encode():
            return other._merge_ordered(self)
        return self._merge_ordered(other)

    def _merge_ordered(self, other: Self) -> Self:
        """The Chan combination proper, with the operands already in canonical order."""
        na, nb = self._n, other._n
        n = na + nb
        delta = other._mean - self._mean
        delta2 = delta * delta
        mean = self._mean + delta * nb / n
        m2 = self._m2 + other._m2 + delta2 * na * nb / n
        m3 = (
            self._m3
            + other._m3
            + delta2 * delta * na * nb * (na - nb) / (n * n)
            + 3.0 * delta * (na * other._m2 - nb * self._m2) / n
        )
        m4 = (
            self._m4
            + other._m4
            + delta2 * delta2 * na * nb * (na * na - na * nb + nb * nb) / (n * n * n)
            + 6.0 * delta2 * (na * na * other._m2 + nb * nb * self._m2) / (n * n)
            + 4.0 * delta * (na * other._m3 - nb * self._m3) / n
        )
        return type(self)(
            n=n,
            mean=mean,
            m2=m2,
            m3=m3,
            m4=m4,
            minimum=_lesser(self._min, other._min),
            maximum=_greater(self._max, other._max),
            nonfinite=self._nonfinite + other._nonfinite,
        )

    def _copy_with_nonfinite(self, extra: int) -> Self:
        return type(self)(
            n=self._n,
            mean=self._mean,
            m2=self._m2,
            m3=self._m3,
            m4=self._m4,
            minimum=self._min,
            maximum=self._max,
            nonfinite=self._nonfinite + extra,
        )

    # -- serialisation -------------------------------------------------------------------

    def encode(self) -> bytes:
        """Fixed-width: counts, then the four moments, then the two extremes."""
        body = b"".join(
            (
                self._n.to_bytes(8, "big"),
                self._nonfinite.to_bytes(8, "big"),
                _F64.pack(self._mean),
                _F64.pack(self._m2),
                _F64.pack(self._m3),
                _F64.pack(self._m4),
                _pack_optional(self._min),
                _pack_optional(self._max),
            )
        )
        return encode_container(codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=body)

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        offset = header.body_offset
        raw, offset = read_exact(payload, offset, 8)
        n = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 8)
        nonfinite = int.from_bytes(raw, "big")
        moments: list[float] = []
        for _ in range(4):
            raw, offset = read_exact(payload, offset, _F64.size)
            moments.append(_F64.unpack(raw)[0])
        minimum, offset = _unpack_optional(payload, offset)
        maximum, offset = _unpack_optional(payload, offset)
        return cls(
            n=n,
            mean=moments[0],
            m2=moments[1],
            m3=moments[2],
            m4=moments[3],
            minimum=minimum,
            maximum=maximum,
            nonfinite=nonfinite,
        )


@register
class NullRate(BaseSketch):
    """Null count over total count. Two integers, exactly mergeable.

    The cheapest signal in the system and one of the most useful: a column whose null
    rate moves from 0.1% to 40% overnight is a silent data-quality collapse, and it is
    invisible to anything that looks only at the values that are present.

    Holds no value drawn from a row, so it is a derived statistic and needs no taint.
    """

    KIND: ClassVar[SketchKind] = SketchKind.EXACT_COUNT
    CODEC: ClassVar[str] = "godwit-nullrate-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = False
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.EXACT
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.CATEGORICAL
    ACQUISITION: ClassVar[Acquisition] = Acquisition.COMPUTED_STATISTIC
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DERIVED_STATISTIC

    __slots__ = ("_nulls", "_total")

    def __init__(self, *, nulls: int, total: int) -> None:
        if nulls > total:
            raise ValueError(f"null count {nulls} exceeds total {total}")
        self._nulls = nulls
        self._total = total

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """Zero nulls out of zero rows."""
        del params
        return cls(nulls=0, total=0)

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Count how many observations are null."""
        del params
        nulls = sum(1 for item in items if item is None)
        return cls(nulls=nulls, total=len(items))

    def update(self, item: SketchItem) -> None:
        """Observe one value, null or not. Mutates in place."""
        self._total += 1
        if item is None:
            self._nulls += 1

    @property
    def params(self) -> Mapping[str, ParamValue]:
        """No parameters: any two NullRate sketches are mergeable."""
        return {}

    @property
    def population(self) -> int:
        """Rows observed, null and non-null."""
        return self._total

    def nulls(self) -> int:
        """How many were null."""
        return self._nulls

    def rate(self) -> float:
        """Fraction null, or NaN over an empty population.

        NaN rather than zero: "no rows" and "no nulls" are different findings, and a
        detector that sees 0.0 for an empty partition will call it a clean column.
        """
        return self._nulls / self._total if self._total else math.nan

    def error_bound(self) -> ErrorBound:
        """Exact. Two counters, nothing sampled."""
        return ErrorBound(kind="exact", note="exact counts")

    def merge(self, other: Self) -> Self:
        """Add both counters. Integer addition, so exactly associative and commutative."""
        self.require_mergeable(other)
        return type(self)(nulls=self._nulls + other._nulls, total=self._total + other._total)

    def encode(self) -> bytes:
        """Two eight-byte counts."""
        body = self._nulls.to_bytes(8, "big") + self._total.to_bytes(8, "big")
        return encode_container(codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=body)

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        offset = header.body_offset
        raw_nulls, offset = read_exact(payload, offset, 8)
        raw_total, offset = read_exact(payload, offset, 8)
        return cls(nulls=int.from_bytes(raw_nulls, "big"), total=int.from_bytes(raw_total, "big"))


def _lesser(left: float | None, right: float | None) -> float | None:
    if left is None:
        return right
    return left if right is None else min(left, right)


def _greater(left: float | None, right: float | None) -> float | None:
    if left is None:
        return right
    return left if right is None else max(left, right)


def _pack_optional(value: float | None) -> bytes:
    """Presence byte then the double, so ``None`` and ``0.0`` cannot be confused."""
    return b"\x00" + _F64.pack(0.0) if value is None else b"\x01" + _F64.pack(value)


def _unpack_optional(payload: bytes, offset: int) -> tuple[float | None, int]:
    flag, offset = read_exact(payload, offset, 1)
    raw, offset = read_exact(payload, offset, _F64.size)
    return (None if flag == b"\x00" else _F64.unpack(raw)[0]), offset
