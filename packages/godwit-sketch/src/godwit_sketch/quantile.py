"""Quantiles: :class:`KllQuantile`, a deterministic KLL implemented in this package.

WHY THIS IS NOT A WRAPPER
-------------------------
The stack says to use the Apache DataSketches KLL binding. It cannot be used here, and
the reason is not a preference. Measured on ``datasketches==5.2.0``:

* Building the *same* sketch from the *same* values twice in the *same* process gives
  two different serialisations, as soon as ``n`` exceeds ``k`` and the first compaction
  happens. Below that threshold it is exact and stable; above it, it is not.
* The same holds for ``quantiles_floats_sketch`` and ``req_floats_sketch``.
* The constructor exposes ``k`` and nothing else. There is no seed to pin.

KLL compacts by discarding either the odd-indexed or the even-indexed half of a sorted
buffer, chosen by a fair coin. Upstream draws that coin from a process RNG nobody can
reach. That is a perfectly good engineering choice for a general-purpose library and an
impossible one here: universal rule 5 forbids unseeded randomness anywhere that can
produce a pattern or a prediction, and invariant 7 requires every pattern to reproduce
from ``(probe spec, snapshot id, version, seed)``. A sketch that differs between two
runs over identical data makes both unachievable, and the divergence would surface as
phantom drift in L2 -- a detector cannot tell "the data moved" from "the sketch was
rebuilt".

So the coin is replaced. Here it is a keyed hash of the buffer being compacted, its
level, and the sketch's explicit seed: a *pure function of content*. Same data, same
seed, same bytes, on any machine, in any process, for ever.

``tests/test_upstream_determinism.py`` pins the upstream behaviour that forced this, so
that if a future DataSketches release becomes seedable, the next maintainer finds a
failing test telling them this module can be retired rather than having to rediscover
the problem. See ``docs/change-requests/CR-A2-kll-determinism.md``.

WHAT THIS COSTS
---------------
The published KLL error constants were fitted for independent fair coins. Hash-derived
bits are deterministic, so the guarantee holds against inputs chosen without knowledge
of the seed, and is *not* a guarantee against an adversary who knows it and crafts a
stream to defeat the compaction schedule. The observed error is measured against exact
quantiles on a million rows in ``docs/packages/godwit-sketch.md``; it is the evidence
for the bound, and the bound is stated as empirical because that is what it is.

DISCLOSURE -- READ THIS
-----------------------
**A KLL payload contains real row values.** It retains a sample of the actual items it
saw, and it holds the exact minimum and maximum. Feed it a salary column and its bytes
contain real salaries; feed it a date of birth column and they are real dates of birth.

The contracts classify only ``COUNT_MIN`` and ``FREQUENT_ITEMS`` as item-bearing, and
``tests/golden/sketch_envelopes.json`` ships a ``kll`` envelope declared
``derived_statistic``. That is a leak path. This class declares ``DATA_VALUE`` -- an
envelope may always be declared *more* restricted than its floor -- and
:meth:`quantile`, :meth:`minimum` and :meth:`maximum` return ``Tainted``. See
``docs/change-requests/CR-A2-kll-is-item-bearing.md``.

:meth:`cdf` is the safe export and the one detectors should use: a cumulative fraction
at a caller-supplied grid point is a count over a population, not a value out of a row.
The grid must come from the probe's parameters. A grid derived from the data is a
segment predicate wearing a costume, and it belongs in a ``Segment``.
"""

from __future__ import annotations

import bisect
import functools
import hashlib
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
from godwit_sketch.errors import SketchDecodeError

__all__ = ["DEFAULT_KLL_K", "KLL_CDF_COEF", "KLL_CDF_EXP", "KllQuantile"]

DEFAULT_KLL_K: Final[int] = 200
"""Default buffer parameter. Matches the DataSketches default, so the bounds compare."""

_MIN_K: Final[int] = 8
_MAX_K: Final[int] = 65535

KLL_CDF_COEF: Final[float] = 2.296
KLL_CDF_EXP: Final[float] = 0.9723
"""Normalised rank error ``eps = 2.296 / k**0.9723`` at one standard deviation.

These are the DataSketches empirical constants for the same ``2/3`` capacity schedule
this implementation uses. They are quoted rather than re-derived, and they are checked
against exact quantiles in the accuracy benchmark.
"""

_MIN_LEVEL_CAPACITY: Final[int] = 8
_LEVEL_DECAY: Final[float] = 2.0 / 3.0
_MAX_LEVELS: Final[int] = 60
"""Sixty doublings is 2**60 items. A level count above this means a corrupt payload."""

_F64: Final[struct.Struct] = struct.Struct(">d")


@functools.lru_cache(maxsize=4096)
def _total_level_capacity(k: int, num_levels: int) -> int:
    """Total items the sketch may retain at this depth.

    Cached because :meth:`KllQuantile._compress` consults it on every single update, and
    it depends on nothing but ``(k, num_levels)`` -- a pair that takes a handful of
    distinct values over the life of a process.
    """
    return sum(_level_capacity(k, num_levels, level) for level in range(num_levels))


def _level_capacity(k: int, num_levels: int, level: int) -> int:
    """Capacity of one level, measured as depth *below the top*.

    The schedule is indexed from the top, not the bottom: the heaviest level in use gets
    the full ``k`` and each level below it is two thirds the size of the one above. So
    the capacity of a given level *shrinks* as the sketch grows new levels above it.

    Indexing this from the bottom instead -- giving level 0 the full ``k`` -- looks
    equivalent and is not. A level of capacity ``c`` promotes ``c/2`` items upward; with
    a bottom-indexed schedule the level above has capacity ``2c/3``, which is smaller
    than the ``c/2`` it just received once bulk promotions push it past its limit, so
    every compaction cascades to the top and drains the low levels. The sketch still
    answers queries and still satisfies the weight invariant, so nothing crashes -- it
    just silently holds a fortieth of the items it should and roughly triples its rank
    error. Top-indexed, a level receives ``c/2`` into a capacity of ``1.5c`` and the
    cascade cannot start.
    """
    depth = num_levels - level - 1
    return max(_MIN_LEVEL_CAPACITY, math.ceil(k * _LEVEL_DECAY**depth))


@register
class KllQuantile(BaseSketch):
    """Streaming quantiles with a normalised rank error bound. Deterministic.

    Parameters: ``k`` (buffer size, default :data:`DEFAULT_KLL_K`) and ``seed`` (keys
    the compaction hash; two sketches merge only if both match).

    Merge exactness is :attr:`~godwit_sketch.base.MergeExactness.BOUNDED`. Once a
    compaction has discarded half a buffer to stay inside the size bound, a later merge
    cannot recover it, and a different bracketing discards a different half. No bounded
    quantile summary can be exactly associative; the estimates agree within the error
    bound, and :class:`~godwit_sketch.hierarchy.TimeHierarchy` gets byte-identical
    results anyway by folding in a canonical order.
    """

    KIND: ClassVar[SketchKind] = SketchKind.KLL
    CODEC: ClassVar[str] = "godwit-kll-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = True
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.BOUNDED
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.NUMERIC
    ACQUISITION: ClassVar[Acquisition] = Acquisition.QUANTILE
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DATA_VALUE

    __slots__ = ("_grid", "_k", "_levels", "_max", "_min", "_n", "_nonfinite", "_seed")

    def __init__(
        self,
        *,
        k: int,
        seed: int,
        levels: list[list[float]],
        n: int,
        minimum: float | None,
        maximum: float | None,
        nonfinite: int,
        grid: str = "",
    ) -> None:
        self._k = k
        self._seed = seed
        self._grid = grid
        self._levels = levels
        self._n = n
        self._min = minimum
        self._max = maximum
        self._nonfinite = nonfinite

    # -- construction -------------------------------------------------------------------

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """The empty sketch. Merging it with anything returns that thing unchanged."""
        k, seed, grid = cls._params_of(params)
        return cls(
            k=k, seed=seed, levels=[[]], n=0, minimum=None, maximum=None, nonfinite=0, grid=grid
        )

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from numeric observations.

        Nulls and non-finite values (NaN, infinities) are not orderable and cannot
        participate in a quantile. They are excluded from ``n`` and counted separately
        in :meth:`nonfinite_count`, because silently dropping them would make the
        population behind a quantile a different population from the one the caller
        believes it measured.
        """
        sketch = cls.identity(params)
        for item in items:
            if item is None or isinstance(item, tuple):
                continue
            try:
                value = float(item)
            except (TypeError, ValueError):
                continue
            sketch.update(value)
        return sketch

    @staticmethod
    def _params_of(params: Mapping[str, ParamValue]) -> tuple[int, int, str]:
        k = int(params.get("k", DEFAULT_KLL_K))
        if not _MIN_K <= k <= _MAX_K:
            raise ValueError(f"k must be {_MIN_K}..{_MAX_K}, got {k}")
        grid = str(params.get("cdf_grid", ""))
        if grid:
            for piece in grid.split(","):
                try:
                    float(piece)
                except ValueError:
                    raise ValueError(
                        f"cdf_grid must be comma-separated floats, got {grid!r}"
                    ) from None
        return k, int(params.get("seed", 0)), grid

    # -- ingestion ----------------------------------------------------------------------

    def update(self, value: float) -> None:
        """Add one observation. Mutates in place; this is the ingestion path, not merge."""
        if not math.isfinite(value):
            self._nonfinite += 1
            return
        self._levels[0].append(value)
        self._n += 1
        self._min = value if self._min is None else min(self._min, value)
        self._max = value if self._max is None else max(self._max, value)
        self._compress()

    # -- the compaction schedule ---------------------------------------------------------

    def _compaction_bit(self, buffer: Sequence[float], level: int) -> int:
        """The coin, replaced by a keyed hash of exactly what is being compacted.

        Depends on the seed, the level and the buffer contents, and on nothing else --
        not on a call counter, not on how many compactions came before. That is what
        makes the result a pure function of the sketch's state, which in turn is what
        makes merge commutative in state and the whole package reproducible.
        """
        digest = hashlib.blake2b(digest_size=8)
        digest.update(self._seed.to_bytes(8, "big", signed=True))
        digest.update(level.to_bytes(2, "big"))
        for value in buffer:
            digest.update(_F64.pack(value))
        return digest.digest()[-1] & 1

    def _compact_level(self, level: int) -> None:
        """Halve one level, promoting every other item to twice the weight."""
        buffer = sorted(self._levels[level])
        bit = self._compaction_bit(buffer, level)
        if len(buffer) % 2:
            # An odd buffer keeps one item behind. Which end it keeps follows the same
            # bit, so the retained item is not systematically the largest or smallest --
            # that would drag every quantile estimate in one direction.
            if bit:
                retained, body = [buffer[-1]], buffer[:-1]
            else:
                retained, body = [buffer[0]], buffer[1:]
        else:
            retained, body = [], buffer
        promoted = body[bit::2]
        self._levels[level] = retained
        if level + 1 == len(self._levels):
            self._levels.append([])
        self._levels[level + 1].extend(promoted)

    def _compress(self) -> None:
        """Make room, by compacting the lowest over-capacity level, repeatedly.

        Two stopping conditions, and the second one is the one that matters:

        * Level 0 must have room, because it is the only entry point for new items.
        * The sketch must be within its **total** item budget.

        Compacting until every level individually fits is the obvious reading and it
        costs roughly half the accuracy. Each compaction empties a level, so a
        per-level rule keeps every level at about half occupancy and the sketch holds
        around half the items it has paid memory for. Worse, it cascades: one overflow
        at the bottom walks all the way up and empties the big, heavy top levels, which
        are exactly the ones carrying the accuracy. Stopping at the total budget instead
        means only the small bottom levels churn while the top stays full, which is what
        the upstream implementation does and why it retains about 99% of its capacity.
        Measured on 100k normal variates, the difference is a worst-case rank error of
        roughly 0.012 versus 0.023.

        Always compacts the *lowest* over-capacity level, so the cheapest error (a
        compaction at level ``h`` costs ``2**h``) is spent first.
        """
        while True:
            depth = len(self._levels)
            entry_full = len(self._levels[0]) >= _level_capacity(self._k, depth, 0)
            if not entry_full and self.retained() <= _total_level_capacity(self._k, depth):
                break
            for level in range(depth):
                if len(self._levels[level]) >= _level_capacity(self._k, depth, level):
                    self._compact_level(level)
                    break
            else:
                break
        self._trim()

    def _trim(self) -> None:
        """Drop trailing empty levels, keeping at least one.

        The level count feeds the capacity schedule, so it has to be a function of the
        contents and nothing else. Two sketches holding the same items must agree on how
        many levels they have, or they would compact differently and stop being
        comparable.
        """
        while len(self._levels) > 1 and not self._levels[-1]:
            self._levels.pop()

    def _normalised(self) -> list[list[float]]:
        """Levels, each sorted, trailing empties dropped. The canonical state."""
        levels = [sorted(level) for level in self._levels]
        while len(levels) > 1 and not levels[-1]:
            levels.pop()
        return levels

    # -- identity -----------------------------------------------------------------------

    @property
    def params(self) -> Mapping[str, ParamValue]:
        """``k`` and ``seed``, plus ``cdf_grid`` when one was set.

        The grid is part of the merge identity, which is the right answer even though it
        does not affect a single stored item: it is the axis two snapshots will be
        compared on, and merging a sketch destined for one grid into a sketch destined
        for another produces a series whose points are not comparable. It is omitted
        entirely when unset, so the ordinary case -- no grid on either side -- merges
        without anyone having to think about it.
        """
        base: dict[str, ParamValue] = {"k": self._k, "seed": self._seed}
        if self._grid:
            base["cdf_grid"] = self._grid
        return base

    @property
    def population(self) -> int:
        """Orderable observations. Excludes nulls and non-finite values."""
        return self._n

    def nonfinite_count(self) -> int:
        """Observations excluded as NaN or infinite. A data-quality signal in its own right."""
        return self._nonfinite

    def retained(self) -> int:
        """Items held across all levels. A size diagnostic, not a statistic."""
        return sum(len(level) for level in self._levels)

    def num_levels(self) -> int:
        """How many weight levels are in use."""
        return len(self._normalised())

    # -- queries ------------------------------------------------------------------------

    def _weighted(self) -> tuple[list[float], list[int]]:
        """All retained items sorted, with the cumulative weight at or below each."""
        pairs: list[tuple[float, int]] = []
        for level, items in enumerate(self._levels):
            weight = 1 << level
            pairs.extend((value, weight) for value in items)
        pairs.sort()
        values: list[float] = []
        cumulative: list[int] = []
        running = 0
        for value, weight in pairs:
            running += weight
            values.append(value)
            cumulative.append(running)
        return values, cumulative

    def rank(self, value: float) -> float:
        """Fraction of the population at or below ``value``, in ``[0, 1]``.

        A fraction over a population, so a derived statistic: safe to export. The
        ``value`` argument is the caller's, and if the caller took it out of the data
        then the caller is holding a row value -- that is their taint, not this one's.
        """
        if self._n == 0:
            return math.nan
        total = 0
        for level, items in enumerate(self._levels):
            total += bisect.bisect_right(sorted(items), value) << level
        return total / self._n

    def cdf(self, grid: Sequence[float]) -> tuple[float, ...]:
        """Cumulative fractions at each grid point. The export detectors should use.

        Cheap distribution comparison: two snapshots evaluated on the same grid give two
        vectors a detector can difference without either of them ever holding a value
        out of a row. The grid must be a probe parameter. A grid derived from the data
        makes each returned fraction a statement about a real value, and that is a
        segment predicate, not a statistic.
        """
        if self._n == 0:
            return tuple(math.nan for _ in grid)
        values, cumulative = self._weighted()
        result: list[float] = []
        for point in grid:
            index = bisect.bisect_right(values, point)
            result.append((cumulative[index - 1] if index else 0) / self._n)
        return tuple(result)

    def pmf(self, grid: Sequence[float]) -> tuple[float, ...]:
        """Mass in each bucket induced by ``grid``: ``len(grid) + 1`` fractions."""
        cdf = self.cdf(grid)
        if not cdf or any(math.isnan(point) for point in cdf):
            return tuple(math.nan for _ in range(len(grid) + 1))
        out = [cdf[0]]
        out.extend(cdf[i] - cdf[i - 1] for i in range(1, len(cdf)))
        out.append(1.0 - cdf[-1])
        return tuple(out)

    def quantile(self, fraction: float) -> Tainted[float]:
        """The value at ``fraction`` of the distribution.

        ``Tainted`` DATA_VALUE, and not negotiable: a quantile IS a row value, and over
        a small population it is one person's number. The median salary of a
        twelve-person team identifies somebody. ``population`` rides along so that
        ``is_small_cell`` can do its job downstream.
        """
        if not 0.0 <= fraction <= 1.0:
            raise ValueError(f"fraction must be in [0, 1], got {fraction}")
        value = self._quantile_raw(fraction)
        return data_value(
            value,
            acquisition=Acquisition.QUANTILE,
            population=self._n,
        )

    def _quantile_raw(self, fraction: float) -> float:
        if self._n == 0:
            return math.nan
        values, cumulative = self._weighted()
        target = fraction * self._n
        index = bisect.bisect_left(cumulative, target)
        return values[min(index, len(values) - 1)]

    def minimum(self) -> Tainted[float]:
        """The exact smallest value seen. A row's value, so ``Tainted`` DATA_VALUE."""
        return data_value(
            math.nan if self._min is None else self._min,
            acquisition=Acquisition.QUANTILE,
            population=self._n,
        )

    def maximum(self) -> Tainted[float]:
        """The exact largest value seen. A row's value, so ``Tainted`` DATA_VALUE."""
        return data_value(
            math.nan if self._max is None else self._max,
            acquisition=Acquisition.QUANTILE,
            population=self._n,
        )

    def error_bound(self) -> ErrorBound:
        """Normalised rank error. A function of ``k`` and of nothing in the data."""
        if len(self._levels) == 1 and self._n <= _level_capacity(self._k, 1, 0):
            return ErrorBound(
                kind="exact",
                note="no compaction has happened yet; every item is retained",
            )
        return ErrorBound(
            kind="relative",
            epsilon=KLL_CDF_COEF / self._k**KLL_CDF_EXP,
            confidence=0.6827,
            note=f"normalised rank error {KLL_CDF_COEF}/k^{KLL_CDF_EXP}, k={self._k}, "
            "one standard deviation; empirical constants, measured in the package docs",
        )

    # -- the monoid ---------------------------------------------------------------------

    def merge(self, other: Self) -> Self:
        """Combine two sketches: concatenate each level, then compact until in bounds.

        Commutative in full state, because concatenation is followed by a compaction
        whose choices depend only on the sorted contents of each level. Associative in
        the *estimate* only -- see the class docstring.
        """
        self.require_mergeable(other)
        depth = max(len(self._levels), len(other._levels))
        levels: list[list[float]] = []
        for level in range(depth):
            combined: list[float] = []
            if level < len(self._levels):
                combined.extend(self._levels[level])
            if level < len(other._levels):
                combined.extend(other._levels[level])
            levels.append(combined)
        merged = type(self)(
            k=self._k,
            seed=self._seed,
            grid=self._grid,
            levels=levels,
            n=self._n + other._n,
            minimum=_lesser(self._min, other._min),
            maximum=_greater(self._max, other._max),
            nonfinite=self._nonfinite + other._nonfinite,
        )
        merged._compress()
        return merged

    # -- serialisation -------------------------------------------------------------------

    def encode(self) -> bytes:
        """Canonical bytes: levels sorted, trailing empties dropped.

        Canonical because ``__eq__`` and the hierarchy's byte-identity test both rest on
        it. Two sketches holding the same multiset at each level must encode the same
        way whatever order their items arrived in.
        """
        levels = self._normalised()
        grid_bytes = self._grid.encode("utf-8")
        parts = [
            self._k.to_bytes(4, "big"),
            self._seed.to_bytes(8, "big", signed=True),
            len(grid_bytes).to_bytes(2, "big"),
            grid_bytes,
            self._n.to_bytes(8, "big"),
            self._nonfinite.to_bytes(8, "big"),
            _pack_optional(self._min),
            _pack_optional(self._max),
            len(levels).to_bytes(2, "big"),
        ]
        for items in levels:
            parts.append(len(items).to_bytes(4, "big"))
            parts.extend(_F64.pack(value) for value in items)
        return encode_container(
            codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=b"".join(parts)
        )

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        offset = header.body_offset
        raw, offset = read_exact(payload, offset, 4)
        k = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 8)
        seed = int.from_bytes(raw, "big", signed=True)
        raw, offset = read_exact(payload, offset, 2)
        grid_bytes, offset = read_exact(payload, offset, int.from_bytes(raw, "big"))
        grid = grid_bytes.decode("utf-8")
        raw, offset = read_exact(payload, offset, 8)
        n = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 8)
        nonfinite = int.from_bytes(raw, "big")
        minimum, offset = _unpack_optional(payload, offset)
        maximum, offset = _unpack_optional(payload, offset)
        raw, offset = read_exact(payload, offset, 2)
        depth = int.from_bytes(raw, "big")
        if depth > _MAX_LEVELS:
            raise SketchDecodeError(f"KLL payload claims {depth} levels; refusing to allocate")
        levels: list[list[float]] = []
        for _ in range(depth):
            raw, offset = read_exact(payload, offset, 4)
            count = int.from_bytes(raw, "big")
            chunk, offset = read_exact(payload, offset, count * _F64.size)
            levels.append([_F64.unpack_from(chunk, i * _F64.size)[0] for i in range(count)])
        return cls(
            k=k,
            seed=seed,
            grid=grid,
            levels=levels or [[]],
            n=n,
            minimum=minimum,
            maximum=maximum,
            nonfinite=nonfinite,
        )


def _lesser(left: float | None, right: float | None) -> float | None:
    if left is None:
        return right
    return left if right is None else min(left, right)


def _greater(left: float | None, right: float | None) -> float | None:
    if left is None:
        return right
    return left if right is None else max(left, right)


def _pack_optional(value: float | None) -> bytes:
    """One presence byte then the double, so ``None`` and ``0.0`` cannot be confused."""
    return b"\x00" + _F64.pack(0.0) if value is None else b"\x01" + _F64.pack(value)


def _unpack_optional(payload: bytes, offset: int) -> tuple[float | None, int]:
    flag, offset = read_exact(payload, offset, 1)
    raw, offset = read_exact(payload, offset, _F64.size)
    return (None if flag == b"\x00" else _F64.unpack(raw)[0]), offset
