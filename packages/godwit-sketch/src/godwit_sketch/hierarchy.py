"""The sketch time-series: :class:`TimeHierarchy`.

This is the module that makes batch and streaming the same thing. Batch merges sketches
per data file; streaming merges per micro-window. Both must land on one artifact -- a
series of sketches over exponentially widening windows -- and detectors above must not
be able to tell which produced it. If the two modes diverge, nothing above L1 catches
it: a detector sees the divergence as drift, and reports the ingestion mode change as a
pattern.

HOW BYTE-IDENTITY IS ACTUALLY ACHIEVED
--------------------------------------
Not by assuming merge is order-free, because for three of the eight kinds it is not.
:class:`~godwit_sketch.quantile.KllQuantile`,
:class:`~godwit_sketch.frequency.CountMinHeavy` and everything built on them are
:attr:`~godwit_sketch.base.MergeExactness.BOUNDED`: once a bounded summary has discarded
information to stay inside its size limit, a different bracketing discards different
information. That is a theorem about bounded lossy summaries, not a defect, and no
amount of care in this module can repeal it.

So this module never depends on it. Instead:

1. **Leaves are retained, not folded on arrival.** Every contribution to a base window
   is kept, so the fold can be redone.
2. **Contributions within a window are folded in a canonical order** -- sorted by their
   own serialised bytes. Content, not arrival time, so two workers that received the
   same shards in opposite orders sort them identically.
3. **Coarse levels are derived, never accumulated.** A level-``L`` window is folded from
   its level-``L-1`` children in ascending window order, every time, rather than being
   updated in place as data arrives.

The result is that the *sequence of merge operations* is a pure function of the data,
never of the arrival order. Same data, same bytes, whether it came in one batch, in
reverse, or in a thousand shuffled micro-batches. ``tests/test_hierarchy.py`` proves it
by replaying a shuffled arrival against a batch build and comparing
:meth:`TimeHierarchy.digest`.

The cost is memory: a window holds its contributions rather than one merged sketch. For
kinds whose merge is EXACT the order provably cannot matter, so those are folded
eagerly and only one sketch is kept. See :meth:`TimeHierarchy.append`.

GAPS ARE NOT ZEROS AND ARE NOT INTERPOLATED
-------------------------------------------
:meth:`TimeHierarchy.query` returns one :class:`Bucket` per window in the requested
range, with ``sketch=None`` where no data arrived. It never fills a gap. "No rows landed
in this hour" and "rows landed and they summed to zero" are completely different
findings -- the first is usually a broken pipeline and the second is usually a quiet
Sunday -- and a series that silently interpolates makes the first one invisible, which
is precisely the silent data-quality collapse this product exists to catch.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Self

from godwit_contracts.common import ContentHash, Instant, content_hash, require_utc

from godwit_sketch.base import BaseSketch, MergeExactness, ParamValue
from godwit_sketch.errors import IncompatibleMergeError

__all__ = [
    "DEFAULT_FACTOR",
    "DEFAULT_LEVELS",
    "Bucket",
    "TimeHierarchy",
]

MIN_FACTOR: Final[int] = 2
"""A level has to be at least two of the level below, or it is not a hierarchy."""

DEFAULT_FACTOR: Final[int] = 2
"""Each level is this many windows of the level below. Two gives dyadic windows."""

DEFAULT_LEVELS: Final[int] = 8
"""Levels built above the base. Eight dyadic levels spans base x 1 to base x 128."""


@dataclass(frozen=True, slots=True)
class Bucket:
    """One window of the series, at one level.

    ``sketch`` is ``None`` when no data landed in the window. That is a gap, and it is
    reported as a gap: see the module docstring.
    """

    level: int
    index: int
    start: Instant
    end: Instant
    sketch: BaseSketch | None

    @property
    def is_gap(self) -> bool:
        """True when no data arrived for this window."""
        return self.sketch is None


class TimeHierarchy:
    """Sketches over exponentially widening windows, identical in batch and streaming.

    Level 0 windows are ``base`` wide; a level-``L`` window is ``factor**L`` of them.
    All windows are aligned to ``epoch``, which is injected rather than read from a
    clock, so two workers in two timezones produce the same boundaries.

    One hierarchy holds one sketch class with one set of parameters. Mixing kinds, or
    mixing parameters within a kind, is refused: the series would not be comparable
    across time, which is the only reason the series exists.
    """

    __slots__ = (
        "_base",
        "_cache",
        "_epoch",
        "_factor",
        "_leaves",
        "_levels",
        "_params",
        "_sketch_cls",
    )

    def __init__(
        self,
        *,
        sketch_cls: type[BaseSketch],
        params: Mapping[str, ParamValue],
        base: _dt.timedelta,
        epoch: Instant,
        factor: int = DEFAULT_FACTOR,
        levels: int = DEFAULT_LEVELS,
    ) -> None:
        if base <= _dt.timedelta(0):
            raise ValueError(f"base window must be positive, got {base}")
        if factor < MIN_FACTOR:
            raise ValueError(f"factor must be at least {MIN_FACTOR}, got {factor}")
        if levels < 0:
            raise ValueError(f"levels must be non-negative, got {levels}")
        self._sketch_cls = sketch_cls
        self._params = dict(params)
        self._base = base
        self._epoch = require_utc(epoch)
        self._factor = factor
        self._levels = levels
        self._leaves: dict[int, list[BaseSketch]] = {}
        self._cache: dict[tuple[int, int], BaseSketch] = {}

    # -- geometry -----------------------------------------------------------------------

    def window_index(self, at: Instant, *, level: int = 0) -> int:
        """Which window of ``level`` contains ``at``. Floor division, so negatives work."""
        self._check_level(level)
        elapsed = require_utc(at) - self._epoch
        width = self._base * self._factor**level
        return int(elapsed // width)

    def window_bounds(self, index: int, *, level: int = 0) -> tuple[Instant, Instant]:
        """Half-open ``[start, end)`` of one window."""
        self._check_level(level)
        width = self._base * self._factor**level
        start = self._epoch + width * index
        return start, start + width

    def _check_level(self, level: int) -> None:
        if not 0 <= level <= self._levels:
            raise ValueError(f"level must be 0..{self._levels}, got {level}")

    # -- ingestion ----------------------------------------------------------------------

    def append(self, *, at: Instant, sketch: BaseSketch) -> None:
        """Add one sketch to the base window containing ``at``. The streaming path.

        Contributions to a window are retained rather than folded on arrival, so that
        the fold can be redone in a canonical order and a late arrival cannot change the
        bracketing of the ones already here.

        The exception is a kind whose merge is EXACT. There, bracketing provably cannot
        change the result, so the contributions are folded immediately and the window
        keeps a single sketch. That is not an optimisation for its own sake: Theta, HLL
        and the moment summaries are the kinds most likely to see a very large number of
        micro-batches per window, and retaining every one of them would grow without
        bound for no benefit.
        """
        self._require_compatible(sketch)
        index = self.window_index(at, level=0)
        bucket = self._leaves.setdefault(index, [])
        if sketch.MERGE_EXACTNESS is MergeExactness.EXACT and bucket:
            bucket[0] = bucket[0].merge(sketch)
        else:
            bucket.append(sketch)
        self._cache.clear()

    @classmethod
    def build_from_partitions(
        cls,
        partitions: Iterable[tuple[Instant, BaseSketch]],
        *,
        sketch_cls: type[BaseSketch],
        params: Mapping[str, ParamValue],
        base: _dt.timedelta,
        epoch: Instant,
        factor: int = DEFAULT_FACTOR,
        levels: int = DEFAULT_LEVELS,
    ) -> Self:
        """Build from per-partition sketches. The batch path.

        Takes the partitions in whatever order they are produced. It does not sort them
        first and does not need to: :meth:`append` retains and :meth:`bucket` folds
        canonically, so the order this iterable happens to be in has no effect on the
        result. That is the whole point, and ``tests/test_hierarchy.py`` checks it by
        shuffling.
        """
        hierarchy = cls(
            sketch_cls=sketch_cls,
            params=params,
            base=base,
            epoch=epoch,
            factor=factor,
            levels=levels,
        )
        for at, sketch in partitions:
            hierarchy.append(at=at, sketch=sketch)
        return hierarchy

    def _require_compatible(self, sketch: BaseSketch) -> None:
        if not isinstance(sketch, self._sketch_cls):
            raise IncompatibleMergeError(
                f"this hierarchy holds {self._sketch_cls.__name__}, got {type(sketch).__name__}"
            )
        expected = self._sketch_cls.identity(self._params).fingerprint
        if sketch.fingerprint != expected:
            raise IncompatibleMergeError(
                f"sketch parameters {dict(sketch.params)} do not match the hierarchy's "
                f"{self._params}; a series must be comparable across time"
            )

    # -- reading ------------------------------------------------------------------------

    def bucket(self, index: int, *, level: int = 0) -> BaseSketch | None:
        """The folded sketch for one window, or ``None`` when the window is empty.

        Level 0 folds that window's retained contributions in canonical order -- sorted
        by their serialised bytes, so the order is a property of the data and not of
        when anything arrived. Higher levels fold their children in ascending window
        order. Results are cached, and the cache is dropped whenever anything is
        appended.
        """
        self._check_level(level)
        key = (level, index)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        folded = self._fold_leaves(index) if level == 0 else self._fold_children(index, level)
        if folded is not None:
            self._cache[key] = folded
        return folded

    def _fold_leaves(self, index: int) -> BaseSketch | None:
        contributions = self._leaves.get(index)
        if not contributions:
            return None
        ordered = sorted(contributions, key=lambda sketch: sketch.encode())
        result = ordered[0]
        for contribution in ordered[1:]:
            result = result.merge(contribution)
        return result

    def _fold_children(self, index: int, level: int) -> BaseSketch | None:
        first = index * self._factor
        result: BaseSketch | None = None
        for offset in range(self._factor):
            child = self.bucket(first + offset, level=level - 1)
            if child is None:
                continue
            result = child if result is None else result.merge(child)
        return result

    def query(self, *, start: Instant, end: Instant, level: int = 0) -> tuple[Bucket, ...]:
        """Every window of ``level`` overlapping ``[start, end)``, aligned, gaps marked.

        The series is contiguous: a window with no data is present with ``sketch=None``
        rather than omitted. A caller plotting this must render the gap as a gap. See
        the module docstring on why interpolation is forbidden here.
        """
        self._check_level(level)
        start = require_utc(start)
        end = require_utc(end)
        if end <= start:
            return ()
        first = self.window_index(start, level=level)
        last = self.window_index(end - _dt.timedelta(microseconds=1), level=level)
        buckets: list[Bucket] = []
        for index in range(first, last + 1):
            window_start, window_end = self.window_bounds(index, level=level)
            buckets.append(
                Bucket(
                    level=level,
                    index=index,
                    start=window_start,
                    end=window_end,
                    sketch=self.bucket(index, level=level),
                )
            )
        return tuple(buckets)

    def occupied_windows(self) -> tuple[int, ...]:
        """Base-window indices that hold data, ascending."""
        return tuple(sorted(index for index, items in self._leaves.items() if items))

    def population(self) -> int:
        """Total items across every base window."""
        return sum(sketch.population for items in self._leaves.values() for sketch in items)

    # -- identity -----------------------------------------------------------------------

    def canonical_bytes(self) -> bytes:
        """The whole hierarchy, every level, in one canonical byte string.

        This is what the batch-versus-streaming equivalence test compares. It covers
        every derived level, not just the leaves, because a bug that only showed up in
        the coarse fold would otherwise pass.
        """
        parts: list[bytes] = [
            self._sketch_cls.CODEC.encode("ascii"),
            b"|",
            str(int(self._base.total_seconds() * 1_000_000)).encode("ascii"),
            b"|",
            str(self._factor).encode("ascii"),
            b"|",
            str(self._levels).encode("ascii"),
            b"|",
            self._epoch.isoformat().encode("ascii"),
        ]
        for level in range(self._levels + 1):
            for index in self._indices_at(level):
                sketch = self.bucket(index, level=level)
                if sketch is None:
                    continue
                parts.append(f"|{level}:{index}:".encode("ascii"))
                parts.append(sketch.encode())
        return b"".join(parts)

    def _indices_at(self, level: int) -> Sequence[int]:
        occupied = self.occupied_windows()
        if not occupied:
            return ()
        divisor = self._factor**level
        return sorted({index // divisor for index in occupied})

    def digest(self) -> ContentHash:
        """Content hash of :meth:`canonical_bytes`. Equal digests mean equal hierarchies."""
        return content_hash(self.canonical_bytes(), prefix="sh")

    def __repr__(self) -> str:
        """Never renders a sketch: some of them are value-bearing."""
        return (
            f"<TimeHierarchy {self._sketch_cls.__name__} "
            f"base={self._base} factor={self._factor} levels={self._levels} "
            f"windows={len(self._leaves)}>"
        )
