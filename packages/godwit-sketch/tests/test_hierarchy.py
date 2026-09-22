"""The most important test in the package: batch and streaming produce the same bytes.

If these fail, the two ingestion modes have silently diverged and nothing above L1 can
tell. A detector comparing today's sketch against yesterday's would see the change of
ingestion mode as drift and report it as a pattern -- a false positive that no amount of
tuning at L2 can remove, because the data really did appear to change.

The shuffled-arrival simulation is the core of it. Every kind is driven three ways over
identical underlying data:

* built from partitions in order, as a batch job reading data files would;
* appended in a shuffled order, as a streaming consumer receiving late and out-of-order
  micro-batches would;
* appended in strict reverse.

All three must produce byte-identical hierarchies, at every level, including for the
kinds whose ``merge`` is only associative within its error bound. That works because
:class:`~godwit_sketch.hierarchy.TimeHierarchy` folds in a canonical order rather than
relying on the merge being order-free -- see that module's docstring.
"""

from __future__ import annotations

import datetime as _dt
import itertools

import pytest
from _support import FROZEN_INSTANT, SMALL_PARAMS
from godwit_sketch.base import BaseSketch, ItemFlavour, SketchItem, registered_sketches
from godwit_sketch.deterministic import normals, scramble
from godwit_sketch.errors import IncompatibleMergeError
from godwit_sketch.hierarchy import TimeHierarchy
from godwit_sketch.moments import Moments
from godwit_sketch.quantile import KllQuantile

ALL_SKETCHES = registered_sketches()
BASE = _dt.timedelta(hours=1)
LEVELS = 4


def _items(flavour: ItemFlavour, salt: str, count: int) -> list[SketchItem]:
    """Deterministic observations of the right flavour for a kind."""
    if flavour is ItemFlavour.NUMERIC:
        return list(normals(count, salt=salt, sigma=10.0))
    draws = [int(value * 1000) for value in normals(count, salt=salt, mu=5.0)]
    if flavour is ItemFlavour.EDGE:
        return [(f"a{abs(d) % 12}", f"b{abs(d) % 9}") for d in draws]
    return [f"k{abs(d) % 20}" for d in draws]


def _partitions(
    cls: type[BaseSketch], salt: str = "parts"
) -> list[tuple[_dt.datetime, BaseSketch]]:
    """Thirty partitions over about twenty hours, several sharing a window.

    Several per window on purpose: a window with a single contribution never exercises
    the canonical intra-window fold, which is where an arrival-order dependency would
    actually live.
    """
    built: list[tuple[_dt.datetime, BaseSketch]] = []
    for index in range(30):
        at = FROZEN_INSTANT + _dt.timedelta(minutes=40 * index)
        items = _items(cls.ITEM_FLAVOUR, f"{salt}/{index}", 40)
        built.append((at, cls.from_items(items, SMALL_PARAMS)))
    return built


def _hierarchy(cls: type[BaseSketch]) -> TimeHierarchy:
    return TimeHierarchy(
        sketch_cls=cls, params=SMALL_PARAMS, base=BASE, epoch=FROZEN_INSTANT, levels=LEVELS
    )


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=[c.__name__ for c in ALL_SKETCHES])
def test_shuffled_arrival_matches_batch_byte_for_byte(cls: type[BaseSketch]) -> None:
    """Batch, shuffled streaming and reversed streaming give identical hierarchies."""
    partitions = _partitions(cls)

    batch = TimeHierarchy.build_from_partitions(
        partitions,
        sketch_cls=cls,
        params=SMALL_PARAMS,
        base=BASE,
        epoch=FROZEN_INSTANT,
        levels=LEVELS,
    )

    shuffled = scramble(partitions, salt="arrival-order")
    streaming = _hierarchy(cls)
    for at, sketch in shuffled:
        streaming.append(at=at, sketch=sketch)

    reversed_arrival = _hierarchy(cls)
    for at, sketch in reversed(partitions):
        reversed_arrival.append(at=at, sketch=sketch)

    assert batch.canonical_bytes() == streaming.canonical_bytes()
    assert batch.canonical_bytes() == reversed_arrival.canonical_bytes()
    assert batch.digest() == streaming.digest() == reversed_arrival.digest()


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=[c.__name__ for c in ALL_SKETCHES])
def test_every_level_agrees_not_just_the_leaves(cls: type[BaseSketch]) -> None:
    """The coarse levels match too.

    ``canonical_bytes`` already covers them, but a bug confined to the coarse fold would
    be easy to misread in that one assertion, so the levels are compared one at a time.
    """
    partitions = _partitions(cls)
    batch = TimeHierarchy.build_from_partitions(
        partitions,
        sketch_cls=cls,
        params=SMALL_PARAMS,
        base=BASE,
        epoch=FROZEN_INSTANT,
        levels=LEVELS,
    )
    shuffled = scramble(partitions, salt="arrival-order-2")
    streaming = _hierarchy(cls)
    for at, sketch in shuffled:
        streaming.append(at=at, sketch=sketch)

    end = FROZEN_INSTANT + _dt.timedelta(hours=24)
    for level in range(LEVELS + 1):
        left = batch.query(start=FROZEN_INSTANT, end=end, level=level)
        right = streaming.query(start=FROZEN_INSTANT, end=end, level=level)
        assert [b.index for b in left] == [b.index for b in right]
        for a, b in zip(left, right, strict=True):
            assert a.is_gap == b.is_gap
            if a.sketch is not None and b.sketch is not None:
                assert a.sketch.encode() == b.sketch.encode()


def test_population_is_conserved_across_the_hierarchy() -> None:
    """Every row that went in is accounted for in the top level.

    A fold that dropped a window would still produce matching digests on both paths --
    it would drop the same window twice -- so equivalence alone does not prove the data
    arrived. This checks the total.
    """
    partitions = _partitions(KllQuantile)
    hierarchy = TimeHierarchy.build_from_partitions(
        partitions,
        sketch_cls=KllQuantile,
        params=SMALL_PARAMS,
        base=BASE,
        epoch=FROZEN_INSTANT,
        levels=LEVELS,
    )
    expected = sum(sketch.population for _, sketch in partitions)
    assert hierarchy.population() == expected
    top = hierarchy.query(
        start=FROZEN_INSTANT, end=FROZEN_INSTANT + _dt.timedelta(hours=32), level=LEVELS
    )
    assert sum(b.sketch.population for b in top if b.sketch is not None) == expected


def test_gaps_are_reported_and_never_interpolated() -> None:
    """A window with no data comes back as a gap, not as a zero and not as a neighbour.

    'No rows landed this hour' is usually a broken pipeline; 'rows landed and summed to
    zero' is usually a quiet Sunday. A series that fills the first with the second makes
    the silent data-quality collapse this product exists to catch invisible.
    """
    hierarchy = _hierarchy(Moments)
    hierarchy.append(at=FROZEN_INSTANT, sketch=Moments.from_items([1.0, 2.0], SMALL_PARAMS))
    hierarchy.append(
        at=FROZEN_INSTANT + _dt.timedelta(hours=3),
        sketch=Moments.from_items([5.0], SMALL_PARAMS),
    )

    buckets = hierarchy.query(
        start=FROZEN_INSTANT, end=FROZEN_INSTANT + _dt.timedelta(hours=4), level=0
    )
    assert len(buckets) == 4
    assert [b.is_gap for b in buckets] == [False, True, True, False]
    assert buckets[1].sketch is None
    # Contiguous and aligned: no window is skipped, and each starts where the last ended.
    for earlier, later in itertools.pairwise(buckets):
        assert earlier.end == later.start


def test_a_gap_is_distinct_from_a_window_of_zeros() -> None:
    """An empty window and a window holding a zero must not look the same."""
    hierarchy = _hierarchy(Moments)
    hierarchy.append(at=FROZEN_INSTANT, sketch=Moments.from_items([0.0], SMALL_PARAMS))
    buckets = hierarchy.query(
        start=FROZEN_INSTANT, end=FROZEN_INSTANT + _dt.timedelta(hours=2), level=0
    )
    present, absent = buckets[0], buckets[1]
    assert not present.is_gap
    assert present.sketch is not None
    assert present.sketch.population == 1
    assert absent.is_gap


def test_windows_are_aligned_to_the_injected_epoch() -> None:
    """Boundaries come from the epoch, never from a clock or from the first arrival."""
    hierarchy = _hierarchy(Moments)
    start, end = hierarchy.window_bounds(0, level=0)
    assert start == FROZEN_INSTANT
    assert end == FROZEN_INSTANT + BASE
    assert hierarchy.window_index(FROZEN_INSTANT + _dt.timedelta(minutes=59)) == 0
    assert hierarchy.window_index(FROZEN_INSTANT + _dt.timedelta(minutes=61)) == 1
    # A level-2 window is four base windows wide when factor is 2.
    level_two_start, level_two_end = hierarchy.window_bounds(0, level=2)
    assert level_two_end - level_two_start == BASE * 4


def test_hierarchy_refuses_a_foreign_sketch() -> None:
    """One hierarchy holds one kind at one set of parameters, or the series is not a series."""
    hierarchy = _hierarchy(Moments)
    with pytest.raises(IncompatibleMergeError):
        hierarchy.append(at=FROZEN_INSTANT, sketch=KllQuantile.from_items([1.0], SMALL_PARAMS))


def test_hierarchy_refuses_mismatched_parameters() -> None:
    """A sketch built with different parameters would not be comparable across time."""
    hierarchy = TimeHierarchy(
        sketch_cls=KllQuantile,
        params={"k": 16, "seed": 1},
        base=BASE,
        epoch=FROZEN_INSTANT,
        levels=LEVELS,
    )
    with pytest.raises(IncompatibleMergeError):
        hierarchy.append(
            at=FROZEN_INSTANT, sketch=KllQuantile.from_items([1.0], {"k": 32, "seed": 1})
        )


def test_reading_twice_gives_the_same_answer() -> None:
    """Folding must not consume or mutate the retained contributions.

    The hierarchy re-folds on demand and caches. A fold that mutated its inputs would
    give a different answer on the second read, which would be a nightmare to diagnose
    downstream because the first read would look right.
    """
    hierarchy = _hierarchy(KllQuantile)
    for at, sketch in _partitions(KllQuantile):
        hierarchy.append(at=at, sketch=sketch)
    first = hierarchy.canonical_bytes()
    second = hierarchy.canonical_bytes()
    assert first == second


def test_appending_after_reading_invalidates_the_cache() -> None:
    """A late arrival changes the answer, including for windows already read."""
    hierarchy = _hierarchy(Moments)
    hierarchy.append(at=FROZEN_INSTANT, sketch=Moments.from_items([1.0], SMALL_PARAMS))
    before = hierarchy.digest()
    hierarchy.append(at=FROZEN_INSTANT, sketch=Moments.from_items([100.0], SMALL_PARAMS))
    assert hierarchy.digest() != before
    bucket = hierarchy.bucket(0, level=0)
    assert bucket is not None
    assert bucket.population == 2


def test_late_arrival_lands_where_batch_would_have_put_it() -> None:
    """The point of retaining leaves: a late shard must not depend on being late.

    A hierarchy read, then given a straggler for a window it has already folded, must
    match a hierarchy that had the straggler all along.
    """
    partitions = _partitions(KllQuantile)
    early, straggler = partitions[:-1], partitions[-1]

    late = _hierarchy(KllQuantile)
    for at, sketch in early:
        late.append(at=at, sketch=sketch)
    late.digest()  # force a fold before the straggler arrives
    late.append(at=straggler[0], sketch=straggler[1])

    complete = TimeHierarchy.build_from_partitions(
        partitions,
        sketch_cls=KllQuantile,
        params=SMALL_PARAMS,
        base=BASE,
        epoch=FROZEN_INSTANT,
        levels=LEVELS,
    )
    assert late.digest() == complete.digest()


def test_empty_hierarchy_queries_cleanly() -> None:
    """No data is a series of gaps, not an error and not an empty result."""
    hierarchy = _hierarchy(Moments)
    buckets = hierarchy.query(
        start=FROZEN_INSTANT, end=FROZEN_INSTANT + _dt.timedelta(hours=3), level=0
    )
    assert len(buckets) == 3
    assert all(b.is_gap for b in buckets)
    assert hierarchy.occupied_windows() == ()
    assert hierarchy.population() == 0
    assert hierarchy.query(start=FROZEN_INSTANT, end=FROZEN_INSTANT) == ()


def test_windows_before_the_epoch_work() -> None:
    """Data older than the epoch lands in negative windows rather than being lost.

    The epoch is injected, so nothing stops a caller passing one that sits in the middle
    of their history -- or a backfill arriving for a period before it. Floor division
    handles the negative side; ordinary integer division would round toward zero and
    quietly merge the first window before the epoch with the first one after it.
    """
    hierarchy = _hierarchy(Moments)
    hierarchy.append(
        at=FROZEN_INSTANT - _dt.timedelta(hours=3, minutes=30),
        sketch=Moments.from_items([5.0], SMALL_PARAMS),
    )
    hierarchy.append(
        at=FROZEN_INSTANT + _dt.timedelta(minutes=10),
        sketch=Moments.from_items([7.0], SMALL_PARAMS),
    )
    assert hierarchy.occupied_windows() == (-4, 0)
    assert hierarchy.population() == 2

    buckets = hierarchy.query(
        start=FROZEN_INSTANT - _dt.timedelta(hours=4),
        end=FROZEN_INSTANT + _dt.timedelta(hours=1),
    )
    assert [(b.index, b.is_gap) for b in buckets] == [
        (-4, False),
        (-3, True),
        (-2, True),
        (-1, True),
        (0, False),
    ]


def test_instants_are_normalised_to_utc_not_taken_at_face_value() -> None:
    """Two workers in two timezones must agree on which window a row belongs to.

    ``09:30`` in Tokyo is ``00:30`` UTC and belongs in window 0, not window 9. Getting
    this wrong would put the same event in two different windows depending on where the
    worker ran, which is the batch/streaming divergence again by another route.
    """
    tokyo = _dt.datetime(2024, 1, 1, 9, 30, tzinfo=_dt.timezone(_dt.timedelta(hours=9)))
    hierarchy = _hierarchy(Moments)
    assert hierarchy.window_index(tokyo) == 0


def test_a_naive_instant_is_refused() -> None:
    """A naive timestamp is a determinism bug waiting to happen, so it never gets in."""
    hierarchy = _hierarchy(Moments)
    with pytest.raises(ValueError, match="naive datetime"):
        hierarchy.append(
            at=_dt.datetime(2024, 1, 1),
            sketch=Moments.from_items([1.0], SMALL_PARAMS),
        )


def test_a_hierarchy_with_no_coarse_levels_is_valid() -> None:
    """``levels=0`` is a plain series of base windows, and asking for level 1 raises."""
    hierarchy = TimeHierarchy(
        sketch_cls=Moments, params=SMALL_PARAMS, base=BASE, epoch=FROZEN_INSTANT, levels=0
    )
    hierarchy.append(at=FROZEN_INSTANT, sketch=Moments.from_items([1.0], SMALL_PARAMS))
    assert len(hierarchy.query(start=FROZEN_INSTANT, end=FROZEN_INSTANT + BASE)) == 1
    with pytest.raises(ValueError, match=r"level must be 0\.\.0"):
        hierarchy.query(start=FROZEN_INSTANT, end=FROZEN_INSTANT + BASE, level=1)


def test_construction_rejects_nonsense_geometry() -> None:
    """A non-positive base or a factor below two is not a hierarchy."""
    for base, factor, message in (
        (_dt.timedelta(0), 2, "base window must be positive"),
        (_dt.timedelta(hours=-1), 2, "base window must be positive"),
        (BASE, 1, "factor must be at least 2"),
    ):
        with pytest.raises(ValueError, match=message):
            TimeHierarchy(
                sketch_cls=Moments,
                params=SMALL_PARAMS,
                base=base,
                epoch=FROZEN_INSTANT,
                factor=factor,
            )
