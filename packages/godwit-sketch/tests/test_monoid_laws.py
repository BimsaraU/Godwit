"""The monoid law suite. Invariant 6, enforced over every registered kind.

This module is parametrised over :func:`~godwit_sketch.base.registered_sketches`, not
over a hand-written list. Register a new sketch and it is swept up here on the next run;
that is the whole enforcement mechanism described in :mod:`godwit_sketch.base`, and it
is why the registry refuses a class that has not declared its flavour and exactness.

Laws 1 to 3 are what make batch and streaming able to run identical code, so they get
property tests rather than examples. An associativity bug survives example tests
comfortably -- it needs a particular interleaving of compactions to show up, which is
exactly what hypothesis is for and exactly what a hand-written case will miss.
"""

from __future__ import annotations

import math

import pytest
from _support import (
    OTHER_PARAMS,
    SMALL_PARAMS,
    build,
    context,
    item_lists,
    same_vector,
)
from godwit_sketch.base import BaseSketch, MergeExactness, SketchItem, registered_sketches
from godwit_sketch.errors import IncompatibleMergeError
from godwit_sketch.features import extract_features
from hypothesis import HealthCheck, given, settings

ALL_SKETCHES = registered_sketches()
EXACT_SKETCHES = [c for c in ALL_SKETCHES if c.MERGE_EXACTNESS is MergeExactness.EXACT]
BOUNDED_SKETCHES = [c for c in ALL_SKETCHES if c.MERGE_EXACTNESS is MergeExactness.BOUNDED]

SUITE = settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)


def _ids(classes: list[type[BaseSketch]]) -> list[str]:
    return [c.__name__ for c in classes]


def test_the_registry_is_not_empty() -> None:
    """A vacuous parametrisation would make every law below pass without testing anything."""
    assert len(ALL_SKETCHES) >= 8
    assert EXACT_SKETCHES and BOUNDED_SKETCHES


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_every_registered_class_declares_its_nature(cls: type[BaseSketch]) -> None:
    """The declarations the registry demands are present and of the right type."""
    assert isinstance(cls.CODEC, str) and cls.CODEC
    assert isinstance(cls.SCHEMA_VERSION, int)
    assert isinstance(cls.VALUE_BEARING, bool)
    assert cls.MERGE_EXACTNESS in set(MergeExactness)
    assert cls.SENSITIVITY is not None


# --------------------------------------------------------------------------------------
# Law 3 -- identity
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_identity_is_two_sided(cls: type[BaseSketch]) -> None:
    """``a.merge(identity()) == a == identity().merge(a)``, in full internal state.

    Exact for every kind including the bounded ones: merging with an empty sketch adds
    nothing, so there is nothing for a bounded summary to have to discard. A failure
    here means the ingestion path leaves the sketch in a state the merge path would
    normalise differently, which would also break batch/streaming equivalence.
    """

    @given(items=item_lists(cls.ITEM_FLAVOUR))
    @SUITE
    def law(items: list[SketchItem]) -> None:
        sketch = build(cls, items)
        empty = cls.identity(SMALL_PARAMS)
        assert sketch.merge(empty) == sketch
        assert empty.merge(sketch) == sketch

    law()


# --------------------------------------------------------------------------------------
# Law 2 -- commutativity
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_merge_is_commutative(cls: type[BaseSketch]) -> None:
    """``a.merge(b) == b.merge(a)``, in full internal state, for every kind.

    Bounded kinds included, and that is not an accident: a bounded merge unions both
    operands before deciding what to discard, and the decision is a pure function of the
    union. Commutativity is what lets the time hierarchy fold a window's contributions
    without caring which shard was read first.
    """

    @given(left=item_lists(cls.ITEM_FLAVOUR), right=item_lists(cls.ITEM_FLAVOUR))
    @SUITE
    def law(left: list[SketchItem], right: list[SketchItem]) -> None:
        a, b = build(cls, left), build(cls, right)
        assert a.merge(b) == b.merge(a)

    law()


# --------------------------------------------------------------------------------------
# Law 1 -- associativity
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", EXACT_SKETCHES, ids=_ids(EXACT_SKETCHES))
def test_merge_is_exactly_associative(cls: type[BaseSketch]) -> None:
    """For EXACT kinds, law 1 holds as the contract writes it: byte-for-byte equality."""

    @given(
        x=item_lists(cls.ITEM_FLAVOUR),
        y=item_lists(cls.ITEM_FLAVOUR),
        z=item_lists(cls.ITEM_FLAVOUR),
    )
    @SUITE
    def law(x: list[SketchItem], y: list[SketchItem], z: list[SketchItem]) -> None:
        a, b, c = build(cls, x), build(cls, y), build(cls, z)
        assert a.merge(b).merge(c) == a.merge(b.merge(c))

    law()


@pytest.mark.parametrize("cls", BOUNDED_SKETCHES, ids=_ids(BOUNDED_SKETCHES))
def test_merge_is_associative_within_the_bound(cls: type[BaseSketch]) -> None:
    """For BOUNDED kinds, the two bracketings agree on what downstream actually reads.

    Not byte equality, which is impossible once a bounded summary has truncated -- see
    ``docs/change-requests/CR-A2-monoid-law-exactness.md`` and
    ``test_contract_gaps.py``, which demonstrates the failure rather than asserting it
    away.

    Two things are asserted, and deliberately not a third. The population is exact: it
    is a counter, and no amount of truncation may lose track of how many rows were
    measured. And the two bracketings agree on *which* feature slots apply -- the NaN
    pattern -- because a slot appearing in one bracketing and not the other would mean
    the kind itself changed shape, which is a bug rather than an approximation.

    What is not asserted is agreement on the numbers. That is the bounded part, and the
    right instrument for it is a per-kind accuracy test at realistic parameters
    (``test_accuracy.py``), not a generic tolerance here: with ``capacity=8`` a
    Count-Min's retained-counter count legitimately differs between bracketings, and a
    loose enough tolerance to allow that would be loose enough to hide anything.
    """

    @given(
        x=item_lists(cls.ITEM_FLAVOUR),
        y=item_lists(cls.ITEM_FLAVOUR),
        z=item_lists(cls.ITEM_FLAVOUR),
    )
    @SUITE
    def law(x: list[SketchItem], y: list[SketchItem], z: list[SketchItem]) -> None:
        a, b, c = build(cls, x), build(cls, y), build(cls, z)
        left = a.merge(b).merge(c)
        right = a.merge(b.merge(c))
        assert left.population == right.population
        ctx = context()
        left_vector = extract_features(left.serialise(ctx), small_cell_threshold=0)
        right_vector = extract_features(right.serialise(ctx), small_cell_threshold=0)
        assert [math.isnan(v) for v in left_vector] == [math.isnan(v) for v in right_vector]

    law()


# --------------------------------------------------------------------------------------
# Law 7 -- population is additive
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_population_is_additive_under_merge(cls: type[BaseSketch]) -> None:
    """Contract law 7. Population is a count of what went in, never an estimate."""

    @given(left=item_lists(cls.ITEM_FLAVOUR), right=item_lists(cls.ITEM_FLAVOUR))
    @SUITE
    def law(left: list[SketchItem], right: list[SketchItem]) -> None:
        a, b = build(cls, left), build(cls, right)
        assert a.merge(b).population == a.population + b.population

    law()


# --------------------------------------------------------------------------------------
# Law 4 -- merging across parameters must raise, not guess
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_merge_refuses_mismatched_parameters(cls: type[BaseSketch]) -> None:
    """Two sketches built differently must refuse to merge.

    Silently merging two KLL sketches with different ``k``, or two Count-Min matrices
    with different seeds, produces a plausible number that is wrong, and nothing above
    L1 can detect it. An exception is the strictly better outcome.
    """
    a = cls.from_items([], SMALL_PARAMS)
    b = cls.from_items([], OTHER_PARAMS)
    if not a.params:
        # Moments and NullRate take no parameters at all, so there is no such thing as
        # an incompatible pair of them and any two are safely mergeable. Asserting a
        # refusal here would be asserting a bug.
        assert a.fingerprint == b.fingerprint
        assert a.merge(b).population == 0
        return
    assert a.fingerprint != b.fingerprint
    with pytest.raises(IncompatibleMergeError):
        a.merge(b)


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_merge_does_not_mutate_its_operands(cls: type[BaseSketch]) -> None:
    """``merge`` returns a new sketch. A fold that corrupted its inputs would make the
    time hierarchy's re-folding return different answers on the second read."""

    @given(left=item_lists(cls.ITEM_FLAVOUR, min_size=1), right=item_lists(cls.ITEM_FLAVOUR))
    @SUITE
    def law(left: list[SketchItem], right: list[SketchItem]) -> None:
        a, b = build(cls, left), build(cls, right)
        before_a, before_b = a.encode(), b.encode()
        a.merge(b)
        assert a.encode() == before_a
        assert b.encode() == before_b

    law()


# --------------------------------------------------------------------------------------
# Law 5 -- serialisation round-trips
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_decode_of_serialise_is_identity(cls: type[BaseSketch]) -> None:
    """``decode(x.serialise()) == x``, for every x. Contract law 5."""

    @given(items=item_lists(cls.ITEM_FLAVOUR))
    @SUITE
    def law(items: list[SketchItem]) -> None:
        sketch = build(cls, items)
        assert cls.decode(sketch.serialise(context())) == sketch

    law()


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_building_twice_gives_identical_bytes(cls: type[BaseSketch]) -> None:
    """Determinism, universal rule 5. The same items always give the same sketch.

    This is the law the upstream KLL fails, and the reason
    :class:`~godwit_sketch.quantile.KllQuantile` is implemented here rather than wrapped.
    """

    @given(items=item_lists(cls.ITEM_FLAVOUR))
    @SUITE
    def law(items: list[SketchItem]) -> None:
        assert build(cls, items).encode() == build(cls, items).encode()

    law()


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=_ids(ALL_SKETCHES))
def test_merge_order_does_not_change_the_estimate_beyond_the_bound(
    cls: type[BaseSketch],
) -> None:
    """Folding four shards in two different orders lands in the same place.

    The stronger statement for EXACT kinds -- identical bytes under every permutation --
    is covered by the associativity law above. This one is about the estimate a detector
    would read, which is the thing that must not depend on how the data was sharded.
    """

    @given(
        parts=item_lists(cls.ITEM_FLAVOUR, min_size=4, max_size=40),
    )
    @SUITE
    def law(parts: list[SketchItem]) -> None:
        quarter = max(1, len(parts) // 4)
        shards = [
            build(cls, parts[0:quarter]),
            build(cls, parts[quarter : 2 * quarter]),
            build(cls, parts[2 * quarter : 3 * quarter]),
            build(cls, parts[3 * quarter :]),
        ]
        forward = shards[0].merge(shards[1]).merge(shards[2]).merge(shards[3])
        backward = shards[3].merge(shards[2]).merge(shards[1]).merge(shards[0])
        assert forward.population == backward.population
        ctx = context()
        forward_vector = extract_features(forward.serialise(ctx), small_cell_threshold=0)
        backward_vector = extract_features(backward.serialise(ctx), small_cell_threshold=0)
        if cls.MERGE_EXACTNESS is MergeExactness.EXACT:
            assert same_vector(forward_vector, backward_vector, tolerance=1e-9)
        else:
            assert [math.isnan(v) for v in forward_vector] == [
                math.isnan(v) for v in backward_vector
            ]

    law()
