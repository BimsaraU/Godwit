"""Evidence for the change requests. These tests document, they do not work around.

Universal rule 2: a contract that is wrong, missing or impossible gets a change request
and a failing ``xfail`` test showing what was needed -- never a quiet patch. Each xfail
below corresponds to one file in ``docs/change-requests/``. When A0 accepts a request,
the matching test starts passing as ``XPASS`` and the suite says so, which is how this
package finds out that a contract moved.

The non-xfail tests in this module pin *upstream* behaviour that forced a design
decision. If a future DataSketches release fixes one of them, the test fails and the
next maintainer is told which module can be deleted, rather than having to rediscover
the problem from scratch.
"""

from __future__ import annotations

import hashlib
from collections.abc import Buffer

import datasketches as ds
import pytest
from _support import SMALL_PARAMS
from godwit_contracts.sketch import ITEM_BEARING_KINDS, SketchKind
from godwit_sketch.frequency import CountMinHeavy
from godwit_sketch.quantile import KllQuantile

# --------------------------------------------------------------------------------------
# CR-A2-sketch-kind-vocabulary
# --------------------------------------------------------------------------------------


@pytest.mark.xfail(
    reason="CR-A2-sketch-kind-vocabulary: SketchKind has no member for Moments, "
    "NullRate, category histograms or graph degree, so four classes share a kind with "
    "something else and are told apart by codec",
    strict=True,
)
def test_sketch_kind_covers_every_kind_the_brief_requires() -> None:
    """The A2 brief requires eight sketches; the contract vocabulary names six kinds.

    ``SketchKind`` is closed -- "a kind not listed here cannot cross a package boundary"
    -- so Moments and NullRate currently serialise as ``EXACT_COUNT``, the category
    histogram as ``FREQUENT_ITEMS`` and graph degree as ``COUNT_MIN``, each with its own
    codec. That works, and it means a detector switching on ``kind`` cannot tell a
    moment summary from a row count.
    """
    names = {kind.name for kind in SketchKind}
    assert {"MOMENTS", "NULL_RATE", "CATEGORY_HISTOGRAM", "GRAPH_DEGREE"} <= names


# --------------------------------------------------------------------------------------
# CR-A2-kll-is-item-bearing
# --------------------------------------------------------------------------------------


@pytest.mark.xfail(
    reason="CR-A2-kll-is-item-bearing: a KLL payload retains real row values, but the "
    "contract lists only COUNT_MIN and FREQUENT_ITEMS as item-bearing",
    strict=True,
)
def test_kll_is_listed_as_item_bearing() -> None:
    """A quantile sketch stores sampled items verbatim. That is a leak path.

    This package declares its KLL envelopes DATA_VALUE anyway -- an envelope may always
    be *more* restricted than its floor -- so nothing is currently leaking through here.
    What the contract's classification does is invite the next implementer to declare a
    quantile sketch a derived statistic, which the shipped golden fixture already does.
    """
    assert SketchKind.KLL in ITEM_BEARING_KINDS


def test_a_kll_payload_really_does_contain_row_values() -> None:
    """The evidence behind the request above, as a runnable demonstration.

    A distinctive value is fed in among ordinary ones and then found verbatim in the
    serialised bytes.
    """
    distinctive = 987654.3125  # exactly representable, so the search is unambiguous
    sketch = KllQuantile.from_items(
        [float(v) for v in range(400)] + [distinctive], {"k": 32, "seed": 1}
    )
    import struct

    assert struct.pack(">d", distinctive) in sketch.encode()
    assert sketch.maximum().reveal() == distinctive


def test_the_golden_kll_envelope_declares_a_derived_statistic(golden_json: object) -> None:
    """The shipped fixture classifies a KLL envelope as safe. Pinned so the CR has a cite.

    A0 owns ``tests/golden/sketch_envelopes.json`` and this package does not edit it.
    When the classification is corrected, this test fails and this module is the place
    that explains why.
    """
    load = golden_json
    assert callable(load)
    payload = load("sketch_envelopes.json")
    kll = [e for e in payload["envelopes"] if e["kind"] == "kll"]
    assert kll, "the fixture no longer contains a kll envelope"
    assert kll[0]["sensitivity"] == "derived_statistic"


# --------------------------------------------------------------------------------------
# CR-A2-monoid-law-exactness
# --------------------------------------------------------------------------------------


@pytest.mark.xfail(
    reason="CR-A2-monoid-law-exactness: exact associativity is impossible for a bounded "
    "lossy summary; the law needs restating as 'within the documented bound'",
    strict=True,
)
def test_bounded_kinds_are_exactly_associative() -> None:
    """Demonstrates the impossibility rather than asserting it away.

    Once an intermediate merge has discarded counters to stay inside ``capacity``, a
    later merge cannot bring them back, and a different bracketing discards a different
    set. No implementation can repeal this: it is a property of bounded lossy summaries,
    not a defect in this one.
    """
    params = {**SMALL_PARAMS, "capacity": 2, "width": 32, "depth": 2}
    a = CountMinHeavy.from_items(["a"] * 9 + ["b"] * 7, params)
    b = CountMinHeavy.from_items(["c"] * 8 + ["d"] * 6, params)
    c = CountMinHeavy.from_items(["b"] * 5 + ["e"] * 4, params)
    assert a.merge(b).merge(c) == a.merge(b.merge(c))


def test_bounded_kinds_still_agree_on_the_population() -> None:
    """What does survive bracketing: the row count is a counter and is never approximate."""
    params = {**SMALL_PARAMS, "capacity": 2}
    a = CountMinHeavy.from_items(["a"] * 9, params)
    b = CountMinHeavy.from_items(["c"] * 8, params)
    c = CountMinHeavy.from_items(["b"] * 5, params)
    assert a.merge(b).merge(c).population == a.merge(b.merge(c)).population == 22


# --------------------------------------------------------------------------------------
# CR-A2-serialise-needs-context
# --------------------------------------------------------------------------------------


def test_serialise_without_context_refuses_rather_than_inventing_one() -> None:
    """The ``Sketch`` protocol declares ``serialise(self)``, which cannot build an envelope.

    An envelope needs ``source_id``, ``snapshot_id``, ``produced_for`` and
    ``produced_at``. A sketch knows none of them and should not: holding run metadata
    would make two sketches of the same snapshot differ in fields unrelated to their
    contents, and merge would need a reconciliation rule for it.

    The zero-argument shape stays callable so the protocol is satisfied structurally; it
    raises, because an envelope with no snapshot cannot be stored or replayed.
    """
    sketch = KllQuantile.from_items([1.0], SMALL_PARAMS)
    with pytest.raises(ValueError, match="SketchContext"):
        sketch.serialise()


# --------------------------------------------------------------------------------------
# Upstream behaviour that forced a decision here. Not xfail: these must keep holding,
# or the module that worked around them can be retired.
# --------------------------------------------------------------------------------------


def _digest(payload: Buffer) -> str:
    return hashlib.sha256(bytes(payload)).hexdigest()


def test_upstream_kll_is_still_non_deterministic() -> None:
    """Why :mod:`godwit_sketch.quantile` exists.

    Two sketches built from identical values in the same process serialise differently,
    as soon as ``n`` passes ``k`` and the first randomised compaction happens. If this
    ever starts failing, DataSketches has become reproducible and the hand-written KLL
    can be reconsidered -- see ``docs/change-requests/CR-A2-kll-determinism.md``.
    """
    values = [float(v) for v in range(2000)]

    def build() -> str:
        sketch = ds.kll_floats_sketch(200)
        for value in values:
            sketch.update(value)
        return _digest(sketch.serialize())

    assert build() != build(), "upstream KLL has become deterministic; revisit the CR"


def test_upstream_kll_has_no_seed_parameter() -> None:
    """There is no way to pin the compaction coin from the Python binding."""
    with pytest.raises(TypeError):
        ds.kll_floats_sketch(200, 7)


def test_upstream_kll_is_deterministic_below_k() -> None:
    """The non-determinism starts at the first compaction, not before.

    Worth pinning because it is exactly why the problem would survive a small test
    suite: at or below ``k`` items everything reproduces perfectly, and the divergence
    only appears once real volume forces a compaction.

    Only the "still deterministic" half is asserted here. The obvious companion --
    ``build(k + 1) != build(k + 1)`` -- is **not** a valid assertion: after a single
    compaction the two runs have flipped one coin each and agree half the time, so that
    test would fail roughly one run in two. The divergence is asserted at 2000 items in
    ``test_upstream_kll_is_still_non_deterministic``, where many compactions have
    happened and coincidental agreement is negligible.
    """

    def build(count: int) -> str:
        sketch = ds.kll_floats_sketch(200)
        for value in range(count):
            sketch.update(float(value))
        return _digest(sketch.serialize())

    assert build(200) == build(200)
    assert build(199) == build(199)


def test_upstream_hll_is_deterministic_but_not_canonical() -> None:
    """Why :mod:`godwit_sketch.hll` exists.

    Upstream HLL reproduces byte for byte across runs -- unlike KLL -- but below its
    sparse threshold it stores a coupon list in insertion order, so two unions of the
    same pair in opposite orders agree on the estimate and disagree on the bytes. That
    is fatal to a hierarchy whose equivalence guarantee is byte-level.
    """

    def single(key: str) -> ds.hll_sketch:
        sketch = ds.hll_sketch(8, ds.tgt_hll_type.HLL_4)
        sketch.update(key)
        return sketch

    def union(first: str, second: str) -> ds.hll_sketch:
        merged = ds.hll_union(8)
        merged.update(single(first))
        merged.update(single(second))
        return merged.get_result(ds.tgt_hll_type.HLL_4)

    forward, backward = union("a", "b"), union("b", "a")
    assert forward.get_estimate() == backward.get_estimate()
    assert _digest(forward.serialize_compact()) != _digest(backward.serialize_compact())


def test_upstream_theta_unions_byte_identically_in_every_order() -> None:
    """Why Theta *is* wrapped: it is both deterministic and order-free.

    Pinned so that a DataSketches upgrade which broke it would be caught here rather
    than showing up as phantom drift in a detector.
    """
    import itertools

    def part(low: int, high: int) -> ds.compact_theta_sketch:
        sketch = ds.update_theta_sketch(lg_k=10, seed=9001)
        for value in range(low, high):
            sketch.update(float(value))
        return sketch.compact(ordered=True)

    parts = [part(index * 3000, (index + 1) * 3000) for index in range(3)]

    digests = set()
    for order in itertools.permutations(range(3)):
        union = ds.theta_union(lg_k=10, seed=9001)
        for index in order:
            union.update(parts[index])
        digests.add(_digest(union.get_result(ordered=True).serialize()))
    assert len(digests) == 1
