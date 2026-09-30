"""The feature vector: fixed length, documented layout, and no embedded values.

A7, A11, A12 and A13 read this vector and cannot ask what a column means, so the
contract between them and this package is :data:`~godwit_sketch.features.FEATURE_LAYOUT`
itself. These tests pin the properties those four agents are entitled to rely on:

* the length never changes with the kind;
* the names are unique, stable and documented;
* a slot that does not apply is NaN and not zero;
* no value out of a row is anywhere in it.
"""

from __future__ import annotations

import math

import pytest
from _support import SMALL_PARAMS, context
from godwit_sketch.base import BaseSketch, SketchItem, registered_sketches
from godwit_sketch.features import (
    CDF_GRID_SLOTS,
    DEFAULT_SMALL_CELL_THRESHOLD,
    FEATURE_LAYOUT,
    extract_features,
    feature_index,
)
from godwit_sketch.frequency import CountMinHeavy
from godwit_sketch.graph import GraphDegree
from godwit_sketch.moments import Moments, NullRate
from godwit_sketch.quantile import KllQuantile

ALL_SKETCHES = registered_sketches()
IDS = [c.__name__ for c in ALL_SKETCHES]


def _items(cls: type[BaseSketch], count: int = 60) -> list[SketchItem]:
    flavour = cls.ITEM_FLAVOUR.value
    if flavour == "numeric":
        return [float(index % 17) for index in range(count)]
    if flavour == "edge":
        return [(f"s{index % 7}", f"t{index % 5}") for index in range(count)]
    return [f"k{index % 9}" for index in range(count)]


# --------------------------------------------------------------------------------------
# Layout
# --------------------------------------------------------------------------------------


def test_slot_names_are_unique() -> None:
    """Duplicated names would make ``feature_index`` silently return the wrong column."""
    names = [slot.name for slot in FEATURE_LAYOUT]
    assert len(names) == len(set(names))


def test_every_slot_is_documented() -> None:
    """A downstream agent reads the description instead of asking. It has to be there."""
    for slot in FEATURE_LAYOUT:
        assert slot.description.strip()
        assert len(slot.description) > 20, f"{slot.name} needs a real description"


def test_feature_index_resolves_names_and_rejects_unknown_ones() -> None:
    """Callers address columns by name, never by a literal offset."""
    assert feature_index("population") == 0
    assert FEATURE_LAYOUT[feature_index("null_rate")].name == "null_rate"
    with pytest.raises(KeyError, match="no feature slot named"):
        feature_index("not_a_slot")


def test_the_layout_reserves_the_advertised_number_of_cdf_slots() -> None:
    """The CDF block is generated, so its size and the constant must agree."""
    cdf = [slot for slot in FEATURE_LAYOUT if slot.name.startswith("cdf_")]
    assert len(cdf) == CDF_GRID_SLOTS


def test_no_slot_exposes_an_extreme() -> None:
    """Invariant 2 at the vector's boundary.

    No minimum, no maximum, no quantile, no range. The module docstring explains why a
    standardised extreme is not a way around this: the vector carries mean and stddev,
    so any rearrangement of the extreme solves straight back to it.
    """
    forbidden = ("min", "max", "quantile_value", "range", "extreme", "p50", "p99", "median")
    for slot in FEATURE_LAYOUT:
        lowered = slot.name.lower()
        for token in forbidden:
            assert token not in lowered, f"{slot.name} looks like it exposes an extreme"


# --------------------------------------------------------------------------------------
# The vector
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=IDS)
def test_vector_length_is_fixed_for_every_kind(cls: type[BaseSketch]) -> None:
    """One length, always. A13 builds a matrix out of these and cannot handle ragged rows."""
    envelope = cls.from_items(_items(cls), SMALL_PARAMS).serialise(context())
    assert len(extract_features(envelope)) == len(FEATURE_LAYOUT)


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=IDS)
def test_vector_length_is_fixed_for_an_empty_sketch(cls: type[BaseSketch]) -> None:
    """Including when nothing was measured, which is the case a gap produces."""
    envelope = cls.from_items([], SMALL_PARAMS).serialise(context())
    vector = extract_features(envelope)
    assert len(vector) == len(FEATURE_LAYOUT)
    assert vector[feature_index("population")] == 0.0


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=IDS)
def test_extraction_is_pure(cls: type[BaseSketch]) -> None:
    """Same envelope, same vector. No clock, no randomness, no accumulated state."""
    envelope = cls.from_items(_items(cls), SMALL_PARAMS).serialise(context())
    first = extract_features(envelope)
    second = extract_features(envelope)
    assert [math.isnan(v) for v in first] == [math.isnan(v) for v in second]
    assert all(a == b for a, b in zip(first, second, strict=True) if not math.isnan(a))


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=IDS)
def test_inapplicable_slots_are_nan_not_zero(cls: type[BaseSketch]) -> None:
    """Zero is a measurement; NaN is the absence of one.

    A model that cannot tell them apart learns that a missing Theta sketch means a
    column with no distinct values.
    """
    envelope = cls.from_items(_items(cls), SMALL_PARAMS).serialise(context())
    vector = extract_features(envelope)
    if cls is not NullRate:
        assert math.isnan(vector[feature_index("null_rate")])
    if cls is not GraphDegree:
        assert math.isnan(vector[feature_index("graph_edge_multiplicity")])


def test_universal_slots_are_populated_for_every_kind() -> None:
    """The first six slots describe the sketch itself and always apply."""
    for cls in ALL_SKETCHES:
        envelope = cls.from_items(_items(cls), SMALL_PARAMS).serialise(context())
        vector = extract_features(envelope)
        for name in ("population", "log1p_population", "error_epsilon", "value_bearing"):
            assert not math.isnan(vector[feature_index(name)]), f"{cls.__name__}: {name}"


def test_value_bearing_flag_matches_the_class() -> None:
    """The flag is metadata about the sketch, and it must not lie."""
    for cls in ALL_SKETCHES:
        envelope = cls.from_items(_items(cls), SMALL_PARAMS).serialise(context())
        vector = extract_features(envelope)
        assert vector[feature_index("value_bearing")] == (1.0 if cls.VALUE_BEARING else 0.0)


# --------------------------------------------------------------------------------------
# Small cells
# --------------------------------------------------------------------------------------


def test_small_populations_blank_the_scale_slots() -> None:
    """The mean of one row is that row, so it does not travel in a control-plane vector."""
    tiny = Moments.from_items([41000.0, 44100.0], SMALL_PARAMS).serialise(context())
    vector = extract_features(tiny, small_cell_threshold=DEFAULT_SMALL_CELL_THRESHOLD)
    for name in ("moments_mean", "moments_stddev", "moments_sum"):
        assert math.isnan(vector[feature_index(name)]), name


def test_large_populations_keep_the_scale_slots() -> None:
    """Above the threshold the aggregates are aggregates again."""
    big = Moments.from_items([float(v) for v in range(100)], SMALL_PARAMS).serialise(context())
    vector = extract_features(big)
    assert not math.isnan(vector[feature_index("moments_mean")])
    assert vector[feature_index("moments_mean")] == pytest.approx(49.5)


def test_threshold_zero_is_the_data_plane_escape_hatch() -> None:
    """Inside the perimeter a value is allowed to be a value."""
    tiny = Moments.from_items([41000.0, 44100.0], SMALL_PARAMS).serialise(context())
    vector = extract_features(tiny, small_cell_threshold=0)
    assert vector[feature_index("moments_mean")] == pytest.approx(42550.0)


# --------------------------------------------------------------------------------------
# Per-kind content
# --------------------------------------------------------------------------------------


def test_cdf_slots_fill_from_the_envelope_grid() -> None:
    """The CDF is the safe distribution export and comes from a probe parameter."""
    sketch = KllQuantile.from_items(
        [float(v) for v in range(100)], {"k": 64, "seed": 1, "cdf_grid": "10,50,90"}
    )
    vector = extract_features(sketch.serialise(context()))
    assert vector[feature_index("cdf_00")] == pytest.approx(0.11, abs=0.05)
    assert vector[feature_index("cdf_01")] == pytest.approx(0.51, abs=0.05)
    assert vector[feature_index("cdf_02")] == pytest.approx(0.91, abs=0.05)
    # Unused slots stay NaN rather than defaulting to a fraction.
    assert math.isnan(vector[feature_index("cdf_03")])


def test_no_grid_means_no_cdf_rather_than_a_guessed_one() -> None:
    """Inventing a grid from the data would make each fraction a statement about a value."""
    sketch = KllQuantile.from_items([float(v) for v in range(100)], {"k": 64, "seed": 1})
    vector = extract_features(sketch.serialise(context()))
    assert all(math.isnan(vector[feature_index(f"cdf_{i:02d}")]) for i in range(CDF_GRID_SLOTS))


def test_top1_share_catches_a_segment_taking_over() -> None:
    """The headline segment-divergence signal, and it names nobody."""
    quiet = CountMinHeavy.from_items(
        [f"c{index % 10}" for index in range(1000)], {"width": 512, "depth": 4, "seed": 1}
    )
    loud = CountMinHeavy.from_items(
        ["PT"] * 180 + [f"c{index % 10}" for index in range(820)],
        {"width": 512, "depth": 4, "seed": 1},
    )
    quiet_share = extract_features(quiet.serialise(context()))[feature_index("freq_top1_share")]
    loud_share = extract_features(loud.serialise(context()))[feature_index("freq_top1_share")]
    assert quiet_share < 0.15 < loud_share


def test_null_rate_distinguishes_no_rows_from_no_nulls() -> None:
    """An empty population gives NaN, not a clean bill of health."""
    empty = extract_features(NullRate.from_items([], SMALL_PARAMS).serialise(context()))
    assert math.isnan(empty[feature_index("null_rate")])
    clean = extract_features(NullRate.from_items(["a", "b"], SMALL_PARAMS).serialise(context()))
    assert clean[feature_index("null_rate")] == 0.0


def test_graph_slots_describe_a_funnel() -> None:
    """Many payers into one collector moves in-degree and concentration, not out-degree."""
    edges: list[object] = [(f"payer{index}", "COLLECTOR") for index in range(40)]
    edges += [(f"x{index}", f"y{index}") for index in range(40)]
    sketch = GraphDegree.from_items(edges, {"lg_k": 10, "width": 512, "depth": 4, "seed": 1})
    vector = extract_features(sketch.serialise(context()))
    assert (
        vector[feature_index("graph_mean_in_degree")]
        > vector[feature_index("graph_mean_out_degree")]
    )
    assert vector[feature_index("graph_concentration_in_top10")] > 0.4
    assert vector[feature_index("graph_fan_in_out_ratio")] > 1.5


def test_degree_population_is_zero_when_the_probe_did_not_pre_aggregate() -> None:
    """Zero here tells a detector the degree quantiles are empty, not that degrees are zero."""
    sketch = GraphDegree.from_items(
        [("a", "b"), ("a", "c")], {"lg_k": 10, "width": 512, "depth": 4, "seed": 1}
    )
    vector = extract_features(sketch.serialise(context()))
    assert vector[feature_index("graph_degree_population_in")] == 0.0
