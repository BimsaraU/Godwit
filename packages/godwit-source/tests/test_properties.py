"""Property tests for the claims this package makes about its own maths and encoding."""

from __future__ import annotations

import math
import statistics

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from godwit_source.detectors import _median, _p_from_z, _robust_z, _two_proportion_z
from godwit_source.puffin import Blob, read_puffin, write_puffin

finite = st.floats(min_value=-1e9, max_value=1e9, allow_nan=False, allow_infinity=False)
series = st.lists(finite, min_size=2, max_size=40)


def _mad(xs: list[float]) -> float:
    med = _median(xs)
    return _median([abs(v - med) for v in xs])


def _scale_survives(original: list[float], transformed: list[float], expected: float) -> bool:
    """True when a transform changed the median-absolute-deviation by exactly the factor it
    should have, rather than destroying it to floating-point absorption.

    Adding 1.0 to ``[0.0, 1.0, 3e-234]`` gives ``[1.0, 2.0, 1.0]``: the spread survives but
    the MAD does not, because the tiny element is absorbed into the exponent of 1.0. No
    scale estimator can be equivariant across that, so the property is stated only where the
    arithmetic preserved the quantity being measured. The degenerate case is safe in
    production: it drives ``z`` toward zero, which is a missed signal, not a false pattern.

    A constant baseline is excluded for a different reason: it has no scale at all, so
    ``_robust_z`` returns a saturation flag rather than a score, and a flag is not a
    continuous function of its input. That branch is pinned by
    :func:`test_constant_baseline_saturates` instead.
    """
    before, after = _mad(original), _mad(transformed)
    if before <= 0.0 or after <= 0.0:
        return False
    return abs(after / before - expected) <= 1e-9 * expected


@given(series)
def test_median_matches_the_standard_library(xs: list[float]) -> None:
    assert _median(xs) == statistics.median(xs)


@given(series, finite, finite)
def test_robust_z_is_translation_invariant(xs: list[float], x: float, shift: float) -> None:
    """Median/MAD is location-equivariant, so the score must not move when the whole series
    moves. Without this, a table whose ids simply grow would score as drift forever.

See :func:`_scale_survives` for the one class of input this is not asserted over.
    """
    shifted = [v + shift for v in xs]
    assume(_scale_survives(xs, shifted, 1.0))
    base_z, _ = _robust_z(xs, x)
    shifted_z, _ = _robust_z(shifted, x + shift)
    assert abs(base_z - shifted_z) <= 1e-6 * max(1.0, abs(base_z))


@given(series, finite, st.floats(min_value=0.001, max_value=1000.0))
def test_robust_z_is_scale_invariant(xs: list[float], x: float, scale: float) -> None:
    """Scale-equivariance is what lets one alpha work for byte counts and for rates alike."""
    scaled = [v * scale for v in xs]
    assume(_scale_survives(xs, scaled, scale))
    base_z, _ = _robust_z(xs, x)
    scaled_z, _ = _robust_z(scaled, x * scale)
    assert abs(base_z - scaled_z) <= 1e-6 * max(1.0, abs(base_z))


def test_constant_baseline_saturates() -> None:
    """With no spread there is no scale, so the score is a flag: zero on a match, saturated
    otherwise. Saturating rather than returning infinity matters -- an infinite z outranks
    every real finding in the queue."""
    assert _robust_z([5.0, 5.0, 5.0], 5.0) == (0.0, 1.0)
    z, p = _robust_z([5.0, 5.0, 5.0], 6.0)
    assert z == 8.0
    assert 0.0 < p < 1e-10


def test_underflowed_spread_does_not_divide_by_zero() -> None:
    """``spread / 2`` can itself underflow to zero on subnormal input."""
    z, p = _robust_z([0.0, 5e-324], 0.0)
    assert math.isfinite(z)
    assert 0.0 <= p <= 1.0


@given(series)
def test_robust_z_of_the_median_is_zero(xs: list[float]) -> None:
    z, p = _robust_z(xs, _median(xs))
    assert z == 0.0
    assert p == 1.0


@given(
    st.integers(min_value=0, max_value=10_000),
    st.integers(min_value=1, max_value=10_000),
    st.integers(min_value=0, max_value=10_000),
    st.integers(min_value=1, max_value=10_000),
)
def test_two_proportion_z_is_antisymmetric(
    e1: int, n1: int, e2: int, n2: int
) -> None:
    assume(e1 <= n1 and e2 <= n2)
    forward, _ = _two_proportion_z(e1, n1, e2, n2)
    backward, _ = _two_proportion_z(e2, n2, e1, n1)
    assert abs(forward + backward) <= 1e-6 * max(1.0, abs(forward))


@given(st.floats(min_value=-40.0, max_value=40.0, allow_nan=False))
def test_p_is_a_probability_and_symmetric_in_sign(z: float) -> None:
    p = _p_from_z(z)
    assert 0.0 <= p <= 1.0
    assert _p_from_z(-z) == p


@given(
    st.floats(min_value=0.0, max_value=20.0),
    st.floats(min_value=0.0, max_value=20.0),
)
def test_p_decreases_with_distance(a: float, b: float) -> None:
    assume(a <= b)
    assert _p_from_z(a) >= _p_from_z(b)


blob_strategy = st.builds(
    Blob,
    type=st.sampled_from(["godwit-metadata-stats-v1", "apache-datasketches-theta-v1"]),
    fields=st.tuples(st.integers(min_value=1, max_value=100)),
    snapshot_id=st.integers(min_value=0, max_value=2**62),
    sequence_number=st.integers(min_value=0, max_value=2**31),
    data=st.binary(min_size=0, max_size=512),
    properties=st.dictionaries(
        st.text(min_size=1, max_size=12), st.text(max_size=12), max_size=4
    ),
)


@settings(max_examples=100)
@given(st.lists(blob_strategy, min_size=1, max_size=6))
def test_puffin_round_trips_any_blob(blobs: list[Blob]) -> None:
    """Arbitrary payloads, including bytes that look like the magic, survive a round trip."""
    got, _ = read_puffin(write_puffin(blobs))
    assert [(b.type, b.fields, b.snapshot_id, b.data) for b in got] == [
        (b.type, b.fields, b.snapshot_id, b.data) for b in blobs
    ]
