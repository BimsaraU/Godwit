"""The acceptance properties: purity, seasonality, suppression, and no hidden clock."""

from __future__ import annotations

import ast
import math
from pathlib import Path

import pytest
from _detect_scenarios import SCENARIOS
from _detect_support import categories, rng, series, snapshot
from godwit_detect import (
    REGISTRY,
    DetectionResult,
    FixedReference,
    HeavyHitterShift,
    JensenShannonDrift,
    PsiDrift,
    Seasonal,
    Trailing,
    WassersteinDrift,
)
from godwit_sketch import CategoryHistogram, KllQuantile
from godwit_sketch.deterministic import lognormals
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

SOURCE = Path(__file__).resolve().parents[1] / "src" / "godwit_detect"


def _dump(result: DetectionResult) -> object:
    return result.model_dump(mode="json")


# -- purity ----------------------------------------------------------------------------


def test_every_registered_detector_has_a_scenario() -> None:
    assert set(SCENARIOS) == set(REGISTRY)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_detector_is_pure_on_its_scenario(name: str) -> None:
    """Same input, same output, in the same order -- run three times."""
    first, second, third = (SCENARIOS[name]() for _ in range(3))
    assert _dump(first) == _dump(second) == _dump(third)
    assert first.findings, f"{name}'s scenario should produce at least one finding"


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    seed=st.integers(0, 2**31),
    shift=st.floats(-0.5, 0.5),
    n=st.integers(120, 1500),
    detector=st.sampled_from([PsiDrift(), WassersteinDrift()]),
)
def test_numeric_drift_is_pure_for_any_input(
    seed: int, shift: float, n: int, detector: PsiDrift | WassersteinDrift
) -> None:
    def build() -> DetectionResult:
        generator = rng(seed)
        data = [
            KllQuantile.from_items(list(generator.lognormal(3.0 + s, 0.7, n)), {"k": 64, "seed": 1})
            for s in (0.0, shift)
        ]
        return detector.run(series(data), policy=FixedReference(snapshot_id=snapshot(0)))

    assert _dump(build()) == _dump(build())


@settings(max_examples=25, deadline=None)
@given(
    seed=st.integers(0, 2**31),
    weights=st.lists(st.integers(1, 50), min_size=2, max_size=12),
    detector=st.sampled_from([JensenShannonDrift(), HeavyHitterShift(), PsiDrift()]),
)
def test_categorical_detectors_are_pure_for_any_input(
    seed: int, weights: list[int], detector: JensenShannonDrift | HeavyHitterShift | PsiDrift
) -> None:
    def build() -> DetectionResult:
        generator = rng(seed)
        data = [
            CategoryHistogram.from_items(categories(generator, weights, 400), {}) for _ in range(3)
        ]
        return detector.run(series(data), policy=Trailing(points=2))

    assert _dump(build()) == _dump(build())


_FORBIDDEN_CALLS = {
    "now",
    "utcnow",
    "today",
    "time",
    "perf_counter",
    "monotonic",
    "random",
    "urandom",
}
_FORBIDDEN_MODULES = {"random", "secrets", "time", "socket", "urllib", "http", "requests", "os"}


@pytest.mark.parametrize("path", sorted(SOURCE.glob("*.py")), ids=lambda p: p.name)
def test_no_clock_randomness_or_io_in_source(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            assert not {n.split(".")[0] for n in names} & _FORBIDDEN_MODULES, (path.name, names)
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_CALLS:
            raise AssertionError(f"{path.name}:{node.lineno} reads {node.attr}")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
        ):
            raise AssertionError(f"{path.name}:{node.lineno} opens a file")


# -- seasonality -----------------------------------------------------------------------


_QUIET_LIMIT = 3


def _weekly(weeks: int = 6) -> tuple[list[KllQuantile], list[CategoryHistogram]]:
    """Daily windows with a strong weekly cycle: weekends spend more, on other channels."""
    amounts: list[KllQuantile] = []
    channels: list[CategoryHistogram] = []
    for day in range(7 * weeks):
        weekend = day % 7 in (5, 6)
        generator = rng(1000 + day)
        mu = 3.9 if weekend else 3.0
        # Portable lognormals, not numpy's: numpy's goes through the C library's exp, whose
        # last bit differs between Windows and Linux, and KLL compaction turns a last-bit
        # difference into a different sketch.
        values = lognormals(2000, salt=f"weekly-{day}", mu=mu, sigma=0.7)
        amounts.append(KllQuantile.from_items(values, {"k": 200, "seed": 5}))
        shares = [10, 30, 60] if weekend else [60, 30, 10]
        channels.append(CategoryHistogram.from_items(categories(generator, shares, 2000), {}))
    return amounts, channels


@pytest.mark.parametrize(
    "detector",
    [PsiDrift(), WassersteinDrift(), JensenShannonDrift(), HeavyHitterShift()],
    ids=lambda d: d.NAME,
)
def test_a_weekly_series_is_quiet_under_the_seasonal_baseline(
    detector: PsiDrift | WassersteinDrift | JensenShannonDrift | HeavyHitterShift,
) -> None:
    amounts, channels = _weekly()
    data = channels if isinstance(detector, JensenShannonDrift | HeavyHitterShift) else amounts
    seasonal = Seasonal(period=7, cycles=4)
    fired_seasonal = 0
    fired_trailing = 0
    for end in range(28, len(data)):
        window = series(data[: end + 1])
        current = window.current.envelope
        if current is None or not detector.accepts(current):
            continue
        fired_seasonal += len(detector.run(window, policy=seasonal).findings)
        fired_trailing += len(detector.run(window, policy=Trailing(points=3)).findings)
    # Each window is one raw test at alpha, so a quiet detector still fires by chance:
    # 14 windows at alpha = 0.05 expect 0.7 false findings. Three or fewer covers 99.6%
    # of quiet runs (binomial). The trailing baseline, which compares weekends with
    # weekdays, must fire on the cycle.
    windows = len(data) - 28
    assert fired_seasonal <= _QUIET_LIMIT, (fired_seasonal, windows)
    assert fired_trailing > 0, "the trailing baseline should fire on the weekly cycle"


# -- suppression -----------------------------------------------------------------------

_IDENTITY_FREE_MINIMUM = 1


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_finding_survives_identity_suppression(name: str) -> None:
    """Strip every heavy-hitter key, label and entity. What is left must still say how far
    something moved, which way, and how surely."""
    for finding in SCENARIOS[name]().findings:
        stripped = finding.without_identities()
        assert not stripped.carries_identities
        assert stripped.effect == finding.effect and math.isfinite(stripped.effect.value.reveal())
        assert stripped.direction == finding.direction
        assert stripped.p_value == finding.p_value
        assert stripped.p_value is not None or stripped.p_value_note
        if finding.carries_identities:
            assert len(stripped.shape) >= _IDENTITY_FREE_MINIMUM, (
                f"{name}/{finding.method} carries identities but no identity-free shape"
            )
        assert {a.feature for a in stripped.attribution} == {a.feature for a in finding.attribution}
