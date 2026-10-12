"""Synthetic worlds for the null and power measurements, one per detector.

Each world takes ``(seed, effect, size)`` and returns a ``DetectionResult``. ``effect=0``
is the null: nothing injected. The effect's unit is per world and printed by the
benchmark next to the numbers; ``size`` is the sample size a user would think of --
rows per window, rows per segment, edges per window, series length.

numpy's seeded generator is fine here: these are Monte Carlo measurements, not pinned
hashes, and a numpy release that shifts the streams moves the estimates by noise only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

import numpy as np
from _detect_support import (
    DAY,
    EPOCH,
    categories,
    context,
    edges,
    envelope,
    eq_segment,
    rng,
    series,
    snapshot,
)
from godwit_detect import (
    CopodScorer,
    CorrelationPanel,
    CorrelationShift,
    DetectionResult,
    EcodScorer,
    FeatureRow,
    FixedReference,
    GraphAnomaly,
    HeavyHitterShift,
    JensenShannonDrift,
    MatrixProfile,
    MatrixProfileSettings,
    PanelSnapshot,
    PsiDrift,
    SegmentDivergence,
    SegmentSlice,
    Trailing,
    WassersteinDrift,
)
from godwit_detect.correlation import CorrelationSlice, pair_key
from godwit_sketch import (
    CategoryHistogram,
    CountMinHeavy,
    GraphDegree,
    KllQuantile,
    Moments,
    NullRate,
)

FIX: Final = FixedReference(snapshot_id=snapshot(0))
KLL: Final[dict[str, int]] = {"k": 200, "seed": 1}
BASE_SHARES: Final[list[float]] = [30, 20, 15, 10, 8, 6, 5, 3, 2, 1]


@dataclass(frozen=True)
class World:
    detector: str
    effect_unit: str
    default_size: int
    sizes: tuple[int, ...]
    max_effect: float
    run: Callable[[int, float, int], DetectionResult]


def _kll_pair(seed: int, effect: float, size: int) -> list[KllQuantile]:
    g = rng(seed)
    return [
        KllQuantile.from_items(list(g.lognormal(3.0 + s, 0.7, size)), KLL)
        for s in (0.0, effect * 0.7)
    ]


def _psi_kll(seed: int, effect: float, size: int) -> DetectionResult:
    return PsiDrift().run(series(_kll_pair(seed, effect, size)), policy=FIX)


def _wasserstein(seed: int, effect: float, size: int) -> DetectionResult:
    return WassersteinDrift().run(series(_kll_pair(seed, effect, size)), policy=FIX)


def _shares(effect: float) -> list[float]:
    total = sum(BASE_SHARES)
    moved = [share / total for share in BASE_SHARES]
    moved[5] += effect
    return moved


def _hist_pair(seed: int, effect: float, size: int) -> list[CategoryHistogram]:
    g = rng(seed)
    return [
        CategoryHistogram.from_items(categories(g, s, size), {})
        for s in (_shares(0.0), _shares(effect))
    ]


def _psi_cat(seed: int, effect: float, size: int) -> DetectionResult:
    return PsiDrift().run(series(_hist_pair(seed, effect, size)), policy=FIX)


def _js(seed: int, effect: float, size: int) -> DetectionResult:
    return JensenShannonDrift().run(series(_hist_pair(seed, effect, size)), policy=FIX)


def _heavy(seed: int, effect: float, size: int) -> DetectionResult:
    g = rng(seed)
    zipf = [1 / (i + 1) for i in range(40)]
    total = sum(zipf)
    base = [z / total for z in zipf]
    moved = list(base)
    moved[15] += effect
    data = [
        CountMinHeavy.from_items(categories(g, s, size), {"capacity": 64}) for s in (base, moved)
    ]
    return HeavyHitterShift().run(series(data), policy=FIX)


def _segments(seed: int, effect: float, size: int) -> DetectionResult:
    g = rng(seed)
    slices = []
    for i in range(8):
        values = g.normal(100.0 + (effect * 20.0 if i == 3 else 0.0), 20.0, size)
        slices.append(
            SegmentSlice(
                context=context(f"m:{i}", probe=f"p{i}", segment=eq_segment("k", f"v{i}")),
                envelope=envelope(Moments.from_items(list(values), {}), 1, probe=f"p{i}"),
            )
        )
    panel = PanelSnapshot(snapshot_id=snapshot(1), at=EPOCH + DAY, slices=tuple(slices))
    return SegmentDivergence().run(panel)


def _corr_slice(
    g: np.random.Generator, index: int, name: str, rho: float, size: int
) -> CorrelationSlice:
    x = g.normal(size=size)
    y = rho * x + np.sqrt(1 - rho * rho) * g.normal(size=size)
    z = g.normal(size=size)
    columns = [list(x), list(y), list(z)]
    probe = f"c_{name}"
    return CorrelationSlice(
        context=context("c", columns=("a", "b", "c"), probe=probe, segment=eq_segment("r", name)),
        columns=tuple(envelope(Moments.from_items(c, {}), index, probe=probe) for c in columns),
        pair_sums={
            pair_key(i, j): envelope(
                Moments.from_items(
                    [a + b for a, b in zip(columns[i], columns[j], strict=True)], {}
                ),
                index,
                probe=probe,
            )
            for i in range(3)
            for j in range(i + 1, 3)
        },
    )


def _correlation(seed: int, effect: float, size: int) -> DetectionResult:
    """Null: every pair sits at r=0.25, just under the 0.3 edge threshold, in both windows."""
    g = rng(seed)
    names = ("n", "s", "e", "w")
    base = 0.25
    current = CorrelationPanel(
        snapshot_id=snapshot(1),
        at=EPOCH + DAY,
        slices=tuple(
            _corr_slice(g, 1, n, min(0.95, base + (effect if n == "n" else 0.0)), size)
            for n in names
        ),
    )
    before = CorrelationPanel(
        snapshot_id=snapshot(0),
        at=EPOCH,
        slices=tuple(_corr_slice(g, 0, n, base, size) for n in names),
    )
    return CorrelationShift().run(current, baseline=before)


def _graph(seed: int, effect: float, size: int) -> DetectionResult:
    g = rng(seed)
    windows = []
    for w in range(7):
        pairs = edges(g, size)
        if w == 6 and effect > 0:
            diverted = int(effect * size)
            pairs[:diverted] = [(f"m{seed}_{i}", f"collector{i % 4}") for i in range(diverted)]
        windows.append(GraphDegree.from_items(pairs, {}))
    ctx = context("count_min:graph", columns=("a", "b"))
    return GraphAnomaly().run(series(windows, ctx=ctx), policy=Trailing(points=6))


def _rows(
    seed: int, effect: float, size: int, scorer: EcodScorer | CopodScorer, *, shape: bool = False
) -> DetectionResult:
    """One row in forty shifted by ``effect`` sd of log-value; with ``shape``, its spread
    also grows by ``effect / 2``, so skewness, kurtosis and CV move too."""
    g = rng(seed)
    rows = []
    for i in range(40):
        mu = 3.0 + (effect * 0.7 if i == 0 else 0.0)
        sigma = 0.7 * (1.0 + effect / 2.0 if i == 0 and shape else 1.0)
        values = g.lognormal(mu, sigma, size)
        rows.append(
            FeatureRow(
                context=context(f"r:{i}", probe=f"r{i}"),
                snapshot_id=snapshot(1),
                at=EPOCH,
                envelope=envelope(Moments.from_items(list(values), {}), 1, probe=f"r{i}"),
            )
        )
    return scorer.run(rows)


def _ecod(seed: int, effect: float, size: int) -> DetectionResult:
    return _rows(seed, effect, size, EcodScorer())


def _copod(seed: int, effect: float, size: int) -> DetectionResult:
    return _rows(seed, effect, size, CopodScorer())


def _ecod_shape(seed: int, effect: float, size: int) -> DetectionResult:
    return _rows(seed, effect, size, EcodScorer(), shape=True)


def _copod_shape(seed: int, effect: float, size: int) -> DetectionResult:
    return _rows(seed, effect, size, CopodScorer(), shape=True)


def _profile(seed: int, effect: float, size: int, *, period: bool = False) -> DetectionResult:
    """White-noise volumes (a residual series), or a 12-window cycle plus noise; a spike of
    ``effect`` noise sd lands three windows before the latest."""
    noise = rng(seed).normal(0.0, 30.0, size)
    wave = [150.0 * np.sin(2 * np.pi * i / 12) if period else 0.0 for i in range(size)]
    counts = [int(1000 + w + v) for w, v in zip(wave, noise, strict=True)]
    counts[-3] += int(effect * 30.0)
    sketches = [NullRate.from_items([1.0] * c, {}) for c in counts]
    detector = (
        MatrixProfile(MatrixProfileSettings(discord_ratio=2.1)) if period else MatrixProfile()
    )
    return detector.run(series(sketches, ctx=context("t")))


def _profile_periodic(seed: int, effect: float, size: int) -> DetectionResult:
    return _profile(seed, effect, size, period=True)


WORLDS: Final[dict[str, World]] = {
    "psi_drift[kll]": World(
        "psi_drift", "location shift, sd of log-amount", 2000, (200, 1000, 5000), 2.0, _psi_kll
    ),
    "psi_drift[categorical]": World(
        "psi_drift", "share moved into one category", 2000, (200, 1000, 5000), 0.5, _psi_cat
    ),
    "wasserstein_drift": World(
        "wasserstein_drift",
        "location shift, sd of log-amount",
        2000,
        (200, 1000, 5000),
        2.0,
        _wasserstein,
    ),
    "js_drift": World(
        "js_drift", "share moved into one category", 2000, (200, 1000, 5000), 0.5, _js
    ),
    "heavy_hitter_shift": World(
        "heavy_hitter_shift", "share gained by one key", 3000, (500, 3000, 20000), 0.5, _heavy
    ),
    "segment_divergence": World(
        "segment_divergence",
        "Cohen's d of one segment in eight",
        400,
        (50, 200, 1000),
        3.0,
        _segments,
    ),
    "correlation_shift": World(
        "correlation_shift",
        "correlation gained by one pair, from 0.25",
        600,
        (100, 500, 2000),
        0.7,
        _correlation,
    ),
    "graph_anomaly": World(
        "graph_anomaly",
        "share of edges diverted to four collectors",
        800,
        (300, 800, 3000),
        0.6,
        _graph,
    ),
    "ecod[location]": World(
        "ecod", "location shift of one row in forty, sd", 300, (50, 300, 2000), 4.0, _ecod
    ),
    "ecod[shape]": World(
        "ecod",
        "location and spread shift of one row in forty",
        300,
        (50, 300, 2000),
        4.0,
        _ecod_shape,
    ),
    "copod[location]": World(
        "copod", "location shift of one row in forty, sd", 300, (50, 300, 2000), 4.0, _copod
    ),
    "copod[shape]": World(
        "copod",
        "location and spread shift of one row in forty",
        300,
        (50, 300, 2000),
        4.0,
        _copod_shape,
    ),
    "matrix_profile[white]": World(
        "matrix_profile", "spike height, noise sd", 120, (60, 120, 240), 40.0, _profile
    ),
    "matrix_profile[periodic]": World(
        "matrix_profile",
        "spike height, noise sd (ratio 2.1)",
        120,
        (60, 120, 240),
        40.0,
        _profile_periodic,
    ),
}


def null_rate(world: World, series_count: int, *, first_seed: int = 0) -> tuple[int, int]:
    """Emitted findings and tests over ``series_count`` null worlds."""
    emitted = tests = 0
    for seed in range(first_seed, first_seed + series_count):
        result = world.run(seed, 0.0, world.default_size)
        emitted += len(result.findings)
        tests += result.tests
    return emitted, tests


def detected(world: World, result: DetectionResult) -> bool:
    """Did this run find the injected change, not merely something?"""
    if world.detector in ("ecod", "copod"):
        return any(str(f.probe_key) == "r0" for f in result.findings)
    if world.detector == "segment_divergence":
        return any(f.segment.predicates[0].values[0].reveal() == "v3" for f in result.findings)
    if world.detector == "correlation_shift":
        return any(f.segment.predicates[0].values[0].reveal() == "n" for f in result.findings)
    if world.detector == "matrix_profile":
        return any(f.method == "discord" for f in result.findings)
    return bool(result.findings)
