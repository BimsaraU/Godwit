"""Graph anomaly over a GraphDegree series: the structuring and mule detector.

Structuring keeps every payment individually unremarkable. What it cannot hide is the
shape of the graph it draws: many payers converging on a few collectors (fan-in rises,
the sources-to-targets ratio rises), each pair transacting once (edge multiplicity falls
toward 1), and a handful of targets taking a growing share of all edges (in-concentration
rises). None of these is visible in any one row.

EIGHT SHAPE METRICS, EACH AGAINST ITS OWN HISTORY
-------------------------------------------------
``mean_in_degree``, ``mean_out_degree``, ``fan_in_out_ratio``, ``edge_multiplicity``
(log scale); ``concentration_in``, ``concentration_out`` (logit scale); and the degree
tails ``in_degree_tail`` and ``out_degree_tail``, ``log(q99 / q50)`` of the degree
distribution, when the probe recorded per-entity degrees.

These are ratios of Theta and Count-Min estimates and have no closed-form sampling
variance, so each is tested with a Student-t prediction interval against the same metric
in each reference window (:func:`godwit_detect.stats.prediction_test`). That needs
``min_history`` reference windows; a single baseline bundle cannot support this detector
and it says so with a refusal rather than guessing a variance.

THE FUNNEL SIGNATURE
--------------------
The dense-subgraph signal is the conjunction. The one-sided p-values of the four metrics
that move in a known direction under a mule funnel -- in-degree up, fan-in ratio up,
multiplicity down, in-concentration up -- are combined with Fisher's method into one
further test. It is one extra hypothesis, counted as such.

The collectors themselves -- fan-in heavy hitters that were not heavy in the reference --
are identities: tainted, attached to the funnel and concentration findings, and removed
by suppression. The shape metrics above are what remains, and they are the finding.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import ClassVar, Final

from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.taint import Tainted, derived_statistic
from godwit_sketch import Direction as EdgeDirection
from godwit_sketch import GraphDegree
from pydantic import Field

from godwit_detect.base import Claim, SeriesDetector, Settings, decoded, item_key, merge_all
from godwit_detect.evidence import (
    Attribution,
    DetectionResult,
    Direction,
    Finding,
    Measure,
    Refusal,
    RefusalReason,
    Window,
    measure,
)
from godwit_detect.series import SeriesPoint, SketchSeries
from godwit_detect.stats import PredictionTest, fisher_combine, prediction_test

__all__ = ["GraphAnomaly", "GraphSettings"]

_CLIP: Final[float] = 1e-6
_TOP_COLLECTORS: Final[int] = 10
_MIN_SIGNATURE_PARTS: Final[int] = 3


class GraphSettings(Settings):
    """Settings for :class:`GraphAnomaly`."""

    min_history: int = Field(default=5, ge=3)


def _log(x: float) -> float:
    return math.log(x) if x > 0 and math.isfinite(x) else math.nan


def _logit(x: float) -> float:
    if not math.isfinite(x):
        return math.nan
    clipped = min(1.0 - _CLIP, max(_CLIP, x))
    return math.log(clipped / (1.0 - clipped))


def _tail(sketch: GraphDegree, direction: EdgeDirection) -> float:
    if sketch.degree_population(direction=direction) == 0:
        return math.nan
    median = sketch.degree_quantile(0.5, direction=direction)
    high = sketch.degree_quantile(0.99, direction=direction)
    return high / median if median > 0 else math.nan


@dataclass(frozen=True, slots=True)
class _Metric:
    name: str
    raw: Callable[[GraphDegree], float]
    transform: Callable[[float], float]
    log_scale: bool
    funnel: int
    """+1 if a mule funnel pushes it up, -1 down, 0 if it plays no part."""


_METRICS: Final[tuple[_Metric, ...]] = (
    _Metric("mean_in_degree", GraphDegree.mean_in_degree, _log, True, +1),
    _Metric("mean_out_degree", GraphDegree.mean_out_degree, _log, True, 0),
    _Metric("fan_in_out_ratio", GraphDegree.fan_in_out_ratio, _log, True, +1),
    _Metric("edge_multiplicity", GraphDegree.edge_multiplicity, _log, True, -1),
    _Metric(
        "concentration_in",
        lambda g: g.concentration(direction=EdgeDirection.IN, top=_TOP_COLLECTORS),
        _logit,
        False,
        +1,
    ),
    _Metric(
        "concentration_out",
        lambda g: g.concentration(direction=EdgeDirection.OUT, top=_TOP_COLLECTORS),
        _logit,
        False,
        0,
    ),
    _Metric("in_degree_tail", lambda g: _tail(g, EdgeDirection.IN), _log, True, 0),
    _Metric("out_degree_tail", lambda g: _tail(g, EdgeDirection.OUT), _log, True, 0),
)


@dataclass(frozen=True, slots=True)
class _Tested:
    metric: _Metric
    test: PredictionTest
    current_raw: float
    history_raw: tuple[float, ...]


class GraphAnomaly(SeriesDetector[GraphSettings]):
    """Fan-in/fan-out shifts, degree-tail change, and the mule funnel signature."""

    NAME: ClassVar[str] = "graph_anomaly"
    VERSION: ClassVar[str] = "1.0.0"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.GRAPH_ANOMALY
    SUMMARY: ClassVar[str] = (
        "Graph shape metrics against their history, plus a combined funnel test"
    )
    CODECS: ClassVar[frozenset[str]] = frozenset({GraphDegree.CODEC})

    @classmethod
    def default_settings(cls) -> GraphSettings:
        """Alpha 0.05, 100 edges per window, five reference windows."""
        return GraphSettings()

    def _detect(
        self, series: SketchSeries, reference: Sequence[SeriesPoint], window: Window
    ) -> DetectionResult:
        name = (series.context.sketch_name,)
        current = decoded(series.current)
        windows = [decoded(point) for point in reference]
        graphs = [
            w
            for w in windows
            if isinstance(w, GraphDegree) and w.edge_count() >= self.settings.min_support
        ]
        if not isinstance(current, GraphDegree):
            return self._result(refusals=[self._refusal(RefusalReason.UNSUPPORTED_SKETCH, name)])
        if current.edge_count() < self.settings.min_support:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_SKETCH, name)])
        if len(graphs) < self.settings.min_history:
            return self._result(
                refusals=[
                    self._refusal(RefusalReason.THIN_BASELINE, name, f"windows:{len(graphs)}")
                ]
            )

        tested: list[_Tested] = []
        refusals: list[Refusal] = []
        for metric in _METRICS:
            now_raw = metric.raw(current)
            history_raw = tuple(metric.raw(g) for g in graphs)
            values = [metric.transform(v) for v in history_raw]
            value = metric.transform(now_raw)
            if not math.isfinite(value) or not all(math.isfinite(v) for v in values):
                refusals.append(
                    self._refusal(RefusalReason.THIN_SKETCH, name, f"metric:{metric.name}")
                )
                continue
            tested.append(_Tested(metric, prediction_test(value, values), now_raw, history_raw))

        collectors = self._collectors(current, graphs)
        findings = [
            f
            for t in tested
            if (f := self._metric_finding(series, window, current, t, collectors)) is not None
        ]
        tests = len(tested)
        parts = [t for t in tested if t.metric.funnel != 0]
        if len(parts) >= _MIN_SIGNATURE_PARTS:
            tests += 1
            signature = self._signature(series, window, current, parts, collectors)
            if signature is not None:
                findings.append(signature)
        return self._result(findings, tests=tests, refusals=refusals)

    @staticmethod
    def _collectors(
        current: GraphDegree, reference: Sequence[GraphDegree]
    ) -> tuple[Tainted[str], ...]:
        """Current top fan-in entities that were not top fan-in in the pooled reference."""
        pooled = merge_all(list(reference))
        before = (
            {item_key(key) for key, _ in pooled.fan_in_heavy_hitters(_TOP_COLLECTORS)}
            if isinstance(pooled, GraphDegree)
            else set()
        )
        return tuple(
            key
            for key, _ in current.fan_in_heavy_hitters(_TOP_COLLECTORS)
            if item_key(key) not in before
        )

    @staticmethod
    def _effect(tested: _Tested) -> Measure:
        history = tested.history_raw
        if tested.metric.log_scale:
            geometric = math.exp(math.fsum(math.log(v) for v in history) / len(history))
            return measure(f"{tested.metric.name}_ratio", tested.current_raw / geometric, "ratio")
        return measure(
            f"{tested.metric.name}_change",
            tested.current_raw - math.fsum(history) / len(history),
            "share",
        )

    def _shape(self, current: GraphDegree) -> tuple[Measure, ...]:
        return (
            measure("edges", current.edge_count(), "edges"),
            measure("distinct_sources", current.distinct_sources(), "entities"),
            measure("distinct_targets", current.distinct_targets(), "entities"),
            measure("fan_in_out_ratio", current.fan_in_out_ratio(), "ratio"),
            measure("edge_multiplicity", current.edge_multiplicity(), "ratio"),
            measure(
                "concentration_in",
                current.concentration(direction=EdgeDirection.IN, top=_TOP_COLLECTORS),
                "share",
            ),
        )

    def _metric_finding(
        self,
        series: SketchSeries,
        window: Window,
        current: GraphDegree,
        tested: _Tested,
        collectors: tuple[Tainted[str], ...],
    ) -> Finding | None:
        p_value = tested.test.p_two_sided
        if p_value > self.settings.alpha:
            return None
        carries = tested.metric.name == "concentration_in" and tested.test.statistic > 0
        return self._emit(
            series.context,
            window,
            Claim(
                method=tested.metric.name,
                statistic=measure("t", tested.test.statistic, "t"),
                effect=self._effect(tested),
                p_value=p_value,
                direction=Direction.UP if tested.test.statistic > 0 else Direction.DOWN,
                attribution=(
                    Attribution(
                        feature=f"graph_{tested.metric.name}",
                        contribution=derived_statistic(tested.test.statistic),
                    ),
                ),
                identities=collectors if carries else (),
                note=f"t prediction interval against {tested.test.df + 1} reference windows",
                shape=self._shape(current),
                population=current.edge_count(),
            ),
        )

    def _signature(
        self,
        series: SketchSeries,
        window: Window,
        current: GraphDegree,
        parts: Sequence[_Tested],
        collectors: tuple[Tainted[str], ...],
    ) -> Finding | None:
        one_sided = [t.test.p_upper if t.metric.funnel > 0 else t.test.p_lower for t in parts]
        p_value = fisher_combine(one_sided)
        if p_value > self.settings.alpha:
            return None
        toward = [t.test.statistic * t.metric.funnel for t in parts]
        return self._emit(
            series.context,
            window,
            Claim(
                method="funnel_signature",
                statistic=measure(
                    "fisher_chi_square",
                    -2.0 * sum(math.log(max(p, 1e-300)) for p in one_sided),
                    "chi2",
                ),
                effect=measure("mean_shift_toward_funnel", sum(toward) / len(toward), "sd"),
                p_value=p_value,
                direction=Direction.UP,
                attribution=tuple(
                    Attribution(feature=f"graph_{t.metric.name}", contribution=derived_statistic(s))
                    for t, s in zip(parts, toward, strict=True)
                ),
                identities=collectors,
                note="Fisher's combination of one-sided t prediction tests in the funnel direction",
                shape=self._shape(current),
                population=current.edge_count(),
            ),
        )
