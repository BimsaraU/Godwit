"""One fixed scenario per registered detector, each with a change injected.

Shared by the behaviour-hash pins, the purity property, the suppression test and the
golden tests. Every input is either the shared golden fixture or hash-derived through
``godwit_sketch.deterministic`` -- never numpy's generators, whose streams are allowed to
change between numpy releases and would move the pinned hashes with no code change here.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any, Final

import pyarrow.parquet as pq
from _detect_support import DAY, EPOCH, context, envelope, eq_segment, series, snapshot
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.taint import Acquisition, data_value, schema_name
from godwit_detect import (
    CopodScorer,
    CorrelationPanel,
    CorrelationShift,
    CorrelationSlice,
    DetectionResult,
    EcodScorer,
    FeatureRow,
    FixedReference,
    GraphAnomaly,
    HeavyHitterShift,
    JensenShannonDrift,
    MatrixProfile,
    PanelSnapshot,
    PsiDrift,
    SegmentDivergence,
    SegmentDivergenceSettings,
    SegmentSlice,
    Trailing,
    WassersteinDrift,
    pair_key,
)
from godwit_sketch import CategoryHistogram, GraphDegree, KllQuantile, Moments, NullRate
from godwit_sketch.deterministic import lognormals, normals, uniforms

GOLDEN: Final[Path] = Path(__file__).resolve().parents[3] / "tests" / "golden"
KLL: Final[dict[str, int]] = {"k": 200, "seed": 7}


@cache
def golden_rows(index: int) -> tuple[dict[str, Any], ...]:
    """Rows of ``drift_table/snapshot_<index>.parquet``. The test acts as the data plane."""
    table = pq.read_table(GOLDEN / "drift_table" / f"snapshot_{index}.parquet")
    return tuple(table.to_pylist())


def golden_country_series() -> Any:
    sketches = [
        CategoryHistogram.from_items([r["country"] for r in golden_rows(i)], {}) for i in range(3)
    ]
    return series(sketches, ctx=context("frequent_items:0", columns=("country",)))


def cell_segment(country: str, status: str, population: int) -> Segment:
    return Segment(
        predicates=tuple(
            Predicate(
                column=schema_name(column),
                op=Operator.EQ,
                values=(data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE),),
            )
            for column, value in (("country", country), ("status", status))
        ),
        population=population,
    )


def golden_amount_panel(index: int, kind: str = "moments") -> PanelSnapshot:
    """``amount`` per ``country x status`` cell of one golden snapshot."""
    cells: dict[tuple[str, str], list[float]] = {}
    for row in golden_rows(index):
        cells.setdefault((row["country"], row["status"]), []).append(float(row["amount"]))
    slices = []
    for (country, status), amounts in sorted(cells.items()):
        probe = f"prb_amount_{country}_{status}"
        sketch = (
            Moments.from_items(amounts, {})
            if kind == "moments"
            else KllQuantile.from_items(amounts, KLL)
        )
        slices.append(
            SegmentSlice(
                context=context(
                    "exact_count:0",
                    probe=probe,
                    segment=cell_segment(country, status, len(amounts)),
                ),
                envelope=envelope(sketch, index, probe=probe),
            )
        )
    return PanelSnapshot(snapshot_id=snapshot(index), at=EPOCH + DAY * index, slices=tuple(slices))


def _psi() -> DetectionResult:
    return PsiDrift().run(golden_country_series(), policy=FixedReference(snapshot_id=snapshot(1)))


def _js() -> DetectionResult:
    return JensenShannonDrift().run(
        golden_country_series(), policy=FixedReference(snapshot_id=snapshot(1))
    )


def _heavy() -> DetectionResult:
    return HeavyHitterShift().run(
        golden_country_series(), policy=FixedReference(snapshot_id=snapshot(1))
    )


def _wasserstein() -> DetectionResult:
    sketches = [
        KllQuantile.from_items(
            lognormals(1500, salt=f"w{i}", mu=3.2 + (0.25 if i == 5 else 0.0)), KLL
        )
        for i in range(6)
    ]
    return WassersteinDrift().run(series(sketches), policy=Trailing(points=5))


def _segments() -> DetectionResult:
    detector = SegmentDivergence(SegmentDivergenceSettings(min_support=30))
    return detector.run(golden_amount_panel(2), baseline=golden_amount_panel(1))


def correlation_slice(index: int, name: str, rho: float, rows: int = 600) -> CorrelationSlice:
    x = normals(rows, salt=f"cx{name}{index}")
    noise = normals(rows, salt=f"cn{name}{index}")
    y = [rho * a + math.sqrt(1 - rho * rho) * b for a, b in zip(x, noise, strict=True)]
    z = normals(rows, salt=f"cz{name}{index}")
    columns = [x, y, z]
    probe = f"prb_corr_{name}"
    return CorrelationSlice(
        context=context(
            "exact_count:pairs",
            columns=("amount", "fee", "age"),
            probe=probe,
            segment=eq_segment("region", name),
        ),
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


def _correlation() -> DetectionResult:
    names = ("north", "south", "east", "west")
    current = CorrelationPanel(
        snapshot_id=snapshot(1),
        at=EPOCH + DAY,
        slices=tuple(correlation_slice(1, n, 0.7 if n == "north" else 0.0) for n in names),
    )
    baseline = CorrelationPanel(
        snapshot_id=snapshot(0),
        at=EPOCH,
        slices=tuple(correlation_slice(0, n, 0.0) for n in names),
    )
    return CorrelationShift().run(current, baseline=baseline)


def graph_window(index: int, *, funnel: bool, edges: int = 1500) -> GraphDegree:
    u = uniforms(2 * edges, salt=f"g{index}")
    pairs: list[tuple[str, str]] = []
    for i in range(edges):
        source = f"acct{int(u[2 * i] * 600)}"
        if funnel and i % 3 == 0:
            pairs.append((f"mule{i}", f"collector{int(u[2 * i + 1] * 4)}"))
        else:
            pairs.append((source, f"payee{int(u[2 * i + 1] * 300)}"))
    return GraphDegree.from_items(pairs, {})


def _graph() -> DetectionResult:
    sketches = [graph_window(i, funnel=i == 6) for i in range(7)]
    ctx = context("count_min:graph", columns=("payer", "payee"))
    return GraphAnomaly().run(series(sketches, ctx=ctx), policy=Trailing(points=6))


def scoring_rows() -> list[FeatureRow]:
    rows = []
    for i in range(40):
        odd = i in (7, 23)
        values = lognormals(300, salt=f"s{i}", mu=4.5 if odd else 3.2, sigma=1.4 if odd else 0.7)
        sketch = Moments.from_items(values, {})
        rows.append(
            FeatureRow(
                context=context(f"exact_count:{i}", probe=f"prb_score_{i}"),
                snapshot_id=snapshot(1),
                at=EPOCH,
                envelope=envelope(sketch, 1, probe=f"prb_score_{i}"),
            )
        )
    return rows


def _ecod() -> DetectionResult:
    return EcodScorer().run(scoring_rows())


def _copod() -> DetectionResult:
    return CopodScorer().run(scoring_rows())


def profile_series() -> Any:
    sketches = []
    noise = normals(96, salt="profile", sigma=15.0)
    for i in range(96):
        wave = 500 + 200 * math.sin(2 * math.pi * i / 12) + noise[i]
        rows = int(wave) + (900 if i == 92 else 0)
        sketches.append(NullRate.from_items([1.0] * rows, {}))
    return series(sketches, ctx=context("exact_count:table", columns=()))


def _profile() -> DetectionResult:
    return MatrixProfile().run(profile_series())


SCENARIOS: Final[dict[str, Callable[[], DetectionResult]]] = {
    "psi_drift": _psi,
    "wasserstein_drift": _wasserstein,
    "js_drift": _js,
    "heavy_hitter_shift": _heavy,
    "segment_divergence": _segments,
    "correlation_shift": _correlation,
    "graph_anomaly": _graph,
    "ecod": _ecod,
    "copod": _copod,
    "matrix_profile": _profile,
}
