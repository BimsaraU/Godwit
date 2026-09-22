"""The fixed-length feature vector: :func:`extract_features` and :data:`FEATURE_LAYOUT`.

A7 (detectors), A11 (feature factory), A12 (subtractor) and A13 (prediction) all consume
this and none of them can ask what column 14 means. So the layout is data --
:data:`FEATURE_LAYOUT` -- and every slot carries its own description. Read the layout,
not this docstring, for what each column is; ``docs/packages/godwit-sketch.md`` renders
the same table from the same tuple, so the two cannot drift apart.

THREE RULES THIS MODULE KEEPS
-----------------------------
**Fixed length, always.** ``len(extract_features(envelope)) == len(FEATURE_LAYOUT)`` for
every envelope of every kind. A slot that does not apply to the kind in hand is ``NaN``,
never ``0.0`` and never absent. Zero is a measurement; NaN is the absence of one, and a
model that cannot tell them apart will learn that a missing Theta sketch means a column
with no distinct values.

**Derived statistics only. Never an embedded value.** Counts, fractions, ratios and
shape statistics are aggregates over a population. Values out of rows are not here at
all -- no minimum, no maximum, no quantile, no category label, no heavy hitter.

**No extreme, and nothing that recovers one.** The obvious way to include the maximum
safely is to standardise it: export ``(max - mean) / stddev`` rather than ``max``. That
does not work, and the reason is worth stating because it will occur to the next person
too. The vector already carries ``mean`` and ``stddev``, so any standardised extreme
solves straight back to the extreme with school algebra. The same applies to the range,
to a normalised range, and to every other rearrangement. There is no version of this
that is safe while the vector also carries the scale, so the extremes are simply absent.
If a detector needs to know that the maximum moved, the honest route is
:meth:`~godwit_sketch.quantile.KllQuantile.cdf` on a fixed grid, which answers "what
fraction is above this threshold" without naming anybody's number.

SMALL CELLS
-----------
Three slots -- mean, standard deviation and sum -- are aggregates that stop being
aggregates over a tiny population. The mean of one row *is* that row. So they are
blanked to NaN below ``small_cell_threshold``. This is defence in depth and not a
control: redaction belongs to ``godwit-guard`` and the gate is what actually enforces
invariant 2. Pass ``small_cell_threshold=0`` inside the data plane, where a value is
allowed to be a value, and leave the default alone anywhere the vector can travel.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from godwit_contracts.sketch import SketchEnvelope
from godwit_contracts.taint import Tainted

from godwit_sketch.base import BaseSketch, MergeExactness, decode_envelope
from godwit_sketch.distinct import ThetaNdv
from godwit_sketch.frequency import CategoryHistogram, CountMinHeavy, HistogramRegime
from godwit_sketch.graph import Direction, GraphDegree
from godwit_sketch.hll import HllCount
from godwit_sketch.moments import Moments, NullRate
from godwit_sketch.quantile import KllQuantile

__all__ = [
    "CDF_GRID_SLOTS",
    "DEFAULT_SMALL_CELL_THRESHOLD",
    "FEATURE_LAYOUT",
    "FeatureSlot",
    "extract_features",
    "feature_index",
    "sketch_of",
]

DEFAULT_SMALL_CELL_THRESHOLD: Final[int] = 20
"""Populations below this blank the scale-bearing moment slots. See the module docstring."""

CDF_GRID_SLOTS: Final[int] = 9
"""How many CDF slots the layout reserves.

The grid comes from the envelope's ``cdf_grid`` parameter, a comma-separated string of
floats -- ``params`` values are scalars, so a grid cannot be a list there. Fewer grid
points than slots leaves the remainder NaN; more are truncated. The grid must be a probe
parameter: one derived from the data would make each fraction a statement about a real
value, which is a segment predicate, not a statistic.
"""

type _Assign = Callable[[str, float], None]
"""Writes one named slot. Passed to the per-kind helpers so each writes by name."""


@dataclass(frozen=True, slots=True)
class FeatureSlot:
    """One column of the vector: its name, and what it means."""

    name: str
    description: str


def _slots() -> tuple[FeatureSlot, ...]:
    """Build the layout. A function so the CDF slots are generated rather than typed out."""
    layout: list[FeatureSlot] = [
        FeatureSlot("population", "Items fed into the sketch. 0 for an empty sketch."),
        FeatureSlot(
            "log1p_population",
            "log(1 + population). Population spans orders of magnitude across probes; "
            "the log is what a linear model can use.",
        ),
        FeatureSlot(
            "error_epsilon",
            "Epsilon from the envelope's ErrorBound, or 0.0 when the bound is exact. "
            "Lets a detector discount a divergence that is inside the sketch's noise.",
        ),
        FeatureSlot("error_delta", "Delta from an epsilon_delta bound; NaN for other kinds."),
        FeatureSlot(
            "value_bearing",
            "1.0 if the source sketch's state contains row values, else 0.0. Metadata "
            "about the sketch, not about the data; useful for routing, never a signal.",
        ),
        FeatureSlot(
            "merge_is_exact",
            "1.0 if the kind's merge is exactly associative, 0.0 if bounded.",
        ),
        FeatureSlot("distinct_estimate", "Estimated distinct values. Theta and HLL only."),
        FeatureSlot(
            "distinct_ratio",
            "distinct_estimate / population, in [0, 1]. Near 1.0 means a near-unique "
            "column (an identifier); a sharp fall is a join key losing uniqueness.",
        ),
        FeatureSlot("distinct_lower_bound", "Two-standard-deviation lower bound on the estimate."),
        FeatureSlot("distinct_upper_bound", "Two-standard-deviation upper bound on the estimate."),
        FeatureSlot("distinct_retained", "Hashes the sketch holds. A size diagnostic."),
        FeatureSlot("quantile_retained", "Items retained across all KLL levels."),
        FeatureSlot("quantile_levels", "KLL weight levels in use. Grows with log(n)."),
        FeatureSlot(
            "quantile_nonfinite_rate",
            "Share of observations dropped as NaN or infinite, over the total offered. "
            "A data-quality signal: a column that starts emitting NaN moves this.",
        ),
    ]
    layout.extend(
        FeatureSlot(
            f"cdf_{index:02d}",
            f"Cumulative fraction at grid point {index} of the envelope's cdf_grid "
            "parameter. NaN when the grid does not reach this slot. Comparing two "
            "snapshots on one grid is the cheap way to compare distributions.",
        )
        for index in range(CDF_GRID_SLOTS)
    )
    layout.extend(
        [
            FeatureSlot(
                "freq_distinct_categories",
                "Categories held exactly, or retained heavy-hitter candidates once the "
                "histogram has degraded.",
            ),
            FeatureSlot(
                "freq_top1_share",
                "Share of the population in the single most frequent key, in [0, 1]. "
                "The headline segment-divergence signal: a country going from 1% to 18% "
                "of rows shows up here and nowhere cheaper.",
            ),
            FeatureSlot("freq_top5_share", "Share of the population in the top five keys."),
            FeatureSlot("freq_top10_share", "Share of the population in the top ten keys."),
            FeatureSlot(
                "freq_underestimate_rate",
                "Misra-Gries counter mass lost to shrinking, over the population. High "
                "values mean the heavy-hitter list is not exhaustive.",
            ),
            FeatureSlot(
                "freq_regime_exact",
                "1.0 when a category histogram is still exact, 0.0 once degraded to "
                "Count-Min. NaN for kinds that have no regime.",
            ),
            FeatureSlot(
                "moments_mean",
                "Arithmetic mean. BLANKED to NaN below small_cell_threshold: the mean "
                "of one row is that row.",
            ),
            FeatureSlot(
                "moments_stddev",
                "Sample standard deviation. Blanked below small_cell_threshold.",
            ),
            FeatureSlot("moments_sum", "Sum of observations. Blanked below small_cell_threshold."),
            FeatureSlot(
                "moments_cv",
                "Coefficient of variation, stddev/|mean|. Scale-free, so it compares "
                "across snapshots whose absolute scale has drifted.",
            ),
            FeatureSlot("moments_skewness", "Population skewness. NaN below three observations."),
            FeatureSlot(
                "moments_kurtosis",
                "Excess kurtosis, zero for a normal distribution. NaN below four "
                "observations. A fat tail appearing is a classic fraud signature.",
            ),
            FeatureSlot(
                "moments_nonfinite_rate",
                "Share of numeric observations dropped as NaN or infinite.",
            ),
            FeatureSlot(
                "null_rate",
                "Nulls over total rows, in [0, 1]. NaN over an empty population -- "
                "'no rows' and 'no nulls' are different findings.",
            ),
            FeatureSlot("graph_edges", "Total directed edges observed, counting repeats."),
            FeatureSlot("graph_distinct_sources", "Estimated distinct source entities."),
            FeatureSlot("graph_distinct_targets", "Estimated distinct target entities."),
            FeatureSlot("graph_distinct_edges", "Estimated distinct (source, target) pairs."),
            FeatureSlot("graph_mean_out_degree", "Edges per source entity."),
            FeatureSlot(
                "graph_mean_in_degree",
                "Edges per target entity. A funnel raises this while out-degree stays flat.",
            ),
            FeatureSlot(
                "graph_edge_multiplicity",
                "Edges over distinct edges. Near 1.0 means almost every pair transacts "
                "once, which is what a burst of one-shot mule transfers looks like.",
            ),
            FeatureSlot(
                "graph_fan_in_out_ratio",
                "Distinct sources over distinct targets. Well above 1.0 is a funnel: "
                "many payers, few payees.",
            ),
            FeatureSlot(
                "graph_concentration_in_top10",
                "Share of all edges arriving at the ten busiest targets, in [0, 1]. "
                "Rises sharply when a structuring ring starts collecting.",
            ),
            FeatureSlot(
                "graph_concentration_out_top10",
                "Share of all edges leaving the ten busiest sources, in [0, 1].",
            ),
            FeatureSlot(
                "graph_degree_population_in",
                "How many in-degrees were recorded. 0 means the degree quantiles are "
                "empty because the probe did not pre-aggregate by entity.",
            ),
            FeatureSlot("graph_degree_population_out", "How many out-degrees were recorded."),
        ]
    )
    return tuple(layout)


FEATURE_LAYOUT: Final[tuple[FeatureSlot, ...]] = _slots()
"""The vector's columns, in order. Its length is the vector's length, for every kind."""

_INDEX: Final[dict[str, int]] = {slot.name: index for index, slot in enumerate(FEATURE_LAYOUT)}


def feature_index(name: str) -> int:
    """Column index of a named slot. Use this rather than writing a literal 14."""
    try:
        return _INDEX[name]
    except KeyError:
        raise KeyError(
            f"no feature slot named {name!r}; the layout has {len(FEATURE_LAYOUT)} slots"
        ) from None


def _parse_grid(raw: object) -> tuple[float, ...]:
    """Read the ``cdf_grid`` parameter: comma-separated floats, or nothing."""
    if not isinstance(raw, str) or not raw.strip():
        return ()
    points: list[float] = []
    for piece in raw.split(","):
        try:
            points.append(float(piece))
        except ValueError:
            return ()
    return tuple(points)


def extract_features(
    envelope: SketchEnvelope,
    *,
    small_cell_threshold: int = DEFAULT_SMALL_CELL_THRESHOLD,
) -> tuple[float, ...]:
    """Turn one envelope into the fixed-length vector described by :data:`FEATURE_LAYOUT`.

    Pure: the same envelope always gives the same vector, with no clock and no
    randomness. Slots that do not apply to the envelope's kind are ``NaN``.
    """
    sketch = decode_envelope(envelope)
    vector = [math.nan] * len(FEATURE_LAYOUT)

    def put(name: str, value: float) -> None:
        vector[_INDEX[name]] = value

    population = sketch.population
    put("population", float(population))
    put("log1p_population", math.log1p(population))
    bound = envelope.error_bound
    put("error_epsilon", 0.0 if bound.kind == "exact" else float(bound.epsilon or 0.0))
    if bound.delta is not None:
        put("error_delta", float(bound.delta))
    put("value_bearing", 1.0 if sketch.VALUE_BEARING else 0.0)
    put("merge_is_exact", 1.0 if sketch.MERGE_EXACTNESS is MergeExactness.EXACT else 0.0)

    if isinstance(sketch, ThetaNdv | HllCount):
        _distinct_features(sketch, put, population)
    elif isinstance(sketch, KllQuantile):
        _quantile_features(sketch, put, envelope)
    elif isinstance(sketch, CategoryHistogram):
        put("freq_regime_exact", 1.0 if sketch.regime is HistogramRegime.EXACT else 0.0)
        put("freq_distinct_categories", float(sketch.distinct_categories()))
        _share_features(sketch.categories(), put, population)
    elif isinstance(sketch, CountMinHeavy):
        _frequency_features(sketch, put, population)
    elif isinstance(sketch, Moments):
        _moment_features(sketch, put, population, small_cell_threshold)
    elif isinstance(sketch, NullRate):
        put("null_rate", sketch.rate())
    elif isinstance(sketch, GraphDegree):
        _graph_features(sketch, put)

    return tuple(vector)


def _distinct_features(sketch: ThetaNdv | HllCount, put: _Assign, population: int) -> None:
    """Theta and HLL: cardinality, its bounds, and the uniqueness ratio."""
    estimate = sketch.estimate()
    put("distinct_estimate", estimate)
    put("distinct_ratio", estimate / population if population else math.nan)
    lower, upper = sketch.bounds()
    put("distinct_lower_bound", lower)
    put("distinct_upper_bound", upper)
    if isinstance(sketch, ThetaNdv):
        put("distinct_retained", float(sketch.retained()))


def _quantile_features(sketch: KllQuantile, put: _Assign, envelope: SketchEnvelope) -> None:
    """KLL: size diagnostics and the CDF on the envelope's grid. Never a quantile."""
    put("quantile_retained", float(sketch.retained()))
    put("quantile_levels", float(sketch.num_levels()))
    offered = sketch.population + sketch.nonfinite_count()
    put("quantile_nonfinite_rate", sketch.nonfinite_count() / offered if offered else math.nan)
    grid = _parse_grid(envelope.params.get("cdf_grid"))
    if grid:
        for index, fraction in enumerate(sketch.cdf(grid[:CDF_GRID_SLOTS])):
            put(f"cdf_{index:02d}", fraction)


def _frequency_features(sketch: CountMinHeavy, put: _Assign, population: int) -> None:
    """Count-Min: concentration shares and how much the counters lost."""
    hitters = sketch.heavy_hitters()
    put("freq_distinct_categories", float(len(hitters)))
    put(
        "freq_underestimate_rate",
        sketch.underestimate() / population if population else math.nan,
    )
    _share_features(hitters, put, population)


def _share_features(
    hitters: Sequence[tuple[Tainted[str], int]], put: _Assign, population: int
) -> None:
    """Top-1, top-5 and top-10 concentration. Shares of a population, never a key.

    Takes the tainted pairs and reads only the counts. The keys are never unwrapped: a
    concentration share says how lopsided a column is without naming what is on top.
    """
    if not population:
        return
    counts = [count for _, count in hitters]
    for slot, top in (("freq_top1_share", 1), ("freq_top5_share", 5), ("freq_top10_share", 10)):
        put(slot, sum(counts[:top]) / population)


def _moment_features(
    sketch: Moments, put: _Assign, population: int, small_cell_threshold: int
) -> None:
    """Moments: shape always, scale only above the small-cell threshold. No extremes."""
    if population >= small_cell_threshold:
        put("moments_mean", sketch.mean())
        put("moments_stddev", sketch.stddev())
        put("moments_sum", sketch.total())
    put("moments_cv", sketch.coefficient_of_variation())
    put("moments_skewness", sketch.skewness())
    put("moments_kurtosis", sketch.kurtosis())
    offered = population + sketch.nonfinite_count()
    put("moments_nonfinite_rate", sketch.nonfinite_count() / offered if offered else math.nan)


def _graph_features(sketch: GraphDegree, put: _Assign) -> None:
    """Graph shape: the ratios a structuring or mule pattern moves."""
    put("graph_edges", float(sketch.edge_count()))
    put("graph_distinct_sources", sketch.distinct_sources())
    put("graph_distinct_targets", sketch.distinct_targets())
    put("graph_distinct_edges", sketch.distinct_edges())
    put("graph_mean_out_degree", sketch.mean_out_degree())
    put("graph_mean_in_degree", sketch.mean_in_degree())
    put("graph_edge_multiplicity", sketch.edge_multiplicity())
    put("graph_fan_in_out_ratio", sketch.fan_in_out_ratio())
    put("graph_concentration_in_top10", sketch.concentration(direction=Direction.IN, top=10))
    put("graph_concentration_out_top10", sketch.concentration(direction=Direction.OUT, top=10))
    put("graph_degree_population_in", float(sketch.degree_population(direction=Direction.IN)))
    put("graph_degree_population_out", float(sketch.degree_population(direction=Direction.OUT)))


def sketch_of(envelope: SketchEnvelope) -> BaseSketch:
    """Decode an envelope to its sketch. For callers that want the object, not the vector."""
    return decode_envelope(envelope)
