"""L-1 metadata detectors: free signals over a metadata time-series.

DATA PLANE (by taint, not by cost). These functions read nothing but the structures in
:mod:`godwit_source.stats`, which already came from catalog metadata. They scan zero bytes
of table data. Their job is to tell L4 where a paid scan is worth spending.

**Which detectors need a value, and why.** Most emit only *how far* something moved, which
is a derived statistic and cheap for every downstream consumer to handle:

- ``null_rate_shift`` -- derived only: a rate and a z-score.
- ``ndv_ratio_shift`` -- derived only.
- ``row_volume_anomaly`` -- derived only.
- ``file_layout_anomaly`` -- derived only; file counts and byte sizes quote no row.
- ``bounds_drift`` -- derived by default. The distance a bound moved carries the signal; the
  bound itself is a real name or a real email. Pass ``include_bound_values=True`` only when
  a human reviewer needs to see *which* value appeared, and the evidence then carries it as
  DATA_VALUE.
- ``schema_change`` -- **must** carry values. The finding *is* the column name, and a column
  name is a leak path in its own right (``patient_hiv_status``, ``salary_2024``). No derived
  form preserves the signal.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence

from ._contracts import (
    Candidate,
    ColumnAccessMode,
    Evidence,
    Tainted,
    data_value,
    derived_statistic,
)
from .stats import ColumnMetadata, FileLayoutStats, SnapshotMetadata, stat

__all__ = [
    "DEFAULT_DETECTORS",
    "bounds_drift",
    "file_layout_anomaly",
    "ndv_ratio_shift",
    "null_rate_shift",
    "row_volume_anomaly",
    "run_all",
    "schema_change",
]

_MIN_HISTORY = 3
_BOUNDS_ARITHMETIC = "bound arithmetic inside the data plane; only the distance is emitted"
_SATURATED_Z = 8.0


def _p_from_z(z: float) -> float:
    """Two-sided normal tail. Deterministic, stdlib only; scipy is not in the stack."""
    return math.erfc(abs(z) / math.sqrt(2.0))


def _median(xs: Sequence[float]) -> float:
    ordered = sorted(xs)
    n = len(ordered)
    mid = n // 2
    return ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0


def _robust_z(baseline: Sequence[float], x: float) -> tuple[float, float]:
    """Median/MAD z-score, returned as ``(z, p)``.

    Robust because a metadata series contains the very outliers we are hunting, and a
    mean/stdev score lets one big spike hide the next one. A zero-spread baseline scores 0
    when ``x`` matches it and saturates otherwise; dividing by zero would produce an
    infinity that outranks every real finding.
    """
    if len(baseline) < 2:
        return 0.0, 1.0
    med = _median(baseline)
    mad = _median([abs(v - med) for v in baseline])
    scale = 1.4826 * mad
    if scale <= 0.0:
        scale = (max(baseline) - min(baseline)) / 2.0
    if scale <= 0.0:
        # No usable scale: the baseline is constant, or its spread underflowed to zero.
        # Either way there is nothing to divide by, and guessing one would manufacture a
        # z-score out of arithmetic noise.
        return (0.0, 1.0) if x == med else (_SATURATED_Z, _p_from_z(_SATURATED_Z))
    z = (x - med) / scale
    return z, _p_from_z(z)


def _two_proportion_z(
    base_events: float, base_trials: float, obs_events: float, obs_trials: float
) -> tuple[float, float]:
    """Pooled two-proportion z-test.

    Used for null rates, where the denominator is known exactly from the manifest. A
    proportion test beats a robust z over rates there: it knows that a 10% null rate out of
    20 rows and out of 20 million rows are not the same evidence.
    """
    if base_trials <= 0 or obs_trials <= 0:
        return 0.0, 1.0
    p1 = base_events / base_trials
    p2 = obs_events / obs_trials
    pooled = (base_events + obs_events) / (base_trials + obs_trials)
    se = math.sqrt(pooled * (1.0 - pooled) * (1.0 / base_trials + 1.0 / obs_trials))
    if se <= 0.0:
        return (0.0, 1.0) if p1 == p2 else (_SATURATED_Z, _p_from_z(_SATURATED_Z))
    z = (p2 - p1) / se
    return z, _p_from_z(z)


def _series(
    history: Sequence[SnapshotMetadata],
    column: str,
    pick: Callable[[ColumnMetadata], float | None],
) -> list[float]:
    out: list[float] = []
    for snap in history:
        col = snap.columns.get(column)
        if col is None:
            continue
        value = pick(col)
        if value is not None and math.isfinite(value):
            out.append(value)
    return out


def _candidate(
    detector: str,
    snap: SnapshotMetadata,
    column: str | None,
    effect_size: float,
    p_value: float,
    evidence: Evidence,
) -> Candidate:
    return Candidate(
        detector=detector,
        table=snap.table,
        column=column,
        snapshot_id=snap.snapshot_id,
        effect_size=effect_size,
        p_value=p_value,
        evidence=evidence,
    )


def null_rate_shift(
    history: Sequence[SnapshotMetadata],
    *,
    alpha: float = 0.01,
    min_history: int = _MIN_HISTORY,
) -> list[Candidate]:
    """Null rate of a column moved against its own baseline.

    Metadata fields used: ``null_count`` and ``row_count`` -- Iceberg manifest
    ``null_value_counts`` / ``record_count``, or ``pg_stats.null_frac`` times
    ``pg_class.reltuples``.
    """
    if len(history) <= min_history:
        return []
    latest = history[-1]
    baseline_snaps = history[:-1]
    out: list[Candidate] = []
    for column, col in latest.columns.items():
        rows = stat(col.counts.row_count)
        nulls = stat(col.counts.null_count)
        if rows is None or nulls is None or rows <= 0:
            continue
        base_rows = sum(_series(baseline_snaps, column, lambda c: stat(c.counts.row_count)))
        base_nulls = sum(_series(baseline_snaps, column, lambda c: stat(c.counts.null_count)))
        if base_rows <= 0:
            continue
        z, p = _two_proportion_z(base_nulls, base_rows, nulls, rows)
        if p >= alpha:
            continue
        out.append(
            _candidate(
                "null_rate_shift",
                latest,
                column,
                effect_size=(nulls / rows) - (base_nulls / base_rows),
                p_value=p,
                evidence={
                    "metadata_fields": "null_count,row_count",
                    "baseline_null_rate": derived_statistic(
                        base_nulls / base_rows, "manifest.null_value_counts"
                    ),
                    "observed_null_rate": derived_statistic(
                        nulls / rows, "manifest.null_value_counts"
                    ),
                    "z": z,
                },
            )
        )
    return out


def ndv_ratio_shift(
    history: Sequence[SnapshotMetadata],
    *,
    alpha: float = 0.01,
    min_history: int = _MIN_HISTORY,
) -> list[Candidate]:
    """Distinct-count ratio ``ndv / row_count`` moved.

    Metadata fields used: the Puffin ``apache-datasketches-theta-v1`` blob's ``ndv``
    property, or ``pg_stats.n_distinct``, against ``row_count``. This one works on OPAQUE
    columns -- a distinct count quotes nothing -- which is what keeps identifier columns in
    play instead of deleting the strongest fraud signal we have.
    """
    if len(history) <= min_history:
        return []
    latest = history[-1]
    out: list[Candidate] = []
    for column, col in latest.columns.items():
        observed = col.counts.ndv_ratio
        if observed is None:
            continue
        baseline = _series(history[:-1], column, lambda c: c.counts.ndv_ratio)
        if len(baseline) < min_history:
            continue
        z, p = _robust_z(baseline, observed)
        if p >= alpha:
            continue
        out.append(
            _candidate(
                "ndv_ratio_shift",
                latest,
                column,
                effect_size=observed - _median(baseline),
                p_value=p,
                evidence={
                    "metadata_fields": "puffin.ndv,row_count",
                    "baseline_ndv_ratio": derived_statistic(_median(baseline), "puffin.ndv"),
                    "observed_ndv_ratio": derived_statistic(observed, "puffin.ndv"),
                    "z": z,
                },
            )
        )
    return out


def row_volume_anomaly(
    history: Sequence[SnapshotMetadata],
    *,
    alpha: float = 0.01,
    min_history: int = _MIN_HISTORY,
) -> list[Candidate]:
    """Rows in a snapshot moved against the table's own history.

    Scored on ``log1p`` because table volume is multiplicative: a doubling means the same
    thing at a thousand rows and at a million. Metadata fields used: ``record_count``
    (``pg_class.reltuples`` on Postgres).
    """
    if len(history) <= min_history:
        return []
    totals = [
        (snap, max((stat(c.counts.row_count) or 0.0) for c in snap.columns.values()))
        for snap in history
        if snap.columns
    ]
    if len(totals) <= min_history:
        return []
    baseline = [math.log1p(v) for _, v in totals[:-1]]
    snap, observed = totals[-1]
    z, p = _robust_z(baseline, math.log1p(observed))
    if p >= alpha:
        return []
    return [
        _candidate(
            "row_volume_anomaly",
            snap,
            None,
            effect_size=math.log1p(observed) - _median(baseline),
            p_value=p,
            evidence={
                "metadata_fields": "row_count",
                "observed_row_count": derived_statistic(observed, "manifest.record_count"),
                "baseline_log1p_row_count": derived_statistic(
                    _median(baseline), "manifest.record_count"
                ),
                "z": z,
            },
        )
    ]


def _layout_file_count(layout: FileLayoutStats) -> float:
    return float(layout.file_count)


def _layout_median_bytes(layout: FileLayoutStats) -> float:
    return float(layout.median_file_bytes)


def file_layout_anomaly(
    history: Sequence[SnapshotMetadata],
    *,
    alpha: float = 0.01,
    min_history: int = _MIN_HISTORY,
) -> list[Candidate]:
    """File count or file-size distribution changed shape.

    Metadata fields used: manifest entry ``file_size_in_bytes`` and the entry count. A
    sudden change here almost always means an upstream pipeline changed rather than that
    the business did -- and it quotes no row at all, so it is the cheapest signal we have.
    """
    layouts = [(s, s.layout) for s in history if s.layout is not None]
    if len(layouts) <= min_history:
        return []
    snap, latest_layout = layouts[-1]
    if latest_layout is None:  # pragma: no cover - filtered above, kept for the type checker
        return []
    out: list[Candidate] = []
    for name, pick in (
        ("file_count", _layout_file_count),
        ("median_file_bytes", _layout_median_bytes),
    ):
        baseline = [math.log1p(pick(prev)) for _, prev in layouts[:-1] if prev is not None]
        observed = math.log1p(pick(latest_layout))
        z, p = _robust_z(baseline, observed)
        if p >= alpha:
            continue
        out.append(
            _candidate(
                "file_layout_anomaly",
                snap,
                None,
                effect_size=observed - _median(baseline),
                p_value=p,
                evidence={
                    "metadata_fields": f"manifest.{name}",
                    "statistic": name,
                    "observed": derived_statistic(pick(latest_layout), f"manifest.{name}"),
                    "baseline_log1p": derived_statistic(_median(baseline), f"manifest.{name}"),
                    "z": z,
                },
            )
        )
    return out


def _bound_at(snap: SnapshotMetadata, column: str, edge: str) -> Tainted[object] | None:
    col = snap.columns.get(column)
    if col is None or col.bounds is None:
        return None
    bound: Tainted[object] | None = getattr(col.bounds, edge)
    return bound


def bounds_drift(
    history: Sequence[SnapshotMetadata],
    *,
    alpha: float = 0.01,
    min_history: int = _MIN_HISTORY,
    include_bound_values: bool = False,
) -> list[Candidate]:
    """A column's lower or upper manifest bound moved further than its history explains.

    Metadata fields used: manifest ``lower_bounds`` / ``upper_bounds``. Those two values are
    two real rows, so by default this detector emits only the distance, which is a derived
    statistic. ``include_bound_values=True`` attaches the bound as DATA_VALUE for a human
    reviewer; nothing else in the pipeline should ask for it.

    Runs on ``OPEN`` columns only. For ``OPAQUE`` the adapter never constructed the bounds
    in the first place, which is why there is no filter here that could be forgotten.
    """
    if len(history) <= min_history:
        return []
    latest = history[-1]
    out: list[Candidate] = []
    for column, col in latest.columns.items():
        if col.bounds is None or col.access_mode is not ColumnAccessMode.OPEN:
            continue
        for edge in ("lower", "upper"):
            observed_t = _bound_at(latest, column, edge)
            if observed_t is None:
                continue
            observed = observed_t.unwrap(_BOUNDS_ARITHMETIC)
            baseline_raw = [
                bound.unwrap(_BOUNDS_ARITHMETIC)
                for bound in (_bound_at(s, column, edge) for s in history[:-1])
                if bound is not None
            ]
            if len(baseline_raw) < min_history:
                continue
            candidate = _numeric_bound_candidate(
                latest, column, edge, baseline_raw, observed, alpha
            ) or _categorical_bound_candidate(latest, column, edge, baseline_raw, observed)
            if candidate is None:
                continue
            if include_bound_values:
                evidence = dict(candidate.evidence)
                evidence[f"{edge}_bound"] = data_value(observed, f"manifest.{edge}_bounds")
                candidate = _candidate(
                    candidate.detector,
                    latest,
                    column,
                    candidate.effect_size,
                    candidate.p_value,
                    evidence,
                )
            out.append(candidate)
    return out


def _numeric_bound_candidate(
    latest: SnapshotMetadata,
    column: str,
    edge: str,
    baseline_raw: Sequence[object],
    observed: object,
    alpha: float,
) -> Candidate | None:
    try:
        baseline = [float(v) for v in baseline_raw]  # type: ignore[arg-type]
        value = float(observed)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    z, p = _robust_z(baseline, value)
    if p >= alpha:
        return None
    return _candidate(
        "bounds_drift",
        latest,
        column,
        effect_size=value - _median(baseline),
        p_value=p,
        evidence={
            "metadata_fields": f"manifest.{edge}_bounds",
            "edge": edge,
            "bound_shift": derived_statistic(
                value - _median(baseline), f"manifest.{edge}_bounds"
            ),
            "z": z,
        },
    )


def _categorical_bound_candidate(
    latest: SnapshotMetadata,
    column: str,
    edge: str,
    baseline_raw: Sequence[object],
    observed: object,
) -> Candidate | None:
    """Non-numeric bound: no distance exists, so the signal is that a bound which had been
    stable has left the set it lived in.

    ``p`` is the exchangeability bound ``1/(n+1)`` -- the chance a fresh draw is a new
    extreme under a stationary distribution. Honest and weak, which is the right shape for
    a free signal whose job is to aim a paid scan.
    """
    seen = {str(v) for v in baseline_raw}
    if len(seen) != 1 or str(observed) in seen:
        return None
    return _candidate(
        "bounds_drift",
        latest,
        column,
        effect_size=1.0,
        p_value=1.0 / (len(baseline_raw) + 1.0),
        evidence={
            "metadata_fields": f"manifest.{edge}_bounds",
            "edge": edge,
            "form": "categorical_bound_left_stable_set",
            "baseline_distinct_bounds": derived_statistic(
                float(len(seen)), f"manifest.{edge}_bounds"
            ),
        },
    )


def schema_change(
    history: Sequence[SnapshotMetadata],
    *,
    alpha: float = 0.01,
    min_history: int = _MIN_HISTORY,
) -> list[Candidate]:
    """Columns appeared or disappeared between the last two snapshots.

    Metadata fields used: the Iceberg schema (``information_schema.columns`` elsewhere).
    Column names travel as DATA_VALUE: ``patient_hiv_status`` discloses as much as a row
    does, and there is no derived form of "which column appeared".

    A newly discovered column is BLIND until a classification is recorded, so this candidate
    doubles as the trigger for that classification. Nothing reads the column before then.
    """
    del alpha, min_history
    if len(history) < 2:
        return []
    previous, latest = history[-2], history[-1]
    before = set(previous.schema_columns or tuple(previous.columns))
    after = set(latest.schema_columns or tuple(latest.columns))
    added = sorted(after - before)
    removed = sorted(before - after)
    if not added and not removed:
        return []
    return [
        _candidate(
            "schema_change",
            latest,
            None,
            effect_size=float(len(added) + len(removed)),
            p_value=0.0,
            evidence={
                "metadata_fields": "schema.columns",
                "added_columns": data_value(tuple(added), "schema.columns"),
                "removed_columns": data_value(tuple(removed), "schema.columns"),
                "added_count": derived_statistic(float(len(added)), "schema.columns"),
                "removed_count": derived_statistic(float(len(removed)), "schema.columns"),
            },
        )
    ]


DEFAULT_DETECTORS: tuple[Callable[..., list[Candidate]], ...] = (
    bounds_drift,
    null_rate_shift,
    ndv_ratio_shift,
    row_volume_anomaly,
    schema_change,
    file_layout_anomaly,
)


def run_all(
    history: Sequence[SnapshotMetadata],
    *,
    alpha: float = 0.01,
    detectors: Sequence[Callable[..., list[Candidate]]] = DEFAULT_DETECTORS,
) -> list[Candidate]:
    """Run every L-1 detector. Deterministic order, no clock read, no randomness."""
    out: list[Candidate] = []
    for detector in detectors:
        out.extend(detector(history, alpha=alpha))
    out.sort(key=lambda c: (c.p_value, c.detector, c.column or ""))
    return out
