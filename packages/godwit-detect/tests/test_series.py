"""Baseline selection: fixed, trailing and seasonal, with gaps and irregular spacing."""

from __future__ import annotations

import pytest
from _detect_support import DAY, EPOCH, context, series, snapshot
from godwit_contracts.common import SnapshotId
from godwit_detect.series import (
    FixedReference,
    IrregularSeriesError,
    Seasonal,
    SeriesPoint,
    SketchSeries,
    Trailing,
    select_baseline,
)
from godwit_sketch import NullRate


def _nulls(count: int, gaps: frozenset[int] = frozenset()) -> SketchSeries:
    return series(
        [None if i in gaps else NullRate.from_items([1.0] * 10, {}) for i in range(count)]
    )


def test_fixed_reference_picks_one_snapshot() -> None:
    chosen = select_baseline(_nulls(5), FixedReference(snapshot_id=snapshot(2)))
    assert [p.snapshot_id for p in chosen] == [snapshot(2)]


def test_trailing_takes_the_most_recent_windows_and_drops_gaps() -> None:
    chosen = select_baseline(_nulls(10, frozenset({8})), Trailing(points=3))
    assert [p.snapshot_id for p in chosen] == [snapshot(6), snapshot(7)]


def test_seasonal_counts_phase_by_time_not_position() -> None:
    chosen = select_baseline(_nulls(29, frozenset({14})), Seasonal(period=7, cycles=4))
    assert [p.snapshot_id for p in chosen] == [snapshot(0), snapshot(7), snapshot(21)]


def test_seasonal_refuses_irregular_windows() -> None:
    points = tuple(
        SeriesPoint(at=EPOCH + DAY * day, snapshot_id=SnapshotId(f"s{day}"), envelope=None)
        for day in (0, 1, 3)
    )
    with pytest.raises(IrregularSeriesError):
        select_baseline(
            SketchSeries(context=context(), points=points), Seasonal(period=1, cycles=1)
        )


def test_series_must_move_forward() -> None:
    point = SeriesPoint(at=EPOCH, snapshot_id=SnapshotId("s"), envelope=None)
    with pytest.raises(ValueError, match="strictly increasing"):
        SketchSeries(context=context(), points=(point, point))
