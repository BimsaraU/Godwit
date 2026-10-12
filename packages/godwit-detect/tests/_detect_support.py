"""Builders shared by the godwit-detect suite and its benchmarks.

Named ``_detect_support`` rather than ``_support`` because several packages put their
test directory on ``sys.path`` and a shared basename would make one package import
another's helpers.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence
from typing import Final

import numpy as np
from godwit_contracts.common import ProbeKey, SnapshotId, SourceId
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.sketch import SketchEnvelope
from godwit_contracts.taint import Acquisition, data_value, schema_name
from godwit_detect.series import ProbeContext, SeriesPoint, SketchSeries
from godwit_sketch import BaseSketch, SketchContext

EPOCH: Final[_dt.datetime] = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
DAY: Final[_dt.timedelta] = _dt.timedelta(days=1)
SOURCE: Final[SourceId] = SourceId("src_detect")


def context(
    sketch_name: str = "kll:0",
    *,
    columns: Sequence[str] = ("amount",),
    probe: str = "prb_detect",
    segment: Segment | None = None,
) -> ProbeContext:
    return ProbeContext(
        probe_key=ProbeKey(probe),
        source_id=SOURCE,
        sketch_name=sketch_name,
        segment=segment if segment is not None else Segment(),
        columns=tuple(schema_name(c) for c in columns),
    )


def eq_segment(column: str, value: str, population: int | None = None) -> Segment:
    return Segment(
        predicates=(
            Predicate(
                column=schema_name(column),
                op=Operator.EQ,
                values=(data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE),),
            ),
        ),
        population=population,
    )


def snapshot(index: int) -> SnapshotId:
    return SnapshotId(f"snap_{index:04d}")


def envelope(
    sketch: BaseSketch, index: int, *, probe: str = "prb_detect", column: str | None = None
) -> SketchEnvelope:
    return sketch.serialise(
        SketchContext(
            source_id=SOURCE,
            snapshot_id=snapshot(index),
            produced_for=ProbeKey(probe),
            produced_at=EPOCH + DAY * index,
            column=column,
        )
    )


def series(
    sketches: Sequence[BaseSketch | None], *, ctx: ProbeContext | None = None
) -> SketchSeries:
    points = tuple(
        SeriesPoint(
            at=EPOCH + DAY * i,
            snapshot_id=snapshot(i),
            envelope=envelope(s, i) if s is not None else None,
        )
        for i, s in enumerate(sketches)
    )
    return SketchSeries(context=ctx if ctx is not None else context(), points=points)


def rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


def categories(generator: np.random.Generator, shares: Sequence[float], n: int) -> list[str]:
    labels = [f"c{i:02d}" for i in range(len(shares))]
    probabilities = np.asarray(shares, dtype=float) / float(np.sum(shares))
    return [labels[i] for i in generator.choice(len(labels), size=n, p=probabilities)]


def edges(
    generator: np.random.Generator, n: int, *, sources: int = 400, targets: int = 200
) -> list[tuple[str, str]]:
    return [
        (f"a{s}", f"b{t}")
        for s, t in zip(
            generator.integers(0, sources, size=n),
            generator.integers(0, targets, size=n),
            strict=True,
        )
    ]
