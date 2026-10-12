"""Sketch time-series, and the three baseline policies.

"Emerging" means the statistics changed over time, so every detector that looks for
change reads a *series*: one envelope per window, in time order, with gaps kept as gaps.
A window where no data arrived is ``envelope=None`` and is never treated as a window
where data arrived and summed to nothing -- the first is usually a broken pipeline, the
second a quiet Sunday, and a detector that confuses them reports the wrong one.

A baseline policy picks which earlier windows the latest one is compared against:

``FixedReference``
    One named snapshot. Use when a human has blessed a reference period.
``Trailing``
    The last ``points`` windows before the current one. Cheap and adaptive, and fires
    every Monday morning on anything with a weekly cycle.
``Seasonal``
    The same phase of the last ``cycles`` cycles: for daily windows with ``period=7``,
    the previous four Mondays. This is the policy that keeps a strongly weekly series
    quiet, and it is what a trailing baseline gets wrong.

Selected baseline windows are merged into one reference sketch (every sketch is a
monoid, invariant 6), and -- when there are at least three of them -- also compared with
each other to estimate how much the reference itself moves. See
:func:`godwit_detect.stats.dispersion_factor`.
"""

from __future__ import annotations

import datetime as _dt
from typing import Literal, Self

from godwit_contracts.common import GodwitModel, Instant, ProbeKey, SnapshotId, SourceId
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.segment import Segment
from godwit_contracts.sketch import SketchEnvelope
from godwit_contracts.taint import Sensitivity, Tainted
from pydantic import Field, model_validator

__all__ = [
    "BaselinePolicy",
    "FixedReference",
    "IrregularSeriesError",
    "ProbeContext",
    "Seasonal",
    "SeriesPoint",
    "SketchSeries",
    "Trailing",
    "select_baseline",
]


class ProbeContext(GodwitModel):
    """What a series measured: which probe, which slice, which columns.

    A detector needs this to write evidence that names its segment and columns in a
    structured way, and the contract's ``SketchBundle`` does not carry it -- see
    ``docs/change-requests/CR-A7-detector-cannot-see-history-or-spec.md``.
    """

    probe_key: ProbeKey
    source_id: SourceId
    sketch_name: str
    segment: Segment = Field(default_factory=Segment)
    columns: tuple[Tainted[str], ...] = ()

    @model_validator(mode="after")
    def _columns_are_schema_names(self) -> Self:
        for index, column in enumerate(self.columns):
            if column.sensitivity is not Sensitivity.SCHEMA_NAME:
                raise ValueError(f"ProbeContext.columns[{index}] must be tainted SCHEMA_NAME")
        return self

    @classmethod
    def from_spec(cls, spec: ProbeSpec, sketch_name: str) -> ProbeContext:
        """Resolve a bundle's sketch name against the spec that produced it.

        Sketch names follow godwit-probe's convention: ``"<kind>:<index>"`` indexes
        ``spec.columns``, ``"<kind>:table"`` measures the table, and ``"count_min:graph"``
        is the graph over both columns.
        """
        suffix = sketch_name.rpartition(":")[2]
        columns: tuple[Tainted[str], ...] = ()
        if suffix == "graph":
            columns = tuple(spec.columns)
        elif suffix.isdigit() and int(suffix) < len(spec.columns):
            columns = (spec.columns[int(suffix)],)
        return cls(
            probe_key=spec.key,
            source_id=spec.source.source_id,
            sketch_name=sketch_name,
            segment=spec.segment,
            columns=columns,
        )


class SeriesPoint(GodwitModel):
    """One window. ``envelope=None`` is a gap: no data arrived, which is not zero data."""

    at: Instant
    snapshot_id: SnapshotId
    envelope: SketchEnvelope | None = None


class SketchSeries(GodwitModel):
    """Windows of one probe's one sketch, strictly increasing in time; the last is current."""

    context: ProbeContext
    points: tuple[SeriesPoint, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        for earlier, later in zip(self.points, self.points[1:], strict=False):
            if later.at <= earlier.at:
                raise ValueError("series points must be strictly increasing in time")
        return self

    @property
    def current(self) -> SeriesPoint:
        """The window under test."""
        return self.points[-1]

    def is_regular(self) -> bool:
        """True when every step between consecutive windows is the same length."""
        steps = {
            later.at - earlier.at
            for earlier, later in zip(self.points, self.points[1:], strict=False)
        }
        return len(steps) <= 1


class FixedReference(GodwitModel):
    """Compare against one named snapshot."""

    kind: Literal["fixed"] = "fixed"
    snapshot_id: SnapshotId

    def describe(self) -> str:
        """Stable text for evidence. Never a value: snapshot ids are ours."""
        return f"fixed({self.snapshot_id})"


class Trailing(GodwitModel):
    """Compare against the ``points`` windows immediately before the current one."""

    kind: Literal["trailing"] = "trailing"
    points: int = Field(ge=1)

    def describe(self) -> str:
        """Stable text for evidence."""
        return f"trailing(points={self.points})"


class Seasonal(GodwitModel):
    """Compare against the same phase of the last ``cycles`` cycles of ``period`` windows."""

    kind: Literal["seasonal"] = "seasonal"
    period: int = Field(ge=1)
    cycles: int = Field(ge=1)

    def describe(self) -> str:
        """Stable text for evidence."""
        return f"seasonal(period={self.period},cycles={self.cycles})"


type BaselinePolicy = FixedReference | Trailing | Seasonal


class IrregularSeriesError(ValueError):
    """A seasonal baseline was asked of a series whose windows are not evenly spaced."""


def select_baseline(series: SketchSeries, policy: BaselinePolicy) -> tuple[SeriesPoint, ...]:
    """The non-gap windows ``policy`` compares the current window against, oldest first.

    A seasonal policy counts phase by *time*, not by position, so a missing window does
    not shift every earlier Monday onto a Sunday. It therefore needs evenly spaced
    windows and raises :class:`IrregularSeriesError` otherwise.
    """
    history = series.points[:-1]
    if isinstance(policy, FixedReference):
        chosen = tuple(point for point in history if point.snapshot_id == policy.snapshot_id)
    elif isinstance(policy, Trailing):
        chosen = history[-policy.points :]
    else:
        if not series.is_regular():
            raise IrregularSeriesError("a seasonal baseline needs evenly spaced windows")
        step = (
            series.points[1].at - series.points[0].at
            if len(series.points) > 1
            else _dt.timedelta(0)
        )
        wanted = {series.current.at - step * policy.period * j for j in range(1, policy.cycles + 1)}
        chosen = tuple(point for point in history if point.at in wanted)
    return tuple(point for point in chosen if point.envelope is not None)
