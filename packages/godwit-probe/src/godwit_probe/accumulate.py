"""Feeding query results into godwit-sketch, one Arrow batch at a time.

DATA PLANE. Values exist here, in the batch a sketch is being fed from, and nowhere
downstream: an :class:`Accumulator` holds a sketch, never the rows, and every batch is
dropped as soon as it has been folded in. That is what makes peak memory a function of
the batch size and the sketch parameters rather than of the table.

How each column type reaches a sketch:

* ``ThetaNdv`` / ``HllCount`` take canonical keys: every non-null value is rendered with
  ``canonical_scalar``, exactly as ``godwit_sketch`` renders items itself, so a sketch
  built here equals one built with ``from_items`` over the same values.
* ``KllQuantile`` / ``Moments`` take floats.
* ``CountMinHeavy`` / ``CategoryHistogram`` take the value itself (string, integer,
  float or boolean) and canonicalise internally.
* ``GraphDegree`` takes the two endpoint columns as strings.
* ``NullRate`` is counted per batch without leaving Arrow -- the null count is a column
  statistic -- and merged, which is exact for this sketch. A table-level row count
  (``count(*)`` per file) sums into the same sketch with no nulls.

An OPAQUE column arrives as its ``h_...`` digest. A value-bearing sketch over it (or over
an unpermitted identifier) is given ``godwit_sketch.KeyHasher`` in OPAQUE mode, so its
stored keys are digests of digests and its envelope says so.
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

import pyarrow as pa
from godwit_contracts import ScalarValue, SketchEnvelope
from godwit_contracts.segment import canonical_scalar
from godwit_sketch import (
    BaseSketch,
    CategoryHistogram,
    CountMinHeavy,
    GraphDegree,
    HllCount,
    KllQuantile,
    Moments,
    NullRate,
    SketchContext,
    ThetaNdv,
)

from godwit_probe.keyring import ProbeKeyring
from godwit_probe.plan import ROW_COUNT_FIELD, PlannedSketch

__all__ = ["Accumulator"]


def _floats(values: Sequence[ScalarValue]) -> list[float]:
    return [float(value) for value in values if isinstance(value, int | float | Decimal)]


class Accumulator:
    """One sketch, fed batch by batch."""

    __slots__ = ("_planned", "_sketch")

    def __init__(self, planned: PlannedSketch, *, keyring: ProbeKeyring | None) -> None:
        self._planned = planned
        sketch = planned.sketch_cls.identity(planned.params)
        if planned.hashed_entropy_bits is not None:
            if keyring is None:
                raise ValueError("a hashed sketch needs a keyring")
            hasher = keyring.sketch_hasher(input_entropy_bits=planned.hashed_entropy_bits)
            if isinstance(sketch, CountMinHeavy | GraphDegree):
                sketch = sketch.with_hasher(hasher)
        self._sketch: BaseSketch = sketch

    @property
    def planned(self) -> PlannedSketch:
        """What this accumulator was planned to build."""
        return self._planned

    def feed(self, batch: pa.RecordBatch) -> None:
        """Fold one result batch in. The batch is not retained."""
        sketch = self._sketch
        fields = self._planned.fields
        if isinstance(sketch, NullRate):
            column = batch.column(fields[0])
            if fields[0] == ROW_COUNT_FIELD:
                rows = sum(int(value) for value in column.to_pylist() if value is not None)
                self._sketch = sketch.merge(NullRate(nulls=0, total=rows))
            else:
                self._sketch = sketch.merge(NullRate(nulls=column.null_count, total=len(column)))
            return
        if isinstance(sketch, GraphDegree):
            sources = batch.column(fields[0]).to_pylist()
            targets = batch.column(fields[1]).to_pylist()
            for source, target in zip(sources, targets, strict=True):
                if source is not None and target is not None:
                    sketch.observe_edge(str(source), str(target))
            return
        values = [value for value in batch.column(fields[0]).to_pylist() if value is not None]
        self._update(sketch, values)

    @staticmethod
    def _update(sketch: BaseSketch, values: list[ScalarValue]) -> None:
        if isinstance(sketch, ThetaNdv | HllCount):
            for value in values:
                sketch.update(canonical_scalar(value))
        elif isinstance(sketch, KllQuantile | Moments):
            for number in _floats(values):
                sketch.update(number)
        elif isinstance(sketch, CountMinHeavy | CategoryHistogram):
            for value in values:
                if isinstance(value, str | int | float):
                    sketch.update(value)
        else:
            raise TypeError("no feeding rule for this sketch class")

    def envelope(self, context: SketchContext) -> SketchEnvelope:
        """Serialise the sketch with the probe's context."""
        return self._sketch.serialise(context)

    def sketch(self) -> BaseSketch:
        """The sketch built so far. Data plane; it may hold row values."""
        return self._sketch
