"""The seam between reading data and summarising it. Data plane.

Non-goal, straight from the brief: *no sketch implementations -- code against the
Protocol; A2 provides the classes.* So this package reads a column out of a data file
and hands the values to somebody else, which needs one narrow injection point.

``godwit_contracts.protocols.Sketch`` is the algorithm protocol: merge, error bound,
serialise. It is not quite enough on its own, because ``Sketch.serialise()`` takes no
arguments and yet a ``SketchEnvelope`` requires a ``source_id``, a ``snapshot_id``, a
``produced_for`` probe key, a ``produced_at`` instant and a ``Provenance`` -- none of
which a sketching algorithm can know. See
``docs/change-requests/CR-A1-sketch-serialise-needs-context.md``.

Until that is decided, the injection point here passes the context in explicitly and
takes a ``SketchEnvelope`` back. An implementation is free to build a ``Sketch``, feed
it, call ``serialise()`` and fill the context in afterwards; this package does not care
how, and owns no sketch code.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

import pyarrow as pa
from godwit_contracts.common import Instant, ProbeKey, SnapshotId, SourceId
from godwit_contracts.sketch import SketchEnvelope, SketchKind
from godwit_contracts.taint import Provenance

__all__ = ["SketchBuilder", "SketchContext"]


class SketchContext:
    """Everything an envelope needs that a sketching algorithm cannot know.

    A plain object rather than a contract model: it is an argument bundle passed
    between two packages in the same process, not a fact that is stored or serialised.
    """

    __slots__ = ("population", "probe_key", "produced_at", "provenance", "snapshot_id", "source_id")

    def __init__(
        self,
        *,
        source_id: SourceId,
        snapshot_id: SnapshotId,
        probe_key: ProbeKey,
        produced_at: Instant,
        provenance: Provenance,
        population: int,
    ) -> None:
        self.source_id = source_id
        self.snapshot_id = snapshot_id
        self.probe_key = probe_key
        self.produced_at = produced_at
        self.provenance = provenance
        self.population = population


@runtime_checkable
class SketchBuilder(Protocol):
    """Turns column values into a serialised sketch. Implemented by A2, used here.

    LAWS, which this package relies on and cannot check:

    1. Deterministic given ``(kind, params, values, context)``. A probe that is not
       reproducible breaks invariant 7 one layer below where anyone will look for it.
    2. The returned envelope declares its own sensitivity honestly. Count-Min and
       frequent-items store observed items and must be ``DATA_VALUE``; contracts
       enforce that on construction, and this package does not second-guess it.
    3. ``values`` is an Arrow table with a ``value`` column and a ``count`` column, or
       ``None`` for a measurement that has no values of its own -- a row count -- where
       ``context.population`` carries the answer instead. ``count`` says how many rows
       each value stands for: one apiece when a scan handed the raw column over, and
       the group size when the database pre-aggregated it. A builder that ignores
       ``count`` gets a warehouse probe wrong by orders of magnitude.
    """

    def build(
        self,
        *,
        kind: SketchKind,
        params: Mapping[str, int | float | str | bool],
        values: pa.Table | None,
        context: SketchContext,
    ) -> SketchEnvelope:
        """Summarise ``values`` into one envelope."""
        ...
