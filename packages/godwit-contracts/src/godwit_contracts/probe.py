"""Probes: the unit of paid work in the data plane (L1).

A ``ProbeSpec`` is a complete, deterministic description of one measurement. Hand the
same spec, snapshot and seed to a worker twice and you get the same ``SketchBundle``
twice. That is invariant 7 at the probe layer, and it is what makes ``godwit-replay``
possible at all.

``probe_key`` identifies the *measurement*, not the *run*. It deliberately excludes the
snapshot, the budget and anything about scheduling, so that the same measurement taken
at two snapshots shares a key and can be compared over time -- which is the entire
premise of discovery.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    GodwitModel,
    Instant,
    ProbeId,
    ProbeKey,
    Version,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget
from godwit_contracts.segment import Segment, canonical_column, canonical_scalar
from godwit_contracts.sketch import SketchKind
from godwit_contracts.source import SnapshotRef, SourceRef
from godwit_contracts.taint import Sensitivity, Tainted

__all__ = ["ProbeKind", "ProbeSpec", "probe_key"]


class ProbeKind(StrEnum):
    """What a probe measures.

    Metadata-first (invariant 5): ``COLUMN_BOUNDS``, ``FRESHNESS`` and ``ROW_COUNT`` are
    usually answerable from the catalog with no table scan at all. The rest cost money.
    """

    COLUMN_BOUNDS = "column_bounds"
    ROW_COUNT = "row_count"
    FRESHNESS = "freshness"
    NULL_RATE = "null_rate"
    DISTINCT_COUNT = "distinct_count"
    QUANTILES = "quantiles"
    HEAVY_HITTERS = "heavy_hitters"
    CATEGORY_HISTOGRAM = "category_histogram"
    SEGMENT_AGGREGATE = "segment_aggregate"
    JOIN_CARDINALITY = "join_cardinality"
    GRAPH_DEGREE = "graph_degree"


class ProbeSpec(GodwitModel):
    """One measurement, fully specified.

    Determinism rules, enforced by the shape of this type:

    * ``seed`` is explicit. There is no default, because a default seed is an unseeded
      run wearing a hat.
    * ``as_of`` is injected. No probe reads a clock.
    * ``snapshot`` may be ``None`` at scheduling time, meaning "whatever is current when
      this runs". The worker MUST record the snapshot it resolved in the returned
      ``SketchBundle``; replay uses the resolved one, never ``None``.
    """

    probe_id: ProbeId
    kind: ProbeKind
    spec_version: Version

    source: SourceRef
    snapshot: SnapshotRef | None = None
    columns: tuple[Tainted[str], ...] = ()
    segment: Segment = Field(
        default_factory=Segment,
        description="The slice to measure. The default empty segment is the whole table.",
    )
    sketches: tuple[SketchKind, ...] = ()
    params: Mapping[str, int | float | str | bool] = Field(
        default_factory=dict,
        description="Our measurement parameters (k, lg_k, top_k, bucket count). Never a "
        "row value: a threshold that came out of the data belongs in ``segment``.",
    )

    budget: CostBudget = Field(
        description="Invariant 6. The worker refuses rather than exceeds. A refusal is "
        "a normal outcome and must be recorded, not retried with a bigger number."
    )
    seed: int
    as_of: Instant

    @model_validator(mode="after")
    def _columns_are_schema_tainted(self) -> Self:
        for index, column in enumerate(self.columns):
            if column.sensitivity is not Sensitivity.SCHEMA_NAME:
                raise ValueError(f"ProbeSpec.columns[{index}] must be tainted SCHEMA_NAME")
        return self

    def canonical_form(self) -> str:
        """The exact string hashed into :attr:`key`. See :func:`probe_key`."""
        return _canonical_probe(self)

    @property
    def key(self) -> ProbeKey:
        """Stable identity of this measurement across snapshots."""
        return probe_key(self)


def _canonical_probe(spec: ProbeSpec) -> str:
    """Canonical identity form of a probe spec.

    Included, in this order: kind, spec_version, source_id, normalised namespace,
    normalised table, sorted normalised column names, segment key, sorted sketch kinds,
    params (keys sorted, each value rendered by ``canonical_scalar`` so float formatting
    is portable), seed.

    Excluded, deliberately: probe_id (a run handle), snapshot (the point in time being
    measured), budget (an operational ceiling), as_of (scheduling). Two probes that
    measure the same thing at different times must share a key.
    """
    payload = {
        "kind": spec.kind.value,
        "spec_version": int(spec.spec_version),
        "source_id": str(spec.source.source_id),
        "namespace": canonical_column(spec.source.namespace.reveal()),
        "table": canonical_column(spec.source.table.reveal()),
        "columns": sorted(canonical_column(column.reveal()) for column in spec.columns),
        "segment": str(spec.segment.key),
        "sketches": sorted(kind.value for kind in spec.sketches),
        "params": {key: canonical_scalar(spec.params[key]) for key in sorted(spec.params)},
        "seed": spec.seed,
    }
    return canonical_json(payload)


def probe_key(spec: ProbeSpec) -> ProbeKey:
    """Hash a probe spec's identity form into its stable key."""
    return ProbeKey(content_hash(_canonical_probe(spec), prefix="prb"))
