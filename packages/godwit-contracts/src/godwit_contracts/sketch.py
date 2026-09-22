"""Sketches: the mergeable monoids that let batch and streaming run identical code.

Invariant 6: every sketch is a monoid. ``merge`` is associative and commutative, there
is an identity, and the error bound is documented. The laws are stated on the
``Sketch`` protocol in ``godwit_contracts.protocols`` and must be property-tested by
whoever implements one.

Contracts define the *envelope*, not the algorithm. An envelope is a serialised sketch
plus everything needed to merge it safely with another one and to know what it may
disclose. Two sketch kinds -- Count-Min and frequent-items -- store observed items, so
their payloads contain row values. The envelope carries a sensitivity and validates it.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final, Literal, Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    ContentHash,
    GodwitModel,
    Instant,
    NonNegFloat,
    NonNegInt,
    Probability,
    ProbeKey,
    SnapshotId,
    SourceId,
    Version,
)
from godwit_contracts.cost import CostSpend
from godwit_contracts.taint import Provenance, Sensitivity, egress_risk_rank

__all__ = [
    "ITEM_BEARING_KINDS",
    "ErrorBound",
    "SketchBundle",
    "SketchEnvelope",
    "SketchKind",
]


class SketchKind(StrEnum):
    """The sketch vocabulary. A kind not listed here cannot cross a package boundary."""

    THETA = "theta"
    """Distinct counting with set operations. apache-datasketches."""

    HLL = "hll"
    """Distinct counting, smaller than Theta, no set difference. apache-datasketches."""

    KLL = "kll"
    """Quantiles with a rank error bound. apache-datasketches."""

    COUNT_MIN = "count_min"
    """Frequency estimates. LEAK PATH: heavy hitters on an identifier column ARE the PII."""

    FREQUENT_ITEMS = "frequent_items"
    """Top-k items with bounds. LEAK PATH: the items are row values."""

    EXACT_COUNT = "exact_count"
    """A plain count per key-free population. The trivial monoid; used in golden tests."""


ITEM_BEARING_KINDS: Final[frozenset[SketchKind]] = frozenset(
    {SketchKind.COUNT_MIN, SketchKind.FREQUENT_ITEMS}
)
"""Kinds whose serialised payload can contain values taken from rows.

An envelope of one of these kinds must declare DATA_VALUE (or TOKEN, after the gate has
substituted the items). Declaring one as a derived statistic is a validation error, not
a review comment.
"""


class ErrorBound(GodwitModel):
    """The documented accuracy of a sketch. Invariant 6 requires one on every kind."""

    kind: Literal["relative", "absolute", "epsilon_delta", "exact"]
    epsilon: NonNegFloat | None = Field(
        default=None, description="Error magnitude, in the units implied by ``kind``."
    )
    delta: Probability | None = Field(
        default=None, description="Failure probability for epsilon_delta bounds."
    )
    confidence: Probability | None = None
    note: str = Field(
        default="",
        description="Plain-language statement of what the bound means. Never a row value.",
    )

    @model_validator(mode="after")
    def _bound_is_stated(self) -> Self:
        if self.kind == "exact":
            return self
        if self.epsilon is None:
            raise ValueError(f"a {self.kind} error bound must state epsilon")
        if self.kind == "epsilon_delta" and self.delta is None:
            raise ValueError("an epsilon_delta bound must state delta")
        return self


class SketchEnvelope(GodwitModel):
    """One serialised sketch, ready to merge or to store.

    ``payload`` is opaque bytes in the codec named by ``codec``. Contracts never parse
    it. ``godwit-sketch`` owns every codec and must keep old ones readable, because the
    pattern store holds envelopes written by older versions.
    """

    kind: SketchKind
    codec: str = Field(
        description="Codec identifier, e.g. 'datasketches-kll-v1' or 'godwit-cm-v1'. "
        "Versioned, because stored envelopes outlive the code that wrote them."
    )
    schema_version: Version
    payload: bytes = Field(description="The serialised sketch. Opaque to contracts.")
    payload_digest: ContentHash

    sensitivity: Sensitivity
    provenance: Provenance
    population: NonNegInt | None = Field(
        default=None, description="Rows fed into this sketch, when known."
    )

    error_bound: ErrorBound
    params: Mapping[str, int | float | str | bool] = Field(
        default_factory=dict,
        description="Sketch construction parameters: k, lg_k, width, depth, seed. "
        "These are OUR parameters, never row values. Two sketches merge only if their "
        "params match, so they are part of the identity of the envelope.",
    )

    source_id: SourceId
    snapshot_id: SnapshotId
    produced_for: ProbeKey
    produced_at: Instant

    @model_validator(mode="after")
    def _item_bearing_kinds_are_data_tainted(self) -> Self:
        if self.kind in ITEM_BEARING_KINDS:
            floor = Sensitivity.TOKEN
            if egress_risk_rank(self.sensitivity) < egress_risk_rank(floor):
                raise ValueError(
                    f"{self.kind} stores observed items: the envelope must declare "
                    "DATA_VALUE, or TOKEN once the gate has substituted the items"
                )
        return self


class SketchBundle(GodwitModel):
    """Everything one probe run produced, keyed by a name the ProbeSpec chose.

    A bundle is the only thing a probe worker returns. It is the data plane's output
    boundary: no rows, no cursors, no driver objects -- envelopes and numbers.
    """

    bundle_id: str
    probe_key: ProbeKey
    source_id: SourceId
    snapshot_id: SnapshotId
    sketches: Mapping[str, SketchEnvelope]
    cost_spent: CostSpend
    produced_at: Instant
    worker_version: str = Field(description="Code version of the probe worker, for replay.")
    seed: int = Field(description="The seed the worker ran with. Determinism, invariant 7.")

    @model_validator(mode="after")
    def _envelopes_agree_with_bundle(self) -> Self:
        for name, envelope in self.sketches.items():
            if envelope.produced_for != self.probe_key:
                raise ValueError(
                    f"sketch {name!r} was produced for {envelope.produced_for}, "
                    f"not for this bundle's probe {self.probe_key}"
                )
            if envelope.snapshot_id != self.snapshot_id:
                raise ValueError(
                    f"sketch {name!r} is from snapshot {envelope.snapshot_id}, "
                    f"not {self.snapshot_id}; a bundle is one snapshot"
                )
        return self
