"""Graph structure: :class:`GraphDegree`, over an ``(source_entity, target_entity)`` pair.

WHY THIS SKETCH EXISTS
----------------------
Row-level statistics cannot see organised fraud. A structuring ring moves amounts that
are individually unremarkable, at times that are individually unremarkable, between
accounts that are individually unremarkable. What gives it away is *shape*: forty
accounts funnelling into one, one device shared by two hundred customers, a cluster of
accounts that transact only with each other. Those are properties of the edge multiset,
and no amount of staring at the ``amount`` column recovers them.

Every column that carries this signal -- device id, address, phone, account number -- is
a direct identifier. Skipping them would protect the data by deleting the product, which
is why they are OPAQUE by default rather than BLIND: pass a
:class:`~godwit_sketch.items.KeyHasher` in hashed mode and this sketch keeps every
structural property it needs (degree, fan-in, fan-out, repeat-edge structure) while
storing only keyed digests.

WHAT IS AND IS NOT MERGEABLE HERE -- READ BEFORE USING THE DEGREE QUANTILES
---------------------------------------------------------------------------
Edge counts, distinct-entity counts and the fan-in/fan-out summaries are all built from
edges and merge correctly however the edges were partitioned. Feed them shards of a
table in any order and the answer is the same.

The **degree quantiles** are different, and the difference is a trap. A degree is a
per-entity aggregate, so it is only known once every edge for that entity has been seen.
:meth:`observe_degree` therefore takes an already-aggregated degree, from a
``GROUP BY``, and the resulting quantiles are meaningful only if each entity's edges
were wholly inside one partition. Merge two shards that both contain account ``A`` and
the sketch records ``A`` twice with two partial degrees, understating its true degree --
which is precisely the account a mule detector most needs to see.

That precondition is not left to a docstring. It travels in the parameters as
``degrees_partitioned_by_entity``, it is part of the merge identity, and a sketch that
claims it refuses to merge with one that does not. A probe that cannot hash-partition by
entity should leave the degree quantiles empty and use the fan-in/fan-out summaries,
which carry no such condition.

DISCLOSURE
----------
Value-bearing: the fan-in and fan-out heavy hitters are entity identifiers. They come
back :class:`~godwit_contracts.taint.Tainted` DATA_VALUE in both key modes.

Degrees themselves are counts -- aggregates over edges, not values out of rows -- so
:meth:`out_degree_quantile` and the concentration ratios return plain floats. "The
busiest account has 400 counterparties" discloses a count; *which* account it is, is the
disclosure, and that only ever leaves here tainted.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import ClassVar, Final, Self

from godwit_contracts.sketch import ErrorBound, SketchKind
from godwit_contracts.taint import Acquisition, Sensitivity, Tainted

from godwit_sketch.base import (
    BaseSketch,
    ItemFlavour,
    MergeExactness,
    ParamValue,
    SketchItem,
    register,
)
from godwit_sketch.codec import decode_header, encode_container, read_exact
from godwit_sketch.distinct import ThetaNdv
from godwit_sketch.frequency import CountMinHeavy
from godwit_sketch.items import KeyHasher, canonical_item_key, edge_key
from godwit_sketch.quantile import KllQuantile

__all__ = ["Direction", "GraphDegree"]

_DEFAULT_GRAPH_PARAMS: Final[dict[str, ParamValue]] = {
    "lg_k": 12,
    "width": 2718,
    "depth": 5,
    "seed": 0,
    "capacity": 256,
    "k": 200,
    "degrees_partitioned_by_entity": False,
}


class Direction(StrEnum):
    """Which side of an edge a degree is measured on."""

    OUT = "out"
    """Degree of the source entity: how many edges leave it. Fan-out."""

    IN = "in"
    """Degree of the target entity: how many edges arrive at it. Fan-in."""


@register
class GraphDegree(BaseSketch):
    """Fan-in and fan-out structure over a directed edge stream.

    Composed of, and merged componentwise with, sketches from the rest of this package:
    three :class:`~godwit_sketch.distinct.ThetaNdv` for distinct sources, targets and
    edges; two :class:`~godwit_sketch.frequency.CountMinHeavy` for per-entity out- and
    in-degree with heavy hitters; and two :class:`~godwit_sketch.quantile.KllQuantile`
    for the degree distributions, subject to the partitioning precondition above.

    Composition rather than a bespoke structure is deliberate: each part is already
    property-tested as a monoid, so the composite inherits those proofs instead of
    restating them.
    """

    KIND: ClassVar[SketchKind] = SketchKind.COUNT_MIN
    CODEC: ClassVar[str] = "godwit-graphdegree-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = True
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.BOUNDED
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.EDGE
    ACQUISITION: ClassVar[Acquisition] = Acquisition.COUNT_MIN_HEAVY_HITTER
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DATA_VALUE

    __slots__ = (
        "_edges",
        "_hasher",
        "_in_cm",
        "_in_deg",
        "_out_cm",
        "_out_deg",
        "_pairs",
        "_params",
        "_sources",
        "_targets",
    )

    def __init__(
        self,
        *,
        params: Mapping[str, ParamValue],
        hasher: KeyHasher,
        edges: int,
        sources: ThetaNdv,
        targets: ThetaNdv,
        pairs: ThetaNdv,
        out_cm: CountMinHeavy,
        in_cm: CountMinHeavy,
        out_deg: KllQuantile,
        in_deg: KllQuantile,
    ) -> None:
        self._params = dict(params)
        self._hasher = hasher
        self._edges = edges
        self._sources = sources
        self._targets = targets
        self._pairs = pairs
        self._out_cm = out_cm
        self._in_cm = in_cm
        self._out_deg = out_deg
        self._in_deg = in_deg

    # -- construction -------------------------------------------------------------------

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """An empty graph summary."""
        merged: dict[str, ParamValue] = {**_DEFAULT_GRAPH_PARAMS, **dict(params)}
        hasher = KeyHasher.from_params(dict(merged))
        return cls(
            params=merged,
            hasher=hasher,
            edges=0,
            sources=ThetaNdv.identity(merged),
            targets=ThetaNdv.identity(merged),
            pairs=ThetaNdv.identity(merged),
            out_cm=CountMinHeavy.identity(merged),
            in_cm=CountMinHeavy.identity(merged),
            out_deg=KllQuantile.identity(merged),
            in_deg=KllQuantile.identity(merged),
        )

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from ``(source, target)`` tuples. Anything else is skipped."""
        sketch = cls.identity(params)
        for item in items:
            if isinstance(item, tuple):
                sketch.observe_edge(item[0], item[1])
        return sketch

    def with_hasher(self, hasher: KeyHasher) -> Self:
        """Return a copy that keys new entities with ``hasher``. Data plane only."""
        return type(self)(
            params=self._params,
            hasher=hasher,
            edges=self._edges,
            sources=self._sources,
            targets=self._targets,
            pairs=self._pairs,
            out_cm=self._out_cm.with_hasher(hasher),
            in_cm=self._in_cm.with_hasher(hasher),
            out_deg=self._out_deg,
            in_deg=self._in_deg,
        )

    # -- ingestion ----------------------------------------------------------------------

    def observe_edge(self, source: str, target: str) -> None:
        """Record one directed edge. Mutates in place."""
        # One keying path: canonicalise, then hash. The Count-Min pair does exactly the
        # same thing internally, so the entity identity the distinct counters see and
        # the one the heavy hitters see are the same string. They take the raw entity
        # rather than the stored form, because passing an already-hashed key would hash
        # it twice and the heavy hitters would stop matching a caller's lookup.
        stored_source = self._hasher.apply(canonical_item_key(source) or source)
        stored_target = self._hasher.apply(canonical_item_key(target) or target)
        self._edges += 1
        self._sources.update(stored_source)
        self._targets.update(stored_target)
        self._pairs.update(edge_key(stored_source, stored_target))
        self._out_cm.update(source)
        self._in_cm.update(target)

    def observe_degree(self, degree: int, *, direction: Direction) -> None:
        """Record one entity's already-aggregated degree.

        Only meaningful when the caller partitioned by entity -- see the module
        docstring -- and this refuses to accept one otherwise, rather than quietly
        building a distribution nobody can interpret.
        """
        if not self._params.get("degrees_partitioned_by_entity", False):
            raise ValueError(
                "observe_degree() needs degrees_partitioned_by_entity=True in params: "
                "a degree from a partition that does not hold all of an entity's edges "
                "is a partial degree, and merging partials understates exactly the "
                "high-degree entities a mule detector is looking for"
            )
        target = self._out_deg if direction is Direction.OUT else self._in_deg
        target.update(float(degree))

    # -- identity -----------------------------------------------------------------------

    @property
    def params(self) -> Mapping[str, ParamValue]:
        """Every component's parameters, plus the degree-partitioning precondition."""
        return dict(self._params)

    @property
    def population(self) -> int:
        """Edges observed."""
        return self._edges

    # -- structural statistics -----------------------------------------------------------

    def edge_count(self) -> int:
        """Total edges, counting repeats."""
        return self._edges

    def distinct_sources(self) -> float:
        """Estimated number of distinct source entities."""
        return self._sources.estimate()

    def distinct_targets(self) -> float:
        """Estimated number of distinct target entities."""
        return self._targets.estimate()

    def distinct_edges(self) -> float:
        """Estimated number of distinct ``(source, target)`` pairs."""
        return self._pairs.estimate()

    def mean_out_degree(self) -> float:
        """Edges per source entity."""
        sources = self.distinct_sources()
        return self._edges / sources if sources else math.nan

    def mean_in_degree(self) -> float:
        """Edges per target entity.

        A funnel shows up here before it shows up anywhere else: many accounts paying
        few accounts drives mean in-degree up while mean out-degree stays flat.
        """
        targets = self.distinct_targets()
        return self._edges / targets if targets else math.nan

    def edge_multiplicity(self) -> float:
        """Edges divided by distinct edges: how often the same pair transacts again.

        Near 1.0 means almost every pair is seen once, which is what a burst of
        one-shot mule transfers looks like. A high value is ordinary repeat business.
        """
        distinct = self.distinct_edges()
        return self._edges / distinct if distinct else math.nan

    def fan_in_out_ratio(self) -> float:
        """Distinct sources over distinct targets.

        Well above 1.0 is a funnel: many payers, few payees. Well below is a
        distributor. Scale-free, so it is comparable across snapshots of different size.
        """
        targets = self.distinct_targets()
        return self.distinct_sources() / targets if targets else math.nan

    def out_degree(self, entity: str) -> int:
        """Estimated out-degree of one entity. Over-estimates, never under.

        Takes the entity in the form :meth:`observe_edge` was given it, not a hashed
        one: the keying happens inside.
        """
        return self._out_cm.estimate(entity)

    def in_degree(self, entity: str) -> int:
        """Estimated in-degree of one entity. Over-estimates, never under."""
        return self._in_cm.estimate(entity)

    def fan_out_heavy_hitters(
        self, limit: int | None = None
    ) -> tuple[tuple[Tainted[str], int], ...]:
        """Entities with the most outgoing edges. Identifiers, so ``Tainted``."""
        return self._out_cm.heavy_hitters(limit)

    def fan_in_heavy_hitters(
        self, limit: int | None = None
    ) -> tuple[tuple[Tainted[str], int], ...]:
        """Entities with the most incoming edges. Identifiers, so ``Tainted``.

        The single most useful list in the package for detecting a mule network: the
        collection accounts a structuring ring funnels into sit at the top of it.
        """
        return self._in_cm.heavy_hitters(limit)

    def concentration(self, *, direction: Direction, top: int = 10) -> float:
        """Share of all edges held by the ``top`` busiest entities, in ``[0, 1]``.

        A count over a population, so a derived statistic: it says how concentrated the
        graph is without naming anybody.
        """
        if not self._edges:
            return math.nan
        summary = self._out_cm if direction is Direction.OUT else self._in_cm
        return sum(count for _, count in summary.heavy_hitters(top)) / self._edges

    def degree_quantile(self, fraction: float, *, direction: Direction) -> float:
        """A quantile of the degree distribution. NaN when no degrees were recorded.

        A degree is a count of edges, not a value out of a row, so this is a derived
        statistic and comes back as a plain float. Valid only under the partitioning
        precondition in the module docstring.
        """
        sketch = self._out_deg if direction is Direction.OUT else self._in_deg
        if not sketch.population:
            return math.nan
        return sketch.quantile(fraction).reveal()

    def degree_population(self, *, direction: Direction) -> int:
        """How many entity degrees were recorded. Zero means the quantiles are empty."""
        sketch = self._out_deg if direction is Direction.OUT else self._in_deg
        return sketch.population

    def error_bound(self) -> ErrorBound:
        """The weakest component bound: the Count-Min degree estimate."""
        bound = self._out_cm.error_bound()
        return ErrorBound(
            kind=bound.kind,
            epsilon=bound.epsilon,
            delta=bound.delta,
            note=f"composite; degree estimates carry the Count-Min bound ({bound.note}), "
            f"distinct-entity counts carry the Theta bound "
            f"({self._sources.error_bound().note})",
        )

    # -- the monoid ---------------------------------------------------------------------

    def merge(self, other: Self) -> Self:
        """Merge every component. Bounded, inheriting Count-Min's and KLL's exactness."""
        self.require_mergeable(other)
        return type(self)(
            params=self._params,
            hasher=self._hasher,
            edges=self._edges + other._edges,
            sources=self._sources.merge(other._sources),
            targets=self._targets.merge(other._targets),
            pairs=self._pairs.merge(other._pairs),
            out_cm=self._out_cm.merge(other._out_cm),
            in_cm=self._in_cm.merge(other._in_cm),
            out_deg=self._out_deg.merge(other._out_deg),
            in_deg=self._in_deg.merge(other._in_deg),
        )

    # -- serialisation -------------------------------------------------------------------

    def encode(self) -> bytes:
        """Edge count, then each component's own framed payload, length-prefixed."""
        params_json = json.dumps(dict(self._params), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        parts = [
            len(params_json).to_bytes(4, "big"),
            params_json,
            self._edges.to_bytes(8, "big"),
        ]
        for component in (
            self._sources,
            self._targets,
            self._pairs,
            self._out_cm,
            self._in_cm,
            self._out_deg,
            self._in_deg,
        ):
            blob = component.encode()
            parts.append(len(blob).to_bytes(4, "big"))
            parts.append(blob)
        return encode_container(
            codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=b"".join(parts)
        )

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        offset = header.body_offset
        raw, offset = read_exact(payload, offset, 4)
        params_bytes, offset = read_exact(payload, offset, int.from_bytes(raw, "big"))
        params = json.loads(params_bytes.decode("utf-8"))
        raw, offset = read_exact(payload, offset, 8)
        edges = int.from_bytes(raw, "big")
        blobs: list[bytes] = []
        for _ in range(7):
            raw, offset = read_exact(payload, offset, 4)
            blob, offset = read_exact(payload, offset, int.from_bytes(raw, "big"))
            blobs.append(blob)
        return cls(
            params=params,
            hasher=KeyHasher.from_params(dict(params)),
            edges=edges,
            sources=ThetaNdv._decode_body(blobs[0]),
            targets=ThetaNdv._decode_body(blobs[1]),
            pairs=ThetaNdv._decode_body(blobs[2]),
            out_cm=CountMinHeavy._decode_body(blobs[3]),
            in_cm=CountMinHeavy._decode_body(blobs[4]),
            out_deg=KllQuantile._decode_body(blobs[5]),
            in_deg=KllQuantile._decode_body(blobs[6]),
        )
