"""Distinct counting with set operations: :class:`ThetaNdv`, over Apache DataSketches.

Verified, not assumed, to be deterministic and to union byte-identically across every
permutation of its inputs -- see ``tests/test_upstream_determinism.py``, which pins that
assumption so a future DataSketches upgrade cannot quietly break the batch/streaming
equivalence the whole package rests on.

:attr:`~godwit_sketch.base.MergeExactness.EXACT`: Theta keeps the *k* smallest hashes of
the input, and the k smallest of a union is a pure function of that union, so bracketing
cannot matter. One wrinkle, handled in :meth:`ThetaNdv._resolved`, is that a theta sketch
has more than one byte representation of the same set.

The HyperLogLog counterpart lives in :mod:`godwit_sketch.hll` and is written by hand,
because the upstream HLL *is* deterministic but is not byte-canonical below its sparse
threshold. That module explains why.

DISCLOSURE
----------
Neither payload contains a row value: both store hashes, so both are
``DERIVED_STATISTIC``. One caveat worth stating plainly, because it is easy to miss:

    A Theta or HLL sketch over a *low-cardinality* column is a membership oracle.

The hash seed is a construction parameter and travels in the envelope. Anyone holding
the envelope can hash a guess and test whether it is present. For ``country`` or
``status`` that is a complete disclosure of which values occur. It does not make the
sketch item-bearing -- nothing is stored verbatim, and set membership over a guessable
domain is a different and lesser hazard than a stored value -- but a guardrail that
treats these as unconditionally safe is wrong. Use :meth:`ThetaNdv.is_membership_oracle`
to ask, and route through the gate when it says yes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import ClassVar, Final, Self

import datasketches as ds
from godwit_contracts.sketch import ErrorBound, SketchKind
from godwit_contracts.taint import Acquisition, Sensitivity

from godwit_sketch.base import (
    BaseSketch,
    ItemFlavour,
    MergeExactness,
    ParamValue,
    SketchItem,
    register,
)
from godwit_sketch.codec import decode_header, encode_container, read_exact
from godwit_sketch.errors import SketchDecodeError
from godwit_sketch.items import canonical_item_key

__all__ = [
    "DEFAULT_THETA_SEED",
    "ICEBERG_THETA_BLOB_TYPE",
    "ThetaNdv",
]

DEFAULT_THETA_SEED: Final[int] = 9001
"""The DataSketches default hash seed, which Iceberg's Theta blobs also use.

Changing it makes a sketch unmergeable with every Iceberg-sourced sketch in existence,
so it is a parameter rather than a constant, and the default is the interoperable one.
"""

ICEBERG_THETA_BLOB_TYPE: Final[str] = "apache-datasketches-theta-v1"
"""The Puffin blob type Iceberg writes NDV sketches as.

Read one with :meth:`ThetaNdv.from_iceberg_blob`.
"""

_MEMBERSHIP_ORACLE_CARDINALITY: Final[int] = 1024
"""At or below this estimated distinct count, treat the sketch as a membership oracle.

A domain small enough to enumerate is a domain an envelope holder can test exhaustively.
"""

_DEFAULT_LG_K: Final[int] = 12
_MIN_LG_K: Final[int] = 4
_MAX_LG_K: Final[int] = 21


def _lg_k_of(params: Mapping[str, ParamValue], default: int = _DEFAULT_LG_K) -> int:
    lg_k = int(params.get("lg_k", default))
    if not _MIN_LG_K <= lg_k <= _MAX_LG_K:
        raise ValueError(f"lg_k must be {_MIN_LG_K}..{_MAX_LG_K}, got {lg_k}")
    return lg_k


@register
class ThetaNdv(BaseSketch):
    """Distinct-value counting with set operations, over Apache DataSketches Theta.

    Theta is the kind to reach for when a detector needs set *difference* -- "which
    entities are in this snapshot and not the last" -- which HLL cannot do. It is
    larger than HLL for the same accuracy, so use :class:`HllCount` when a plain
    cardinality is all that is wanted.

    Parameters: ``lg_k`` (log2 of the sketch size, default 12) and ``seed`` (default
    :data:`DEFAULT_THETA_SEED`).
    """

    KIND: ClassVar[SketchKind] = SketchKind.THETA
    CODEC: ClassVar[str] = "godwit-theta-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = False
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.EXACT
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.CATEGORICAL
    ACQUISITION: ClassVar[Acquisition] = Acquisition.SKETCH_SUMMARY
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DERIVED_STATISTIC

    __slots__ = ("_builder", "_canonical", "_lg_k", "_population", "_seed", "_sketch")

    def __init__(
        self,
        *,
        sketch: ds.compact_theta_sketch | None,
        lg_k: int,
        seed: int,
        population: int,
        builder: ds.update_theta_sketch | None = None,
        canonical: bool = False,
    ) -> None:
        self._sketch = sketch
        self._builder = builder
        self._lg_k = lg_k
        self._seed = seed
        self._population = population
        self._canonical = canonical

    def _resolved(self) -> ds.compact_theta_sketch:
        """Fold staged updates in, canonicalise, and return the compact state.

        Two things happen here, and the second one is not obvious.

        *Lazy compaction.* Ingestion stages into an ``update_theta_sketch`` and compacts
        only when something reads, because compacting per item would make :meth:`update`
        quadratic -- and the graph sketch calls it three times per edge.

        *Canonicalisation.* A theta sketch has more than one representation of the same
        set. ``update_theta_sketch.compact()`` hands back everything it happens to be
        holding, which is up to ``2k`` entries with a correspondingly looser theta, while
        ``theta_union.get_result()`` trims to exactly ``k``. Both are valid and they
        estimate almost the same number, but they are different bytes -- so a freshly
        built sketch would not equal itself after a merge with the identity, and law 3
        would fail for reasons that have nothing to do with the merge being wrong.
        Everything is therefore pushed through a union on the way out, which is
        idempotent and gives one representation per set.

        Mutates the internal representation only; the logical value is unchanged, so a
        read may call this.
        """
        if self._builder is not None:
            staged = self._builder.compact(ordered=True)
            self._builder = None
            if self._sketch is None:
                self._sketch = staged
            else:
                self._sketch = self._union_of(self._sketch, staged)
            self._canonical = False
        if self._sketch is None:
            empty = ds.update_theta_sketch(lg_k=self._lg_k, seed=self._seed)
            self._sketch = empty.compact(ordered=True)
            self._canonical = False
        if not self._canonical:
            self._sketch = self._union_of(self._sketch)
            self._canonical = True
        return self._sketch

    def _union_of(self, *sketches: ds.compact_theta_sketch) -> ds.compact_theta_sketch:
        """Union some compact sketches into the canonical trimmed representation."""
        union = ds.theta_union(lg_k=self._lg_k, seed=self._seed)
        for sketch in sketches:
            union.update(sketch)
        return union.get_result(ordered=True)

    def update(self, key: str) -> None:
        """Observe one already-canonical key. Mutates in place; the ingestion path."""
        if self._builder is None:
            self._builder = ds.update_theta_sketch(lg_k=self._lg_k, seed=self._seed)
        self._builder.update(key)
        self._population += 1

    # -- construction -------------------------------------------------------------------

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """An empty Theta sketch. Merging it with anything returns that thing."""
        lg_k = _lg_k_of(params)
        seed = int(params.get("seed", DEFAULT_THETA_SEED))
        return cls(sketch=None, lg_k=lg_k, seed=seed, population=0)

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from observations. Nulls are not distinct values and are skipped."""
        lg_k = _lg_k_of(params)
        seed = int(params.get("seed", DEFAULT_THETA_SEED))
        sketch = cls(sketch=None, lg_k=lg_k, seed=seed, population=0)
        for item in items:
            key = canonical_item_key(item)
            if key is not None:
                sketch.update(key)
        return sketch

    @classmethod
    def from_iceberg_blob(
        cls, blob: bytes, *, seed: int = DEFAULT_THETA_SEED, population: int = 0
    ) -> Self:
        """Adopt an Iceberg ``apache-datasketches-theta-v1`` Puffin blob.

        Invariant 5, metadata first: when a table already carries an NDV sketch in its
        statistics file, reading it costs nothing and a distinct-count probe should
        never be scheduled. The blob is a serialised compact Theta sketch written with
        the DataSketches default seed; a table written with a different seed will fail
        to deserialise here rather than return a wrong number.

        ``population`` is the row count behind the blob when the caller knows it from
        the manifest, and 0 when it does not. It affects only the reported population,
        never the estimate.
        """
        try:
            adopted = ds.compact_theta_sketch.deserialize(blob, seed=seed)
        except Exception as exc:
            raise SketchDecodeError(
                f"not a readable {ICEBERG_THETA_BLOB_TYPE} blob under seed {seed}"
            ) from exc
        return cls(sketch=adopted, lg_k=_DEFAULT_LG_K, seed=seed, population=population)

    # -- identity -----------------------------------------------------------------------

    @property
    def params(self) -> Mapping[str, ParamValue]:
        """``lg_k`` and ``seed``. Both must match for two sketches to merge."""
        return {"lg_k": self._lg_k, "seed": self._seed}

    @property
    def population(self) -> int:
        """Rows fed in. Distinct from :meth:`estimate`, which counts distinct values."""
        return self._population

    # -- estimates ----------------------------------------------------------------------

    def estimate(self) -> float:
        """Estimated number of distinct values."""
        return float(self._resolved().get_estimate())

    def bounds(self, std_devs: int = 2) -> tuple[float, float]:
        """Lower and upper confidence bounds on :meth:`estimate`."""
        return (
            float(self._resolved().get_lower_bound(std_devs)),
            float(self._resolved().get_upper_bound(std_devs)),
        )

    def retained(self) -> int:
        """How many hashes the sketch is holding. A size diagnostic, not a statistic."""
        return int(self._resolved().num_retained)

    def is_membership_oracle(self) -> bool:
        """True when this sketch's domain is small enough to enumerate.

        See the module docstring. A caller that is about to let an envelope cross to the
        control plane should ask this and route through the gate when the answer is yes.
        """
        return self.estimate() <= _MEMBERSHIP_ORACLE_CARDINALITY

    def error_bound(self) -> ErrorBound:
        """Relative standard error, a function of ``lg_k`` alone.

        Theta's RSE is approximately ``1/sqrt(k)`` for ``k = 2**lg_k``. Below ``k``
        distinct values the sketch is exact and says so, which matters because a
        detector comparing two small populations should not be told they carry 1.6%
        error when they carry none.
        """
        if not self._resolved().is_estimation_mode():
            return ErrorBound(
                kind="exact",
                note="below k distinct values Theta retains every hash and is exact",
            )
        k = float(2**self._lg_k)
        return ErrorBound(
            kind="relative",
            epsilon=1.0 / (k**0.5),
            confidence=0.6827,
            note=f"relative standard error 1/sqrt(k), k=2^{self._lg_k}, one standard deviation",
        )

    # -- the monoid ---------------------------------------------------------------------

    def merge(self, other: Self) -> Self:
        """Union two Theta sketches.

        Exactly associative and commutative: the union retains the k smallest hashes of
        the combined input, which is a pure function of that input and cannot depend on
        the order the parts arrived in.
        """
        self.require_mergeable(other)
        return type(self)(
            sketch=self._union_of(self._resolved(), other._resolved()),
            lg_k=self._lg_k,
            seed=self._seed,
            population=self._population + other._population,
            canonical=True,
        )

    # -- serialisation -------------------------------------------------------------------

    def encode(self) -> bytes:
        """Container, then ``lg_k``, ``seed``, ``population`` and the DataSketches bytes."""
        inner = bytes(self._resolved().serialize())
        body = b"".join(
            (
                self._lg_k.to_bytes(1, "big"),
                self._seed.to_bytes(8, "big"),
                self._population.to_bytes(8, "big"),
                len(inner).to_bytes(4, "big"),
                inner,
            )
        )
        return encode_container(codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=body)

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        offset = header.body_offset
        raw_lg_k, offset = read_exact(payload, offset, 1)
        raw_seed, offset = read_exact(payload, offset, 8)
        raw_population, offset = read_exact(payload, offset, 8)
        raw_length, offset = read_exact(payload, offset, 4)
        inner, offset = read_exact(payload, offset, int.from_bytes(raw_length, "big"))
        seed = int.from_bytes(raw_seed, "big")
        return cls(
            sketch=ds.compact_theta_sketch.deserialize(inner, seed=seed),
            lg_k=int.from_bytes(raw_lg_k, "big"),
            seed=seed,
            population=int.from_bytes(raw_population, "big"),
            canonical=True,
        )
