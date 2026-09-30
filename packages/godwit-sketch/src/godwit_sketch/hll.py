"""Distinct counting, small: :class:`HllCount`, a dense HyperLogLog written here.

WHY THIS IS NOT A WRAPPER EITHER
--------------------------------
The same reason as :mod:`godwit_sketch.quantile`, arrived at from a different direction.
The DataSketches HLL binding *is* deterministic -- it was measured, and unlike KLL it
reproduces byte for byte across runs. What it is not is **canonical**: below a few
hundred distinct values it stores a coupon list rather than dense registers, and that
list is in insertion order. So two sketches holding exactly the same set serialise to
different bytes depending on the order they saw it, and:

    ``a.merge(b)`` and ``b.merge(a)`` give the same estimate and different bytes.

Measured on ``datasketches==5.2.0``: two single-item sketches unioned both ways give
identical estimates (2.000000004967054) and different serialisations. Above the sparse
threshold the dense representation takes over and the problem disappears, which is
exactly why it would have survived a test suite built on realistic volumes and then
appeared in production on a quiet partition.

That is fatal to the guarantee this package exists to make. The time hierarchy folds a
window's contributions to get one artifact, and if the bytes depend on arrival order
then batch and streaming produce different artifacts for the same data -- the divergence
this package is the guard against.

A dense HLL has no sparse mode and therefore no representation problem. Registers hold a
maximum, maximum is associative and commutative, and the register array is the whole
state. Every law holds exactly, by construction rather than by luck.

The cost is memory on tiny inputs: this always allocates ``2**lg_k`` register bytes,
where the sparse form would have used a handful. At the default ``lg_k=12`` that is 4 KB
per sketch regardless of population, and the serialised form varint-compresses the long
runs of zero registers that a small population leaves behind. That trade is documented
in the memory benchmark in ``docs/packages/godwit-sketch.md``.

One register per byte, rather than the 4- or 6-bit packing the name ``HLL_4`` implies.
Packing would save three quarters of the memory and cost a bit-fiddling routine that
would have to be exactly right on the merge path. A byte per register is boring, and
boring is what someone wants at 3am. The varint encoding recovers most of the size on
the wire, which is where it actually matters -- envelopes are stored and copied, live
sketches are transient.

DISCLOSURE
----------
Holds no row value: a register is the maximum leading-zero count of a hash, which is a
derived statistic. The membership-oracle caveat in :mod:`godwit_sketch.distinct` applies
here too -- over a small domain, anyone holding the envelope can hash a guess and see
whether it moved a register.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from typing import ClassVar, Final, Self

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

__all__ = ["HllCount"]

_DEFAULT_LG_K: Final[int] = 12
_MIN_LG_K: Final[int] = 4
_MAX_LG_K: Final[int] = 18
_HASH_BITS: Final[int] = 64
_MAX_RUN: Final[int] = 0xFFFF
"""Longest run the two-byte run-length marker can express."""

_ALPHA: Final[dict[int, float]] = {4: 0.673, 5: 0.697, 6: 0.709}
"""Bias constants for small register counts. Above 64 registers the formula below applies."""


def _alpha(m: int) -> float:
    """The HyperLogLog bias constant for ``m`` registers."""
    bits = m.bit_length() - 1
    if bits in _ALPHA:
        return _ALPHA[bits]
    return 0.7213 / (1.0 + 1.079 / m)


@register
class HllCount(BaseSketch):
    """Dense HyperLogLog. Smaller than Theta, no set difference, exactly mergeable.

    Parameters: ``lg_k`` (log2 of the register count, default 12) and ``seed`` (keys the
    hash). Both must match for two sketches to merge: registers from two different hash
    functions describe two different partitions of the value space, and taking their
    elementwise maximum would produce a confident wrong number.

    Reach for :class:`~godwit_sketch.distinct.ThetaNdv` instead when a detector needs set
    operations -- "which entities are here and were not in the last snapshot" is a set
    difference, and no HLL can answer it.
    """

    KIND: ClassVar[SketchKind] = SketchKind.HLL
    CODEC: ClassVar[str] = "godwit-hll-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = False
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.EXACT
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.CATEGORICAL
    ACQUISITION: ClassVar[Acquisition] = Acquisition.SKETCH_SUMMARY
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DERIVED_STATISTIC

    __slots__ = ("_lg_k", "_population", "_registers", "_seed")

    def __init__(self, *, lg_k: int, seed: int, registers: bytearray, population: int) -> None:
        self._lg_k = lg_k
        self._seed = seed
        self._registers = registers
        self._population = population

    # -- construction -------------------------------------------------------------------

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """All registers zero. Merging it with anything returns that thing."""
        lg_k, seed = cls._params_of(params)
        return cls(lg_k=lg_k, seed=seed, registers=bytearray(1 << lg_k), population=0)

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from observations. Nulls are not distinct values and are skipped."""
        sketch = cls.identity(params)
        for item in items:
            key = canonical_item_key(item)
            if key is not None:
                sketch.update(key)
        return sketch

    @staticmethod
    def _params_of(params: Mapping[str, ParamValue]) -> tuple[int, int]:
        lg_k = int(params.get("lg_k", _DEFAULT_LG_K))
        if not _MIN_LG_K <= lg_k <= _MAX_LG_K:
            raise ValueError(f"lg_k must be {_MIN_LG_K}..{_MAX_LG_K}, got {lg_k}")
        return lg_k, int(params.get("seed", 0))

    # -- ingestion ----------------------------------------------------------------------

    def update(self, key: str) -> None:
        """Observe one already-canonical key. Mutates in place; the ingestion path."""
        digest = hashlib.blake2b(
            key.encode("utf-8"), key=self._seed.to_bytes(8, "big", signed=True), digest_size=8
        ).digest()
        value = int.from_bytes(digest, "big")
        index = value >> (_HASH_BITS - self._lg_k)
        remainder = (value << self._lg_k) & ((1 << _HASH_BITS) - 1)
        # Rank is the position of the first set bit in what is left, counting from 1.
        # An all-zero remainder means every bit was zero, which is the maximum rank.
        if remainder == 0:
            rank = _HASH_BITS - self._lg_k + 1
        else:
            rank = _HASH_BITS - remainder.bit_length() + 1
        self._registers[index] = max(self._registers[index], rank)
        self._population += 1

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
        """Estimated number of distinct values.

        Linear counting while registers are still empty, the HyperLogLog harmonic-mean
        estimator once they are not. The switch is the standard small-range correction:
        raw HLL is badly biased low when most registers have never been touched, which
        is exactly the regime a per-hour probe on a quiet column lives in.
        """
        m = len(self._registers)
        zeros = self._registers.count(0)
        if zeros:
            return m * math.log(m / zeros)
        harmonic = sum(2.0**-register for register in self._registers)
        return _alpha(m) * m * m / harmonic

    def bounds(self, std_devs: int = 2) -> tuple[float, float]:
        """Confidence bounds from the relative standard error. Never negative."""
        estimate = self.estimate()
        spread = std_devs * self._relative_error() * estimate
        return max(0.0, estimate - spread), estimate + spread

    def _relative_error(self) -> float:
        return 1.04 / math.sqrt(len(self._registers))

    def retained(self) -> int:
        """Registers that have been touched. A size diagnostic, not a statistic."""
        return len(self._registers) - self._registers.count(0)

    def error_bound(self) -> ErrorBound:
        """Relative standard error ``1.04/sqrt(m)``, a function of ``lg_k`` alone."""
        return ErrorBound(
            kind="relative",
            epsilon=self._relative_error(),
            confidence=0.6827,
            note=f"relative standard error 1.04/sqrt(m), m=2^{self._lg_k} registers, "
            "one standard deviation",
        )

    # -- the monoid ---------------------------------------------------------------------

    def merge(self, other: Self) -> Self:
        """Elementwise maximum of the registers.

        Exactly associative and commutative, and byte-canonical with it: the register
        array is the entire state, and maximum does not care what order it sees things.
        """
        self.require_mergeable(other)
        return type(self)(
            lg_k=self._lg_k,
            seed=self._seed,
            registers=bytearray(
                max(left, right)
                for left, right in zip(self._registers, other._registers, strict=True)
            ),
            population=self._population + other._population,
        )

    # -- serialisation -------------------------------------------------------------------

    def encode(self) -> bytes:
        """Header then the registers, run-length encoded over zeros.

        A sketch that has seen a hundred values leaves nearly every one of its 4096
        registers at zero, and an envelope is stored and copied for every probe of every
        column of every snapshot. Runs of zeros are the one thing worth compressing here,
        and a two-byte run marker does it without pulling in a compressor whose output
        would have to be pinned for determinism.
        """
        body = bytearray()
        body += self._lg_k.to_bytes(1, "big")
        body += self._seed.to_bytes(8, "big", signed=True)
        body += self._population.to_bytes(8, "big")
        runs = bytearray()
        index = 0
        size = len(self._registers)
        while index < size:
            value = self._registers[index]
            run = 1
            while index + run < size and self._registers[index + run] == value and run < _MAX_RUN:
                run += 1
            runs += value.to_bytes(1, "big")
            runs += run.to_bytes(2, "big")
            index += run
        body += (len(runs) // 3).to_bytes(4, "big")
        body += runs
        return encode_container(
            codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=bytes(body)
        )

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        offset = header.body_offset
        raw, offset = read_exact(payload, offset, 1)
        lg_k = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 8)
        seed = int.from_bytes(raw, "big", signed=True)
        raw, offset = read_exact(payload, offset, 8)
        population = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 4)
        run_count = int.from_bytes(raw, "big")
        registers = bytearray()
        expected = 1 << lg_k
        for _ in range(run_count):
            raw, offset = read_exact(payload, offset, 1)
            value = raw[0]
            raw, offset = read_exact(payload, offset, 2)
            registers += bytes([value]) * int.from_bytes(raw, "big")
            if len(registers) > expected:
                raise SketchDecodeError("HLL payload declares more registers than lg_k allows")
        if len(registers) != expected:
            raise SketchDecodeError(
                f"HLL payload holds {len(registers)} registers, expected {expected}"
            )
        return cls(lg_k=lg_k, seed=seed, registers=registers, population=population)
