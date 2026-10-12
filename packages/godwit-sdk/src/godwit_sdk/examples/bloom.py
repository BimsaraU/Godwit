"""Reference plugin 2: a Bloom-filter set-membership sketch. **DATA PLANE.**

TUTORIAL. Read this after ``docs/packages/godwit-sdk.md`` section 5. The interesting
part is not the Bloom filter -- it is the ``VALUE_BEARING = True`` line and why it is
there.

A Bloom filter stores bits, not items, so it *looks* safe: nothing in the payload is a
customer value. But anyone who holds the payload and knows the hash can ask "was
``aoife.brennan@northfield-bank.test`` in this column?" and get a correct "yes". The
hash parameters travel in the envelope, so everyone who holds it does know the hash. A
membership oracle over customer data discloses customer data, one guess at a time, and
a guess over a small space (a country, a status, a short name list) is an enumeration.
So this sketch declares itself value-bearing and DATA_VALUE, and its membership query
takes a ``Tainted`` value rather than a plain string.

The monoid is the easy part: merge is bitwise OR, which is exactly associative,
commutative and idempotent, with the all-zero filter as identity. ``MergeExactness.EXACT``.
Population (items fed, counting repeats) adds under merge.

Error bound: no false negatives; false positives with probability at most
``(1 - exp(-k n / m)) ** k`` for ``n`` distinct items. ``n`` is not known without the
items, so the bound uses the population -- an upper bound on ``n`` -- which keeps it a
function of the parameters and the item count only (contract law 6).
"""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Mapping, Sequence
from typing import ClassVar, Final, Self

from godwit_contracts.common import ScalarValue
from godwit_contracts.segment import canonical_scalar
from godwit_contracts.taint import Tainted
from godwit_sketch.base import ParamValue, SketchItem
from godwit_sketch.codec import decode_header, encode_container, read_exact

from godwit_sdk import (
    Acquisition,
    ErrorBound,
    ItemFlavour,
    MergeExactness,
    Sensitivity,
    SketchBase,
    SketchKind,
    sketch,
)

__all__ = ["BloomMembership"]

_BODY: Final[struct.Struct] = struct.Struct(">IIQQ")
"""bits, hashes, seed, population."""
_MIN_BITS: Final[int] = 64
_MAX_BITS: Final[int] = 1 << 24
_MAX_HASHES: Final[int] = 16


@sketch(
    name="bloom",
    namespace="examples",
    version="1.0.0",
    summary="Bloom-filter set membership. Value-bearing: it is a membership oracle.",
)
class BloomMembership(SketchBase):
    """``m`` bits, ``k`` hashes. Parameters: ``bits`` (a power of two), ``hashes``, ``seed``."""

    KIND: ClassVar[SketchKind] = SketchKind.THETA
    """Borrowed: the contract vocabulary has no membership kind (CR-A2-sketch-kind-vocabulary).
    The codec, not the kind, identifies the payload."""
    CODEC: ClassVar[str] = "examples-bloom-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = True
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DATA_VALUE
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.EXACT
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.CATEGORICAL
    ACQUISITION: ClassVar[Acquisition] = Acquisition.SKETCH_SUMMARY
    DEFAULT_PARAMS: ClassVar[Mapping[str, ParamValue]] = {"bits": 4096, "hashes": 4, "seed": 7}

    def __init__(self, *, bits: int, hashes: int, seed: int, population: int, array: bytes) -> None:
        self._bits = bits
        self._hashes = hashes
        self._seed = seed
        self._population = population
        self._array = array

    # -- construction --------------------------------------------------------------------

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        bits = int(params.get("bits", 4096))
        hashes = int(params.get("hashes", 4))
        seed = int(params.get("seed", 7))
        if bits < _MIN_BITS or bits > _MAX_BITS or bits & (bits - 1):
            raise ValueError(f"bits must be a power of two in {_MIN_BITS}..{_MAX_BITS}")
        if not 1 <= hashes <= _MAX_HASHES:
            raise ValueError(f"hashes must be 1..{_MAX_HASHES}")
        return cls(bits=bits, hashes=hashes, seed=seed, population=0, array=bytes(bits // 8))

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        built = cls.identity(params)
        array = bytearray(built._array)
        population = 0
        for item in items:
            if item is None or isinstance(item, tuple):
                continue
            population += 1
            for index in built._positions(item):
                array[index >> 3] |= 1 << (index & 7)
        return cls(
            bits=built._bits,
            hashes=built._hashes,
            seed=built._seed,
            population=population,
            array=bytes(array),
        )

    def _positions(self, item: ScalarValue) -> list[int]:
        # Double hashing over one keyed BLAKE2b digest of the item's canonical form.
        digest = hashlib.blake2b(
            canonical_scalar(item).encode("utf-8"),
            digest_size=16,
            key=self._seed.to_bytes(8, "big"),
        ).digest()
        first = int.from_bytes(digest[:8], "big")
        second = int.from_bytes(digest[8:], "big") | 1
        mask = self._bits - 1
        return [(first + i * second) & mask for i in range(self._hashes)]

    # -- the monoid ----------------------------------------------------------------------

    @property
    def params(self) -> Mapping[str, ParamValue]:
        return {"bits": self._bits, "hashes": self._hashes, "seed": self._seed}

    @property
    def population(self) -> int:
        return self._population

    def merge(self, other: Self) -> Self:
        return type(self)(
            bits=self._bits,
            hashes=self._hashes,
            seed=self._seed,
            population=self._population + other._population,
            array=bytes(x | y for x, y in zip(self._array, other._array, strict=True)),
        )

    def error_bound(self) -> ErrorBound:
        fpr = (1.0 - math.exp(-self._hashes * self._population / self._bits)) ** self._hashes
        return ErrorBound(
            kind="epsilon_delta",
            epsilon=0.0,
            delta=min(1.0, fpr),
            note="no false negatives; a false positive with probability at most delta, "
            "taking the population as an upper bound on distinct items",
        )

    def estimate(self) -> float:
        """Fraction of bits set. Exact under merge; used by nothing but the law checks."""
        ones = sum(bin(byte).count("1") for byte in self._array)
        return ones / self._bits

    # -- the query: takes a Tainted value, because the answer discloses it ---------------

    def might_contain(self, value: Tainted[ScalarValue]) -> bool:
        """True if ``value`` may have been fed in; False if it certainly was not.

        Data plane only. The answer is a statement about a customer value.
        """
        return all(self._array[i >> 3] & (1 << (i & 7)) for i in self._positions(value.reveal()))

    # -- serialisation -------------------------------------------------------------------

    def encode(self) -> bytes:
        body = _BODY.pack(self._bits, self._hashes, self._seed, self._population) + self._array
        return encode_container(codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=body)

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        raw, offset = read_exact(payload, header.body_offset, _BODY.size)
        bits, hashes, seed, population = _BODY.unpack(raw)
        array, _ = read_exact(payload, offset, bits // 8)
        return cls(bits=bits, hashes=hashes, seed=seed, population=population, array=array)
