"""Frequency: :class:`CountMinHeavy` and :class:`CategoryHistogram`.

Both are **item-bearing**. Their state contains keys taken from customer rows, and on an
identifier column the heavy hitters *are* the PII: the top values of ``device_id`` are
real device ids, and they are also the single strongest organised-fraud signal in the
product. That is why identifiers are OPAQUE by default rather than excluded -- see
:mod:`godwit_sketch.items`.

The consequence for this module is narrow and absolute: **there is no plain-string path
to a stored key.** :meth:`CountMinHeavy.heavy_hitters` returns
:class:`~godwit_contracts.taint.Tainted` values and so does every other accessor that
can reach a key. ``tests/test_no_plain_value_path.py`` proves it by inspecting the
public surface of every value-bearing class, rather than by trusting this paragraph.
``__repr__`` renders counts and parameters only.

Counts are a different matter. A frequency is an aggregate over rows and is a derived
statistic; it is the *key* that is the row value. So :meth:`CountMinHeavy.estimate`
takes a key from the caller and returns a plain ``int``: the caller already holds the
key, and handing back a tainted integer would only teach people that the taint is noise.

WHY MISRA-GRIES AND NOT A TOP-K HEAP
------------------------------------
The brief asks for a bounded heavy-hitter heap. A plain "keep the top *k* by count" heap
does not survive merging: two heaps that each dropped a different key can produce a
merged heap missing a key that is genuinely in the global top *k*, with no bound on how
wrong the result is. The bounded structure here is a Misra-Gries summary, whose merge
has a published error bound (Agarwal et al., *Mergeable Summaries*): union the counters,
and if more than ``capacity`` survive, subtract the ``(capacity+1)``-th largest count
from all of them and drop whatever reaches zero. The total subtracted is carried in
:meth:`CountMinHeavy.underestimate` so a caller can say how far off a count may be.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import ClassVar, Final, Self

from godwit_contracts.sketch import ErrorBound, SketchKind
from godwit_contracts.taint import Acquisition, Sensitivity, Tainted, data_value

from godwit_sketch.base import (
    BaseSketch,
    ItemFlavour,
    MergeExactness,
    ParamValue,
    SketchItem,
    register,
)
from godwit_sketch.codec import decode_header, encode_container, read_exact
from godwit_sketch.errors import GodwitSketchError, SketchDecodeError
from godwit_sketch.items import KeyHasher, canonical_item_key
from godwit_sketch.varint import decode_varints, encode_varints

__all__ = [
    "DEFAULT_CM_CAPACITY",
    "DEFAULT_CM_DEPTH",
    "DEFAULT_CM_WIDTH",
    "DEFAULT_EXACT_CARDINALITY",
    "CategoryHistogram",
    "CountMinHeavy",
    "HistogramRegime",
]

DEFAULT_CM_WIDTH: Final[int] = 2718
"""Columns per row. ``e/width`` is the frequency over-estimate, so this gives 0.001 N."""

DEFAULT_CM_DEPTH: Final[int] = 5
"""Rows. Failure probability is ``exp(-depth)``, so five rows gives about 0.7%."""

DEFAULT_CM_CAPACITY: Final[int] = 256
"""Misra-Gries counters retained. The number of candidate heavy hitters kept."""

DEFAULT_EXACT_CARDINALITY: Final[int] = 1024
"""Distinct categories a :class:`CategoryHistogram` holds exactly before degrading."""

_MAX_DEPTH: Final[int] = 8
"""One BLAKE2b digest is 64 bytes, which is eight independent 8-byte row hashes."""

_MAX_WIDTH: Final[int] = 1 << 24


def _matrix_positions(key: str, *, seed: int, width: int, depth: int) -> list[int]:
    """One column index per row, from a single keyed digest.

    Deriving all ``depth`` positions from one BLAKE2b call rather than ``depth`` calls
    is a real saving on a hot path, and the rows stay independent enough for the
    Count-Min bound because each takes a disjoint 8-byte slice of the digest.
    """
    digest = hashlib.blake2b(
        key.encode("utf-8"), key=seed.to_bytes(8, "big", signed=True), digest_size=8 * depth
    ).digest()
    return [int.from_bytes(digest[row * 8 : row * 8 + 8], "big") % width for row in range(depth)]


@register
class CountMinHeavy(BaseSketch):
    """Count-Min matrix plus a mergeable Misra-Gries heavy-hitter summary.

    Parameters: ``width``, ``depth``, ``seed``, ``capacity``, and the key-mode
    parameters from :class:`~godwit_sketch.items.KeyHasher` (``key_mode``, and for
    OPAQUE columns ``key_id`` and ``input_entropy_bits``). All of them must match for
    two sketches to merge -- a merge across different hash seeds or different keys would
    add up counters for unrelated cells and return a confident wrong number.
    """

    KIND: ClassVar[SketchKind] = SketchKind.COUNT_MIN
    CODEC: ClassVar[str] = "godwit-cm-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = True
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.BOUNDED
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.CATEGORICAL
    ACQUISITION: ClassVar[Acquisition] = Acquisition.COUNT_MIN_HEAVY_HITTER
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DATA_VALUE

    __slots__ = (
        "_capacity",
        "_counters",
        "_depth",
        "_hasher",
        "_matrix",
        "_n",
        "_seed",
        "_subtracted",
        "_width",
    )

    def __init__(
        self,
        *,
        width: int,
        depth: int,
        seed: int,
        capacity: int,
        hasher: KeyHasher,
        matrix: list[int],
        counters: dict[str, int],
        n: int,
        subtracted: int,
    ) -> None:
        self._width = width
        self._depth = depth
        self._seed = seed
        self._capacity = capacity
        self._hasher = hasher
        self._matrix = matrix
        self._counters = counters
        self._n = n
        self._subtracted = subtracted

    # -- construction -------------------------------------------------------------------

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """An all-zero matrix with no counters."""
        width, depth, seed, capacity = cls._params_of(params)
        return cls(
            width=width,
            depth=depth,
            seed=seed,
            capacity=capacity,
            hasher=KeyHasher.from_params(dict(params)),
            matrix=[0] * (width * depth),
            counters={},
            n=0,
            subtracted=0,
        )

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from observations. Nulls are not keys and are skipped."""
        sketch = cls.identity(params)
        for item in items:
            sketch.update(item)
        return sketch

    @staticmethod
    def _params_of(params: Mapping[str, ParamValue]) -> tuple[int, int, int, int]:
        width = int(params.get("width", DEFAULT_CM_WIDTH))
        depth = int(params.get("depth", DEFAULT_CM_DEPTH))
        seed = int(params.get("seed", 0))
        capacity = int(params.get("capacity", DEFAULT_CM_CAPACITY))
        if not 1 <= depth <= _MAX_DEPTH:
            raise ValueError(f"depth must be 1..{_MAX_DEPTH}, got {depth}")
        if not 1 <= width <= _MAX_WIDTH:
            raise ValueError(f"width must be 1..{_MAX_WIDTH}, got {width}")
        if capacity < 1:
            raise ValueError(f"capacity must be at least 1, got {capacity}")
        return width, depth, seed, capacity

    def with_hasher(self, hasher: KeyHasher) -> Self:
        """Return a copy that keys new observations with ``hasher``.

        A sketch decoded from an envelope knows the *identity* of its hasher but not its
        key, because the key never leaves the data plane. Re-supplying it is therefore a
        data-plane operation, and this is where it happens.
        """
        return type(self)(
            width=self._width,
            depth=self._depth,
            seed=self._seed,
            capacity=self._capacity,
            hasher=hasher,
            matrix=list(self._matrix),
            counters=dict(self._counters),
            n=self._n,
            subtracted=self._subtracted,
        )

    # -- ingestion ----------------------------------------------------------------------

    def update(self, item: SketchItem, count: int = 1) -> None:
        """Observe ``item`` ``count`` times. Mutates in place; the ingestion path.

        Canonicalises the item exactly as :meth:`estimate` does, so that building with
        one and querying with the other agree. They did not always: ``from_items`` used
        to canonicalise while ``update`` and ``estimate`` took raw strings, so a caller
        who built a sketch and then asked it about one of the very keys they had fed in
        got an answer of roughly zero -- and Count-Min's one hard guarantee is that it
        never under-counts. One keying path, applied at one place, is the fix.
        """
        key = canonical_item_key(item)
        if key is None:
            return
        self._update_canonical(key, count)

    def _update_canonical(self, key: str, count: int) -> None:
        """Observe an already-canonical key. The internal path, used by degradation."""
        stored = self._hasher.apply(key)
        for row, column in enumerate(
            _matrix_positions(stored, seed=self._seed, width=self._width, depth=self._depth)
        ):
            self._matrix[row * self._width + column] += count
        self._n += count
        self._counters[stored] = self._counters.get(stored, 0) + count
        if len(self._counters) > self._capacity:
            self._shrink_counters()

    def _shrink_counters(self) -> None:
        """Misra-Gries: subtract the first losing count from everyone, drop the zeros.

        Deterministic tie-breaking by key, so two workers that saw the same data in a
        different order shrink to the same summary rather than to two different ones.
        """
        ordered = sorted(self._counters.items(), key=lambda kv: (-kv[1], kv[0]))
        floor = ordered[self._capacity][1]
        self._subtracted += floor
        self._counters = {
            key: count - floor for key, count in ordered[: self._capacity] if count > floor
        }

    # -- identity -----------------------------------------------------------------------

    @property
    def params(self) -> Mapping[str, ParamValue]:
        """Matrix shape, seed, counter capacity and the key mode."""
        return {
            "width": self._width,
            "depth": self._depth,
            "seed": self._seed,
            "capacity": self._capacity,
            **self._hasher.params(),
        }

    @property
    def population(self) -> int:
        """Total observations counted."""
        return self._n

    # -- queries ------------------------------------------------------------------------

    def estimate(self, item: SketchItem) -> int:
        """Estimated frequency of ``item``. Never under-counts; over by at most ``e*N/width``.

        Takes the item in the same form :meth:`update` accepts and canonicalises it the
        same way, so building and querying cannot disagree about what a key is.

        Returns a plain ``int``: a frequency is an aggregate over rows. It is the *key*
        that is the row value, and the caller already holds that one, having just passed
        it in.
        """
        key = canonical_item_key(item)
        if key is None:
            return 0
        return self._raw_estimate(self._hasher.apply(key))

    def underestimate(self) -> int:
        """Most that the Misra-Gries counters may have lost, from all shrink steps.

        A heavy hitter whose true count is below this may be missing from
        :meth:`heavy_hitters` entirely. Report it next to any top-k list, or the list
        reads as exhaustive when it is not.
        """
        return self._subtracted

    def heavy_hitters(self, limit: int | None = None) -> tuple[tuple[Tainted[str], int], ...]:
        """Candidate heavy hitters, most frequent first, with Count-Min frequencies.

        Keys come back ``Tainted`` DATA_VALUE. On an identifier column they *are* the
        PII, whether the sketch is in plain or hashed mode: a keyed hash is a stable
        pseudonym, and only the gate in ``godwit-guard`` can issue a token. The
        ``population`` on each is the sketch's total, so small-cell rules downstream have
        the denominator they need.

        Ordering is by estimated count then by stored key, so it is stable across
        processes rather than dependent on dictionary insertion order.
        """
        ranked = sorted(
            ((key, self._raw_estimate(key)) for key in self._counters),
            key=lambda kv: (-kv[1], kv[0]),
        )
        if limit is not None:
            ranked = ranked[:limit]
        return tuple(
            (
                data_value(
                    key,
                    acquisition=Acquisition.COUNT_MIN_HEAVY_HITTER,
                    population=self._n,
                ),
                count,
            )
            for key, count in ranked
        )

    def _raw_estimate(self, stored_key: str) -> int:
        """Matrix estimate for an already-stored (already-hashed) key."""
        return min(
            self._matrix[row * self._width + column]
            for row, column in enumerate(
                _matrix_positions(stored_key, seed=self._seed, width=self._width, depth=self._depth)
            )
        )

    def error_bound(self) -> ErrorBound:
        """``e/width`` over-estimate, failing with probability ``exp(-depth)``."""
        return ErrorBound(
            kind="epsilon_delta",
            epsilon=math.e / self._width,
            delta=math.exp(-self._depth),
            note=f"frequency over-estimate at most e*N/width, width={self._width}, "
            f"depth={self._depth}; never under-counts",
        )

    # -- the monoid ---------------------------------------------------------------------

    def merge(self, other: Self) -> Self:
        """Add the matrices, union the counters.

        The matrix half is exactly associative and commutative: it is integer addition.
        The Misra-Gries half is not, and cannot be. Once a shrink has dropped a key to
        stay inside ``capacity``, a later merge cannot bring it back, and a different
        bracketing drops a different key. The counts agree within
        :meth:`underestimate`, which is exactly the Misra-Gries guarantee.
        """
        self.require_mergeable(other)
        matrix = [left + right for left, right in zip(self._matrix, other._matrix, strict=True)]
        counters = dict(self._counters)
        for key, count in other._counters.items():
            counters[key] = counters.get(key, 0) + count
        merged = type(self)(
            width=self._width,
            depth=self._depth,
            seed=self._seed,
            capacity=self._capacity,
            hasher=self._hasher,
            matrix=matrix,
            counters=counters,
            n=self._n + other._n,
            subtracted=self._subtracted + other._subtracted,
        )
        if len(merged._counters) > merged._capacity:
            merged._shrink_counters()
        return merged

    # -- serialisation -------------------------------------------------------------------

    def encode(self) -> bytes:
        """Varint matrix, then the counters in canonical key order."""
        keys = sorted(self._counters)
        head = [
            self._width.to_bytes(4, "big"),
            self._depth.to_bytes(1, "big"),
            self._seed.to_bytes(8, "big", signed=True),
            self._capacity.to_bytes(4, "big"),
            self._n.to_bytes(8, "big"),
            self._subtracted.to_bytes(8, "big"),
            encode_varints(self._matrix),
            len(keys).to_bytes(4, "big"),
        ]
        body = bytearray(b"".join(head))
        body += encode_varints([self._counters[key] for key in keys])
        for key in keys:
            raw = key.encode("utf-8")
            body += len(raw).to_bytes(4, "big")
            body += raw
        return encode_container(
            codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=bytes(body)
        )

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        header = decode_header(
            payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION
        )
        offset = header.body_offset
        raw, offset = read_exact(payload, offset, 4)
        width = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 1)
        depth = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 8)
        seed = int.from_bytes(raw, "big", signed=True)
        raw, offset = read_exact(payload, offset, 4)
        capacity = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 8)
        n = int.from_bytes(raw, "big")
        raw, offset = read_exact(payload, offset, 8)
        subtracted = int.from_bytes(raw, "big")
        if width * depth > _MAX_WIDTH * _MAX_DEPTH:
            raise SketchDecodeError("Count-Min payload declares an implausible matrix")
        matrix, offset = decode_varints(payload, offset, width * depth)
        raw, offset = read_exact(payload, offset, 4)
        count = int.from_bytes(raw, "big")
        counts, offset = decode_varints(payload, offset, count)
        counters: dict[str, int] = {}
        for index in range(count):
            raw, offset = read_exact(payload, offset, 4)
            key_bytes, offset = read_exact(payload, offset, int.from_bytes(raw, "big"))
            counters[key_bytes.decode("utf-8")] = counts[index]
        return cls(
            width=width,
            depth=depth,
            seed=seed,
            capacity=capacity,
            hasher=KeyHasher.plain(),
            matrix=matrix,
            counters=counters,
            n=n,
            subtracted=subtracted,
        )


class HistogramRegime(StrEnum):
    """Whether a :class:`CategoryHistogram` is still exact or has degraded."""

    EXACT = "exact"
    """Every category and count is held exactly. Below the cardinality threshold."""

    APPROXIMATE = "approximate"
    """Cardinality exceeded the threshold; counts come from a Count-Min sketch."""


@register
class CategoryHistogram(BaseSketch):
    """Exact category counts below a cardinality threshold, Count-Min above it.

    Low-cardinality columns -- ``status``, ``country``, ``channel`` -- are where segment
    divergence lives, and for those an exact histogram is both small and precise. The
    threshold exists because the same probe pointed at ``customer_id`` would otherwise
    try to hold one counter per customer. Crossing it degrades to
    :class:`CountMinHeavy` rather than failing, because a probe that dies on an
    unexpectedly high-cardinality column costs a scan and returns nothing.

    Parameters: ``max_exact_cardinality``, plus every :class:`CountMinHeavy` parameter,
    which the degraded form needs and which therefore has to be fixed up front.

    **The regime is recorded in the envelope by** :attr:`error_bound`: an exact
    histogram reports ``kind="exact"`` and a degraded one reports ``epsilon_delta``. A
    reader can tell which it has without decoding the payload, and the two forms still
    merge, which they could not do if the regime were part of the codec or the
    merge-identity parameters.

    Item-bearing in both regimes. Below the threshold the payload holds exact category
    labels, which are row values; above it, the heavy hitters are.
    """

    KIND: ClassVar[SketchKind] = SketchKind.FREQUENT_ITEMS
    CODEC: ClassVar[str] = "godwit-cathist-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = True
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.BOUNDED
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.CATEGORICAL
    ACQUISITION: ClassVar[Acquisition] = Acquisition.CATEGORY_HISTOGRAM
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DATA_VALUE

    __slots__ = ("_approx", "_exact", "_max_exact", "_n", "_params")

    def __init__(
        self,
        *,
        params: Mapping[str, ParamValue],
        exact: dict[str, int] | None,
        approx: CountMinHeavy | None,
        n: int,
    ) -> None:
        self._params = dict(params)
        self._max_exact = int(self._params.get("max_exact_cardinality", DEFAULT_EXACT_CARDINALITY))
        self._exact = exact
        self._approx = approx
        self._n = n

    @classmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """An empty histogram, in the exact regime."""
        merged = {"max_exact_cardinality": DEFAULT_EXACT_CARDINALITY, **dict(params)}
        return cls(params=merged, exact={}, approx=None, n=0)

    @classmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from observations. Nulls are skipped."""
        sketch = cls.identity(params)
        for item in items:
            sketch.update(item)
        return sketch

    @property
    def regime(self) -> HistogramRegime:
        """Which form this histogram is currently in."""
        return HistogramRegime.EXACT if self._exact is not None else HistogramRegime.APPROXIMATE

    def _degraded(self) -> CountMinHeavy:
        """The Count-Min this histogram degraded into, or raise.

        Exactly one of ``_exact`` and ``_approx`` is set, and every caller of this has
        already established which. A plain ``assert`` would say so more briefly and
        would also vanish under ``python -O``, taking the invariant with it -- so the
        check is a real branch that raises a real error.
        """
        if self._approx is None:
            raise GodwitSketchError(
                "category histogram is in the exact regime; there is no Count-Min to read"
            )
        return self._approx

    def update(self, item: SketchItem, count: int = 1) -> None:
        """Observe ``item``, degrading to Count-Min if the threshold is crossed.

        Canonicalises through the same path as :class:`CountMinHeavy`, so a histogram
        and a Count-Min built from the same column agree on what a key is -- and so a
        histogram that degrades mid-stream does not change its own keying halfway.
        """
        key = canonical_item_key(item)
        if key is None:
            return
        self._update_canonical(key, count)

    def _update_canonical(self, key: str, count: int) -> None:
        """Observe an already-canonical key."""
        self._n += count
        if self._exact is not None:
            self._exact[key] = self._exact.get(key, 0) + count
            if len(self._exact) > self._max_exact:
                self._degrade()
            return
        self._degraded()._update_canonical(key, count)

    def _degrade(self) -> None:
        """Move every exact count into a Count-Min sketch and drop the exact table."""
        approx = CountMinHeavy.identity(self._params)
        for key, count in sorted((self._exact or {}).items()):
            approx._update_canonical(key, count)
        self._approx = approx
        self._exact = None

    @property
    def params(self) -> Mapping[str, ParamValue]:
        """The threshold plus every Count-Min parameter the degraded form will need."""
        return dict(self._params)

    @property
    def population(self) -> int:
        """Total observations counted."""
        return self._n

    def categories(self) -> tuple[tuple[Tainted[str], int], ...]:
        """Category labels with counts, most frequent first. Labels are ``Tainted``.

        Below the threshold these are every category, exactly. Above it they are the
        Count-Min heavy hitters and the list is not exhaustive -- check :attr:`regime`
        before describing the output as complete.
        """
        if self._exact is None:
            return self._degraded().heavy_hitters()
        ranked = sorted(self._exact.items(), key=lambda kv: (-kv[1], kv[0]))
        return tuple(
            (
                data_value(
                    key,
                    acquisition=Acquisition.CATEGORY_HISTOGRAM,
                    population=self._n,
                ),
                count,
            )
            for key, count in ranked
        )

    def distinct_categories(self) -> int:
        """How many categories are held. Exact below the threshold, retained count above."""
        if self._exact is not None:
            return len(self._exact)
        return len(self._degraded().heavy_hitters())

    def error_bound(self) -> ErrorBound:
        """Exact below the threshold; the Count-Min bound above it. Records the regime."""
        if self._exact is not None:
            return ErrorBound(
                kind="exact",
                note=f"exact regime: every category held, under the "
                f"{self._max_exact}-category threshold",
            )
        bound = self._degraded().error_bound()
        return ErrorBound(
            kind=bound.kind,
            epsilon=bound.epsilon,
            delta=bound.delta,
            note=f"approximate regime: cardinality passed {self._max_exact}, "
            f"counts from Count-Min ({bound.note})",
        )

    def merge(self, other: Self) -> Self:
        """Merge two histograms, degrading if the union crosses the threshold.

        Exact plus exact stays exact while the union fits, and is exactly associative
        there. Anything involving an approximate operand is approximate, and inherits
        the Count-Min bound.
        """
        self.require_mergeable(other)
        if self._exact is not None and other._exact is not None:
            union = dict(self._exact)
            for key, count in other._exact.items():
                union[key] = union.get(key, 0) + count
            merged = type(self)(params=self._params, exact=union, approx=None, n=self._n + other._n)
            if len(union) > self._max_exact:
                merged._degrade()
            return merged
        left = self._as_approx()
        right = other._as_approx()
        return type(self)(
            params=self._params,
            exact=None,
            approx=left.merge(right),
            n=self._n + other._n,
        )

    def _as_approx(self) -> CountMinHeavy:
        """This histogram as a Count-Min sketch, degrading a copy if it is still exact."""
        if self._approx is not None:
            return self._approx
        approx = CountMinHeavy.identity(self._params)
        for key, count in sorted((self._exact or {}).items()):
            approx._update_canonical(key, count)
        return approx

    def encode(self) -> bytes:
        """Params, then a regime byte, then the exact table or the Count-Min payload.

        The full parameter mapping is written out even in the exact regime. It carries
        the Count-Min shape and key mode that a later :meth:`_degrade` will need, and it
        is what :attr:`fingerprint` is computed from -- a histogram that lost those on a
        round-trip would come back merge-incompatible with the one that wrote it.
        """
        body = bytearray()
        params_json = json.dumps(dict(self._params), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        body += len(params_json).to_bytes(4, "big")
        body += params_json
        body += self._n.to_bytes(8, "big")
        if self._exact is not None:
            keys = sorted(self._exact)
            body += b"\x00"
            body += len(keys).to_bytes(4, "big")
            body += encode_varints([self._exact[key] for key in keys])
            for key in keys:
                raw = key.encode("utf-8")
                body += len(raw).to_bytes(4, "big")
                body += raw
        else:
            inner = self._degraded().encode()
            body += b"\x01"
            body += len(inner).to_bytes(4, "big")
            body += inner
        return encode_container(
            codec=self.CODEC, schema_version=self.SCHEMA_VERSION, body=bytes(body)
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
        if not isinstance(params, dict):
            raise SketchDecodeError("category histogram parameters are not an object")
        raw, offset = read_exact(payload, offset, 8)
        n = int.from_bytes(raw, "big")
        flag, offset = read_exact(payload, offset, 1)
        if flag == b"\x00":
            raw, offset = read_exact(payload, offset, 4)
            count = int.from_bytes(raw, "big")
            counts, offset = decode_varints(payload, offset, count)
            exact: dict[str, int] = {}
            for index in range(count):
                raw, offset = read_exact(payload, offset, 4)
                key_bytes, offset = read_exact(payload, offset, int.from_bytes(raw, "big"))
                exact[key_bytes.decode("utf-8")] = counts[index]
            return cls(params=params, exact=exact, approx=None, n=n)
        raw, offset = read_exact(payload, offset, 4)
        inner, offset = read_exact(payload, offset, int.from_bytes(raw, "big"))
        return cls(
            params=params,
            exact=None,
            approx=CountMinHeavy._decode_body(inner),
            n=n,
        )
