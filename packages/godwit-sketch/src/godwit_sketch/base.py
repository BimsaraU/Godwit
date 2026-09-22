"""The sketch base class and the registry that holds every kind to the monoid laws.

READ THIS BEFORE ADDING A SKETCH.

Invariant 6 says every sketch is a mergeable monoid. That claim is only worth anything
if it is enforced mechanically, so this module is built so that a non-compliant sketch
is *structurally* hard to add rather than merely discouraged:

1. A sketch class is unusable until :func:`register` accepts it. ``register`` rejects a
   class that omits any of the declaration class-vars below, that reuses a codec, or
   that fails to implement the abstract surface.
2. ``register`` records the class in :data:`SKETCH_REGISTRY`. The property suite in
   ``tests/test_monoid_laws.py`` iterates that registry, so a newly registered sketch is
   subjected to the associativity, commutativity, identity and merge-order tests without
   anyone remembering to wire it up. Forgetting the tests is not an available mistake;
   the only way to dodge them is to not register, and an unregistered sketch cannot be
   decoded by :func:`decode_envelope` and so cannot cross a package boundary.
3. :attr:`BaseSketch.ITEM_FLAVOUR` tells the suite what to feed the class, which is what
   lets the suite be universal instead of per-kind.

MERGE EXACTNESS -- the thing most likely to surprise you
--------------------------------------------------------
The ``Sketch`` protocol states law 1 as ``a.merge(b).merge(c) == a.merge(b.merge(c))``,
exact equality. That is achievable for the additive and idempotent kinds, and it is
**provably impossible** for any *bounded lossy* summary: once an intermediate merge has
discarded information to stay inside its size bound, a later merge cannot recover it,
and a different bracketing discards different information. Quantile sketches and bounded
heavy-hitter summaries are in this class.

So every sketch declares :attr:`MERGE_EXACTNESS`:

``MergeExactness.EXACT``
    Law 1 holds as written, byte for byte. Theta, HLL, Moments, NullRate, the Count-Min
    matrix and an exact category histogram are all in this class.
``MergeExactness.BOUNDED``
    Law 1 holds for the *estimate*, within the sketch's documented error bound. The
    internal state may differ between bracketings.

The property suite applies the exact test to EXACT kinds and the within-bound test to
BOUNDED ones. See ``docs/change-requests/CR-A2-monoid-law-exactness.md`` -- the law as
written cannot be met by the kinds the brief requires, and this is the smallest honest
reading of it.

None of this weakens what the layer above actually needs. Batch and streaming agree
because :class:`~godwit_sketch.hierarchy.TimeHierarchy` folds in a **canonical order**,
not because merge is order-free. See that module.
"""

from __future__ import annotations

import abc
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import ClassVar, Final, Self

from godwit_contracts.common import (
    ContentHash,
    GodwitModel,
    Instant,
    ProbeKey,
    SnapshotId,
    SourceId,
)
from godwit_contracts.sketch import ErrorBound, SketchEnvelope, SketchKind
from godwit_contracts.taint import Acquisition, Provenance, Sensitivity

from godwit_sketch.codec import payload_digest, producer_fingerprint
from godwit_sketch.errors import (
    IncompatibleMergeError,
    SketchRegistryError,
    UnsupportedCodecError,
)

__all__ = [
    "SKETCH_REGISTRY",
    "BaseSketch",
    "ItemFlavour",
    "MergeExactness",
    "ParamValue",
    "SketchContext",
    "SketchItem",
    "decode_envelope",
    "register",
    "registered_sketches",
]

type ParamValue = int | float | str | bool
"""A construction parameter. Ours, never a row value -- see ``SketchEnvelope.params``."""

type SketchItem = float | str | tuple[str, str] | None
"""One observation, in the widest form any sketch here accepts.

``None`` is a null (NullRate counts them, everything else ignores them), a ``tuple`` is
a directed edge for :class:`~godwit_sketch.graph.GraphDegree`, and the scalars are
numeric or categorical observations. The union exists so the property suite can drive
every registered kind through one code path.
"""


class MergeExactness(StrEnum):
    """Whether ``merge`` satisfies contract law 1 exactly or only within its bound."""

    EXACT = "exact"
    """``a.merge(b).merge(c)`` equals ``a.merge(b.merge(c))`` in full internal state."""

    BOUNDED = "bounded"
    """The two bracketings agree on the estimate within the documented error bound.

    Not a licence to be sloppy: the merge is still deterministic, still commutative in
    its estimate, and still byte-identical for a fixed fold order.
    """


class ItemFlavour(StrEnum):
    """What kind of observation a sketch consumes. Drives the universal property suite."""

    NUMERIC = "numeric"
    CATEGORICAL = "categorical"
    EDGE = "edge"


class SketchContext(GodwitModel):
    """The run context an envelope needs and a sketch has no business holding.

    A sketch is a pure summary: it knows its items, not which probe run produced it.
    But :class:`~godwit_contracts.sketch.SketchEnvelope` requires ``source_id``,
    ``snapshot_id``, ``produced_for`` and ``produced_at``, so something must supply them
    at serialisation time. Holding them *inside* the sketch would be worse: two sketches
    from two data files of the same snapshot would then differ in fields that have
    nothing to do with their contents, and merge would have to invent a reconciliation
    rule for run metadata.

    The ``Sketch`` protocol declares ``serialise(self)`` with no arguments, which cannot
    construct a valid envelope. See
    ``docs/change-requests/CR-A2-serialise-needs-context.md``.
    """

    source_id: SourceId
    snapshot_id: SnapshotId
    produced_for: ProbeKey
    produced_at: Instant
    table: str | None = None
    column: str | None = None


SKETCH_REGISTRY: Final[dict[str, type[BaseSketch]]] = {}
"""Every compliant sketch class, keyed by codec identifier.

Keyed by *codec*, not by ``SketchKind``, and that is deliberate. The contract's
``SketchKind`` vocabulary is closed and has no member for Moments, NullRate, category
histograms or graph degree, so several classes here share a kind and are told apart by
their codec. See ``docs/change-requests/CR-A2-sketch-kind-vocabulary.md``.
"""

_REQUIRED_CLASS_VARS: Final[tuple[str, ...]] = (
    "KIND",
    "CODEC",
    "SCHEMA_VERSION",
    "VALUE_BEARING",
    "MERGE_EXACTNESS",
    "ITEM_FLAVOUR",
    "ACQUISITION",
)

_REQUIRED_METHODS: Final[tuple[str, ...]] = (
    "merge",
    "encode",
    "_decode_body",
    "identity",
    "from_items",
    "error_bound",
)


def register[S: "BaseSketch"](cls: type[S]) -> type[S]:
    """Admit a sketch class to the registry, or refuse it.

    Refusal is the point. A class that reaches ``SKETCH_REGISTRY`` has declared its
    kind, codec, value-bearing status and merge exactness, and will be swept up by the
    property suite on the next test run.
    """
    if abc.ABC in cls.__bases__:
        raise SketchRegistryError(f"{cls.__name__} is abstract and cannot be registered")
    for name in _REQUIRED_CLASS_VARS:
        if getattr(cls, name, None) is None:
            raise SketchRegistryError(
                f"{cls.__name__} must declare {name} before it can be registered; "
                "see godwit_sketch.base for what each declaration means"
            )
    missing = sorted(
        name
        for name in _REQUIRED_METHODS
        if getattr(cls, name, None) is getattr(BaseSketch, name, None)
    )
    if missing:
        raise SketchRegistryError(f"{cls.__name__} does not implement {missing}")
    if cls.CODEC in SKETCH_REGISTRY:
        clash = SKETCH_REGISTRY[cls.CODEC].__name__
        raise SketchRegistryError(
            f"codec {cls.CODEC!r} is already registered to {clash}; codecs are the "
            "identity of a stored payload and must be unique"
        )
    SKETCH_REGISTRY[cls.CODEC] = cls
    return cls


def registered_sketches() -> tuple[type[BaseSketch], ...]:
    """Every registered class, in codec order. Deterministic, so tests are stable."""
    return tuple(SKETCH_REGISTRY[codec] for codec in sorted(SKETCH_REGISTRY))


def decode_envelope(envelope: SketchEnvelope) -> BaseSketch:
    """Rebuild whichever sketch wrote this envelope, dispatching on ``codec``."""
    cls = SKETCH_REGISTRY.get(envelope.codec)
    if cls is None:
        raise UnsupportedCodecError(
            f"no registered sketch reads codec {envelope.codec!r}; "
            f"this build knows {sorted(SKETCH_REGISTRY)}"
        )
    return cls.decode(envelope)


class BaseSketch(abc.ABC):
    """A mergeable summary. Implements the ``Sketch`` protocol from the contracts.

    Subclasses implement :meth:`merge`, :meth:`encode`, :meth:`_decode_body`,
    :meth:`identity`, :meth:`from_items` and :meth:`error_bound`, and declare the
    class-vars listed in :data:`_REQUIRED_CLASS_VARS`.
    """

    KIND: ClassVar[SketchKind]
    """The contract kind this serialises as. Several classes share one; see the registry."""

    CODEC: ClassVar[str]
    """Unique codec identifier. The real discriminator for stored payloads."""

    SCHEMA_VERSION: ClassVar[int]
    """Body version. Bump when the byte layout changes; never reuse a number."""

    VALUE_BEARING: ClassVar[bool]
    """True when the serialised state contains values taken from customer rows.

    A value-bearing sketch may expose its stored items ONLY as
    :class:`~godwit_contracts.taint.Tainted`. There is no plain-``str`` accessor on any
    such class, and ``tests/test_no_plain_value_path.py`` asserts that by inspecting the
    public API rather than by trusting the author.
    """

    MERGE_EXACTNESS: ClassVar[MergeExactness]
    """Whether contract law 1 holds exactly or within the error bound. See module docs."""

    ITEM_FLAVOUR: ClassVar[ItemFlavour]
    """What :meth:`from_items` expects. Drives the universal property suite."""

    ACQUISITION: ClassVar[Acquisition]
    """How the state was obtained. Sets the taint floor for everything this emits."""

    SENSITIVITY: ClassVar[Sensitivity | None] = None
    """Fixed sensitivity, when it does not depend on the data.

    ``None`` means the class computes it in :attr:`sensitivity`.
    """

    # -- identity ----------------------------------------------------------------------

    @property
    @abc.abstractmethod
    def params(self) -> Mapping[str, ParamValue]:
        """Construction parameters. Two sketches merge only if these match exactly."""

    @property
    def kind(self) -> SketchKind:
        """Which contract kind this serialises as."""
        return self.KIND

    @property
    @abc.abstractmethod
    def population(self) -> int:
        """Items fed in so far. Contract law 7: merging sums it."""

    @property
    def sensitivity(self) -> Sensitivity:
        """Taint class of this sketch's serialised state.

        Declaring a sketch *more* restricted than its acquisition floor is always
        allowed; declaring it less is a validation error in the envelope.
        """
        if self.SENSITIVITY is None:
            raise NotImplementedError(f"{type(self).__name__} must override `sensitivity`")
        return self.SENSITIVITY

    @property
    def fingerprint(self) -> ContentHash:
        """Deterministic producer identity. Equal fingerprints mean mergeable."""
        return producer_fingerprint(
            codec=self.CODEC,
            schema_version=self.SCHEMA_VERSION,
            params=dict(self.params),
        )

    # -- the monoid ---------------------------------------------------------------------

    @abc.abstractmethod
    def merge(self, other: Self) -> Self:
        """Combine two sketches into a new one. Never mutates either operand.

        Must raise :class:`IncompatibleMergeError` when ``other`` was built with
        different parameters -- contract law 4. Use :meth:`require_mergeable`.
        """

    @classmethod
    @abc.abstractmethod
    def identity(cls, params: Mapping[str, ParamValue]) -> Self:
        """The empty sketch for these parameters."""

    @classmethod
    @abc.abstractmethod
    def from_items(cls, items: Sequence[SketchItem], params: Mapping[str, ParamValue]) -> Self:
        """Build from observations. The universal property suite's entry point."""

    @abc.abstractmethod
    def error_bound(self) -> ErrorBound:
        """The documented accuracy at the current size.

        Contract law 6: a function of the construction parameters and the item count,
        never of the data itself.
        """

    def require_mergeable(self, other: Self) -> None:
        """Refuse a merge across differing parameters. Contract law 4."""
        if type(self) is not type(other):
            raise IncompatibleMergeError(
                f"cannot merge {type(self).__name__} with {type(other).__name__}"
            )
        if self.fingerprint != other.fingerprint:
            raise IncompatibleMergeError(
                f"{type(self).__name__} parameters differ ({dict(self.params)} vs "
                f"{dict(other.params)}); merging them would silently give a wrong answer"
            )

    # -- serialisation -------------------------------------------------------------------

    @abc.abstractmethod
    def encode(self) -> bytes:
        """The framed payload. Deterministic: equal state gives equal bytes."""

    @classmethod
    @abc.abstractmethod
    def _decode_body(cls, payload: bytes) -> Self:
        """Parse a framed payload this class wrote. Called by :meth:`decode`."""

    def provenance(self, context: SketchContext | None = None) -> Provenance:
        """Where this sketch's state came from."""
        return Provenance(
            acquisition=self.ACQUISITION,
            source_id=str(context.source_id) if context else None,
            table=context.table if context else None,
            column=context.column if context else None,
            snapshot_id=str(context.snapshot_id) if context else None,
        )

    def serialise(self, context: SketchContext | None = None) -> SketchEnvelope:
        """Encode to a storable envelope tagged with the correct sensitivity.

        ``context`` is required in practice. It carries a default of ``None`` only so
        that the zero-argument shape declared by the ``Sketch`` protocol remains
        callable; calling it that way raises, because an envelope without a snapshot is
        not a thing that can be stored or replayed. See :class:`SketchContext`.
        """
        if context is None:
            raise ValueError(
                f"{type(self).__name__}.serialise() needs a SketchContext: an envelope "
                "carries source_id, snapshot_id, produced_for and produced_at, none of "
                "which a sketch knows. See CR-A2-serialise-needs-context."
            )
        payload = self.encode()
        return SketchEnvelope(
            kind=self.KIND,
            codec=self.CODEC,
            schema_version=self.SCHEMA_VERSION,
            payload=payload,
            payload_digest=payload_digest(payload),
            sensitivity=self.sensitivity,
            provenance=self.provenance(context),
            population=self.population,
            error_bound=self.error_bound(),
            params=dict(self.params),
            source_id=context.source_id,
            snapshot_id=context.snapshot_id,
            produced_for=context.produced_for,
            produced_at=context.produced_at,
        )

    @classmethod
    def decode(cls, envelope: SketchEnvelope) -> Self:
        """Rebuild from an envelope, checking the envelope agrees with the payload."""
        if envelope.codec != cls.CODEC:
            raise UnsupportedCodecError(
                f"{cls.__name__} reads codec {cls.CODEC!r}, envelope carries {envelope.codec!r}"
            )
        if payload_digest(envelope.payload) != envelope.payload_digest:
            raise ValueError(
                f"payload digest mismatch on a {cls.CODEC} envelope: the bytes are not "
                "the bytes that were written"
            )
        return cls._decode_body(envelope.payload)

    # -- equality ------------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        """Structural equality by encoded bytes. The property suite's notion of ``==``."""
        if not isinstance(other, BaseSketch):
            return NotImplemented
        return self.CODEC == other.CODEC and self.encode() == other.encode()

    def __hash__(self) -> int:
        return hash((self.CODEC, self.encode()))

    def __repr__(self) -> str:
        """Never renders stored items: a value-bearing sketch must not leak via a log line."""
        return f"<{type(self).__name__} n={self.population} params={dict(self.params)}>"
