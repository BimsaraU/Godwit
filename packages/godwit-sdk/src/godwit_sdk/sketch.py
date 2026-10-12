"""``@sketch``: a custom mergeable sketch, held to the monoid laws at registration. **DATA PLANE.**

A sketch is invariant 6 made concrete: ``merge`` is associative and commutative, there
is an identity, the error bound is documented. A sketch that breaks one of those laws
does not fail loudly -- it makes batch and streaming quietly disagree, months later, in
a way nobody can debug. So the decorator *runs* the laws before it admits the class:

* determinism -- the same items give the same bytes;
* commutativity and associativity -- exactly (byte-identical state) for
  ``MergeExactness.EXACT``, and within twice the documented error bound on
  :meth:`SketchBase.estimate` for ``MergeExactness.BOUNDED``;
* identity on both sides, exactly, and population additivity (contract law 7);
* round trip: ``decode(serialise(context)) == sketch`` (contract law 5);
* the error bound depends on parameters and item count, not on the data (law 6);
* value-bearing honesty: a sketch that declares ``VALUE_BEARING = False`` is fed
  poisoned strings and its serialised payload must not contain them.

Contract law 4 -- merging across different parameters must raise -- is not tested but
*enforced*: :class:`SketchBase` wraps every subclass's ``merge`` so that it calls
``require_mergeable`` first. A plugin cannot forget it.

The checks at registration use a fixed, hash-derived sample, so importing a plugin is
deterministic and quick. The conformance kit re-runs the same checks under
:mod:`hypothesis` with generated inputs, which is where an associativity bug that only
shows on a particular split is found.

A registered sketch also joins ``godwit_sketch.SKETCH_REGISTRY``, so its envelopes decode
through ``godwit_sketch.decode_envelope`` like any core sketch -- and so its codec must
be unique. It must start with the plugin's namespace: ``acme-tdigest-v1``.

VALUE-BEARING
-------------
Declare ``VALUE_BEARING = True`` if the serialised state contains anything taken from a
row -- items, extremes, samples -- *or anything that lets someone test whether a value
was present*. An unkeyed hash is the second kind: a Bloom filter over names answers
"was Aoife Brennan here?" for anyone who can hash. The reference Bloom plugin is
value-bearing for exactly that reason. A value-bearing sketch must declare
``SENSITIVITY = Sensitivity.DATA_VALUE`` and expose stored items only as ``Tainted``.
"""

from __future__ import annotations

import abc
import datetime as _dt
import functools
import math
from collections.abc import Callable, Mapping, Sequence
from typing import ClassVar, Final

from godwit_contracts.common import ProbeKey, SnapshotId, SourceId
from godwit_contracts.sketch import ITEM_BEARING_KINDS
from godwit_contracts.taint import Sensitivity
from godwit_sketch import (
    SKETCH_REGISTRY,
    BaseSketch,
    ItemFlavour,
    MergeExactness,
    SketchContext,
    register,
)
from godwit_sketch.base import ParamValue, SketchItem
from godwit_sketch.deterministic import lognormals, zipf_indices
from godwit_sketch.errors import SketchRegistryError

from godwit_sdk.capabilities import Capabilities, ResourceLimits
from godwit_sdk.plugin import (
    DEFAULT_REQUIREMENT,
    PluginBase,
    PluginInfo,
    PluginKind,
    decorator_for,
    require_class_vars,
)

__all__ = ["SketchBase", "sketch"]

_DECLARATIONS: Final[tuple[str, ...]] = (
    "KIND",
    "CODEC",
    "SCHEMA_VERSION",
    "VALUE_BEARING",
    "MERGE_EXACTNESS",
    "ITEM_FLAVOUR",
    "ACQUISITION",
    "DEFAULT_PARAMS",
)
_TRIALS: Final[int] = 6
_ITEMS_PER_BATCH: Final[int] = 400

LAW_CONTEXT: Final[SketchContext] = SketchContext(
    source_id=SourceId("src_sdk_laws"),
    snapshot_id=SnapshotId("snap_sdk_laws"),
    produced_for=ProbeKey("prb_sdk_laws"),
    produced_at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
)
"""The fixed context the law checks serialise with. Ours; names nothing real."""


_LAW4_WRAPPED: Final[set[Callable[..., object]]] = set()
"""``merge`` functions already wrapped to enforce contract law 4."""


class SketchBase(PluginBase, BaseSketch, abc.ABC):
    """Base class for ``@sketch`` plugins: ``godwit_sketch.BaseSketch`` plus a plugin identity.

    Declare the class attributes listed in ``godwit_sketch.base`` (``KIND``, ``CODEC``,
    ``SCHEMA_VERSION``, ``VALUE_BEARING``, ``MERGE_EXACTNESS``, ``ITEM_FLAVOUR``,
    ``ACQUISITION``, ``SENSITIVITY``) plus ``DEFAULT_PARAMS``, and implement ``params``,
    ``population``, ``merge``, ``identity``, ``from_items``, ``error_bound``, ``encode``,
    ``_decode_body`` and :meth:`estimate`.
    """

    SDK_METHODS = ("serialise", "decode", "require_mergeable", "fingerprint", "provenance")

    DEFAULT_PARAMS: ClassVar[Mapping[str, ParamValue]]
    """Parameters the law checks build the sketch with. Ours, never row values."""

    @abc.abstractmethod
    def estimate(self) -> float:
        """One number that summarises the sketch, in the units ``error_bound`` describes.

        A count for a counting sketch, a false-positive rate or a fill fraction for a
        membership sketch, a median rank for a quantile sketch. The bounded-merge law
        compares it across bracketings; nothing else reads it.
        """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        merge = cls.__dict__.get("merge")
        if merge is None or merge in _LAW4_WRAPPED:
            return

        @functools.wraps(merge)
        def checked(self: SketchBase, other: SketchBase) -> SketchBase:
            self.require_mergeable(other)
            result: SketchBase = merge(self, other)
            return result

        _LAW4_WRAPPED.add(checked)
        type.__setattr__(cls, "merge", checked)


def _items(flavour: ItemFlavour, count: int, salt: str) -> list[SketchItem]:
    if flavour is ItemFlavour.NUMERIC:
        return list(lognormals(count, salt=salt, mu=4.0, sigma=1.6))
    indices = zipf_indices(count, distinct=max(8, count // 4), salt=salt)
    if flavour is ItemFlavour.EDGE:
        return [(f"node-{i}", f"node-{(i * 7 + 3) % 97}") for i in indices]
    return [f"item-{i}" for i in indices]


def _tolerance(sketch: BaseSketch, value: float) -> float:
    bound = sketch.error_bound()
    if bound.kind == "exact" or bound.epsilon is None:
        return 1e-9 * max(1.0, abs(value))
    if bound.kind == "relative":
        return 2.0 * bound.epsilon * max(1.0, abs(value))
    return 2.0 * bound.epsilon


def _estimate(sketch: BaseSketch) -> float:
    if not isinstance(sketch, SketchBase):
        raise TypeError("law checks need a SketchBase")
    return float(sketch.estimate())


def _agree(
    exactness: MergeExactness, left: BaseSketch, right: BaseSketch, law: str, problems: list[str]
) -> None:
    if exactness is MergeExactness.EXACT:
        if left != right:
            problems.append(f"{law} fails: the two results differ in state (declared EXACT)")
        return
    first, second = _estimate(left), _estimate(right)
    if not (math.isfinite(first) and math.isfinite(second)):
        problems.append(f"{law} fails: estimate() is not finite")
    elif abs(first - second) > _tolerance(left, first):
        problems.append(
            f"{law} fails: estimates {first!r} and {second!r} differ by more than twice "
            "the declared error bound (declared BOUNDED)"
        )


def law_problems(
    cls: type[SketchBase],
    batches: Sequence[tuple[Sequence[SketchItem], Sequence[SketchItem], Sequence[SketchItem]]],
    *,
    sentinels: Sequence[str] = (),
) -> list[str]:
    """Run every monoid law over each ``(a, b, c)`` triple. Returns problems; never raises.

    ``sentinels`` are strings that must not appear in the payload of a sketch declared
    ``VALUE_BEARING = False`` when they were among its items.
    """
    problems: list[str] = []
    params = dict(cls.DEFAULT_PARAMS)
    exactness = cls.MERGE_EXACTNESS
    try:
        for items_a, items_b, items_c in batches:
            a = cls.from_items(items_a, params)
            b = cls.from_items(items_b, params)
            c = cls.from_items(items_c, params)
            if cls.from_items(items_a, params) != a:
                problems.append("from_items is not deterministic: same items, different bytes")
            _agree(exactness, a.merge(b), b.merge(a), "commutativity", problems)
            _agree(exactness, a.merge(b).merge(c), a.merge(b.merge(c)), "associativity", problems)
            empty = cls.identity(params)
            if a.merge(empty) != a or empty.merge(a) != a:
                problems.append("identity fails: merging with identity() changed the sketch")
            if a.merge(b).population != a.population + b.population:
                problems.append("population is not additive under merge (contract law 7)")
            if cls.decode(a.serialise(LAW_CONTEXT)) != a:
                problems.append("round trip fails: decode(serialise(x)) != x (contract law 5)")
            twin = cls.from_items(list(reversed(items_a)), params)
            other = cls.from_items(items_b[: len(items_a)], params)
            if other.population == twin.population and other.error_bound() != twin.error_bound():
                problems.append(
                    "error_bound() depends on the data, not only on params and item count "
                    "(contract law 6)"
                )
        problems.extend(_disclosure_problems(cls, params, sentinels))
    except Exception as exc:  # the plugin's own code raised; report its type, not its text
        problems.append(f"raised {type(exc).__name__} while the monoid laws were checked")
    return list(dict.fromkeys(problems))


def _disclosure_problems(
    cls: type[SketchBase], params: Mapping[str, ParamValue], sentinels: Sequence[str]
) -> list[str]:
    problems: list[str] = []
    if not sentinels or cls.ITEM_FLAVOUR is ItemFlavour.NUMERIC:
        return problems
    items: list[SketchItem] = list(sentinels)
    if cls.ITEM_FLAVOUR is ItemFlavour.EDGE:
        items = [(value, value) for value in sentinels]
    built = cls.from_items(items, params)
    envelope = built.serialise(LAW_CONTEXT)
    if cls.VALUE_BEARING and envelope.sensitivity is not Sensitivity.DATA_VALUE:
        problems.append("is VALUE_BEARING but its envelope does not declare DATA_VALUE")
    rendered = repr(built)
    for value in sentinels:
        if value in rendered:
            problems.append("repr() renders a stored item; it must render counts only")
            break
    if not cls.VALUE_BEARING:
        for value in sentinels:
            if value.encode("utf-8") in envelope.payload:
                problems.append(
                    "declares VALUE_BEARING = False but its payload contains an item it "
                    "was fed; declare it value-bearing"
                )
                break
    return problems


_REGISTRATION_SENTINELS: Final[tuple[str, ...]] = (
    "godwit-sdk-sentinel-aoife.brennan@example.test",
    "godwit-sdk-sentinel-100-40-1000",
    "godwit-sdk-sentinel-ACME_CORP",
)


def registration_batches(
    flavour: ItemFlavour,
) -> list[tuple[list[SketchItem], list[SketchItem], list[SketchItem]]]:
    """The fixed sample the decorator checks the laws over."""
    batches = []
    for trial in range(_TRIALS):
        # Unequal sizes: a law that only holds for equal-sized operands is a broken law.
        sizes = (_ITEMS_PER_BATCH, _ITEMS_PER_BATCH // 3 + 17 * trial, 1 + 5 * trial)
        a, b, c = (
            _items(flavour, size, f"sdk-laws-{trial}-{part}")
            for size, part in zip(sizes, "abc", strict=True)
        )
        batches.append((a, b, c))
    return batches


def _registration_problems(cls: type[SketchBase], info: PluginInfo) -> list[str]:
    problems = require_class_vars(cls, _DECLARATIONS)
    if problems:
        return problems
    codec: object = cls.CODEC
    if isinstance(codec, str):
        if not codec.startswith(f"{info.namespace}-"):
            problems.append(f"CODEC {codec!r} must start with the namespace: '{info.namespace}-'")
        if codec in SKETCH_REGISTRY:
            problems.append(f"CODEC {codec!r} is already registered by another sketch")
    else:
        problems.append("CODEC must be a string")
    bearing: object = cls.VALUE_BEARING
    if bearing is True and cls.SENSITIVITY is not Sensitivity.DATA_VALUE:
        problems.append("is VALUE_BEARING, so it must declare SENSITIVITY = DATA_VALUE")
    if bearing is False and cls.KIND in ITEM_BEARING_KINDS:
        problems.append("declares an item-bearing KIND but VALUE_BEARING = False")
    params: object = cls.DEFAULT_PARAMS
    if not isinstance(params, Mapping):
        problems.append("DEFAULT_PARAMS must be a mapping of construction parameters")
    if problems:
        return problems
    problems = law_problems(
        cls, registration_batches(cls.ITEM_FLAVOUR), sentinels=_REGISTRATION_SENTINELS
    )
    if problems:
        return problems
    try:
        register(cls)
    except SketchRegistryError as exc:
        return [str(exc)]
    return []


def sketch[S: SketchBase](
    *,
    name: str,
    namespace: str,
    version: str,
    summary: str = "",
    requires_sdk: str = DEFAULT_REQUIREMENT,
    capabilities: Capabilities | None = None,
    limits: ResourceLimits | None = None,
) -> Callable[[type[S]], type[S]]:
    """Register a :class:`SketchBase` subclass, after checking it against the monoid laws."""

    return decorator_for(
        PluginKind.SKETCH,
        SketchBase,
        _registration_problems,
        name=name,
        namespace=namespace,
        version=version,
        summary=summary,
        requires_sdk=requires_sdk,
        capabilities=capabilities,
        limits=limits,
    )
