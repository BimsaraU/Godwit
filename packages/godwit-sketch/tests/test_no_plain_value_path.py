"""Invariant 2 at this package's boundary: no plain-string path to a stored value.

Three layers of checking, in increasing order of how much they actually prove.

1. **Structural.** Every public method of every value-bearing class is inspected. Any
   that returns a bare ``str``, or a container of bare ``str``, must appear in
   :data:`PLAIN_STRING_ALLOWLIST` with a stated reason. Adding an accessor that hands
   back a heavy hitter as a plain string fails the suite without anybody remembering to
   write a test for it -- which is the point, because the person adding that accessor is
   precisely the person who will not think to.

2. **Behavioural.** The documented state accessors are called and their results are
   asserted to be ``Tainted``, carrying an acquisition that meets the DATA_VALUE floor.

3. **A backstop.** Sketches are built from ``tests/golden/pii_torture`` and everything
   this package renders -- ``repr``, ``str``, feature vectors, error messages -- is
   searched for the fixture's forbidden strings.

Layer 3 is a backstop and nothing more. It is written down here because the golden
fixture's own README insists on the point: a passing string search proves almost
nothing, since most of the leak paths in Godwit are things no scanner would recognise as
sensitive. The control is layers 1 and 2, the typed taint. If a value ever escapes and
layer 3 is the thing that caught it, that is a bug in the typing and must be reported as
one.
"""

from __future__ import annotations

import inspect
import itertools
import json
import typing
from pathlib import Path
from typing import Any

import pytest
from _support import SMALL_PARAMS, context
from godwit_contracts.taint import Acquisition, Sensitivity, Tainted, egress_risk_rank
from godwit_sketch.base import BaseSketch, SketchItem, registered_sketches
from godwit_sketch.features import extract_features
from godwit_sketch.frequency import CategoryHistogram, CountMinHeavy
from godwit_sketch.graph import Direction, GraphDegree
from godwit_sketch.moments import Moments
from godwit_sketch.quantile import KllQuantile

VALUE_BEARING = [c for c in registered_sketches() if c.VALUE_BEARING]
NOT_VALUE_BEARING = [c for c in registered_sketches() if not c.VALUE_BEARING]

PLAIN_STRING_ALLOWLIST: dict[str, str] = {
    "CODEC": "our codec identifier, minted by us, never read from a customer system",
    "redacted": "renders a label, never a value -- that is its whole job",
    "params": (
        "construction parameters: k, lg_k, width, depth, seed, key_mode, key_id. The "
        "contract states these are ours and never row values, and a threshold that came "
        "out of the data belongs in a Segment instead. The str in the annotation is the "
        "mapping's key -- a parameter name."
    ),
}
"""Members that may expose a plain ``str``, and why each one is not a leak."""

AMBIGUOUS_LENGTH = 10
"""Fixture values shorter than this collide with ordinary English and are checked apart.

Four of the eighty forbidden strings are ``positive``, ``negative``, ``unknown`` and
``general`` -- the ``patient_hiv_status`` and ``cohort`` category values. They are real
row values and they are also words that appear in perfectly innocent label vocabulary:
``Tainted.redacted()`` renders ``<tainted data_value via ... from unknown>`` when no
column is known, and a naive substring scan calls that a leak.

That collision is not an inconvenience to be worked around, it is the demonstration the
golden fixture's README is asking for. A scanner cannot distinguish the word "unknown"
in a redaction label from the value ``unknown`` in an HIV-status column, which is why
scanning is a backstop and the typed taint is the control.
"""


def _public_callables(cls: type[BaseSketch]) -> list[tuple[str, Any]]:
    """Every public method and property of a sketch class, with inherited ones included."""
    found: list[tuple[str, Any]] = []
    for name, member in inspect.getmembers(cls):
        if name.startswith("_"):
            continue
        target = member.fget if isinstance(member, property) else member
        if callable(target):
            found.append((name, target))
    return found


def _mentions_bare_str(annotation: Any) -> bool:
    """True if a return annotation can produce a plain ``str`` outside a ``Tainted``.

    Walks the annotation rather than string-matching it, so ``tuple[tuple[Tainted[str],
    int], ...]`` reads as safe while ``tuple[str, ...]`` does not.
    """
    if annotation is str:
        return True
    origin = typing.get_origin(annotation)
    if origin is None:
        return False
    if origin is Tainted:
        return False
    return any(_mentions_bare_str(arg) for arg in typing.get_args(annotation))


@pytest.mark.parametrize("cls", VALUE_BEARING, ids=[c.__name__ for c in VALUE_BEARING])
def test_no_public_accessor_returns_a_bare_string(cls: type[BaseSketch]) -> None:
    """Layer 1. A value-bearing class exposes keys only as ``Tainted``.

    The allowlist is the escape hatch, and it is deliberately tiny and documented. If
    this test fails on an accessor you just added, the fix is to wrap the return in
    ``Tainted``, not to widen the allowlist.
    """
    offenders: list[str] = []
    for name, member in _public_callables(cls):
        if name in PLAIN_STRING_ALLOWLIST:
            continue
        try:
            hints = typing.get_type_hints(member)
        except (NameError, TypeError):
            continue
        if _mentions_bare_str(hints.get("return")):
            offenders.append(f"{cls.__name__}.{name} -> {hints.get('return')}")
    assert not offenders, (
        "value-bearing sketches must expose stored keys only as Tainted; "
        f"these return a bare str: {offenders}"
    )


def test_the_allowlist_has_not_quietly_grown() -> None:
    """A guard on the guard. Widening the allowlist should be a visible decision."""
    assert set(PLAIN_STRING_ALLOWLIST) == {"CODEC", "redacted", "params"}


def test_count_min_heavy_hitters_are_tainted() -> None:
    """Layer 2. On an identifier column the heavy hitters ARE the PII."""
    sketch = CountMinHeavy.from_items(["device-aaa"] * 9 + ["device-bbb"], SMALL_PARAMS)
    hitters = sketch.heavy_hitters()
    assert hitters
    for key, count in hitters:
        assert isinstance(key, Tainted)
        assert key.sensitivity is Sensitivity.DATA_VALUE
        assert key.provenance.acquisition is Acquisition.COUNT_MIN_HEAVY_HITTER
        assert key.population == sketch.population
        assert isinstance(count, int)
        # The rendering never contains the value.
        assert "device" not in repr(key)
        assert "device" not in str(key)


def test_category_labels_are_tainted() -> None:
    """Category labels below the cardinality threshold are exact row values."""
    sketch = CategoryHistogram.from_items(["positive", "negative", "positive"], SMALL_PARAMS)
    for key, _ in sketch.categories():
        assert isinstance(key, Tainted)
        assert key.sensitivity is Sensitivity.DATA_VALUE
        assert key.provenance.acquisition is Acquisition.CATEGORY_HISTOGRAM


def test_quantiles_and_extremes_are_tainted() -> None:
    """A quantile is a row's value, and over a small population it is one person's number."""
    sketch = KllQuantile.from_items([float(v) for v in (41000, 44100, 47200)], SMALL_PARAMS)
    for tainted in (sketch.quantile(0.5), sketch.minimum(), sketch.maximum()):
        assert isinstance(tainted, Tainted)
        assert tainted.sensitivity is Sensitivity.DATA_VALUE
        assert tainted.provenance.acquisition is Acquisition.QUANTILE
    assert sketch.quantile(0.5).is_small_cell(20)


def test_moment_extremes_are_tainted_even_though_moments_look_statistical() -> None:
    """The mean is a statistic; the maximum is somebody's salary."""
    sketch = Moments.from_items([41000.0, 44100.0, 47200.0], SMALL_PARAMS)
    assert isinstance(sketch.minimum(), Tainted)
    assert isinstance(sketch.maximum(), Tainted)
    assert sketch.maximum().sensitivity is Sensitivity.DATA_VALUE
    assert isinstance(sketch.mean(), float)


def test_graph_heavy_hitters_are_tainted() -> None:
    """Fan-in and fan-out hitters are entity identifiers."""
    sketch = GraphDegree.from_items(
        [("payer-1", "collector-9")] * 5 + [("payer-2", "collector-9")], SMALL_PARAMS
    )
    for key, _ in sketch.fan_in_heavy_hitters():
        assert isinstance(key, Tainted)
        assert key.sensitivity is Sensitivity.DATA_VALUE
    # Ratios and concentrations are counts over a population, so they stay plain.
    assert isinstance(sketch.concentration(direction=Direction.IN, top=1), float)
    assert isinstance(sketch.mean_in_degree(), float)


@pytest.mark.parametrize("cls", VALUE_BEARING, ids=[c.__name__ for c in VALUE_BEARING])
def test_envelope_sensitivity_meets_the_data_value_floor(cls: type[BaseSketch]) -> None:
    """A value-bearing sketch's envelope declares DATA_VALUE, never a derived statistic."""
    envelope = cls.from_items([], SMALL_PARAMS).serialise(context())
    assert egress_risk_rank(envelope.sensitivity) >= egress_risk_rank(Sensitivity.DATA_VALUE)


@pytest.mark.parametrize("cls", NOT_VALUE_BEARING, ids=[c.__name__ for c in NOT_VALUE_BEARING])
def test_non_value_bearing_kinds_are_derived_statistics(cls: type[BaseSketch]) -> None:
    """Theta, HLL and NullRate hold no row value and should not claim otherwise.

    Over-declaring is safe but not free: everything above treats DATA_VALUE as needing
    the gate, and a distinct count that needed clearing would make the cheap tier
    useless.
    """
    envelope = cls.from_items([], SMALL_PARAMS).serialise(context())
    assert envelope.sensitivity is Sensitivity.DERIVED_STATISTIC


# --------------------------------------------------------------------------------------
# Layer 3 -- the backstop, against the shared PII torture fixture
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def forbidden() -> list[str]:
    """Strings from ``tests/golden/pii_torture`` that must never appear in any egress."""
    root = Path(__file__).resolve().parents[3]
    payload = json.loads(
        (root / "tests" / "golden" / "pii_torture" / "expected_leaks.json").read_text("utf-8")
    )
    values = payload["must_never_appear_in_any_egress"]
    assert isinstance(values, list) and values
    return [str(v) for v in values]


def test_nothing_this_package_renders_contains_a_forbidden_string(
    forbidden: list[str],
) -> None:
    """Backstop. Build every kind from the torture values and render everything.

    ``repr``, ``str``, the feature vector and the hierarchy's repr are all checked. The
    serialised payload is deliberately NOT checked: an item-bearing payload is *supposed*
    to contain values, which is exactly why its envelope declares DATA_VALUE and why it
    may not cross the gate unredacted.
    """
    identifiers = [v for v in forbidden if not v.replace(".", "").isdigit()]
    numbers = [float(v) for v in forbidden if v.isdigit()]

    state_renderings: list[str] = []
    label_renderings: list[str] = []
    for cls in registered_sketches():
        if cls.ITEM_FLAVOUR.value == "numeric":
            items: list[SketchItem] = list(numbers)
        elif cls.ITEM_FLAVOUR.value == "edge":
            items = list(itertools.pairwise(identifiers))
        else:
            items = list(identifiers)
        sketch = cls.from_items(items, SMALL_PARAMS)
        envelope = sketch.serialise(context())
        state_renderings += [
            repr(sketch),
            str(sketch),
            str(extract_features(envelope)),
            repr(envelope.error_bound),
            repr(dict(envelope.params)),
        ]
        label_renderings.append(repr(envelope.provenance))

    state = "\n".join(state_renderings)
    leaked = [value for value in forbidden if value in state]
    assert not leaked, f"these fixture values were rendered in the clear: {leaked[:5]}"

    # Redaction labels are checked against the unambiguous identifiers only. See
    # AMBIGUOUS_LENGTH for why the four short ones cannot be checked this way, and why
    # that is the point rather than a gap.
    labels = "\n".join(label_renderings)
    long_leaks = [
        value for value in forbidden if len(value) >= AMBIGUOUS_LENGTH and value in labels
    ]
    assert not long_leaks, f"redaction labels leaked: {long_leaks[:5]}"


def test_tainted_heavy_hitters_do_not_leak_through_repr(forbidden: list[str]) -> None:
    """Even holding the Tainted wrapper, printing it must render a label."""
    identifiers = [v for v in forbidden if " " in v][:6]
    sketch = CountMinHeavy.from_items(identifiers * 3, SMALL_PARAMS)
    rendering = "\n".join(
        repr(key) + str(key) + key.redacted() for key, _ in sketch.heavy_hitters()
    )
    leaked = [value for value in forbidden if len(value) >= AMBIGUOUS_LENGTH and value in rendering]
    assert not leaked


def test_revealing_is_explicit_and_greppable(forbidden: list[str]) -> None:
    """``reveal()`` does return the value. That is the point: it is the one audited door.

    A test asserting the opposite would be asserting that the data plane cannot read its
    own data. What matters is that this is the *only* way through, which layers 1 and 2
    establish.
    """
    identifiers = [v for v in forbidden if " " in v][:3]
    sketch = CountMinHeavy.from_items(identifiers * 4, SMALL_PARAMS)
    revealed = [key.reveal() for key, _ in sketch.heavy_hitters()]
    assert revealed
    assert all(isinstance(value, str) for value in revealed)
