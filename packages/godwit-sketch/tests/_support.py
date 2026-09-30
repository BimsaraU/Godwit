"""Shared fixtures and hypothesis strategies for the godwit-sketch suite.

The point of this file is that the property suite can be *universal*: one set of laws
applied to every class in :data:`~godwit_sketch.base.SKETCH_REGISTRY`, with no per-kind
wiring to forget. :func:`items_strategy` turns a class's declared
:class:`~godwit_sketch.base.ItemFlavour` into observations it can actually consume, and
:data:`SMALL_PARAMS` gives every kind a deliberately tiny configuration so that the
bounded kinds are pushed into truncation rather than tested only on inputs small enough
to stay exact by accident.
"""

from __future__ import annotations

import datetime as _dt
import math
from collections.abc import Sequence
from typing import Final

from godwit_contracts.common import ProbeKey, SnapshotId, SourceId
from godwit_sketch.base import BaseSketch, ItemFlavour, ParamValue, SketchContext, SketchItem
from hypothesis import strategies as st

SMALL_PARAMS: Final[dict[str, ParamValue]] = {
    # Theta / HLL
    "lg_k": 8,
    # Count-Min and the Misra-Gries counters
    "width": 64,
    "depth": 3,
    "seed": 11,
    "capacity": 8,
    # KLL
    "k": 8,
    # Category histogram
    "max_exact_cardinality": 8,
    # Graph degree
    "degrees_partitioned_by_entity": False,
}
"""One parameter mapping every registered kind understands.

Small on purpose. With ``capacity=8`` and ``k=8`` the bounded kinds truncate almost
immediately, which is the regime where their laws are interesting. Generous parameters
would keep every test sketch exact and the suite would prove nothing about merging.
"""

OTHER_PARAMS: Final[dict[str, ParamValue]] = {**SMALL_PARAMS, "seed": 12, "lg_k": 9, "k": 16}
"""A second, deliberately incompatible configuration, for the merge-refusal law."""

FROZEN_INSTANT: Final[_dt.datetime] = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)


def context() -> SketchContext:
    """A fixed serialisation context. No clock is read anywhere in this package's tests."""
    return SketchContext(
        source_id=SourceId("src_test"),
        snapshot_id=SnapshotId("snap_0"),
        produced_for=ProbeKey("prb_test"),
        produced_at=FROZEN_INSTANT,
        table="orders",
        column="amount",
    )


def items_strategy(flavour: ItemFlavour) -> st.SearchStrategy[SketchItem]:
    """Observations a sketch of this flavour can consume.

    Numeric values are kept finite and bounded: infinities and NaN are handled
    explicitly by their own tests, and letting hypothesis mix them in here would make
    every law failure ambiguous between "the merge is wrong" and "NaN does not compare
    equal to itself".
    """
    if flavour is ItemFlavour.NUMERIC:
        return st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False)
    if flavour is ItemFlavour.EDGE:
        entities = st.text(alphabet="abcdefghij", min_size=1, max_size=3)
        return st.tuples(entities, entities)
    return st.text(alphabet="abcdefghij", min_size=1, max_size=3)


def item_lists(
    flavour: ItemFlavour, *, min_size: int = 0, max_size: int = 60
) -> st.SearchStrategy[list[SketchItem]]:
    """A list of observations for this flavour."""
    return st.lists(items_strategy(flavour), min_size=min_size, max_size=max_size)


def build(cls: type[BaseSketch], items: Sequence[SketchItem]) -> BaseSketch:
    """Build one sketch of ``cls`` from ``items`` at :data:`SMALL_PARAMS`."""
    return cls.from_items(list(items), SMALL_PARAMS)


def same_vector(left: Sequence[float], right: Sequence[float], *, tolerance: float) -> bool:
    """Compare two feature vectors, treating NaN as equal to NaN.

    NaN means "this slot does not apply", so two vectors that disagree about *which*
    slots apply are genuinely different even when every number matches.
    """
    if len(left) != len(right):
        return False
    for a, b in zip(left, right, strict=True):
        if math.isnan(a) != math.isnan(b):
            return False
        if math.isnan(a):
            continue
        if not math.isclose(a, b, rel_tol=tolerance, abs_tol=tolerance):
            return False
    return True
