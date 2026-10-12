"""The only two ``.reveal()`` calls in this package. Both refuse anything else.

Scope matching compares customer column names (``SCHEMA_NAME``) and the counterfactual
check compares effect sizes (``DERIVED_STATISTIC``). Nothing here ever needs a
``DATA_VALUE``: segment predicates are compared by the hash of their canonical form,
which the contract computes, so no predicate value is held in this package's memory
outside a ``Tainted``.
"""

from __future__ import annotations

from godwit_contracts import Predicate, Sensitivity, Tainted, canonical_column, canonical_json
from godwit_contracts import content_hash as _hash

__all__ = ["column_name", "predicate_hash", "statistic"]


def column_name(value: Tainted[str]) -> str:
    """Canonical column name of a ``SCHEMA_NAME`` value. Raises on anything else."""
    if value.sensitivity is not Sensitivity.SCHEMA_NAME:
        raise ValueError(f"refusing to reveal {value.sensitivity} as a column name")
    return canonical_column(value.reveal())


def statistic(value: Tainted[float]) -> float:
    """The number inside a ``DERIVED_STATISTIC``. Raises on anything else."""
    if value.sensitivity is not Sensitivity.DERIVED_STATISTIC:
        raise ValueError(f"refusing to reveal {value.sensitivity} as a statistic")
    return float(value.reveal())


def predicate_hash(predicate: Predicate) -> str:
    """A pseudonym for one predicate: the hash of the contract's canonical form."""
    return str(_hash(canonical_json(predicate.canonical_form()), prefix="prd"))
