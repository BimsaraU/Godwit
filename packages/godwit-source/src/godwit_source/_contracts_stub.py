"""Provisional stand-in for ``godwit_contracts`` (owned by A0).

A1 does not own the contracts package and must not create it. This module exists so
``godwit-source`` type-checks and tests green from a clean checkout while
``godwit-contracts`` is absent. ``godwit_source._contracts`` prefers the real package
whenever it is importable, so this file evaporates the moment A0 lands.

See ``docs/change-requests/CR-A1-contracts-missing.md``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

__all__ = [
    "Candidate",
    "ColumnAccessMode",
    "CostBudget",
    "CostBudgetExceeded",
    "Evidence",
    "PiiClass",
    "ProbeSpec",
    "Segment",
    "SemanticRole",
    "SketchBundle",
    "TaintKind",
    "Tainted",
    "data_value",
    "derived_statistic",
]


class TaintKind(StrEnum):
    """How close a value sits to a customer row.

    ``DATA_VALUE`` is a row value or something from which one is recoverable (an Iceberg
    bound, a ``most_common_vals`` entry, a heavy hitter, a segment predicate value, a
    column name). ``DERIVED_STATISTIC`` is an aggregate that quotes nothing (a count, a
    rate, a distance). Both are denied by default at the egress gate; they differ in what
    a gate is permitted to let through and under which guardrail.
    """

    DATA_VALUE = "data_value"
    DERIVED_STATISTIC = "derived_statistic"


@dataclass(frozen=True, slots=True, eq=True)
class Tainted[V]:
    """A value that came from customer data, denied by default.

    The payload is never rendered by ``repr``/``str`` and never serialises implicitly.
    Reading it is an explicit, reasoned act via :meth:`unwrap`, legal only inside the data
    plane or behind ``godwit-guard``'s egress gate.
    """

    _value: V = field(repr=False)
    kind: TaintKind
    origin: str

    def unwrap(self, reason: str) -> V:
        """Read the payload. ``reason`` is required so the call site is self-documenting."""
        if not reason:
            raise ValueError("unwrap() requires a non-empty reason")
        return self._value

    def map[U](self, fn: Callable[[V], U]) -> Tainted[U]:
        """Transform the payload without widening taint: the result keeps this taint."""
        return Tainted(fn(self._value), self.kind, self.origin)

    def __repr__(self) -> str:
        return f"Tainted(<redacted {self.kind.value}>, origin={self.origin!r})"

    __str__ = __repr__


def data_value[V](value: V, origin: str) -> Tainted[V]:
    """Tag a row value (bound, most_common_val, heavy hitter, column name)."""
    return Tainted(value, TaintKind.DATA_VALUE, origin)


def derived_statistic[V](value: V, origin: str) -> Tainted[V]:
    """Tag an aggregate that quotes no row value (count, rate, distance)."""
    return Tainted(value, TaintKind.DERIVED_STATISTIC, origin)


class ColumnAccessMode(StrEnum):
    """How a column may be touched. Resolved at plan time, enforced structurally."""

    BLIND = "blind"
    OPAQUE = "opaque"
    OPEN = "open"


class PiiClass(StrEnum):
    DIRECT_IDENTIFIER = "direct_identifier"
    QUASI_IDENTIFIER = "quasi_identifier"
    SENSITIVE_ATTRIBUTE = "sensitive_attribute"
    FREE_TEXT = "free_text"
    SECRET = "secret"
    NON_PII = "non_pii"
    UNKNOWN = "unknown"


class SemanticRole(StrEnum):
    ENTITY_ID = "entity_id"
    FOREIGN_KEY = "foreign_key"
    TIMESTAMP = "timestamp"
    AMOUNT = "amount"
    CATEGORY = "category"
    BOOLEAN_FLAG = "boolean_flag"
    FREE_TEXT = "free_text"
    GEO = "geo"
    UNKNOWN = "unknown"


class CostBudgetExceeded(RuntimeError):
    """Raised when a plan would spend more than its budget. A normal outcome, not a fault."""


@dataclass(slots=True)
class CostBudget:
    """A spend ceiling carried by every billable path."""

    max_bytes: int
    max_queries: int
    bytes_spent: int = 0
    queries_spent: int = 0

    def check_bytes(self, estimated: int) -> None:
        """Refuse *before* reading. Estimation happens from manifest sizes, not from data."""
        if self.bytes_spent + estimated > self.max_bytes:
            raise CostBudgetExceeded(
                f"would read {self.bytes_spent + estimated} bytes, budget {self.max_bytes}"
            )

    def spend_bytes(self, actual: int) -> None:
        self.check_bytes(actual)
        self.bytes_spent += actual

    def spend_query(self) -> None:
        if self.queries_spent + 1 > self.max_queries:
            raise CostBudgetExceeded(f"query budget {self.max_queries} exhausted")
        self.queries_spent += 1


@dataclass(frozen=True, slots=True)
class Segment:
    """``(column, operator, value)``. The value is real data and travels tainted."""

    column: str
    operator: str
    value: Tainted[object]


Evidence = Mapping[str, "float | int | str | Tainted[object]"]


@dataclass(frozen=True, slots=True)
class Candidate:
    """A pre-pattern: something a detector thinks is worth a second look."""

    detector: str
    table: str
    column: str | None
    snapshot_id: str
    effect_size: float
    p_value: float
    evidence: Evidence
    segment: Segment | None = None


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    """What to measure, where. Replayable from ``(spec, snapshot_id, version, seed)``."""

    table: str
    columns: tuple[str, ...]
    snapshot_id: str
    version: str
    seed: int
    sketches: tuple[str, ...] = ()


@runtime_checkable
class SketchBundle(Protocol):
    """A2 provides the classes; A1 only ever codes against this Protocol."""

    def merge(self, other: SketchBundle) -> SketchBundle: ...

    def serialize(self) -> bytes: ...

