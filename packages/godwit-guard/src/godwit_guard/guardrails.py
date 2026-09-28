"""Evaluating declarative guardrails. Pure functions; no I/O, no clock.

A ``Guardrail`` is data: a scope, a conjunction of conditions and an action. This module
decides whether one applies to a set of attributes, and combines the actions of every
guardrail that does. Two fail-closed rules are worth stating plainly:

* **Scope is where a rule applies.** If a scope restricts on an attribute the caller
  cannot supply -- a destination, when resolving a column's access mode -- the rule does
  not apply there. Scopes narrow; they never widen.
* **A condition on a missing attribute** (population unknown, say) is TRUE for a
  restrictive rule and FALSE for an ALLOW rule. Unknown never grants anything and never
  escapes a denial.

Ordering (EgressGate law 5): DENY beats REQUIRE_APPROVAL beats REDACT beats ALLOW.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Final

from godwit_contracts import (
    Guardrail,
    GuardrailAction,
    GuardrailAttribute,
    GuardrailCondition,
)
from godwit_contracts.segment import canonical_column

__all__ = [
    "ACCESS_ATTRIBUTES",
    "ACTION_SEVERITY",
    "AttrValue",
    "applicable",
    "applies",
    "is_access_guardrail",
    "strongest_action",
]

type AttrValue = str | int | float | bool | None

A = GuardrailAttribute

ACTION_SEVERITY: Final[dict[GuardrailAction, int]] = {
    GuardrailAction.ALLOW: 0,
    GuardrailAction.REDACT: 1,
    GuardrailAction.REQUIRE_APPROVAL: 2,
    GuardrailAction.DENY: 3,
}

ACCESS_ATTRIBUTES: Final[frozenset[GuardrailAttribute]] = frozenset(
    {A.PII_CLASS, A.SOURCE_ID, A.COLUMN_NAME, A.TABLE_NAME, A.SENSITIVITY, A.PLANE}
)
"""Attributes that describe a *column* rather than an *egress*. Only guardrails that
test these alone take part in access-mode resolution."""

_NAME_ATTRIBUTES: Final[frozenset[GuardrailAttribute]] = frozenset(
    {A.COLUMN_NAME, A.TABLE_NAME, A.PURPOSE, A.SOURCE_ID}
)


def strongest_action(actions: Iterable[GuardrailAction]) -> GuardrailAction | None:
    """The most restrictive action, or None if there were none."""
    ranked = sorted(actions, key=ACTION_SEVERITY.__getitem__)
    return ranked[-1] if ranked else None


def is_access_guardrail(guardrail: Guardrail) -> bool:
    """True if the guardrail speaks about columns, not about a particular egress."""
    scope = guardrail.scope
    if scope.destinations or scope.min_population is not None:
        return False
    return all(cond.attribute in ACCESS_ATTRIBUTES for cond in guardrail.predicate.all_of)


def applicable(
    guardrails: Sequence[Guardrail], attrs: Mapping[GuardrailAttribute, AttrValue]
) -> tuple[Guardrail, ...]:
    """Every enabled guardrail that fires, ordered by (id, version) for determinism."""
    ordered = sorted(guardrails, key=lambda g: (g.guardrail_id, g.version))
    return tuple(g for g in ordered if applies(g, attrs))


def applies(guardrail: Guardrail, attrs: Mapping[GuardrailAttribute, AttrValue]) -> bool:
    """True if ``guardrail`` is enabled, in scope and its predicate holds."""
    if not guardrail.enabled:
        return False
    if not _in_scope(guardrail, attrs):
        return False
    restrictive = guardrail.action is not GuardrailAction.ALLOW
    return all(
        _condition(cond, attrs.get(cond.attribute), restrictive=restrictive)
        for cond in guardrail.predicate.all_of
    )


def _in_scope(guardrail: Guardrail, attrs: Mapping[GuardrailAttribute, AttrValue]) -> bool:
    scope = guardrail.scope
    checks: tuple[tuple[GuardrailAttribute, tuple[str, ...]], ...] = (
        (A.PLANE, tuple(p.value for p in scope.planes)),
        (A.DESTINATION, tuple(d.value for d in scope.destinations)),
        (A.SENSITIVITY, tuple(s.value for s in scope.sensitivities)),
        (A.PII_CLASS, tuple(c.value for c in scope.pii_classes)),
        (A.SOURCE_ID, scope.source_ids),
    )
    for attribute, allowed in checks:
        if not allowed:
            continue
        actual = attrs.get(attribute)
        if actual is None or str(actual) not in allowed:
            return False
    if scope.min_population is not None:
        population = attrs.get(A.POPULATION)
        if not isinstance(population, int) or population < scope.min_population:
            return False
    return True


def _condition(cond: GuardrailCondition, actual: AttrValue, *, restrictive: bool) -> bool:
    if actual is None:
        return restrictive
    try:
        return _evaluate(cond, actual)
    except (TypeError, ValueError, re.error):
        # A malformed condition fails closed: it fires for a denial, never for an allow.
        return restrictive


def _norm(attribute: GuardrailAttribute, value: AttrValue) -> str:
    text = str(value)
    if attribute in (A.COLUMN_NAME, A.TABLE_NAME):
        return canonical_column(text)
    return text


def _evaluate(cond: GuardrailCondition, actual: AttrValue) -> bool:
    op = cond.op
    if op in ("eq", "ne", "in", "not_in"):
        wanted = {_norm(cond.attribute, v) for v in cond.values}
        hit = _norm(cond.attribute, actual) in wanted
        return hit if op in ("eq", "in") else not hit
    if op == "matches":
        if cond.attribute not in _NAME_ATTRIBUTES:
            raise ValueError("'matches' is only valid on name attributes")
        return re.search(str(cond.values[0]), str(actual)) is not None
    if isinstance(actual, bool) or not isinstance(actual, int | float):
        raise TypeError("ordering comparison on a non-numeric attribute")
    bound = cond.values[0]
    if isinstance(bound, bool) or not isinstance(bound, int | float):
        raise TypeError("ordering comparison against a non-numeric bound")
    comparisons = {
        "lt": actual < bound,
        "le": actual <= bound,
        "gt": actual > bound,
        "ge": actual >= bound,
    }
    return comparisons[op]
