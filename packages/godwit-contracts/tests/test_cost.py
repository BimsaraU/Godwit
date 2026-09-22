"""Budgets: spending, refusing, and composing by field-wise minimum."""

from __future__ import annotations

from decimal import Decimal

import pytest
from godwit_contracts import BudgetExceededError, CostBudget, CostSpend
from hypothesis import given
from hypothesis import strategies as st


def budget(**overrides: object) -> CostBudget:
    base: dict[str, object] = {
        "bytes_scanned": 1_000_000,
        "wall_seconds": 60.0,
        "usd": Decimal("1.00"),
        "llm_tokens": 10_000,
        "train_seconds": 300.0,
    }
    base.update(overrides)
    return CostBudget(**base)  # type: ignore[arg-type]


def test_spending_returns_the_remainder() -> None:
    remaining = budget().spend(CostSpend(bytes_scanned=400_000, usd=Decimal("0.25")))
    assert remaining.bytes_scanned == 600_000
    assert remaining.usd == Decimal("0.75")
    assert remaining.llm_tokens == 10_000


def test_spending_does_not_mutate_the_original() -> None:
    original = budget()
    original.spend(CostSpend(bytes_scanned=400_000))
    assert original.bytes_scanned == 1_000_000


@pytest.mark.parametrize(
    ("field", "spend"),
    [
        ("bytes_scanned", CostSpend(bytes_scanned=1_000_001)),
        ("wall_seconds", CostSpend(wall_seconds=60.1)),
        ("usd", CostSpend(usd=Decimal("1.01"))),
        ("llm_tokens", CostSpend(llm_tokens=10_001)),
        ("train_seconds", CostSpend(train_seconds=300.1)),
    ],
)
def test_every_field_can_refuse(field: str, spend: CostSpend) -> None:
    """Refusing is a normal outcome (invariant 6). The message names the field."""
    with pytest.raises(BudgetExceededError, match=field):
        budget().spend(spend)


def test_spending_exactly_the_budget_is_allowed() -> None:
    exhausted = budget().spend(
        CostSpend(
            bytes_scanned=1_000_000,
            wall_seconds=60.0,
            usd=Decimal("1.00"),
            llm_tokens=10_000,
            train_seconds=300.0,
        )
    )
    assert exhausted.bytes_scanned == 0
    assert exhausted.usd == Decimal("0")


def test_can_afford_agrees_with_spend() -> None:
    small = CostSpend(bytes_scanned=1)
    huge = CostSpend(bytes_scanned=10_000_000)
    assert budget().can_afford(small) is True
    assert budget().can_afford(huge) is False


def test_money_is_decimal_not_float() -> None:
    """Three cents, ten times, is thirty cents. With floats it is not."""
    remaining = budget(usd=Decimal("0.30"))
    for _ in range(10):
        remaining = remaining.spend(CostSpend(usd=Decimal("0.03")))
    assert remaining.usd == Decimal("0.00")


_BUDGETS = st.builds(
    CostBudget,
    bytes_scanned=st.integers(min_value=0, max_value=10**9),
    wall_seconds=st.floats(min_value=0.0, max_value=1e6, allow_nan=False),
    usd=st.decimals(min_value=0, max_value=1000, places=2, allow_nan=False),
    llm_tokens=st.integers(min_value=0, max_value=10**7),
    train_seconds=st.floats(min_value=0.0, max_value=1e6, allow_nan=False),
)


@given(_BUDGETS, _BUDGETS)
def test_compose_takes_the_field_wise_minimum(a: CostBudget, b: CostBudget) -> None:
    composed = CostBudget.compose(a, b)
    assert composed.bytes_scanned == min(a.bytes_scanned, b.bytes_scanned)
    assert composed.wall_seconds == min(a.wall_seconds, b.wall_seconds)
    assert composed.usd == min(a.usd, b.usd)
    assert composed.llm_tokens == min(a.llm_tokens, b.llm_tokens)
    assert composed.train_seconds == min(a.train_seconds, b.train_seconds)


@given(_BUDGETS, _BUDGETS, _BUDGETS)
def test_compose_is_associative_commutative_and_idempotent(
    a: CostBudget, b: CostBudget, c: CostBudget
) -> None:
    """Property: composition is a meet. Nesting budgets can only ever tighten them."""
    assert CostBudget.compose(a, b) == CostBudget.compose(b, a)
    assert CostBudget.compose(CostBudget.compose(a, b), c) == CostBudget.compose(
        a, CostBudget.compose(b, c)
    )
    assert CostBudget.compose(a, a) == a


@given(_BUDGETS, _BUDGETS)
def test_composition_never_widens(a: CostBudget, b: CostBudget) -> None:
    """The safety property: handing a nested budget to code you did not write is safe."""
    composed = CostBudget.compose(a, b)
    for field in ("bytes_scanned", "wall_seconds", "usd", "llm_tokens", "train_seconds"):
        assert getattr(composed, field) <= getattr(a, field)
        assert getattr(composed, field) <= getattr(b, field)


def test_compose_needs_at_least_one_budget() -> None:
    with pytest.raises(ValueError, match="at least one"):
        CostBudget.compose()


def test_spends_add() -> None:
    total = CostSpend(bytes_scanned=1, llm_tokens=2) + CostSpend(bytes_scanned=3, llm_tokens=4)
    assert total.bytes_scanned == 4
    assert total.llm_tokens == 6
    assert total + CostSpend.zero() == total


def test_negative_amounts_are_refused() -> None:
    with pytest.raises(ValueError, match="greater than or equal to 0"):
        CostSpend(bytes_scanned=-1)
    with pytest.raises(ValueError, match="greater than or equal to 0"):
        budget(llm_tokens=-1)
