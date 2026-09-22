"""Budgets. Invariant 6: refusing to spend is a normal outcome, not an error.

Any path that can issue a billable query or start a training run takes a ``CostBudget``
and must refuse rather than exceed it. Budgets are immutable: spending returns the
remainder, so a caller cannot lose track of what it has left by mutating a shared object.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Self

from pydantic import Field

from godwit_contracts.common import GodwitModel
from godwit_contracts.errors import BudgetExceededError

__all__ = ["CostBudget", "CostSpend"]

_FIELDS: tuple[str, ...] = (
    "bytes_scanned",
    "wall_seconds",
    "usd",
    "llm_tokens",
    "train_seconds",
)


class CostSpend(GodwitModel):
    """An amount of resource actually consumed, or about to be."""

    bytes_scanned: int = Field(default=0, ge=0)
    wall_seconds: float = Field(default=0.0, ge=0.0)
    usd: Decimal = Field(default=Decimal("0"), ge=0)
    llm_tokens: int = Field(default=0, ge=0)
    train_seconds: float = Field(default=0.0, ge=0.0)

    def __add__(self, other: CostSpend) -> CostSpend:
        """Accumulate two spends field-wise."""
        return CostSpend(
            bytes_scanned=self.bytes_scanned + other.bytes_scanned,
            wall_seconds=self.wall_seconds + other.wall_seconds,
            usd=self.usd + other.usd,
            llm_tokens=self.llm_tokens + other.llm_tokens,
            train_seconds=self.train_seconds + other.train_seconds,
        )

    @classmethod
    def zero(cls) -> CostSpend:
        """The additive identity. ``spend + zero() == spend``."""
        return cls()


class CostBudget(GodwitModel):
    """A ceiling on what one unit of work may consume.

    There is deliberately no ``unlimited()`` constructor. Every field must be stated,
    because "I forgot to set a ceiling" and "there is no ceiling" must not look alike.
    """

    bytes_scanned: int = Field(ge=0)
    wall_seconds: float = Field(ge=0.0)
    usd: Decimal = Field(ge=0)
    llm_tokens: int = Field(ge=0)
    train_seconds: float = Field(ge=0.0)

    def can_afford(self, spend: CostSpend) -> bool:
        """Return True if every field of ``spend`` fits inside this budget."""
        return not self._overruns(spend)

    def spend(self, spend: CostSpend) -> Self:
        """Return the remaining budget after ``spend``.

        Raises :class:`BudgetExceededError` naming the first field that would go
        negative. Catch it, record the refusal, and stop -- do not retry with a bigger
        budget unless a human widened it.
        """
        overrun = self._overruns(spend)
        if overrun is not None:
            field, available, requested = overrun
            raise BudgetExceededError(f"{field}: requested {requested}, {available} remaining")
        return type(self)(
            bytes_scanned=self.bytes_scanned - spend.bytes_scanned,
            wall_seconds=self.wall_seconds - spend.wall_seconds,
            usd=self.usd - spend.usd,
            llm_tokens=self.llm_tokens - spend.llm_tokens,
            train_seconds=self.train_seconds - spend.train_seconds,
        )

    @classmethod
    def compose(cls, *budgets: CostBudget) -> CostBudget:
        """Combine budgets by field-wise minimum.

        A sub-task inherits the tightest ceiling in force anywhere above it. Composition
        can only shrink a budget, never widen one, which is what makes nested budgets
        safe to hand to code you did not write.
        """
        if not budgets:
            raise ValueError("compose() needs at least one budget")
        first, *rest = budgets
        result = first
        for other in rest:
            result = cls(
                bytes_scanned=min(result.bytes_scanned, other.bytes_scanned),
                wall_seconds=min(result.wall_seconds, other.wall_seconds),
                usd=min(result.usd, other.usd),
                llm_tokens=min(result.llm_tokens, other.llm_tokens),
                train_seconds=min(result.train_seconds, other.train_seconds),
            )
        return result

    def _overruns(self, spend: CostSpend) -> tuple[str, object, object] | None:
        for field in _FIELDS:
            available = getattr(self, field)
            requested = getattr(spend, field)
            if requested > available:
                return (field, available, requested)
        return None
