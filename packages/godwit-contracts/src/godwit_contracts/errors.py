"""Every exception the contracts layer can raise.

Contracts raise on *representation* failures only: something was constructed that the
invariants say must not exist. Operational failures belong to the package that hit them.
"""

from __future__ import annotations

__all__ = [
    "BudgetExceededError",
    "EgressDeniedError",
    "ForgedObjectError",
    "GodwitContractError",
    "IssuerAlreadyClaimedError",
    "MemorisationAuditFailedError",
    "SealedConstructionError",
]


class GodwitContractError(Exception):
    """Base for every contract violation."""


class SealedConstructionError(GodwitContractError):
    """Something tried to construct a type that only a designated issuer may create."""


class ForgedObjectError(GodwitContractError):
    """An object of a sealed type exists but was never issued. Its contents are absent."""


class IssuerAlreadyClaimedError(GodwitContractError):
    """The single issuer capability for a sealed type has already been handed out."""


class BudgetExceededError(GodwitContractError):
    """A spend would exceed a CostBudget.

    Invariant 6 consequence: refusing to spend is a normal outcome, not a failure. Catch
    this, record the refusal, and carry on. Do not widen the budget to make it go away.
    """


class MemorisationAuditFailedError(GodwitContractError):
    """A model artifact was offered for deployment without a passing memorisation audit."""


class EgressDeniedError(GodwitContractError):
    """A guardrail denied an egress. The value stays inside the perimeter."""
