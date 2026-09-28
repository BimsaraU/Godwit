"""Every exception godwit-guard raises, and the refusal they carry.

A refusal is a normal outcome of the gate, not a crash: deny by default means most
requests that are not explicitly cleared come back refused. Each refusal says *why* in
our own words and names *which field* by its key. It never quotes a value, because an
exception message is leak path 10 in the other direction.
"""

from __future__ import annotations

from enum import StrEnum

from godwit_contracts import ApprovalRequest, EgressDeniedError, GodwitModel

__all__ = [
    "ApprovalRequiredError",
    "BackstopHitError",
    "EgressRefusedError",
    "GrantError",
    "GuardError",
    "LedgerWriteError",
    "OpaqueHashRefusedError",
    "PolicyVersionError",
    "ProjectionViolationError",
    "ProviderRefusedError",
    "Refusal",
    "RefusalReason",
    "TokenScopeError",
]


class RefusalReason(StrEnum):
    """Why the gate said no. A closed set, so a dashboard can count them."""

    UNKNOWN_DESTINATION = "unknown_destination"
    NO_DESTINATION_POLICY = "no_destination_policy"
    MISSING_POLICY = "missing_policy"
    INVALID_POLICY = "invalid_policy"
    MISSING_PURPOSE = "missing_purpose"
    UNSAFE_FIELD_NAME = "unsafe_field_name"
    UNCLASSIFIED_FIELD = "unclassified_field"
    UNSUPPORTED_VALUE = "unsupported_value"
    GUARDRAIL_DENY = "guardrail_deny"
    APPROVAL_REQUIRED = "approval_required"
    RELEASE_NARROWS_POPULATION = "release_narrows_population"
    BACKSTOP_HIT = "backstop_hit"
    LEDGER_UNAVAILABLE = "ledger_unavailable"


class Refusal(GodwitModel):
    """What the gate refused and why. Field *names* only; never a value."""

    reason: RefusalReason
    fields: tuple[str, ...] = ()
    detail: str
    guardrail_ids: tuple[str, ...] = ()


class GuardError(Exception):
    """Base for operational failures inside godwit-guard that are not refusals."""


class EgressRefusedError(EgressDeniedError):
    """The gate refused. Nothing left the perimeter. Inspect :attr:`refusal`."""

    def __init__(self, refusal: Refusal) -> None:
        super().__init__(f"egress refused: {refusal.reason.value}: {refusal.detail}")
        self.refusal = refusal


class ApprovalRequiredError(EgressRefusedError):
    """A REQUIRE_APPROVAL guardrail matched. Re-submit with an approved request."""

    def __init__(self, refusal: Refusal, request: ApprovalRequest) -> None:
        super().__init__(refusal)
        self.request = request


class BackstopHitError(EgressRefusedError):
    """The backstop scanner found something the taint system should have stopped.

    This is a DEFECT, not a routine catch. The primary control leaked; someone has been
    paged, and the package that produced the leaking value owes a fix.
    """


class LedgerWriteError(EgressRefusedError):
    """The EgressRecord could not be written, so nothing leaves (EgressGate law 1)."""


class OpaqueHashRefusedError(GuardError):
    """Somebody asked to keyed-hash a column that failed the minimum-entropy check.

    Hashing a four-digit PIN and calling it safe is the false claim this package exists
    to catch. Bucket the column or blind it.
    """


class GrantError(GuardError):
    """An AccessGrant or narrowing override is malformed or not applicable."""


class PolicyVersionError(GuardError):
    """A policy or guardrail was published out of version order, or edited in place."""


class ProjectionViolationError(GuardError):
    """A planned query or result schema touches a column its access mode forbids."""


class TokenScopeError(GuardError):
    """A token scope is unknown or has expired."""


class ProviderRefusedError(GuardError):
    """No configured LLM provider satisfies the provider policy."""
