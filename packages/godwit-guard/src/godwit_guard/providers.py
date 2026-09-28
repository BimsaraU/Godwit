"""LLM provider controls: zero retention, data residency, and a fully local option.

The gate decides *what* may leave. This module decides *where to*: which configured
provider a ``SafePayload`` may be sent to under the buyer's provider policy. godwit-llm
(A15) makes the call; it asks :func:`select_provider` first.

The strictest buyers run the whole cascade inside their own network with
``local_only=True``. That works, and it is worse: expect weaker names and explanations
from a small local model, more template fallbacks, and slower responses. The quality
cost is written into each profile's ``quality_note`` so it is visible where the choice
is made, rather than discovered afterwards. Detection and prediction are unaffected
either way -- the LLM is not in those paths (invariant 7).
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from godwit_contracts import GodwitModel
from pydantic import Field

from godwit_guard.errors import ProviderRefusedError

__all__ = [
    "ProviderKind",
    "ProviderPolicy",
    "ProviderProfile",
    "select_provider",
]


class ProviderKind(StrEnum):
    """Where a model runs."""

    HOSTED = "hosted"
    LOCAL = "local"
    """Inside the buyer's network. Nothing crosses an organisational boundary."""


class ProviderProfile(GodwitModel):
    """One configured model endpoint and the promises attached to it."""

    provider_id: str = Field(min_length=1)
    kind: ProviderKind
    region: str = Field(description="Where requests are processed, e.g. 'eu-west-1'.")
    zero_retention: bool = Field(
        description="Contractual zero data retention. Local endpoints retain nothing "
        "outside the buyer's control by construction and should set this True."
    )
    model_name: str
    quality_note: str = Field(
        default="",
        description="The honest quality cost of choosing this provider. Shown, not hidden.",
    )


class ProviderPolicy(GodwitModel):
    """The buyer's rules for where payloads may go."""

    require_zero_retention: bool = True
    allowed_regions: tuple[str, ...] = Field(
        default=(), description="Empty means any region; otherwise residency routing."
    )
    local_only: bool = False


def select_provider(
    policy: ProviderPolicy, providers: Sequence[ProviderProfile]
) -> ProviderProfile:
    """The first compliant provider, by ``provider_id``, preferring local ones.

    Raises :class:`~godwit_guard.errors.ProviderRefusedError` when none complies. That is
    a normal outcome: the caller falls back to a template and records why.
    """
    compliant = [
        p
        for p in providers
        if (not policy.local_only or p.kind is ProviderKind.LOCAL)
        and (not policy.require_zero_retention or p.zero_retention)
        and (not policy.allowed_regions or p.region in policy.allowed_regions)
    ]
    if not compliant:
        raise ProviderRefusedError("no configured provider satisfies the provider policy")
    return sorted(compliant, key=lambda p: (p.kind is not ProviderKind.LOCAL, p.provider_id))[0]
