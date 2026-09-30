"""Policy as data: versioned RedactionPolicies and Guardrails, and the default policy.

Policies and guardrails are records, not code. They are never edited in place: a change
is a new version, published as an audited event, and every ``EgressRecord`` and
``SafePayload`` names the exact ``policy_id`` and ``version`` that cleared it. That is
what lets somebody explain a narrative written years ago: look up the record, look up
that version, and the redaction is reproducible.
"""

from __future__ import annotations

import datetime as _dt
from typing import Final

from godwit_contracts import (
    Guardrail,
    Instant,
    PiiClass,
    Plane,
    RedactionAction,
    RedactionPolicy,
    RedactionRule,
)

from godwit_guard.errors import PolicyVersionError
from godwit_guard.ledger import EgressLedger, audit_event

__all__ = [
    "DEFAULT_POLICY",
    "PolicyRegistry",
]

_R = RedactionAction
_P = PiiClass

DEFAULT_POLICY: Final[RedactionPolicy] = RedactionPolicy(
    policy_id="godwit.default",
    version=1,
    rules=(
        RedactionRule(pii_class=_P.UNKNOWN, action=_R.SUPPRESS),
        RedactionRule(pii_class=_P.CREDENTIAL, action=_R.SUPPRESS),
        RedactionRule(pii_class=_P.HEALTH, action=_R.SUPPRESS),
        RedactionRule(pii_class=_P.SENSITIVE_ATTRIBUTE, action=_R.SUPPRESS),
        RedactionRule(pii_class=_P.DIRECT_IDENTIFIER, action=_R.TOKENISE),
        RedactionRule(pii_class=_P.QUASI_IDENTIFIER, action=_R.TOKENISE),
        RedactionRule(
            pii_class=_P.FINANCIAL,
            action=_R.GENERALISE,
            params={"hierarchy": "magnitude", "level": 1},
        ),
        RedactionRule(pii_class=_P.NONE, action=_R.ALLOW),
    ),
    default_action=_R.SUPPRESS,
    min_cell_size=20,
    quantile_min_population=100,
    created_at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
)
"""Suppress the special categories, tokenise identifiers, band money by magnitude, and
allow only what a human confirmed as NONE -- which destinations may still escalate.

``min_cell_size`` is the contract's default of 20, stricter than the brief's k=10."""


class PolicyRegistry:
    """Every version of every policy and guardrail ever published. Append-only."""

    def __init__(self, *, ledger: EgressLedger) -> None:
        self._ledger = ledger
        self._policies: dict[str, list[RedactionPolicy]] = {}
        self._guardrails: dict[str, list[Guardrail]] = {}

    def publish_policy(self, policy: RedactionPolicy, *, actor: str, at: Instant) -> None:
        """Publish the next version of a policy. Version must be exactly latest + 1."""
        history = self._policies.setdefault(policy.policy_id, [])
        self._check_version(policy.version, len(history))
        history.append(policy)
        self._ledger.append_audit(
            audit_event(
                action="policy.publish",
                actor=actor,
                subject_kind="redaction_policy",
                subject_id=f"{policy.policy_id}@{policy.version}",
                at=at,
                detail=policy.model_dump(mode="json"),
                plane=Plane.CONTROL,
            )
        )

    def publish_guardrail(self, guardrail: Guardrail, *, actor: str, at: Instant) -> None:
        """Publish the next version of a guardrail. Version must be exactly latest + 1."""
        history = self._guardrails.setdefault(guardrail.guardrail_id, [])
        self._check_version(guardrail.version, len(history))
        history.append(guardrail)
        self._ledger.append_audit(
            audit_event(
                action="guardrail.publish",
                actor=actor,
                subject_kind="guardrail",
                subject_id=f"{guardrail.guardrail_id}@{guardrail.version}",
                at=at,
                detail=guardrail.model_dump(mode="json"),
                plane=Plane.CONTROL,
            )
        )

    def policy(self, policy_id: str, version: int | None = None) -> RedactionPolicy:
        """A specific version, or the latest. Old versions stay readable forever."""
        history = self._policies.get(policy_id)
        if not history:
            raise KeyError("unknown policy")
        if version is None:
            return history[-1]
        if not 1 <= version <= len(history):
            raise KeyError("unknown policy version")
        return history[version - 1]

    def active_guardrails(self) -> tuple[Guardrail, ...]:
        """The latest version of each guardrail, enabled or not, ordered by id."""
        return tuple(self._guardrails[gid][-1] for gid in sorted(self._guardrails))

    def guardrail_history(self, guardrail_id: str) -> tuple[Guardrail, ...]:
        """Every version of one guardrail, oldest first."""
        return tuple(self._guardrails.get(guardrail_id, ()))

    @staticmethod
    def _check_version(version: int, published: int) -> None:
        if version != published + 1:
            raise PolicyVersionError(
                f"expected version {published + 1}; versions are append-only, never edited"
            )
