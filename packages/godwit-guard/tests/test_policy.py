"""Policy as data, and provider controls."""

from __future__ import annotations

import datetime as _dt

import pytest
from _guard_support import cond, guardrail
from godwit_contracts import GuardrailAction, GuardrailAttribute, RedactionAction
from godwit_guard import (
    DEFAULT_POLICY,
    MemoryLedger,
    PolicyRegistry,
    PolicyVersionError,
    ProviderKind,
    ProviderPolicy,
    ProviderProfile,
    ProviderRefusedError,
    select_provider,
)


def test_the_default_policy_is_deny_by_default() -> None:
    assert DEFAULT_POLICY.default_action is RedactionAction.SUPPRESS
    assert DEFAULT_POLICY.min_cell_size >= 10


def test_policies_are_versioned_audited_and_never_edited(at: _dt.datetime) -> None:
    ledger = MemoryLedger()
    registry = PolicyRegistry(ledger=ledger)
    registry.publish_policy(DEFAULT_POLICY, actor="dpo", at=at)
    v2 = DEFAULT_POLICY.model_copy(update={"version": 2, "min_cell_size": 50})
    registry.publish_policy(v2, actor="dpo", at=at)
    with pytest.raises(PolicyVersionError):
        registry.publish_policy(v2, actor="dpo", at=at)
    with pytest.raises(PolicyVersionError):
        registry.publish_policy(DEFAULT_POLICY.model_copy(update={"version": 7}), actor="x", at=at)
    assert registry.policy("godwit.default").min_cell_size == 50
    assert registry.policy("godwit.default", 1) == DEFAULT_POLICY, "years later, still there"
    assert ledger.actions() == ("policy.publish", "policy.publish")


def test_guardrails_are_versioned_too(at: _dt.datetime) -> None:
    ledger = MemoryLedger()
    registry = PolicyRegistry(ledger=ledger)
    g1 = guardrail(
        "g", GuardrailAction.DENY, cond(GuardrailAttribute.PII_CLASS, "eq", "health"), at=at
    )
    registry.publish_guardrail(g1, actor="dpo", at=at)
    registry.publish_guardrail(
        g1.model_copy(update={"version": 2, "enabled": False}), actor="dpo", at=at
    )
    assert [g.version for g in registry.guardrail_history("g")] == [1, 2]
    assert registry.active_guardrails()[0].enabled is False
    assert ledger.actions() == ("guardrail.publish", "guardrail.publish")


def _provider(pid: str, kind: ProviderKind, region: str, zero: bool) -> ProviderProfile:
    return ProviderProfile(
        provider_id=pid,
        kind=kind,
        region=region,
        zero_retention=zero,
        model_name="m",
        quality_note="",
    )


def test_provider_routing_honours_retention_residency_and_local_only() -> None:
    hosted_us = _provider("a_hosted_us", ProviderKind.HOSTED, "us-east-1", True)
    hosted_eu_retains = _provider("b_hosted_eu", ProviderKind.HOSTED, "eu-west-1", False)
    local = _provider("c_local", ProviderKind.LOCAL, "on-prem", True)
    everything = (hosted_us, hosted_eu_retains, local)
    assert select_provider(ProviderPolicy(), (hosted_us, hosted_eu_retains)) == hosted_us
    assert select_provider(ProviderPolicy(), everything) == local, "local preferred"
    eu_only = ProviderPolicy(allowed_regions=("eu-west-1",))
    with pytest.raises(ProviderRefusedError):
        select_provider(eu_only, everything)
    assert select_provider(ProviderPolicy(local_only=True), everything) == local
    with pytest.raises(ProviderRefusedError):
        select_provider(ProviderPolicy(local_only=True), (hosted_us,))
