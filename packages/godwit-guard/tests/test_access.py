"""Access modes, grants, the entropy check -- and the enumeration attack that motivates it."""

from __future__ import annotations

import datetime as _dt
from collections import Counter

import pytest
from _guard_support import classify, col_ref, cond, guardrail, record_entropy
from godwit_contracts import (
    ColumnRole,
    Destination,
    GuardrailAction,
    GuardrailAttribute,
    LogicalType,
    PiiClass,
)
from godwit_guard import (
    AccessControl,
    AccessGrant,
    AccessMode,
    ClassificationRegistry,
    KeyedHasher,
    MemoryLedger,
    Narrowing,
    OpaqueHashRefusedError,
    ProjectionViolationError,
    Remediation,
    assess_entropy,
    format_space_bits,
    plan_projection,
    verify_arrow_schema,
    verify_sql,
)
from godwit_guard.errors import GrantError

KEY = b"k" * 32
type World = tuple[ClassificationRegistry, AccessControl, MemoryLedger]
A = GuardrailAttribute


@pytest.fixture
def world() -> World:
    registry = ClassificationRegistry()
    ledger = MemoryLedger()
    return registry, AccessControl(registry, ledger=ledger), ledger


def _grant(ref: object, at: _dt.datetime, **overrides: object) -> AccessGrant:
    fields: dict[str, object] = {
        "grant_id": "g1",
        "column": ref,
        "from_mode": AccessMode.OPAQUE,
        "to_mode": AccessMode.OPEN,
        "reason": "fraud investigation 42",
        "requested_by": "analyst",
        "approved_by": "dpo",
        "granted_at": at,
        "expires_at": at + _dt.timedelta(days=7),
        "authorising_guardrail_id": "allow_email",
    }
    fields.update(overrides)
    return AccessGrant.model_validate(fields)


# --------------------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------------------


def test_unknown_and_unconfirmed_columns_are_blind(world: World, at: _dt.datetime) -> None:
    registry, access, _ = world
    ref = classify(registry, "customer_email_v2", at=at, confirm=None)
    assert access.resolve(ref, guardrails=(), at=at).mode is AccessMode.BLIND
    assert access.resolve(col_ref("never_seen"), guardrails=(), at=at).mode is AccessMode.BLIND
    access.grant(
        _grant(
            ref,
            at,
            from_mode=AccessMode.BLIND,
            to_mode=AccessMode.OPAQUE,
            authorising_guardrail_id=None,
        ),
        actor="dpo",
    )
    assert access.resolve(ref, guardrails=(), at=at).mode is AccessMode.BLIND, (
        "grants cannot rescue"
    )


def test_identifiers_default_to_opaque_when_entropy_allows(world: World, at: _dt.datetime) -> None:
    registry, access, _ = world
    emails = [f"user{i}@bank.test" for i in range(50)]
    ref = classify(registry, "email", at=at, confirm=PiiClass.DIRECT_IDENTIFIER, sample=emails)
    record_entropy(access, ref, LogicalType.STRING, emails)
    decision = access.resolve(ref, guardrails=(), at=at)
    assert decision.mode is AccessMode.OPAQUE
    assert decision.entropy is not None and decision.entropy.passed


def test_credentials_and_free_text_are_blind(world: World, at: _dt.datetime) -> None:
    registry, access, _ = world
    secret = classify(registry, "api_key", at=at, confirm=PiiClass.CREDENTIAL)
    notes = classify(
        registry, "notes", at=at, confirm=PiiClass.SENSITIVE_ATTRIBUTE, role=ColumnRole.FREE_TEXT
    )
    assert access.resolve(secret, guardrails=(), at=at).mode is AccessMode.BLIND
    assert access.resolve(notes, guardrails=(), at=at).mode is AccessMode.BLIND


def test_no_entropy_assessment_means_no_hashing(world: World, at: _dt.datetime) -> None:
    registry, access, _ = world
    ref = classify(registry, "device_id", at=at, confirm=PiiClass.QUASI_IDENTIFIER)
    decision = access.resolve(ref, guardrails=(), at=at)
    assert decision.mode is AccessMode.BLIND
    assert decision.remediation is Remediation.BLIND


# --------------------------------------------------------------------------------------
# The entropy check, and the attacks that make it necessary
# --------------------------------------------------------------------------------------


def test_worked_enumeration_attack_recovers_every_hashed_pin(
    world: World, at: _dt.datetime
) -> None:
    """A keyed hash of a four-digit PIN is a lookup table away from the PINs.

    The attacker holds the hashes and -- after a key compromise, or with an unkeyed hash
    -- the ability to compute the function. 10^4 candidates. Every value comes back.
    """
    pins = ["0427", "1234", "9981", "0000", "5550", "3141", "2718", "8008"]
    hasher = KeyedHasher(KEY, key_id="k1")
    leaked_hashes = [hasher.digest(pin) for pin in pins]

    rainbow = {hasher.digest(f"{n:04d}"): f"{n:04d}" for n in range(10_000)}
    recovered = [rainbow[h] for h in leaked_hashes]
    assert recovered == pins, "the enumeration recovers every PIN: hashing it was not safe"

    assessment = assess_entropy(
        column_name="card_pin",
        logical_type=LogicalType.STRING,
        observed_distinct=len(pins),
        format_bits=format_space_bits(pins),
    )
    assert assessment.bits < 14 and not assessment.passed

    registry, access, _ = world
    ref = classify(registry, "card_pin", at=at, confirm=PiiClass.QUASI_IDENTIFIER, sample=pins)
    access.record_entropy(ref, assessment)
    decision = access.resolve(ref, guardrails=(), at=at)
    assert decision.mode is AccessMode.BLIND
    assert decision.remediation is Remediation.BUCKET
    with pytest.raises(OpaqueHashRefusedError, match="enumerable"):
        hasher.hash_for("0427", decision=decision.model_copy(update={"mode": AccessMode.OPAQUE}))


def test_frequency_attack_needs_no_key_at_all() -> None:
    """Without the key, a hashed country column is still a relabelled country column.

    Rank the hashes by frequency, rank public country shares, zip them. Done.
    """
    hasher = KeyedHasher(b"s" * 32, key_id="secret")
    population = ["US"] * 50 + ["GB"] * 20 + ["DE"] * 15 + ["FR"] * 10 + ["PT"] * 5
    hashed = [hasher.digest(c) for c in population]
    public_ranking = ["US", "GB", "DE", "FR", "PT"]
    by_frequency = [h for h, _ in Counter(hashed).most_common()]
    guess = dict(zip(by_frequency, public_ranking, strict=True))
    assert [guess[h] for h in hashed] == population
    assessment = assess_entropy(
        column_name="country",
        logical_type=LogicalType.STRING,
        observed_distinct=5,
        format_bits=format_space_bits(["US"]),
    )
    assert not assessment.passed


@pytest.mark.parametrize(
    ("name", "logical", "sample", "passes"),
    [
        ("postcode", LogicalType.STRING, ["SW1A 1AA"], False),
        ("date_of_birth", LogicalType.DATE, [], False),
        ("nic_prefix", LogicalType.STRING, ["19901"], False),
        ("gender", LogicalType.STRING, ["F", "M"], False),
        ("email", LogicalType.STRING, ["a.person@bank.test"], True),
        ("device_id", LogicalType.STRING, ["dev-0000-a4f7723b"], True),
        ("customer_ssn", LogicalType.STRING, ["100-40-1000"], True),
    ],
)
def test_entropy_priors(name: str, logical: LogicalType, sample: list[str], passes: bool) -> None:
    assessment = assess_entropy(
        column_name=name,
        logical_type=logical,
        observed_distinct=len(sample) or None,
        format_bits=format_space_bits(sample),
    )
    assert assessment.passed is passes


def test_raising_min_bits_to_40_blinds_ssn_against_key_compromise() -> None:
    assessment = assess_entropy(
        column_name="customer_ssn",
        logical_type=LogicalType.STRING,
        observed_distinct=12,
        format_bits=format_space_bits(["100-40-1000"]),
        min_bits=40,
    )
    assert not assessment.passed


def test_the_hasher_refuses_to_render_or_serialise_its_key() -> None:
    hasher = KeyedHasher(KEY, key_id="k1")
    assert "kkkk" not in repr(hasher)
    with pytest.raises(TypeError):
        __import__("pickle").dumps(hasher)
    with pytest.raises(ValueError, match="32 bytes"):
        KeyedHasher(b"short", key_id="k")


# --------------------------------------------------------------------------------------
# Grants, guardrails, narrowing
# --------------------------------------------------------------------------------------


def _email_world(world: World, at: _dt.datetime) -> object:
    registry, access, _ = world
    emails = [f"user{i}@bank.test" for i in range(50)]
    ref = classify(registry, "email", at=at, confirm=PiiClass.DIRECT_IDENTIFIER, sample=emails)
    record_entropy(access, ref, LogicalType.STRING, emails)
    return ref


def test_widening_to_open_needs_a_grant_and_an_allow_guardrail(
    world: World, at: _dt.datetime
) -> None:
    _, access, ledger = world
    ref = _email_world(world, at)
    allow = guardrail(
        "allow_email", GuardrailAction.ALLOW, cond(A.COLUMN_NAME, "eq", "email"), at=at
    )
    assert access.resolve(ref, guardrails=(allow,), at=at).mode is AccessMode.OPAQUE
    access.grant(_grant(ref, at), actor="dpo")
    assert access.resolve(ref, guardrails=(allow,), at=at).mode is AccessMode.OPEN
    ignored = access.resolve(ref, guardrails=(), at=at)
    assert ignored.mode is AccessMode.OPAQUE
    assert any("no matching ALLOW guardrail" in r for r in ignored.reasons)
    assert "access.grant" in ledger.actions()


def test_grants_expire_and_can_be_revoked(world: World, at: _dt.datetime) -> None:
    _, access, ledger = world
    ref = _email_world(world, at)
    allow = guardrail(
        "allow_email", GuardrailAction.ALLOW, cond(A.COLUMN_NAME, "eq", "email"), at=at
    )
    access.grant(_grant(ref, at), actor="dpo")
    later = at + _dt.timedelta(days=8)
    assert access.resolve(ref, guardrails=(allow,), at=later).mode is AccessMode.OPAQUE
    access.revoke("g1", actor="dpo", at=at)
    assert access.resolve(ref, guardrails=(allow,), at=at).mode is AccessMode.OPAQUE
    assert "access.revoke" in ledger.actions()


def test_a_permanent_grant_is_separately_audited(world: World, at: _dt.datetime) -> None:
    _, access, ledger = world
    ref = _email_world(world, at)
    access.grant(_grant(ref, at, expires_at=None, permanent=True), actor="dpo")
    assert ledger.actions().count("access.grant.permanent") == 1


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"approved_by": "analyst"}, "approved by the person"),
        ({"expires_at": None}, "explicitly permanent"),
        ({"to_mode": AccessMode.OPAQUE}, "must widen"),
        ({"authorising_guardrail_id": None}, "authorising ALLOW guardrail"),
        ({"reason": ""}, "at least 1"),
    ],
)
def test_malformed_grants_do_not_construct(
    overrides: dict[str, object], message: str, at: _dt.datetime
) -> None:
    with pytest.raises(ValueError, match=message):
        _grant(col_ref("email"), at, **overrides)


def test_deny_beats_a_grant_and_narrowing_is_immediate(world: World, at: _dt.datetime) -> None:
    _, access, ledger = world
    ref = _email_world(world, at)
    deny = guardrail(
        "deny_email", GuardrailAction.DENY, cond(A.PII_CLASS, "eq", "direct_identifier"), at=at
    )
    assert access.resolve(ref, guardrails=(deny,), at=at).mode is AccessMode.BLIND
    access.narrow(
        Narrowing(
            narrowing_id="n1",
            column=ref,
            to_mode=AccessMode.BLIND,
            reason="incident 7",
            actor="ciso",
            at=at,
        )
    )
    assert access.resolve(ref, guardrails=(), at=at).mode is AccessMode.BLIND
    with pytest.raises(GrantError, match="different approver"):
        access.lift("n1", actor="ciso", approved_by="ciso", reason="resolved", at=at)
    access.lift("n1", actor="ciso", approved_by="dpo", reason="resolved", at=at)
    assert access.resolve(ref, guardrails=(), at=at).mode is AccessMode.OPAQUE
    assert {"access.narrow", "access.lift"} <= set(ledger.actions())


def test_egress_guardrails_do_not_blind_columns(world: World, at: _dt.datetime) -> None:
    """A rule about what reaches an LLM says nothing about what a probe may read."""
    _, access, _ = world
    ref = _email_world(world, at)
    llm_only = guardrail(
        "no_llm",
        GuardrailAction.DENY,
        cond(A.PII_CLASS, "eq", "direct_identifier"),
        at=at,
        destinations=(Destination.LLM_PROVIDER,),
    )
    assert access.resolve(ref, guardrails=(llm_only,), at=at).mode is AccessMode.OPAQUE


def test_the_mode_map_is_queryable_state(world: World, at: _dt.datetime) -> None:
    registry, access, _ = world
    _email_world(world, at)
    classify(registry, "country", at=at, confirm=PiiClass.NONE)
    classify(registry, "notes", at=at, confirm=None)
    mode_map = access.mode_map(guardrails=(), at=at)
    assert mode_map.counts() == {"blind": 1, "opaque": 1, "open": 1}
    assert mode_map.mode_of(col_ref("country")) is AccessMode.OPEN
    assert mode_map.mode_of(col_ref("nobody_classified_this")) is AccessMode.BLIND
    assert AccessMode.OPEN.value in mode_map.model_dump_json()


# --------------------------------------------------------------------------------------
# Plan-time enforcement
# --------------------------------------------------------------------------------------


def test_blind_columns_never_reach_a_plan_sql_or_schema(world: World, at: _dt.datetime) -> None:
    registry, access, _ = world
    _email_world(world, at)
    classify(registry, "country", at=at, confirm=PiiClass.NONE)
    classify(
        registry, "notes", at=at, confirm=PiiClass.SENSITIVE_ATTRIBUTE, role=ColumnRole.FREE_TEXT
    )
    mode_map = access.mode_map(guardrails=(), at=at)
    plan = plan_projection(
        ["email", "country", "notes", "unclassified_new"],
        mode_map,
        source_id="src_pii",
        table="customers",
    )
    assert plan.open_columns == ("country",)
    assert plan.opaque_columns == ("email",)
    assert plan.dropped == ("notes", "unclassified_new")

    verify_sql(
        "SELECT country, count(*) FROM customers WHERE note_kind = 'notes'",
        blind_columns=plan.dropped,
    )
    with pytest.raises(ProjectionViolationError, match="#0") as caught:
        verify_sql(
            "SELECT country FROM customers WHERE \"NOTES\" LIKE '%x%'", blind_columns=plan.dropped
        )
    assert "notes" not in str(caught.value).casefold()

    verify_arrow_schema(
        ["country", "email__opaque"], mode_map, source_id="src_pii", table="customers"
    )
    for bad in (["email"], ["notes"], ["country__opaque"], ["surprise_column"]):
        with pytest.raises(ProjectionViolationError):
            verify_arrow_schema(bad, mode_map, source_id="src_pii", table="customers")
