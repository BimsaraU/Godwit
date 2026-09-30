"""Transforms and the redactor: bucket, generalise, hash, tokenise-and-restore."""

from __future__ import annotations

import copy
import datetime as _dt
import pickle
from decimal import Decimal

import pytest
from _guard_support import SCOPE, classify, col_ref, make_vault, record_entropy, stat, value
from godwit_contracts import (
    Acquisition,
    Destination,
    LogicalType,
    PiiClass,
    RedactionAction,
    RedactionPolicy,
    RedactionRule,
    Redactor,
    Sensitivity,
)
from godwit_guard import (
    DEFAULT_POLICY,
    AccessControl,
    ClassificationRegistry,
    KeyedHasher,
    MemoryLedger,
    PolicyRedactor,
    TokenScopeError,
    bucket,
    generalise,
    mapping_hierarchy,
)
from hypothesis import given
from hypothesis import strategies as st


def test_bucket_numbers_and_dates() -> None:
    assert bucket(41000, {"width": 10000}) == "[40000, 50000)"
    assert bucket(-5, {"width": 10}) == "[-10, 0)"
    assert bucket(Decimal("12.5"), {"width": 2.5}) == "[12.5, 15)"
    assert bucket(_dt.date(2024, 5, 17), {"period": "quarter"}) == "2024-Q2"
    assert bucket(_dt.date(2024, 5, 17), {"period": "year"}) == "2024"
    assert bucket("not a number", {"width": 10}) is None
    assert bucket(5, {"width": 0}) is None


def test_generalise_hierarchies() -> None:
    assert generalise("SW1A 1AA", {"hierarchy": "postcode", "level": 1}) == "SW1A"
    assert generalise("SW1A 1AA", {"hierarchy": "postcode", "level": 2}) == "SW"
    assert generalise("94107", {"hierarchy": "postcode"}) == "941**"
    assert generalise(58050, {"hierarchy": "magnitude"}) == "[10000, 100000)"
    assert generalise("ACME_CORP", {"hierarchy": "prefix", "level": 2}) == "AC*"
    occupations = {
        "occupation": mapping_hierarchy(
            {"surgeon": "healthcare", "nurse": "healthcare"}, default="other"
        )
    }
    assert generalise("Surgeon", {"hierarchy": "occupation"}, occupations) == "healthcare"
    assert generalise("pilot", {"hierarchy": "occupation"}, occupations) == "other"
    assert generalise("x", {"hierarchy": "no_such_thing"}) is None


# --------------------------------------------------------------------------------------
# Tokenise and restore
# --------------------------------------------------------------------------------------


def test_tokens_are_stable_within_a_scope_and_unlinkable_across_scopes(at: _dt.datetime) -> None:
    vault = make_vault(at)
    vault.open_scope("pattern_2", expires_at=at + _dt.timedelta(days=1))
    acme = value("ACME_CORP", "merchant_name")
    other = value("vendor_01", "merchant_name")
    first = vault.tokenise(acme, scope_id=SCOPE, namespace="MERCHANT", at=at)
    second = vault.tokenise(other, scope_id=SCOPE, namespace="MERCHANT", at=at)
    again = vault.tokenise(acme, scope_id=SCOPE, namespace="MERCHANT", at=at)
    elsewhere = vault.tokenise(other, scope_id="pattern_2", namespace="MERCHANT", at=at)
    assert (first.reveal(), second.reveal(), again.reveal()) == (
        "MERCHANT_1",
        "MERCHANT_2",
        "MERCHANT_1",
    )
    assert elsewhere.reveal() == "MERCHANT_1", "numbering restarts: no cross-scope linkage"
    assert first.sensitivity is Sensitivity.TOKEN
    assert first.provenance.upstream == acme.provenance


def test_restore_round_trips_for_permitted_roles_only(at: _dt.datetime) -> None:
    vault = make_vault(at)
    tok = vault.tokenise(
        value("ACME_CORP", "merchant_name"), scope_id=SCOPE, namespace="MERCHANT", at=at
    ).reveal()
    narrative = f"Refunds at {tok} rose sharply; COVID_19 and MERCHANT_99 are unrelated."
    restored = vault.restore(narrative, scope_id=SCOPE, roles=frozenset({"investigator"}), at=at)
    assert restored.reveal().startswith("Refunds at ACME_CORP rose")
    assert "COVID_19 and MERCHANT_99" in restored.reveal()
    assert restored.sensitivity is Sensitivity.DATA_VALUE
    denied = vault.restore(narrative, scope_id=SCOPE, roles=frozenset({"analyst"}), at=at)
    assert denied.reveal() == narrative


def test_scopes_expire_and_are_purged(at: _dt.datetime) -> None:
    vault = make_vault(at)
    vault.tokenise(value("x1234", "merchant_name"), scope_id=SCOPE, namespace="M", at=at)
    later = at + _dt.timedelta(days=31)
    with pytest.raises(TokenScopeError, match="expired"):
        vault.restore("M_1", scope_id=SCOPE, roles=frozenset({"investigator"}), at=later)
    assert vault.purge_expired(at=later) == 1
    with pytest.raises(TokenScopeError, match="unknown"):
        vault.tokenise(value("x", "m"), scope_id=SCOPE, namespace="M", at=at)


def test_the_token_map_cannot_leave(at: _dt.datetime) -> None:
    vault = make_vault(at)
    vault.tokenise(value("ACME_CORP", "merchant_name"), scope_id=SCOPE, namespace="M", at=at)
    assert "ACME" not in repr(vault)
    for attempt in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            attempt(vault)
    ref = vault.map_ref(SCOPE)
    assert ref.startswith("tmap_") and "ACME" not in ref


def test_namespaces_come_from_policy_not_data(at: _dt.datetime) -> None:
    vault = make_vault(at)
    with pytest.raises(ValueError, match="namespace"):
        vault.tokenise(value("x", "m"), scope_id=SCOPE, namespace="acme corp", at=at)


# --------------------------------------------------------------------------------------
# The redactor and its five laws
# --------------------------------------------------------------------------------------


@pytest.fixture
def registry(at: _dt.datetime) -> ClassificationRegistry:
    reg = ClassificationRegistry()
    classify(reg, "merchant_name", at=at, confirm=PiiClass.QUASI_IDENTIFIER)
    classify(reg, "country", at=at, confirm=PiiClass.NONE)
    classify(reg, "patient_hiv_status", at=at, confirm=PiiClass.HEALTH)
    classify(reg, "salary_2024", LogicalType.INT, at=at, confirm=PiiClass.FINANCIAL)
    classify(reg, "card_pin", at=at, confirm=PiiClass.QUASI_IDENTIFIER)
    return reg


def _redactor(registry: ClassificationRegistry, at: _dt.datetime, **kw: object) -> PolicyRedactor:
    return PolicyRedactor(registry=registry, at=at, vault=make_vault(at), scope_id=SCOPE, **kw)


def test_it_is_a_redactor(registry: ClassificationRegistry, at: _dt.datetime) -> None:
    assert isinstance(_redactor(registry, at), Redactor)


def test_small_cells_go_first(registry: ClassificationRegistry, at: _dt.datetime) -> None:
    r = _redactor(registry, at)
    assert (
        r.redact(
            value("PT", "country", population=3), policy=DEFAULT_POLICY, destination=Destination.UI
        )
        is None
    )
    assert (
        r.redact(stat(0.4, population=None), policy=DEFAULT_POLICY, destination=Destination.UI)
        is None
    )


def test_quantiles_and_extrema_need_a_large_population(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    r = _redactor(registry, at)
    median = value(58050.0, "salary_2024", acquisition=Acquisition.QUANTILE, population=50)
    bound = value(
        41000, "salary_2024", acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS, population=50
    )
    for v in (median, bound):
        assert r.redact(v, policy=DEFAULT_POLICY, destination=Destination.UI) is None


def test_actions_per_class_and_destination(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    r = _redactor(registry, at)

    def decide(v: object, dest: Destination, **kw: bool) -> tuple[RedactionAction, object]:
        d = r.decide(v, policy=DEFAULT_POLICY, destination=dest, **kw)
        return d.action, d.scalar

    assert decide(value("ACME_CORP", "merchant_name"), Destination.LLM_PROVIDER) == (
        RedactionAction.TOKENISE,
        "MERCHANT_1",
    )
    assert decide(value("positive", "patient_hiv_status"), Destination.UI)[0] is (
        RedactionAction.SUPPRESS
    )
    assert decide(value(58050, "salary_2024"), Destination.LLM_PROVIDER) == (
        RedactionAction.GENERALISE,
        "[10000, 100000)",
    )
    # NONE is ALLOW by policy, but raw values need an ALLOW guardrail, and never go to an LLM.
    assert decide(value("PT", "country"), Destination.UI)[0] is RedactionAction.TOKENISE
    assert decide(value("PT", "country"), Destination.UI, allow_authorised=True) == (
        RedactionAction.ALLOW,
        "PT",
    )
    assert (
        decide(value("PT", "country"), Destination.LLM_PROVIDER, allow_authorised=True)[0]
        is RedactionAction.TOKENISE
    )
    assert (
        decide(value("PT", "country"), Destination.UI, allow_authorised=True, force_redact=True)[0]
        is RedactionAction.TOKENISE
    )
    assert (
        decide(value("PT", "country"), Destination.LOG, allow_authorised=True)[0]
        is RedactionAction.SUPPRESS
    )


def test_unclassified_is_flagged_not_passed(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    decision = _redactor(registry, at).decide(
        value("x", "brand_new_column"), policy=DEFAULT_POLICY, destination=Destination.UI
    )
    assert decision.unclassified and not decision.emitted


def test_hash_is_refused_for_an_enumerable_column(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    access = AccessControl(registry, ledger=MemoryLedger())
    pins = ["0427", "1234"]
    record_entropy(access, col_ref("card_pin"), LogicalType.STRING, pins)
    modes = access.mode_map(guardrails=(), at=at)
    policy = RedactionPolicy(
        policy_id="p",
        version=1,
        created_at=at,
        rules=(RedactionRule(pii_class=PiiClass.QUASI_IDENTIFIER, action=RedactionAction.HASH),),
    )
    r = PolicyRedactor(
        registry=registry, at=at, hasher=KeyedHasher(b"k" * 32, key_id="k"), modes=modes
    )
    pin = r.decide(value("0427", "card_pin"), policy=policy, destination=Destination.EXPORT_FILE)
    assert pin.action is RedactionAction.SUPPRESS and "hash refused" in pin.reason


def test_deterministic(registry: ClassificationRegistry, at: _dt.datetime) -> None:
    runs = [
        _redactor(registry, at)
        .decide(
            value("ACME_CORP", "merchant_name"),
            policy=DEFAULT_POLICY,
            destination=Destination.LLM_PROVIDER,
        )
        .scalar
        for _ in range(3)
    ]
    assert len(set(runs)) == 1


@given(
    raw=st.one_of(st.text(max_size=20), st.integers(), st.floats(allow_nan=True)),
    column=st.sampled_from(["merchant_name", "country", "patient_hiv_status", "salary_2024"]),
    population=st.one_of(st.none(), st.integers(min_value=0, max_value=10**6)),
    authorised=st.booleans(),
)
def test_no_raw_data_value_ever_reaches_an_llm(
    raw: object, column: str, population: int | None, authorised: bool
) -> None:
    """Monotone and total: whatever comes in, an LLM gets a token, a band, or nothing."""
    at = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
    reg = ClassificationRegistry()
    for name, pii in (
        ("merchant_name", PiiClass.QUASI_IDENTIFIER),
        ("country", PiiClass.NONE),
        ("patient_hiv_status", PiiClass.HEALTH),
        ("salary_2024", PiiClass.FINANCIAL),
    ):
        classify(reg, name, at=at, confirm=pii)
    decision = _redactor(reg, at).decide(
        value(raw, column, population=population),
        policy=DEFAULT_POLICY,
        destination=Destination.LLM_PROVIDER,
        allow_authorised=authorised,
    )
    assert decision.action is not RedactionAction.ALLOW
    assert decision.action is not RedactionAction.HASH
