"""The egress gate: deny by default, destinations, guardrails, the record, and forgery."""

from __future__ import annotations

import ast
import copy
import datetime as _dt
import pickle
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from _guard_support import SCOPE, classify, cond, guardrail, make_gate, stat, value
from godwit_contracts import (
    Acquisition,
    ApprovalStatus,
    Destination,
    EgressGate,
    EgressRecord,
    EvidenceKind,
    ForgedObjectError,
    Guardrail,
    GuardrailAction,
    GuardrailAttribute,
    IssuerAlreadyClaimedError,
    PiiClass,
    RedactionPolicy,
    SafePayload,
    SafePayloadIssuer,
    SealedConstructionError,
    Tainted,
    canonical_json,
    claim_safe_payload_issuer,
    content_hash,
    issuer_claimant,
    schema_name,
)
from godwit_guard import (
    DEFAULT_POLICY,
    GATE_CLAIMANT,
    ApprovalRequiredError,
    Backstop,
    BackstopHitError,
    ClassificationRegistry,
    EgressOptions,
    EgressRefusedError,
    Gate,
    LedgerWriteError,
    RefusalReason,
    StoreLedger,
)
from godwit_guard.access import AccessMode

A = GuardrailAttribute
LLM = Destination.LLM_PROVIDER


@pytest.fixture
def registry(at: _dt.datetime) -> ClassificationRegistry:
    reg = ClassificationRegistry()
    classify(reg, "merchant_name", at=at, confirm=PiiClass.QUASI_IDENTIFIER)
    classify(reg, "country", at=at, confirm=PiiClass.NONE)
    classify(reg, "customer_ssn", at=at, confirm=PiiClass.DIRECT_IDENTIFIER)
    classify(reg, "pending_review", at=at, confirm=None, sample=["alpha"])
    return reg


def _clear(
    gate: Gate,
    at: _dt.datetime,
    fields: Mapping[str, Tainted[Any]],
    destination: Any = LLM,
    guardrails: Sequence[Guardrail] = (),
    policy: RedactionPolicy | None = DEFAULT_POLICY,
    **opts: Any,
) -> tuple[SafePayload, EgressRecord]:
    return gate.clear(
        fields=fields,
        destination=destination,
        purpose="explain_pattern",
        policy=policy,
        guardrails=guardrails,
        actor="godwit-llm",
        occurred_at=at,
        options=EgressOptions(token_scope=SCOPE, **opts),
    )


def _reason(excinfo: pytest.ExceptionInfo[EgressRefusedError]) -> RefusalReason:
    return excinfo.value.refusal.reason


# --------------------------------------------------------------------------------------
# The happy path, and law 1: record before payload
# --------------------------------------------------------------------------------------


def test_the_record_is_written_first_and_matches_the_payload(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, ledger, _ = make_gate(registry, at=at)
    payload, record = _clear(
        gate, at, {"merchant": value("ACME_CORP", "merchant_name"), "rate": stat(0.42)}
    )
    assert isinstance(gate, EgressGate)
    assert dict(payload.fields) == {"merchant": "MERCHANT_1", "rate": 0.42}
    assert ledger.egress[0][0] == record
    assert payload.egress_record_id == record.record_id
    assert payload.digest == record.content_digest
    assert record.content_digest == content_hash(canonical_json(dict(payload.fields)))
    assert record.field_names == ("merchant", "rate")
    assert ledger.egress[0][1] is not None and ledger.egress[0][1].startswith("tmap_")
    assert (payload.policy_id, payload.policy_version) == ("godwit.default", 1)
    assert "ACME" not in record.model_dump_json()


def test_if_the_record_cannot_be_written_nothing_leaves(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    class Broken:
        def append_egress(self, record: object, *, token_map_ref: str | None) -> None:
            del record, token_map_ref
            raise OSError("disk full")

        def append_audit(self, event: object) -> None:
            del event

    gate, _, _ = make_gate(registry, at=at)
    gate._ledger = Broken()
    with pytest.raises(LedgerWriteError) as caught:
        _clear(gate, at, {"rate": stat(0.42)})
    assert _reason(caught) is RefusalReason.LEDGER_UNAVAILABLE


def test_records_go_through_the_store_ledger(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    """The production path: A3's append-only, hash-chained ledger."""
    from godwit_store.engine import bootstrap_schema, create_store_engine, session_factory
    from godwit_store.ledger import egress_query, verify_chain
    from sqlalchemy.pool import StaticPool

    engine = create_store_engine("sqlite://", poolclass=StaticPool)
    bootstrap_schema(engine)
    factory = session_factory(engine)
    gate, _, _ = make_gate(registry, at=at)
    gate._ledger = StoreLedger(factory)
    _, record = _clear(gate, at, {"merchant": value("ACME_CORP", "merchant_name")})
    with factory() as session:
        [entry] = egress_query(session, content_digest=record.content_digest)
        assert entry.token_map_ref is not None
        chain = verify_chain(session, table="egress_records")
        assert chain.intact and chain.length == 1


# --------------------------------------------------------------------------------------
# Deny by default
# --------------------------------------------------------------------------------------


def test_unknown_destination_is_refused(registry: ClassificationRegistry, at: _dt.datetime) -> None:
    gate, ledger, _ = make_gate(registry, at=at)
    with pytest.raises(EgressRefusedError) as caught:
        _clear(gate, at, {"rate": stat(0.4)}, destination="carrier_pigeon")
    assert _reason(caught) is RefusalReason.UNKNOWN_DESTINATION
    assert ledger.actions() == ("egress.refused.unknown_destination",)


def test_a_destination_without_a_policy_is_refused(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    with pytest.raises(EgressRefusedError) as caught:
        _clear(gate, at, {"rate": stat(0.4)}, destination=Destination.MODEL_ARTIFACT_STORE)
    assert _reason(caught) is RefusalReason.NO_DESTINATION_POLICY


@pytest.mark.parametrize("k", [0, 1])
def test_missing_or_disabled_policy_is_refused(
    registry: ClassificationRegistry, at: _dt.datetime, k: int
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    with pytest.raises(EgressRefusedError) as caught:
        _clear(gate, at, {"rate": stat(0.4)}, policy=None)
    assert _reason(caught) is RefusalReason.MISSING_POLICY
    weak = RedactionPolicy(policy_id="weak", version=1, min_cell_size=k, created_at=at)
    with pytest.raises(EgressRefusedError) as caught:
        _clear(gate, at, {"rate": stat(0.4)}, policy=weak)
    assert _reason(caught) is RefusalReason.INVALID_POLICY


def test_an_unclassified_field_refuses_the_whole_call(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    for tainted in (
        value("x", "customer_email_v2"),
        value(
            "ERROR: Key (customer_ssn)=(100-40-1000)",
            None,
            acquisition=Acquisition.DRIVER_EXCEPTION,
        ),
        schema_name("customer_email_v2", source_id="src_pii", table="customers"),
    ):
        with pytest.raises(EgressRefusedError) as caught:
            _clear(gate, at, {"rate": stat(0.4), "extra": tainted})
        assert _reason(caught) is RefusalReason.UNCLASSIFIED_FIELD


def test_unconfirmed_columns_are_handled_at_their_most_restrictive(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    payload, _ = _clear(gate, at, {"v": value("alpha", "pending_review")})
    assert "v" not in payload.fields  # UNKNOWN-class: suppressed by the default policy


def test_field_names_are_disclosures_too(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    for fields in ({"Bad Name": stat(0.4)}, {"customer_ssn_bucket": value("1", "customer_ssn")}):
        with pytest.raises(EgressRefusedError) as caught:
            _clear(gate, at, fields)
        assert _reason(caught) is RefusalReason.UNSAFE_FIELD_NAME
        assert "customer_ssn" not in str(caught.value)


def test_literals_are_our_vocabulary_only(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    from enum import StrEnum

    gate, _, _ = make_gate(registry, at=at)
    payload, _ = _clear(gate, at, {}, literals={"kind": EvidenceKind.RATE_CHANGE, "ok": True})
    assert dict(payload.fields) == {"kind": "rate_change", "ok": True}

    smuggled = StrEnum("Smuggled", {"SSN": "100-40-1000"})
    for bad in ("100-40-1000", smuggled.SSN, 7):
        with pytest.raises(EgressRefusedError) as caught:
            _clear(gate, at, {}, literals={"x": bad})
        assert _reason(caught) is RefusalReason.UNSUPPORTED_VALUE


# --------------------------------------------------------------------------------------
# Destinations are not collapsed
# --------------------------------------------------------------------------------------


def test_one_value_three_destinations_three_outcomes(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    allow = guardrail(
        "show_country", GuardrailAction.ALLOW, cond(A.COLUMN_NAME, "eq", "country"), at=at
    )
    fields = {"place": value("PT", "country")}
    ui, _ = _clear(gate, at, fields, destination=Destination.UI, guardrails=(allow,))
    llm, _ = _clear(gate, at, fields, guardrails=(allow,))
    log, _ = _clear(gate, at, fields, destination=Destination.LOG, guardrails=(allow,))
    assert ui.fields["place"] == "PT"
    assert llm.fields["place"] == "COUNTRY_1"
    assert "place" not in log.fields


# --------------------------------------------------------------------------------------
# Guardrails: DENY > REQUIRE_APPROVAL > REDACT > ALLOW
# --------------------------------------------------------------------------------------


def test_deny_beats_allow(registry: ClassificationRegistry, at: _dt.datetime) -> None:
    gate, ledger, _ = make_gate(registry, at=at)
    allow = guardrail("a", GuardrailAction.ALLOW, cond(A.COLUMN_NAME, "eq", "country"), at=at)
    deny = guardrail("d", GuardrailAction.DENY, cond(A.DESTINATION, "eq", "ui"), at=at)
    with pytest.raises(EgressRefusedError) as caught:
        _clear(
            gate,
            at,
            {"place": value("PT", "country")},
            destination=Destination.UI,
            guardrails=(allow, deny),
        )
    assert _reason(caught) is RefusalReason.GUARDRAIL_DENY
    assert caught.value.refusal.guardrail_ids == ("a", "d")
    assert ledger.egress == []


def test_a_restrictive_rule_fires_on_unknown_population(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    deny_small = guardrail("small", GuardrailAction.DENY, cond(A.POPULATION, "lt", 50), at=at)
    with pytest.raises(EgressRefusedError):
        _clear(
            gate,
            at,
            {"m": value("ACME", "merchant_name", population=None)},
            guardrails=(deny_small,),
        )
    payload, _ = _clear(
        gate, at, {"m": value("ACME", "merchant_name", population=500)}, guardrails=(deny_small,)
    )
    assert payload.fields["m"] == "MERCHANT_1"


def test_approval_is_requested_then_honoured(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    needs = guardrail(
        "review", GuardrailAction.REQUIRE_APPROVAL, cond(A.PURPOSE, "eq", "explain_pattern"), at=at
    )
    fields = {"m": value("ACME_CORP", "merchant_name")}
    with pytest.raises(ApprovalRequiredError) as caught:
        _clear(gate, at, fields, guardrails=(needs,))
    request = caught.value.request
    approved = request.model_copy(
        update={"status": ApprovalStatus.APPROVED, "decided_by": "dpo", "decided_at": at}
    )
    _, record = _clear(gate, at, fields, guardrails=(needs,), approval=approved)
    assert record.approval_id == request.request_id
    other = {"n": value("ACME_CORP", "merchant_name")}
    with pytest.raises(ApprovalRequiredError):
        _clear(gate, at, other, guardrails=(needs,), approval=approved)


def test_redact_forbids_allow(registry: ClassificationRegistry, at: _dt.datetime) -> None:
    gate, _, _ = make_gate(registry, at=at)
    allow = guardrail("a", GuardrailAction.ALLOW, cond(A.COLUMN_NAME, "eq", "country"), at=at)
    redact = guardrail("r", GuardrailAction.REDACT, cond(A.PII_CLASS, "eq", "none"), at=at)
    payload, record = _clear(
        gate,
        at,
        {"place": value("PT", "country")},
        destination=Destination.UI,
        guardrails=(allow, redact),
    )
    assert payload.fields["place"] == "COUNTRY_1"
    assert record.guardrail_ids == ("a", "r")


# --------------------------------------------------------------------------------------
# The backstop, as the gate uses it
# --------------------------------------------------------------------------------------


def test_a_mislabelled_value_is_caught_as_a_defect(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    """Someone confirmed a column NONE and it carries SSNs. The taint system was wrong."""
    paged: list[object] = []
    reg = registry
    classify(reg, "reference", at=at, confirm=PiiClass.NONE)
    gate, ledger, _ = make_gate(
        reg, at=at, backstop=Backstop(use_presidio=False, pager=paged.append)
    )
    allow = guardrail("a", GuardrailAction.ALLOW, cond(A.COLUMN_NAME, "eq", "reference"), at=at)
    with pytest.raises(BackstopHitError) as caught:
        _clear(
            gate,
            at,
            {"ref": value("100-40-1000", "reference")},
            destination=Destination.UI,
            guardrails=(allow,),
        )
    assert "DEFECT" in caught.value.refusal.detail
    assert "egress.backstop_hit" in ledger.actions()
    assert paged and gate.backstop.metrics.hit_rate == 1.0
    assert ledger.egress == []


# --------------------------------------------------------------------------------------
# SafePayload cannot be produced anywhere but here
# --------------------------------------------------------------------------------------


def test_adversarial_attempts_to_forge_a_payload(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    genuine, _ = _clear(gate, at, {"rate": stat(0.4)})

    with pytest.raises(SealedConstructionError):
        SafePayload()
    with pytest.raises(SealedConstructionError):
        SafePayload.__new__(SafePayload)
    husk = object.__new__(SafePayload)
    with pytest.raises(ForgedObjectError):
        _ = husk.fields
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(SealedConstructionError):
            clone(genuine)
    with pytest.raises(TypeError, match="final"):
        type("Forged", (SafePayload,), {})
    with pytest.raises(SealedConstructionError):
        SafePayloadIssuer()
    assert issuer_claimant() == GATE_CLAIMANT
    with pytest.raises(IssuerAlreadyClaimedError):
        claim_safe_payload_issuer(claimant="an_eager_helper")
    with pytest.raises(TypeError):
        genuine.fields["rate"] = 1.0  # type: ignore[index]


def _mints(source: str) -> bool:
    """True if the module imports the claim function, calls it, or calls ``.issue(...)``
    with a ``purpose=`` keyword -- the shapes of minting a payload. Parsed, not grepped,
    so a docstring that merely names the issuer is not an offender."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and any(
            alias.name in {"claim_safe_payload_issuer", "SafePayloadIssuer"} for alias in node.names
        ):
            return True
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name == "claim_safe_payload_issuer":
                return True
            if name == "issue" and any(k.arg == "purpose" for k in node.keywords):
                return True
    return False


def test_nothing_else_in_the_workspace_mints_payloads() -> None:
    """Static check over every package's source: only the gate claims or issues."""
    root = Path(__file__).resolve().parents[3]
    allowed = {
        root / "packages/godwit-contracts/src/godwit_contracts/safe.py",
        root / "packages/godwit-contracts/src/godwit_contracts/__init__.py",
        root / "packages/godwit-guard/src/godwit_guard/gate.py",
    }
    offenders = [
        str(path.relative_to(root))
        for path in sorted(root.glob("packages/*/src/**/*.py"))
        if path not in allowed and _mints(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_a_raw_value_cannot_even_be_offered(
    registry: ClassificationRegistry, at: _dt.datetime
) -> None:
    gate, _, _ = make_gate(registry, at=at)
    with pytest.raises(AttributeError):
        _clear(gate, at, {"ssn": "100-40-1000"})  # type: ignore[dict-item]
    assert AccessMode.BLIND.value == "blind"
