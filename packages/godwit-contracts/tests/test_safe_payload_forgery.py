"""Five ways to forge a SafePayload, and why each one fails.

This is the difference between a policy and a guarantee. If any test in this file ever
starts passing by producing a usable payload, invariant 2 is no longer enforced by the
type system and the whole gate becomes advisory.
"""

from __future__ import annotations

import copy
import pickle

import pytest
from godwit_contracts import (
    ForgedObjectError,
    IssuerAlreadyClaimedError,
    SafePayload,
    SafePayloadIssuer,
    SealedConstructionError,
    claim_safe_payload_issuer,
    issuer_claimant,
)


@pytest.fixture
def authentic(issuer: SafePayloadIssuer) -> SafePayload:
    return issuer.issue(
        purpose="explain_pattern",
        fields={"segment_size": 361, "effect": 17.05, "label": "country_share_shift"},
        policy_id="pol_default",
        policy_version=1,
        egress_record_id="egr_0001",
    )


# --------------------------------------------------------------------------------------
# The five attempts
# --------------------------------------------------------------------------------------


def test_forge_1_direct_construction_is_refused() -> None:
    """Attempt 1: just call the class, the way you would any other object."""
    with pytest.raises(SealedConstructionError):
        SafePayload()

    with pytest.raises(SealedConstructionError):
        SafePayload(fields={"anything": 1})  # type: ignore[call-arg]


def test_forge_2_dunder_new_is_refused() -> None:
    """Attempt 2: skip ``__init__`` by calling ``__new__`` on the class."""
    with pytest.raises(SealedConstructionError):
        SafePayload.__new__(SafePayload)


def test_forge_3_object_new_produces_an_inert_husk() -> None:
    """Attempt 3: bypass the class's ``__new__`` entirely with ``object.__new__``.

    This one *succeeds* at producing an object, and that is fine: the contents do not
    live on the instance. Every accessor refuses, because the shell was never issued.
    """
    husk = object.__new__(SafePayload)
    assert isinstance(husk, SafePayload)

    for accessor in ("fields", "purpose", "policy_id", "egress_record_id", "digest"):
        with pytest.raises(ForgedObjectError):
            getattr(husk, accessor)

    assert repr(husk) == "<SafePayload forged: no contents>"


def test_forge_4_copy_and_pickle_are_refused(authentic: SafePayload) -> None:
    """Attempt 4: clone a genuine payload, then swap the contents."""
    with pytest.raises(SealedConstructionError):
        copy.copy(authentic)

    with pytest.raises(SealedConstructionError):
        copy.deepcopy(authentic)

    with pytest.raises(SealedConstructionError):
        pickle.dumps(authentic)


def test_forge_5_subclassing_is_refused() -> None:
    """Attempt 5: subclass it and override the accessors."""
    with pytest.raises(TypeError, match="final"):

        class Forged(SafePayload):  # pragma: no cover - the class body never runs
            @property
            def fields(self) -> dict[str, str]:
                return {"ssn": "100-40-1000"}


def test_forge_6_the_issuer_cannot_be_claimed_twice(
    issuer: SafePayloadIssuer, claimant_name: str
) -> None:
    """Bonus: take the capability from whoever holds it.

    Single-holder, not unforgeable. In production godwit-guard claims it at import
    time, so a second claimant fails loudly rather than quietly minting payloads.
    """
    assert issuer.claimant == claimant_name
    assert issuer_claimant() == claimant_name

    with pytest.raises(IssuerAlreadyClaimedError):
        claim_safe_payload_issuer(claimant="definitely_not_the_gate")

    with pytest.raises(SealedConstructionError):
        SafePayloadIssuer()


# --------------------------------------------------------------------------------------
# The authentic path still works
# --------------------------------------------------------------------------------------


def test_an_issued_payload_carries_its_authorisation(authentic: SafePayload) -> None:
    assert authentic.purpose == "explain_pattern"
    assert authentic.egress_record_id == "egr_0001"
    assert authentic.policy_id == "pol_default"
    assert authentic.policy_version == 1
    assert authentic.fields["segment_size"] == 361
    assert authentic.digest.startswith("b2_")


def test_payload_fields_are_read_only(authentic: SafePayload) -> None:
    with pytest.raises(TypeError):
        authentic.fields["injected"] = "value"  # type: ignore[index]


def test_issue_requires_an_egress_record(issuer: SafePayloadIssuer) -> None:
    """No record, no payload. The audit trail is not optional."""
    with pytest.raises(ValueError, match="egress_record_id"):
        issuer.issue(
            purpose="explain",
            fields={},
            policy_id="pol_default",
            policy_version=1,
            egress_record_id="",
        )


def test_issue_requires_a_purpose(issuer: SafePayloadIssuer) -> None:
    with pytest.raises(ValueError, match="purpose"):
        issuer.issue(
            purpose="",
            fields={},
            policy_id="pol_default",
            policy_version=1,
            egress_record_id="egr_0002",
        )


def test_a_tainted_value_cannot_be_smuggled_into_a_payload(
    issuer: SafePayloadIssuer,
) -> None:
    """Defence in depth: the payload holds flat scalars, nothing else.

    mypy already rejects this. The runtime check exists because the gate will be
    assembling field maps dynamically, where the static type is `Mapping[str, object]`.
    """
    from godwit_contracts import Acquisition, data_value

    tainted = data_value("100-40-1000", acquisition=Acquisition.PG_STATS_MCV)
    with pytest.raises(TypeError, match="flat scalars"):
        issuer.issue(
            purpose="explain",
            fields={"ssn": tainted},  # type: ignore[dict-item]
            policy_id="pol_default",
            policy_version=1,
            egress_record_id="egr_0003",
        )


def test_payloads_are_not_equal_by_content(issuer: SafePayloadIssuer) -> None:
    """Identity equality. Two payloads with the same fields are two egresses."""
    first = issuer.issue(
        purpose="p",
        fields={"a": 1},
        policy_id="pol",
        policy_version=1,
        egress_record_id="egr_a",
    )
    second = issuer.issue(
        purpose="p",
        fields={"a": 1},
        policy_id="pol",
        policy_version=1,
        egress_record_id="egr_b",
    )
    assert first != second
    assert first.digest == second.digest
