"""Column access modes: fail-closed resolution, entropy floor, structural projection."""

from __future__ import annotations

import pytest

from godwit_source._contracts import ColumnAccessMode, PiiClass
from godwit_source.access import (
    MIN_OPAQUE_ENTROPY_BITS,
    AccessPolicy,
    BlindColumnError,
    ColumnClassification,
    keyed_hash,
)


def test_unknown_column_is_blind() -> None:
    assert AccessPolicy([]).mode("anything_at_all") is ColumnAccessMode.BLIND


def test_unconfirmed_classification_is_blind() -> None:
    policy = AccessPolicy(
        [ColumnClassification("device_id", PiiClass.DIRECT_IDENTIFIER, input_space_bits=80.0)]
    )
    assert policy.mode("device_id") is ColumnAccessMode.BLIND


def test_identifier_defaults_to_opaque_not_blind() -> None:
    """Skipping identifiers protects the data by deleting the product: shared-attribute
    graph structure is the strongest organised-fraud signal we have."""
    policy = AccessPolicy(
        [
            ColumnClassification(
                "device_id", PiiClass.DIRECT_IDENTIFIER, confirmed=True, input_space_bits=80.0
            )
        ]
    )
    assert policy.mode("device_id") is ColumnAccessMode.OPAQUE


@pytest.mark.parametrize(
    ("column", "bits"),
    [("pin", 13.3), ("country_code", 7.8), ("date_of_birth", 15.2)],
)
def test_low_entropy_opaque_falls_back_to_blind(column: str, bits: float) -> None:
    """A hashed four-digit PIN is enumerable in seconds. Hashing it is not anonymisation."""
    assert bits < MIN_OPAQUE_ENTROPY_BITS
    policy = AccessPolicy(
        [
            ColumnClassification(
                column, PiiClass.QUASI_IDENTIFIER, confirmed=True, input_space_bits=bits
            )
        ]
    )
    assert policy.mode(column) is ColumnAccessMode.BLIND


def test_entropy_estimated_from_ndv_when_not_declared() -> None:
    policy = AccessPolicy(
        [ColumnClassification("device_id", PiiClass.DIRECT_IDENTIFIER, confirmed=True)],
        ndv_by_column={"device_id": 2**40},
    )
    assert policy.mode("device_id") is ColumnAccessMode.OPAQUE


def test_open_without_guardrail_downgrades() -> None:
    policy = AccessPolicy(
        [
            ColumnClassification(
                "customer_email",
                PiiClass.DIRECT_IDENTIFIER,
                confirmed=True,
                requested_mode=ColumnAccessMode.OPEN,
                input_space_bits=64.0,
            )
        ]
    )
    assert policy.mode("customer_email") is ColumnAccessMode.OPAQUE


def test_open_with_guardrail_is_open() -> None:
    policy = AccessPolicy(
        [
            ColumnClassification(
                "customer_email",
                PiiClass.DIRECT_IDENTIFIER,
                confirmed=True,
                requested_mode=ColumnAccessMode.OPEN,
                guardrail_id="G-2",
            )
        ]
    )
    assert policy.mode("customer_email") is ColumnAccessMode.OPEN


def test_secret_and_free_text_are_blind_even_when_open_is_requested() -> None:
    policy = AccessPolicy(
        [
            ColumnClassification(
                "api_key",
                PiiClass.SECRET,
                confirmed=True,
                requested_mode=ColumnAccessMode.OPEN,
                guardrail_id="G-9",
            ),
            ColumnClassification(
                "notes",
                PiiClass.FREE_TEXT,
                confirmed=True,
                requested_mode=ColumnAccessMode.OPEN,
                guardrail_id="G-9",
            ),
        ]
    )
    assert policy.mode("api_key") is ColumnAccessMode.BLIND
    assert policy.mode("notes") is ColumnAccessMode.BLIND


def test_plan_drops_blind_and_hashes_opaque(policy: AccessPolicy) -> None:
    plan = policy.plan(["txn_id", "device_id", "notes", "never_classified"])
    columns = {p.column: p for p in plan}
    assert "notes" not in columns
    assert "never_classified" not in columns
    assert columns["txn_id"].sql == '"txn_id"'
    assert "hmac" in columns["device_id"].sql
    assert '"device_id"' in columns["device_id"].sql


def test_metadata_readable_only_for_open(policy: AccessPolicy) -> None:
    assert policy.metadata_readable("customer_email")
    assert not policy.metadata_readable("device_id")
    assert not policy.metadata_readable("notes")


def test_assert_readable_raises_on_blind(policy: AccessPolicy) -> None:
    with pytest.raises(BlindColumnError):
        policy.assert_readable("notes")


def test_keyed_hash_is_stable_and_key_dependent() -> None:
    assert keyed_hash("abc", b"k1") == keyed_hash("abc", b"k1")
    assert keyed_hash("abc", b"k1") != keyed_hash("abc", b"k2")
    assert keyed_hash("abc", b"k1") != keyed_hash("abd", b"k1")
    assert "abc" not in keyed_hash("abc", b"k1")
