"""Classification: recognisers, proposals, fail-closed confirmation, QI combinations."""

from __future__ import annotations

import datetime as _dt

import pytest
from _guard_support import classify, col_ref, make_profile
from godwit_contracts import Acquisition, ColumnRole, LogicalType, PiiClass, Provenance
from godwit_guard import ClassificationRegistry, propose, quasi_identifier_combinations
from godwit_guard.classify import RECOGNISERS, iban_valid, luhn_valid, match_concept


def _recognises(name: str, text: str) -> bool:
    return next(r for r in RECOGNISERS if r.name == name).matches(text)


def test_luhn_and_iban_checksums() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert iban_valid("GB82 WEST 1234 5698 7654 32")
    assert not iban_valid("GB82 WEST 1234 5698 7654 33")


@pytest.mark.parametrize(
    ("recogniser", "good", "bad"),
    [
        ("us_ssn", "100-40-1000", "100-40-100"),
        ("payment_card", "4111 1111 1111 1111", "4111 1111 1111 1112"),
        ("iban", "DE89370400440532013000", "DE89370400440532013001"),
        ("lk_nic", "901234567V", "909994567V"),
        ("lk_nic", "199012345678", "199099945678"),
        ("uk_nino", "AB123456C", "BG123456C"),
        ("us_ein", "12-3456789", "123-456789"),
        ("in_pan", "ABCDE1234F", "ABCD1234F"),
        ("phone", "+44 20 7946 0958", "12-34"),
        ("email", "a.b@example.test", "not an email"),
        ("uk_postcode", "SW1A 1AA", "SW1A"),
    ],
)
def test_jurisdiction_specific_recognisers(recogniser: str, good: str, bad: str) -> None:
    assert _recognises(recogniser, good)
    assert not _recognises(recogniser, bad)


def test_name_vocabulary_orders_specific_before_generic() -> None:
    assert match_concept("merchant_name").name == "counterparty"
    assert match_concept("full_name").name == "person_name"
    assert match_concept("patient_hiv_status").name == "health"
    assert match_concept("label_time").name == "timestamp"
    assert match_concept("x1") is None


def test_value_formats_drive_the_proposal(at: _dt.datetime) -> None:
    profile = make_profile("ref_code", at=at)
    proposal = propose(profile, sample=["100-40-1000", "101-41-1007", "102-42-1014"])
    assert proposal.likely is PiiClass.DIRECT_IDENTIFIER
    assert any(s.detector == "us_ssn" and s.support == 1.0 for s in proposal.signals)
    assert "100-40-1000" not in proposal.model_dump_json()


def test_one_card_in_ten_makes_the_column_plausibly_financial(at: _dt.datetime) -> None:
    """Most restrictive PLAUSIBLE, not most likely."""
    sample = ["ok"] * 9 + ["4111111111111111"]
    proposal = propose(make_profile("reference", at=at), sample=sample)
    assert PiiClass.FINANCIAL in proposal.plausible
    assert proposal.most_restrictive_plausible is not PiiClass.NONE


def test_an_unconfirmed_harmless_column_is_never_treated_as_none(at: _dt.datetime) -> None:
    profile = make_profile("x1", LogicalType.FLOAT, at=at, role=ColumnRole.MEASURE)
    proposal = propose(profile)
    assert proposal.likely is PiiClass.NONE
    assert proposal.most_restrictive_plausible is PiiClass.QUASI_IDENTIFIER


def test_no_evidence_means_unknown(at: _dt.datetime) -> None:
    proposal = propose(make_profile("zzz", at=at))
    assert proposal.plausible == (PiiClass.UNKNOWN,)


def test_near_unique_cardinality_is_a_signal(at: _dt.datetime) -> None:
    profile = make_profile("zzz", LogicalType.STRING, at=at, rows=1000, ndv=990)
    assert propose(profile).likely is PiiClass.QUASI_IDENTIFIER


def test_confirmation_is_final_until_the_evidence_worsens(at: _dt.datetime) -> None:
    registry = ClassificationRegistry()
    ref = classify(registry, "ref_code", at=at, confirm=None, sample=["alpha", "beta"])
    assert not registry.entry(ref).confirmed
    registry.confirm(ref, PiiClass.NONE, by="dpo", at=at)
    assert registry.entry(ref).effective_class is PiiClass.NONE
    # A new profile shows SSNs in the column: the human decision no longer stands.
    registry.record(propose(make_profile("ref_code", at=at), sample=["100-40-1000"]))
    entry = registry.entry(ref)
    assert entry is not None and not entry.confirmed
    assert entry.effective_class is PiiClass.DIRECT_IDENTIFIER


def test_confirm_requires_a_proposal_and_a_person(at: _dt.datetime) -> None:
    registry = ClassificationRegistry()
    with pytest.raises(KeyError):
        registry.confirm(col_ref("nothing"), PiiClass.NONE, by="dpo", at=at)
    ref = classify(registry, "c", at=at, confirm=None)
    with pytest.raises(ValueError, match="who confirmed"):
        registry.confirm(ref, PiiClass.NONE, by="", at=at)


def test_lookup_is_exact_or_uniquely_resolvable_or_nothing(at: _dt.datetime) -> None:
    registry = ClassificationRegistry()
    classify(registry, "email", at=at, confirm=None)
    classify(registry, "email", at=at, confirm=None, table="other")
    exact = Provenance(
        acquisition=Acquisition.PG_STATS_MCV, source_id="src_pii", table="customers", column="email"
    )
    ambiguous = Provenance(
        acquisition=Acquisition.PG_STATS_MCV, source_id="src_pii", column="email"
    )
    assert registry.lookup(exact) is not None
    assert registry.lookup(ambiguous) is None


def test_the_postcode_birthdate_sex_triad_is_flagged(at: _dt.datetime) -> None:
    registry = ClassificationRegistry()
    for name, ndv in (("postcode", 2000), ("date_of_birth", 20000), ("sex", 2)):
        classify(registry, name, at=at, confirm=PiiClass.QUASI_IDENTIFIER, rows=10**9, ndv=ndv)
    found = quasi_identifier_combinations(registry.entries(), k=10)
    assert any(c.known_triad for c in found)


def test_low_cardinality_combinations_are_flagged_with_their_class_size(
    at: _dt.datetime,
) -> None:
    registry = ClassificationRegistry()
    classify(registry, "cohort", at=at, confirm=PiiClass.QUASI_IDENTIFIER, rows=1000, ndv=100)
    classify(registry, "merchant", at=at, confirm=PiiClass.QUASI_IDENTIFIER, rows=1000, ndv=50)
    classify(registry, "status", at=at, confirm=PiiClass.QUASI_IDENTIFIER, rows=1000, ndv=2)
    found = quasi_identifier_combinations(registry.entries(), k=10)
    widths = sorted(len(c.columns) for c in found)
    assert widths == [2, 2]  # cohort+merchant and cohort+status; no superset re-reported
    assert all(c.expected_class_size < 10 for c in found)
    with pytest.raises(ValueError, match="at least 2"):
        quasi_identifier_combinations(registry.entries(), k=1)
