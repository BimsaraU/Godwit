"""The backstop. A hit is a defect in the taint system; these tests pin what it catches."""

from __future__ import annotations

import base64
from urllib.parse import quote

import pytest
from godwit_guard import Backstop, BackstopFinding
from godwit_guard.classify import CONCEPTS
from godwit_guard.schema_names import ROLE_PHRASES


@pytest.fixture(scope="module")
def backstop() -> Backstop:
    return Backstop(use_presidio=True)


NAME_VALUE = "Aoife Brennan"


@pytest.mark.parametrize(
    ("fields", "encoding"),
    [
        ({"a": "called Aoife Brennan today"}, "raw"),
        ({"a": "AOIFE BRENNAN"}, "raw"),
        ({"a": base64.b64encode(NAME_VALUE.encode()).decode()}, "base64"),
        ({"a": "x" + base64.urlsafe_b64encode(b"..Aoife Brennan..").decode()}, "base64"),
        ({"a": quote(NAME_VALUE)}, "url"),
        ({"a": NAME_VALUE.encode().hex()}, "hex"),
        ({"a": "Aoife", "b": "Brennan"}, "raw"),
    ],
)
def test_echo_finds_a_revealed_value_in_any_encoding(fields: dict[str, str], encoding: str) -> None:
    findings = Backstop(use_presidio=False).scan(fields, forbidden=[NAME_VALUE])
    assert any(f.recogniser == "echo" and f.encoding == encoding for f in findings)


def test_echo_compares_digits_of_numeric_identifiers() -> None:
    findings = Backstop(use_presidio=False).scan({"a": "id 100 40 1000"}, forbidden=["100-40-1000"])
    assert any(f.encoding == "digits" for f in findings)


def test_echo_ignores_values_too_short_to_mean_anything() -> None:
    assert Backstop(use_presidio=False).scan({"a": "n=3 PT"}, forbidden=["PT", "3"]) == ()


@pytest.mark.parametrize(
    ("text", "recogniser"),
    [
        ("ssn 100-40-1000", "us_ssn"),
        ("card 4111 1111 1111 1111", "payment_card"),
        ("iban DE89370400440532013000", "iban"),
        ("mail a.person@bank.test", "email"),
        ("call +447946095812", "phone_e164"),
        ("nic 901234567V", "lk_nic"),
    ],
)
def test_format_recognisers(text: str, recogniser: str) -> None:
    findings = Backstop(use_presidio=False).scan({"narrative": text})
    assert recogniser in {f.recogniser for f in findings}


def test_presidio_catches_a_name_no_rule_would(backstop: Backstop) -> None:
    findings = backstop.scan({"narrative": "Refund approved for Kwame Mensah yesterday"})
    assert "presidio:PERSON" in {f.recogniser for f in findings}


def test_our_own_vocabulary_is_not_a_finding(backstop: Backstop) -> None:
    """If the backstop cried wolf on our own output, someone would switch it off."""
    fields: dict[str, str | int | float | bool | None] = {
        f"c{i}": f"COLUMN_{i}: {c.phrase} (entity identifier, string)"
        for i, c in enumerate(CONCEPTS)
    }
    fields |= {f"r{i}": phrase for i, phrase in enumerate(ROLE_PHRASES.values())}
    fields |= {
        "tok": "MERCHANT_7 refunds rose; PERSON_3 used DEVICE_2 and NATIONALID_1",
        "hash": "h_0123456789abcdef0123456789abcdef",
        "stat": 0.1234567890123456,
        "count": 4111111111111111,
        "band": "[10000, 100000)",
    }
    assert backstop.scan(fields) == ()


def test_hits_are_counted_and_page_someone() -> None:
    paged: list[tuple[BackstopFinding, ...]] = []
    scanner = Backstop(use_presidio=False, pager=paged.append)
    scanner.scan({"a": "fine"})
    scanner.scan({"a": "100-40-1000"})
    assert scanner.metrics.scans == 2 and scanner.metrics.hits == 1
    assert scanner.metrics.hit_rate == 0.5
    assert len(paged) == 1
    assert "100-40-1000" not in paged[0][0].model_dump_json(), "findings never quote the text"
