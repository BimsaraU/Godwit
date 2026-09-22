"""Fixtures for the contracts tests.

Everything shared between test modules is exposed as a fixture rather than as an
importable helper. Seventeen packages each have a ``tests/`` directory, pytest runs in
importlib mode, and cross-importing between test modules is the fastest way to make
that fragile.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable

import pytest
from godwit_contracts import (
    Acquisition,
    Operator,
    Predicate,
    SafePayloadIssuer,
    Segment,
    claim_safe_payload_issuer,
    data_value,
    schema_name,
)

TEST_CLAIMANT = "godwit_contracts.tests"


@pytest.fixture(scope="session")
def claimant_name() -> str:
    """The name the tests claim the issuer capability under."""
    return TEST_CLAIMANT


@pytest.fixture(scope="session")
def issuer() -> SafePayloadIssuer:
    """The one SafePayload issuer, claimed once for the whole session.

    In production godwit-guard claims this at import time. The tests stand in for the
    gate so that the mechanism itself can be exercised. That the tests *can* claim it is
    the honest limit of the design: the capability is single-holder, not unforgeable by
    a determined in-process caller. See docs/ARCHITECTURE.md, open question 1.
    """
    return claim_safe_payload_issuer(claimant=TEST_CLAIMANT)


@pytest.fixture
def utc_now() -> _dt.datetime:
    """A fixed instant. Nothing in these tests reads a clock."""
    return _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)


@pytest.fixture
def make_predicate() -> Callable[..., Predicate]:
    """Factory for a predicate with correctly tainted parts."""

    def _make(column: str, op: Operator, *values: object) -> Predicate:
        return Predicate(
            column=schema_name(column),
            op=op,
            values=tuple(
                data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE, column=column)
                for value in values
            ),
        )

    return _make


@pytest.fixture
def make_segment() -> Callable[..., Segment]:
    """Factory for a segment."""

    def _make(*predicates: Predicate, population: int | None = None) -> Segment:
        return Segment(predicates=predicates, population=population)

    return _make
