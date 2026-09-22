"""Comparing and measuring bounds without leaking them.

``ScalarValue`` spans nine Python types and most cross-type comparisons are meaningless.
The interesting cases are the ones Python gets "right" in a way that is wrong for us:
``True == 1``, ``datetime`` is a subclass of ``date``, and a naive datetime compares
against another naive datetime while meaning something different.
"""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal

import pytest
from godwit_source.scalars import as_axis, prefix_similarity, scalar_le
from hypothesis import given, settings
from hypothesis import strategies as st

# Hypothesis' default 200 ms per-example deadline is a wall-clock check, and a
# wall-clock check is exactly the nondeterminism universal rule 5 forbids: these
# tests fail on a loaded machine and pass on a quiet one, which is a flake rather
# than a finding. Deadlines are off; what the property asserts is unchanged.
NO_DEADLINE = settings(deadline=None)

TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=32)


# --------------------------------------------------------------------------------------
# scalar_le
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        (1, 2, True),
        (2, 1, False),
        (1.5, Decimal("1.5"), True),
        ("a", "b", True),
        (b"\x00", b"\x01", True),
        (_dt.date(2024, 1, 1), _dt.date(2024, 1, 2), True),
        (
            _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
            _dt.datetime(2024, 1, 2, tzinfo=_dt.UTC),
            True,
        ),
        (True, False, False),
        (False, True, True),
    ],
)
def test_comparable_pairs_compare(left: object, right: object, expected: bool) -> None:
    assert scalar_le(left, right) is expected


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (True, 1),
        (1, True),
        ("a", 1),
        (b"a", "a"),
        (None, 1),
        (_dt.date(2024, 1, 1), _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)),
        (
            _dt.datetime(2024, 1, 1),
            _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
        ),
    ],
)
def test_incomparable_pairs_say_so(left: object, right: object) -> None:
    """``None`` means "cannot say". Guessing here silently creates or hides drift."""
    assert scalar_le(left, right) is None


@given(left=st.integers(), right=st.integers())
@NO_DEADLINE
def test_integer_order_is_total(left: int, right: int) -> None:
    forward = scalar_le(left, right)
    backward = scalar_le(right, left)
    assert forward is not None
    assert backward is not None
    assert forward or backward


# --------------------------------------------------------------------------------------
# as_axis
# --------------------------------------------------------------------------------------


def test_temporal_values_land_on_a_common_axis() -> None:
    """A timestamp and an amount must be measurable by the same arithmetic."""
    moment = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
    assert as_axis(moment) == moment.timestamp()
    assert as_axis(_dt.date(2024, 1, 1)) == float(_dt.date(2024, 1, 1).toordinal())
    assert as_axis(Decimal("12.5")) == 12.5
    assert as_axis(7) == 7.0


@pytest.mark.parametrize("value", [None, True, False, "text", b"bytes", _dt.datetime(2024, 1, 1)])
def test_values_with_no_axis_say_so(value: object) -> None:
    """A naive datetime is refused rather than assumed UTC."""
    assert as_axis(value) is None


# --------------------------------------------------------------------------------------
# prefix_similarity
# --------------------------------------------------------------------------------------


@given(text=TEXT)
@NO_DEADLINE
def test_a_string_is_identical_to_itself(text: str) -> None:
    assert prefix_similarity(text, text) == 1.0


@given(left=TEXT, right=TEXT)
@NO_DEADLINE
def test_similarity_is_a_ratio(left: str, right: str) -> None:
    assert 0.0 <= prefix_similarity(left, right) <= 1.0


@given(left=TEXT, right=TEXT)
@NO_DEADLINE
def test_similarity_is_symmetric(left: str, right: str) -> None:
    assert prefix_similarity(left, right) == prefix_similarity(right, left)


def test_similarity_measures_the_shared_prefix() -> None:
    """The case the golden fixture turns on: a monotonically advancing identifier."""
    assert prefix_similarity("ord_00_05999", "ord_01_05999") == pytest.approx(5 / 12)
    assert prefix_similarity("abc", "xyz") == 0.0
    assert prefix_similarity("", "") == 1.0
    assert prefix_similarity("abc", "abcdef") == pytest.approx(0.5)
