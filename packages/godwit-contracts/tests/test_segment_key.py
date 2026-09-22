"""segment_key: the golden vectors, and the properties the normalisation must have.

Two agents who cannot talk to each other must produce the same key for the same
segment. These tests are the arbiter.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from godwit_contracts import (
    Operator,
    Predicate,
    Segment,
    canonical_column,
    canonical_scalar,
    segment_key,
)
from hypothesis import given
from hypothesis import strategies as st

# --------------------------------------------------------------------------------------
# golden vectors
# --------------------------------------------------------------------------------------

_LITERAL_BUILDERS: dict[str, Callable[[str], Any]] = {
    "str": str,
    "int": int,
    "float": float,
    "bool": lambda literal: literal == "true",
    "Decimal": Decimal,
    "datetime": _dt.datetime.fromisoformat,
    "date": _dt.date.fromisoformat,
    "NoneType": lambda _literal: None,
}


def rebuild(vector: dict[str, Any], make_predicate: Callable[..., Predicate]) -> Segment:
    predicates = [
        make_predicate(
            item["column"],
            Operator(item["op"]),
            *(_LITERAL_BUILDERS[value["py_type"]](value["literal"]) for value in item["values"]),
        )
        for item in vector["predicates"]
    ]
    return Segment(predicates=tuple(predicates))


def test_every_golden_vector_reproduces(
    golden_json: Callable[[str], Any], make_predicate: Callable[..., Predicate]
) -> None:
    """If this fails, either the normalisation changed or the fixture is stale.

    Both are contract changes. Neither is fixed by regenerating the fixture until you
    have understood which one happened.
    """
    fixture = golden_json("segment_key_vectors.json")
    assert len(fixture["vectors"]) >= 20

    for vector in fixture["vectors"]:
        segment = rebuild(vector, make_predicate)
        assert segment.canonical_form() == vector["canonical"], vector["note"]
        assert str(segment.key) == vector["segment_key"], vector["note"]


def test_the_vectors_cover_the_collisions_that_matter(
    golden_json: Callable[[str], Any], make_predicate: Callable[..., Predicate]
) -> None:
    """Pairs that must agree, and pairs that must not."""
    fixture = golden_json("segment_key_vectors.json")
    by_note = {vector["note"]: rebuild(vector, make_predicate) for vector in fixture["vectors"]}

    # Column name case and whitespace are normalised away.
    assert (
        by_note["simple equality"].key
        == by_note["column case and surrounding whitespace are normalised away"].key
    )
    # Value case is NOT: values are data.
    assert (
        by_note["simple equality"].key
        != by_note["value case is NOT normalised: values are data"].key
    )
    # Predicate order is irrelevant.
    assert (
        by_note["predicate order does not matter"].key
        == by_note["same predicates, written in the other order"].key
    )
    # 1 is not "1" is not True.
    assert by_note["int 1 and str '1' are different values"].key != (
        by_note["str '1' again, for contrast"].key
    )
    assert by_note["int 1 and str '1' are different values"].key != (by_note["bool is not int"].key)
    # IN escaping: one member with a comma is not two members.
    assert by_note["IN escaping: one member containing a comma is not two members"].key != (
        by_note["two members, for contrast with the escaped case"].key
    )
    # NFC: composed and decomposed forms are the same city.
    assert by_note["unicode is NFC-normalised: composed and decomposed agree"].key == (
        by_note["the same city, written with a combining tilde"].key
    )


# --------------------------------------------------------------------------------------
# scalar rendering
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "n:"),
        (True, "b:true"),
        (False, "b:false"),
        (0, "i:0"),
        (-42, "i:-42"),
        (1.5, "f:1.5"),
        (-0.0, "f:0.0"),
        (0.0, "f:0.0"),
        (float("inf"), "f:inf"),
        (float("-inf"), "f:-inf"),
        (float("nan"), "f:nan"),
        (Decimal("1.2300"), "d:1.23"),
        (Decimal("100"), "d:100"),
        (Decimal("0.00"), "d:0"),
        (Decimal("-0"), "d:0"),
        (b"\xde\xad\xbe\xef", "y:deadbeef"),
        (_dt.date(2024, 1, 31), "t:2024-01-31"),
        (
            _dt.datetime(2024, 1, 31, 12, 0, tzinfo=_dt.UTC),
            "T:2024-01-31T12:00:00.000000Z",
        ),
        ("PT", "s:PT"),
        ("", "s:"),
    ],
)
def test_scalar_rendering_matches_the_documented_table(value: object, expected: str) -> None:
    assert canonical_scalar(value) == expected  # type: ignore[arg-type]


def test_timezone_is_normalised_to_utc() -> None:
    plus_two = _dt.timezone(_dt.timedelta(hours=2))
    aware = _dt.datetime(2024, 1, 31, 14, 0, tzinfo=plus_two)
    assert canonical_scalar(aware) == "T:2024-01-31T12:00:00.000000Z"


def test_naive_datetimes_are_refused() -> None:
    """A naive timestamp would key differently depending on who ran the detector."""
    with pytest.raises(ValueError, match="naive datetime"):
        canonical_scalar(_dt.datetime(2024, 1, 31, 12, 0))


def test_non_finite_decimals_are_refused() -> None:
    with pytest.raises(ValueError, match="NaN and Infinity"):
        canonical_scalar(Decimal("NaN"))


def test_column_normalisation() -> None:
    assert canonical_column("  CoUnTry ") == "country"
    assert canonical_column("Straße") == "strasse"


# --------------------------------------------------------------------------------------
# properties
# --------------------------------------------------------------------------------------

_SAFE_TEXT = st.text(min_size=0, max_size=12)


@given(st.lists(_SAFE_TEXT, min_size=1, max_size=4, unique=True))
def test_key_is_order_independent(
    values: list[str],
) -> None:
    """Property: a segment is a set of predicates, so ordering cannot matter."""
    from godwit_contracts import Acquisition, data_value, schema_name

    def predicate(index: int, value: str) -> Predicate:
        return Predicate(
            column=schema_name(f"col_{index}"),
            op=Operator.EQ,
            values=(data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE),),
        )

    predicates = [predicate(index, value) for index, value in enumerate(values)]
    forward = Segment(predicates=tuple(predicates))
    backward = Segment(predicates=tuple(reversed(predicates)))
    assert forward.key == backward.key


@given(_SAFE_TEXT)
def test_duplicate_predicates_collapse(value: str) -> None:
    from godwit_contracts import Acquisition, data_value, schema_name

    predicate = Predicate(
        column=schema_name("country"),
        op=Operator.EQ,
        values=(data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE),),
    )
    once = Segment(predicates=(predicate,))
    thrice = Segment(predicates=(predicate, predicate, predicate))
    assert once.key == thrice.key


def test_population_does_not_affect_the_key(
    make_predicate: Callable[..., Predicate],
) -> None:
    """Two snapshots of the same slice must share a key. That is the whole point."""
    predicate = make_predicate("country", Operator.EQ, "PT")
    small = Segment(predicates=(predicate,), population=3)
    large = Segment(predicates=(predicate,), population=900_000)
    assert small.key == large.key


def test_the_empty_segment_is_the_universe() -> None:
    universe = Segment()
    assert universe.is_universe is True
    assert universe.canonical_form() == "[]"
    assert str(universe.key) == str(segment_key(Segment()))


def test_key_has_the_documented_shape(make_predicate: Callable[..., Predicate]) -> None:
    key = str(Segment(predicates=(make_predicate("country", Operator.EQ, "PT"),)).key)
    prefix, _, digest = key.partition("_")
    assert prefix == "seg"
    assert len(digest) == 32
    assert set(digest) <= set("0123456789abcdef")


# --------------------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------------------


def test_predicate_arity_is_enforced(make_predicate: Callable[..., Predicate]) -> None:
    with pytest.raises(ValueError, match="takes 1 value"):
        make_predicate("country", Operator.EQ, "PT", "GB")
    with pytest.raises(ValueError, match="takes 2 value"):
        make_predicate("amount", Operator.BETWEEN, 10)
    with pytest.raises(ValueError, match="takes 0 value"):
        make_predicate("shipped_at", Operator.IS_NULL, None)
    with pytest.raises(ValueError, match="at least one value"):
        make_predicate("country", Operator.IN)


def test_predicate_values_must_be_tainted_as_row_values() -> None:
    """A predicate value is by definition a row value. Statistics are refused."""
    from godwit_contracts import derived_statistic, schema_name

    with pytest.raises(ValueError, match="tainted DATA_VALUE"):
        Predicate(
            column=schema_name("country"),
            op=Operator.EQ,
            values=(derived_statistic("PT"),),
        )


def test_predicate_column_must_be_schema_tainted() -> None:
    from godwit_contracts import Acquisition, data_value

    with pytest.raises(ValueError, match="SCHEMA_NAME"):
        Predicate(
            column=data_value("country", acquisition=Acquisition.PG_STATS_MCV),
            op=Operator.IS_NULL,
        )
