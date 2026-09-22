"""The taint system: ordering, acquisition floors, small cells, and safe rendering."""

from __future__ import annotations

import pytest
from godwit_contracts import (
    ACQUISITION_MINIMUM_SENSITIVITY,
    Acquisition,
    Provenance,
    Sensitivity,
    Tainted,
    data_value,
    derived_statistic,
    egress_risk_rank,
    most_sensitive,
    schema_name,
    token,
)
from hypothesis import given
from hypothesis import strategies as st


def test_risk_order_is_total_and_data_value_is_the_top() -> None:
    ordered = sorted(Sensitivity, key=egress_risk_rank)
    assert ordered == [
        Sensitivity.DERIVED_STATISTIC,
        Sensitivity.TOKEN,
        Sensitivity.SCHEMA_NAME,
        Sensitivity.DATA_VALUE,
    ]
    assert len({egress_risk_rank(item) for item in Sensitivity}) == len(Sensitivity)


@given(st.lists(st.sampled_from(list(Sensitivity)), min_size=1, max_size=6))
def test_combining_taint_only_ever_goes_up(values: list[Sensitivity]) -> None:
    """Property: the combination is at least as restricted as every input."""
    combined = most_sensitive(*values)
    assert all(egress_risk_rank(combined) >= egress_risk_rank(item) for item in values)
    assert combined in values


def test_most_sensitive_needs_an_argument() -> None:
    with pytest.raises(ValueError, match="at least one"):
        most_sensitive()


def test_every_acquisition_route_has_a_declared_floor() -> None:
    """A new Acquisition without a floor would default to 'whatever the caller said'."""
    assert set(ACQUISITION_MINIMUM_SENSITIVITY) == set(Acquisition)


@pytest.mark.parametrize(
    "acquisition",
    [
        Acquisition.ICEBERG_MANIFEST_BOUNDS,
        Acquisition.PG_STATS_MCV,
        Acquisition.COUNT_MIN_HEAVY_HITTER,
        Acquisition.SEGMENT_PREDICATE,
        Acquisition.QUANTILE,
        Acquisition.DRIVER_EXCEPTION,
    ],
)
def test_row_bearing_routes_cannot_be_labelled_as_statistics(
    acquisition: Acquisition,
) -> None:
    """The mislabelling this system exists to prevent.

    Calling an Iceberg manifest bound a 'derived statistic' is the single most likely
    way someone leaks a name or an email while believing they shipped a number.
    """
    with pytest.raises(ValueError, match="requires at least"):
        Tainted[str](
            value="Aoife Brennan",
            sensitivity=Sensitivity.DERIVED_STATISTIC,
            provenance=Provenance(acquisition=acquisition),
        )


def test_a_value_may_be_declared_more_restricted_than_its_floor() -> None:
    """Upwards is always allowed. Only downgrades are refused."""
    value = Tainted[float](
        value=0.5,
        sensitivity=Sensitivity.DATA_VALUE,
        provenance=Provenance(acquisition=Acquisition.COMPUTED_STATISTIC),
    )
    assert value.sensitivity is Sensitivity.DATA_VALUE


def test_repr_and_str_never_render_the_value() -> None:
    """An accidental f-string in a log line must leak the label, not the data."""
    ssn_value = "100-40-1000"
    tainted = data_value(ssn_value, acquisition=Acquisition.PG_STATS_MCV, column="customer_ssn")

    assert ssn_value not in repr(tainted)
    assert ssn_value not in str(tainted)
    assert ssn_value not in f"found {tainted}"
    assert ssn_value not in "{}".format(tainted)
    assert ssn_value not in tainted.redacted()
    assert "customer_ssn" in repr(tainted)


def test_reveal_is_the_only_way_out() -> None:
    tainted = data_value(42, acquisition=Acquisition.QUANTILE)
    assert tainted.reveal() == 42


@given(st.integers(min_value=0, max_value=1000), st.integers(min_value=1, max_value=100))
def test_small_cell_rule(population: int, threshold: int) -> None:
    tainted = derived_statistic(1.0, population=population)
    assert tainted.is_small_cell(threshold) == (population < threshold)


def test_unknown_population_counts_as_a_small_cell() -> None:
    """Unknown must mean unsafe. Treating it as 'large' is how n=3 gets published."""
    tainted = derived_statistic(1.0, population=None)
    assert tainted.is_small_cell(1) is True
    assert tainted.is_small_cell(0) is True


def test_schema_name_helper_produces_schema_taint() -> None:
    name = schema_name("patient_hiv_status")
    assert name.sensitivity is Sensitivity.SCHEMA_NAME
    assert name.provenance.acquisition is Acquisition.CATALOG_IDENTIFIER


def test_tokenisation_keeps_a_link_to_what_it_replaced() -> None:
    """A token traces home, or the gate cannot explain itself in an audit."""
    original = data_value(
        "Aoife Brennan", acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS, column="full_name"
    )
    substitute = token("tok_9f2a", upstream=original.provenance, population=361)

    assert substitute.sensitivity is Sensitivity.TOKEN
    assert substitute.provenance.upstream is not None
    assert substitute.provenance.upstream.column == "full_name"
    assert "Aoife" not in repr(substitute)


def test_tainted_is_frozen() -> None:
    tainted = derived_statistic(1.0)
    with pytest.raises(ValueError, match=r"frozen|Instance is frozen"):
        tainted.value = 2.0  # type: ignore[misc]
