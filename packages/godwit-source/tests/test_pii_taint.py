"""ACCEPTANCE: nothing this package emits carries a row value in an untainted field.

The brief's test, written out: *walk every field of every emitted object and assert
that no untainted string field contains a value present in the fixture's identifier
set.*

The walker below descends through pydantic models, dataclasses, mappings and sequences,
and stops at a ``Tainted``: a value inside one is, by definition, declared. Everything
else -- every plain ``str`` anywhere in the tree -- is collected and checked against the
PII torture fixture's identifiers.

Two refinements the naive version misses:

* **Prefixes.** Iceberg truncates string bounds to sixteen characters. A whole-value
  search would sail past ``aoife.brennan@no``, which is still that person. Twelve-
  character prefixes are checked too.
* **Exceptions.** A driver message is a string field of an object we emit, so
  ``SanitisedDriverError`` is walked like anything else.

**This test is a backstop.** The control is the taint type plus the gate. A passing
string search proves only that this particular fixture's particular values did not
appear; it does not prove the typing is right, and it never will.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

import pytest
from godwit_contracts.cost import CostBudget
from godwit_contracts.source import PiiClass, SourceRef
from godwit_contracts.taint import Sensitivity, Tainted
from godwit_source.detectors import run_metadata_detectors
from godwit_source.errors import SanitisedDriverError, sanitise_driver_error
from godwit_source.iceberg import IcebergAdapter
from godwit_source.semantic import pii_restrictiveness
from pydantic import BaseModel

PREFIX_LENGTH = 12


def untainted_strings(root: object) -> Iterator[str]:
    """Every plain string reachable from ``root``, skipping declared tainted values.

    A ``Tainted`` is not descended into: its payload is exactly the thing that is
    allowed to be a row value, because it says so in its type. Its ``provenance`` is
    walked, because provenance is a plain model and a careless implementation could put
    a row value in its ``detail`` field.
    """
    seen: set[int] = set()

    def walk(node: object) -> Iterator[str]:
        if id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, Tainted):
            yield from walk(node.provenance)
            return
        if isinstance(node, str):
            yield node
            return
        if isinstance(node, bytes | bytearray | int | float | bool) or node is None:
            return
        if isinstance(node, BaseModel):
            for name in type(node).model_fields:
                yield from walk(getattr(node, name))
            return
        if dataclasses.is_dataclass(node) and not isinstance(node, type):
            for field in dataclasses.fields(node):
                yield from walk(getattr(node, field.name))
            return
        if isinstance(node, BaseException):
            yield str(node)
            for value in vars(node).values():
                yield from walk(value)
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                yield from walk(key)
                yield from walk(value)
            return
        if isinstance(node, Sequence | set | frozenset):
            for item in node:
                yield from walk(item)
            return

    yield from walk(root)


def assert_no_leak(root: object, identifiers: frozenset[str], *, what: str) -> None:
    needles = set(identifiers) | {
        value[:PREFIX_LENGTH] for value in identifiers if len(value) >= PREFIX_LENGTH
    }
    for text in untainted_strings(root):
        for needle in needles:
            assert needle not in text, (
                f"{what} leaked {needle!r} into an untainted string field: {text!r}"
            )


def test_the_identifier_set_is_not_empty(pii_identifiers: frozenset[str]) -> None:
    """Guard the guard: an empty needle set would make every leak test pass."""
    assert len(pii_identifiers) >= 15
    assert "aoife.brennan@northfield-bank.test" in pii_identifiers
    assert "is_merchant_ACME_CORP" in pii_identifiers


def test_manifest_bounds_are_tainted_data_values(
    pii_adapter: IcebergAdapter, pii_source: SourceRef, generous_budget: CostBudget
) -> None:
    """Every bound this adapter reads is DATA_VALUE, via the manifest-bounds route."""
    snapshot = pii_adapter.list_snapshots(pii_source)[-1]
    metadata = pii_adapter.read_metadata_stats(pii_source, snapshot, budget=generous_budget)

    bounded = [column for column in metadata.columns if column.lower_bound is not None]
    assert len(bounded) == 9, "every column in the torture fixture has bounds"
    for column in bounded:
        for bound in (column.lower_bound, column.upper_bound):
            assert bound is not None
            assert bound.sensitivity is Sensitivity.DATA_VALUE
            assert bound.provenance.acquisition.value == "iceberg_manifest_bounds"
            assert bound.provenance.column == column.ref.column.reveal()


def test_metadata_emits_no_untainted_identifier(
    pii_adapter: IcebergAdapter,
    pii_source: SourceRef,
    generous_budget: CostBudget,
    pii_identifiers: frozenset[str],
) -> None:
    snapshot = pii_adapter.list_snapshots(pii_source)[-1]
    metadata = pii_adapter.read_metadata_stats(pii_source, snapshot, budget=generous_budget)
    assert_no_leak(metadata, pii_identifiers, what="SnapshotMetadata")
    assert_no_leak(metadata.to_table_profile(), pii_identifiers, what="TableProfile")


def test_candidates_emit_no_untainted_identifier(
    pii_adapter: IcebergAdapter,
    pii_source: SourceRef,
    generous_budget: CostBudget,
    pii_identifiers: frozenset[str],
) -> None:
    """Detectors over the torture table, walked field by field.

    The table has one snapshot, so no detector can fire; what is being checked is the
    metadata the detectors were handed and anything they build from it. The drift
    fixture exercises the firing path and this one exercises the leak surface.
    """
    snapshots = pii_adapter.list_snapshots(pii_source)
    history = [
        pii_adapter.read_metadata_stats(pii_source, snapshot, budget=generous_budget)
        for snapshot in snapshots
    ]
    candidates = run_metadata_detectors(history, code_version="test-pii", seed=1)
    assert_no_leak(history, pii_identifiers, what="the metadata history")
    assert_no_leak(candidates, pii_identifiers, what="the candidates")


def test_rendered_output_carries_no_identifier(
    pii_adapter: IcebergAdapter,
    pii_source: SourceRef,
    generous_budget: CostBudget,
    pii_identifiers: frozenset[str],
) -> None:
    """``repr`` and ``str`` of a tainted value render the label, never the value.

    This is the property that makes an accidental f-string in a log line survivable.
    """
    snapshot = pii_adapter.list_snapshots(pii_source)[-1]
    metadata = pii_adapter.read_metadata_stats(pii_source, snapshot, budget=generous_budget)
    for column in metadata.columns:
        if column.lower_bound is None:
            continue
        rendered = f"{column.lower_bound} {column.lower_bound!r}"
        for identifier in pii_identifiers:
            assert identifier not in rendered


def test_driver_exceptions_never_carry_their_message(
    pii_fixture: Mapping[str, Any], pii_identifiers: frozenset[str]
) -> None:
    """The leak path everybody forgets: ``str(exc)`` quotes the offending row."""
    trap = str(pii_fixture["driver_exception_trap"])
    assert "100-40-1000" in trap, "the fixture's trap should contain an SSN"

    sanitised = sanitise_driver_error(RuntimeError(trap), source_id="pii", table="customers")
    assert isinstance(sanitised, SanitisedDriverError)
    assert sanitised.classification == "constraint_violation"
    assert_no_leak(sanitised, pii_identifiers, what="SanitisedDriverError")

    assert sanitised.original.sensitivity is Sensitivity.DATA_VALUE
    assert sanitised.original.provenance.acquisition.value == "driver_exception"
    assert sanitised.original.reveal() == trap


def test_inferred_pii_class_is_never_less_restrictive_than_the_fixture(
    pii_adapter: IcebergAdapter,
    pii_source: SourceRef,
    generous_budget: CostBudget,
    pii_fixture: Mapping[str, Any],
) -> None:
    """First-pass classification may over-restrict. It must never under-restrict.

    ``merchant_name`` comes back a direct identifier where the fixture calls it a
    quasi-identifier; that is the safe direction and the test allows it. Coming back
    ``UNKNOWN`` would also be safe at the gate but useless as a catalog, so that is
    rejected separately.
    """
    snapshot = pii_adapter.list_snapshots(pii_source)[-1]
    metadata = pii_adapter.read_metadata_stats(pii_source, snapshot, budget=generous_budget)
    expected = {column["name"]: PiiClass(column["pii_class"]) for column in pii_fixture["columns"]}

    for column in metadata.columns:
        name = column.ref.column.reveal()
        assert column.pii_class is not PiiClass.UNKNOWN, f"{name} was not classified at all"
        assert pii_restrictiveness(column.pii_class) >= pii_restrictiveness(expected[name]), (
            f"{name}: inferred {column.pii_class} is less restrictive than {expected[name]}"
        )


@pytest.mark.parametrize(
    ("column", "expected"),
    [
        ("customer_ssn", PiiClass.DIRECT_IDENTIFIER),
        ("patient_hiv_status", PiiClass.HEALTH),
        ("salary_2024", PiiClass.FINANCIAL),
        ("device_id", PiiClass.QUASI_IDENTIFIER),
        ("notes", PiiClass.SENSITIVE_ATTRIBUTE),
    ],
)
def test_named_columns_classify_as_expected(
    pii_adapter: IcebergAdapter,
    pii_source: SourceRef,
    generous_budget: CostBudget,
    column: str,
    expected: PiiClass,
) -> None:
    snapshot = pii_adapter.list_snapshots(pii_source)[-1]
    metadata = pii_adapter.read_metadata_stats(pii_source, snapshot, budget=generous_budget)
    found = metadata.column(column)
    assert found is not None
    assert found.pii_class is expected
