"""PII torture: nothing this package emits carries a row value in an untainted field.

The fixture's ``identifier_values`` are the real row values that appear in it as manifest
bounds. This test walks *every* field of *every* object A1 emits -- metadata, candidates,
profiles, join edges, probe results -- and fails if any of those strings turns up outside a
``Tainted`` wrapper. It is deliberately a structural walk rather than a scan of a rendered
payload: a scanner at the boundary would catch almost none of these, and the control is the
typed taint, not the scan.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

import pytest

from godwit_source._contracts import Tainted
from godwit_source.access import AccessPolicy
from godwit_source.detectors import run_all
from godwit_source.iceberg import IcebergAdapter
from godwit_source.profile import candidate_join_edges, profile_snapshot


def untainted_strings(obj: object, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield ``(path, text)`` for every string reachable without passing through a Tainted.

    A ``Tainted`` node terminates the walk: whatever it holds is tagged, which is the whole
    contract. Everything else is fair game, including dict keys, tuple members and the
    fields of nested dataclasses.
    """
    if isinstance(obj, Tainted):
        return
    if isinstance(obj, str):
        yield path, obj
        return
    if isinstance(obj, bytes | int | float | bool | type(None)):
        return
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            yield from untainted_strings(key, f"{path}.<key>")
            yield from untainted_strings(value, f"{path}[{key!r}]")
        return
    if isinstance(obj, Sequence):
        for i, item in enumerate(obj):
            yield from untainted_strings(item, f"{path}[{i}]")
        return
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        for f in dataclasses.fields(obj):
            yield from untainted_strings(getattr(obj, f.name), f"{path}.{f.name}")
        return
    if hasattr(obj, "__dict__"):
        for name, value in vars(obj).items():
            yield from untainted_strings(value, f"{path}.{name}")


def emitted_objects(adapter: IcebergAdapter, policy: AccessPolicy) -> list[Any]:
    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    return [
        history,
        run_all(history),
        [c for snap in history for c in profile_snapshot(snap)],
        candidate_join_edges(history, min_score=0.0),
    ]


def test_no_row_value_escapes_untainted(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    identifiers = [str(v) for v in fixture_data["identifier_values"]]
    offenders: list[tuple[str, str, str]] = []
    for emitted in emitted_objects(adapter, policy):
        for path, text in untainted_strings(emitted):
            for identifier in identifiers:
                if identifier in text:
                    offenders.append((path, identifier, text))
    assert offenders == []


def test_the_walk_can_actually_fail(fixture_data: Mapping[str, Any]) -> None:
    """A guard on the guard: prove the walk would catch a leak if one existed.

    Without this, a walker with a bug that returns nothing would make the test above pass
    forever while the perimeter quietly leaked.
    """
    identifier = str(fixture_data["identifier_values"][0])
    leaky = {"evidence": {"lower_bound": identifier}}
    found = [text for _, text in untainted_strings(leaky) if identifier in text]
    assert found == [identifier]


def test_tainted_values_are_present_but_wrapped(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    """The bounds really were read -- they are simply tagged. A test that passed because
    nothing was read at all would be worthless."""
    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    email = history[0].columns["customer_email"].bounds
    assert email is not None
    assert email.lower is not None
    raw = email.lower.unwrap("test asserts the bound was read and tagged")
    assert raw in fixture_data["identifier_values"]


def test_tainted_repr_does_not_render_the_value(
    adapter: IcebergAdapter, policy: AccessPolicy
) -> None:
    """Logging an object that holds a bound must not print the bound."""
    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    bounds = history[0].columns["customer_email"].bounds
    assert bounds is not None
    assert bounds.lower is not None
    assert "example.org" not in repr(bounds)
    assert "example.org" not in str(bounds.lower)
    assert "redacted" in repr(bounds.lower)


def test_opaque_column_never_yields_a_bound(
    adapter: IcebergAdapter, policy: AccessPolicy
) -> None:
    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    device = history[0].columns["device_id"]
    assert device.bounds is None
    assert device.counts.ndv is not None, "the derived statistic survives; only the value goes"


def test_blind_column_is_absent_entirely(adapter: IcebergAdapter, policy: AccessPolicy) -> None:
    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    assert "notes" not in history[0].columns
    assert "notes" in history[0].schema_columns, "the name stays in the plan; the data never is"


@pytest.mark.parametrize("include_values", [False, True])
def test_bounds_drift_value_mode_is_the_only_way_a_bound_ships(
    adapter: IcebergAdapter, policy: AccessPolicy, include_values: bool
) -> None:
    from godwit_source.detectors import bounds_drift

    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    candidates = bounds_drift(history, include_bound_values=include_values)
    tainted_bounds = [
        v
        for c in candidates
        for k, v in c.evidence.items()
        if k.endswith("_bound")
    ]
    assert bool(tainted_bounds) is include_values
    assert all(isinstance(v, Tainted) for v in tainted_bounds)
