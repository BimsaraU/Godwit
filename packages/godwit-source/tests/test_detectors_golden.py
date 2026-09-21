"""L-1 detectors against the golden fixture, with the object-store ledger watching."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from godwit_source.access import AccessPolicy
from godwit_source.detectors import (
    bounds_drift,
    file_layout_anomaly,
    ndv_ratio_shift,
    null_rate_shift,
    row_volume_anomaly,
    run_all,
    schema_change,
)
from godwit_source.iceberg import IcebergAdapter
from godwit_source.instrument import IoLedger
from godwit_source.stats import SnapshotMetadata


def history_through(
    adapter: IcebergAdapter, policy: AccessPolicy, snapshot_id: str
) -> list[SnapshotMetadata]:
    """Metadata series ending at ``snapshot_id`` -- what the detector would have seen then."""
    return adapter.read_metadata_stats("prod.payments", policy=policy, until=snapshot_id)


def test_metadata_read_touches_zero_data_bytes(
    adapter: IcebergAdapter, policy: AccessPolicy, ledger: IoLedger
) -> None:
    """The whole point of L-1: a first-pass signal that costs nothing.

    Proven with an instrumented object-store client rather than asserted in a docstring.
    """
    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    candidates = run_all(history)

    assert history
    assert candidates
    ledger.assert_no_data_bytes()
    assert ledger.metadata_bytes > 0
    assert ledger.data_bytes == 0


def test_null_rate_shift_found_at_injected_snapshot(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    target = fixture_data["injected_drift"]["null_rate"]
    found = null_rate_shift(history_through(adapter, policy, target))
    assert [c.column for c in found] == ["merchant_country"]
    assert found[0].snapshot_id == target
    assert found[0].effect_size > 0.15


def test_row_volume_anomaly_found_at_injected_snapshot(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    target = fixture_data["injected_drift"]["row_volume"]
    found = row_volume_anomaly(history_through(adapter, policy, target))
    assert [c.snapshot_id for c in found] == [target]
    assert found[0].effect_size > 0


def test_bounds_drift_found_on_amount(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    target = fixture_data["injected_drift"]["bounds_drift"]
    found = bounds_drift(history_through(adapter, policy, target))
    assert any(c.column == "amount" for c in found)
    amount = next(c for c in found if c.column == "amount")
    assert amount.snapshot_id == target
    assert amount.effect_size > 1000.0


def test_bounds_drift_emits_no_value_by_default(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    """The distance carries the signal; the bound is a real row."""
    target = fixture_data["injected_drift"]["bounds_drift"]
    history = history_through(adapter, policy, target)
    assert all("lower_bound" not in c.evidence for c in bounds_drift(history))
    with_values = bounds_drift(history, include_bound_values=True)
    assert any("upper_bound" in c.evidence for c in with_values)


def test_ndv_ratio_shift_found_on_opaque_column(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    """device_id is OPAQUE: no bound is ever surfaced, yet the signal still lands."""
    target = fixture_data["injected_drift"]["ndv_ratio"]
    found = ndv_ratio_shift(history_through(adapter, policy, target))
    assert any(c.column == "device_id" for c in found)
    device = next(c for c in found if c.column == "device_id")
    assert device.snapshot_id == target
    assert device.effect_size < 0


def test_file_layout_anomaly_found_at_injected_snapshot(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    target = fixture_data["injected_drift"]["file_layout"]
    found = file_layout_anomaly(history_through(adapter, policy, target))
    statistics = {c.evidence["statistic"] for c in found}
    assert {"file_count", "median_file_bytes"} <= statistics
    assert all(c.snapshot_id == target for c in found)


def test_schema_change_found_at_injected_snapshot(
    adapter: IcebergAdapter, policy: AccessPolicy, fixture_data: Mapping[str, Any]
) -> None:
    target = fixture_data["injected_drift"]["schema_change"]
    found = schema_change(history_through(adapter, policy, target))
    assert len(found) == 1
    added = found[0].evidence["added_columns"]
    assert added.unwrap("test asserts the detector tagged the column name") == (
        "customer_email_v2",
    )


def test_no_candidates_on_the_stable_prefix(
    adapter: IcebergAdapter, policy: AccessPolicy
) -> None:
    """Snapshots s01..s07 are stable by construction. A detector that fires here is noise,
    and noise at 50 alerts/day is the difference between 30% precision and none."""
    history = history_through(adapter, policy, "s07")
    assert run_all(history) == []


def test_detectors_are_deterministic(adapter: IcebergAdapter, policy: AccessPolicy) -> None:
    history = adapter.read_metadata_stats("prod.payments", policy=policy)
    first: Sequence[Any] = run_all(history)
    second: Sequence[Any] = run_all(history)
    assert [(c.detector, c.column, c.p_value) for c in first] == [
        (c.detector, c.column, c.p_value) for c in second
    ]
