"""SourceBase: tainting, fail-closed governance, refusals, budget, sanitising."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable, Mapping, Sequence

import pyarrow as pa
import pytest
from _sdk_support import EPOCH, GENEROUS, NOTHING, MemorySource, amounts, spec
from godwit_contracts import (
    BudgetExceededError,
    ProbeKind,
    Sensitivity,
    SourceAdapter,
)
from godwit_guard import AccessMode
from godwit_probe import ProbeKeyring, ProbeStatus
from godwit_probe.testing import access_map
from godwit_sdk import (
    ColumnStats,
    Partition,
    PluginFailedError,
    ProbeRefusedError,
    ResourceLimitError,
    ResourceLimits,
    Snapshot,
    TableName,
    source,
)


@source(name="stats", namespace="test", version="0.1.0")
class StatsSource(MemorySource):
    """Publishes catalog statistics, including bounds and common values."""

    def column_stats(self, table: TableName, snapshot: Snapshot) -> Mapping[str, ColumnStats]:
        del table, snapshot
        return {
            "account": ColumnStats(
                null_fraction=0.0,
                distinct=97,
                minimum="acct-0000",
                maximum="acct-0096",
                common_values=("acct-0001", "acct-0002"),
            )
        }


@source(name="capped", namespace="test", version="0.1.0", limits=ResourceLimits(max_bytes_read=64))
class CappedSource(MemorySource):
    """Under-reports its partitions and is capped at 64 bytes per probe."""

    def partitions(self, table: TableName, snapshot: Snapshot) -> Sequence[Partition]:
        del table, snapshot
        return [Partition(key="all", estimated_bytes=0, row_count=0)]


@source(name="under", namespace="test", version="0.1.0")
class UnderSource(MemorySource):
    """Estimates nothing, so only the mid-read check can stop it."""

    def partitions(self, table: TableName, snapshot: Snapshot) -> Sequence[Partition]:
        del table, snapshot
        return [Partition(key="all", estimated_bytes=0, row_count=0)]


@source(name="naive", namespace="test", version="0.1.0")
class NaiveSnapshotSource(MemorySource):
    def snapshot(self, table: TableName, *, at: _dt.datetime | None) -> Snapshot:
        del table, at
        return Snapshot(snapshot_id="v 1; drop", sequence_number=1, committed_at=EPOCH)


@source(name="greedy", namespace="test", version="0.1.0")
class GreedySource(MemorySource):
    """Returns every column whatever it is asked for."""

    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        del partition, columns
        yield self.tables[table.name]


def _governed(plugin: MemorySource, **modes: AccessMode) -> object:
    ref = type(plugin).source_ref(source_id="src_t", namespace="shop", table="payments")
    plugin.govern(
        access=access_map(ref, modes, at=EPOCH),
        keyring=ProbeKeyring(column_key=b"k" * 32, sketch_key=b"s" * 32),
    )
    return ref


def test_profile_taints_bounds_and_common_values_as_data_values() -> None:
    plugin = StatsSource({"payments": amounts()})
    ref = StatsSource.source_ref(source_id="src_t", namespace="shop", table="payments")
    assert isinstance(plugin, SourceAdapter)
    profile = plugin.profile_table(ref, plugin.resolve_snapshot(ref), budget=NOTHING)
    account = next(c for c in profile.columns if c.ref.column.reveal() == "account")
    assert account.min_bound is not None and account.min_bound.sensitivity is Sensitivity.DATA_VALUE
    assert all(v.sensitivity is Sensitivity.DATA_VALUE for v in account.most_common_values)
    assert account.distinct_estimate is not None
    assert account.distinct_estimate.sensitivity is Sensitivity.DERIVED_STATISTIC
    assert account.ref.column.sensitivity is Sensitivity.SCHEMA_NAME
    assert "acct-0000" not in repr(profile)


def test_an_ungoverned_source_fails_closed() -> None:
    plugin = StatsSource({"payments": amounts()})
    ref = StatsSource.source_ref(source_id="src_t", namespace="shop", table="payments")
    with pytest.raises(ProbeRefusedError, match="unclassified"):
        plugin.execute_probe(
            spec(ref, ProbeKind.QUANTILES, "amount"), plugin.resolve_snapshot(ref), budget=GENEROUS
        )


def test_a_probe_for_another_plugins_table_is_refused() -> None:
    plugin = StatsSource({"payments": amounts()})
    ref = CappedSource.source_ref(source_id="src_t", namespace="shop", table="payments")
    with pytest.raises(ProbeRefusedError, match="wrong_source"):
        plugin.run_probe(spec(ref, ProbeKind.QUANTILES, "amount"), budget=GENEROUS)


def test_opaque_identifiers_are_sketched_as_keyed_hashes() -> None:
    plugin = StatsSource({"payments": amounts()})
    ref = _governed(plugin, account=AccessMode.OPAQUE)
    outcome = plugin.run_probe(spec(ref, ProbeKind.HEAVY_HITTERS, "account"), budget=GENEROUS)
    assert outcome.bundle is not None
    envelope = outcome.bundle.sketches["count_min:0"]
    assert b"acct-0001" not in envelope.payload


def test_a_budget_refusal_raises_the_contract_error_before_reading() -> None:
    plugin = StatsSource({"payments": amounts()})
    ref = _governed(plugin, amount=AccessMode.OPEN)
    with pytest.raises(BudgetExceededError):
        plugin.execute_probe(
            spec(ref, ProbeKind.QUANTILES, "amount"), plugin.resolve_snapshot(ref), budget=NOTHING
        )


def test_an_under_estimating_plugin_is_stopped_by_its_byte_ceiling() -> None:
    plugin = CappedSource({"payments": amounts()})
    ref = _governed(plugin, amount=AccessMode.OPEN)
    with pytest.raises(ResourceLimitError, match="max_bytes_read=64"):
        plugin.run_probe(spec(ref, ProbeKind.QUANTILES, "amount"), budget=GENEROUS)


def test_a_mid_read_overrun_of_the_budget_is_a_budget_refusal() -> None:
    plugin = UnderSource({"payments": amounts(50_000)})
    ref = _governed(plugin, amount=AccessMode.OPEN)
    tight = GENEROUS.model_copy(update={"bytes_scanned": 10})
    probe = spec(ref, ProbeKind.QUANTILES, "amount")
    outcome = plugin.run_probe(probe, budget=tight)
    assert outcome.status is ProbeStatus.CANCELLED
    with pytest.raises(BudgetExceededError, match="exceeded the budget"):
        plugin.execute_probe(probe, plugin.resolve_snapshot(ref), budget=tight)


def test_a_snapshot_id_that_is_not_a_plain_identifier_is_refused() -> None:
    plugin = NaiveSnapshotSource({"payments": amounts()})
    ref = NaiveSnapshotSource.source_ref(source_id="src_t", namespace="shop", table="payments")
    with pytest.raises(PluginFailedError, match="snapshot_id_not_a_plain_identifier"):
        plugin.resolve_snapshot(ref)


def test_a_plugin_that_hands_over_unrequested_columns_fails_the_probe() -> None:
    plugin = GreedySource({"payments": amounts()})
    ref = _governed(plugin, amount=AccessMode.OPEN, account=AccessMode.BLIND)
    with pytest.raises(PluginFailedError, match="plan_violation"):
        plugin.run_probe(spec(ref, ProbeKind.QUANTILES, "amount"), budget=GENEROUS)


def test_completed_probes_report_bytes_and_are_deterministic() -> None:
    first = StatsSource({"payments": amounts()})
    second = StatsSource({"payments": amounts()})
    ref = _governed(first, amount=AccessMode.OPEN)
    _governed(second, amount=AccessMode.OPEN)
    one = first.run_probe(spec(ref, ProbeKind.QUANTILES, "amount"), budget=GENEROUS)
    two = second.run_probe(spec(ref, ProbeKind.QUANTILES, "amount"), budget=GENEROUS)
    assert one.status is ProbeStatus.COMPLETED
    assert one.cost_spent.bytes_scanned > 0
    assert one.bundle == two.bundle
    assert one.bundle is not None
    assert one.bundle.worker_version.startswith("godwit-sdk/0.1.0+test.stats/0.1.0")
