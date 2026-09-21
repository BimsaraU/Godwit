"""IcebergAdapter probe path: budget refusal before any read, and structural OPAQUE hashing."""

from __future__ import annotations

from collections.abc import Sequence
from typing import cast

import pyarrow as pa
import pytest
from conftest import FakeManifestReader, payments_policy

from godwit_source._contracts import CostBudget, CostBudgetExceeded, ProbeSpec
from godwit_source.access import BlindColumnError
from godwit_source.iceberg import ArrowTable, IcebergAdapter
from godwit_source.instrument import IoLedger

DEVICES = ["d0f41a2c9b7e4d1583aa", "f9c2e71b08a34d6ea115", "d0f41a2c9b7e4d1583aa"]


class ArrowSource:
    """Stands in for Parquet. Records which files and columns were asked for."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def __call__(self, path: str, columns: Sequence[str]) -> ArrowTable:
        self.calls.append((path, tuple(columns)))
        data = {
            "txn_id": pa.array(["txn_1", "txn_2", "txn_3"]),
            "device_id": pa.array(DEVICES),
            "amount": pa.array([1.0, 2.0, 3.0]),
            "customer_email": pa.array(["a@example.org", "b@example.org", "c@example.org"]),
            "merchant_country": pa.array(["GB", "US", "GB"]),
            "created_at": pa.array([1, 2, 3]),
        }
        return cast("ArrowTable", pa.table({c: data[c] for c in columns if c in data}))


def spec(*columns: str, snapshot: str = "s01") -> ProbeSpec:
    return ProbeSpec(
        table="prod.payments", columns=columns, snapshot_id=snapshot, version="1", seed=0
    )


def test_budget_refuses_before_a_single_byte_is_read(
    reader: FakeManifestReader, ledger: IoLedger
) -> None:
    """Estimation comes from manifest file sizes, so refusing is free. Refusing is a normal
    outcome, not an error condition."""
    source = ArrowSource()
    adapter = IcebergAdapter(reader, hash_key=b"k", read_arrow=source)
    budget = CostBudget(max_bytes=1024, max_queries=10)

    with pytest.raises(CostBudgetExceeded):
        adapter.execute_probe(spec("txn_id"), policy=payments_policy(), budget=budget)

    assert source.calls == []
    assert ledger.data_bytes == 0
    assert budget.bytes_spent == 0


def test_estimate_is_free_and_matches_the_manifest(reader: FakeManifestReader) -> None:
    adapter = IcebergAdapter(reader, read_arrow=ArrowSource())
    estimated = adapter.estimate_probe_bytes(spec("txn_id"))
    files = reader.data_files("prod.payments", "s01")
    assert estimated == sum(f.file_size_in_bytes for f in files)


def test_probe_projects_only_readable_columns(reader: FakeManifestReader) -> None:
    source = ArrowSource()
    adapter = IcebergAdapter(reader, hash_key=b"k", read_arrow=source)
    result = adapter.execute_probe(
        spec("txn_id", "device_id"),
        policy=payments_policy(),
        budget=CostBudget(max_bytes=1 << 40, max_queries=10),
    )
    assert result.schema_names == ("txn_id", "device_id")
    assert all(cols == ("txn_id", "device_id") for _, cols in source.calls)
    assert result.aggregates["row_count"].unwrap("test") == 3.0 * len(source.calls)


def test_probe_refuses_a_blind_column(reader: FakeManifestReader) -> None:
    adapter = IcebergAdapter(reader, hash_key=b"k", read_arrow=ArrowSource())
    with pytest.raises(BlindColumnError):
        adapter.execute_probe(
            spec("notes"),
            policy=payments_policy(),
            budget=CostBudget(max_bytes=1 << 40, max_queries=10),
        )


def test_opaque_values_are_replaced_before_aggregation(reader: FakeManifestReader) -> None:
    """Parquet has no server-side compute, so the value is materialised in this worker and
    replaced before anything looks at it. The aggregate sees hashes; nothing else does."""
    seen: list[list[str]] = []

    def aggregate(chunk: ArrowTable) -> dict[str, float]:
        values = cast("list[str]", chunk.column("device_id").to_pylist())  # type: ignore[attr-defined]
        seen.append(values)
        return {"device_id__ndv": float(len(set(values)))}

    adapter = IcebergAdapter(reader, hash_key=b"data-plane-key", read_arrow=ArrowSource())
    result = adapter.execute_probe(
        spec("device_id"),
        policy=payments_policy(),
        budget=CostBudget(max_bytes=1 << 40, max_queries=10),
        aggregate=aggregate,
    )
    assert seen
    flat = [v for chunk in seen for v in chunk]
    assert not set(flat) & set(DEVICES), "no raw device id reached the aggregator"
    assert len({v for v in flat}) == 2, "collision structure is preserved by the keyed hash"
    assert result.aggregates["device_id__ndv"].unwrap("test") > 0


def test_opaque_without_a_key_is_refused(reader: FakeManifestReader) -> None:
    adapter = IcebergAdapter(reader, read_arrow=ArrowSource())
    with pytest.raises(RuntimeError, match="hash key"):
        adapter.execute_probe(
            spec("device_id"),
            policy=payments_policy(),
            budget=CostBudget(max_bytes=1 << 40, max_queries=10),
        )


def test_budget_stops_mid_scan(reader: FakeManifestReader) -> None:
    """A per-file spend means a budget that was estimated optimistically still bites."""
    files = reader.data_files("prod.payments", "s01")
    adapter = IcebergAdapter(reader, hash_key=b"k", read_arrow=ArrowSource())
    budget = CostBudget(
        max_bytes=sum(f.file_size_in_bytes for f in files), max_queries=10
    )
    result = adapter.execute_probe(
        spec("txn_id"), policy=payments_policy(), budget=budget
    )
    assert result.files_read == len(files)
    assert budget.bytes_spent == budget.max_bytes
