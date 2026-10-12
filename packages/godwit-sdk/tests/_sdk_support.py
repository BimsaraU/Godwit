"""Builders shared by godwit-sdk's tests. Imported by name; see conftest.py."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal
from typing import Final, Self

import pyarrow as pa
from godwit_contracts import CostBudget, ProbeId, ProbeKind, ProbeSpec, schema_name
from godwit_contracts.common import SnapshotId
from godwit_contracts.source import SourceRef
from godwit_detect import ProbeContext, SeriesPoint, SketchSeries
from godwit_sdk import LogicalType, Partition, Snapshot, SourceBase, TableName, logical_type
from godwit_sketch import KllQuantile, SketchContext
from godwit_sketch.deterministic import portable_exp

EPOCH: Final[_dt.datetime] = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)

GENEROUS: Final[CostBudget] = CostBudget(
    bytes_scanned=10**12, wall_seconds=3600.0, usd=Decimal(1000), llm_tokens=0, train_seconds=0.0
)
NOTHING: Final[CostBudget] = CostBudget(
    bytes_scanned=0, wall_seconds=3600.0, usd=Decimal(1000), llm_tokens=0, train_seconds=0.0
)


class MemorySource(SourceBase):
    """An undecorated in-memory source for tests to subclass and decorate."""

    def __init__(self, tables: Mapping[str, pa.Table]) -> None:
        self.tables = dict(tables)

    def snapshot(self, table: TableName, *, at: _dt.datetime | None) -> Snapshot:
        del table, at
        return Snapshot(snapshot_id="v1", sequence_number=1, committed_at=EPOCH)

    def columns(self, table: TableName, snapshot: Snapshot) -> Mapping[str, LogicalType]:
        del snapshot
        return {f.name: logical_type(f.type) for f in self.tables[table.name].schema}

    def partitions(self, table: TableName, snapshot: Snapshot) -> Sequence[Partition]:
        del snapshot
        data = self.tables[table.name]
        return [Partition(key="all", estimated_bytes=data.nbytes, row_count=data.num_rows)]

    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        del partition
        yield self.tables[table.name].select(list(columns))

    @classmethod
    def for_conformance(cls, tables: Mapping[str, pa.Table]) -> Self:
        return cls(tables)


def spec(ref: SourceRef, kind: ProbeKind, *columns: str, at: _dt.datetime = EPOCH) -> ProbeSpec:
    """A probe spec over ``ref`` with a generous budget."""
    return ProbeSpec(
        probe_id=ProbeId(f"test-{kind.value}"),
        kind=kind,
        spec_version=1,
        source=ref,
        columns=tuple(schema_name(c) for c in columns),
        budget=GENEROUS,
        seed=7,
        as_of=at,
    )


def amounts(rows: int = 2000) -> pa.Table:
    """A small payments table: an amount, a status and an identifier."""
    return pa.table(
        {
            "amount": [float(10 + (i * 37) % 900) for i in range(rows)],
            "status": ["settled" if i % 9 else "refund" for i in range(rows)],
            "account": [f"acct-{i % 97:04d}" for i in range(rows)],
        }
    )


def kll_series(windows: list[list[float]]) -> SketchSeries:
    """A daily series of KLL sketches over an ``amount`` column, one per window."""
    from godwit_sdk.examples.rest_source import RestOrdersSource

    ref = RestOrdersSource.source_ref(source_id="src_b", namespace="n", table="payments")
    probe = spec(ref, ProbeKind.QUANTILES, "amount")
    points = []
    for index, values in enumerate(windows):
        when = EPOCH + _dt.timedelta(days=index)
        envelope = KllQuantile.from_items(values, {}).serialise(
            SketchContext(
                source_id=probe.source.source_id,
                snapshot_id=SnapshotId(f"s{index}"),
                produced_for=probe.key,
                produced_at=when,
            )
        )
        points.append(SeriesPoint(at=when, snapshot_id=SnapshotId(f"s{index}"), envelope=envelope))
    return SketchSeries(context=ProbeContext.from_spec(probe, "kll:0"), points=tuple(points))


def pow10(exponent: float) -> float:
    """``10 ** exponent`` with the same bits on every platform (see godwit_sketch.deterministic)."""
    return portable_exp(2.302585092994046 * exponent)
