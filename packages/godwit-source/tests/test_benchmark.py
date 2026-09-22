"""Benchmark: what does the free metadata tier actually cost on a wide table?

The brief asks for metadata read time and bytes for a ten-thousand-file table. The
recorded figures are in ``docs/packages/godwit-source.md``. This test runs the same
measurement at a smaller default size so that ``make test`` stays quick, and reports
its numbers so a regression is visible in the output rather than only in a threshold.

Set ``GODWIT_BENCH_FILES=10000`` to reproduce the recorded run. Building the table
dominates the wall time either way -- writing ten thousand Parquet files takes about
forty seconds, and reading the manifest that describes them takes about a fiftieth of
that, which is the whole point of the exercise.

What is asserted rather than merely printed:

* Zero bytes of table data. At ten thousand files, a metadata path that quietly opened
  one Parquet footer per file would be a scan.
* Metadata bytes scale with files, not with rows. The manifest holds one entry per
  file, and the per-entry cost has to stay roughly constant or the free tier stops
  being free on the tables that need it most.
"""

from __future__ import annotations

import os
import time
from decimal import Decimal
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from godwit_contracts.common import SourceId
from godwit_contracts.cost import CostBudget
from godwit_contracts.source import SourceKind, SourceRef
from godwit_contracts.taint import schema_name
from godwit_source.iceberg import IcebergAdapter
from godwit_source.objectstore import ByteMeter
from pyiceberg.catalog.sql import SqlCatalog

DEFAULT_FILES = 1000
ROWS_PER_FILE = 10
MAX_METADATA_BYTES_PER_FILE = 400
"""Ceiling on manifest bytes per data file.

A manifest entry is a fixed set of per-column statistics, so this is a property of the
schema rather than of the table's size. Measured at roughly 130 bytes for a three-column
table; the ceiling is loose enough to survive Avro block boundaries and tight enough
that an accidental per-file footer read would blow straight through it.
"""

BENCH_SOURCE = SourceId("bench")
BUDGET = CostBudget(
    bytes_scanned=1_000_000_000,
    wall_seconds=600.0,
    usd=Decimal("10"),
    llm_tokens=0,
    train_seconds=0.0,
)


def file_count() -> int:
    raw = os.environ.get("GODWIT_BENCH_FILES")
    return int(raw) if raw else DEFAULT_FILES


@pytest.fixture(scope="module")
def wide_table(tmp_path_factory: pytest.TempPathFactory) -> tuple[IcebergAdapter, SourceRef, int]:
    """An Iceberg table with many small data files, registered in one commit.

    ``add_files`` rather than repeated ``append``: one commit with N entries is the
    shape a real wide table has after a compaction-free load, and it keeps the fixture
    from costing N snapshots.
    """
    count = file_count()
    root = tmp_path_factory.mktemp("bench")
    warehouse = root / "warehouse"
    warehouse.mkdir()
    parts = root / "parts"
    parts.mkdir()

    catalog = SqlCatalog(
        "godwit-bench",
        uri=f"sqlite:///{(root / 'catalog.db').as_posix()}",
        warehouse=f"file://{warehouse.as_posix()}",
    )
    catalog.create_namespace("bench")
    schema = pa.schema([("id", pa.int64()), ("amount", pa.float64()), ("label", pa.string())])
    table = catalog.create_table("bench.wide", schema=schema)

    locations: list[str] = []
    for index in range(count):
        path = parts / f"part-{index:06d}.parquet"
        pq.write_table(
            pa.table(
                {
                    "id": pa.array([index * ROWS_PER_FILE + row for row in range(ROWS_PER_FILE)]),
                    "amount": pa.array([float(index) + row for row in range(ROWS_PER_FILE)]),
                    "label": pa.array([f"l{index:06d}_{row}" for row in range(ROWS_PER_FILE)]),
                },
                schema=schema,
            ),
            path,
        )
        locations.append(f"file://{Path(path).as_posix()}")
    table.add_files(locations)

    source = SourceRef(
        source_id=BENCH_SOURCE,
        kind=SourceKind.ICEBERG,
        catalog="godwit-bench",
        namespace=schema_name("bench", source_id=BENCH_SOURCE),
        table=schema_name("wide", source_id=BENCH_SOURCE),
    )
    return IcebergAdapter(catalog, meter=ByteMeter()), source, count


def test_metadata_read_cost_scales_with_files_not_rows(
    wide_table: tuple[IcebergAdapter, SourceRef, int], capsys: pytest.CaptureFixture[str]
) -> None:
    adapter, source, count = wide_table
    snapshot = adapter.resolve_snapshot(source)

    baseline = adapter.meter.metadata_bytes
    started = time.perf_counter()
    metadata = adapter.read_metadata_stats(source, snapshot, budget=BUDGET)
    elapsed = time.perf_counter() - started

    metadata_bytes = adapter.meter.metadata_bytes - baseline
    assert metadata.row_count is not None
    assert metadata.row_count.reveal() == count * ROWS_PER_FILE
    assert metadata.layout is not None
    assert metadata.layout.file_count.reveal() == count

    assert adapter.meter.data_bytes == 0, "the metadata path opened a data file"
    assert adapter.meter.data_reads == 0
    per_file = metadata_bytes / count
    assert per_file <= MAX_METADATA_BYTES_PER_FILE, (
        f"{per_file:.0f} metadata bytes per file exceeds the ceiling; a per-file footer "
        "read would look exactly like this"
    )

    with capsys.disabled():
        print(
            f"\n  godwit-source metadata benchmark"
            f"\n    files            {count}"
            f"\n    rows             {count * ROWS_PER_FILE}"
            f"\n    metadata bytes   {metadata_bytes} ({per_file:.0f}/file)"
            f"\n    data bytes       {adapter.meter.data_bytes}"
            f"\n    wall seconds     {elapsed:.3f}"
            f"\n    projected @10k   {int(per_file * 10_000)} bytes, "
            f"{elapsed * 10_000 / count:.3f}s"
        )


def test_the_whole_table_is_profiled_from_one_manifest_read(
    wide_table: tuple[IcebergAdapter, SourceRef, int],
) -> None:
    """Three columns, N files, one pass. Bounds are reduced across files, not re-read."""
    adapter, source, count = wide_table
    snapshot = adapter.resolve_snapshot(source)
    metadata = adapter.read_metadata_stats(source, snapshot, budget=BUDGET)

    assert {column.ref.column.reveal() for column in metadata.columns} == {
        "id",
        "amount",
        "label",
    }
    identifier = metadata.column("id")
    assert identifier is not None
    assert identifier.lower_bound is not None
    assert identifier.upper_bound is not None
    assert identifier.lower_bound.reveal() == 0
    assert identifier.upper_bound.reveal() == count * ROWS_PER_FILE - 1
