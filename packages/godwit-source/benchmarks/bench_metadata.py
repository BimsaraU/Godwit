"""Benchmark: metadata read time and bytes for a 10,000-file table.

Run with ``python benchmarks/bench_metadata.py``. Deterministic: the synthetic manifest is
built from fixed values, and the only thing that varies between runs is the clock, which is
read here and nowhere in the library.

The number that matters is not the wall time. It is the byte column: the whole L-1 tier
exists so that the first pass over a table costs metadata bytes rather than data bytes, and
the ratio between the two is the argument for the design.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from godwit_source._contracts import ColumnAccessMode, PiiClass
from godwit_source.access import AccessPolicy, ColumnClassification
from godwit_source.base import SnapshotRef
from godwit_source.detectors import run_all
from godwit_source.iceberg import DataFileStats, IcebergAdapter, SchemaField
from godwit_source.instrument import InstrumentedObjectStore, IoLedger

FILES_PER_SNAPSHOT = 10_000
SNAPSHOTS = 8
COLUMNS = 24
AVG_MANIFEST_BYTES_PER_FILE = 420  # a realistic Avro manifest entry with 24 columns of stats
AVG_DATA_BYTES_PER_FILE = 128 * 1024 * 1024


def schema() -> list[SchemaField]:
    fields = [SchemaField(1, "txn_id", "string"), SchemaField(2, "amount", "double")]
    fields += [SchemaField(i, f"attr_{i:02d}", "string") for i in range(3, COLUMNS + 1)]
    return fields


class SyntheticReader:
    """A manifest reader over a synthetic table, served through a counted object store."""

    def __init__(self, store: InstrumentedObjectStore) -> None:
        self._store = store
        self._schema = schema()

    def snapshots(self, table: str) -> Sequence[SnapshotRef]:
        del table
        return [
            SnapshotRef(f"s{i:02d}", i, 1_700_000_000_000 + i * 86_400_000)
            for i in range(1, SNAPSHOTS + 1)
        ]

    def schema(self, table: str, snapshot_id: str) -> Sequence[SchemaField]:
        del table, snapshot_id
        return self._schema

    def data_files(
        self, table: str, snapshot_id: str, *, delta_only: bool = True
    ) -> Sequence[DataFileStats]:
        del table, delta_only
        self._store.get(f"s3://warehouse/bench/metadata/{snapshot_id}.avro")
        drift = 3 if snapshot_id == f"s{SNAPSHOTS:02d}" else 0
        return [
            DataFileStats(
                path=f"s3://warehouse/bench/data/{snapshot_id}-{n:05d}.parquet",
                file_size_in_bytes=AVG_DATA_BYTES_PER_FILE,
                record_count=1_000_000,
                value_counts={f.field_id: 1_000_000 for f in self._schema},
                null_value_counts={f.field_id: 10 * (1 + drift) for f in self._schema},
                lower_bounds={1: "txn_00000001", 2: 0.01},
                upper_bounds={1: "txn_09999999", 2: 4_999.0 + drift * 20_000},
            )
            for n in range(FILES_PER_SNAPSHOT)
        ]

    def puffin_ndv(self, table: str, snapshot_id: str) -> Mapping[int, int]:
        del table, snapshot_id
        return {f.field_id: 900_000 for f in self._schema}


class SyntheticStore:
    """Returns a manifest-sized payload per snapshot; data files are never requested."""

    def get(self, path: str) -> bytes:
        if path.endswith(".avro"):
            return b"\x00" * (FILES_PER_SNAPSHOT * AVG_MANIFEST_BYTES_PER_FILE)
        raise AssertionError(f"benchmark must not read data: {path}")


def policy() -> AccessPolicy:
    confirmed = [
        ColumnClassification("txn_id", PiiClass.NON_PII, confirmed=True,
                             requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-1"),
        ColumnClassification("amount", PiiClass.NON_PII, confirmed=True,
                             requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-2"),
    ]
    confirmed += [
        ColumnClassification(f"attr_{i:02d}", PiiClass.DIRECT_IDENTIFIER, confirmed=True,
                             input_space_bits=64.0)
        for i in range(3, COLUMNS + 1)
    ]
    return AccessPolicy(confirmed)


def main() -> None:
    ledger = IoLedger()
    reader = SyntheticReader(InstrumentedObjectStore(SyntheticStore().get, ledger))
    adapter = IcebergAdapter(reader)

    started = time.perf_counter()
    history = adapter.read_metadata_stats("bench.table", policy=policy())
    read_seconds = time.perf_counter() - started

    started = time.perf_counter()
    candidates = run_all(history)
    detect_seconds = time.perf_counter() - started

    scanned_bytes = SNAPSHOTS * FILES_PER_SNAPSHOT * AVG_DATA_BYTES_PER_FILE
    report = {
        "files_per_snapshot": FILES_PER_SNAPSHOT,
        "snapshots": SNAPSHOTS,
        "columns": COLUMNS,
        "metadata_read_seconds": round(read_seconds, 3),
        "detect_seconds": round(detect_seconds, 3),
        "metadata_bytes": ledger.metadata_bytes,
        "data_bytes": ledger.data_bytes,
        "bytes_a_full_scan_would_have_cost": scanned_bytes,
        "byte_ratio": f"1 : {scanned_bytes // max(ledger.metadata_bytes, 1):,}",
        "candidates": len(candidates),
        "detectors_that_fired": sorted({c.detector for c in candidates}),
    }
    ledger.assert_no_data_bytes()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
