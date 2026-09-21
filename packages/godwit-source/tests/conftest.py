"""Fixture plumbing for the A1 tests.

The fake manifest reader serves every metadata read through an
:class:`~godwit_source.instrument.InstrumentedObjectStore`, and it also stages a byte
payload at each data-file path. That is what makes "the metadata tier scans zero bytes of
table data" a real assertion: if any code path touched a Parquet file, the ledger would say
so.
"""

from __future__ import annotations

import json
import pathlib
from collections.abc import Mapping, Sequence
from typing import Any, cast

import pytest

from godwit_source._contracts import ColumnAccessMode, PiiClass
from godwit_source.access import AccessPolicy, ColumnClassification
from godwit_source.base import SnapshotRef
from godwit_source.iceberg import DataFileStats, IcebergAdapter, SchemaField
from godwit_source.instrument import InstrumentedObjectStore, IoLedger

GOLDEN = pathlib.Path(__file__).resolve().parents[3] / "tests" / "golden"
FIXTURE_PATH = GOLDEN / "a1_iceberg_payments.json"


@pytest.fixture(scope="session")
def fixture_data() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))


class FixtureObjectStore:
    """In-memory object store holding fixture manifests and dummy Parquet payloads."""

    def __init__(self, data: Mapping[str, Any]) -> None:
        self._objects: dict[str, bytes] = {}
        for snap in data["snapshots"]:
            key = f"s3://warehouse/prod/payments/metadata/{snap['snapshot_id']}.avro"
            self._objects[key] = json.dumps(snap, sort_keys=True).encode("utf-8")
            for f in snap["files"]:
                self._objects[f["path"]] = b"\x00" * 1024

    def get(self, path: str) -> bytes:
        return self._objects[path]


class FakeManifestReader:
    """Drives :class:`IcebergAdapter` from the golden fixture via a counted object store."""

    def __init__(self, data: Mapping[str, Any], store: InstrumentedObjectStore) -> None:
        self._data = data
        self._store = store
        self._by_id = {s["snapshot_id"]: s for s in data["snapshots"]}

    def _snapshot(self, snapshot_id: str) -> Mapping[str, Any]:
        key = f"s3://warehouse/prod/payments/metadata/{snapshot_id}.avro"
        return cast("Mapping[str, Any]", json.loads(self._store.get(key).decode("utf-8")))

    def snapshots(self, table: str) -> Sequence[SnapshotRef]:
        del table
        return [
            SnapshotRef(
                snapshot_id=s["snapshot_id"],
                sequence_number=int(s["sequence_number"]),
                commit_ms=int(s["commit_ms"]),
            )
            for s in self._data["snapshots"]
        ]

    def schema(self, table: str, snapshot_id: str) -> Sequence[SchemaField]:
        del table
        return [
            SchemaField(field_id=int(f["field_id"]), name=f["name"], data_type=f["data_type"])
            for f in self._snapshot(snapshot_id)["schema"]
        ]

    def data_files(
        self, table: str, snapshot_id: str, *, delta_only: bool = True
    ) -> Sequence[DataFileStats]:
        del table, delta_only
        return [
            DataFileStats(
                path=f["path"],
                file_size_in_bytes=int(f["file_size_in_bytes"]),
                record_count=int(f["record_count"]),
                value_counts={int(k): int(v) for k, v in f["value_counts"].items()},
                null_value_counts={int(k): int(v) for k, v in f["null_value_counts"].items()},
                lower_bounds={int(k): v for k, v in f["lower_bounds"].items()},
                upper_bounds={int(k): v for k, v in f["upper_bounds"].items()},
            )
            for f in self._snapshot(snapshot_id)["files"]
        ]

    def puffin_ndv(self, table: str, snapshot_id: str) -> Mapping[int, int]:
        del table
        return {int(k): int(v) for k, v in self._data["puffin_ndv"][snapshot_id].items()}


@pytest.fixture
def ledger() -> IoLedger:
    return IoLedger()


@pytest.fixture
def reader(fixture_data: Mapping[str, Any], ledger: IoLedger) -> FakeManifestReader:
    store = InstrumentedObjectStore(FixtureObjectStore(fixture_data).get, ledger)
    return FakeManifestReader(fixture_data, store)


@pytest.fixture
def adapter(reader: FakeManifestReader) -> IcebergAdapter:
    return IcebergAdapter(reader, hash_key=b"data-plane-key-not-a-secret-in-tests")


def payments_policy(*, classify_new_column: bool = False) -> AccessPolicy:
    """The classifications a human has confirmed for the fixture table.

    ``notes`` is BLIND (free text, pure liability). ``customer_email`` and ``device_id`` are
    direct identifiers: email is OPEN under a recorded guardrail so the bounds detectors
    have something to chew on, device_id is OPAQUE, which is the default for an identifier.
    ``merchant_country`` is a quasi-identifier opened under a guardrail; note that it could
    not have been made OPAQUE instead, because a hashed ISO country code is about 7.8 bits
    and enumerable in microseconds -- see ``test_access.py``.
    """
    confirmed = [
        ColumnClassification("txn_id", PiiClass.NON_PII, confirmed=True,
                             requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-1"),
        ColumnClassification("customer_email", PiiClass.DIRECT_IDENTIFIER, confirmed=True,
                             requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-2"),
        ColumnClassification("amount", PiiClass.NON_PII, confirmed=True,
                             requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-3"),
        ColumnClassification("merchant_country", PiiClass.QUASI_IDENTIFIER, confirmed=True,
                             requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-5"),
        ColumnClassification("device_id", PiiClass.DIRECT_IDENTIFIER, confirmed=True,
                             input_space_bits=80.0),
        ColumnClassification("created_at", PiiClass.NON_PII, confirmed=True,
                             requested_mode=ColumnAccessMode.OPEN, guardrail_id="G-4"),
        ColumnClassification("notes", PiiClass.FREE_TEXT, confirmed=True),
    ]
    if classify_new_column:
        confirmed.append(
            ColumnClassification("customer_email_v2", PiiClass.DIRECT_IDENTIFIER,
                                 confirmed=True, input_space_bits=64.0)
        )
    return AccessPolicy(confirmed)


@pytest.fixture
def policy() -> AccessPolicy:
    return payments_policy()
