"""Fixtures for godwit-source.

The expensive one is :func:`golden_iceberg`, which builds a **real** Iceberg table --
real manifests, real Avro, real column bounds -- out of the three golden Parquet
snapshots, using a SQLite catalog in a temporary directory. That matters: the
acceptance claim is "the metadata detectors find the injected drift with zero bytes of
table data read", and a fake manifest would prove nothing about where the bytes came
from. Session-scoped, because building it three times is three times the Avro.

Nothing here reads a clock. Instants come from the golden manifest or from the root
``frozen_now`` fixture.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from godwit_contracts.common import SourceId
from godwit_contracts.cost import CostBudget
from godwit_contracts.sketch import ErrorBound, SketchEnvelope, SketchKind
from godwit_contracts.source import SourceKind, SourceRef
from godwit_contracts.taint import Sensitivity, schema_name
from godwit_source.iceberg import IcebergAdapter
from godwit_source.objectstore import ByteMeter
from godwit_source.sketches import SketchContext
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.sql import SqlCatalog

GOLDEN_NAMESPACE = "godwit_golden"
GOLDEN_TABLE = "orders"
GOLDEN_SOURCE = SourceId("golden-iceberg")

PII_NAMESPACE = "godwit_golden_pii"
PII_TABLE = "customers"
PII_SOURCE = SourceId("pii-torture")


@pytest.fixture(scope="session")
def generous_budget() -> CostBudget:
    """A budget large enough that nothing in the happy path refuses."""
    return CostBudget(
        bytes_scanned=1_000_000_000,
        wall_seconds=600.0,
        usd=Decimal("100"),
        llm_tokens=0,
        train_seconds=0.0,
    )


@pytest.fixture(scope="session")
def golden_manifest(golden_dir: Path) -> Mapping[str, Any]:
    """The golden drift table's hand-written manifest, for the documented drift."""
    return json.loads((golden_dir / "drift_table" / "manifest.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def golden_catalog(golden_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Catalog:
    """A real Iceberg table with three snapshots, one per golden Parquet file.

    Each ``append`` is one commit, so snapshot N of this table contains the data files
    of snapshots 0..N -- which is exactly how a real table accumulates, and is what the
    aggregated bounds in ``read_metadata_stats`` describe.
    """
    root = tmp_path_factory.mktemp("iceberg")
    warehouse = root / "warehouse"
    warehouse.mkdir()
    catalog = SqlCatalog(
        "godwit-test",
        uri=f"sqlite:///{(root / 'catalog.db').as_posix()}",
        warehouse=f"file://{warehouse.as_posix()}",
    )
    catalog.create_namespace(GOLDEN_NAMESPACE)
    snapshots = [
        pq.read_table(golden_dir / "drift_table" / f"snapshot_{index}.parquet")
        for index in range(3)
    ]
    table = catalog.create_table(f"{GOLDEN_NAMESPACE}.{GOLDEN_TABLE}", schema=snapshots[0].schema)
    for snapshot in snapshots:
        table.append(snapshot)
    return catalog


@pytest.fixture
def golden_source() -> SourceRef:
    """A ``SourceRef`` addressing the golden Iceberg table."""
    return SourceRef(
        source_id=GOLDEN_SOURCE,
        kind=SourceKind.ICEBERG,
        catalog="godwit-test",
        namespace=schema_name(GOLDEN_NAMESPACE, source_id=GOLDEN_SOURCE),
        table=schema_name(GOLDEN_TABLE, source_id=GOLDEN_SOURCE),
    )


@pytest.fixture
def golden_meter() -> ByteMeter:
    """A fresh meter per test, so byte assertions mean what they say."""
    return ByteMeter()


@pytest.fixture
def golden_adapter(golden_catalog: Catalog, golden_meter: ByteMeter) -> IcebergAdapter:
    """An adapter over the golden table whose every read is instrumented."""
    return IcebergAdapter(golden_catalog, meter=golden_meter)


@pytest.fixture(scope="session")
def pii_catalog(golden_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Catalog:
    """A real Iceberg table over the PII torture data.

    Real manifests, so the bounds really are two of the twelve people in the fixture.
    Iceberg truncates string bounds to sixteen characters, which is why the leak test
    checks prefixes as well as whole values: a sixteen-character prefix of an email
    address is still that person.
    """
    root = tmp_path_factory.mktemp("iceberg-pii")
    warehouse = root / "warehouse"
    warehouse.mkdir()
    catalog = SqlCatalog(
        "godwit-pii",
        uri=f"sqlite:///{(root / 'catalog.db').as_posix()}",
        warehouse=f"file://{warehouse.as_posix()}",
    )
    catalog.create_namespace(PII_NAMESPACE)
    rows = pq.read_table(golden_dir / "pii_torture" / "table.parquet")
    table = catalog.create_table(f"{PII_NAMESPACE}.{PII_TABLE}", schema=rows.schema)
    table.append(rows)
    return catalog


@pytest.fixture
def pii_source() -> SourceRef:
    """A ``SourceRef`` addressing the PII torture table."""
    return SourceRef(
        source_id=PII_SOURCE,
        kind=SourceKind.ICEBERG,
        catalog="godwit-pii",
        namespace=schema_name(PII_NAMESPACE, source_id=PII_SOURCE),
        table=schema_name(PII_TABLE, source_id=PII_SOURCE),
    )


@pytest.fixture
def pii_adapter(pii_catalog: Catalog) -> IcebergAdapter:
    """An adapter over the PII torture table."""
    return IcebergAdapter(pii_catalog, meter=ByteMeter())


@pytest.fixture(scope="session")
def pii_fixture(golden_dir: Path) -> Mapping[str, Any]:
    """The PII torture fixture: every leak path, in one table."""
    return json.loads((golden_dir / "pii_torture" / "fixture.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def pii_identifiers(pii_fixture: Mapping[str, Any]) -> frozenset[str]:
    """Every identifier value the PII fixture contains, as strings.

    Drawn from the fixture's own leak paths rather than from ``expected_leaks.json``,
    which also lists generic tokens like ``unknown`` and ``general`` that collide with
    enum members. The identifiers here are the ones whose appearance in an untainted
    field would be unambiguous evidence of a leak.
    """
    found: set[str] = set()
    for bounds in pii_fixture["manifest_bounds"].values():
        found.update({str(bounds["lower"]), str(bounds["upper"])})
    for values in pii_fixture["pg_stats_most_common_vals"].values():
        found.update(str(value) for value in values)
    for hitters in pii_fixture["count_min_heavy_hitters"].values():
        found.update(str(item["item"]) for item in hitters)
    found.add(str(pii_fixture["derived_feature_name_trap"]))
    found.add(str(pii_fixture["driver_exception_trap"]))
    generic = {"general", "unknown", "positive", "negative", "pilot_group_a"}
    return frozenset(value for value in found if value not in generic and len(value) > 4)


# --------------------------------------------------------------------------------------
# A DB-API connection that records instead of connecting
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class RecordingCursor:
    """A cursor that remembers what it was asked and answers from a script."""

    statements: list[tuple[str, object]]
    script: list[Sequence[Sequence[object]]]

    def execute(
        self, operation: str, parameters: Mapping[str, object] | Sequence[object] = ()
    ) -> object:
        self.statements.append((operation, parameters))
        return None

    def fetchall(self) -> Sequence[Sequence[object]]:
        return self.script.pop(0) if self.script else []

    def close(self) -> None:
        return None


@dataclass(slots=True)
class RecordingConnection:
    """A DB-API connection that never touches a database.

    This is what makes "zero table scans" provable rather than asserted: every
    statement the adapter issues lands in :attr:`statements`, and a test can read them.
    """

    script: list[Sequence[Sequence[object]]] = field(default_factory=list)
    statements: list[tuple[str, object]] = field(default_factory=list)

    def cursor(self) -> RecordingCursor:
        return RecordingCursor(statements=self.statements, script=self.script)

    @property
    def sql(self) -> list[str]:
        """Just the SQL text, for readable assertions."""
        return [statement for statement, _ in self.statements]


@pytest.fixture
def recording_connection() -> RecordingConnection:
    """A scripted, recording DB-API connection."""
    return RecordingConnection()


# --------------------------------------------------------------------------------------
# A stub sketch builder
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class StubSketchBuilder:
    """Stands in for A2.

    godwit-source owns no sketch code (a stated non-goal), so the probe tests need
    something that satisfies the ``SketchBuilder`` protocol. This one records what it
    was handed and emits a valid ``EXACT_COUNT`` envelope: enough to prove the adapter
    filtered, projected and budgeted correctly, and no more.
    """

    calls: list[tuple[SketchKind, pa.Table | None, int]] = field(default_factory=list)

    def build(
        self,
        *,
        kind: SketchKind,
        params: Mapping[str, int | float | str | bool],
        values: pa.Table | None,
        context: SketchContext,
    ) -> SketchEnvelope:
        self.calls.append((kind, values, context.population))
        payload = str(context.population).encode("utf-8")
        return SketchEnvelope(
            kind=SketchKind.EXACT_COUNT,
            codec="stub-exact-count-v1",
            schema_version=1,
            payload=payload,
            payload_digest=_digest(payload),
            sensitivity=Sensitivity.DERIVED_STATISTIC,
            provenance=context.provenance,
            population=context.population,
            error_bound=ErrorBound(kind="exact", note="a count of rows is exact"),
            params=dict(params),
            source_id=context.source_id,
            snapshot_id=context.snapshot_id,
            produced_for=context.probe_key,
            produced_at=context.produced_at,
        )


def _digest(payload: bytes) -> Any:
    from godwit_contracts.common import content_hash

    return content_hash(payload)


@pytest.fixture
def stub_builder() -> StubSketchBuilder:
    """A recording stand-in for A2's sketch classes."""
    return StubSketchBuilder()


@pytest.fixture(scope="session")
def utc() -> _dt.tzinfo:
    """UTC, so no test has to import datetime just to say so."""
    return _dt.UTC
