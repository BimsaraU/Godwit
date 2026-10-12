"""Against real Iceberg tables built from the golden fixtures.

Real manifests, real Parquet, real column sizes, and every data-file read metered by
``godwit_source.ByteMeter`` -- so "refused before a byte was read" and "a no-change probe
reads nothing" are measurements, not claims.
"""

from __future__ import annotations

import datetime as _dt
import json
import math
import re
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest
from _probe_support import predicate, segment
from godwit_contracts import (
    ColumnRef,
    Operator,
    PiiClass,
    ProbeId,
    ProbeKind,
    ProbeSpec,
    Segment,
    Sensitivity,
    SketchKind,
    SourceId,
    SourceKind,
    SourceRef,
    schema_name,
)
from godwit_guard import (
    AccessControl,
    AccessMode,
    AccessModeMap,
    ClassificationRegistry,
    MemoryLedger,
)
from godwit_probe import (
    IcebergProbeSource,
    MemoryProbeState,
    ProbeExecutor,
    ProbeStatus,
    RefusalReason,
    backfill,
)
from godwit_probe.testing import access_map, generous_budget, simulator_keyring
from godwit_sketch import CategoryHistogram, KllQuantile, decode_envelope
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.sql import SqlCatalog

GOLDEN_SOURCE = SourceId("golden-iceberg")
PII_SOURCE = SourceId("pii-torture")
AT = _dt.datetime(2024, 2, 1, tzinfo=_dt.UTC)


def _catalog(root: Path, name: str) -> Catalog:
    warehouse = root / "warehouse"
    warehouse.mkdir()
    return SqlCatalog(
        name,
        uri=f"sqlite:///{(root / 'catalog.db').as_posix()}",
        warehouse=f"file://{warehouse.as_posix()}",
    )


@pytest.fixture(scope="module")
def golden_catalog(golden_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Catalog:
    """Three appends, one per golden snapshot: snapshot N holds files 0..N."""
    catalog = _catalog(tmp_path_factory.mktemp("golden"), "golden")
    catalog.create_namespace("godwit_golden")
    parts = [pq.read_table(golden_dir / "drift_table" / f"snapshot_{i}.parquet") for i in range(3)]
    table = catalog.create_table("godwit_golden.orders", schema=parts[0].schema)
    for part in parts:
        table.append(part)
    return catalog


@pytest.fixture(scope="module")
def pii_catalog(golden_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Catalog:
    catalog = _catalog(tmp_path_factory.mktemp("pii"), "pii")
    catalog.create_namespace("godwit_golden_pii")
    rows = pq.read_table(golden_dir / "pii_torture" / "table.parquet")
    catalog.create_table("godwit_golden_pii.customers", schema=rows.schema).append(rows)
    return catalog


def _ref(source_id: SourceId, namespace: str, table: str) -> SourceRef:
    return SourceRef(
        source_id=source_id,
        kind=SourceKind.ICEBERG,
        catalog="test",
        namespace=schema_name(namespace, source_id=source_id),
        table=schema_name(table, source_id=source_id),
    )


GOLDEN = _ref(GOLDEN_SOURCE, "godwit_golden", "orders")
PII = _ref(PII_SOURCE, "godwit_golden_pii", "customers")


def _modes_map(ref: SourceRef, modes: dict[str, AccessMode], **kwargs: Any) -> AccessModeMap:
    return access_map(ref, modes, at=AT, **kwargs)


GOLDEN_MODES = {
    "country": AccessMode.OPEN,
    "status": AccessMode.OPEN,
    "amount": AccessMode.OPEN,
    "created_at": AccessMode.OPEN,
    "order_id": AccessMode.OPAQUE,
    "customer_email": AccessMode.OPAQUE,
}


def _spec(
    ref: SourceRef,
    kind: ProbeKind,
    columns: list[str],
    *,
    sketches: tuple[SketchKind, ...] = (),
    where: Segment | None = None,
) -> ProbeSpec:
    return ProbeSpec(
        probe_id=ProbeId("golden"),
        kind=kind,
        spec_version=1,
        source=ref,
        columns=tuple(schema_name(c, source_id=ref.source_id) for c in columns),
        segment=where or Segment(),
        sketches=sketches,
        budget=generous_budget(),
        seed=7,
        as_of=AT,
    )


def _executor(source: IcebergProbeSource, access: AccessModeMap) -> ProbeExecutor:
    return ProbeExecutor(
        source, access=access, state=MemoryProbeState(), keyring=simulator_keyring()
    )


def test_the_documented_drift_appears_at_snap_2_and_the_control_stays_still(
    golden_catalog: Catalog,
) -> None:
    source = IcebergProbeSource(golden_catalog)
    executor = _executor(source, _modes_map(GOLDEN, GOLDEN_MODES))
    state = MemoryProbeState()
    spec = _spec(GOLDEN, ProbeKind.CATEGORY_HISTOGRAM, ["country"])
    outcomes = backfill(executor, state, spec, budget=generous_budget())
    assert [o.status for o in outcomes] == [ProbeStatus.COMPLETED] * 3
    shares: list[dict[str, float]] = []
    for outcome in outcomes:
        assert outcome.bundle is not None
        histogram = decode_envelope(outcome.bundle.sketches["frequent_items:0"])
        assert isinstance(histogram, CategoryHistogram)
        assert histogram.population == 6000  # one golden file per commit
        counts = {key.reveal(): count for key, count in histogram.categories()}
        total = sum(counts.values())
        shares.append({key: count / total for key, count in counts.items()})
    assert shares[0]["s:PT"] < 0.05
    assert shares[1]["s:PT"] < 0.05
    assert shares[2]["s:PT"] == pytest.approx(0.18, abs=0.03)
    us = [share["s:US"] for share in shares]
    assert max(us) - min(us) < 0.12 * max(us) + 0.05


def test_amount_inside_pt_refunds_jumps_an_order_of_magnitude(golden_catalog: Catalog) -> None:
    source = IcebergProbeSource(golden_catalog)
    executor = _executor(source, _modes_map(GOLDEN, GOLDEN_MODES))
    where = segment(
        predicate("country", Operator.EQ, "PT"), predicate("status", Operator.EQ, "refund")
    )
    spec = _spec(GOLDEN, ProbeKind.QUANTILES, ["amount"], where=where)
    outcomes = backfill(executor, MemoryProbeState(), spec, budget=generous_budget())
    medians = []
    for outcome in outcomes:
        assert outcome.bundle is not None
        kll = decode_envelope(outcome.bundle.sketches["kll:0"])
        assert isinstance(kll, KllQuantile)
        medians.append(kll.quantile(0.5).reveal())
    assert medians[0] == pytest.approx(math.exp(3.2), rel=0.6)
    assert medians[2] > 10 * max(medians[0], medians[1])


def test_budget_refusal_reads_zero_data_bytes_on_a_real_table(golden_catalog: Catalog) -> None:
    source = IcebergProbeSource(golden_catalog)
    executor = _executor(source, _modes_map(GOLDEN, GOLDEN_MODES))
    spec = _spec(GOLDEN, ProbeKind.QUANTILES, ["amount"])
    outcome = executor.execute(spec, budget=generous_budget(bytes_scanned=100))
    assert outcome.status is ProbeStatus.REFUSED
    assert outcome.refusal is not None
    assert outcome.refusal.reason is RefusalReason.BUDGET
    assert source.meter.data_bytes == 0
    assert outcome.estimated_cost.bytes_scanned > 100


def test_the_estimate_uses_column_sizes_and_bounds_the_actual(golden_catalog: Catalog) -> None:
    source = IcebergProbeSource(golden_catalog)
    executor = _executor(source, _modes_map(GOLDEN, GOLDEN_MODES))
    spec = _spec(GOLDEN, ProbeKind.NULL_RATE, ["country"])
    outcome = executor.execute(spec, budget=generous_budget())
    assert outcome.status is ProbeStatus.COMPLETED
    delta = source.delta(GOLDEN, since=None, until=source.resolve_snapshot(GOLDEN))
    whole_files = sum(item.size_bytes for item in delta.files)
    assert 0 < outcome.estimated_cost.bytes_scanned < whole_files
    assert 0 < outcome.cost_spent.bytes_scanned <= outcome.estimated_cost.bytes_scanned
    assert outcome.cost_spent.bytes_scanned == source.meter.data_bytes


def test_no_change_on_a_real_table_reads_no_data(golden_catalog: Catalog) -> None:
    source = IcebergProbeSource(golden_catalog)
    executor = _executor(source, _modes_map(GOLDEN, GOLDEN_MODES))
    state = MemoryProbeState()
    spec = _spec(GOLDEN, ProbeKind.DISTINCT_COUNT, ["customer_email"])
    backfill(executor, state, spec, budget=generous_budget())
    read = source.meter.data_bytes
    (again,) = backfill(executor, state, spec, budget=generous_budget())
    assert again.status is ProbeStatus.NO_CHANGE
    assert source.meter.data_bytes == read


def test_pii_torture_opaque_heavy_hitters_carry_no_identifier(
    pii_catalog: Catalog, golden_dir: Path
) -> None:
    leaks = json.loads((golden_dir / "pii_torture" / "expected_leaks.json").read_text())
    forbidden = [
        s
        for s in leaks["must_never_appear_in_any_egress"]
        if s not in {"general", "negative", "positive", "unknown"}
    ]
    modes = {
        "customer_ssn": AccessMode.OPAQUE,
        "device_id": AccessMode.OPAQUE,
        "email": AccessMode.OPAQUE,
        "salary_2024": AccessMode.OPEN,
        "notes": AccessMode.BLIND,
    }
    access = _modes_map(
        PII, modes, pii={"salary_2024": PiiClass.FINANCIAL}, entropy_bits={"customer_ssn": 40.0}
    )
    source = IcebergProbeSource(pii_catalog)
    executor = _executor(source, access)
    spec = _spec(
        PII,
        ProbeKind.HEAVY_HITTERS,
        ["customer_ssn", "device_id", "email"],
        sketches=(SketchKind.COUNT_MIN, SketchKind.THETA),
    )
    outcome = executor.execute(spec, budget=generous_budget())
    assert outcome.status is ProbeStatus.COMPLETED
    assert outcome.bundle is not None
    # Payloads are checked as raw bytes; their base64 rendering is excluded from the text
    # search because random base64 contains digit runs like the salaries in the list.
    rendered = outcome.bundle.model_dump(mode="json")
    for envelope in rendered["sketches"].values():
        envelope.pop("payload")
    blob = json.dumps(rendered) + outcome.model_dump_json(exclude={"bundle"})
    # Our own hex identifiers (probe keys, bundle ids) are hashes and cannot echo a
    # value, but a 32-digit hex string contains a five-digit salary by chance often
    # enough to matter: the probe key here does. Scrub them before searching.
    blob = re.sub(r"\b[a-z][a-z0-9]{1,7}_[0-9a-f]{16,64}\b", "<id>", blob)
    payloads = b"".join(e.payload for e in outcome.bundle.sketches.values())
    assert [s for s in forbidden if s in blob] == []
    assert [s for s in forbidden if s.encode() in payloads] == []

    notes = executor.execute(_spec(PII, ProbeKind.NULL_RATE, ["notes"]), budget=generous_budget())
    assert notes.refusal is not None
    assert notes.refusal.reason is RefusalReason.BLIND_COLUMN
    merchant = executor.execute(
        _spec(PII, ProbeKind.NULL_RATE, ["merchant_name"]), budget=generous_budget()
    )
    assert merchant.refusal is not None
    assert merchant.refusal.reason is RefusalReason.UNCLASSIFIED_COLUMN

    salaries = executor.execute(
        _spec(PII, ProbeKind.QUANTILES, ["salary_2024"]), budget=generous_budget()
    )
    assert salaries.bundle is not None
    assert salaries.bundle.sketches["kll:0"].sensitivity is Sensitivity.DATA_VALUE


def test_a_mode_map_from_the_real_access_control_fails_closed(pii_catalog: Catalog) -> None:
    """Nothing classified yet: godwit-guard resolves every column BLIND, so nothing runs."""
    control = AccessControl(ClassificationRegistry(), ledger=MemoryLedger())
    access = control.mode_map(guardrails=(), at=AT)
    probe = ColumnRef(
        source_id=PII_SOURCE,
        table=schema_name("customers"),
        column=schema_name("customer_ssn"),
    )
    assert access.mode_of(probe) is AccessMode.BLIND
    source = IcebergProbeSource(pii_catalog)
    executor = _executor(source, access)
    for column in ("customer_ssn", "salary_2024", "cohort"):
        outcome = executor.execute(
            _spec(PII, ProbeKind.NULL_RATE, [column]), budget=generous_budget()
        )
        assert outcome.refusal is not None
        assert outcome.refusal.reason is RefusalReason.UNCLASSIFIED_COLUMN
    assert source.meter.data_bytes == 0
