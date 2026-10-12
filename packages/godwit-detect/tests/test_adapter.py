"""The contract's ``Detector`` protocol, over the series detectors."""

from __future__ import annotations

from decimal import Decimal

from _detect_scenarios import golden_rows, graph_window
from _detect_support import DAY, EPOCH, SOURCE
from godwit_contracts.common import ProbeId, SnapshotId
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.discovery import Candidate
from godwit_contracts.probe import ProbeKind, ProbeSpec
from godwit_contracts.protocols import Detector
from godwit_contracts.sketch import SketchBundle
from godwit_contracts.source import SourceKind, SourceRef
from godwit_contracts.taint import schema_name
from godwit_detect import BundleDetector, GraphAnomaly, JensenShannonDrift, RefusalReason
from godwit_sketch import BaseSketch, CategoryHistogram, SketchContext

BUDGET = CostBudget(
    bytes_scanned=10**9, wall_seconds=60.0, usd=Decimal("1"), llm_tokens=0, train_seconds=0.0
)


def _spec(kind: ProbeKind, *columns: str) -> ProbeSpec:
    return ProbeSpec(
        probe_id=ProbeId("probe-1"),
        kind=kind,
        spec_version=1,
        source=SourceRef(
            source_id=SOURCE,
            kind=SourceKind.ICEBERG,
            catalog="golden",
            namespace=schema_name("godwit_golden"),
            table=schema_name("orders"),
        ),
        columns=tuple(schema_name(c) for c in columns),
        seed=7,
        budget=BUDGET,
        as_of=EPOCH,
    )


def _bundle(spec: ProbeSpec, index: int, name: str, sketch: BaseSketch) -> SketchBundle:
    snapshot_id = SnapshotId(f"snap_{index}")
    envelope = sketch.serialise(
        SketchContext(
            source_id=SOURCE,
            snapshot_id=snapshot_id,
            produced_for=spec.key,
            produced_at=EPOCH + DAY * index,
        )
    )
    return SketchBundle(
        bundle_id=f"b{index}",
        probe_key=spec.key,
        source_id=SOURCE,
        snapshot_id=snapshot_id,
        sketches={name: envelope},
        cost_spent=CostSpend(),
        produced_at=EPOCH + DAY * index,
        worker_version="test",
        seed=7,
    )


def test_bundle_detector_satisfies_the_protocol_and_names_the_column() -> None:
    spec = _spec(ProbeKind.CATEGORY_HISTOGRAM, "country")
    adapter = BundleDetector(JensenShannonDrift(), spec=spec, code_version="test")
    assert isinstance(adapter, Detector)
    bundles = [
        _bundle(
            spec,
            i,
            "frequent_items:0",
            CategoryHistogram.from_items([r["country"] for r in golden_rows(i)], {}),
        )
        for i in (1, 2)
    ]
    candidates = adapter.detect(current=bundles[1], baseline=bundles[0], profiles=(), seed=7)
    assert len(candidates) == 1
    (candidate,) = candidates
    assert isinstance(candidate, Candidate)
    assert candidate.lineage.snapshot_id == "snap_2"
    assert candidate.lineage.baseline_snapshot_id == "snap_1"
    assert candidate.lineage.detector_version == adapter.version
    assert [c.reveal() for c in candidate.evidence[0].columns] == ["country"]
    assert adapter.last_results[0].tests == 1
    again = adapter.detect(current=bundles[1], baseline=bundles[0], profiles=(), seed=7)
    assert again == candidates
    assert adapter.detect(current=bundles[1], baseline=None, profiles=(), seed=7) == ()


def test_a_detector_that_needs_history_refuses_through_the_protocol() -> None:
    spec = _spec(ProbeKind.GRAPH_DEGREE, "payer", "payee")
    adapter = BundleDetector(GraphAnomaly(), spec=spec, code_version="test")
    bundles = [_bundle(spec, i, "count_min:graph", graph_window(i, funnel=i == 1)) for i in (0, 1)]
    assert adapter.detect(current=bundles[1], baseline=bundles[0], profiles=(), seed=7) == ()
    (result,) = adapter.last_results
    assert result.refusals[0].reason is RefusalReason.THIN_BASELINE
