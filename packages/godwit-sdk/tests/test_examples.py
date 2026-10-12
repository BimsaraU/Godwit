"""The three reference plugins: conformance, and that each does what its docs say."""

from __future__ import annotations

import datetime as _dt
import json
import math
from pathlib import Path

import pyarrow as pa
import pytest
from _sdk_support import GENEROUS, kll_series, spec
from godwit_contracts import Acquisition, ProbeKind, SnapshotId, data_value, schema_name
from godwit_detect import FixedReference
from godwit_sdk import CapabilityViolationError, PluginBase
from godwit_sdk.examples.benford import BENFORD, BenfordDetector, leading_digits
from godwit_sdk.examples.bloom import BloomMembership
from godwit_sdk.examples.rest_source import RestOrdersSource, UrlTransport
from godwit_sdk.testing import run_conformance
from godwit_sketch import KllQuantile, SketchContext
from godwit_sketch.deterministic import uniforms

HERE = Path(__file__).resolve().parent


@pytest.mark.parametrize("plugin", [RestOrdersSource, BloomMembership, BenfordDetector])
def test_every_reference_plugin_passes_conformance(plugin: type[PluginBase]) -> None:
    report = run_conformance(plugin, pins=HERE / "behaviour_pins.json")
    assert report.passed, report.render()


# -- Bloom ------------------------------------------------------------------------------


def test_bloom_has_no_false_negatives_and_about_the_promised_false_positive_rate() -> None:
    members = [f"member-{i}" for i in range(500)]
    bloom = BloomMembership.from_items(members, {"bits": 8192, "hashes": 4, "seed": 3})

    def tainted(value: str) -> object:
        return data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE)

    assert all(bloom.might_contain(tainted(m)) for m in members)
    strangers = [f"stranger-{i}" for i in range(5000)]
    false_positives = sum(bloom.might_contain(tainted(s)) for s in strangers)
    promised = bloom.error_bound().delta
    assert promised is not None
    assert false_positives / len(strangers) <= promised * 1.5 + 0.005


def test_bloom_declares_itself_value_bearing_because_it_is_a_membership_oracle() -> None:
    envelope = BloomMembership.from_items(["Aoife Brennan"], BloomMembership.DEFAULT_PARAMS)
    serialised = envelope.serialise(
        SketchContext(
            source_id="src",
            snapshot_id="snap",
            produced_for="prb",
            produced_at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
        )
    )
    assert serialised.sensitivity.value == "data_value"
    assert b"Aoife" not in serialised.payload


# -- Benford ----------------------------------------------------------------------------


def _kll(values: list[float]) -> KllQuantile:
    return KllQuantile.from_items(values, {})


def test_leading_digits_of_log_uniform_amounts_follow_benford() -> None:
    values = [10.0 ** (1 + 5 * u) for u in uniforms(20_000, salt="benford-ok")]
    digits, covered = leading_digits(_kll(values))
    assert covered == pytest.approx(1.0)
    assert max(abs(o - e) for o, e in zip(digits, BENFORD, strict=True)) < 0.03


_series = kll_series


def test_benford_flags_fabricated_amounts_in_a_column_that_used_to_conform() -> None:
    honest = [10.0 ** (1 + 4 * u) for u in uniforms(8000, salt="honest")]
    fabricated = [400.0 + 500.0 * u for u in uniforms(8000, salt="fraud")]
    result = BenfordDetector().run(
        _series([honest, honest[:4000] + fabricated[:4000]]),
        policy=FixedReference(snapshot_id=SnapshotId("s0")),
    )
    assert result.tests == 1
    (finding,) = result.findings
    assert finding.p_value is not None and finding.p_value.reveal() < 1e-6
    assert finding.effect.value.reveal() > 0


def test_benford_stays_quiet_on_a_conforming_column() -> None:
    first = [10.0 ** (1 + 4 * u) for u in uniforms(8000, salt="a")]
    second = [10.0 ** (1 + 4 * u) for u in uniforms(8000, salt="b")]
    result = BenfordDetector().run(
        _series([first, second]), policy=FixedReference(snapshot_id=SnapshotId("s0"))
    )
    assert result.tests == 1
    assert result.findings == ()


def test_benford_does_not_fire_on_the_golden_drift(golden_dir: Path) -> None:
    """The golden drift table's documented drift is a segment shift -- PT refunds moving to
    uniform(400, 900) inside 18% of rows -- not fabrication across the column. At the
    power the sketch's rank error allows, the column-level digit test must not fire: a
    Benford alarm on every segment drift would bury the real ones."""
    import pyarrow.parquet as pq

    windows = [
        [
            float(v)
            for v in pq.read_table(golden_dir / "drift_table" / f"snapshot_{i}.parquet")
            .column("amount")
            .to_pylist()
            if v is not None
        ]
        for i in range(3)
    ]
    result = BenfordDetector().run(
        _series(windows), policy=FixedReference(snapshot_id=SnapshotId("s1"))
    )
    assert result.findings == ()
    assert result.tests == 1


def test_benford_never_tests_a_column_that_is_not_money() -> None:
    from godwit_contracts import ColumnProfile, ColumnRef, ColumnRole, LogicalType, SketchBundle
    from godwit_contracts.cost import CostSpend

    series = _series(
        [
            [10.0 ** (1 + 4 * u) for u in uniforms(8000, salt="c")],
            [400.0 + 500.0 * u for u in uniforms(8000, salt="d")],
        ]
    )
    ref = RestOrdersSource.source_ref(source_id="src_b", namespace="n", table="payments")
    probe = spec(ref, ProbeKind.QUANTILES, "amount")
    bundles = [
        SketchBundle(
            bundle_id=f"b{i}",
            probe_key=probe.key,
            source_id=probe.source.source_id,
            snapshot_id=point.snapshot_id,
            sketches={"kll:0": point.envelope},
            cost_spent=CostSpend.zero(),
            produced_at=point.at,
            worker_version="t",
            seed=1,
        )
        for i, point in enumerate(series.points)
    ]

    def profile(role: ColumnRole) -> ColumnProfile:
        return ColumnProfile(
            ref=ColumnRef(
                source_id=probe.source.source_id,
                table=schema_name("payments"),
                column=schema_name("amount"),
            ),
            logical_type=LogicalType.FLOAT,
            native_type="double",
            nullable=True,
            role=role,
            observed_at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
            profile_version=1,
        )

    adapter = BenfordDetector().as_contract(spec=probe, code_version="t")
    as_money = adapter.detect(
        current=bundles[1], baseline=bundles[0], profiles=(profile(ColumnRole.AMOUNT),), seed=1
    )
    as_id = adapter.detect(
        current=bundles[1], baseline=bundles[0], profiles=(profile(ColumnRole.ENTITY_ID),), seed=1
    )
    assert len(as_money) == 1
    assert as_money[0].lineage.detector == "examples.benford"
    assert as_id == ()


# -- REST source ------------------------------------------------------------------------


def test_the_rest_source_probes_through_its_transport() -> None:
    table = pa.table({"amount": [float(i) for i in range(1200)], "status": ["ok"] * 1200})
    plugin = RestOrdersSource.for_conformance({"orders": table})
    ref = RestOrdersSource.source_ref(source_id="src_r", namespace="shop", table="orders")
    from godwit_guard import AccessMode
    from godwit_probe.testing import access_map

    plugin.govern(
        access=access_map(
            ref, {"amount": AccessMode.OPEN}, at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
        )
    )
    snapshot = plugin.resolve_snapshot(ref)
    outcome = plugin.run_probe(spec(ref, ProbeKind.QUANTILES, "amount"), budget=GENEROUS)
    assert outcome.bundle is not None
    assert outcome.files_read == 3  # three pages of 500
    assert snapshot.snapshot_id == "v1"
    assert json.loads(outcome.bundle.model_dump_json())["sketches"]["kll:0"]["population"] == 1200


def test_the_rest_source_cannot_reach_a_host_it_did_not_declare() -> None:
    plugin = RestOrdersSource(UrlTransport("exfil.example.net"))
    ref = RestOrdersSource.source_ref(source_id="src_r", namespace="shop", table="orders")
    with pytest.raises(CapabilityViolationError, match="not declared"):
        plugin.resolve_snapshot(ref)


def test_bloom_false_positive_bound_is_a_probability() -> None:
    empty = BloomMembership.identity(BloomMembership.DEFAULT_PARAMS)
    assert empty.error_bound().delta == 0.0
    full = BloomMembership.from_items([str(i) for i in range(100_000)], {"bits": 64, "hashes": 1})
    delta = full.error_bound().delta
    assert delta is not None and math.isclose(delta, 1.0, abs_tol=1e-9)
