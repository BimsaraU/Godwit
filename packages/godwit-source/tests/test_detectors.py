"""Unit tests for the six L-1 detectors, on metadata built by hand.

The golden fixture proves the detectors work on a real table. These prove they work on
the cases a real table does not conveniently contain: a null rate that collapses, a
cardinality that halves, a column that disappears, a backfill that quadruples the file
count -- and, just as importantly, the several ways a detector must stay quiet.

Everything here is assembled with :func:`metadata`, which builds a
``SnapshotMetadata`` from plain numbers. No adapter, no catalog, no I/O: a detector is a
pure function over metadata and it is tested as one.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping, Sequence

import pytest
from godwit_contracts.common import ScalarValue, SnapshotId, SourceId
from godwit_contracts.discovery import Candidate
from godwit_contracts.source import ColumnRef, LogicalType, SnapshotRef, SourceKind, SourceRef
from godwit_contracts.taint import Acquisition, data_value, derived_statistic, schema_name
from godwit_source.detectors import (
    DEFAULT_CONFIG,
    DetectorConfig,
    bounds_drift,
    evaluate_deltas,
    file_layout_anomaly,
    ndv_ratio_shift,
    null_rate_shift,
    row_volume_anomaly,
    run_metadata_detectors,
    schema_change,
)
from godwit_source.metadata import ColumnMetadata, FileLayoutStats, SnapshotMetadata

SOURCE_ID = SourceId("unit")
EPOCH = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
CODE_VERSION = "test-unit"
SEED = 7

SOURCE = SourceRef(
    source_id=SOURCE_ID,
    kind=SourceKind.ICEBERG,
    catalog="unit",
    namespace=schema_name("ns", source_id=SOURCE_ID),
    table=schema_name("events", source_id=SOURCE_ID),
)


def column(
    name: str,
    *,
    logical_type: LogicalType = LogicalType.FLOAT,
    row_count: int = 1000,
    nulls: int | None = None,
    distinct: int | None = None,
    bounds: tuple[ScalarValue, ScalarValue] | None = None,
) -> ColumnMetadata:
    """One column's metadata, with only the fields a given test cares about."""

    def statistic(value: int | None) -> object:
        return (
            None
            if value is None
            else derived_statistic(value, source_id=SOURCE_ID, table="events", column=name)
        )

    def bound(value: ScalarValue) -> object:
        return data_value(
            value,
            acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS,
            source_id=SOURCE_ID,
            table="events",
            column=name,
        )

    return ColumnMetadata(
        ref=ColumnRef(
            source_id=SOURCE_ID,
            table=schema_name("events", source_id=SOURCE_ID),
            column=schema_name(name, source_id=SOURCE_ID, table="events"),
        ),
        logical_type=logical_type,
        native_type=logical_type.value,
        nullable=True,
        row_count=statistic(row_count),
        null_count=statistic(nulls),
        value_count=statistic(None if nulls is None else row_count - nulls),
        distinct_estimate=statistic(distinct),
        lower_bound=None if bounds is None else bound(bounds[0]),
        upper_bound=None if bounds is None else bound(bounds[1]),
    )


def metadata(
    index: int,
    columns: Sequence[ColumnMetadata],
    *,
    row_count: int = 1000,
    layout: tuple[int, float] | None = None,
) -> SnapshotMetadata:
    """One snapshot's metadata. ``index`` orders the series and dates it."""
    committed = EPOCH + _dt.timedelta(days=7 * index)
    return SnapshotMetadata(
        source=SOURCE,
        snapshot=SnapshotRef(
            source_id=SOURCE_ID,
            snapshot_id=SnapshotId(f"snap_{index}"),
            sequence_number=index,
            committed_at=committed,
        ),
        columns=tuple(columns),
        row_count=derived_statistic(row_count, source_id=SOURCE_ID, table="events"),
        layout=(
            None
            if layout is None
            else FileLayoutStats(
                file_count=derived_statistic(layout[0], source_id=SOURCE_ID),
                total_bytes=derived_statistic(int(layout[0] * layout[1]), source_id=SOURCE_ID),
                mean_file_bytes=derived_statistic(layout[1], source_id=SOURCE_ID),
                stdev_file_bytes=derived_statistic(0.0, source_id=SOURCE_ID),
            )
        ),
        observed_at=committed,
    )


def run(detector: object, history: Sequence[SnapshotMetadata]) -> tuple[Candidate, ...]:
    assert callable(detector)
    found: tuple[Candidate, ...] = detector(history, code_version=CODE_VERSION, seed=SEED)
    return found


# --------------------------------------------------------------------------------------
# evaluate_deltas: the shared decision rule
# --------------------------------------------------------------------------------------


def test_a_single_transition_never_fires() -> None:
    """One change and nothing to compare it against is not evidence of anything."""
    verdict = evaluate_deltas([5.0], threshold=0.5, config=DEFAULT_CONFIG)
    assert verdict is not None
    assert verdict.fired is False
    assert verdict.p_value is None


def test_an_empty_series_has_no_verdict() -> None:
    assert evaluate_deltas([], threshold=0.5, config=DEFAULT_CONFIG) is None


def test_a_change_in_line_with_history_does_not_fire() -> None:
    """A table that always moves by the same amount is not drifting."""
    verdict = evaluate_deltas([0.6, 0.6], threshold=0.5, config=DEFAULT_CONFIG)
    assert verdict is not None
    assert verdict.fired is False


def test_a_change_out_of_line_with_history_fires() -> None:
    verdict = evaluate_deltas([0.05, 1.2], threshold=0.5, config=DEFAULT_CONFIG)
    assert verdict is not None
    assert verdict.fired is True


def test_a_long_history_uses_a_real_p_value() -> None:
    """With enough history the fallback gives way to a robust z and a p-value."""
    verdict = evaluate_deltas([0.01, -0.02, 0.0, 0.01, 3.0], threshold=0.5, config=DEFAULT_CONFIG)
    assert verdict is not None
    assert verdict.p_value is not None
    assert verdict.p_value < 0.01
    assert verdict.fired is True


# --------------------------------------------------------------------------------------
# bounds_drift
# --------------------------------------------------------------------------------------


def test_bounds_drift_finds_a_range_explosion() -> None:
    history = [
        metadata(0, [column("amount", bounds=(1.0, 100.0))]),
        metadata(1, [column("amount", bounds=(1.0, 100.0))]),
        metadata(2, [column("amount", bounds=(1.0, 900.0))]),
    ]
    found = run(bounds_drift, history)
    assert len(found) == 1
    assert found[0].evidence[0].columns[0].reveal() == "amount"
    assert found[0].segment.predicates[0].op.value == "not_null"
    assert found[0].segment.predicates[0].values == ()


def test_bounds_drift_ignores_a_steadily_advancing_identifier() -> None:
    """The order-id case. A prefix that advances every load is not drift."""
    history = [
        metadata(
            index,
            [
                column(
                    "order_id",
                    logical_type=LogicalType.STRING,
                    bounds=(f"ord_{index:02d}_00000", f"ord_{index:02d}_05999"),
                )
            ],
        )
        for index in range(4)
    ]
    assert run(bounds_drift, history) == ()


def test_bounds_drift_finds_a_location_shift_without_a_range_change() -> None:
    """A distribution can move without spreading. Range alone would miss it."""
    history = [
        metadata(0, [column("amount", bounds=(0.0, 100.0))]),
        metadata(1, [column("amount", bounds=(0.0, 100.0))]),
        metadata(2, [column("amount", bounds=(500.0, 600.0))]),
    ]
    found = run(bounds_drift, history)
    assert len(found) == 1
    assert {evidence.sketch_names for evidence in found[0].evidence}


def test_bounds_drift_is_silent_without_bounds() -> None:
    history = [metadata(index, [column("amount")]) for index in range(3)]
    assert run(bounds_drift, history) == ()


def test_bounds_drift_is_silent_on_a_tiny_table() -> None:
    """Below ``min_population`` every statistic is noise and every segment a small cell."""
    history = [
        metadata(
            index, [column("amount", row_count=10, bounds=(1.0, 10.0 * (index + 1)))], row_count=10
        )
        for index in range(3)
    ]
    assert run(bounds_drift, history) == ()


# --------------------------------------------------------------------------------------
# null_rate_shift and ndv_ratio_shift
# --------------------------------------------------------------------------------------


def test_null_rate_shift_finds_a_collapse() -> None:
    """Silent data-quality failure: an upstream join starts missing."""
    history = [
        metadata(0, [column("merchant", nulls=5)]),
        metadata(1, [column("merchant", nulls=5)]),
        metadata(2, [column("merchant", nulls=400)]),
    ]
    found = run(null_rate_shift, history)
    assert len(found) == 1
    evidence = found[0].evidence[0]
    assert evidence.kind.value == "null_rate_shift"
    assert evidence.p_value is not None
    assert evidence.p_value.reveal() < 0.01
    assert found[0].segment.predicates[0].op.value == "is_null"
    assert evidence.sketch_names == ("manifest.null_value_counts", "manifest.record_count")


def test_null_rate_shift_stays_quiet_when_nothing_moves() -> None:
    history = [metadata(index, [column("merchant", nulls=5)]) for index in range(3)]
    assert run(null_rate_shift, history) == ()


def test_null_rate_shift_needs_a_count_to_have_been_recorded() -> None:
    """A writer that records no null counts is not a table with no nulls."""
    history = [metadata(index, [column("merchant")]) for index in range(3)]
    assert run(null_rate_shift, history) == ()


def test_ndv_ratio_shift_finds_a_cardinality_collapse() -> None:
    """A ring reusing one device across many accounts collapses the distinct ratio."""
    history = [
        metadata(0, [column("device_id", distinct=900)]),
        metadata(1, [column("device_id", distinct=900)]),
        metadata(2, [column("device_id", distinct=200)]),
    ]
    found = run(ndv_ratio_shift, history)
    assert len(found) == 1
    assert found[0].evidence[0].kind.value == "cardinality_shift"
    assert found[0].segment.predicates[0].op.value == "not_null"


# --------------------------------------------------------------------------------------
# row_volume_anomaly, file_layout_anomaly, schema_change
# --------------------------------------------------------------------------------------


def test_row_volume_anomaly_ignores_steady_growth() -> None:
    history = [
        metadata(index, [column("amount")], row_count=1000 * (index + 1)) for index in range(5)
    ]
    assert run(row_volume_anomaly, history) == ()


def test_row_volume_anomaly_finds_a_sudden_drop() -> None:
    counts = [1000, 1010, 1005, 1008, 40]
    history = [
        metadata(index, [column("amount", row_count=count)], row_count=count)
        for index, count in enumerate(counts)
    ]
    found = run(row_volume_anomaly, history)
    assert len(found) == 1
    assert found[0].evidence[0].kind.value == "rate_change"
    assert found[0].segment.is_universe


def test_file_layout_anomaly_finds_a_backfill() -> None:
    layouts = [(10, 1_000_000.0), (11, 1_000_000.0), (10, 1_000_000.0), (900, 12_000.0)]
    history = [
        metadata(index, [column("amount")], layout=layout) for index, layout in enumerate(layouts)
    ]
    found = run(file_layout_anomaly, history)
    assert len(found) == 1
    kinds = {evidence.kind.value for evidence in found[0].evidence}
    assert kinds == {"rate_change", "distribution_shift"}


def test_file_layout_anomaly_needs_layout_statistics() -> None:
    history = [metadata(index, [column("amount")]) for index in range(3)]
    assert run(file_layout_anomaly, history) == ()


def test_schema_change_counts_without_naming() -> None:
    """A column name is a disclosure on its own. Only the count is reported."""
    history = [
        metadata(0, [column("amount"), column("patient_hiv_status")]),
        metadata(1, [column("amount"), column("patient_hiv_status")]),
        metadata(2, [column("amount")]),
    ]
    found = run(schema_change, history)
    assert len(found) == 1
    evidence = found[0].evidence[0]
    assert evidence.statistic.reveal() == 1.0
    assert evidence.columns == ()
    assert found[0].segment.is_universe
    rendered = found[0].model_dump_json()
    assert "patient_hiv_status" not in rendered


def test_schema_change_notices_a_retype() -> None:
    history = [
        metadata(index, [column("amount", logical_type=LogicalType.FLOAT)]) for index in range(2)
    ] + [metadata(2, [column("amount", logical_type=LogicalType.STRING)])]
    found = run(schema_change, history)
    assert len(found) == 1
    assert found[0].evidence[0].statistic.reveal() == 1.0


def test_schema_change_is_silent_when_nothing_changed() -> None:
    history = [metadata(index, [column("amount")]) for index in range(3)]
    assert run(schema_change, history) == ()


# --------------------------------------------------------------------------------------
# The whole suite
# --------------------------------------------------------------------------------------


def test_running_everything_is_ordered_and_idempotent() -> None:
    history = [
        metadata(0, [column("amount", nulls=5, bounds=(1.0, 100.0))]),
        metadata(1, [column("amount", nulls=5, bounds=(1.0, 100.0))]),
        metadata(2, [column("amount", nulls=400, bounds=(1.0, 900.0))]),
    ]
    first = run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED)
    second = run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED)

    assert len(first) == 2, "bounds_drift and null_rate_shift should both fire"
    assert [candidate.candidate_id for candidate in first] == sorted(
        candidate.candidate_id for candidate in first
    )
    assert [candidate.candidate_id for candidate in first] == [
        candidate.candidate_id for candidate in second
    ]
    detectors = {candidate.lineage.detector for candidate in first}
    assert detectors == {"metadata.bounds_drift", "metadata.null_rate_shift"}


def test_candidate_ids_are_stable_across_reruns_of_the_same_snapshot() -> None:
    """``PatternStore`` law 1 depends on this: ingesting twice must yield one pattern."""
    history = [
        metadata(0, [column("amount", bounds=(1.0, 100.0))]),
        metadata(1, [column("amount", bounds=(1.0, 100.0))]),
        metadata(2, [column("amount", bounds=(1.0, 900.0))]),
    ]
    once = run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED)
    again = run_metadata_detectors(list(history), code_version=CODE_VERSION, seed=SEED)
    assert [candidate.candidate_id for candidate in once] == [
        candidate.candidate_id for candidate in again
    ]


def test_a_different_seed_is_a_different_measurement() -> None:
    """The seed is part of the probe key, so it is part of the candidate's identity."""
    history = [
        metadata(0, [column("amount", bounds=(1.0, 100.0))]),
        metadata(1, [column("amount", bounds=(1.0, 100.0))]),
        metadata(2, [column("amount", bounds=(1.0, 900.0))]),
    ]
    one = run_metadata_detectors(history, code_version=CODE_VERSION, seed=1)
    two = run_metadata_detectors(history, code_version=CODE_VERSION, seed=2)
    assert one[0].candidate_id != two[0].candidate_id
    assert one[0].lineage.probe_key != two[0].lineage.probe_key


@pytest.mark.parametrize(
    "detector",
    [
        bounds_drift,
        null_rate_shift,
        ndv_ratio_shift,
        row_volume_anomaly,
        file_layout_anomaly,
        schema_change,
    ],
)
def test_every_detector_is_silent_on_too_little_history(detector: object) -> None:
    history = [metadata(0, [column("amount", nulls=5, bounds=(1.0, 100.0))])]
    assert run(detector, history) == ()


def test_thresholds_are_configurable() -> None:
    """A change that the default config ignores can be surfaced by a louder one."""
    history = [
        metadata(0, [column("amount", bounds=(0.0, 100.0))]),
        metadata(1, [column("amount", bounds=(0.0, 100.0))]),
        metadata(2, [column("amount", bounds=(0.0, 110.0))]),
    ]
    assert bounds_drift(history, code_version=CODE_VERSION, seed=SEED) == ()

    loud = DetectorConfig(min_abs_log_ratio=0.01)
    found = bounds_drift(history, code_version=CODE_VERSION, seed=SEED, config=loud)
    assert len(found) == 1


def test_every_number_a_detector_emits_is_a_derived_statistic() -> None:
    """Evidence contracts enforce this on construction; the test states why it matters."""
    history = [
        metadata(0, [column("amount", nulls=5, bounds=(1.0, 100.0))]),
        metadata(1, [column("amount", nulls=5, bounds=(1.0, 100.0))]),
        metadata(2, [column("amount", nulls=400, bounds=(1.0, 900.0))]),
    ]
    for candidate in run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED):
        for evidence in candidate.evidence:
            numbers = [
                evidence.statistic,
                evidence.baseline,
                evidence.effect_size,
                evidence.p_value,
            ]
            for number in numbers:
                if number is not None:
                    assert number.sensitivity.value == "derived_statistic"
            for reference in evidence.columns:
                assert reference.sensitivity.value == "schema_name"


def test_probe_ids_do_not_embed_column_names() -> None:
    """A readable probe id would be a customer column name in an untainted field."""
    history = [
        metadata(0, [column("patient_hiv_status", bounds=(1.0, 100.0))]),
        metadata(1, [column("patient_hiv_status", bounds=(1.0, 100.0))]),
        metadata(2, [column("patient_hiv_status", bounds=(1.0, 900.0))]),
    ]
    found = run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED)
    assert found
    for candidate in found:
        assert "patient_hiv_status" not in str(candidate.lineage.probe_key)
        assert "patient_hiv_status" not in str(candidate.candidate_id)


def test_metadata_fields_used_are_named_in_evidence() -> None:
    """The brief: each detector says exactly which metadata fields it used."""
    history = [
        metadata(0, [column("amount", nulls=5, bounds=(1.0, 100.0))]),
        metadata(1, [column("amount", nulls=5, bounds=(1.0, 100.0))]),
        metadata(2, [column("amount", nulls=400, bounds=(1.0, 900.0))]),
    ]
    named: dict[str, Mapping[str, object]] = {}
    for candidate in run_metadata_detectors(history, code_version=CODE_VERSION, seed=SEED):
        for evidence in candidate.evidence:
            assert evidence.sketch_names, "every claim must name its inputs"
            named[candidate.lineage.detector] = {"fields": evidence.sketch_names}
    assert set(named) == {"metadata.bounds_drift", "metadata.null_rate_shift"}
