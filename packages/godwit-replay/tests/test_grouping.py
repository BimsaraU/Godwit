"""The top-N is one row per phenomenon, and each row says what it is."""

from __future__ import annotations

import datetime as _dt

from godwit_contracts import (
    Acquisition,
    ColumnRef,
    LogicalType,
    SnapshotId,
    SnapshotRef,
    SourceId,
    SourceKind,
    SourceRef,
    data_value,
    derived_statistic,
    schema_name,
)
from godwit_replay.verdict import _label, _triage, group_candidates
from godwit_source.detectors import run_metadata_detectors
from godwit_source.metadata import ColumnMetadata, SnapshotMetadata

SRC = SourceId("src_trips")
EPOCH = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
SOURCE = SourceRef(
    source_id=SRC,
    kind=SourceKind.ICEBERG,
    catalog="unit",
    namespace=schema_name("ns", source_id=SRC),
    table=schema_name("trips", source_id=SRC),
)


def _column(name: str, rows: int, nulls: int, bounds: tuple[float, float]) -> ColumnMetadata:
    def stat(value: int) -> object:
        return derived_statistic(value, source_id=SRC, table="trips", column=name)

    def bound(value: float) -> object:
        return data_value(
            value,
            acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS,
            source_id=SRC,
            table="trips",
            column=name,
        )

    return ColumnMetadata(
        ref=ColumnRef(
            source_id=SRC,
            table=schema_name("trips", source_id=SRC),
            column=schema_name(name, source_id=SRC, table="trips"),
        ),
        logical_type=LogicalType.FLOAT,
        native_type="double",
        nullable=True,
        row_count=stat(rows),
        null_count=stat(nulls),
        value_count=stat(rows - nulls),
        lower_bound=bound(bounds[0]),
        upper_bound=bound(bounds[1]),
    )


def _history() -> list[SnapshotMetadata]:
    """Append-only: 1,000 rows a period. Three columns go null together in the last
    period; fare's maximum explodes in the same period."""
    history = []
    nulls = 0
    for index in range(6):
        rows = 1_000 * (index + 1)
        nulls += 300 if index == 5 else 50
        fare_high = 90_000.0 if index == 5 else 100.0 + index
        columns = [_column(name, rows, nulls, (0.0, 10.0)) for name in ("tip", "surcharge", "fee")]
        columns.append(_column("fare", rows, 0, (1.0, fare_high)))
        committed = EPOCH + _dt.timedelta(days=31 * index)
        history.append(
            SnapshotMetadata(
                source=SOURCE,
                snapshot=SnapshotRef(
                    source_id=SRC,
                    snapshot_id=SnapshotId(f"s{index}"),
                    sequence_number=index,
                    committed_at=committed,
                ),
                columns=tuple(columns),
                row_count=derived_statistic(rows, source_id=SRC, table="trips"),
                observed_at=committed,
            )
        )
    return history


def test_lockstep_columns_become_one_labelled_row() -> None:
    found = run_metadata_detectors(_history(), code_version="t", seed=1)
    ranked = tuple(sorted(found, key=lambda c: (-c.score, str(c.candidate_id))))
    groups = group_candidates(ranked)

    nulls = [g for g in groups if g[0].lineage.detector.endswith("null_rate_shift")]
    assert len(nulls) == 1, "three columns missing on the same rows are one finding"
    assert len(nulls[0]) == 3
    label = _label(nulls[0])
    assert "5.0% to 30.0%" in label
    assert any(tag.startswith("co-missing block: 3 columns") for tag in _triage(nulls[0], 1))

    bounds = [g for g in groups if g[0].lineage.detector.endswith("bounds_drift")]
    assert len(bounds) == 1
    assert "`fare`" in _label(bounds[0]) and "jumped" in _label(bounds[0])
    assert any(tag.startswith("extreme value") for tag in _triage(bounds[0], 1))


def test_a_segment_is_shown_once_however_often_it_fires() -> None:
    history = _history()
    first = run_metadata_detectors(history, code_version="t", seed=1)
    again = run_metadata_detectors(history, code_version="t", seed=2)
    groups = group_candidates((*first, *again))
    keys = [str(c.segment.key) for g in groups for c in g]
    assert len(keys) == len(set(keys))
    assert _triage(groups[0], 4)[-1].startswith("persistent: re-surfaced in 4 periods")
