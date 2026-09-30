"""The dataset registry, and the honesty rules it has to keep.

The tests that matter are the ones about fabricated assumptions. A harness whose loaders
quietly invent a label delay produces time-to-detection numbers that measure nothing, and the
only defence is a registry that cannot hold an unmarked invention.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from godwit_replay.datasets import (
    REGISTRY,
    LoadedDataset,
    Period,
    build_label_set,
    dataset_root,
    list_datasets,
    materialise,
    missing_files,
    open_catalog,
    prepare_table,
    resolve,
)
from godwit_replay.errors import DatasetNotAvailableError

PUBLIC_BENCHMARKS = ("ieee-cis", "paysim", "telco-churn", "nyc-tlc")


def test_the_four_public_datasets_from_the_brief_are_all_registered() -> None:
    for name in PUBLIC_BENCHMARKS:
        assert name in REGISTRY
    assert len(list_datasets()) == len(REGISTRY)


def test_every_fabricated_assumption_is_marked_and_explained() -> None:
    """The load-bearing honesty test.

    A dataset with an invented calendar anchor or an invented label delay must say so, in a
    sentence fit to print next to a number. A fabricated delay that looks real is worse than no
    delay at all, and an unmarked one is exactly that.
    """
    for spec in list_datasets():
        if spec.anchor_is_fabricated:
            assert spec.epoch_anchor is not None
            assert any("anchor" in caveat for caveat in spec.caveats)
        if spec.label_delay is not None and spec.label_delay.is_fabricated:
            assert len(spec.label_delay.note) > 40, "a marked invention needs a real reason"
            assert any("fabricated" in caveat for caveat in spec.caveats)
        if spec.is_labelled and not spec.has_honest_label_time:
            assert spec.label_delay is not None
            assert spec.label_delay.is_fabricated


def test_only_the_classification_fixture_claims_an_honest_label_time() -> None:
    honest = [
        spec.name for spec in list_datasets() if spec.is_labelled and spec.has_honest_label_time
    ]
    assert honest == ["golden-classification"]


def test_a_dataset_with_no_labels_says_so_rather_than_implying_negatives() -> None:
    tlc = resolve("nyc-tlc")
    assert not tlc.is_labelled
    assert tlc.label_delay is None
    assert any("no labels" in caveat for caveat in tlc.caveats)


def test_a_labelled_spec_never_carries_both_a_real_time_and_an_invented_delay() -> None:
    for spec in list_datasets():
        if spec.label_time_column is not None:
            assert spec.label_delay is None, (
                "inventing a delay for data that states one is not a fallback, it is a lie"
            )


def test_resolving_an_unknown_dataset_lists_the_known_ones() -> None:
    with pytest.raises(DatasetNotAvailableError, match="ieee-cis"):
        resolve("not-a-dataset")


def test_an_absent_dataset_names_its_files_and_refuses_to_substitute() -> None:
    """Nothing is downloaded and nothing is faked. The message says where to get it."""
    spec = resolve("ieee-cis")
    absent = missing_files(spec, root=Path("this-path-does-not-exist"))
    assert [path.name for path in absent] == ["train_transaction.csv"]
    with pytest.raises(DatasetNotAvailableError) as raised:
        materialise(spec, workspace=Path("unused"), root=Path("this-path-does-not-exist"))
    message = str(raised.value)
    assert "train_transaction.csv" in message
    assert "kaggle" in message.lower()
    assert "Nothing is substituted" in message


def test_the_in_repo_fixtures_resolve_against_tests_golden(golden_dir: Path) -> None:
    assert dataset_root(resolve("golden-drift")) == golden_dir / "drift_table"
    assert dataset_root(resolve("golden-classification")) == golden_dir / "classification"
    assert missing_files(resolve("golden-drift")) == ()


def test_materialise_writes_one_commit_per_period(golden_loaded: LoadedDataset) -> None:
    assert golden_loaded.snapshot_count == 3
    assert golden_loaded.period_keys == ("file_0", "file_1", "file_2")
    assert list(golden_loaded.clock_instants) == sorted(golden_loaded.clock_instants)
    assert all(count == 6000 for count in golden_loaded.row_counts)
    assert golden_loaded.spec.period is Period.SNAPSHOT_FILE


def test_the_clock_instants_come_from_the_data_not_from_the_loader(
    golden_loaded: LoadedDataset,
) -> None:
    """An Iceberg commit time is the loader's wall clock and differs on every machine.

    The replay clock must not be that. Each instant here is the maximum ``event_time`` in its
    commit, which is a property of the data and reproduces anywhere.
    """
    catalog = open_catalog(golden_loaded)
    table = catalog.load_table(f"godwit_replay.{golden_loaded.source.table.reveal()}")
    commit_times = {
        _dt.datetime.fromtimestamp(snapshot.timestamp_ms / 1000.0, tz=_dt.UTC)
        for snapshot in table.metadata.snapshots
    }
    assert commit_times.isdisjoint(set(golden_loaded.clock_instants))
    assert all(
        moment < _dt.datetime(2025, 1, 1, tzinfo=_dt.UTC) for moment in golden_loaded.clock_instants
    )


def test_the_event_table_does_not_contain_the_label_column(
    tmp_path: Path, golden_dir: Path
) -> None:
    """The structural guarantee: a handler cannot read a label by reading the table.

    Not a convention, not a filter applied afterwards -- the column is absent from the Iceberg
    schema, so no budget and no query can reach it.
    """
    loaded = materialise(resolve("golden-classification"), workspace=tmp_path / "cls")
    catalog = open_catalog(loaded)
    table = catalog.load_table(f"godwit_replay.{loaded.source.table.reveal()}")
    names = set(table.schema().column_names)
    assert "label" not in names
    assert "label_observed" not in names
    assert "label_time" not in names
    assert "event_time" in names
    assert loaded.labels is not None


def test_labels_carry_the_two_timestamps_and_the_delay_that_produced_them(
    golden_dir: Path,
) -> None:
    spec = resolve("golden-classification")
    holdout = prepare_table(pq.read_table(golden_dir / "classification" / "holdout.parquet"), spec)
    labels = build_label_set(
        holdout,
        spec,
        complete_from=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
        complete_to=_dt.datetime(2024, 12, 31, tzinfo=_dt.UTC),
    )
    assert labels.labels
    for label in labels.labels[:20]:
        assert label.label_time > label.event_time
        assert (label.label_time - label.event_time) == _dt.timedelta(days=45)
    assert "real field in the data" in labels.coverage.note


def test_coverage_is_not_exhaustive_when_labels_are_missing(golden_dir: Path) -> None:
    """Half the training rows are unlabelled, so absence of a label must mean nothing at all."""
    spec = resolve("golden-classification")
    train = prepare_table(pq.read_table(golden_dir / "classification" / "train.parquet"), spec)
    renamed = train.rename_columns(
        ["label" if name == "label_observed" else name for name in train.schema.names]
    )
    labels = build_label_set(
        renamed,
        spec,
        complete_from=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
        complete_to=_dt.datetime(2024, 12, 31, tzinfo=_dt.UTC),
    )
    assert not labels.coverage.is_exhaustive
    assert not labels.coverage_at(instant=_dt.datetime(2024, 6, 1, tzinfo=_dt.UTC))


def test_reusing_a_workspace_with_a_different_history_is_refused(tmp_path: Path) -> None:
    """--workspace caching is useful; silently doubling a replay's history is not."""
    workspace = tmp_path / "shared"
    first = materialise(resolve("golden-drift"), workspace=workspace)
    assert first.snapshot_count == 3
    again = materialise(resolve("golden-drift"), workspace=workspace)
    assert again.snapshot_count == 3
    with pytest.raises(DatasetNotAvailableError, match="already holds 3 commits"):
        materialise(resolve("golden-drift"), workspace=workspace, max_periods=2)


def test_a_dataset_whose_time_column_is_an_offset_needs_a_declared_anchor() -> None:
    spec = resolve("paysim").model_copy(update={"epoch_anchor": None})
    import pyarrow as pa

    table = pa.table({"step": [1, 2], "nameOrig": ["a", "b"], "isFraud": [0, 1]})
    with pytest.raises(DatasetNotAvailableError, match="declares no epoch_anchor"):
        prepare_table(table, spec)
