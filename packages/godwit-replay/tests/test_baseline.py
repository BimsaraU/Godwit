"""The expert baseline: reproducible, clean of the fixture's traps, and honestly described.

The fixture ships a ``bayes_auc`` ceiling -- the AUC of the *true* generating probabilities.
A baseline scoring above it has leaked the generating process into its features, which is a
failing result however good the number looks. That assertion is the point of this file.
"""

from __future__ import annotations

import datetime as _dt
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from godwit_contracts.cost import CostBudget
from godwit_contracts.errors import BudgetExceededError
from godwit_replay.baseline import (
    DROPPED_COLUMNS,
    GRIDS,
    baseline_path,
    build_baseline,
    design_matrix,
    load_baseline,
    save_baseline,
    verify_baseline,
)
from godwit_replay.errors import BaselineNotReproducibleError, DatasetNotAvailableError

CODE_VERSION = "godwit-replay/test"
SEED = 20240117
AS_OF = _dt.datetime(2024, 6, 1, tzinfo=_dt.UTC)

BUDGET = CostBudget(
    bytes_scanned=1 << 30,
    wall_seconds=3600.0,
    usd=Decimal("0"),
    llm_tokens=0,
    train_seconds=1_000_000.0,
)


@pytest.fixture(scope="module")
def record() -> Any:
    """The golden-classification baseline, built once for this module."""
    return build_baseline(
        "golden-classification",
        seed=SEED,
        as_of=AS_OF,
        code_version=CODE_VERSION,
        budget=BUDGET,
    )


def test_the_baseline_lands_below_the_fixtures_bayes_ceiling(record: Any, golden_dir: Path) -> None:
    """Above the ceiling means the generating process leaked, not that the model is good."""
    meta = json.loads((golden_dir / "classification" / "meta.json").read_text(encoding="utf-8"))
    ceiling = float(meta["bayes_auc"])
    assert record.auc <= ceiling, (
        f"AUC {record.auc:.4f} beats the Bayes ceiling {ceiling:.4f}: the features carry the "
        "generating process, and the baseline is worthless"
    )
    # And it is a real model, not a coin: well clear of chance.
    assert record.auc > 0.8
    assert 0.0 < record.metrics["pr_auc"] <= 1.0


def test_the_baseline_avoids_the_fixtures_three_traps(record: Any) -> None:
    """``entity_id`` is unique per row; encoding it would memorise the labels outright."""
    assert "entity_id" not in record.feature_names
    assert "entity_id" in record.dropped_columns
    assert "label" not in record.feature_names
    assert "label_observed" not in record.feature_names
    assert "label_time" not in record.feature_names
    assert "event_time" not in record.feature_names
    assert "merchant" in record.feature_names, (
        "merchant carries real signal and must be usable -- as a frequency encoding, which "
        "cannot memorise an outcome, and under its own name, so no is_merchant_ACME_CORP "
        "feature can arise"
    )
    assert "no target encoding" in record.encoding
    assert not any(name.startswith("is_merchant_") for name in record.feature_names)


def test_the_tuning_is_a_recorded_procedure_not_an_adjective(record: Any) -> None:
    assert len(record.grid) == len(GRIDS["default"])
    assert record.chosen in record.grid
    assert 0.0 <= record.validation_auc <= 1.0
    assert record.library == "lightgbm"
    assert record.seed == SEED
    assert record.built_as_of == AS_OF


def test_the_record_states_what_the_baseline_is_and_is_not(record: Any) -> None:
    note = record.comparison_note()
    assert "competent data scientist working for a week" in note
    assert "NOT parity with a mature in-house system" in note
    assert any("bayes_auc" in caveat for caveat in record.caveats)
    assert any("label_time" in caveat for caveat in record.caveats)


def test_the_record_carries_no_row_value(record: Any) -> None:
    """Feature names are plain strings, which is only safe on a public benchmark."""
    rendered = record.model_dump_json()
    assert "ent_00" not in rendered, "an entity id is a row value"
    assert "ACME_CORP" not in rendered, "a merchant name is a row value"


def test_rebuilding_reproduces_the_numbers_exactly(record: Any) -> None:
    """Tolerance zero. A baseline that drifts is not a baseline A13 can be graded against."""
    rebuilt = verify_baseline(record, code_version=CODE_VERSION, budget=BUDGET, tolerance=0.0)
    assert rebuilt.metrics == record.metrics
    assert rebuilt.identity() == record.identity()
    assert rebuilt.chosen == record.chosen


def test_a_drifted_record_is_refused(record: Any) -> None:
    tampered = record.model_copy(update={"metrics": {**record.metrics, "auc": record.auc + 0.05}})
    with pytest.raises(BaselineNotReproducibleError, match="drifted"):
        verify_baseline(tampered, code_version=CODE_VERSION, budget=BUDGET, tolerance=0.0)


def test_a_record_survives_a_round_trip_through_disk(record: Any, tmp_path: Path) -> None:
    path = save_baseline(record, directory=tmp_path)
    assert path == baseline_path(record.dataset, directory=tmp_path)
    reloaded = load_baseline(record.dataset, directory=tmp_path)
    assert reloaded.model_dump() == record.model_dump()
    assert reloaded.identity() == record.identity()


def test_loading_a_baseline_that_was_never_built_says_how_to_build_it(tmp_path: Path) -> None:
    with pytest.raises(BaselineNotReproducibleError, match="godwit-replay baseline"):
        load_baseline("ieee-cis", directory=tmp_path)


def test_a_baseline_refuses_rather_than_exceeding_its_budget() -> None:
    """Invariant 6. The proxy is deterministic, so this refusal is reproducible too."""
    starved = BUDGET.model_copy(update={"train_seconds": 0.0})
    with pytest.raises(BudgetExceededError, match="train_seconds"):
        build_baseline(
            "golden-classification",
            seed=SEED,
            as_of=AS_OF,
            code_version=CODE_VERSION,
            budget=starved,
        )


def test_an_unlabelled_dataset_has_nothing_to_baseline() -> None:
    with pytest.raises(DatasetNotAvailableError, match="no labels"):
        build_baseline("nyc-tlc", seed=SEED, as_of=AS_OF, code_version=CODE_VERSION, budget=BUDGET)


def test_an_absent_public_dataset_refuses_with_its_file_names() -> None:
    with pytest.raises(DatasetNotAvailableError, match=r"train_transaction\.csv"):
        build_baseline(
            "ieee-cis",
            seed=SEED,
            as_of=AS_OF,
            code_version=CODE_VERSION,
            budget=BUDGET,
            root=Path("this-path-does-not-exist"),
        )


def test_the_ieee_grid_is_separately_specified() -> None:
    """The dataset the brief names gets its own candidate set, not the default one."""
    assert "ieee-cis" in GRIDS
    assert GRIDS["ieee-cis"] != GRIDS["default"]
    assert max(int(item["num_leaves"]) for item in GRIDS["ieee-cis"]) > max(
        int(item["num_leaves"]) for item in GRIDS["default"]
    )


def test_the_design_matrix_drops_identifiers_and_names_what_it_kept(golden_dir: Path) -> None:
    import pyarrow.parquet as pq

    table = pq.read_table(golden_dir / "classification" / "train.parquet")
    matrix, shape = design_matrix(table)
    assert matrix.shape[0] == table.num_rows
    assert matrix.shape[1] == len(shape.feature_names)
    assert set(shape.feature_names).isdisjoint(DROPPED_COLUMNS)
    assert "entity_id" in shape.dropped


def test_the_design_matrix_drops_a_near_unique_categorical(golden_dir: Path) -> None:
    """Frequency-encoding a near-unique column is the memorisation hazard in a new hat."""
    import pyarrow as pa

    table = pa.table(
        {
            "device_id": [f"dev_{index}" for index in range(2000)],
            "amount": [float(index) for index in range(2000)],
        }
    )
    _, shape = design_matrix(table)
    assert "device_id" in shape.dropped
    assert shape.feature_names == ("amount",)
