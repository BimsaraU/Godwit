"""The expert baseline A13 is graded against, built here so A13 cannot grade itself.

**This module runs in the DATA PLANE.** It reads rows, trains a model and writes a record.

WHAT "TUNED EXPERT BASELINE" MEANS, CONCRETELY
----------------------------------------------
Not a set of magic numbers in a constant with the word "tuned" next to it. Every baseline
here is produced by a small, fixed, deterministic grid search over a validation slice carved
out of the *training* half, and the record states which candidates were tried and which one
won. That makes "tuned" a reproducible fact rather than an adjective, and it means the number
A13 must come within 0.02 AUC of was arrived at by a procedure anyone can rerun.

WHAT THE BASELINE DELIBERATELY DOES NOT DO
------------------------------------------
* **No target encoding, anywhere.** Target encoding a high-cardinality column is the
  fastest way to a high AUC and it bakes identifiers into the artifact -- invariant 3's whole
  subject. Categoricals get *frequency* encoding, which cannot memorise an outcome.
* **No identifier columns as features.** ``TransactionID``, ``entity_id``, ``customerID`` and
  ``nameOrig`` are dropped by name. The golden fixture ships a unique ``entity_id``
  specifically as a trap for this, and the baseline has to be clean for its number to mean
  anything.
* **No feature named after a value.** A frequency encoding produces one column per input
  column, named after the input column, so ``is_merchant_ACME_CORP`` cannot arise.
* **No look-ahead.** Labels are read at the split's cut-off, from the split record.

A baseline that broke any of those would beat the honest one and would be worthless, which
is the same reason the whole harness exists.

COST AND DETERMINISM
--------------------
Training time is charged against ``CostBudget.train_seconds`` using a *deterministic proxy* --
boosting rounds times rows divided by a million -- because measuring elapsed time would be a
wall-clock read in a prediction path, and universal rule 5 forbids that. The proxy is a
budget device, not a performance claim.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import lightgbm as lgb
import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv
import pyarrow.parquet as pq
from godwit_contracts.common import (
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    Probability,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.taint import schema_name
from godwit_contracts.training import SplitKind, SplitSpec
from numpy.typing import NDArray
from pydantic import Field

from godwit_replay.datasets import (
    DatasetSpec,
    dataset_root,
    prepare_table,
    require_available,
    resolve,
)
from godwit_replay.errors import BaselineNotReproducibleError, DatasetNotAvailableError
from godwit_replay.metrics import average_precision, roc_auc
from godwit_replay.split import HalfLabelled, MaskKind, SplitRecord, half_labelled

__all__ = [
    "DROPPED_COLUMNS",
    "GRIDS",
    "BaselineRecord",
    "DesignMatrix",
    "baseline_path",
    "build_baseline",
    "design_matrix",
    "load_baseline",
    "save_baseline",
    "verify_baseline",
]

DROPPED_COLUMNS: Final[frozenset[str]] = frozenset(
    {
        "TransactionID",
        "TransactionDT",
        "entity_id",
        "customerID",
        "nameOrig",
        "nameDest",
        "event_time",
        "label_time",
        "label",
        "label_observed",
        "isFraud",
        "isFlaggedFraud",
        "Churn",
        "step",
        "tenure",
    }
)
"""Never a feature. Identifiers, the label under any of its names, and the time columns.

``tenure`` is on this list for ``telco-churn`` only in the sense that it is also the column
event time was derived from; keeping both would be using the same fact twice. The list is
deliberately over-broad and shared across datasets: a column excluded from a dataset that
never had it costs nothing, and a forgotten identifier costs the whole comparison.
"""

_MAX_CATEGORY_CARDINALITY: Final[int] = 512
"""Above this a string column is dropped rather than encoded.

Frequency encoding a near-unique column produces a near-unique feature, which is the
memorisation hazard wearing a different hat. Five hundred and twelve is generous for a real
categorical and far below any identifier's cardinality.
"""

_VALIDATION_FRACTION: Final[float] = 0.2

_TRAIN_SECONDS_PER_ROW_ROUND: Final[float] = 1_000_000.0
"""Divisor for the deterministic training-cost proxy: rounds times rows over a million.

A proxy, not a measurement. Measuring elapsed time would be a wall-clock read in a
prediction path, which universal rule 5 forbids."""

_FIXTURE_LABEL_TIME_CAVEAT: Final[str] = (
    "this fixture ships a real label_time 45 days after event_time, so no delay was invented"
)

_FIXTURE_CEILING_CAVEAT: Final[str] = (
    "meta.json records bayes_auc: a score above it means the generating process leaked into "
    "the features, not that the model is good"
)

GRIDS: Final[Mapping[str, tuple[Mapping[str, Any], ...]]] = {
    "default": (
        {"num_leaves": 31, "learning_rate": 0.05, "min_data_in_leaf": 20, "num_boost_round": 300},
        {"num_leaves": 63, "learning_rate": 0.05, "min_data_in_leaf": 50, "num_boost_round": 400},
        {"num_leaves": 127, "learning_rate": 0.03, "min_data_in_leaf": 100, "num_boost_round": 600},
        {"num_leaves": 31, "learning_rate": 0.1, "min_data_in_leaf": 20, "num_boost_round": 200},
    ),
    "ieee-cis": (
        {"num_leaves": 255, "learning_rate": 0.05, "min_data_in_leaf": 100, "num_boost_round": 800},
        {"num_leaves": 127, "learning_rate": 0.05, "min_data_in_leaf": 50, "num_boost_round": 600},
        {"num_leaves": 63, "learning_rate": 0.1, "min_data_in_leaf": 20, "num_boost_round": 400},
        {
            "num_leaves": 255,
            "learning_rate": 0.02,
            "min_data_in_leaf": 200,
            "num_boost_round": 1200,
        },
    ),
}
"""The candidate sets. Four each, fixed, small enough to rerun and wide enough to matter.

The IEEE-CIS grid is deeper because 590,000 rows and 393 columns reward capacity, which is
the same thing a competent practitioner would conclude in their first afternoon. That is the
claim being made: parity with a good data scientist working for a week. Not parity with a
mature in-house system carrying years of consortium data, device intelligence and
investigator feedback. Those are different claims and only the first one is ours.
"""

_FIXED_PARAMS: Final[Mapping[str, Any]] = {
    "objective": "binary",
    "metric": "auc",
    "verbosity": -1,
    "deterministic": True,
    "force_row_wise": True,
    "num_threads": 1,
    "feature_pre_filter": False,
}
"""Determinism settings, not tuning knobs. ``num_threads=1`` costs wall time and buys
bit-identical output across machines, which is the trade the whole package is about."""


class BaselineRecord(GodwitModel):
    """A recorded expert baseline. Committable: counts, names of public columns, numbers.

    ``feature_names`` holds plain strings rather than ``Tainted``, and that is only safe
    because :func:`build_baseline` refuses to run on a dataset that is not marked
    ``is_public``. A feature name is a leak path; a feature name from a published benchmark
    is not. The refusal is what makes the plain type honest.
    """

    dataset: str
    title: str
    library: str
    library_version: str
    code_version: str
    seed: int
    built_as_of: Instant = Field(description="Injected, never a clock read.")

    mask: str
    split: SplitSpec
    split_record: SplitRecord

    grid: tuple[Mapping[str, Any], ...]
    chosen: Mapping[str, Any]
    validation_auc: float

    feature_names: tuple[str, ...]
    dropped_columns: tuple[str, ...]
    encoding: str = "numeric passthrough plus frequency encoding; no target encoding"

    train_rows: NonNegInt
    eval_rows: NonNegInt
    positive_rate: Probability

    metrics: Mapping[str, float]
    cost_spent: CostSpend
    data_digest: ContentHash
    caveats: tuple[str, ...] = ()

    @property
    def auc(self) -> float:
        """The number A13 must land within 0.02 of."""
        return self.metrics["auc"]

    def comparison_note(self) -> str:
        """The sentence that must travel with any comparison against this baseline."""
        return (
            f"expert baseline: a hand-built LightGBM on {self.dataset}, tuned by a fixed "
            f"{len(self.grid)}-candidate grid on a held-out validation slice, seed {self.seed}, "
            f"AUC {self.auc:.4f} on {self.eval_rows} held-out rows. This is parity with a "
            "competent data scientist working for a week. It is NOT parity with a mature "
            "in-house system carrying years of consortium data, device intelligence and "
            "investigator feedback."
        )

    def identity(self) -> ContentHash:
        """What must be unchanged for a rebuild to count as reproducing this record."""
        return content_hash(
            canonical_json(
                {
                    "dataset": self.dataset,
                    "seed": self.seed,
                    "mask": self.mask,
                    "chosen": dict(sorted(self.chosen.items())),
                    "features": list(self.feature_names),
                    "data_digest": str(self.data_digest),
                }
            ),
            prefix="bln",
        )


class DesignMatrix(GodwitModel):
    """The shape of a design matrix, for the record. The values stay in the data plane."""

    feature_names: tuple[str, ...]
    rows: NonNegInt
    dropped: tuple[str, ...]


def _frequency_encode(column: pa.ChunkedArray) -> NDArray[np.float64] | None:
    """Encode a string column by how often each value occurs. Cannot memorise an outcome.

    Returns None when the column's cardinality is above the ceiling, which is the signal to
    drop it rather than to encode it.
    """
    values = column.to_pylist()
    counts: dict[object, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    if len(counts) > _MAX_CATEGORY_CARDINALITY:
        return None
    total = float(len(values)) or 1.0
    return np.asarray([counts[value] / total for value in values], dtype=np.float64)


def design_matrix(table: pa.Table) -> tuple[NDArray[np.float64], DesignMatrix]:
    """Build features by hand: numerics as they are, categoricals by frequency, nothing else.

    Column order is the table's own order, filtered, so the matrix is a deterministic function
    of the table and not of dictionary iteration.
    """
    columns: list[NDArray[np.float64]] = []
    names: list[str] = []
    dropped: list[str] = []
    for field in table.schema:
        if field.name in DROPPED_COLUMNS:
            dropped.append(field.name)
            continue
        column = table.column(field.name)
        if pa.types.is_boolean(field.type):
            columns.append(
                np.asarray(
                    pc.cast(pc.fill_null(column, False), pa.float64()).to_numpy(
                        zero_copy_only=False
                    ),
                    dtype=np.float64,
                )
            )
            names.append(field.name)
        elif pa.types.is_integer(field.type) or pa.types.is_floating(field.type):
            columns.append(
                np.asarray(
                    pc.cast(column, pa.float64()).to_numpy(zero_copy_only=False), dtype=np.float64
                )
            )
            names.append(field.name)
        elif pa.types.is_string(field.type) or pa.types.is_large_string(field.type):
            encoded = _frequency_encode(column)
            if encoded is None:
                dropped.append(field.name)
                continue
            columns.append(encoded)
            names.append(field.name)
        else:
            dropped.append(field.name)
    if not columns:
        raise DatasetNotAvailableError("no usable feature columns after dropping identifiers")
    matrix = np.column_stack(columns)
    return matrix, DesignMatrix(
        feature_names=tuple(names), rows=matrix.shape[0], dropped=tuple(dropped)
    )


def _rows_digest(table: pa.Table) -> ContentHash:
    """A hash over the logical shape and column names, not over Parquet bytes.

    Parquet bytes are not stable across pyarrow versions; the golden fixtures are pinned the
    same way for the same reason.
    """
    return content_hash(
        canonical_json(
            {
                "rows": table.num_rows,
                "columns": [(field.name, str(field.type)) for field in table.schema],
            }
        ),
        prefix="dat",
    )


def _train_once(
    *,
    features: NDArray[np.float64],
    labels: NDArray[np.int_],
    valid_features: NDArray[np.float64],
    valid_labels: NDArray[np.int_],
    params: Mapping[str, Any],
    seed: int,
    feature_names: Sequence[str],
) -> tuple[Any, float]:
    """Fit one candidate and return (booster, validation AUC)."""
    rounds = int(params["num_boost_round"])
    settings = {
        **_FIXED_PARAMS,
        **{key: value for key, value in params.items() if key != "num_boost_round"},
        "seed": seed,
        "bagging_seed": seed + 1,
        "feature_fraction_seed": seed + 2,
        "data_random_seed": seed + 3,
    }
    train_set = lgb.Dataset(
        features, label=labels, feature_name=list(feature_names), free_raw_data=False
    )
    booster = lgb.train(settings, train_set, num_boost_round=rounds)
    predicted = np.asarray(booster.predict(valid_features), dtype=np.float64)
    return booster, roc_auc(valid_labels, predicted)


def _golden_classification_frames(
    spec: DatasetSpec, root: Path | None
) -> tuple[pa.Table, pa.Table]:
    base = require_available(spec, root=root)
    train = pq.read_table(base / "train.parquet")
    holdout = pq.read_table(base / "holdout.parquet")
    return train, holdout


@dataclass(frozen=True, slots=True)
class _Inputs:
    """Everything one baseline build needs, once the dataset-specific part is done.

    Two dataset shapes reach here: a fixture that already ships its own split, and a public
    dataset whose half-labelled split the harness manufactures. Both produce this, so the
    training and recording code below has exactly one path through it.
    """

    train_matrix: NDArray[np.float64]
    train_labels: NDArray[np.int_]
    eval_matrix: NDArray[np.float64]
    eval_labels: NDArray[np.int_]
    eval_times: pa.ChunkedArray | pa.Array
    shape: DesignMatrix
    split_record: SplitRecord
    data_digest: ContentHash
    caveats: tuple[str, ...]


def _fixture_inputs(spec: DatasetSpec, *, seed: int, root: Path | None) -> _Inputs:
    """Inputs for ``golden-classification``, which ships its own train/holdout split."""
    train_table, eval_table = _golden_classification_frames(spec, root)
    observed = np.asarray(
        train_table.column("label_observed").to_numpy(zero_copy_only=False), dtype=np.float64
    )
    visible = ~np.isnan(observed)
    eval_labels = np.asarray(
        eval_table.column("label").to_numpy(zero_copy_only=False), dtype=np.int64
    )
    combined = pa.concat_tables([train_table, eval_table], promote_options="default")
    matrix, shape = design_matrix(combined)
    eval_times = eval_table.column("event_time")
    digest = _rows_digest(combined)
    return _Inputs(
        train_matrix=matrix[: train_table.num_rows][visible],
        train_labels=observed[visible].astype(np.int64),
        eval_matrix=matrix[train_table.num_rows :],
        eval_labels=eval_labels,
        eval_times=eval_times,
        shape=shape,
        split_record=SplitRecord(
            dataset=spec.name,
            mask=MaskKind.TEMPORAL,
            spec=_fixture_split_spec(train_table, seed),
            rows=combined.num_rows,
            labelled_rows=int(visible.sum()) + int(eval_labels.size),
            hidden_rows=int((~visible).sum()),
            eval_rows=int(eval_labels.size),
            cut_off=pc.min(eval_times).as_py(),
            hidden_fraction=float((~visible).sum() / max(1, train_table.num_rows)),
            seed=seed,
            digest=digest,
        ),
        data_digest=digest,
        caveats=(_FIXTURE_LABEL_TIME_CAVEAT, _FIXTURE_CEILING_CAVEAT),
    )


def _public_inputs(spec: DatasetSpec, *, seed: int, mask: MaskKind, root: Path | None) -> _Inputs:
    """Inputs for a public dataset, whose half-labelled condition the harness manufactures."""
    if spec.label_column is None:
        raise DatasetNotAvailableError(f"{spec.name} has no label column")
    base = require_available(spec, root=root)
    prepared = pa.concat_tables(
        [prepare_table(_read(base / name), spec) for name in spec.raw_files],
        promote_options="default",
    )
    split = half_labelled(prepared, spec, mask=mask, seed=seed)
    matrix, shape = design_matrix(prepared)
    labels_all = np.asarray(
        pc.fill_null(pc.cast(prepared.column(spec.label_column), pa.int64()), -1).to_numpy(
            zero_copy_only=False
        ),
        dtype=np.int64,
    )
    train_rows = split.train_rows[split.label_visible]
    return _Inputs(
        train_matrix=matrix[train_rows],
        train_labels=labels_all[train_rows],
        eval_matrix=matrix[split.eval_rows],
        eval_labels=labels_all[split.eval_rows],
        eval_times=prepared.column("event_time").take(pa.array(split.eval_rows)),
        shape=shape,
        split_record=split.record,
        data_digest=_rows_digest(prepared),
        caveats=spec.caveats,
    )


def _search(inputs: _Inputs, *, dataset: str, seed: int) -> tuple[Mapping[str, Any], float]:
    """The fixed grid search. Returns the winning candidate and its validation AUC.

    The validation slice is drawn from a seeded generator over the *training* rows only, so
    the held-out half stays untouched by tuning. Ties go to the earlier candidate in the grid,
    which makes the search's output a function of the grid's order rather than of dictionary
    iteration order.
    """
    generator = np.random.default_rng(seed)
    order = generator.permutation(inputs.train_matrix.shape[0])
    cut = round((1.0 - _VALIDATION_FRACTION) * order.size)
    fit_rows, validation_rows = order[:cut], order[cut:]
    if validation_rows.size == 0 or fit_rows.size == 0:
        raise DatasetNotAvailableError("not enough labelled rows to carve a validation slice")

    best_score = float("-inf")
    best_candidate: Mapping[str, Any] | None = None
    for candidate in _grid(dataset):
        _, validation_auc = _train_once(
            features=inputs.train_matrix[fit_rows],
            labels=inputs.train_labels[fit_rows],
            valid_features=inputs.train_matrix[validation_rows],
            valid_labels=inputs.train_labels[validation_rows],
            params=candidate,
            seed=seed,
            feature_names=inputs.shape.feature_names,
        )
        score = validation_auc if np.isfinite(validation_auc) else float("-inf")
        if score > best_score:
            best_score, best_candidate = score, candidate
    if best_candidate is None:
        raise DatasetNotAvailableError("every grid candidate failed to produce a usable AUC")
    return best_candidate, best_score


def build_baseline(
    dataset: str,
    *,
    seed: int,
    as_of: Instant,
    code_version: str,
    budget: CostBudget,
    root: Path | None = None,
    mask: MaskKind = MaskKind.TEMPORAL,
) -> BaselineRecord:
    """Build and record the expert baseline for one dataset.

    Refuses on a dataset that is not marked public, because the record it writes contains
    feature names and a feature name is a leak path. Refuses rather than exceeds ``budget``:
    a refusal raises ``BudgetExceededError`` from the contract, which the caller records.
    """
    spec = resolve(dataset)
    if not spec.is_public:
        raise DatasetNotAvailableError(
            f"{dataset} is not marked public; a baseline record stores feature names and a "
            "feature name is a leak path. Record it inside the perimeter instead."
        )
    if not spec.is_labelled:
        raise DatasetNotAvailableError(f"{dataset} has no labels; there is nothing to baseline")

    inputs = (
        _fixture_inputs(spec, seed=seed, root=root)
        if spec.name == "golden-classification"
        else _public_inputs(spec, seed=seed, mask=mask, root=root)
    )

    grid = _grid(spec.name)
    rounds_estimate = max(int(candidate["num_boost_round"]) for candidate in grid)
    proxy = CostSpend(
        train_seconds=float(rounds_estimate * max(1, inputs.train_matrix.shape[0]) * len(grid))
        / _TRAIN_SECONDS_PER_ROW_ROUND
    )
    budget.spend(proxy)

    chosen, validation_auc = _search(inputs, dataset=spec.name, seed=seed)
    final_booster, _ = _train_once(
        features=inputs.train_matrix,
        labels=inputs.train_labels,
        valid_features=inputs.train_matrix[:1],
        valid_labels=inputs.train_labels[:1],
        params=chosen,
        seed=seed,
        feature_names=inputs.shape.feature_names,
    )
    predicted = np.asarray(final_booster.predict(inputs.eval_matrix), dtype=np.float64)

    return BaselineRecord(
        dataset=spec.name,
        title=spec.title,
        library="lightgbm",
        library_version=str(lgb.__version__),
        code_version=code_version,
        seed=seed,
        built_as_of=as_of,
        mask=inputs.split_record.mask.value,
        split=inputs.split_record.spec,
        split_record=inputs.split_record,
        grid=grid,
        chosen=chosen,
        validation_auc=validation_auc,
        feature_names=inputs.shape.feature_names,
        dropped_columns=inputs.shape.dropped,
        train_rows=int(inputs.train_matrix.shape[0]),
        eval_rows=int(inputs.eval_labels.size),
        positive_rate=float(inputs.eval_labels.mean()),
        metrics={
            "auc": roc_auc(inputs.eval_labels, predicted),
            "pr_auc": average_precision(inputs.eval_labels, predicted),
        },
        cost_spent=proxy,
        data_digest=inputs.data_digest,
        caveats=(
            *inputs.caveats,
            f"event-time span of the evaluation half: {_span(inputs.eval_times)}",
        ),
    )


def _read(path: Path) -> pa.Table:
    return pq.read_table(path) if path.suffix == ".parquet" else pacsv.read_csv(path)


def _span(stamps: pa.ChunkedArray | pa.Array) -> str:
    low, high = pc.min(stamps).as_py(), pc.max(stamps).as_py()
    return f"{low.date().isoformat()}..{high.date().isoformat()}"


def _fixture_split_spec(train_table: pa.Table, seed: int) -> SplitSpec:
    stamps = train_table.column("event_time")
    end = pc.max(stamps).as_py()
    return SplitSpec(
        kind=SplitKind.TIME_ORDERED,
        time_column=schema_name("event_time"),
        train_end=end,
        valid_end=end + _dt.timedelta(microseconds=1),
        seed=seed,
    )


def _grid(dataset: str) -> tuple[Mapping[str, Any], ...]:
    return GRIDS.get(dataset, GRIDS["default"])


def baseline_path(dataset: str, *, directory: Path | None = None) -> Path:
    """Where a recorded baseline lives. Committed, so the comparison survives the session."""
    base = directory if directory is not None else Path(__file__).resolve().parent / "baselines"
    return base / f"{dataset}.json"


def save_baseline(record: BaselineRecord, *, directory: Path | None = None) -> Path:
    """Write a baseline record as canonical JSON."""
    path = baseline_path(record.dataset, directory=directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def load_baseline(dataset: str, *, directory: Path | None = None) -> BaselineRecord:
    """Read a recorded baseline, or say it has not been built."""
    path = baseline_path(dataset, directory=directory)
    if not path.is_file():
        raise BaselineNotReproducibleError(
            f"no recorded baseline for {dataset} at {path}; run "
            f"`godwit-replay baseline --dataset {dataset}` with the raw data in place"
        )
    return BaselineRecord.model_validate_json(path.read_text(encoding="utf-8"))


def verify_baseline(
    record: BaselineRecord,
    *,
    code_version: str,
    budget: CostBudget,
    root: Path | None = None,
    tolerance: float = 0.0,
) -> BaselineRecord:
    """Rebuild a recorded baseline and refuse if the numbers moved.

    ``tolerance`` defaults to exactly zero. A baseline that is not bit-reproducible is not a
    baseline: the comparison A13 is graded against would drift under it. Raise the tolerance
    only with a written reason, and say so in the record's caveats.
    """
    rebuilt = build_baseline(
        record.dataset,
        seed=record.seed,
        as_of=record.built_as_of,
        code_version=code_version,
        budget=budget,
        root=root,
        mask=MaskKind(record.mask),
    )
    drift = {
        name: abs(rebuilt.metrics[name] - value)
        for name, value in record.metrics.items()
        if name in rebuilt.metrics
    }
    worst = max(drift.values(), default=0.0)
    if worst > tolerance or rebuilt.identity() != record.identity():
        raise BaselineNotReproducibleError(
            f"{record.dataset}: rebuild drifted by {worst:.6f} (tolerance {tolerance}); "
            f"recorded identity {record.identity()}, rebuilt {rebuilt.identity()}"
        )
    return rebuilt


def half_labelled_for(
    dataset: str, *, seed: int, mask: MaskKind, root: Path | None = None
) -> HalfLabelled:
    """The half-labelled split for one dataset, for callers that want it without training."""
    spec = resolve(dataset)
    base = dataset_root(spec, root=root)
    prepared = pa.concat_tables(
        [prepare_table(_read(base / name), spec) for name in spec.raw_files],
        promote_options="default",
    )
    return half_labelled(prepared, spec, mask=mask, seed=seed)
