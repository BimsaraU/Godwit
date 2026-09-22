"""The feature factory (L6), and the one rule that prevents target leakage.

Every ``FeatureSpec`` must state its point-in-time rule. A spec that cannot state one
is invalid and validation rejects it. This is not defensive programming; it is where
leakage comes from. A feature computed "as of now" over a table that has been updated
since the event is a feature that knows the future, and a model trained on it will look
excellent in evaluation and fail the moment it is deployed.

The second thing this module carries is the loop that makes Godwit one product rather
than two: ``derived_from_pattern``. A confirmed pattern from L5 becomes a feature here,
which the prediction engine trains on, whose residuals go back to discovery.
"""

from __future__ import annotations

import datetime as _dt
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from godwit_contracts.common import GodwitModel, Instant, PatternId, SourceId, Version
from godwit_contracts.segment import Segment
from godwit_contracts.source import LogicalType
from godwit_contracts.taint import Sensitivity, Tainted

__all__ = [
    "FeatureKind",
    "FeatureSet",
    "FeatureSpec",
    "FillPolicy",
    "PointInTimeRule",
]


class FeatureKind(StrEnum):
    """What shape of computation produces this feature."""

    RAW_COLUMN = "raw_column"
    AGGREGATE = "aggregate"
    TIME_WINDOW = "time_window"
    GRAPH = "graph"
    ENTITY_HISTORY = "entity_history"
    PATTERN_INDICATOR = "pattern_indicator"
    """A discovered pattern, turned into a feature. The product's central idea."""
    RESIDUAL = "residual"


class FillPolicy(StrEnum):
    """What a feature evaluates to when its inputs are missing.

    There is no "mean imputation" option on purpose: filling with a statistic computed
    over the training set is itself a leak across the split boundary.
    """

    NULL = "null"
    ZERO = "zero"
    SENTINEL = "sentinel"
    FAIL = "fail"


class PointInTimeRule(GodwitModel):
    """When a feature is allowed to look, relative to the event it describes.

    Worked example, card fraud. The transaction happens at T. Chargebacks arrive up to
    60 days later. A feature that counts this card's prior transactions must:

    * read ``timestamp_column`` to find each row's time,
    * include rows in ``[T - max_lookback, T - embargo)``,
    * and the trainer must not use any label whose ``label_time`` is after T, which is
      what ``label_lag_allowance`` records.

    ``embargo`` exists for the case where a row's own timestamp is not the moment the
    data became visible -- a late-arriving feed, a nightly batch. Set it to the feed's
    worst-case delay, not its average.
    """

    timestamp_column: Tainted[str]
    max_lookback: _dt.timedelta = Field(
        description="How far back the feature may read. Must be positive: a feature "
        "with no lookback bound reads the whole table and is not reproducible."
    )
    embargo: _dt.timedelta = Field(
        default=_dt.timedelta(0),
        description="Gap between the event and the newest row the feature may read. "
        "Covers ingestion delay. Non-negative.",
    )
    label_lag_allowance: _dt.timedelta = Field(
        default=_dt.timedelta(0),
        description="How long after an event its label may arrive. Used by the trainer "
        "to decide which labels existed at prediction time.",
    )
    inclusive_end: bool = Field(
        default=False,
        description="Whether the row at exactly ``event_time - embargo`` is included. "
        "Default False: the safe direction is to exclude the boundary row.",
    )

    @model_validator(mode="after")
    def _rule_is_coherent(self) -> Self:
        if self.timestamp_column.sensitivity is not Sensitivity.SCHEMA_NAME:
            raise ValueError("PointInTimeRule.timestamp_column must be tainted SCHEMA_NAME")
        if self.max_lookback <= _dt.timedelta(0):
            raise ValueError("max_lookback must be positive")
        if self.embargo < _dt.timedelta(0):
            raise ValueError("embargo cannot be negative")
        if self.label_lag_allowance < _dt.timedelta(0):
            raise ValueError("label_lag_allowance cannot be negative")
        if self.embargo >= self.max_lookback:
            raise ValueError(
                "embargo is at least as long as max_lookback: the feature would have "
                "no rows to read"
            )
        return self


class FeatureSpec(GodwitModel):
    """A deterministic recipe for one feature value.

    ``point_in_time`` is mandatory. There is no ``None``, no default and no flag that
    turns the check off.
    """

    feature_id: str
    name: Tainted[str] = Field(
        description="LEAK PATH. Feature names reach SHAP output, importance tables and "
        "model cards. ``is_merchant_ACME_CORP`` discloses a merchant."
    )
    kind: FeatureKind
    spec_version: Version

    source_id: SourceId
    entity_key: Tainted[str]
    inputs: tuple[Tainted[str], ...] = Field(
        default=(), description="Columns this feature reads. Tainted SCHEMA_NAME."
    )
    expression: str = Field(
        description="The computation, in the data plane's SQL dialect (DuckDB). Must "
        "not embed a literal drawn from rows: that belongs in ``segment``."
    )
    dtype: LogicalType
    fill_policy: FillPolicy = FillPolicy.NULL

    point_in_time: PointInTimeRule
    segment: Segment | None = Field(
        default=None,
        description="Restricts the rows this feature reads. Carries row values.",
    )
    derived_from_pattern: PatternId | None = Field(
        default=None,
        description="Set when this feature is a discovered pattern turned into an input. "
        "This is the discovery-feeds-prediction loop.",
    )

    deterministic: Literal[True] = Field(
        default=True,
        description="A feature that is not deterministic is not a feature. The field "
        "exists so that the claim is explicit in every serialised spec.",
    )
    seed: int | None = Field(
        default=None,
        description="Required if the expression samples or hashes with a random salt.",
    )

    @model_validator(mode="after")
    def _names_are_correctly_tainted(self) -> Self:
        if self.entity_key.sensitivity is not Sensitivity.SCHEMA_NAME:
            raise ValueError("FeatureSpec.entity_key must be tainted SCHEMA_NAME")
        for index, column in enumerate(self.inputs):
            if column.sensitivity is not Sensitivity.SCHEMA_NAME:
                raise ValueError(f"FeatureSpec.inputs[{index}] must be tainted SCHEMA_NAME")
        derived_from_values = self.segment is not None and bool(self.segment.predicates)
        if derived_from_values and self.name.sensitivity is not Sensitivity.DATA_VALUE:
            raise ValueError(
                "this feature is defined by a segment, so its name encodes row values "
                "(is_merchant_ACME_CORP): name must be tainted DATA_VALUE"
            )
        if self.name.sensitivity is Sensitivity.DERIVED_STATISTIC:
            raise ValueError("FeatureSpec.name is at least SCHEMA_NAME")
        return self


class FeatureSet(GodwitModel):
    """A versioned bundle of features, computed as of one instant.

    ``as_of`` is what makes a feature set reproducible: recomputing it with the same
    specs, the same snapshot and the same instant must give the same values.
    """

    feature_set_id: str
    version: Version
    entity_type: str
    specs: tuple[FeatureSpec, ...] = Field(min_length=1)
    source_id: SourceId
    as_of: Instant
    created_at: Instant

    @model_validator(mode="after")
    def _feature_ids_are_unique(self) -> Self:
        ids = [spec.feature_id for spec in self.specs]
        if len(set(ids)) != len(ids):
            raise ValueError("feature_id values inside a FeatureSet must be unique")
        return self
