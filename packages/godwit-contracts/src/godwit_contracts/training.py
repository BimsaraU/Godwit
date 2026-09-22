"""Training, memorisation audit and evaluation (L7).

Invariant 3: model artifacts are audited for memorisation before they cross. A model
can memorise its training rows. Target encoding on a high-cardinality column bakes
identifiers straight into the artifact; a deep enough tree on a near-unique column does
the same thing with extra steps. An unaudited artifact is a data leak wearing a hat.

That invariant is carried in the type system here. ``Deployment`` does not accept a
``ModelArtifact``. It accepts a ``DeployableModel``, which can only be produced by
:func:`certify_deployable`, which refuses anything without a passing audit. A failing
audit is not merely rejected at runtime -- ``audit_passed: Literal[True]`` means a
failed deployable is not a representable value.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from enum import StrEnum
from typing import Final, Literal, Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    ArtifactId,
    AuditId,
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    Probability,
    RunId,
    SourceId,
    Version,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.errors import MemorisationAuditFailedError
from godwit_contracts.features import FeatureSet
from godwit_contracts.segment import Segment
from godwit_contracts.taint import Sensitivity, Tainted

__all__ = [
    "REQUIRED_MEMORISATION_CHECKS",
    "ArtifactFormat",
    "DeployableModel",
    "EvaluationReport",
    "MemorisationAudit",
    "MemorisationCheck",
    "MemorisationCheckKind",
    "ModelArtifact",
    "ModelCard",
    "Objective",
    "SliceMetric",
    "SplitKind",
    "SplitSpec",
    "TrainingRun",
    "TrainingStatus",
    "TrainingTask",
    "certify_deployable",
]


class Objective(StrEnum):
    """What the trainer optimises."""

    BINARY_CLASSIFICATION = "binary_classification"
    MULTICLASS = "multiclass"
    REGRESSION = "regression"
    RANKING = "ranking"


class SplitKind(StrEnum):
    """How train, validation and test are separated.

    ``TIME_ORDERED`` is the default for anything with an event time. Random splitting a
    time series is the second most common way to produce an impressive, useless model.
    """

    TIME_ORDERED = "time_ordered"
    GROUP_KFOLD = "group_kfold"
    RANDOM = "random"


class SplitSpec(GodwitModel):
    """The split, stated precisely enough to reproduce."""

    kind: SplitKind
    time_column: Tainted[str] | None = None
    train_end: Instant | None = None
    valid_end: Instant | None = None
    test_end: Instant | None = None
    group_key: Tainted[str] | None = None
    n_folds: int | None = Field(default=None, ge=2)
    embargo: _dt.timedelta = Field(
        default=_dt.timedelta(0),
        description="Gap between train and validation, to stop adjacent rows leaking "
        "across the boundary.",
    )
    seed: int

    @model_validator(mode="after")
    def _split_is_complete(self) -> Self:
        if self.kind is SplitKind.TIME_ORDERED:
            missing = [
                name
                for name, value in (
                    ("time_column", self.time_column),
                    ("train_end", self.train_end),
                    ("valid_end", self.valid_end),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"a time-ordered split needs {', '.join(missing)}")
            if (
                self.valid_end is not None
                and self.train_end is not None
                and self.valid_end <= self.train_end
            ):
                raise ValueError("valid_end must follow train_end")
        if self.kind is SplitKind.GROUP_KFOLD and (self.group_key is None or self.n_folds is None):
            raise ValueError("a group k-fold split needs group_key and n_folds")
        if self.embargo < _dt.timedelta(0):
            raise ValueError("embargo cannot be negative")
        return self


class TrainingTask(GodwitModel):
    """A request to train. Deterministic, budgeted, and explicit about "as of"."""

    task_id: str
    source_id: SourceId
    feature_set: FeatureSet
    objective: Objective
    primary_metric: str = Field(
        description="The metric the model search optimises, e.g. 'auc'. One metric. "
        "A search with two objectives has none."
    )
    split: SplitSpec
    labels_as_of: Instant = Field(
        description="The instant labels are read at. Explicit, never 'now'. Everything "
        "a LabelSet will not show you at this instant did not exist yet."
    )
    semi_supervised: bool = Field(
        description="True when the dataset is partly labelled and unlabelled rows are "
        "'unknown', not 'negative'. Check LabelSet.coverage_at before setting False."
    )
    budget: CostBudget
    seed: int


class TrainingStatus(StrEnum):
    """Where a run got to. ``REFUSED_BUDGET`` is a normal outcome (invariant 6)."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUSED_BUDGET = "refused_budget"
    CANCELLED = "cancelled"


class TrainingRun(GodwitModel):
    """One execution of a task. Reproducible from task, code version and seed."""

    run_id: RunId
    task_id: str
    status: TrainingStatus
    started_at: Instant
    finished_at: Instant | None = None
    cost_spent: CostSpend = Field(default_factory=CostSpend.zero)
    code_version: str
    seed: int
    artifact_id: ArtifactId | None = None
    failure_reason: str | None = Field(
        default=None,
        description="Our own message. NEVER a driver exception: those contain rows.",
    )

    @model_validator(mode="after")
    def _success_produces_an_artifact(self) -> Self:
        if self.status is TrainingStatus.SUCCEEDED and self.artifact_id is None:
            raise ValueError("a succeeded run must name its artifact")
        return self


class MemorisationCheckKind(StrEnum):
    """The specific ways a model can carry its training rows out of the perimeter."""

    EXACT_VALUE_ECHO = "exact_value_echo"
    """Literal training values found inside the serialised artifact."""

    TARGET_ENCODING_CARDINALITY = "target_encoding_cardinality"
    """Target encoding over a column with near-row-level cardinality. The encoding table
    IS a lookup from identifier to outcome."""

    RARE_CATEGORY_RETENTION = "rare_category_retention"
    """Categories held by fewer entities than the small-cell threshold surviving into
    the model's vocabulary."""

    FEATURE_NAME_LEAK = "feature_name_leak"
    """Feature names that embed row values, e.g. ``is_merchant_ACME_CORP``."""

    CANARY_EXTRACTION = "canary_extraction"
    """Planted canary rows recoverable from the trained model."""

    MODEL_CARD_STRINGS = "model_card_strings"
    """Row values that reached the model card, importances or example section."""

    SPLIT_OVERFIT_GAP = "split_overfit_gap"
    """Train-test gap wide enough to indicate memorisation rather than learning."""


REQUIRED_MEMORISATION_CHECKS: Final[frozenset[MemorisationCheckKind]] = frozenset(
    {
        MemorisationCheckKind.EXACT_VALUE_ECHO,
        MemorisationCheckKind.TARGET_ENCODING_CARDINALITY,
        MemorisationCheckKind.RARE_CATEGORY_RETENTION,
        MemorisationCheckKind.FEATURE_NAME_LEAK,
        MemorisationCheckKind.MODEL_CARD_STRINGS,
    }
)
"""Checks every audit must contain. Omitting one is a validation error, not an option.

``CANARY_EXTRACTION`` and ``SPLIT_OVERFIT_GAP`` are strongly recommended but not
required, because they need a training-time hook that not every trainer can provide.
"""


class MemorisationCheck(GodwitModel):
    """One check, its threshold, what was observed, and whether that passed."""

    kind: MemorisationCheckKind
    threshold: float
    observed: float
    passed: bool
    detail: str = Field(
        default="",
        description="Our description of the finding. MUST NOT quote the offending "
        "value: that is the thing we are trying to stop leaving.",
    )


class MemorisationAudit(GodwitModel):
    """The verdict on one artifact.

    ``passed`` is not a field an optimistic caller can set: it is validated to equal
    the conjunction of the checks, and the required checks must all be present.
    """

    audit_id: AuditId
    artifact_id: ArtifactId
    artifact_digest: ContentHash
    checks: tuple[MemorisationCheck, ...] = Field(min_length=1)
    passed: bool
    performed_at: Instant
    auditor_version: Version
    small_cell_threshold: NonNegInt

    @model_validator(mode="after")
    def _verdict_matches_checks(self) -> Self:
        present = {check.kind for check in self.checks}
        missing = REQUIRED_MEMORISATION_CHECKS - present
        if missing:
            raise ValueError(
                "audit is incomplete, missing: " + ", ".join(sorted(kind.value for kind in missing))
            )
        expected = all(check.passed for check in self.checks)
        if self.passed != expected:
            raise ValueError(
                f"passed={self.passed} contradicts the checks (all passed: {expected})"
            )
        return self

    def digest(self) -> ContentHash:
        """Stable hash of this audit's verdict, used in the deployment certificate."""
        return content_hash(
            canonical_json(
                {
                    "audit_id": str(self.audit_id),
                    "artifact_id": str(self.artifact_id),
                    "artifact_digest": str(self.artifact_digest),
                    "auditor_version": int(self.auditor_version),
                    "passed": self.passed,
                    "checks": sorted(f"{check.kind.value}:{check.passed}" for check in self.checks),
                }
            ),
            prefix="aud",
        )


class ArtifactFormat(StrEnum):
    """How a model is serialised. ONNX is the portable one; the others are native."""

    ONNX = "onnx"
    LIGHTGBM_TXT = "lightgbm_txt"
    SKLEARN_JOBLIB = "sklearn_joblib"


class ModelCard(GodwitModel):
    """The human-readable description that travels with a model.

    Every free-text field here is ``Tainted``. Model cards are exactly where a helpful
    engineer pastes an example row.
    """

    intended_use: Tainted[str]
    limitations: Tainted[str]
    training_window: str = Field(description="Dates only. No values.")
    feature_names: tuple[Tainted[str], ...] = Field(
        default=(),
        description="LEAK PATH. Feature names can encode row values.",
    )
    top_importances: Mapping[str, float] = Field(
        default_factory=dict,
        description="Keyed by feature id, never by feature name, because the name is "
        "the part that can leak.",
    )


class ModelArtifact(GodwitModel):
    """A trained model plus its provenance and, perhaps, its audit.

    ``audit`` is optional here because an artifact exists before it has been audited.
    It is not optional for deployment: see :func:`certify_deployable`.
    """

    artifact_id: ArtifactId
    version: Version
    format: ArtifactFormat
    digest: ContentHash
    size_bytes: NonNegInt
    storage_uri: str = Field(description="Object-storage location. Ours, not a data path.")

    feature_set_id: str
    training_run_id: RunId
    created_at: Instant
    audit: MemorisationAudit | None = None
    card: ModelCard

    @model_validator(mode="after")
    def _audit_matches_artifact(self) -> Self:
        if self.audit is None:
            return self
        if self.audit.artifact_id != self.artifact_id:
            raise ValueError("the attached audit is for a different artifact")
        if self.audit.artifact_digest != self.digest:
            raise ValueError(
                "the attached audit was performed on different bytes; re-audit before "
                "this artifact can be deployed"
            )
        return self


class DeployableModel(GodwitModel):
    """An artifact that has passed its memorisation audit. The only thing deployable.

    ``audit_passed`` is ``Literal[True]``: a deployable carrying a failed audit cannot
    be constructed, cannot be parsed from JSON, and is not a representable value. The
    ``certificate`` binds this object to specific artifact bytes and a specific audit,
    so a deployable cannot be re-pointed at a different artifact after the fact.

    Produced only by :func:`certify_deployable`.
    """

    artifact_id: ArtifactId
    artifact_version: Version
    artifact_digest: ContentHash
    audit_id: AuditId
    audit_digest: ContentHash
    audit_passed: Literal[True]
    certificate: ContentHash

    @model_validator(mode="after")
    def _certificate_binds_these_bytes(self) -> Self:
        expected = _deployment_certificate(
            artifact_id=self.artifact_id,
            artifact_version=self.artifact_version,
            artifact_digest=self.artifact_digest,
            audit_id=self.audit_id,
            audit_digest=self.audit_digest,
        )
        if self.certificate != expected:
            raise ValueError(
                "deployment certificate does not match these artifact and audit fields"
            )
        return self


def _deployment_certificate(
    *,
    artifact_id: ArtifactId,
    artifact_version: Version,
    artifact_digest: ContentHash,
    audit_id: AuditId,
    audit_digest: ContentHash,
) -> ContentHash:
    return content_hash(
        canonical_json(
            {
                "artifact_id": str(artifact_id),
                "artifact_version": int(artifact_version),
                "artifact_digest": str(artifact_digest),
                "audit_id": str(audit_id),
                "audit_digest": str(audit_digest),
            }
        ),
        prefix="dep",
    )


def certify_deployable(artifact: ModelArtifact) -> DeployableModel:
    """Turn an audited artifact into something that can be deployed.

    Raises :class:`MemorisationAuditFailedError` when there is no audit, when the audit
    did not pass, or when it was performed on different bytes. There is no override
    parameter, no ``force`` and no ``skip_audit``. Invariant 3 has no exceptions.
    """
    audit = artifact.audit
    if audit is None:
        raise MemorisationAuditFailedError(
            f"artifact {artifact.artifact_id} has no memorisation audit; "
            "an unaudited artifact is a data leak wearing a hat"
        )
    if not audit.passed:
        failures = ", ".join(check.kind.value for check in audit.checks if not check.passed)
        raise MemorisationAuditFailedError(
            f"artifact {artifact.artifact_id} failed its audit: {failures}"
        )
    if audit.artifact_digest != artifact.digest:
        raise MemorisationAuditFailedError(
            f"artifact {artifact.artifact_id} was audited at a different digest"
        )
    return DeployableModel(
        artifact_id=artifact.artifact_id,
        artifact_version=artifact.version,
        artifact_digest=artifact.digest,
        audit_id=audit.audit_id,
        audit_digest=audit.digest(),
        audit_passed=True,
        certificate=_deployment_certificate(
            artifact_id=artifact.artifact_id,
            artifact_version=artifact.version,
            artifact_digest=artifact.digest,
            audit_id=audit.audit_id,
            audit_digest=audit.digest(),
        ),
    )


class SliceMetric(GodwitModel):
    """A metric restricted to a segment. Carries row values in the segment predicates."""

    segment: Segment
    metric: str
    value: Tainted[float]
    population: NonNegInt | None = None

    @model_validator(mode="after")
    def _value_is_a_statistic(self) -> Self:
        if self.value.sensitivity is not Sensitivity.DERIVED_STATISTIC:
            raise ValueError("SliceMetric.value is an aggregate: DERIVED_STATISTIC")
        return self


class EvaluationReport(GodwitModel):
    """How the model did, and how that compares to the baseline it must match.

    The prediction objective is to land within 0.02 AUC of a tuned expert baseline.
    ``baseline_metrics`` is therefore not optional decoration: without it the primary
    number means nothing.
    """

    report_id: str
    artifact_id: ArtifactId
    primary_metric: str
    metrics: Mapping[str, float]
    baseline_metrics: Mapping[str, float] = Field(
        default_factory=dict,
        description="The comparison baseline. State what it was in ``baseline_note``.",
    )
    baseline_note: str = Field(
        default="",
        description="What the baseline is. Be honest: 'a competent hand-built model' "
        "is not 'a mature in-house system with years of consortium data'.",
    )
    calibration_error: float | None = Field(
        default=None, description="Expected calibration error, if measured."
    )
    slices: tuple[SliceMetric, ...] = ()
    evaluated_as_of: Instant
    population: NonNegInt | None = None
    positive_rate: Probability | None = None

    @model_validator(mode="after")
    def _primary_metric_is_reported(self) -> Self:
        if self.primary_metric not in self.metrics:
            raise ValueError(f"primary_metric {self.primary_metric!r} is not present in metrics")
        return self
