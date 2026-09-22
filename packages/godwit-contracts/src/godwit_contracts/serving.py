"""Serving (L8): predictions and deployments.

Inference runs in the data plane, because scoring a row means reading a row. What
crosses to the control plane is the prediction record, and a prediction is about an
entity, so ``entity_id`` is tainted and attributions are tainted with it.

``Deployment.model`` is a ``DeployableModel``, never a ``ModelArtifact``. Passing an
unaudited artifact here is a type error, caught by mypy before it is caught by a bank.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    ArtifactId,
    DeploymentId,
    GodwitModel,
    Instant,
    Probability,
    Version,
)
from godwit_contracts.taint import Sensitivity, Tainted
from godwit_contracts.training import DeployableModel

__all__ = [
    "Deployment",
    "DeploymentMode",
    "DeploymentStatus",
    "FeatureAttribution",
    "Prediction",
]


class FeatureAttribution(GodwitModel):
    """One feature's contribution to one prediction.

    ``feature_name`` is a leak path: SHAP output carries feature names, and a feature
    name can encode a row value. ``feature_id`` is ours and is safe.
    """

    feature_id: str
    feature_name: Tainted[str]
    contribution: Tainted[float]

    @model_validator(mode="after")
    def _attribution_is_tainted_correctly(self) -> Self:
        if self.feature_name.sensitivity is Sensitivity.DERIVED_STATISTIC:
            raise ValueError("FeatureAttribution.feature_name is at least SCHEMA_NAME")
        return self


class Prediction(GodwitModel):
    """One scored entity.

    ``score`` is the model's raw output; ``calibrated_probability`` is what a human or a
    threshold should use. They are separate fields because a raw LightGBM score is not a
    probability and treating it as one is how alert queues end up mis-sized.
    """

    prediction_id: str
    artifact_id: ArtifactId
    model_version: Version
    feature_set_version: Version

    entity_id: Tainted[str]
    score: Tainted[float]
    calibrated_probability: Tainted[float] | None = None

    computed_at: Instant
    features_as_of: Instant = Field(
        description="The point-in-time instant the features were computed at. Without "
        "it a prediction cannot be reproduced or audited."
    )
    attributions: tuple[FeatureAttribution, ...] = ()

    @model_validator(mode="after")
    def _scores_are_statistics(self) -> Self:
        if self.score.sensitivity is not Sensitivity.DERIVED_STATISTIC:
            raise ValueError("Prediction.score is a model output: DERIVED_STATISTIC")
        if (
            self.calibrated_probability is not None
            and self.calibrated_probability.sensitivity is not Sensitivity.DERIVED_STATISTIC
        ):
            raise ValueError("Prediction.calibrated_probability is a DERIVED_STATISTIC")
        if self.entity_id.sensitivity is Sensitivity.DERIVED_STATISTIC:
            raise ValueError("Prediction.entity_id is a row value, not a statistic")
        return self


class DeploymentMode(StrEnum):
    """How much real traffic a deployment gets.

    ``SHADOW`` scores live traffic and records the result without acting on it. It is
    the default way a new model earns its way in.
    """

    SHADOW = "shadow"
    CANARY = "canary"
    LIVE = "live"


class DeploymentStatus(StrEnum):
    """Where a deployment is."""

    PENDING = "pending"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ROLLED_BACK = "rolled_back"


class Deployment(GodwitModel):
    """A model in an environment, at a traffic share.

    Note the type of ``model``. Invariant 3 is enforced here by construction: there is
    no field on this type that will accept an unaudited ``ModelArtifact``.
    """

    deployment_id: DeploymentId
    model: DeployableModel
    environment: str
    mode: DeploymentMode
    traffic_fraction: Probability = Field(
        description="Share of traffic acted on. Must be 0.0 in SHADOW mode: shadow "
        "means scored and recorded, never acted on."
    )
    status: DeploymentStatus
    created_at: Instant
    superseded_by: DeploymentId | None = None
    rollback_of: DeploymentId | None = None
    guardrail_ids: tuple[str, ...] = Field(
        default=(),
        description="Guardrails in force for this deployment, by id and version.",
    )

    @model_validator(mode="after")
    def _shadow_takes_no_traffic(self) -> Self:
        if self.mode is DeploymentMode.SHADOW and self.traffic_fraction != 0.0:
            raise ValueError("a shadow deployment must have traffic_fraction 0.0")
        if self.mode is DeploymentMode.LIVE and self.traffic_fraction == 0.0:
            raise ValueError("a live deployment with zero traffic is a shadow deployment")
        return self
