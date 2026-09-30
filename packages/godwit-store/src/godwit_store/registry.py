"""Model registry metadata, and the storage-layer refusal to record an unaudited model.

The artifact bytes live in object storage inside the perimeter. What lives here is the
metadata, the lineage back to a ``TrainingRun`` and a ``FeatureSet``, the memorisation
audit, and the promotion history. The registry is ours rather than a third party's
precisely because artifact egress needs our own gate -- a model file is a data-bearing
object (invariant 3) and handing it to a vendor's registry is an egress nobody recorded.

THE CONSTRAINT IS IN THE DATABASE, NOT IN THIS MODULE
-----------------------------------------------------
``model_artifacts`` carries ``deployable``, with ``CHECK (NOT deployable OR
audit_passed)`` and ``UNIQUE (artifact_id, deployable)``. ``deployments`` carries
``artifact_deployable``, with ``CHECK (artifact_deployable)`` and a composite foreign
key onto that unique pair.

An artifact whose memorisation audit failed therefore has **no row a deployment could
reference**. Delete every line of Python in this file and the database still refuses
it. That is what "enforce at the storage layer" has to mean for it to be worth saying
to a bank, and it is why the functions below are thin: they exist to give the refusal a
readable error message, not to be the refusal.

The type system says the same thing from the other side: ``Deployment.model`` is a
``DeployableModel``, which only ``certify_deployable`` produces, and which has no
``force`` parameter. Three independent mechanisms -- a type, a check constraint and a
foreign key -- and each one is sufficient on its own.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence
from typing import Any

from godwit_contracts import (
    ArtifactId,
    AuditId,
    ContentHash,
    DeployableModel,
    Deployment,
    EvaluationReport,
    FeatureSet,
    GodwitModel,
    Instant,
    MemorisationAudit,
    MemorisationAuditFailedError,
    MemorisationCheck,
    ModelArtifact,
    ModelCard,
    NonNegInt,
    RunId,
    Sensitivity,
    TrainingRun,
    TrainingTask,
    Version,
    certify_deployable,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from godwit_store.errors import StoreIntegrityError
from godwit_store.schema import (
    DeploymentRow,
    EvaluationReportRow,
    FeatureSetRow,
    MemorisationAuditRow,
    ModelArtifactRow,
    TrainingRunRow,
)

__all__ = [
    "DeploymentRecord",
    "ModelRegistryStore",
]


class DeploymentRecord(GodwitModel):
    """One row of promotion history, as read back.

    A rollback is a new record pointing at an older artifact, never a mutation of the
    old one -- so this sequence, read in order, *is* the promotion history.
    """

    deployment_id: str
    artifact_id: ArtifactId
    artifact_digest: ContentHash
    environment: str
    mode: str
    traffic_fraction: float
    status: str
    superseded_by: str | None = None
    rollback_of: str | None = None
    created_at: Instant


class ModelRegistryStore:
    """Registry metadata over a session. Control plane; holds no artifact bytes."""

    __slots__ = ("_session",)

    def __init__(self, session: Session) -> None:
        self._session = session

    # -- lineage -------------------------------------------------------------------

    def record_feature_set(self, feature_set: FeatureSet, *, at: Instant) -> str:
        """Store a feature set's metadata and the patterns it was built from.

        ``derived_from_patterns`` is lifted out of the payload into its own column so
        that "which discovered patterns is this model built on" is a query rather than
        a JSON scan. That link is the product's central claim and it should be cheap to
        follow in both directions.
        """
        derived = sorted({str(spec.derived_from_pattern) for spec in feature_set.specs} - {"None"})
        existing = self._session.get(
            FeatureSetRow, (feature_set.feature_set_id, int(feature_set.version))
        )
        if existing is not None:
            return feature_set.feature_set_id
        self._session.add(
            FeatureSetRow(
                feature_set_id=feature_set.feature_set_id,
                version=int(feature_set.version),
                entity_type=feature_set.entity_type,
                source_id=str(feature_set.source_id),
                spec_count=len(feature_set.specs),
                derived_from_patterns=derived,
                as_of=feature_set.as_of,
                created_at=at,
                payload_value=feature_set.model_dump(mode="json"),
                payload_sensitivity=Sensitivity.DATA_VALUE.value,
                payload_acquisition="derived_feature_name",
                payload_population=None,
            )
        )
        self._session.flush()
        return feature_set.feature_set_id

    def record_training_run(self, run: TrainingRun, task: TrainingTask) -> RunId:
        """Store a training run, including a refusal.

        ``REFUSED_BUDGET`` is a normal outcome (invariant 6) and is recorded as one.
        ``failure_reason`` is stored verbatim from the contract object, which documents
        it as our own message and never a driver exception -- those contain rows.
        """
        if self._session.get(TrainingRunRow, str(run.run_id)) is not None:
            return run.run_id
        self._session.add(
            TrainingRunRow(
                run_id=str(run.run_id),
                task_id=run.task_id,
                source_id=str(task.source_id),
                feature_set_id=task.feature_set.feature_set_id,
                feature_set_version=int(task.feature_set.version),
                status=run.status.value,
                objective=task.objective.value,
                primary_metric=task.primary_metric,
                labels_as_of=task.labels_as_of,
                semi_supervised=task.semi_supervised,
                code_version=run.code_version,
                seed=run.seed,
                artifact_id=None if run.artifact_id is None else str(run.artifact_id),
                failure_reason=run.failure_reason,
                started_at=run.started_at,
                finished_at=run.finished_at,
                cost_spent=run.cost_spent.model_dump(mode="json"),
            )
        )
        self._session.flush()
        return run.run_id

    # -- artifacts ------------------------------------------------------------------

    def register(self, artifact: ModelArtifact, *, at: Instant) -> ArtifactId:
        """Store artifact metadata. Idempotent on digest (registry law 1).

        Re-registering the same bytes under a different id is refused rather than
        accepted: an artifact is identified by what it contains, and two ids for one
        digest would let an audit attached to one of them appear to cover the other.
        """
        existing = self._session.scalars(
            select(ModelArtifactRow).where(ModelArtifactRow.digest == str(artifact.digest))
        ).first()
        if existing is not None:
            if existing.artifact_id != str(artifact.artifact_id):
                raise StoreIntegrityError(
                    f"digest {artifact.digest} is already registered as "
                    f"{existing.artifact_id}; an artifact is identified by its bytes"
                )
            return artifact.artifact_id

        self._session.add(
            ModelArtifactRow(
                artifact_id=str(artifact.artifact_id),
                version=int(artifact.version),
                digest=str(artifact.digest),
                format=artifact.format.value,
                size_bytes=artifact.size_bytes,
                storage_uri=artifact.storage_uri,
                feature_set_id=artifact.feature_set_id,
                training_run_id=str(artifact.training_run_id),
                audit_id=None,
                audit_passed=False,
                deployable=False,
                certificate=None,
                created_at=at,
                payload_value=artifact.card.model_dump(mode="json"),
                payload_sensitivity=Sensitivity.DATA_VALUE.value,
                payload_acquisition="derived_feature_name",
                payload_population=None,
            )
        )
        self._session.flush()
        return artifact.artifact_id

    def attach_audit(self, audit: MemorisationAudit) -> bool:
        """Record an audit against a digest and update deployability. Returns ``passed``.

        An audit is bound to bytes. If the artifact's digest has changed since the audit
        was performed, the audit is stored -- it is a fact about something -- but the
        artifact stays undeployable, because what was audited is not what would ship.
        """
        row = self._session.get(ModelArtifactRow, str(audit.artifact_id))
        if row is None:
            raise StoreIntegrityError(f"no artifact {audit.artifact_id} to attach an audit to")
        if self._session.get(MemorisationAuditRow, str(audit.audit_id)) is None:
            self._session.add(
                MemorisationAuditRow(
                    audit_id=str(audit.audit_id),
                    artifact_id=str(audit.artifact_id),
                    artifact_digest=str(audit.artifact_digest),
                    audit_digest=str(audit.digest()),
                    passed=audit.passed,
                    auditor_version=int(audit.auditor_version),
                    small_cell_threshold=audit.small_cell_threshold,
                    checks=[check.model_dump(mode="json") for check in audit.checks],
                    performed_at=audit.performed_at,
                )
            )
        binds_these_bytes = str(audit.artifact_digest) == row.digest
        row.audit_id = str(audit.audit_id)
        row.audit_passed = audit.passed and binds_these_bytes
        row.deployable = row.audit_passed
        self._session.flush()
        return row.audit_passed

    def certify(self, artifact_id: ArtifactId) -> DeployableModel:
        """Produce a ``DeployableModel``, or raise. The only route to a deployment.

        Rebuilds the contract objects from storage and hands them to
        ``godwit_contracts.certify_deployable``, which is the single function in the
        system that can mint a deployable and which has no override parameter. This
        method adds a database lookup and nothing else -- deliberately, because a second
        implementation of the rule is a second place for it to be wrong.
        """
        row = self._session.get(ModelArtifactRow, str(artifact_id))
        if row is None:
            raise MemorisationAuditFailedError(f"no artifact {artifact_id} to certify")
        self._refuse_stale_audit(row)
        artifact = self._rebuild_artifact(row)
        deployable = certify_deployable(artifact)
        row.certificate = str(deployable.certificate)
        self._session.flush()
        return deployable

    def _refuse_stale_audit(self, row: ModelArtifactRow) -> None:
        """Refuse before rebuilding, so the caller gets our message and not Pydantic's.

        ``ModelArtifact`` validates that an attached audit was performed on the same
        bytes, so rebuilding a mismatched pair raises a ``ValidationError`` -- correct,
        but it arrives as a schema complaint rather than as the refusal it is. Invariant
        3 deserves a sentence that says what went wrong.
        """
        if row.audit_id is None:
            return
        audit_row = self._session.get(MemorisationAuditRow, row.audit_id)
        if audit_row is not None and audit_row.artifact_digest != row.digest:
            raise MemorisationAuditFailedError(
                f"artifact {row.artifact_id} was audited at digest "
                f"{audit_row.artifact_digest}, but its bytes are now {row.digest}; "
                "re-audit before this artifact can be deployed"
            )

    def _rebuild_artifact(self, row: ModelArtifactRow) -> ModelArtifact:
        audit: MemorisationAudit | None = None
        if row.audit_id is not None:
            audit_row = self._session.get(MemorisationAuditRow, row.audit_id)
            if audit_row is not None:
                audit = MemorisationAudit(
                    audit_id=AuditId(audit_row.audit_id),
                    artifact_id=ArtifactId(audit_row.artifact_id),
                    artifact_digest=ContentHash(audit_row.artifact_digest),
                    checks=tuple(
                        MemorisationCheck.model_validate(check) for check in audit_row.checks
                    ),
                    passed=audit_row.passed,
                    performed_at=audit_row.performed_at,
                    auditor_version=audit_row.auditor_version,
                    small_cell_threshold=audit_row.small_cell_threshold,
                )
        return ModelArtifact(
            artifact_id=ArtifactId(row.artifact_id),
            version=row.version,
            format=row.format,  # type: ignore[arg-type]
            digest=ContentHash(row.digest),
            size_bytes=row.size_bytes,
            storage_uri=row.storage_uri,
            feature_set_id=row.feature_set_id,
            training_run_id=RunId(row.training_run_id),
            created_at=row.created_at,
            audit=audit,
            card=ModelCard.model_validate(row.payload_value),
        )

    # -- evaluation and deployment ---------------------------------------------------

    def record_evaluation(self, report: EvaluationReport) -> str:
        """Store an evaluation report, keeping the baseline note with the number.

        ``baseline_note`` is stored because the primary metric means nothing without
        it. "Parity with a good data scientist working for a week" and "parity with a
        mature in-house system carrying years of consortium data" are different claims,
        and only one of them is ours.
        """
        if self._session.get(EvaluationReportRow, report.report_id) is not None:
            return report.report_id
        self._session.add(
            EvaluationReportRow(
                report_id=report.report_id,
                artifact_id=str(report.artifact_id),
                primary_metric=report.primary_metric,
                primary_value=report.metrics[report.primary_metric],
                baseline_value=report.baseline_metrics.get(report.primary_metric),
                baseline_note=report.baseline_note,
                calibration_error=report.calibration_error,
                metrics=dict(report.metrics),
                slices_value=[item.model_dump(mode="json") for item in report.slices],
                slices_sensitivity=Sensitivity.DATA_VALUE.value,
                population=report.population,
                evaluated_as_of=report.evaluated_as_of,
            )
        )
        self._session.flush()
        return report.report_id

    def deploy(self, deployment: Deployment) -> DeploymentRecord:
        """Record a deployment. Append-only by discipline; refused by the database.

        The argument type is ``Deployment``, whose ``model`` is a ``DeployableModel``,
        so an unaudited artifact cannot even be expressed here. The composite foreign
        key is what catches the remaining case: an artifact certified earlier and marked
        undeployable since, because it was re-audited at different bytes.
        """
        model = deployment.model
        self._session.add(
            DeploymentRow(
                deployment_id=str(deployment.deployment_id),
                artifact_id=str(model.artifact_id),
                artifact_deployable=True,
                artifact_digest=str(model.artifact_digest),
                audit_id=str(model.audit_id),
                certificate=str(model.certificate),
                environment=deployment.environment,
                mode=deployment.mode.value,
                traffic_fraction=deployment.traffic_fraction,
                status=deployment.status.value,
                superseded_by=None
                if deployment.superseded_by is None
                else str(deployment.superseded_by),
                rollback_of=None if deployment.rollback_of is None else str(deployment.rollback_of),
                created_at=deployment.created_at,
            )
        )
        self._session.flush()
        return DeploymentRecord(
            deployment_id=str(deployment.deployment_id),
            artifact_id=model.artifact_id,
            artifact_digest=model.artifact_digest,
            environment=deployment.environment,
            mode=deployment.mode.value,
            traffic_fraction=deployment.traffic_fraction,
            status=deployment.status.value,
            superseded_by=None
            if deployment.superseded_by is None
            else str(deployment.superseded_by),
            rollback_of=None if deployment.rollback_of is None else str(deployment.rollback_of),
            created_at=deployment.created_at,
        )

    def promotion_history(
        self, *, artifact_id: ArtifactId | None = None, environment: str | None = None
    ) -> tuple[DeploymentRecord, ...]:
        """Every deployment, oldest first. A rollback appears as its own row.

        Ordered by ``created_at`` then ``deployment_id``, so two deployments stamped
        with the same injected instant still read back in a defined order.
        """
        statement = select(DeploymentRow)
        if artifact_id is not None:
            statement = statement.where(DeploymentRow.artifact_id == str(artifact_id))
        if environment is not None:
            statement = statement.where(DeploymentRow.environment == environment)
        rows = self._session.scalars(
            statement.order_by(DeploymentRow.created_at, DeploymentRow.deployment_id)
        )
        return tuple(
            DeploymentRecord(
                deployment_id=row.deployment_id,
                artifact_id=ArtifactId(row.artifact_id),
                artifact_digest=ContentHash(row.artifact_digest),
                environment=row.environment,
                mode=row.mode,
                traffic_fraction=row.traffic_fraction,
                status=row.status,
                superseded_by=row.superseded_by,
                rollback_of=row.rollback_of,
                created_at=row.created_at,
            )
            for row in rows
        )

    def deployable_artifacts(self) -> tuple[ArtifactId, ...]:
        """Artifacts the database will currently allow a deployment to reference."""
        rows = self._session.scalars(
            select(ModelArtifactRow.artifact_id)
            .where(ModelArtifactRow.deployable.is_(True))
            .order_by(ModelArtifactRow.artifact_id)
        )
        return tuple(ArtifactId(value) for value in rows)


def artifact_age(record: DeploymentRecord, *, now: Instant) -> _dt.timedelta:
    """How long a deployment has been in place. ``now`` is injected, never read."""
    return now - record.created_at


def deployment_count(session: Session, *, environment: str) -> NonNegInt:
    """How many deployments an environment has seen. Cheap operational counter."""
    rows: Sequence[Any] = list(
        session.scalars(
            select(DeploymentRow.deployment_id).where(DeploymentRow.environment == environment)
        )
    )
    return len(rows)


def artifact_version(row: ModelArtifactRow) -> Version:
    """The artifact's version, typed as the contracts' ``Version``."""
    return row.version
