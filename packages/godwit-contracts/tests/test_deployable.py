"""Invariant 3: an unaudited artifact cannot become a deployment.

The runtime half is here. The static half -- that mypy rejects
``Deployment(model=artifact)`` -- is in ``test_static_typing.py``.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from godwit_contracts import (
    REQUIRED_MEMORISATION_CHECKS,
    ArtifactFormat,
    DeployableModel,
    Deployment,
    DeploymentMode,
    DeploymentStatus,
    MemorisationAudit,
    MemorisationAuditFailedError,
    MemorisationCheck,
    MemorisationCheckKind,
    ModelArtifact,
    ModelCard,
    Sensitivity,
    Tainted,
    certify_deployable,
    content_hash,
)
from godwit_contracts.taint import Acquisition, Provenance

NOW = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
DIGEST = content_hash("model-bytes")


def note(text: str) -> Tainted[str]:
    return Tainted[str](
        value=text,
        sensitivity=Sensitivity.SCHEMA_NAME,
        provenance=Provenance(acquisition=Acquisition.CATALOG_IDENTIFIER),
    )


def passing_checks() -> tuple[MemorisationCheck, ...]:
    return tuple(
        MemorisationCheck(kind=kind, threshold=0.0, observed=0.0, passed=True)
        for kind in sorted(REQUIRED_MEMORISATION_CHECKS, key=lambda item: item.value)
    )


def audit(*, passed: bool = True, digest: str | None = None) -> MemorisationAudit:
    checks = list(passing_checks())
    if not passed:
        checks[0] = MemorisationCheck(
            kind=checks[0].kind, threshold=0.0, observed=1.0, passed=False
        )
    return MemorisationAudit(
        audit_id="aud_0001",
        artifact_id="art_0001",
        artifact_digest=digest or DIGEST,
        checks=tuple(checks),
        passed=passed,
        performed_at=NOW,
        auditor_version=1,
        small_cell_threshold=20,
    )


def artifact(audit_value: MemorisationAudit | None) -> ModelArtifact:
    return ModelArtifact(
        artifact_id="art_0001",
        version=1,
        format=ArtifactFormat.ONNX,
        digest=DIGEST,
        size_bytes=4096,
        storage_uri="s3://godwit-artifacts/art_0001.onnx",
        feature_set_id="fs_0001",
        training_run_id="run_0001",
        created_at=NOW,
        audit=audit_value,
        card=ModelCard(
            intended_use=note("card fraud scoring"),
            limitations=note("trained on 90 days; no consortium data"),
            training_window="2023-10-01/2023-12-31",
        ),
    )


# --------------------------------------------------------------------------------------


def test_an_unaudited_artifact_cannot_be_certified() -> None:
    with pytest.raises(MemorisationAuditFailedError, match="no memorisation audit"):
        certify_deployable(artifact(None))


def test_a_failed_audit_cannot_be_certified() -> None:
    with pytest.raises(MemorisationAuditFailedError, match="failed its audit"):
        certify_deployable(artifact(audit(passed=False)))


def test_an_audit_of_different_bytes_is_rejected_at_attach_time() -> None:
    """Re-training and reusing last week's audit is the obvious way round invariant 3."""
    with pytest.raises(ValueError, match="different bytes"):
        artifact(audit(digest=content_hash("some-other-model")))


def test_certify_has_no_override() -> None:
    """There is no force, no skip_audit, no allow_unaudited. Check the signature."""
    import inspect

    parameters = inspect.signature(certify_deployable).parameters
    assert list(parameters) == ["artifact"]


def test_a_passing_audit_produces_a_deployable() -> None:
    deployable = certify_deployable(artifact(audit()))
    assert deployable.audit_passed is True
    assert deployable.artifact_digest == DIGEST
    assert deployable.certificate.startswith("dep_")


def test_the_certificate_binds_the_artifact_to_the_audit() -> None:
    """A deployable cannot be re-pointed at different bytes after the fact."""
    deployable = certify_deployable(artifact(audit()))
    forged = deployable.model_dump()
    forged["artifact_digest"] = content_hash("a-model-that-was-never-audited")

    with pytest.raises(ValueError, match=r"certificate does not match"):
        DeployableModel(**forged)


def test_a_failed_deployable_is_not_representable() -> None:
    """``audit_passed: Literal[True]`` means False does not parse, let alone deploy."""
    deployable = certify_deployable(artifact(audit()))
    forged = deployable.model_dump()
    forged["audit_passed"] = False

    with pytest.raises(ValueError, match=r"audit_passed"):
        DeployableModel(**forged)


def test_an_audit_missing_a_required_check_is_invalid() -> None:
    """Incomplete audits are the polite way to skip one."""
    incomplete = [
        check
        for check in passing_checks()
        if check.kind is not MemorisationCheckKind.TARGET_ENCODING_CARDINALITY
    ]
    with pytest.raises(ValueError, match="incomplete, missing"):
        MemorisationAudit(
            audit_id="aud_0002",
            artifact_id="art_0001",
            artifact_digest=DIGEST,
            checks=tuple(incomplete),
            passed=True,
            performed_at=NOW,
            auditor_version=1,
            small_cell_threshold=20,
        )


def test_passed_cannot_contradict_the_checks() -> None:
    """``passed=True`` is not something an optimistic caller gets to assert."""
    checks = list(passing_checks())
    checks[0] = MemorisationCheck(kind=checks[0].kind, threshold=0.0, observed=1.0, passed=False)
    with pytest.raises(ValueError, match="contradicts the checks"):
        MemorisationAudit(
            audit_id="aud_0003",
            artifact_id="art_0001",
            artifact_digest=DIGEST,
            checks=tuple(checks),
            passed=True,
            performed_at=NOW,
            auditor_version=1,
            small_cell_threshold=20,
        )


def test_a_deployment_takes_a_deployable_and_nothing_else() -> None:
    deployable = certify_deployable(artifact(audit()))
    deployment = Deployment(
        deployment_id="dep_0001",
        model=deployable,
        environment="prod",
        mode=DeploymentMode.SHADOW,
        traffic_fraction=0.0,
        status=DeploymentStatus.ACTIVE,
        created_at=NOW,
    )
    assert deployment.model.artifact_id == "art_0001"

    with pytest.raises(ValueError, match=r"validation error|model"):
        Deployment(
            deployment_id="dep_0002",
            model=artifact(audit()),  # type: ignore[arg-type]
            environment="prod",
            mode=DeploymentMode.SHADOW,
            traffic_fraction=0.0,
            status=DeploymentStatus.ACTIVE,
            created_at=NOW,
        )


def test_shadow_deployments_take_no_traffic() -> None:
    deployable = certify_deployable(artifact(audit()))
    with pytest.raises(ValueError, match=r"traffic_fraction 0\.0"):
        Deployment(
            deployment_id="dep_0003",
            model=deployable,
            environment="prod",
            mode=DeploymentMode.SHADOW,
            traffic_fraction=0.5,
            status=DeploymentStatus.ACTIVE,
            created_at=NOW,
        )
