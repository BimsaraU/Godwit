"""Model registry metadata, and the storage-layer refusal to deploy an unaudited model.

Invariant 3: *model artifacts are audited for memorisation before they cross. An
unaudited artifact is a data leak wearing a hat.*

Three independent mechanisms enforce it, and each is tested on its own, because a
defence that only works when all three are present is one deployment refactor away from
not working at all:

1. **The type.** ``Deployment.model`` is a ``DeployableModel``, which only
   ``certify_deployable`` produces and which has no override parameter.
2. **The check constraint.** ``model_artifacts.deployable`` cannot be true unless
   ``audit_passed`` is true.
3. **The foreign key.** ``deployments`` references ``(artifact_id, deployable)``, so a
   failed artifact has no row a deployment could point at -- with no application code in
   the path at all.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from godwit_contracts import (
    REQUIRED_MEMORISATION_CHECKS,
    Acquisition,
    ArtifactFormat,
    ArtifactId,
    AuditId,
    ContentHash,
    Deployment,
    DeploymentId,
    DeploymentMode,
    DeploymentStatus,
    Instant,
    MemorisationAudit,
    MemorisationAuditFailedError,
    MemorisationCheck,
    ModelArtifact,
    ModelCard,
    RunId,
    certify_deployable,
    data_value,
)
from godwit_store.errors import StoreIntegrityError
from godwit_store.registry import ModelRegistryStore
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


def _card() -> ModelCard:
    return ModelCard(
        intended_use=data_value("score card transactions", acquisition=Acquisition.USER_SUPPLIED),
        limitations=data_value("not for credit decisions", acquisition=Acquisition.USER_SUPPLIED),
        training_window="2023-01-01/2023-12-31",
    )


def _artifact(at: Instant, *, digest: str = "b2_artifact_one") -> ModelArtifact:
    return ModelArtifact(
        artifact_id=ArtifactId("art_1"),
        version=1,
        format=ArtifactFormat.ONNX,
        digest=ContentHash(digest),
        size_bytes=1024,
        storage_uri="s3://godwit-artifacts/art_1.onnx",
        feature_set_id="fs_1",
        training_run_id=RunId("run_1"),
        created_at=at,
        card=_card(),
    )


def _audit(
    at: Instant, *, digest: str = "b2_artifact_one", passing: bool = True
) -> MemorisationAudit:
    checks = tuple(
        MemorisationCheck(
            kind=kind,
            threshold=0.01,
            observed=0.0 if passing else 0.9,
            passed=passing,
        )
        for kind in sorted(REQUIRED_MEMORISATION_CHECKS, key=lambda kind: kind.value)
    )
    return MemorisationAudit(
        audit_id=AuditId("aud_1"),
        artifact_id=ArtifactId("art_1"),
        artifact_digest=ContentHash(digest),
        checks=checks,
        passed=passing,
        performed_at=at,
        auditor_version=1,
        small_cell_threshold=20,
    )


def _deployment(deployable: object, at: Instant) -> Deployment:
    return Deployment(
        deployment_id=DeploymentId("dep_1"),
        model=deployable,  # type: ignore[arg-type]
        environment="production",
        mode=DeploymentMode.SHADOW,
        traffic_fraction=0.0,
        status=DeploymentStatus.PENDING,
        created_at=at,
    )


# ------------------------------------------------------------------------------------
# Mechanism 1: the type
# ------------------------------------------------------------------------------------


def test_a_failed_audit_cannot_be_certified(session: Session, at: Instant) -> None:
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    assert registry.attach_audit(_audit(at, passing=False)) is False
    with pytest.raises(MemorisationAuditFailedError, match="failed its audit"):
        registry.certify(ArtifactId("art_1"))


def test_an_unaudited_artifact_cannot_be_certified(session: Session, at: Instant) -> None:
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    with pytest.raises(MemorisationAuditFailedError, match="no memorisation audit"):
        registry.certify(ArtifactId("art_1"))


def test_an_audit_of_different_bytes_does_not_make_an_artifact_deployable(
    session: Session, at: Instant
) -> None:
    """An audit is bound to bytes. Re-train and the old verdict means nothing.

    The audit is still stored -- it is a fact about *something* -- but the artifact stays
    undeployable, because what was audited is not what would ship.
    """
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at, digest="b2_new_bytes"), at=at)
    assert registry.attach_audit(_audit(at, digest="b2_old_bytes")) is False
    assert registry.deployable_artifacts() == ()
    with pytest.raises(MemorisationAuditFailedError):
        registry.certify(ArtifactId("art_1"))


def test_a_passing_audit_produces_a_certificate_bound_to_the_bytes(
    session: Session, at: Instant
) -> None:
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    assert registry.attach_audit(_audit(at)) is True
    deployable = registry.certify(ArtifactId("art_1"))
    assert deployable.audit_passed is True
    assert deployable.artifact_digest == ContentHash("b2_artifact_one")
    assert registry.deployable_artifacts() == (ArtifactId("art_1"),)


# ------------------------------------------------------------------------------------
# Mechanism 2: the check constraint
# ------------------------------------------------------------------------------------


def test_the_database_refuses_a_deployable_flag_without_a_passing_audit(
    session: Session, at: Instant
) -> None:
    """**Acceptance criterion, storage layer.** No Python in the path.

    Written as raw SQL on purpose: this is the query a well-meaning operator runs at
    two in the morning to "unblock the release", and it has to fail.
    """
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    registry.attach_audit(_audit(at, passing=False))
    session.commit()

    with pytest.raises(IntegrityError):
        session.execute(
            text("UPDATE model_artifacts SET deployable = 1 WHERE artifact_id = 'art_1'")
        )
        session.commit()
    session.rollback()


# ------------------------------------------------------------------------------------
# Mechanism 3: the foreign key
# ------------------------------------------------------------------------------------


def test_a_deployment_cannot_reference_an_undeployable_artifact(
    session: Session, at: Instant
) -> None:
    """The case the type system cannot catch: certified once, undeployable since.

    An artifact re-audited at different bytes loses its ``deployable`` row while a
    ``DeployableModel`` minted earlier still exists in some caller's memory. The
    composite foreign key is what stops that object being used.
    """
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    registry.attach_audit(_audit(at))
    deployable = registry.certify(ArtifactId("art_1"))
    session.commit()

    registry.attach_audit(
        _audit(at + _dt.timedelta(days=1), digest="b2_something_else").model_copy(
            update={"audit_id": AuditId("aud_2")}
        )
    )
    session.commit()

    with pytest.raises(IntegrityError):
        registry.deploy(_deployment(deployable, at))
        session.commit()
    session.rollback()


def test_a_deployment_of_a_properly_certified_model_is_recorded(
    session: Session, at: Instant
) -> None:
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    registry.attach_audit(_audit(at))
    deployable = registry.certify(ArtifactId("art_1"))
    record = registry.deploy(_deployment(deployable, at))
    assert record.artifact_id == ArtifactId("art_1")
    assert registry.promotion_history(environment="production") == (record,)


def test_a_shadow_deployment_takes_no_traffic(session: Session, at: Instant) -> None:
    """Enforced by the contract and again by a check constraint on the table."""
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    registry.attach_audit(_audit(at))
    deployable = registry.certify(ArtifactId("art_1"))
    with pytest.raises(ValueError, match=r"traffic_fraction 0\.0"):
        Deployment(
            deployment_id=DeploymentId("dep_2"),
            model=deployable,
            environment="production",
            mode=DeploymentMode.SHADOW,
            traffic_fraction=0.5,
            status=DeploymentStatus.PENDING,
            created_at=at,
        )


# ------------------------------------------------------------------------------------
# Content addressing
# ------------------------------------------------------------------------------------


def test_registering_the_same_bytes_twice_returns_the_same_artifact(
    session: Session, at: Instant
) -> None:
    registry = ModelRegistryStore(session)
    assert registry.register(_artifact(at), at=at) == ArtifactId("art_1")
    assert registry.register(_artifact(at), at=at) == ArtifactId("art_1")


def test_the_same_bytes_under_two_ids_is_refused(session: Session, at: Instant) -> None:
    """Two ids for one digest would let an audit on one appear to cover the other."""
    registry = ModelRegistryStore(session)
    registry.register(_artifact(at), at=at)
    other = _artifact(at).model_copy(update={"artifact_id": ArtifactId("art_2")})
    with pytest.raises(StoreIntegrityError, match="identified by its bytes"):
        registry.register(other, at=at)


def test_certify_is_the_only_route_and_matches_the_contracts_own_verdict(
    session: Session, at: Instant
) -> None:
    """The registry adds a lookup and nothing else.

    A second implementation of invariant 3 would be a second place for it to be wrong,
    so ``certify`` hands the rebuilt objects straight to ``certify_deployable``.
    """
    registry = ModelRegistryStore(session)
    artifact = _artifact(at)
    registry.register(artifact, at=at)
    audit = _audit(at)
    registry.attach_audit(audit)
    from_store = registry.certify(ArtifactId("art_1"))
    directly = certify_deployable(artifact.model_copy(update={"audit": audit}))
    assert from_store.certificate == directly.certificate
