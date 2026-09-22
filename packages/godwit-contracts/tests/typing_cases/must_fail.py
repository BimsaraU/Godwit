"""Code that MUST NOT type-check.

Each marked line carries ``# EXPECT: <mypy-error-code>``. ``test_static_typing.py`` runs
mypy over this file and asserts that every marked line produced exactly that error, and
that no unmarked line produced any error at all.

This file is excluded from the normal mypy run (see ``exclude`` in the root
``pyproject.toml``). It is not dead code -- it is the test.
"""

from __future__ import annotations

import datetime as _dt

from godwit_contracts import (
    Acquisition,
    ArtifactId,
    AuditId,
    DeployableModel,
    Deployment,
    DeploymentId,
    DeploymentMode,
    DeploymentStatus,
    ModelArtifact,
    Operator,
    Predicate,
    Tainted,
    content_hash,
    data_value,
    schema_name,
)

NOW = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)


# --------------------------------------------------------------------------------------
# 1. A tainted value is not the value. This is the whole taint system in one line.
# --------------------------------------------------------------------------------------


def send_to_log(message: str) -> None:
    """Pretend this writes to a log, which is an egress destination."""
    print(message)


def case_tainted_is_not_a_plain_value() -> None:
    customer_name: Tainted[str] = data_value(
        "Aoife Brennan",
        acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS,
        column="full_name",
    )
    send_to_log(customer_name)  # EXPECT: arg-type


def case_tainted_number_is_not_a_number() -> None:
    salary: Tainted[int] = data_value(41000, acquisition=Acquisition.QUANTILE)
    total: int = salary  # EXPECT: assignment
    print(total)


# --------------------------------------------------------------------------------------
# 2. A predicate column must be tainted. A bare string does not say whether it is safe.
# --------------------------------------------------------------------------------------


def case_predicate_column_must_be_tainted() -> None:
    Predicate(
        column="country",  # EXPECT: arg-type
        op=Operator.IS_NULL,
    )


# --------------------------------------------------------------------------------------
# 3. Invariant 3, statically: an unaudited artifact is not deployable.
# --------------------------------------------------------------------------------------


def case_deployment_refuses_a_raw_artifact(artifact: ModelArtifact) -> None:
    Deployment(
        deployment_id=DeploymentId("dep_0001"),
        model=artifact,  # EXPECT: arg-type
        environment="prod",
        mode=DeploymentMode.SHADOW,
        traffic_fraction=0.0,
        status=DeploymentStatus.ACTIVE,
        created_at=NOW,
    )


def case_a_failed_audit_is_not_representable() -> None:
    DeployableModel(
        artifact_id=ArtifactId("art_0001"),
        artifact_version=1,
        artifact_digest=content_hash("bytes"),
        audit_id=AuditId("aud_0001"),
        audit_digest=content_hash("audit"),
        audit_passed=False,  # EXPECT: arg-type
        certificate=content_hash("cert"),
    )


# --------------------------------------------------------------------------------------
# 4. The taint classes are not interchangeable at the call site either.
# --------------------------------------------------------------------------------------


def takes_a_column_name(column: str) -> str:
    return column.upper()


def case_schema_names_are_tainted_too() -> None:
    column = schema_name("patient_hiv_status")
    takes_a_column_name(column)  # EXPECT: arg-type
