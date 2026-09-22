"""Governance: guardrails, redaction policy, egress records, approvals, audit.

This module is what a bank's security team will read first. It is deliberately boring
and deliberately declarative: a guardrail is data, not a lambda, so it can be stored,
versioned, diffed, reviewed and replayed. ``godwit-guard`` evaluates these; contracts
only define them.

Three design rules are enforced by validation here:

1. A redaction policy's default action cannot be ALLOW. Deny by default is not a
   convention we hope people follow.
2. An ``EgressRecord`` cannot contain a tainted value. It records *that* something left
   and *what shape* it was, never the thing itself. An audit log full of PII is a
   second breach with better indexing.
3. A ``DatasourceConfig`` has no field that can hold a plaintext secret. Not a
   discouraged one -- none at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    Plane,
    Version,
)
from godwit_contracts.cost import CostBudget
from godwit_contracts.source import PiiClass
from godwit_contracts.taint import Sensitivity

__all__ = [
    "ApprovalRequest",
    "ApprovalStatus",
    "AuditEvent",
    "DatasourceConfig",
    "DatasourceKind",
    "Destination",
    "EgressRecord",
    "Guardrail",
    "GuardrailAction",
    "GuardrailAttribute",
    "GuardrailCondition",
    "GuardrailPredicate",
    "GuardrailScope",
    "RedactionAction",
    "RedactionPolicy",
    "RedactionRule",
    "SecretProvider",
    "SecretRef",
]


class Destination(StrEnum):
    """Everywhere a value can go once it stops being purely internal.

    Every one of these is an egress. ``LOG`` and ``TELEMETRY`` are on this list because
    they are the two people forget, and because driver exception messages routinely
    contain the offending row.
    """

    LLM_PROVIDER = "llm_provider"
    ALERT_CHANNEL = "alert_channel"
    UI = "ui"
    LOG = "log"
    TELEMETRY = "telemetry"
    EXPORT_FILE = "export_file"
    MODEL_ARTIFACT_STORE = "model_artifact_store"
    HUMAN_REVIEW = "human_review"
    WEBHOOK = "webhook"


class GuardrailAction(StrEnum):
    """What a guardrail does when it matches."""

    ALLOW = "allow"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class GuardrailAttribute(StrEnum):
    """The attributes a guardrail condition can test.

    A closed vocabulary, because an open one would mean guardrails carrying arbitrary
    expressions, which cannot be reviewed by the people who need to review them.
    """

    SENSITIVITY = "sensitivity"
    PII_CLASS = "pii_class"
    DESTINATION = "destination"
    PLANE = "plane"
    POPULATION = "population"
    SOURCE_ID = "source_id"
    COLUMN_NAME = "column_name"
    TABLE_NAME = "table_name"
    PURPOSE = "purpose"
    ACQUISITION = "acquisition"


class GuardrailCondition(GodwitModel):
    """One test. ``attribute op value``, with a closed set of operators."""

    attribute: GuardrailAttribute
    op: str = Field(
        pattern=r"^(eq|ne|in|not_in|lt|le|gt|ge|matches)$",
        description="A closed operator set. 'matches' is a regular expression and is "
        "only valid on name attributes.",
    )
    values: tuple[str | int | float | bool, ...] = Field(min_length=1)


class GuardrailPredicate(GodwitModel):
    """A conjunction of conditions. All must hold for the guardrail to fire.

    Disjunction is expressed by writing two guardrails. That is on purpose: a reviewer
    can read a list of rules far more reliably than a nested boolean expression.
    """

    all_of: tuple[GuardrailCondition, ...] = Field(min_length=1)


class GuardrailScope(GodwitModel):
    """Where a guardrail applies, before its predicate is even evaluated."""

    planes: tuple[Plane, ...] = ()
    destinations: tuple[Destination, ...] = ()
    sensitivities: tuple[Sensitivity, ...] = ()
    pii_classes: tuple[PiiClass, ...] = ()
    source_ids: tuple[str, ...] = ()
    min_population: NonNegInt | None = Field(
        default=None,
        description="Applies only when the population behind the value is at least "
        "this large. Use for rules that only make sense above a small-cell threshold.",
    )


class Guardrail(GodwitModel):
    """A named, versioned rule with a scope, a predicate and an action.

    Guardrails are never edited in place. A change produces a new version, so that an
    ``EgressRecord`` written last year still names the exact rule that allowed it.
    """

    guardrail_id: str
    name: str
    version: Version
    scope: GuardrailScope
    predicate: GuardrailPredicate
    action: GuardrailAction
    rationale: str = Field(
        description="Why this rule exists, for the human reading the audit trail."
    )
    enabled: bool = True
    created_at: Instant


class RedactionAction(StrEnum):
    """What to do with a value that may not leave as-is."""

    SUPPRESS = "suppress"
    HASH = "hash"
    BUCKET = "bucket"
    GENERALISE = "generalise"
    TOKENISE = "tokenise"
    ALLOW = "allow"


class RedactionRule(GodwitModel):
    """One redaction, matched by PII class, by column, or by both."""

    pii_class: PiiClass | None = None
    column_pattern: str | None = Field(
        default=None,
        description="Regular expression over the column name. Matching on names is a "
        "backstop, not the control: the control is the taint type.",
    )
    action: RedactionAction
    params: Mapping[str, int | float | str | bool] = Field(
        default_factory=dict,
        description="Action parameters: bucket width, generalisation level, token "
        "namespace. Never a row value.",
    )

    @model_validator(mode="after")
    def _rule_matches_something(self) -> Self:
        if self.pii_class is None and self.column_pattern is None:
            raise ValueError("a redaction rule must match on pii_class, column, or both")
        return self


class RedactionPolicy(GodwitModel):
    """The per-class, per-column rules the gate applies, plus the small-cell floors.

    ``default_action`` cannot be ALLOW. An unmatched value is an unclassified value,
    and an unclassified value is not a safe one.
    """

    policy_id: str
    version: Version
    rules: tuple[RedactionRule, ...] = ()
    default_action: RedactionAction = RedactionAction.SUPPRESS
    min_cell_size: NonNegInt = Field(
        default=20,
        description="Populations below this are suppressed. 'Segment X (n=3) is "
        "anomalous' re-identifies without quoting a value.",
    )
    quantile_min_population: NonNegInt = Field(
        default=100,
        description="Quantiles below this population are suppressed. The median salary "
        "of a twelve-person team is one person's salary, give or take.",
    )
    created_at: Instant

    @model_validator(mode="after")
    def _deny_by_default(self) -> Self:
        if self.default_action is RedactionAction.ALLOW:
            raise ValueError(
                "default_action cannot be ALLOW; unmatched values are unclassified "
                "values and deny by default is invariant 2"
            )
        return self


class EgressRecord(GodwitModel):
    """The immutable log entry for something that left the perimeter.

    What it records: that an egress happened, to where, under which policy and
    guardrails, with which field names, over what population, and a hash of the content.

    What it must never record: the content. Every field below is a plain type, never
    ``Tainted``, precisely so that there is no field a tainted value could sit in.
    """

    record_id: str
    occurred_at: Instant
    destination: Destination
    purpose: str
    actor: str = Field(description="The service or user that caused the egress.")

    policy_id: str
    policy_version: Version
    guardrail_ids: tuple[str, ...] = ()

    content_digest: ContentHash = Field(
        description="Hash of what left, so a later dispute can be settled without "
        "storing the content."
    )
    field_names: tuple[str, ...] = Field(
        default=(),
        description="The KEYS that left, not the values. Note that a key can itself be "
        "a disclosure, so the gate must have cleared these too.",
    )
    source_ids: tuple[str, ...] = ()
    sensitivity_before: Sensitivity
    sensitivity_after: Sensitivity
    actions_applied: tuple[RedactionAction, ...] = ()
    min_population: NonNegInt | None = None
    approval_id: str | None = None


class ApprovalStatus(StrEnum):
    """Where a REQUIRE_APPROVAL guardrail's request got to."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalRequest(GodwitModel):
    """A human decision a guardrail asked for, and what they decided."""

    request_id: str
    subject_kind: str = Field(description="What needs approving: 'egress', 'deployment'.")
    subject_id: str
    requested_by: str
    requested_at: Instant
    reason: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decided_at: Instant | None = None
    expires_at: Instant | None = None

    @model_validator(mode="after")
    def _decision_is_complete(self) -> Self:
        decided = self.status in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED)
        if decided and (self.decided_by is None or self.decided_at is None):
            raise ValueError("a decided request must name who decided and when")
        return self


class AuditEvent(GodwitModel):
    """Anything worth being able to prove happened.

    ``detail_digest`` rather than ``detail``: the audit log says what happened, not what
    the data was.
    """

    event_id: str
    occurred_at: Instant
    actor: str
    action: str
    subject_kind: str
    subject_id: str
    plane: Plane
    detail_digest: ContentHash | None = None
    correlation_id: str | None = None


class SecretProvider(StrEnum):
    """Where a secret actually lives. Never in our database in plaintext."""

    KMS_ENVELOPE = "kms_envelope"
    VAULT = "vault"
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    ENVIRONMENT = "environment"


class SecretRef(GodwitModel):
    """A pointer to a secret. There is no field here that holds one.

    If you find yourself wanting to add ``value: str``, the answer is no. Envelope
    encryption with a KMS, or a reference to an external manager. Those are the options.
    """

    provider: SecretProvider
    reference: str = Field(
        description="Key id, Vault path, secret ARN or environment variable name."
    )
    key_version: str | None = None


class DatasourceKind(StrEnum):
    """What the Vision Board is pointing at."""

    ORCHESTRATOR = "orchestrator"
    CONTROL_PLANE = "control_plane"


class DatasourceConfig(GodwitModel):
    """How the Vision Board reaches an orchestrator or a control plane.

    The Vision Board is a standalone service. It talks to control-plane APIs and never
    to a data-plane worker, which is why there is no connection string here: a
    connection string would imply the Board could read rows, and it cannot.
    """

    datasource_id: str
    name: str
    kind: DatasourceKind
    base_url: str = Field(pattern=r"^https://")
    auth: SecretRef
    tls_ca: SecretRef | None = None
    timeout_seconds: float = Field(default=30.0, gt=0.0)
    default_budget: CostBudget
    created_at: Instant
