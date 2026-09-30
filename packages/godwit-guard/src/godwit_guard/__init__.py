"""Classification, redaction, tokenisation and the egress gate (GATE).

Owner: A5. **Plane: boundary** -- it spans both. The token vault, the keyed hasher, the
format-entropy estimator and value classification run in the DATA PLANE and never leave
it. Policy, guardrails, access-mode state and the audit trail live in the CONTROL PLANE.

Importing this package claims the process's single ``SafePayloadIssuer``
(:mod:`godwit_guard.gate`). Nothing else may. Read ``docs/packages/godwit-guard.md`` and
``docs/specs/pii-threat-model.md`` before changing anything here.

The control is the typed taint plus the gate. The scanner in
:mod:`godwit_guard.scanner` is a BACKSTOP: a hit there is a defect in the taint system.
"""

from godwit_guard.access import (
    DEFAULT_MIN_ENTROPY_BITS,
    OPAQUE_SUFFIX,
    AccessControl,
    AccessGrant,
    AccessMode,
    AccessModeMap,
    EntropyAssessment,
    KeyedHasher,
    ModeDecision,
    Narrowing,
    ProjectionPlan,
    Remediation,
    assess_entropy,
    format_space_bits,
    plan_projection,
    verify_arrow_schema,
    verify_sql,
)
from godwit_guard.classify import (
    CatalogEntry,
    ClassificationProposal,
    ClassificationRegistry,
    Confirmation,
    QuasiIdentifierCombination,
    Signal,
    column_key,
    propose,
    quasi_identifier_combinations,
    ref_key,
)
from godwit_guard.destinations import DEFAULT_DESTINATION_POLICIES, DestinationPolicy
from godwit_guard.disclosure import (
    DifferentialPrivacy,
    ReleaseDecision,
    ReleaseLedger,
    dp_quantile,
    enforce_evidence_k,
    enforce_segment_k,
    laplace_count,
)
from godwit_guard.errors import (
    ApprovalRequiredError,
    BackstopHitError,
    EgressRefusedError,
    GrantError,
    GuardError,
    LedgerWriteError,
    OpaqueHashRefusedError,
    PolicyVersionError,
    ProjectionViolationError,
    ProviderRefusedError,
    Refusal,
    RefusalReason,
    TokenScopeError,
)
from godwit_guard.gate import GATE_CLAIMANT, EgressOptions, Gate, evidence_fields
from godwit_guard.ledger import EgressLedger, MemoryLedger, StoreLedger, audit_event
from godwit_guard.policy import DEFAULT_POLICY, PolicyRegistry
from godwit_guard.providers import ProviderKind, ProviderPolicy, ProviderProfile, select_provider
from godwit_guard.redactor import PolicyRedactor, Redaction
from godwit_guard.scanner import Backstop, BackstopFinding, BackstopMetrics
from godwit_guard.schema_names import SchemaNameMode, describe
from godwit_guard.transforms import (
    BUILTIN_HIERARCHIES,
    TokenVault,
    bucket,
    generalise,
    mapping_hierarchy,
)

__all__ = [
    "BUILTIN_HIERARCHIES",
    "DEFAULT_DESTINATION_POLICIES",
    "DEFAULT_MIN_ENTROPY_BITS",
    "DEFAULT_POLICY",
    "GATE_CLAIMANT",
    "OPAQUE_SUFFIX",
    "AccessControl",
    "AccessGrant",
    "AccessMode",
    "AccessModeMap",
    "ApprovalRequiredError",
    "Backstop",
    "BackstopFinding",
    "BackstopHitError",
    "BackstopMetrics",
    "CatalogEntry",
    "ClassificationProposal",
    "ClassificationRegistry",
    "Confirmation",
    "DestinationPolicy",
    "DifferentialPrivacy",
    "EgressLedger",
    "EgressOptions",
    "EgressRefusedError",
    "EntropyAssessment",
    "Gate",
    "GrantError",
    "GuardError",
    "KeyedHasher",
    "LedgerWriteError",
    "MemoryLedger",
    "ModeDecision",
    "Narrowing",
    "OpaqueHashRefusedError",
    "PolicyRedactor",
    "PolicyRegistry",
    "PolicyVersionError",
    "ProjectionPlan",
    "ProjectionViolationError",
    "ProviderKind",
    "ProviderPolicy",
    "ProviderProfile",
    "ProviderRefusedError",
    "QuasiIdentifierCombination",
    "Redaction",
    "Refusal",
    "RefusalReason",
    "ReleaseDecision",
    "ReleaseLedger",
    "Remediation",
    "SchemaNameMode",
    "Signal",
    "StoreLedger",
    "TokenScopeError",
    "TokenVault",
    "__version__",
    "assess_entropy",
    "audit_event",
    "bucket",
    "column_key",
    "describe",
    "dp_quantile",
    "enforce_evidence_k",
    "enforce_segment_k",
    "evidence_fields",
    "format_space_bits",
    "generalise",
    "laplace_count",
    "mapping_hierarchy",
    "plan_projection",
    "propose",
    "quasi_identifier_combinations",
    "ref_key",
    "select_provider",
    "verify_arrow_schema",
    "verify_sql",
]

__version__ = "0.1.0"
