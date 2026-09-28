"""Pattern store, dedup, false-discovery control, lifecycle and the audit ledgers (L5).

Owner: A3. Plane: **control**.

**This package stores data-derived values.** Segment predicates, label values,
explanation text, model cards and column profiles all sit in tainted payload columns
here, each with its sensitivity recorded beside it. It is not an egress boundary --
godwit-guard is -- but a bank's security team will read this schema, so read
``docs/packages/godwit-store.md`` §1 before using any of it.

WHAT THIS PACKAGE IS FOR
------------------------
A system testing thousands of hypotheses an hour produces findings that are
statistically significant and meaningless, and reports the same finding for ever. Alert
fatigue kills this product faster than poor accuracy does. This package is the answer to
that, in four parts:

* **Dedup** (:mod:`godwit_store.signature`, :mod:`godwit_store.store`) -- a signature
  over source, segment key, column set, detector family and effect direction, plus a
  pgvector embedding built from a **redacted** structural rendering.
* **False-discovery control** (:mod:`godwit_store.fdr`) -- Benjamini-Hochberg over an
  explicitly declared test family, plus a holdout slice a candidate must reproduce on
  before it can reach the operational queue.
* **Lifecycle** (:mod:`godwit_store.lifecycle`) -- allowed transitions, required
  evidence, automatic staleness, and an audit row for every move.
* **Evidence** (:mod:`godwit_store.ledger`, :mod:`godwit_store.reproduce`,
  :mod:`godwit_store.labels`) -- append-only hash-chained ledgers, point-in-time-correct
  labels, and ``reproduce(pattern_id)``, which is the feature a regulator actually asks
  about.

WHERE TO START
--------------
``PatternStore.ingest_batch`` is the wide entry point and the one to read first; the
protocol's ``ingest`` is a deliberately conservative wrapper over it. ``LabelLedger``
is the one every other package will touch, and its read API requires an explicit
instant with no default -- that is the whole design, not an inconvenience.
"""

from __future__ import annotations

from godwit_store.appendonly import (
    APPEND_ONLY_TABLES,
    append_only_statements,
    install_append_only,
)
from godwit_store.engine import (
    bootstrap_schema,
    check_connection,
    create_store_engine,
    session_factory,
    store_session,
)
from godwit_store.errors import (
    AppendOnlyViolationError,
    ChainBrokenError,
    LifecycleTransitionError,
    PatternNotFoundError,
    RevealRefusedError,
    StoreError,
    StoreIntegrityError,
    StoreUnavailableError,
    SuppressedError,
    UnboundedHypothesisFamilyError,
    UncoveredRegionError,
)
from godwit_store.fdr import (
    DEFAULT_Q,
    AdjustedTest,
    HoldoutKind,
    HoldoutPolicy,
    HypothesisFamily,
    ValidationStatus,
    benjamini_hochberg,
    conservative_test_count,
    reconcile_holdout,
)
from godwit_store.labels import CoverageVerdict, LabelLedger, entity_pseudonym
from godwit_store.ledger import (
    GENESIS_HASH,
    AuditEntry,
    ChainVerification,
    EgressEntry,
    append_audit,
    append_egress,
    assert_chain_intact,
    audit_query,
    chain_hash,
    egress_query,
    export_egress,
    verify_chain,
)
from godwit_store.lifecycle import (
    ALLOWED_TRANSITIONS,
    DEFAULT_STALE_WINDOWS,
    REQUIRED_EVIDENCE,
    TERMINAL_STATES,
    TransitionEvidence,
    expire_stale,
    lifecycle_for_verdict,
    transition,
)
from godwit_store.ranking import (
    DISCOVERY_CAPACITY_PER_WEEK,
    OPERATIONAL_CAPACITY_PER_DAY,
    RankedPattern,
    RankingInputs,
    RankingWeights,
    rank,
)
from godwit_store.registry import DeploymentRecord, ModelRegistryStore
from godwit_store.reproduce import (
    CandidateProducer,
    ReproductionKey,
    ReproductionRequest,
    ReproductionResult,
    reproduce,
    reproduction_key_of,
    stored_candidates,
    verify_reproduction,
)
from godwit_store.schema import SAFE_VIEWS, Base
from godwit_store.signature import (
    EMBEDDING_DIM,
    CandidateSignature,
    EffectDirection,
    cosine,
    embed_candidate,
    embed_rendering,
    signature_of,
    structural_rendering,
    structure_key,
)
from godwit_store.store import IngestReport, PatternStore, pattern_id_for

__version__ = "0.1.0"

__all__ = [
    "ALLOWED_TRANSITIONS",
    "APPEND_ONLY_TABLES",
    "DEFAULT_Q",
    "DEFAULT_STALE_WINDOWS",
    "DISCOVERY_CAPACITY_PER_WEEK",
    "EMBEDDING_DIM",
    "GENESIS_HASH",
    "OPERATIONAL_CAPACITY_PER_DAY",
    "REQUIRED_EVIDENCE",
    "SAFE_VIEWS",
    "TERMINAL_STATES",
    "AdjustedTest",
    "AppendOnlyViolationError",
    "AuditEntry",
    "Base",
    "CandidateProducer",
    "CandidateSignature",
    "ChainBrokenError",
    "ChainVerification",
    "CoverageVerdict",
    "DeploymentRecord",
    "EffectDirection",
    "EgressEntry",
    "HoldoutKind",
    "HoldoutPolicy",
    "HypothesisFamily",
    "IngestReport",
    "LabelLedger",
    "LifecycleTransitionError",
    "ModelRegistryStore",
    "PatternNotFoundError",
    "PatternStore",
    "RankedPattern",
    "RankingInputs",
    "RankingWeights",
    "ReproductionKey",
    "ReproductionRequest",
    "ReproductionResult",
    "RevealRefusedError",
    "StoreError",
    "StoreIntegrityError",
    "StoreUnavailableError",
    "SuppressedError",
    "TransitionEvidence",
    "UnboundedHypothesisFamilyError",
    "UncoveredRegionError",
    "ValidationStatus",
    "__version__",
    "append_audit",
    "append_egress",
    "append_only_statements",
    "assert_chain_intact",
    "audit_query",
    "benjamini_hochberg",
    "bootstrap_schema",
    "chain_hash",
    "check_connection",
    "conservative_test_count",
    "cosine",
    "create_store_engine",
    "egress_query",
    "embed_candidate",
    "embed_rendering",
    "entity_pseudonym",
    "expire_stale",
    "export_egress",
    "install_append_only",
    "lifecycle_for_verdict",
    "pattern_id_for",
    "rank",
    "reconcile_holdout",
    "reproduce",
    "reproduction_key_of",
    "session_factory",
    "signature_of",
    "store_session",
    "stored_candidates",
    "structural_rendering",
    "structure_key",
    "transition",
    "verify_chain",
    "verify_reproduction",
]
