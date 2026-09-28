"""The relational schema. Control plane.

**This package stores data-derived values.** Every one of them sits in a column group
whose name ends in ``_value``, with its sensitivity, acquisition and population in the
three columns beside it. Nothing else in a row is customer data, and the ``*_safe``
views exist so that a query which needs statistics cannot reach a value by accident.

THE STORAGE CONVENTION
----------------------
Each stored contract object decomposes into two parts:

* **Safe columns** -- our own identifiers, keys, hashes, counts, p-values, q-values,
  timestamps, lifecycle states. These carry no row value and are what every index,
  every join and every dashboard query uses.
* **One tainted payload** -- the contract object itself, serialised, in
  ``payload_value``, with ``payload_sensitivity``, ``payload_acquisition`` and
  ``payload_population`` alongside. Reading it is a deliberate act: it is the only
  column that can hold a segment predicate, a label value or an explanation.

Making the safe query the easy one is the whole point. ``SELECT q_value, score FROM
patterns_safe WHERE lifecycle = 'proposed'`` answers the question a queue needs and
touches nothing tainted. There is no version of that query that accidentally selects a
merchant name.

APPEND-ONLY LEDGERS
-------------------
``audit_events`` and ``egress_records`` are append-only and hash-chained. The chain is
in :mod:`godwit_store.ledger`; the *enforcement* is in :mod:`godwit_store.appendonly`,
which emits ``REVOKE UPDATE, DELETE`` and a refusing trigger. Grants, not convention.

DEPLOYABILITY IS ENFORCED BY A FOREIGN KEY
------------------------------------------
``model_artifacts`` carries ``deployable``, constrained so it can only be true when
``audit_passed`` is true, and is unique on ``(artifact_id, deployable)``.
``deployments`` carries ``artifact_deployable``, constrained to be true, and references
that pair. An artifact whose memorisation audit failed therefore has no row a
deployment could point at -- the database refuses it, with no application code in the
path (deliverable 7, invariant 3).
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Final

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.engine import Connection
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from godwit_store.columns import Embedding, Json, UtcInstant

__all__ = [
    "SAFE_VIEWS",
    "ApprovalRequestRow",
    "AuditEventRow",
    "Base",
    "CandidateRow",
    "ColumnProfileRow",
    "CostLedgerRow",
    "DeploymentRow",
    "DetectorRunRow",
    "EgressRecordRow",
    "EvaluationReportRow",
    "ExplanationRow",
    "FeatureSetRow",
    "FeedbackRow",
    "GuardrailRow",
    "LabelCoverageRow",
    "LabelRow",
    "MemorisationAuditRow",
    "ModelArtifactRow",
    "PatternAncestryRow",
    "PatternCandidateRow",
    "PatternRow",
    "ProbeSpecRow",
    "RedactionPolicyRow",
    "SketchEnvelopeRow",
    "SnapshotRow",
    "SourceRow",
    "SuppressionRow",
    "TrainingRunRow",
    "view_ddl",
]

_NAMING: Final[dict[str, str]] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s",
    "pk": "pk_%(table_name)s",
}
"""Deterministic constraint names. Alembic autogenerate produces unreadable diffs
without them, and a migration that cannot name the constraint it is dropping is a
migration nobody can review."""


class Base(DeclarativeBase):
    """Declarative base carrying the naming convention."""

    metadata = MetaData(naming_convention=_NAMING)


class TaintedPayload:
    """The four columns every tainted payload decomposes into.

    A mixin rather than four repeated declarations, so that the convention is stated
    once and a new table cannot half-adopt it. ``payload_sensitivity`` is not
    nullable: a stored value whose sensitivity nobody recorded is exactly the
    unclassified case that invariant 2 denies by default.
    """

    payload_value: Mapped[Any] = mapped_column(Json, nullable=False)
    payload_sensitivity: Mapped[str] = mapped_column(Text, nullable=False)
    payload_acquisition: Mapped[str] = mapped_column(Text, nullable=False)
    payload_population: Mapped[int | None] = mapped_column(Integer, nullable=True)


class HashChain:
    """Sequence number and hash chain for an append-only ledger.

    ``row_hash = blake2b(prev_hash || canonical_json(row))``. The chain makes deletion
    and amendment detectable: removing row *n* leaves row *n+1* pointing at a hash
    nothing produces. It is tamper-*evident*, not tamper-proof -- an attacker with
    write access could rebuild the whole chain, which is why the grants matter too.
    """

    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    prev_hash: Mapped[str] = mapped_column(Text, nullable=False)
    row_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)


# --------------------------------------------------------------------------------------
# L-1 / L0 -- what we know about the customer's data, before any of it is measured
# --------------------------------------------------------------------------------------


class SourceRow(Base):
    """One customer table we are allowed to look at.

    ``namespace`` and ``table`` are the customer's names, which are SCHEMA_NAME
    disclosures in their own right (leak path 9), so they live in the tainted payload
    and not in a plain column.
    """

    __tablename__ = "sources"

    source_id: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    catalog: Mapped[str] = mapped_column(Text, nullable=False)
    name_value: Mapped[Any] = mapped_column(Json, nullable=False)
    name_sensitivity: Mapped[str] = mapped_column(Text, nullable=False)
    registered_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)


class SnapshotRow(Base):
    """A point in a table's history. Half of every reproduction key."""

    __tablename__ = "snapshots"

    snapshot_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source_id: Mapped[str] = mapped_column(
        Text, ForeignKey("sources.source_id"), nullable=False, index=True
    )
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    committed_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    parent_snapshot_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    row_count_estimate: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (Index("ix_snapshots_source_committed", "source_id", "committed_at"),)


class ColumnProfileRow(Base, TaintedPayload):
    """L0's view of one column.

    The payload holds ``min_bound``, ``max_bound`` and ``most_common_values``, which are
    leak paths 1 and 2: the minimum of a name column is somebody's name. The safe
    columns hold the type, the role, the PII class and the fractions, which are what
    the orchestrator actually reads when deciding where to spend a scan.
    """

    __tablename__ = "column_profiles"

    profile_id: Mapped[str] = mapped_column(Text, primary_key=True)
    source_id: Mapped[str] = mapped_column(Text, ForeignKey("sources.source_id"), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(Text, nullable=False)
    column_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Canonicalised column name. SCHEMA_NAME class; used as a join key.",
    )
    logical_type: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    pii_class: Mapped[str] = mapped_column(Text, nullable=False)
    access_mode: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="blind, opaque or open. A column with no confirmed classification is "
        "blind: the system fails closed when a migration adds customer_email_v2.",
    )
    null_fraction: Mapped[float | None] = mapped_column(Float, nullable=True)
    distinct_estimate: Mapped[int | None] = mapped_column(Integer, nullable=True)
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    observed_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    profile_version: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        UniqueConstraint("source_id", "snapshot_id", "column_key", name="uq_profile_identity"),
        Index("ix_column_profiles_pii", "source_id", "pii_class"),
    )


# --------------------------------------------------------------------------------------
# L1 / L2 -- measurements and the runs that produced them
# --------------------------------------------------------------------------------------


class ProbeSpecRow(Base, TaintedPayload):
    """A measurement, stored by its stable ``probe_key``.

    The payload is the whole ``ProbeSpec``: its segment carries row values. The safe
    columns are what replay and the orchestrator need to find it again.
    """

    __tablename__ = "probe_specs"

    probe_key: Mapped[str] = mapped_column(Text, primary_key=True)
    probe_id: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str] = mapped_column(
        Text, ForeignKey("sources.source_id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    spec_version: Mapped[int] = mapped_column(Integer, nullable=False)
    segment_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    as_of: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    first_seen: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)


class SketchEnvelopeRow(Base, TaintedPayload):
    """One serialised sketch.

    Count-Min, frequent-items and quantile payloads contain row values -- on an
    identifier column the heavy hitters *are* the PII (leak path 3). The envelope is
    therefore always a tainted payload, whatever the envelope's own declaration says,
    and the declaration is recorded next to it in ``payload_sensitivity`` so a
    disagreement is visible rather than lost.
    """

    __tablename__ = "sketch_envelopes"

    envelope_id: Mapped[str] = mapped_column(Text, primary_key=True)
    probe_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    snapshot_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    sketch_kind: Mapped[str] = mapped_column(Text, nullable=False)
    sketch_name: Mapped[str] = mapped_column(Text, nullable=False)
    codec: Mapped[str] = mapped_column(Text, nullable=False)
    codec_version: Mapped[int] = mapped_column(Integer, nullable=False)
    population: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stored_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        UniqueConstraint("probe_key", "snapshot_id", "sketch_name", name="uq_envelope_identity"),
    )


class DetectorRunRow(Base):
    """One detector execution, and the test family and holdout it declared.

    This row is what makes false-discovery control honest. ``test_count`` is how many
    hypotheses the detector *examined*; adjusting against the number it *emitted* makes
    a heavily prefiltering detector look more significant the more it filters. A run
    that cannot state a count is refused at ingest, not absorbed.
    """

    __tablename__ = "detector_runs"

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    detector: Mapped[str] = mapped_column(Text, nullable=False)
    detector_version: Mapped[int] = mapped_column(Integer, nullable=False)
    code_version: Mapped[str] = mapped_column(Text, nullable=False)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    family_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    test_count: Mapped[int] = mapped_column(Integer, nullable=False)
    emitted_count: Mapped[int] = mapped_column(Integer, nullable=False)
    q_target: Mapped[float] = mapped_column(Float, nullable=False)
    holdout_kind: Mapped[str] = mapped_column(Text, nullable=False)
    holdout_key: Mapped[str] = mapped_column(Text, nullable=False)
    holdout_spec: Mapped[Any] = mapped_column(
        Json,
        nullable=False,
        comment="The HoldoutPolicy, so the reserved slice can be rebuilt on replay. "
        "Contains no row value: a time window and a hash partition, never a predicate.",
    )
    declared_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        CheckConstraint("test_count > 0", name="test_family_is_bounded"),
        CheckConstraint("test_count >= emitted_count", name="tests_cover_emissions"),
        CheckConstraint("q_target > 0.0 AND q_target <= 1.0", name="q_target_is_a_rate"),
    )


class CandidateRow(Base, TaintedPayload):
    """A detector's raw output, before it becomes part of a pattern.

    Candidates are cheap and numerous, and most of them die here. The payload is the
    whole ``Candidate`` -- its segment predicates quote real values. Everything a query
    needs is beside it: the three keys, the statistics, the FDR verdict and the
    holdout verdict.
    """

    __tablename__ = "candidates"

    candidate_id: Mapped[str] = mapped_column(Text, primary_key=True)
    run_id: Mapped[str] = mapped_column(
        Text, ForeignKey("detector_runs.run_id"), nullable=False, index=True
    )
    source_id: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot_id: Mapped[str] = mapped_column(Text, nullable=False)
    baseline_snapshot_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    segment_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    signature: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    structure_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    family: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Sorted evidence kinds, comma separated."
    )
    direction: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    p_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    q_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    fdr_rejected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    validation_status: Mapped[str] = mapped_column(Text, nullable=False)
    population: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detector: Mapped[str] = mapped_column(Text, nullable=False)
    detector_version: Mapped[int] = mapped_column(Integer, nullable=False)
    code_version: Mapped[str] = mapped_column(Text, nullable=False)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    probe_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    ingested_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        Index("ix_candidates_source_created", "source_id", "created_at"),
        Index("ix_candidates_signature_snapshot", "signature", "snapshot_id"),
        CheckConstraint(
            "p_value IS NULL OR (p_value >= 0.0 AND p_value <= 1.0)",
            name="p_value_is_a_probability",
        ),
        CheckConstraint(
            "q_value IS NULL OR (q_value >= 0.0 AND q_value <= 1.0)",
            name="q_value_is_a_probability",
        ),
    )


# --------------------------------------------------------------------------------------
# L5 -- patterns, their membership, their ancestry and their suppression
# --------------------------------------------------------------------------------------


class PatternRow(Base, TaintedPayload):
    """A deduplicated, FDR-controlled claim with a life of its own.

    One row per signature. A second candidate with the same signature extends this
    pattern's evidence; a candidate whose direction or segment has materially shifted
    has a different signature, opens a new pattern, and is linked back here through
    ``pattern_ancestry``.

    ``reproduction_key`` is the regulator-facing field. Given it and the code at
    ``code_version``, the candidates behind this pattern come back identically with the
    entire LLM layer deleted (invariant 7).
    """

    __tablename__ = "patterns"

    pattern_id: Mapped[str] = mapped_column(Text, primary_key=True)
    signature: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    structure_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(Text, nullable=False)
    segment_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    family: Mapped[str] = mapped_column(Text, nullable=False)
    direction: Mapped[str] = mapped_column(Text, nullable=False)

    lifecycle: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    last_seen: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    last_snapshot_id: Mapped[str] = mapped_column(Text, nullable=False)
    windows_without_support: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Consecutive detector runs over this source that produced no supporting "
        "candidate. Drives automatic staleness.",
    )

    score: Mapped[float] = mapped_column(Float, nullable=False)
    q_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    population: Mapped[int | None] = mapped_column(Integer, nullable=True)
    candidate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    validation_status: Mapped[str] = mapped_column(Text, nullable=False)
    explained_away: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    confirmations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rejections: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    representative_candidate_id: Mapped[str] = mapped_column(Text, nullable=False)
    reproduction_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    dedup_group: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    embedding: Mapped[tuple[float, ...] | None] = mapped_column(Embedding, nullable=True)
    embedding_sensitivity: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="SCHEMA_NAME: the vector is built from the redacted rendering, which "
        "carries customer column names but no row value. Never DATA_VALUE -- an "
        "embedding over raw values would itself be an egress channel.",
    )

    __table_args__ = (
        Index("ix_patterns_queue", "source_id", "lifecycle", "last_seen"),
        Index("ix_patterns_open_q", "lifecycle", "q_value"),
        CheckConstraint(
            "q_value IS NULL OR (q_value >= 0.0 AND q_value <= 1.0)",
            name="q_value_is_a_probability",
        ),
        CheckConstraint("last_seen >= first_seen", name="times_are_ordered"),
        CheckConstraint(
            "embedding_sensitivity <> 'data_value'",
            name="embedding_is_not_built_from_values",
        ),
    )


class PatternCandidateRow(Base):
    """Membership: which candidates are the evidence behind which pattern.

    The primary key is the pair, which is what makes ingest idempotent -- re-ingesting
    the same candidate touches one pattern and creates one membership, per protocol
    law 1, with no application-level "have I seen this" check to get wrong.
    """

    __tablename__ = "pattern_candidates"

    pattern_id: Mapped[str] = mapped_column(
        Text, ForeignKey("patterns.pattern_id"), primary_key=True
    )
    candidate_id: Mapped[str] = mapped_column(
        Text, ForeignKey("candidates.candidate_id"), primary_key=True
    )
    added_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    is_representative: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (Index("ix_pattern_candidates_candidate", "candidate_id"),)


class PatternAncestryRow(Base):
    """A new pattern's link back to the one it shifted away from.

    A pattern is never silently rewritten when its segment or direction moves. The new
    finding gets its own row and its own lifecycle, and this table records what it came
    from and why, so a reviewer looking at "refunds in PT are now falling" can see that
    it used to be "rising" and is not a fresh discovery.
    """

    __tablename__ = "pattern_ancestry"

    pattern_id: Mapped[str] = mapped_column(
        Text, ForeignKey("patterns.pattern_id"), primary_key=True
    )
    ancestor_pattern_id: Mapped[str] = mapped_column(
        Text, ForeignKey("patterns.pattern_id"), primary_key=True
    )
    reason: Mapped[str] = mapped_column(
        Text, nullable=False, comment="direction_shift, segment_shift or family_shift."
    )
    linked_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (Index("ix_pattern_ancestry_ancestor", "ancestor_pattern_id"),)


class SuppressionRow(Base):
    """A dismissal, recorded and reversible.

    Suppression is by signature, not by pattern id: the point of dismissing a finding
    is that the *same finding* stops arriving, including the instance of it that next
    week's snapshot produces. ``lifted_at`` rather than a delete, so that "who silenced
    this alert, when, and who turned it back on" is answerable.
    """

    __tablename__ = "suppressions"

    suppression_id: Mapped[str] = mapped_column(Text, primary_key=True)
    signature: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    pattern_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    lifted_at: Mapped[_dt.datetime | None] = mapped_column(UtcInstant, nullable=True)
    lifted_by: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_suppressions_active", "signature", "lifted_at"),)


class ExplanationRow(Base, TaintedPayload):
    """Why we think a pattern matters, in words. L9 writes these; L2 never reads them.

    Invariant 7: deleting every row in this table changes no pattern and no prediction.
    The payload is at least TOKEN-class -- an explanation can echo a token it was shown,
    and a token is still a pseudonym.
    """

    __tablename__ = "explanations"

    explanation_id: Mapped[str] = mapped_column(Text, primary_key=True)
    pattern_id: Mapped[str] = mapped_column(
        Text, ForeignKey("patterns.pattern_id"), nullable=False, index=True
    )
    produced_by: Mapped[str] = mapped_column(Text, nullable=False)
    model_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    prompt_digest: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_digest: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "payload_sensitivity <> 'derived_statistic'",
            name="explanation_is_not_a_statistic",
        ),
    )


class FeedbackRow(Base, TaintedPayload):
    """A human's verdict. The only ground truth discovery ever gets.

    The payload holds the reviewer's free-text notes. Assume they pasted a row, because
    they did.
    """

    __tablename__ = "feedback"

    feedback_id: Mapped[str] = mapped_column(Text, primary_key=True)
    pattern_id: Mapped[str] = mapped_column(
        Text, ForeignKey("patterns.pattern_id"), nullable=False, index=True
    )
    verdict: Mapped[str] = mapped_column(Text, nullable=False)
    reviewer_id: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    decided_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (Index("ix_feedback_verdict_time", "verdict", "decided_at"),)


# --------------------------------------------------------------------------------------
# The label ledger -- point-in-time correctness
# --------------------------------------------------------------------------------------


class LabelCoverageRow(Base, TaintedPayload):
    """What a set of labels actually covers.

    Half-labelled data is the normal case and the dangerous mistake is treating "no
    label" as "negative". ``is_exhaustive`` is the field that tells a trainer whether
    an unlabelled entity is a negative or an unknown, and ``segment_key`` says which
    population the claim is about. The payload holds the population ``Segment``, whose
    predicates quote real values.
    """

    __tablename__ = "label_coverage"

    coverage_id: Mapped[str] = mapped_column(Text, primary_key=True)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    segment_key: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    complete_from: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    complete_to: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    is_exhaustive: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    declared_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        Index("ix_coverage_window", "entity_type", "complete_from", "complete_to"),
        CheckConstraint("complete_to >= complete_from", name="window_is_ordered"),
    )


class LabelRow(Base, TaintedPayload):
    """One label, with the two timestamps that matter.

    ``event_time`` is when the thing happened; ``label_time`` is when we learned about
    it. A chargeback lands sixty days after the transaction, and training on the label
    at its event time leaks sixty days of future knowledge into the model.

    **Every read of this table goes through** :mod:`godwit_store.labels`, which requires
    an explicit instant. There is no convenience overload and no default, because the
    most common leakage bug in the industry is a pipeline that quietly used "now".

    ``entity_key`` is a keyed-free pseudonym of the entity id -- a BLAKE2b digest,
    computed so that labels can be indexed and joined without a plain identifier
    sitting in an index. It is a pseudonym, not an anonymisation: over a small or
    guessable id space it is enumerable, exactly as ``SegmentKey`` is.
    """

    __tablename__ = "labels"

    label_id: Mapped[str] = mapped_column(Text, primary_key=True)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_key: Mapped[str] = mapped_column(Text, nullable=False)
    coverage_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("label_coverage.coverage_id"), nullable=True
    )
    event_time: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    label_time: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    recorded_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        Index("ix_labels_asof", "entity_type", "label_time"),
        Index("ix_labels_entity", "entity_type", "entity_key", "label_time"),
        CheckConstraint("label_time >= event_time", name="label_follows_event"),
    )


# --------------------------------------------------------------------------------------
# L6 / L7 / L8 -- feature sets, training, artifacts, audits, deployments
# --------------------------------------------------------------------------------------


class FeatureSetRow(Base, TaintedPayload):
    """A versioned bundle of feature specs.

    The payload holds the specs, whose *names* are a leak path: ``is_merchant_ACME_CORP``
    discloses a merchant, and it surfaces in SHAP output and model cards.
    ``derived_from_patterns`` records the discovery-to-prediction loop in a column the
    orchestrator can query without opening the payload.
    """

    __tablename__ = "feature_sets"

    feature_set_id: Mapped[str] = mapped_column(Text, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    spec_count: Mapped[int] = mapped_column(Integer, nullable=False)
    derived_from_patterns: Mapped[Any] = mapped_column(
        Json, nullable=False, comment="Pattern ids this feature set is built from. Ours."
    )
    as_of: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)


class TrainingRunRow(Base):
    """One execution of a training task. ``refused_budget`` is a normal outcome.

    ``failure_reason`` is our own message. A driver exception is never stored here:
    they routinely contain the offending row (leak path 10).
    """

    __tablename__ = "training_runs"

    run_id: Mapped[str] = mapped_column(Text, primary_key=True)
    task_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    source_id: Mapped[str] = mapped_column(Text, nullable=False)
    feature_set_id: Mapped[str] = mapped_column(Text, nullable=False)
    feature_set_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    primary_metric: Mapped[str] = mapped_column(Text, nullable=False)
    labels_as_of: Mapped[_dt.datetime] = mapped_column(
        UtcInstant,
        nullable=False,
        comment="The instant labels were read at. Stored because a run that cannot say "
        "this cannot be shown to be free of leakage.",
    )
    semi_supervised: Mapped[bool] = mapped_column(Boolean, nullable=False)
    code_version: Mapped[str] = mapped_column(Text, nullable=False)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    finished_at: Mapped[_dt.datetime | None] = mapped_column(UtcInstant, nullable=True)
    cost_spent: Mapped[Any] = mapped_column(Json, nullable=False)


class MemorisationAuditRow(Base):
    """The verdict on one artifact's bytes.

    An audit is recorded against a digest. Changing the bytes invalidates it, which is
    why ``artifact_digest`` is part of the unique key and why
    :mod:`godwit_store.registry` refuses to mark an artifact deployable when the digests
    disagree.
    """

    __tablename__ = "memorisation_audits"

    audit_id: Mapped[str] = mapped_column(Text, primary_key=True)
    artifact_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    artifact_digest: Mapped[str] = mapped_column(Text, nullable=False)
    audit_digest: Mapped[str] = mapped_column(Text, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    auditor_version: Mapped[int] = mapped_column(Integer, nullable=False)
    small_cell_threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    checks: Mapped[Any] = mapped_column(
        Json,
        nullable=False,
        comment="Kind, threshold, observed and verdict per check. The detail field must "
        "not quote the offending value -- that is the thing being stopped.",
    )
    performed_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        UniqueConstraint("artifact_id", "artifact_digest", name="uq_audit_binds_bytes"),
    )


class ModelArtifactRow(Base, TaintedPayload):
    """Artifact metadata. The bytes stay in object storage inside the perimeter.

    ``deployable`` cannot be true unless ``audit_passed`` is true -- a CHECK constraint,
    not an application rule -- and ``deployments`` references ``(artifact_id,
    deployable)``, so an artifact with a failed audit has nothing a deployment could
    point at. Invariant 3, enforced by the database.

    The payload is the ``ModelCard``: its free text and its feature names are exactly
    where a helpful engineer pastes an example row.
    """

    __tablename__ = "model_artifacts"

    artifact_id: Mapped[str] = mapped_column(Text, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    digest: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    format: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    feature_set_id: Mapped[str] = mapped_column(Text, nullable=False)
    training_run_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    audit_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("memorisation_audits.audit_id"), nullable=True
    )
    audit_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deployable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    certificate: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "NOT deployable OR audit_passed",
            name="deployable_requires_a_passing_audit",
        ),
        CheckConstraint(
            "NOT deployable OR audit_id IS NOT NULL",
            name="deployable_requires_an_audit_row",
        ),
        UniqueConstraint("artifact_id", "deployable", name="uq_artifact_deployability"),
    )


class EvaluationReportRow(Base):
    """How a model did, and against which baseline.

    ``baseline_note`` is stored and is not decoration. "Parity with a good data
    scientist working for a week" and "parity with a mature in-house system" are
    different claims, and only one of them is ours.
    """

    __tablename__ = "evaluation_reports"

    report_id: Mapped[str] = mapped_column(Text, primary_key=True)
    artifact_id: Mapped[str] = mapped_column(
        Text, ForeignKey("model_artifacts.artifact_id"), nullable=False, index=True
    )
    primary_metric: Mapped[str] = mapped_column(Text, nullable=False)
    primary_value: Mapped[float] = mapped_column(Float, nullable=False)
    baseline_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    baseline_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    calibration_error: Mapped[float | None] = mapped_column(Float, nullable=True)
    metrics: Mapped[Any] = mapped_column(Json, nullable=False)
    slices_value: Mapped[Any] = mapped_column(
        Json,
        nullable=False,
        comment="Slice metrics. TAINTED: a slice is a segment and a segment quotes "
        "real values. Below the small-cell threshold a slice is omitted, not widened.",
    )
    slices_sensitivity: Mapped[str] = mapped_column(Text, nullable=False)
    population: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evaluated_as_of: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)


class DeploymentRow(Base):
    """A model in an environment, at a traffic share. Append-only by discipline.

    A rollback is a new row pointing at an older artifact, never a mutation of the old
    row. ``artifact_deployable`` is constrained true and is half of the foreign key
    into ``model_artifacts``, so the database itself refuses to deploy an unaudited
    artifact.
    """

    __tablename__ = "deployments"

    deployment_id: Mapped[str] = mapped_column(Text, primary_key=True)
    artifact_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    artifact_deployable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    artifact_digest: Mapped[str] = mapped_column(Text, nullable=False)
    audit_id: Mapped[str] = mapped_column(Text, nullable=False)
    certificate: Mapped[str] = mapped_column(Text, nullable=False)
    environment: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    mode: Mapped[str] = mapped_column(Text, nullable=False)
    traffic_fraction: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    superseded_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_of: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["artifact_id", "artifact_deployable"],
            ["model_artifacts.artifact_id", "model_artifacts.deployable"],
            name="fk_deployments_artifact_is_deployable",
        ),
        CheckConstraint("artifact_deployable", name="only_deployable_models_deploy"),
        CheckConstraint(
            "mode <> 'shadow' OR traffic_fraction = 0.0", name="shadow_takes_no_traffic"
        ),
        Index("ix_deployments_env_created", "environment", "created_at"),
    )


# --------------------------------------------------------------------------------------
# Governance
# --------------------------------------------------------------------------------------


class GuardrailRow(Base):
    """A named, versioned rule. Never edited in place.

    A change produces a new version, so that an egress record written last year still
    names the exact rule that allowed it.
    """

    __tablename__ = "guardrails"

    guardrail_id: Mapped[str] = mapped_column(Text, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[Any] = mapped_column(Json, nullable=False)
    predicate: Mapped[Any] = mapped_column(Json, nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)


class RedactionPolicyRow(Base):
    """The per-class, per-column rules the gate applies, plus the small-cell floors.

    ``default_action`` cannot be ``allow``: an unmatched value is an unclassified
    value, and an unclassified value is not a safe one. Constrained here as well as in
    the contract, because this table outlives any particular process.
    """

    __tablename__ = "redaction_policies"

    policy_id: Mapped[str] = mapped_column(Text, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    default_action: Mapped[str] = mapped_column(Text, nullable=False)
    min_cell_size: Mapped[int] = mapped_column(Integer, nullable=False)
    quantile_min_population: Mapped[int] = mapped_column(Integer, nullable=False)
    rules: Mapped[Any] = mapped_column(Json, nullable=False)
    created_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        CheckConstraint("default_action <> 'allow'", name="deny_by_default"),
        CheckConstraint("min_cell_size > 0", name="small_cell_floor_is_positive"),
    )


class ApprovalRequestRow(Base):
    """A human decision a guardrail asked for, and what they decided."""

    __tablename__ = "approval_requests"

    request_id: Mapped[str] = mapped_column(Text, primary_key=True)
    subject_kind: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(Text, nullable=False)
    requested_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    decided_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[_dt.datetime | None] = mapped_column(UtcInstant, nullable=True)
    expires_at: Mapped[_dt.datetime | None] = mapped_column(UtcInstant, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status NOT IN ('approved', 'denied') OR "
            "(decided_by IS NOT NULL AND decided_at IS NOT NULL)",
            name="a_decided_request_names_who_decided",
        ),
        Index("ix_approvals_subject", "subject_kind", "subject_id"),
    )


class CostLedgerRow(Base):
    """What each unit of work actually spent, and whether it refused.

    A refusal is a normal outcome (invariant 6) and is recorded as one, with the field
    that would have overrun. "Dollars per human-confirmed pattern" is the objective
    function's second number and this table is where it comes from.
    """

    __tablename__ = "cost_ledger"

    entry_id: Mapped[str] = mapped_column(Text, primary_key=True)
    subject_kind: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    refused: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    refused_field: Mapped[str | None] = mapped_column(Text, nullable=True)
    bytes_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    wall_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    usd: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="0",
        comment="Decimal rendered as text. Money through a float is a rounding bug "
        "waiting for an auditor.",
    )
    llm_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    train_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    occurred_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)

    __table_args__ = (
        Index("ix_cost_subject", "subject_kind", "subject_id"),
        Index("ix_cost_time", "occurred_at"),
        CheckConstraint("NOT refused OR refused_field IS NOT NULL", name="refusal_names_a_field"),
    )


# --------------------------------------------------------------------------------------
# The append-only ledgers
# --------------------------------------------------------------------------------------


class AuditEventRow(Base, HashChain):
    """Every state change: who, when, from what, to what, under which guardrail.

    Append-only, hash-chained, and enforced by grants rather than by convention -- see
    :mod:`godwit_store.appendonly`. ``detail_digest`` rather than ``detail``: the audit
    log says what happened, not what the data was. An audit log full of PII is a second
    breach with better indexing.
    """

    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    occurred_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    subject_kind: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[str] = mapped_column(Text, nullable=False)
    plane: Mapped[str] = mapped_column(Text, nullable=False)
    from_state: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_state: Mapped[str | None] = mapped_column(Text, nullable=True)
    guardrail_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    guardrail_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail_digest: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)

    __table_args__ = (
        UniqueConstraint("seq", name="uq_audit_sequence"),
        Index("ix_audit_subject", "subject_kind", "subject_id", "occurred_at"),
        Index("ix_audit_time", "occurred_at"),
    )


class EgressRecordRow(Base, HashChain):
    """Every payload that left the perimeter.

    A bank will ask "show me everything you ever sent to a model provider". The answer
    is :func:`godwit_store.ledger.egress_query`, and it has to be answerable in front of
    them, in one query, with no caveats.

    **No column here can hold a value.** Destination, purpose, policy version, guardrail
    ids, the digest of the exact bytes, the token map reference, the field *names* and
    the caller. Not the content. Every column is a plain type precisely so that there
    is no field a tainted value could sit in.
    """

    __tablename__ = "egress_records"

    record_id: Mapped[str] = mapped_column(Text, primary_key=True)
    occurred_at: Mapped[_dt.datetime] = mapped_column(UtcInstant, nullable=False)
    destination: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    policy_id: Mapped[str] = mapped_column(Text, nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    guardrail_ids: Mapped[Any] = mapped_column(Json, nullable=False)
    content_digest: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    field_names: Mapped[Any] = mapped_column(
        Json,
        nullable=False,
        comment="The KEYS that left, not the values. A key can itself be a disclosure, "
        "so the gate must have cleared these too.",
    )
    source_ids: Mapped[Any] = mapped_column(Json, nullable=False)
    sensitivity_before: Mapped[str] = mapped_column(Text, nullable=False)
    sensitivity_after: Mapped[str] = mapped_column(Text, nullable=False)
    actions_applied: Mapped[Any] = mapped_column(Json, nullable=False)
    min_population: Mapped[int | None] = mapped_column(Integer, nullable=True)
    approval_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_map_ref: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Reference to the tokenisation map entry in the data plane. A "
        "reference, never a map: the map does not cross the boundary.",
    )

    __table_args__ = (
        UniqueConstraint("seq", name="uq_egress_sequence"),
        Index("ix_egress_destination_time", "destination", "occurred_at"),
        Index("ix_egress_actor_time", "actor", "occurred_at"),
    )


# --------------------------------------------------------------------------------------
# Safe views -- the whole point of the storage convention
# --------------------------------------------------------------------------------------

SAFE_VIEWS: Final[tuple[tuple[str, str], ...]] = (
    (
        "patterns_safe",
        """
        SELECT pattern_id, signature, structure_key, source_id, segment_key, family,
               direction, lifecycle, first_seen, last_seen, last_snapshot_id,
               windows_without_support, score, q_value, population, candidate_count,
               validation_status, explained_away, confirmations, rejections,
               representative_candidate_id, reproduction_key, dedup_group
        FROM patterns
        """,
    ),
    (
        "candidates_safe",
        """
        SELECT candidate_id, run_id, source_id, snapshot_id, baseline_snapshot_id,
               segment_key, signature, structure_key, family, direction, score,
               p_value, q_value, fdr_rejected, validation_status, population,
               detector, detector_version, code_version, seed, probe_key,
               created_at, ingested_at
        FROM candidates
        """,
    ),
    (
        "column_profiles_safe",
        """
        SELECT profile_id, source_id, snapshot_id, logical_type, role, pii_class,
               access_mode, null_fraction, distinct_estimate, row_count, observed_at,
               profile_version
        FROM column_profiles
        """,
    ),
    (
        "labels_safe",
        """
        SELECT label_id, entity_type, coverage_id, event_time, label_time, source,
               confidence, recorded_at
        FROM labels
        """,
    ),
)
"""Views that expose every safe column of a table and none of its tainted ones.

``column_profiles_safe`` additionally drops ``column_key``, because a customer column
name is a disclosure on its own (leak path 9) and a profile view is exactly the thing
somebody points a dashboard at.

These are created by ``metadata.create_all`` and by the Alembic migration, so the two
paths produce the same database.
"""


def view_ddl(name: str, body: str) -> str:
    """The ``CREATE VIEW`` statement for one safe view, whitespace-normalised.

    Shared by ``create_all`` and by the Alembic migration, so the two cannot drift.
    """
    return f"CREATE VIEW {name} AS {' '.join(body.split())}"


def _create_safe_views(_target: object, connection: Connection, **_kw: object) -> None:
    for name, body in SAFE_VIEWS:
        connection.exec_driver_sql(view_ddl(name, body))


def _drop_safe_views(_target: object, connection: Connection, **_kw: object) -> None:
    for name, _body in SAFE_VIEWS:
        connection.exec_driver_sql(f"DROP VIEW IF EXISTS {name}")


event.listen(Base.metadata, "after_create", _create_safe_views)
event.listen(Base.metadata, "before_drop", _drop_safe_views)
