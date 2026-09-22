"""The twelve extension points, and the laws each one must obey.

A protocol here is a promise about behaviour, not just a shape. The laws are written
out because nineteen agents are implementing against them without being able to ask a
question, and because "obvious" behaviour is not obvious to two people at once.

Where a law is a mathematical claim -- associativity, commutativity, idempotence -- the
implementing package owes a property test (hypothesis), not an example test.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, Self, runtime_checkable

from pydantic import Field

from godwit_contracts.common import (
    ArtifactId,
    GodwitModel,
    Instant,
    NonNegInt,
    PatternId,
    SnapshotId,
    Version,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.discovery import (
    Candidate,
    Feedback,
    LabelSet,
    Pattern,
)
from godwit_contracts.features import FeatureSet
from godwit_contracts.governance import (
    Destination,
    EgressRecord,
    Guardrail,
    RedactionPolicy,
)
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.safe import SafePayload
from godwit_contracts.segment import Segment
from godwit_contracts.serving import Deployment, Prediction
from godwit_contracts.sketch import ErrorBound, SketchBundle, SketchEnvelope, SketchKind
from godwit_contracts.source import ColumnProfile, SnapshotRef, SourceRef, TableProfile
from godwit_contracts.taint import Tainted
from godwit_contracts.training import (
    DeployableModel,
    EvaluationReport,
    MemorisationAudit,
    ModelArtifact,
    TrainingRun,
    TrainingTask,
)

__all__ = [
    "Detector",
    "EgressGate",
    "Evaluator",
    "FeatureComputer",
    "FeatureMatrixRef",
    "LLMAdapter",
    "LLMResponse",
    "ModelRegistry",
    "PatternStore",
    "Predictor",
    "Redactor",
    "Sketch",
    "SourceAdapter",
    "Trainer",
]


class FeatureMatrixRef(GodwitModel):
    """A handle to computed features that stayed inside the perimeter.

    Feature values are row-derived, so they are never returned across the boundary.
    ``FeatureComputer`` returns this instead: a location the data plane can read and the
    control plane can only talk about.
    """

    matrix_id: str
    storage_uri: str = Field(
        description="Where the materialised features live, inside the perimeter. A "
        "control-plane reader may hold this string; it cannot read what is behind it."
    )
    feature_set_id: str
    feature_set_version: Version
    snapshot_id: SnapshotId
    computed_as_of: Instant
    row_count: NonNegInt
    entity_count: NonNegInt
    digest: str = Field(
        description="Hash of the materialised content, so a training run can prove "
        "which matrix it read."
    )


class LLMResponse(GodwitModel):
    """What an LLM gave back.

    ``text`` is plain ``str`` and not ``Tainted`` because it is the model's own words
    about a ``SafePayload``. It becomes tainted the moment it is attached to an
    ``Explanation``, which types it as ``Tainted[str]`` -- the LLM can echo tokens it
    was shown, and a token is still a pseudonym.
    """

    text: str
    model_name: str
    prompt_digest: str
    payload_digest: str
    tokens_spent: NonNegInt
    finish_reason: str


@runtime_checkable
class SourceAdapter(Protocol):
    """Reads a customer system. Data plane.

    LAWS
    ----
    1. Metadata first (invariant 5). ``profile_table`` must obtain everything the
       catalog can give before any method that scans is called.
    2. No rows out. Every return value is a profile, a reference or a sketch bundle.
       There is no method that returns rows, and adding one is a contract change.
    3. Bounds and most-common-values come back ``Tainted`` DATA_VALUE. They are row
       values, whatever the catalog calls them.
    4. ``execute_probe`` is deterministic given (spec, snapshot, seed) and must refuse
       rather than exceed ``spec.budget``.
    5. Driver exceptions are never propagated verbatim. They contain rows. Catch,
       classify, and raise your own message.
    """

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        """The snapshot current at ``at``, or the latest when ``at`` is None."""
        ...

    def profile_table(
        self, source: SourceRef, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> TableProfile:
        """Catalog-derived profile. Cheap. Must not scan unless the budget allows it."""
        ...

    def execute_probe(
        self, spec: ProbeSpec, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> SketchBundle:
        """Run one measurement and return sketches. Never rows."""
        ...


@runtime_checkable
class Sketch(Protocol):
    """A mergeable summary. Invariant 6.

    LAWS
    ----
    1. ``merge`` is associative: ``a.merge(b).merge(c) == a.merge(b.merge(c))``.
    2. ``merge`` is commutative: ``a.merge(b) == b.merge(a)``.
    3. ``identity()`` is a two-sided identity: ``a.merge(identity()) == a``.
    4. ``merge`` is total over sketches with equal ``params``, and MUST raise over
       sketches with different ones. Merging two KLL sketches with different k silently
       is a wrong answer, which is worse than an error.
    5. ``decode(x.serialise()) == x``, for every x.
    6. ``error_bound()`` is honest and does not depend on the data: it is a property of
       the construction parameters and the item count.
    7. Merging is monotone in ``population``: the merged sketch's population is the sum.

    Laws 1 through 3 make batch and streaming able to run identical code. Property-test
    all of them; example tests will not find the associativity bug.
    """

    @property
    def kind(self) -> SketchKind:
        """Which sketch family this is."""
        ...

    @property
    def population(self) -> int:
        """Items fed in so far."""
        ...

    def merge(self, other: Self) -> Self:
        """Combine two sketches. Associative, commutative, identity-respecting."""
        ...

    def error_bound(self) -> ErrorBound:
        """The documented accuracy of this sketch at its current size."""
        ...

    def serialise(self) -> SketchEnvelope:
        """Encode to a storable envelope, tagged with the correct sensitivity."""
        ...

    @classmethod
    def identity(cls, params: Mapping[str, int | float | str | bool]) -> Self:
        """The empty sketch for these parameters. The monoid's identity element."""
        ...

    @classmethod
    def decode(cls, envelope: SketchEnvelope) -> Self:
        """Rebuild from an envelope. Must read every codec version ever written."""
        ...


@runtime_checkable
class Detector(Protocol):
    """Turns sketches into candidates. Control plane, no data access. L2.

    LAWS
    ----
    1. Pure. Same (current, baseline, profiles, seed) gives the same candidates, in the
       same order. No clock, no unseeded randomness, no network.
    2. No LLM (invariant 7). A detector that calls an LLM cannot be replayed with the
       LLM layer deleted, which is the whole point of the layer being optional.
    3. Every candidate it emits carries a complete ``Lineage``.
    4. Statistics it emits are ``DERIVED_STATISTIC``; anything it copies out of a
       profile keeps that profile's taint.
    5. It reports raw p-values. FDR control belongs to L5, which can see all the
       hypotheses; a detector cannot.
    """

    @property
    def name(self) -> str:
        """Stable detector name, used in lineage."""
        ...

    @property
    def version(self) -> Version:
        """Bumped whenever output could change for identical input."""
        ...

    def detect(
        self,
        *,
        current: SketchBundle,
        baseline: SketchBundle | None,
        profiles: Sequence[ColumnProfile],
        seed: int,
    ) -> tuple[Candidate, ...]:
        """Score one bundle against its baseline."""
        ...


@runtime_checkable
class PatternStore(Protocol):
    """Persistence, dedup, FDR control and lifecycle for patterns. L5.

    LAWS
    ----
    1. Idempotent ingest: ingesting the same candidate twice yields one pattern and one
       membership. Candidates carry a deterministic id; use it.
    2. Dedup is by ``segment.key`` plus detector family, never by rendered text.
    3. FDR control is applied over the whole hypothesis space of a snapshot, not per
       detector. Reporting a raw p-value as significance, when thousands of hypotheses
       were tested, is a lie by omission.
    4. Lifecycle transitions are append-only and auditable. A pattern never silently
       changes state.
    5. Reads that cross to a UI or an alert must go through the gate first. The store
       holds tainted values; it is not itself an egress boundary.
    """

    def ingest(self, candidates: Sequence[Candidate]) -> tuple[PatternId, ...]:
        """Deduplicate, group and persist. Returns the patterns touched."""
        ...

    def get(self, pattern_id: PatternId) -> Pattern | None:
        """One pattern, or None."""
        ...

    def list_open(self, *, snapshot_id: SnapshotId, limit: int) -> tuple[Pattern, ...]:
        """Open patterns for a snapshot, ranked. Deterministic ordering."""
        ...

    def record_feedback(self, feedback: Feedback) -> Pattern:
        """Apply a human verdict and return the updated pattern."""
        ...


@runtime_checkable
class Redactor(Protocol):
    """Applies a redaction policy to one tainted value. Part of the gate.

    LAWS
    ----
    1. Total: every input either comes back redacted or comes back ``None``
       (suppressed). It never raises to mean "not allowed".
    2. Monotone: the result is never more disclosive than the input.
    3. Deterministic: same value, same policy, same result -- so that a token is stable
       across calls and two alerts about the same entity can be joined by a human.
    4. Tokenisation is one-way outside the data plane. The map never crosses.
    5. Small cells are suppressed before any other rule is considered.
    """

    def redact(
        self,
        value: Tainted[Any],
        *,
        policy: RedactionPolicy,
        destination: Destination,
    ) -> Tainted[Any] | None:
        """Redact one value, or return None to suppress it entirely."""
        ...


@runtime_checkable
class EgressGate(Protocol):
    """The single boundary. Invariant 2 lives or dies here.

    LAWS
    ----
    1. An ``EgressRecord`` is written BEFORE the ``SafePayload`` is returned. If the
       record cannot be written, nothing leaves.
    2. No record, no payload: there is no path that produces a payload without one.
    3. Deny by default. An unmatched value, an unknown PII class and an unknown
       population are all denied, not allowed.
    4. The record never contains a value. It contains names, hashes, counts and
       decisions.
    5. Guardrails are evaluated in a defined order and the most restrictive action
       wins: DENY beats REQUIRE_APPROVAL beats REDACT beats ALLOW.
    6. Presidio and any other scanner is a BACKSTOP. If a scanner is the only thing
       that stopped a value, that is a bug in the taint typing, and it must be
       reported as one.
    """

    def clear(
        self,
        *,
        fields: Mapping[str, Tainted[Any]],
        destination: Destination,
        purpose: str,
        policy: RedactionPolicy,
        guardrails: Sequence[Guardrail],
        actor: str,
        occurred_at: Instant,
    ) -> tuple[SafePayload, EgressRecord]:
        """Clear a set of tainted fields for one destination.

        Raises ``EgressDeniedError`` when a guardrail denies, and
        ``ApprovalRequiredError`` semantics are expressed by the guard package raising
        its own error carrying an ``ApprovalRequest``.
        """
        ...


@runtime_checkable
class LLMAdapter(Protocol):
    """The only thing that talks to a model provider. L9.

    LAWS
    ----
    1. ``SafePayload`` is the only accepted input type. There is no ``str`` overload,
       no ``**kwargs`` passthrough and no "debug" parameter that takes raw text.
    2. Never in a detection or prediction path (invariant 7). Delete this package and
       every pattern and prediction must still reproduce, bit for bit.
    3. Cost scales with the number of hypotheses, not the volume of data (invariant 4).
       An adapter that loops over rows is a bug, not an optimisation opportunity.
    4. Budgeted: refuse rather than exceed ``budget.llm_tokens``.
    5. Deterministic where the provider allows it: temperature and seed are explicit.
    6. No vendor SDK escapes this package.
    """

    def complete(
        self,
        *,
        payload: SafePayload,
        template_id: str,
        budget: CostBudget,
        seed: int,
        max_tokens: int,
    ) -> LLMResponse:
        """One call, one payload, one budgeted response."""
        ...


@runtime_checkable
class FeatureComputer(Protocol):
    """Computes features in the data plane. L6.

    LAWS
    ----
    1. Point-in-time correct: for each entity, only rows permitted by the spec's
       ``PointInTimeRule`` relative to that entity's event time are read. Not the
       batch's time. Each entity's own.
    2. Deterministic: same feature set, same snapshot, same ``as_of``, same values.
    3. Values never cross the boundary. Returns a ``FeatureMatrixRef``, not a frame.
    4. Refuses rather than exceeds its budget.
    5. A feature derived from a pattern records ``derived_from_pattern``, so the
       discovery-to-prediction loop is visible in lineage rather than implied.
    """

    def compute(
        self,
        *,
        feature_set: FeatureSet,
        snapshot: SnapshotRef,
        entities: Segment,
        as_of: Instant,
        budget: CostBudget,
    ) -> FeatureMatrixRef:
        """Materialise features for a population, inside the perimeter."""
        ...


@runtime_checkable
class Trainer(Protocol):
    """Trains a model. Data plane. L7.

    LAWS
    ----
    1. Labels are read at ``task.labels_as_of`` and nowhere else. Calling
       ``LabelSet.visible_as_of`` with anything other than that instant is a bug.
    2. Unlabelled is not negative unless ``LabelSet.coverage_at`` says the window was
       exhaustive.
    3. Deterministic given (task, seed, feature matrix). Set every library seed you
       depend on, including the ones you forgot.
    4. Refusing on budget returns a ``TrainingRun`` with ``REFUSED_BUDGET``. It does not
       raise, because refusal is a normal outcome (invariant 6).
    5. The artifact it produces is not deployable. It must be audited first, and the
       trainer must not attempt to certify its own output.
    """

    def train(
        self,
        *,
        task: TrainingTask,
        features: FeatureMatrixRef,
        labels: LabelSet,
        budget: CostBudget,
    ) -> TrainingRun:
        """Run one training task to completion, failure or refusal."""
        ...


@runtime_checkable
class Evaluator(Protocol):
    """Measures a model. Data plane. L7.

    LAWS
    ----
    1. Evaluates on a split the model never saw, with the embargo from the split spec
       honoured.
    2. Reports a baseline alongside the model, and says in ``baseline_note`` what that
       baseline actually is. "Parity with a good data scientist working for a week" and
       "parity with a mature in-house system" are different claims and only one of them
       is ours.
    3. Slice metrics respect small-cell suppression: a slice below the threshold is
       omitted, not reported with a wide error bar.
    4. Calibration is measured, not assumed.
    """

    def evaluate(
        self,
        *,
        artifact: ModelArtifact,
        features: FeatureMatrixRef,
        labels: LabelSet,
        as_of: Instant,
        budget: CostBudget,
    ) -> EvaluationReport:
        """Produce the report that decides whether this model ships."""
        ...


@runtime_checkable
class ModelRegistry(Protocol):
    """Stores artifacts and gates their release. L8.

    LAWS
    ----
    1. Content-addressed: an artifact is identified by its digest. Re-registering the
       same bytes returns the same artifact.
    2. ``audit`` is recorded against a digest. Changing the bytes invalidates the audit.
    3. ``certify`` is the only route to a ``DeployableModel`` and has no override.
    4. Artifact egress -- to a customer's own store, to an export -- goes through the
       gate, which is why the registry is ours and not a third-party one.
    5. Deployments are append-only. A rollback is a new deployment pointing at an older
       model, never a mutation of the old record.
    """

    def register(self, artifact: ModelArtifact) -> ArtifactId:
        """Store an artifact. Idempotent on digest."""
        ...

    def attach_audit(self, audit: MemorisationAudit) -> ModelArtifact:
        """Record an audit against an artifact and return the updated record."""
        ...

    def certify(self, artifact_id: ArtifactId) -> DeployableModel:
        """Produce a deployable, or raise ``MemorisationAuditFailedError``."""
        ...

    def deploy(self, deployment: Deployment) -> Deployment:
        """Record a deployment. Append-only."""
        ...


@runtime_checkable
class Predictor(Protocol):
    """Scores entities with a deployed model. Data plane. L8.

    LAWS
    ----
    1. Features are computed at ``as_of`` with the same point-in-time rules used in
       training. Training and serving that disagree is the classic silent failure.
    2. Deterministic: same deployment, same entities, same ``as_of``, same scores.
    3. Shadow mode scores and records but never acts. ``traffic_fraction`` is 0.0.
    4. Predictions are tainted: an entity id is a row value and an attribution can echo
       one. Showing a prediction to a human is an egress.
    5. Refuses rather than exceeds its budget, and reports what it spent.
    """

    def predict(
        self,
        *,
        deployment: Deployment,
        entities: Segment,
        as_of: Instant,
        budget: CostBudget,
    ) -> tuple[tuple[Prediction, ...], CostSpend]:
        """Score a population and report the cost of doing so."""
        ...
