"""Round-trip serialisation for every contract model, and the key stability tests.

Contract models are written to Postgres by A3, sent over HTTP by A16 and read back by
code written months later. A model that does not survive ``model_dump_json`` ->
``model_validate_json`` unchanged is a contract that silently loses a field.
"""

from __future__ import annotations

import datetime as _dt
import inspect
from collections.abc import Callable
from decimal import Decimal

import pytest
from godwit_contracts import (
    REQUIRED_MEMORISATION_CHECKS,
    Acquisition,
    Alert,
    AlertQueue,
    ApprovalRequest,
    ApprovalStatus,
    ArtifactFormat,
    AuditEvent,
    Candidate,
    ColumnProfile,
    ColumnRef,
    ColumnRole,
    CostBudget,
    CostSpend,
    CoverageScope,
    DatasourceConfig,
    DatasourceKind,
    Deployment,
    DeploymentMode,
    DeploymentStatus,
    Destination,
    EgressRecord,
    ErrorBound,
    EvaluationReport,
    Evidence,
    Explanation,
    FeatureAttribution,
    FeatureMatrixRef,
    FeatureSet,
    FeatureSpec,
    Feedback,
    FillPolicy,
    GodwitModel,
    Guardrail,
    GuardrailAction,
    GuardrailAttribute,
    GuardrailCondition,
    GuardrailPredicate,
    GuardrailScope,
    JoinEdge,
    Label,
    LabelSet,
    Lineage,
    LLMResponse,
    LogicalType,
    MemorisationAudit,
    MemorisationCheck,
    ModelArtifact,
    ModelCard,
    Objective,
    Operator,
    Pattern,
    PiiClass,
    Plane,
    PointInTimeRule,
    Predicate,
    Prediction,
    ProbeKind,
    ProbeSpec,
    RedactionAction,
    RedactionPolicy,
    RedactionRule,
    SecretProvider,
    SecretRef,
    Segment,
    Sensitivity,
    Severity,
    SketchBundle,
    SketchEnvelope,
    SketchKind,
    SliceMetric,
    SnapshotRef,
    SourceKind,
    SourceRef,
    SplitKind,
    SplitSpec,
    TableProfile,
    Tainted,
    TrainingRun,
    TrainingStatus,
    TrainingTask,
    Verdict,
    certify_deployable,
    content_hash,
    data_value,
    derived_statistic,
    schema_name,
)

NOW = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
BUDGET = CostBudget(
    bytes_scanned=1_000_000,
    wall_seconds=60.0,
    usd=Decimal("1.00"),
    llm_tokens=1000,
    train_seconds=120.0,
)


def predicate(column: str, value: object) -> Predicate:
    return Predicate(
        column=schema_name(column),
        op=Operator.EQ,
        values=(data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE, column=column),),
    )


PT = Segment(predicates=(predicate("country", "PT"),), population=361)
SOURCE = SourceRef(
    source_id="src_0001",
    kind=SourceKind.ICEBERG,
    catalog="godwit_rest",
    namespace=schema_name("retail"),
    table=schema_name("orders"),
)
SNAPSHOT = SnapshotRef(
    source_id="src_0001",
    snapshot_id="snap_2",
    sequence_number=2,
    committed_at=NOW,
)
PROBE = ProbeSpec(
    probe_id="prb_0001",
    kind=ProbeKind.HEAVY_HITTERS,
    spec_version=1,
    source=SOURCE,
    snapshot=SNAPSHOT,
    columns=(schema_name("country"),),
    segment=PT,
    sketches=(SketchKind.COUNT_MIN,),
    params={"width": 2718, "depth": 5},
    budget=BUDGET,
    seed=7,
    as_of=NOW,
)
ENVELOPE = SketchEnvelope(
    kind=SketchKind.COUNT_MIN,
    codec="godwit-cm-v1",
    schema_version=1,
    payload=b"\x00\x01\x02",
    payload_digest=content_hash(b"\x00\x01\x02"),
    sensitivity=Sensitivity.DATA_VALUE,
    provenance=data_value(
        1, acquisition=Acquisition.COUNT_MIN_HEAVY_HITTER, column="country"
    ).provenance,
    population=2000,
    error_bound=ErrorBound(kind="epsilon_delta", epsilon=0.001, delta=0.01),
    params={"width": 2718, "depth": 5},
    source_id="src_0001",
    snapshot_id="snap_2",
    produced_for=PROBE.key,
    produced_at=NOW,
)
EVIDENCE = Evidence(
    kind="rate_change",
    probe_key=PROBE.key,
    snapshot_id="snap_2",
    baseline_snapshot_id="snap_1",
    segment=PT,
    columns=(schema_name("country"),),
    statistic=derived_statistic(0.18, population=2000),
    baseline=derived_statistic(0.01, population=2000),
    population=361,
)
LINEAGE = Lineage(
    probe_key=PROBE.key,
    snapshot_id="snap_2",
    baseline_snapshot_id="snap_1",
    detector="category_share_shift",
    detector_version=1,
    code_version="test",
    seed=7,
)
CANDIDATE = Candidate(
    candidate_id="cand_0001",
    source_id="src_0001",
    segment=PT,
    evidence=(EVIDENCE,),
    score=0.9,
    lineage=LINEAGE,
    created_at=NOW,
)
POINT_IN_TIME = {
    "timestamp_column": schema_name("created_at"),
    "max_lookback": _dt.timedelta(days=30),
    "embargo": _dt.timedelta(hours=1),
    "label_lag_allowance": _dt.timedelta(days=60),
}
FEATURE = FeatureSpec(
    feature_id="f_0001",
    name=schema_name("orders_30d_count"),
    kind="time_window",
    spec_version=1,
    source_id="src_0001",
    entity_key=schema_name("customer_id"),
    inputs=(schema_name("order_id"),),
    expression="count(*)",
    dtype=LogicalType.INT,
    fill_policy=FillPolicy.ZERO,
    point_in_time=POINT_IN_TIME,  # type: ignore[arg-type]
)

MODELS: list[GodwitModel] = [
    BUDGET,
    CostSpend(bytes_scanned=10, usd=Decimal("0.01")),
    SOURCE,
    SNAPSHOT,
    PT,
    PROBE,
    ENVELOPE,
    SketchBundle(
        bundle_id="bun_0001",
        probe_key=PROBE.key,
        source_id="src_0001",
        snapshot_id="snap_2",
        sketches={"country_counts": ENVELOPE},
        cost_spent=CostSpend(bytes_scanned=1024),
        produced_at=NOW,
        worker_version="test",
        seed=7,
    ),
    EVIDENCE,
    LINEAGE,
    CANDIDATE,
    Pattern(
        pattern_id="pat_0001",
        source_id="src_0001",
        segment=PT,
        candidates=("cand_0001",),
        representative=CANDIDATE,
        first_seen=NOW,
        last_seen=NOW,
        q_value=0.001,
        name=data_value("PT share spike", acquisition=Acquisition.LLM_OUTPUT, column="country"),
    ),
    Explanation(
        pattern_id="pat_0001",
        text=Tainted[str](
            value="Orders from PT rose sharply.",
            sensitivity=Sensitivity.TOKEN,
            provenance=data_value("x", acquisition=Acquisition.LLM_OUTPUT).provenance.model_copy(
                update={"acquisition": Acquisition.LLM_OUTPUT}
            ),
        ),
        produced_by="llm",
        model_name="test-model",
        created_at=NOW,
    ),
    Feedback(
        pattern_id="pat_0001",
        verdict=Verdict.CONFIRMED,
        reviewer_id="rev_0001",
        decided_at=NOW,
    ),
    Alert(
        alert_id="alr_0001",
        pattern_id="pat_0001",
        queue=AlertQueue.OPERATIONAL,
        severity=Severity.HIGH,
        title=data_value(
            "PT share spike", acquisition=Acquisition.SEGMENT_PREDICATE, column="country"
        ),
        segment=PT,
        created_at=NOW,
    ),
    Label(
        entity_id=data_value("ent_1", acquisition=Acquisition.USER_SUPPLIED),
        value=data_value(True, acquisition=Acquisition.USER_SUPPLIED),
        event_time=NOW,
        label_time=NOW + _dt.timedelta(days=45),
        source="chargeback_feed",
    ),
    CoverageScope(
        entity_type="transaction",
        complete_from=NOW,
        complete_to=NOW + _dt.timedelta(days=90),
        is_exhaustive=True,
    ),
    FEATURE,
    FeatureSet(
        feature_set_id="fs_0001",
        version=1,
        entity_type="customer",
        specs=(FEATURE,),
        source_id="src_0001",
        as_of=NOW,
        created_at=NOW,
    ),
    Guardrail(
        guardrail_id="gr_0001",
        name="never send data values to an llm",
        version=1,
        scope=GuardrailScope(destinations=("llm_provider",)),
        predicate=GuardrailPredicate(
            all_of=(GuardrailCondition(attribute="sensitivity", op="eq", values=("data_value",)),)
        ),
        action=GuardrailAction.DENY,
        rationale="invariant 2",
        created_at=NOW,
    ),
]


@pytest.mark.parametrize("model", MODELS, ids=lambda model: type(model).__name__)
def test_json_round_trip(model: GodwitModel) -> None:
    """Dump to JSON, parse it back, and get the same object."""
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model


@pytest.mark.parametrize("model", MODELS, ids=lambda model: type(model).__name__)
def test_python_round_trip(model: GodwitModel) -> None:
    restored = type(model).model_validate(model.model_dump())
    assert restored == model


@pytest.mark.parametrize("model", MODELS, ids=lambda model: type(model).__name__)
def test_models_are_frozen_and_forbid_extras(model: GodwitModel) -> None:
    """Frozen: a contract that mutates is not a contract. extra=forbid: an undeclared
    field is a field nobody gated."""
    assert model.model_config.get("frozen") is True
    assert model.model_config.get("extra") == "forbid"

    payload = model.model_dump()
    payload["smuggled"] = "customer_ssn=100-40-1000"
    with pytest.raises(ValueError, match=r"[Ee]xtra"):
        type(model).model_validate(payload)


def test_label_set_round_trips_and_needs_an_explicit_instant() -> None:
    label = Label(
        entity_id=data_value("ent_1", acquisition=Acquisition.USER_SUPPLIED),
        value=data_value(True, acquisition=Acquisition.USER_SUPPLIED),
        event_time=NOW,
        label_time=NOW + _dt.timedelta(days=45),
        source="chargeback_feed",
    )
    label_set = LabelSet(
        coverage=CoverageScope(
            entity_type="transaction",
            complete_from=NOW,
            complete_to=NOW + _dt.timedelta(days=90),
            is_exhaustive=True,
        ),
        labels=(label,),
    )
    assert LabelSet.model_validate_json(label_set.model_dump_json()) == label_set

    signature = inspect.signature(LabelSet.visible_as_of)
    instant = signature.parameters["instant"]
    assert instant.kind is inspect.Parameter.KEYWORD_ONLY
    assert instant.default is inspect.Parameter.empty

    assert label_set.visible_as_of(instant=NOW) == ()
    assert label_set.visible_as_of(instant=NOW + _dt.timedelta(days=45)) == (label,)


def test_naive_datetimes_are_refused_everywhere() -> None:
    with pytest.raises(ValueError, match="naive datetime"):
        SnapshotRef(
            source_id="src_0001",
            snapshot_id="snap_2",
            sequence_number=2,
            committed_at=_dt.datetime(2024, 1, 1),
        )


def test_probe_key_is_stable_across_snapshots(
    make_predicate: Callable[..., Predicate],
) -> None:
    """A probe key identifies the measurement, not the run. Two snapshots, one key."""
    later = PROBE.model_copy(
        update={
            "probe_id": "prb_0002",
            "snapshot": SNAPSHOT.model_copy(update={"snapshot_id": "snap_9", "sequence_number": 9}),
            "as_of": NOW + _dt.timedelta(days=7),
            "budget": BUDGET.model_copy(update={"bytes_scanned": 5}),
        }
    )
    assert later.key == PROBE.key


def test_probe_key_changes_when_the_measurement_changes() -> None:
    assert PROBE.model_copy(update={"seed": 8}).key != PROBE.key
    assert PROBE.model_copy(update={"kind": ProbeKind.QUANTILES}).key != PROBE.key
    assert PROBE.model_copy(update={"params": {"width": 1}}).key != PROBE.key
    assert PROBE.model_copy(update={"segment": Segment()}).key != PROBE.key


def test_probe_key_ignores_column_case() -> None:
    assert PROBE.model_copy(update={"columns": (schema_name("COUNTRY"),)}).key == PROBE.key


def test_probe_key_has_the_documented_shape() -> None:
    prefix, _, digest = str(PROBE.key).partition("_")
    assert prefix == "prb"
    assert len(digest) == 32


# --------------------------------------------------------------------------------------
# Coverage: every contract model round-trips, not just the interesting ones.
#
# The list above holds the models worth reading as examples. The block below fills in the
# rest mechanically, and `test_every_contract_model_is_covered` fails if anyone adds a
# model and forgets both.
# --------------------------------------------------------------------------------------

COLUMN = ColumnRef(source_id="src_0001", table=schema_name("orders"), column=schema_name("country"))
AUDIT_CHECKS = tuple(
    MemorisationCheck(kind=kind, threshold=0.0, observed=0.0, passed=True)
    for kind in sorted(REQUIRED_MEMORISATION_CHECKS, key=lambda item: item.value)
)
ARTIFACT_DIGEST = content_hash("model-bytes")
AUDIT = MemorisationAudit(
    audit_id="aud_0001",
    artifact_id="art_0001",
    artifact_digest=ARTIFACT_DIGEST,
    checks=AUDIT_CHECKS,
    passed=True,
    performed_at=NOW,
    auditor_version=1,
    small_cell_threshold=20,
)
CARD = ModelCard(
    intended_use=schema_name("card fraud scoring"),
    limitations=schema_name("90 days of data, no consortium signal"),
    training_window="2023-10-01/2023-12-31",
)
ARTIFACT = ModelArtifact(
    artifact_id="art_0001",
    version=1,
    format=ArtifactFormat.ONNX,
    digest=ARTIFACT_DIGEST,
    size_bytes=4096,
    storage_uri="s3://godwit-artifacts/art_0001.onnx",
    feature_set_id="fs_0001",
    training_run_id="run_0001",
    created_at=NOW,
    audit=AUDIT,
    card=CARD,
)
DEPLOYABLE = certify_deployable(ARTIFACT)
SECRET = SecretRef(provider=SecretProvider.KMS_ENVELOPE, reference="alias/godwit-vision")
FEATURE_SET = FeatureSet(
    feature_set_id="fs_0001",
    version=1,
    entity_type="customer",
    specs=(FEATURE,),
    source_id="src_0001",
    as_of=NOW,
    created_at=NOW,
)
SPLIT = SplitSpec(
    kind=SplitKind.TIME_ORDERED,
    time_column=schema_name("created_at"),
    train_end=NOW,
    valid_end=NOW + _dt.timedelta(days=7),
    test_end=NOW + _dt.timedelta(days=14),
    embargo=_dt.timedelta(days=1),
    seed=7,
)

MODELS += [
    COLUMN,
    ColumnProfile(
        ref=COLUMN,
        logical_type=LogicalType.STRING,
        native_type="varchar",
        nullable=False,
        role=ColumnRole.CATEGORY,
        pii_class=PiiClass.QUASI_IDENTIFIER,
        null_fraction=derived_statistic(0.0, population=6000),
        distinct_estimate=derived_statistic(5, population=6000),
        min_bound=data_value(
            "DE", acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS, column="country"
        ),
        max_bound=data_value(
            "US", acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS, column="country"
        ),
        most_common_values=(
            data_value("US", acquisition=Acquisition.PG_STATS_MCV, column="country"),
        ),
        observed_at=NOW,
        profile_version=1,
    ),
    TableProfile(
        source=SOURCE,
        snapshot=SNAPSHOT,
        columns=(),
        row_count_estimate=derived_statistic(6000),
        observed_at=NOW,
        profile_version=1,
    ),
    JoinEdge(
        left=COLUMN,
        right=COLUMN,
        confidence=0.9,
        inferred_from="declared_fk",
        observed_at=NOW,
    ),
    predicate("country", "PT"),
    ErrorBound(kind="relative", epsilon=0.01, note="two percent, two sided"),
    PointInTimeRule(**POINT_IN_TIME),
    SPLIT,
    TrainingTask(
        task_id="task_0001",
        source_id="src_0001",
        feature_set=FEATURE_SET,
        objective=Objective.BINARY_CLASSIFICATION,
        primary_metric="auc",
        split=SPLIT,
        labels_as_of=NOW,
        semi_supervised=True,
        budget=BUDGET,
        seed=7,
    ),
    TrainingRun(
        run_id="run_0001",
        task_id="task_0001",
        status=TrainingStatus.REFUSED_BUDGET,
        started_at=NOW,
        finished_at=NOW,
        code_version="test",
        seed=7,
        failure_reason="train_seconds budget would be exceeded",
    ),
    AUDIT_CHECKS[0],
    AUDIT,
    CARD,
    ARTIFACT,
    DEPLOYABLE,
    SliceMetric(
        segment=PT,
        metric="auc",
        value=derived_statistic(0.91, population=361),
        population=361,
    ),
    EvaluationReport(
        report_id="rep_0001",
        artifact_id="art_0001",
        primary_metric="auc",
        metrics={"auc": 0.93},
        baseline_metrics={"auc": 0.90},
        baseline_note="a competent hand-built model, not a mature in-house system",
        calibration_error=0.01,
        evaluated_as_of=NOW,
        population=1200,
        positive_rate=0.03,
    ),
    FeatureAttribution(
        feature_id="f_0001",
        feature_name=schema_name("orders_30d_count"),
        contribution=derived_statistic(0.4),
    ),
    Prediction(
        prediction_id="prd_0001",
        artifact_id="art_0001",
        model_version=1,
        feature_set_version=1,
        entity_id=data_value("ent_1", acquisition=Acquisition.USER_SUPPLIED),
        score=derived_statistic(1.7),
        calibrated_probability=derived_statistic(0.84),
        computed_at=NOW,
        features_as_of=NOW,
    ),
    Deployment(
        deployment_id="dep_0001",
        model=DEPLOYABLE,
        environment="prod",
        mode=DeploymentMode.SHADOW,
        traffic_fraction=0.0,
        status=DeploymentStatus.ACTIVE,
        created_at=NOW,
    ),
    GuardrailScope(destinations=(Destination.LLM_PROVIDER,), min_population=20),
    GuardrailCondition(attribute=GuardrailAttribute.SENSITIVITY, op="eq", values=("token",)),
    GuardrailPredicate(
        all_of=(
            GuardrailCondition(attribute=GuardrailAttribute.DESTINATION, op="eq", values=("ui",)),
        )
    ),
    RedactionRule(pii_class=PiiClass.DIRECT_IDENTIFIER, action=RedactionAction.TOKENISE),
    RedactionPolicy(
        policy_id="pol_default",
        version=1,
        rules=(RedactionRule(pii_class=PiiClass.HEALTH, action=RedactionAction.SUPPRESS),),
        created_at=NOW,
    ),
    EgressRecord(
        record_id="egr_0001",
        occurred_at=NOW,
        destination=Destination.LLM_PROVIDER,
        purpose="explain_pattern",
        actor="godwit-llm",
        policy_id="pol_default",
        policy_version=1,
        guardrail_ids=("gr_0001",),
        content_digest=content_hash("payload"),
        field_names=("segment_size", "effect"),
        source_ids=("src_0001",),
        sensitivity_before=Sensitivity.DATA_VALUE,
        sensitivity_after=Sensitivity.TOKEN,
        actions_applied=(RedactionAction.TOKENISE,),
        min_population=361,
    ),
    ApprovalRequest(
        request_id="apr_0001",
        subject_kind="egress",
        subject_id="egr_0001",
        requested_by="godwit-llm",
        requested_at=NOW,
        reason="guardrail gr_0001 requires approval",
        status=ApprovalStatus.APPROVED,
        decided_by="rev_0001",
        decided_at=NOW,
    ),
    AuditEvent(
        event_id="evt_0001",
        occurred_at=NOW,
        actor="godwit-guard",
        action="egress.cleared",
        subject_kind="pattern",
        subject_id="pat_0001",
        plane=Plane.BOUNDARY,
        detail_digest=content_hash("detail"),
    ),
    SECRET,
    DatasourceConfig(
        datasource_id="ds_0001",
        name="local orchestrator",
        kind=DatasourceKind.ORCHESTRATOR,
        base_url="https://orchestrator.internal",
        auth=SECRET,
        default_budget=BUDGET,
        created_at=NOW,
    ),
    LabelSet(
        coverage=CoverageScope(
            entity_type="transaction",
            complete_from=NOW,
            complete_to=NOW + _dt.timedelta(days=90),
            is_exhaustive=True,
        )
    ),
    FeatureMatrixRef(
        matrix_id="mat_0001",
        storage_uri="s3://godwit-warehouse/features/mat_0001",
        feature_set_id="fs_0001",
        feature_set_version=1,
        snapshot_id="snap_2",
        computed_as_of=NOW,
        row_count=6000,
        entity_count=900,
        digest=content_hash("matrix"),
    ),
    LLMResponse(
        text="Orders from one country rose sharply.",
        model_name="test-model",
        prompt_digest=content_hash("prompt"),
        payload_digest=content_hash("payload"),
        tokens_spent=142,
        finish_reason="stop",
    ),
]


def test_every_contract_model_is_covered() -> None:
    """Every GodwitModel exported from the package must have a round-trip test.

    The acceptance criterion is round-trip serialisation *per model*. This is the guard
    that keeps it true when the next model is added.
    """
    import godwit_contracts

    exported = {
        getattr(godwit_contracts, name)
        for name in godwit_contracts.__all__
        if isinstance(getattr(godwit_contracts, name), type)
    }
    models = {
        item for item in exported if issubclass(item, GodwitModel) and item is not GodwitModel
    }
    missing = models - {type(model) for model in MODELS}
    assert not missing, "these contract models have no round-trip test: " + ", ".join(
        sorted(item.__name__ for item in missing)
    )
