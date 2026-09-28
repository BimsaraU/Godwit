"""Failing tests for the two contract gaps A4 filed change requests about.

Universal rule 2: do not fix the contract. Implement against it as written, and leave a test
showing what was needed. Each test here is the smallest thing that would pass if the
corresponding change request were accepted, and each one names it.

An ``xfail`` that starts passing is the signal that a contract moved, which is why these use
``strict=True``: a silent pass would lose the record.
"""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal

import pytest
from godwit_contracts.common import ArtifactId, ProbeId, SourceId
from godwit_contracts.cost import CostBudget
from godwit_contracts.probe import ProbeKind, ProbeSpec
from godwit_contracts.source import SourceKind, SourceRef
from godwit_contracts.taint import schema_name
from godwit_replay.metrics import roc_auc
from godwit_replay.prediction import ScoringOptions, score_predictions, to_evaluation_report

SEED = 4
AS_OF = _dt.datetime(2024, 6, 1, tzinfo=_dt.UTC)

BUDGET = CostBudget(
    bytes_scanned=1024,
    wall_seconds=1.0,
    usd=Decimal("0"),
    llm_tokens=0,
    train_seconds=0.0,
)


def _score() -> object:
    labels = [0] * 60 + [1] * 40
    scores = [float(index) / 100.0 for index in range(100)]
    assert 0.0 <= roc_auc(labels, scores) <= 1.0
    return score_predictions(
        dataset="golden-classification",
        model_label="gap-test",
        labels=labels,
        scores=scores,
        probabilities=scores,
        seed=SEED,
        options=ScoringOptions(k_values=(10,), resamples=50),
    )


@pytest.mark.xfail(
    reason="CR-A4-evaluation-report-has-no-intervals", strict=True, raises=AttributeError
)
def test_evaluation_report_carries_an_interval() -> None:
    """What I needed: an interval on the report, typed as one.

    On a 1,200-row held-out half the bootstrap interval for AUC is about as wide as the 0.02
    objective it is being compared against, so a point estimate alone cannot answer the
    question the objective asks. Today the bounds travel as ``auc_ci_low`` and ``auc_ci_high``
    string keys beside the point estimate, which works and carries no type information: a
    deployment gate reading ``metrics["auc"]`` cannot tell that an interval exists.
    """
    score = _score()
    report = to_evaluation_report(
        score,  # type: ignore[arg-type]
        artifact_id=ArtifactId("art_gap"),
        report_id="rep_gap",
        as_of=AS_OF,
    )
    # The workaround, which does work, and which this test is not about:
    assert "auc_ci_low" in report.metrics
    assert "auc_ci_high" in report.metrics
    # What the change request asks for:
    intervals = report.intervals  # type: ignore[attr-defined]
    assert intervals["auc"].low <= report.metrics["auc"] <= intervals["auc"].high


@pytest.mark.xfail(
    reason="CR-A4-probe-snapshot-resolution-is-unrecorded", strict=True, raises=ValueError
)
def test_a_refused_probe_records_the_snapshot_it_resolved() -> None:
    """What I needed: a resolution recorded before the work is attempted.

    A probe scheduled with ``snapshot=None`` records which snapshot it resolved in the
    returned ``SketchBundle``. A probe *refused on budget* returns no bundle, and invariant 6
    makes refusal an ordinary outcome rather than an error -- so every probe a bandit declines
    to pay for leaves no record of what it would have measured. Replay cannot reconstruct the
    decision sequence from that.
    """
    source_id = SourceId("src_gap")
    spec = ProbeSpec(
        probe_id=ProbeId("prb_gap"),
        kind=ProbeKind.ROW_COUNT,
        spec_version=1,
        source=SourceRef(
            source_id=source_id,
            kind=SourceKind.ICEBERG,
            catalog="godwit-replay",
            namespace=schema_name("godwit_replay", source_id=source_id),
            table=schema_name("orders", source_id=source_id),
        ),
        snapshot=None,
        budget=BUDGET,
        seed=SEED,
        as_of=AS_OF,
    )
    assert spec.snapshot is None, "the state a scheduled-but-unresolved probe is in today"
    # What the change request asks for: somewhere on the spec that says what it resolved to,
    # written before the budget decision rather than after the work.
    ProbeSpec.model_validate(
        {
            **spec.model_dump(),
            "resolution": {
                "probe_key": str(spec.key),
                "resolved_snapshot_id": "snap_2",
                "resolved_at": AS_OF.isoformat(),
                "resolver_version": 1,
            },
        }
    )
