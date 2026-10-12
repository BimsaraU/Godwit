"""Against the shared golden fixtures: the documented drift, its control, and the leak paths."""

from __future__ import annotations

import json
from typing import Any

import pyarrow.parquet as pq
import pytest
from _detect_scenarios import GOLDEN, golden_amount_panel, golden_country_series
from _detect_support import context, series, snapshot
from godwit_contracts.discovery import Candidate
from godwit_detect import (
    DetectionResult,
    Direction,
    FixedReference,
    HeavyHitterShift,
    JensenShannonDrift,
    PsiDrift,
    RefusalReason,
    SegmentDivergence,
    SegmentDivergenceSettings,
    SketchSeries,
    Trailing,
    to_candidate,
)
from godwit_sketch import CategoryHistogram, CountMinHeavy, KllQuantile

FIXED_1 = FixedReference(snapshot_id=snapshot(1))
FIXED_0 = FixedReference(snapshot_id=snapshot(0))


def _values(finding: Any) -> list[object]:
    return [p.values[0].reveal() for p in finding.segment.predicates]


def _truncated(full: SketchSeries, upto: int) -> SketchSeries:
    return SketchSeries(context=full.context, points=full.points[: upto + 1])


@pytest.mark.parametrize("detector", [PsiDrift(), JensenShannonDrift(), HeavyHitterShift()])
def test_country_mix_is_quiet_between_the_two_baselines(
    detector: PsiDrift | JensenShannonDrift | HeavyHitterShift,
) -> None:
    result = detector.run(_truncated(golden_country_series(), 1), policy=FIXED_0)
    assert result.tests > 0
    assert result.findings == ()


@pytest.mark.parametrize("detector", [PsiDrift(), JensenShannonDrift()])
def test_country_mix_drift_is_found_and_blamed_on_pt(
    detector: PsiDrift | JensenShannonDrift,
) -> None:
    (finding,) = detector.run(golden_country_series(), policy=FIXED_1).findings
    top = finding.attribution[0].identity
    assert top is not None and top.reveal() == "s:PT"


def test_heavy_hitters_put_pt_first_and_never_flag_us_upward() -> None:
    findings = HeavyHitterShift().run(golden_country_series(), policy=FIXED_1).findings
    assert _values(findings[0]) == ["PT"] and findings[0].direction is Direction.UP
    # US's share falls because PT's rose: shares are compositional. It must not rise.
    assert not [f for f in findings if _values(f) == ["US"] and f.direction is Direction.UP]


@pytest.mark.parametrize("kind", ["moments", "kll"])
def test_refunds_in_pt_diverge_and_the_us_control_does_not(kind: str) -> None:
    detector = SegmentDivergence(SegmentDivergenceSettings(min_support=30))
    result = detector.run(golden_amount_panel(2, kind), baseline=golden_amount_panel(1, kind))
    flagged = [_values(f) for f in result.findings]
    assert ["PT", "refund"] in flagged
    assert not [cell for cell in flagged if cell[0] == "US"]
    quiet = detector.run(golden_amount_panel(1, kind), baseline=golden_amount_panel(0, kind))
    assert not [f for f in quiet.findings if _values(f)[0] in ("PT", "US")]


def test_candidates_validate_and_round_trip_like_the_shared_fixture() -> None:
    fixture = json.loads((GOLDEN / "candidates.json").read_text(encoding="utf-8"))
    Candidate.model_validate(fixture["candidates"][0])
    result = SegmentDivergence(SegmentDivergenceSettings(min_support=30)).run(
        golden_amount_panel(2), baseline=golden_amount_panel(1)
    )
    for finding in result.findings:
        candidate = to_candidate(finding, code_version="test", seed=7)
        assert Candidate.model_validate_json(candidate.model_dump_json()) == candidate
        assert candidate.lineage.detector == "segment_divergence"
        assert candidate.lineage.detector_version == 1_000_000
        assert (
            to_candidate(finding, code_version="test", seed=7).candidate_id
            == candidate.candidate_id
        )


# -- the PII torture table -------------------------------------------------------------


def _torture() -> list[dict[str, Any]]:
    return list(pq.read_table(GOLDEN / "pii_torture" / "table.parquet").to_pylist())


def _leaks() -> list[str]:
    payload = json.loads((GOLDEN / "pii_torture" / "expected_leaks.json").read_text("utf-8"))
    # Four fixture values are also ordinary English that a redaction label uses
    # ("<tainted ... from unknown>"). godwit-sketch hit the same collision; it is the
    # demonstration that string scanning is a backstop and the typed taint the control.
    english = {"positive", "negative", "unknown", "general"}
    return [s for s in payload["must_never_appear_in_any_egress"] if s not in english]


def test_twelve_rows_are_refused_everywhere() -> None:
    """A small cell is where spurious findings are manufactured. Nothing is emitted."""
    rows = _torture()
    merchants = [
        CategoryHistogram.from_items([r["merchant_name"] for r in rows], {}) for _ in range(2)
    ]
    salaries = [
        KllQuantile.from_items([float(r["salary_2024"]) for r in rows], {}) for _ in range(2)
    ]
    for detector, data in (
        (PsiDrift(), salaries),
        (JensenShannonDrift(), merchants),
        (HeavyHitterShift(), merchants),
    ):
        result = detector.run(series(data), policy=FIXED_0)
        assert result.findings == ()
        assert result.refusals[0].reason is RefusalReason.THIN_SKETCH


def _torture_results() -> list[DetectionResult]:
    """Replicate the table past the support floor, then make ACME_CORP and one device surge."""
    rows = _torture()
    before = rows * 20
    after = rows * 20 + [r for r in rows if r["merchant_name"] == "ACME_CORP"] * 120
    merchant = [
        CountMinHeavy.from_items([r["merchant_name"] for r in batch], {})
        for batch in (before, after)
    ]
    device = [
        CountMinHeavy.from_items([r["device_id"] for r in batch], {}) for batch in (before, after)
    ]
    salary = [
        KllQuantile.from_items([float(r["salary_2024"]) for r in batch], {})
        for batch in (before, after)
    ]
    return [
        HeavyHitterShift().run(
            series(merchant, ctx=context("count_min:0", columns=("merchant_name",))), policy=FIXED_0
        ),
        HeavyHitterShift().run(
            series(device, ctx=context("count_min:1", columns=("device_id",))), policy=FIXED_0
        ),
        JensenShannonDrift().run(
            series(merchant, ctx=context("count_min:0", columns=("merchant_name",))), policy=FIXED_0
        ),
        PsiDrift().run(
            series(salary, ctx=context("kll:2", columns=("salary_2024",))),
            policy=Trailing(points=1),
        ),
    ]


def test_an_accidental_log_line_leaks_nothing() -> None:
    """repr and str of every result, finding and candidate render labels, not values --
    identities included, because they are Tainted."""
    results = _torture_results()
    assert any(r.findings for r in results)
    rendered = " ".join(
        [repr(r) for r in results]
        + [str(f) for r in results for f in r.findings]
        + [repr(to_candidate(f, code_version="t", seed=1)) for r in results for f in r.findings]
    )
    assert [leak for leak in _leaks() if leak in rendered] == []


def test_suppressed_findings_carry_no_value_outside_segment_and_columns() -> None:
    """With identities stripped, the only row values left are in the segment predicates
    and the column names -- leak paths 4 and 9, the gate's to redact. Everything else a
    reviewer would read is a derived statistic."""
    results = _torture_results()
    surge = [f for r in results for f in r.findings]
    assert any(f.carries_identities for f in surge)
    for finding in surge:
        body = finding.without_identities().model_dump(mode="json", exclude={"segment", "columns"})
        text = json.dumps(body)
        assert [leak for leak in _leaks() if leak in text] == [], finding.method
