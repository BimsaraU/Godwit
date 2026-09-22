"""Golden fixtures: they parse, they validate, and they say what they claim to say.

Every downstream package tests against these files. If they rot, nineteen agents build
on sand, so the checks here are about *the fixtures themselves* being trustworthy, not
about any particular detector or model.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest
from godwit_contracts import Candidate, Sensitivity, SketchEnvelope, SketchKind

# --------------------------------------------------------------------------------------
# sketch envelopes
# --------------------------------------------------------------------------------------


def test_sketch_envelopes_parse_and_declare_honest_sensitivity(
    golden_json: Callable[[str], Any],
) -> None:
    fixture = golden_json("sketch_envelopes.json")
    envelopes = [SketchEnvelope.model_validate(item) for item in fixture["envelopes"]]
    assert len(envelopes) == 3

    by_kind = {envelope.kind: envelope for envelope in envelopes}
    assert by_kind[SketchKind.EXACT_COUNT].sensitivity is Sensitivity.DERIVED_STATISTIC
    assert by_kind[SketchKind.KLL].sensitivity is Sensitivity.DERIVED_STATISTIC
    # Count-Min stores observed items: the payload contains row values.
    assert by_kind[SketchKind.COUNT_MIN].sensitivity is Sensitivity.DATA_VALUE

    for envelope in envelopes:
        assert SketchEnvelope.model_validate_json(envelope.model_dump_json()) == envelope


def test_an_item_bearing_sketch_cannot_claim_to_be_a_statistic(
    golden_json: Callable[[str], Any],
) -> None:
    """The validation that stops a Count-Min payload travelling as 'just a summary'."""
    fixture = golden_json("sketch_envelopes.json")
    count_min = next(
        item for item in fixture["envelopes"] if item["kind"] == SketchKind.COUNT_MIN.value
    )
    downgraded = dict(count_min)
    downgraded["sensitivity"] = Sensitivity.DERIVED_STATISTIC.value

    with pytest.raises(ValueError, match="stores observed items"):
        SketchEnvelope.model_validate(downgraded)


# --------------------------------------------------------------------------------------
# candidates
# --------------------------------------------------------------------------------------


def test_candidates_parse_and_match_the_documented_drift(
    golden_json: Callable[[str], Any],
) -> None:
    fixture = golden_json("candidates.json")
    candidates = [Candidate.model_validate(item) for item in fixture["candidates"]]
    assert len(candidates) == 2

    manifest = golden_json("drift_table/manifest.json")
    drifted = manifest["documented_drift"]["introduced_at_snapshot"]
    for candidate in candidates:
        assert candidate.lineage.snapshot_id == drifted
        assert candidate.lineage.baseline_snapshot_id == "snap_1"
        assert candidate.evidence
        assert Candidate.model_validate_json(candidate.model_dump_json()) == candidate


def test_candidate_segments_carry_row_values(golden_json: Callable[[str], Any]) -> None:
    """The point of the fixture: these are not safe to display just because they are
    aggregates. Their predicates quote real column values."""
    fixture = golden_json("candidates.json")
    candidates = [Candidate.model_validate(item) for item in fixture["candidates"]]

    for candidate in candidates:
        assert candidate.segment.predicates
        for predicate in candidate.segment.predicates:
            for value in predicate.values:
                assert value.sensitivity is Sensitivity.DATA_VALUE


# --------------------------------------------------------------------------------------
# drift table
# --------------------------------------------------------------------------------------


def test_drift_manifest_describes_three_snapshots_and_one_drift(
    golden_json: Callable[[str], Any], golden_dir: Path
) -> None:
    manifest = golden_json("drift_table/manifest.json")
    snapshots = manifest["snapshots"]
    assert len(snapshots) == 3
    assert [snapshot["drifted"] for snapshot in snapshots] == [False, False, True]

    for snapshot in snapshots:
        path = golden_dir / "drift_table" / snapshot["file"]
        assert path.exists()
        table = pq.read_table(path)
        assert table.num_rows == snapshot["row_count"]


def test_the_drift_is_actually_present(golden_dir: Path) -> None:
    """Assert the documented effect, not just that a file exists."""
    baseline = pq.read_table(golden_dir / "drift_table" / "snapshot_1.parquet").to_pylist()
    drifted = pq.read_table(golden_dir / "drift_table" / "snapshot_2.parquet").to_pylist()

    def pt_share(rows: list[dict[str, Any]]) -> float:
        return sum(1 for row in rows if row["country"] == "PT") / len(rows)

    def pt_refund_mean(rows: list[dict[str, Any]]) -> float:
        amounts = [
            row["amount"] for row in rows if row["country"] == "PT" and row["status"] == "refund"
        ]
        return sum(amounts) / len(amounts)

    assert pt_share(baseline) < 0.06
    assert pt_share(drifted) > 0.14
    assert pt_refund_mean(drifted) > 8 * pt_refund_mean(baseline)


def test_the_false_positive_control_did_not_move(golden_dir: Path) -> None:
    """US share is the control. A detector that flags it is wrong, so the fixture must
    genuinely leave it alone."""
    baseline = pq.read_table(golden_dir / "drift_table" / "snapshot_0.parquet").to_pylist()
    second = pq.read_table(golden_dir / "drift_table" / "snapshot_1.parquet").to_pylist()

    def us_share(rows: list[dict[str, Any]]) -> float:
        return sum(1 for row in rows if row["country"] == "US") / len(rows)

    assert abs(us_share(baseline) - us_share(second)) < 0.05


def test_manifest_bounds_are_real_row_values(golden_json: Callable[[str], Any]) -> None:
    """The fixture exists to make the leak path concrete, so prove it is concrete."""
    manifest = golden_json("drift_table/manifest.json")
    bounds = manifest["snapshots"][0]["column_bounds"]
    assert "@" in bounds["customer_email"]["lower"]
    assert "@" in bounds["customer_email"]["upper"]


# --------------------------------------------------------------------------------------
# classification fixture
# --------------------------------------------------------------------------------------


def test_classification_fixture_is_half_labelled_with_a_stated_ceiling(
    golden_json: Callable[[str], Any], golden_dir: Path
) -> None:
    meta = golden_json("classification/meta.json")
    assert 0.45 < meta["labelled_fraction"] < 0.55
    assert round(meta["bayes_auc"] - meta["target_auc"], 4) == 0.02
    assert meta["bayes_auc"] > 0.85

    train = pq.read_table(golden_dir / "classification" / "train.parquet")
    holdout = pq.read_table(golden_dir / "classification" / "holdout.parquet")
    assert train.num_rows == meta["train_rows"]
    assert holdout.num_rows == meta["holdout_rows"]

    # The true label must not be reachable from the training file.
    assert "label" not in train.column_names
    assert "label_observed" in train.column_names
    assert "label" in holdout.column_names


def test_the_split_is_time_ordered(golden_dir: Path) -> None:
    """Random-splitting a time series is how a useless model looks excellent."""
    train = pq.read_table(golden_dir / "classification" / "train.parquet").to_pylist()
    holdout = pq.read_table(golden_dir / "classification" / "holdout.parquet").to_pylist()
    assert max(row["event_time"] for row in train) <= min(row["event_time"] for row in holdout)


def test_the_leak_traps_are_documented_and_present(
    golden_json: Callable[[str], Any], golden_dir: Path
) -> None:
    meta = golden_json("classification/meta.json")
    assert set(meta["leak_traps"]) == {"entity_id", "merchant", "label_time"}

    train = pq.read_table(golden_dir / "classification" / "train.parquet").to_pylist()
    entity_ids = [row["entity_id"] for row in train]
    assert len(set(entity_ids)) == len(entity_ids), "entity_id must be unique per row"
    assert any(row["merchant"] == "ACME_CORP" for row in train)


# --------------------------------------------------------------------------------------
# PII torture fixture
# --------------------------------------------------------------------------------------


def test_pii_fixture_covers_every_leak_path(golden_json: Callable[[str], Any]) -> None:
    fixture = golden_json("pii_torture/fixture.json")
    covered = {path for column in fixture["columns"] for path in column["leak_paths"]}
    assert {
        "column_name",
        "manifest_bounds",
        "most_common_values",
        "count_min_heavy_hitter",
        "category_histogram",
        "quantile",
        "derived_feature_name",
        "small_cell",
    } <= covered

    assert fixture["small_cells"][0]["population"] == 3
    assert fixture["small_population_quantile"]["population"] == 12
    assert fixture["derived_feature_name_trap"] == "is_merchant_ACME_CORP"
    assert "customer_ssn" in fixture["driver_exception_trap"]


def test_expected_leaks_lists_the_strings_that_must_never_escape(
    golden_json: Callable[[str], Any],
) -> None:
    expected = golden_json("pii_torture/expected_leaks.json")
    forbidden = expected["must_never_appear_in_any_egress"]
    assert len(forbidden) > 50
    assert "ACME_CORP" in forbidden
    assert "is_merchant_ACME_CORP" in forbidden
    assert any("@northfield-bank.test" in item for item in forbidden)
    assert any(item.count("-") == 2 and item[:3].isdigit() for item in forbidden)


def test_column_names_are_themselves_disclosures(
    golden_json: Callable[[str], Any],
) -> None:
    fixture = golden_json("pii_torture/fixture.json")
    names = {column["name"] for column in fixture["columns"]}
    assert {"patient_hiv_status", "customer_ssn", "salary_2024"} <= names


def test_parquet_tables_match_their_recorded_digests(golden_dir: Path) -> None:
    """The fixtures are pinned by logical content, not by file bytes.

    Parquet encoding is not stable across pyarrow versions; the rows are.
    """
    import hashlib

    def digest(rows: list[dict[str, Any]]) -> str:
        canonical = json.dumps(
            rows, separators=(",", ":"), ensure_ascii=False, sort_keys=True, default=str
        )
        return hashlib.blake2b(canonical.encode("utf-8"), digest_size=16).hexdigest()

    manifest = json.loads(
        (golden_dir / "drift_table" / "manifest.json").read_text(encoding="utf-8")
    )
    for snapshot in manifest["snapshots"]:
        rows = pq.read_table(golden_dir / "drift_table" / snapshot["file"]).to_pylist()
        assert digest(rows) == snapshot["rows_digest"], snapshot["snapshot_id"]
