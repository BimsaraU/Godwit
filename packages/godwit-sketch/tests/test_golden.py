"""Against the shared golden fixtures, so this package and its readers cannot drift apart.

Two things are checked here that the rest of the suite cannot check on its own.

**The envelope shape.** ``tests/golden/sketch_envelopes.json`` is what the other agents
agreed on before any of this existed. Every envelope this package produces has to
validate as a :class:`~godwit_contracts.sketch.SketchEnvelope` and round-trip through
the same JSON the fixture uses, or a payload written here will not survive a trip
through the pattern store.

**The documented drift.** ``tests/golden/drift_table`` carries three snapshots with a
drift that A0 wrote down in ``manifest.json``: ``country = 'PT'`` rises from about 3% of
rows to about 18% at ``snap_2``, and within ``PT AND status = 'refund'`` the ``amount``
distribution jumps. ``country = 'US'`` is the false-positive control.

This package does not decide whether anything is anomalous -- that is L2's job and
explicitly out of scope here. What it must do is make the drift *visible*: two sketches
built from two snapshots have to differ in the feature vector, in the direction the
manifest says, and the control has to stay still. If a detector cannot see the drift in
these numbers, no amount of cleverness at L2 will recover it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import pytest
from _support import context
from godwit_contracts.sketch import SketchEnvelope
from godwit_sketch.features import extract_features, feature_index
from godwit_sketch.frequency import CategoryHistogram
from godwit_sketch.moments import Moments
from godwit_sketch.quantile import KllQuantile

GOLDEN = Path(__file__).resolve().parents[3] / "tests" / "golden"


def _column(snapshot: str, name: str) -> list[Any]:
    table = pq.read_table(GOLDEN / "drift_table" / f"{snapshot}.parquet")
    return list(table.column(name).to_pylist())


def _rows(snapshot: str) -> list[dict[str, Any]]:
    return list(pq.read_table(GOLDEN / "drift_table" / f"{snapshot}.parquet").to_pylist())


@pytest.fixture(scope="module")
def manifest() -> dict[str, Any]:
    payload = json.loads((GOLDEN / "drift_table" / "manifest.json").read_text("utf-8"))
    assert isinstance(payload, dict)
    return payload


# --------------------------------------------------------------------------------------
# The envelope shape
# --------------------------------------------------------------------------------------


def test_the_golden_envelopes_still_validate() -> None:
    """The shape downstream agreed on parses, including the item-bearing validator."""
    payload = json.loads((GOLDEN / "sketch_envelopes.json").read_text("utf-8"))
    envelopes = [SketchEnvelope.model_validate(entry) for entry in payload["envelopes"]]
    assert len(envelopes) == 3
    kinds = {envelope.kind.value for envelope in envelopes}
    assert kinds == {"exact_count", "kll", "count_min"}


def test_our_envelopes_round_trip_through_the_golden_json_form() -> None:
    """What this package writes survives the same serialisation the fixture uses.

    An envelope is stored as JSON with base64 bytes. If a payload did not survive that
    round trip, sketches would decode correctly in-process and corrupt on the way out of
    the pattern store -- the worst possible place to find out.
    """
    original = CategoryHistogram.from_items(
        _column("snapshot_0", "country"), {"max_exact_cardinality": 64}
    )
    envelope = original.serialise(context())
    rebuilt = SketchEnvelope.model_validate_json(envelope.model_dump_json())
    assert rebuilt.payload == envelope.payload
    assert CategoryHistogram.decode(rebuilt) == original


def test_an_item_bearing_envelope_cannot_claim_to_be_a_statistic() -> None:
    """The contract's own validator, exercised against a real payload of ours.

    A category histogram holds exact labels, which are row values. Declaring one a
    derived statistic is a validation error, not a review comment.
    """
    envelope = CategoryHistogram.from_items(["a", "b"], {}).serialise(context())
    with pytest.raises(ValueError, match="stores observed items"):
        envelope.model_copy(update={"sensitivity": "derived_statistic"}).model_validate(
            envelope.model_dump() | {"kind": "count_min", "sensitivity": "derived_statistic"}
        )


# --------------------------------------------------------------------------------------
# The documented drift
# --------------------------------------------------------------------------------------


def test_the_manifest_still_describes_the_drift_this_test_relies_on(
    manifest: dict[str, Any],
) -> None:
    """Pin the fixture's own claims, so a regenerated fixture fails here first."""
    assert manifest["documented_drift"]["introduced_at_snapshot"] == "snap_2"
    segments = manifest["documented_drift"]["segments"]
    assert ["country", "eq", "PT"] in segments[0]["predicates"]
    controls = manifest["documented_drift"]["unchanged_controls"]
    assert ["country", "eq", "US"] in controls[0]["predicates"]


def test_the_country_share_shift_is_visible_in_the_feature_vector() -> None:
    """A category histogram on ``country`` moves where the manifest says it moves.

    The fixture documents PT going from about 3% of rows to about 18% at ``snap_2``.
    That is a segment-divergence signal, and the cheapest place it shows up is the
    top-share slots -- no row is quoted and nothing is named.

    ``freq_top1_share`` is the slot that carries it, not ``freq_top5_share``: the
    fixture has exactly five countries, so the top five are all of them and that share
    is 1.0 in every snapshot. PT taking share from US moves the leader's share (0.585 to
    0.494) while the top-five share cannot move at all. Worth stating because picking
    the wrong slot here would look like the drift was invisible.
    """
    params = {"max_exact_cardinality": 64}
    vectors = {
        snapshot: extract_features(
            CategoryHistogram.from_items(_column(snapshot, "country"), params).serialise(context())
        )
        for snapshot in ("snapshot_0", "snapshot_1", "snapshot_2")
    }
    share = feature_index("freq_top1_share")
    baseline_gap = abs(vectors["snapshot_1"][share] - vectors["snapshot_0"][share])
    drift_gap = abs(vectors["snapshot_2"][share] - vectors["snapshot_0"][share])
    assert drift_gap > baseline_gap * 5, (
        f"the drifted snapshot must move much further than the baseline pair: "
        f"drift {drift_gap:.4f} vs baseline {baseline_gap:.4f}"
    )
    assert vectors["snapshot_2"][feature_index("freq_top5_share")] == pytest.approx(1.0)


def test_pt_rises_and_us_holds_still() -> None:
    """The signal and the false-positive control, measured the same way.

    ``country = 'US'`` is in the fixture specifically to catch a detector that flags
    everything. If this package's numbers moved for US as much as for PT, a detector
    built on them could not tell the two apart whatever it did.
    """

    def share(snapshot: str, value: str) -> float:
        column = _column(snapshot, "country")
        return column.count(value) / len(column)

    pt_before, pt_after = share("snapshot_0", "PT"), share("snapshot_2", "PT")
    us_before, us_after = share("snapshot_0", "US"), share("snapshot_2", "US")
    assert pt_after > pt_before * 3, f"PT should rise sharply: {pt_before} -> {pt_after}"
    assert abs(us_after - us_before) < 0.1, f"US is the control: {us_before} -> {us_after}"

    # And the sketch reproduces the exact shares, because below the cardinality
    # threshold a category histogram is exact rather than estimated.
    sketch = CategoryHistogram.from_items(
        _column("snapshot_2", "country"), {"max_exact_cardinality": 64}
    )
    counts = {key.reveal(): count for key, count in sketch.categories()}
    assert counts["s:PT"] / sketch.population == pytest.approx(pt_after)


def test_the_amount_distribution_moves_inside_the_drifted_segment() -> None:
    """KLL on ``amount`` within ``PT AND status = 'refund'`` sees the jump.

    The manifest says the mean rises by roughly an order of magnitude there. The safe
    way to see that -- the one that quotes nobody's number -- is the CDF on a fixed
    grid: the fraction of the segment below a threshold collapses.
    """
    grid = "100,200,400"
    params = {"k": 200, "seed": 1, "cdf_grid": grid}

    def segment_cdf(snapshot: str) -> tuple[float, ...]:
        amounts = [
            row["amount"]
            for row in _rows(snapshot)
            if row["country"] == "PT" and row["status"] == "refund"
        ]
        sketch = KllQuantile.from_items(amounts, params)
        return extract_features(sketch.serialise(context()))[
            feature_index("cdf_00") : feature_index("cdf_00") + 3
        ]

    before = segment_cdf("snapshot_0")
    after = segment_cdf("snapshot_2")
    # Before the drift almost everything is under 400; after, almost nothing is.
    assert before[2] > 0.8, f"baseline should sit below the grid: {before}"
    assert after[2] < 0.2, f"drifted segment should sit above the grid: {after}"


def test_the_drifted_segment_is_a_small_cell_before_the_drift() -> None:
    """The real fixture makes the small-cell rule bite, which is worth demonstrating.

    ``PT AND status = 'refund'`` holds 18 rows at ``snapshot_0`` and 92 at
    ``snapshot_2``. Eighteen is below the default threshold of 20, so the mean of the
    *undrifted* segment is blanked out of the control-plane vector -- correctly: a mean
    over eighteen refunds is close enough to quoting them.

    A caller inside the data plane passes ``small_cell_threshold=0`` and sees it. That
    difference is the whole point of the parameter, and this is the case that shows it.
    """

    def amounts(snapshot: str) -> list[float]:
        return [
            row["amount"]
            for row in _rows(snapshot)
            if row["country"] == "PT" and row["status"] == "refund"
        ]

    before_rows, after_rows = amounts("snapshot_0"), amounts("snapshot_2")
    assert len(before_rows) < 20 <= len(after_rows)

    mean_slot = feature_index("moments_mean")
    guarded = extract_features(Moments.from_items(before_rows, {}).serialise(context()))
    assert guarded[mean_slot] != guarded[mean_slot], "an 18-row mean must not leave blanked"

    # The shape statistics are scale-free and survive, so the segment is not invisible.
    assert guarded[feature_index("population")] == float(len(before_rows))


def test_moments_see_the_same_jump_without_exporting_an_extreme() -> None:
    """The mean of the drifted segment rises by an order of magnitude, as documented.

    Read with ``small_cell_threshold=0``, because this is what a data-plane caller sees;
    the previous test covers what a control-plane caller sees. No extreme is exported
    either way -- the vector has no slot for one.
    """

    def segment_mean(snapshot: str) -> float:
        amounts = [
            row["amount"]
            for row in _rows(snapshot)
            if row["country"] == "PT" and row["status"] == "refund"
        ]
        vector = extract_features(
            Moments.from_items(amounts, {}).serialise(context()), small_cell_threshold=0
        )
        return vector[feature_index("moments_mean")]

    before, after = segment_mean("snapshot_0"), segment_mean("snapshot_2")
    assert after > before * 5, f"mean should jump: {before} -> {after}"


def test_the_unchanged_snapshots_look_unchanged() -> None:
    """snap_0 and snap_1 are both baselines: a detector must find nothing between them.

    This is the other half of the false-positive control. A sketch whose numbers wander
    between two undrifted snapshots would manufacture patterns out of nothing.
    """
    params = {"max_exact_cardinality": 64}
    vectors = [
        extract_features(
            CategoryHistogram.from_items(_column(snapshot, "country"), params).serialise(context())
        )
        for snapshot in ("snapshot_0", "snapshot_1")
    ]
    share = feature_index("freq_top1_share")
    assert abs(vectors[0][share] - vectors[1][share]) < 0.05
