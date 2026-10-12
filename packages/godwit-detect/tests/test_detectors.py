"""Each detector finds what it is built to find, and refuses what it cannot judge."""

from __future__ import annotations

import pytest
from _detect_scenarios import SCENARIOS, correlation_slice, graph_window, scoring_rows
from _detect_support import (
    DAY,
    EPOCH,
    categories,
    context,
    envelope,
    eq_segment,
    rng,
    series,
    snapshot,
)
from godwit_contracts.discovery import EvidenceKind
from godwit_detect import (
    CorrelationPanel,
    CorrelationShift,
    Direction,
    DriftSettings,
    FixedReference,
    GraphAnomaly,
    HeavyHitterSettings,
    HeavyHitterShift,
    JensenShannonDrift,
    PanelSnapshot,
    PsiDrift,
    RefusalReason,
    SegmentDivergence,
    SegmentSlice,
    Trailing,
    WassersteinDrift,
)
from godwit_detect.heavy import parse_canonical_key
from godwit_detect.histograms import compare, effective_n
from godwit_sketch import (
    CategoryHistogram,
    CountMinHeavy,
    KeyHasher,
    KllQuantile,
    Moments,
    NullRate,
)

KLL = {"k": 200, "seed": 3}
FIX = FixedReference(snapshot_id=snapshot(0))


def _kll(seed: int, n: int = 3000, shift: float = 0.0) -> KllQuantile:
    return KllQuantile.from_items(list(rng(seed).lognormal(3.0 + shift, 0.7, n)), KLL)


def _hist(seed: int, shares: list[float], n: int = 3000) -> CategoryHistogram:
    return CategoryHistogram.from_items(categories(rng(seed), shares, n), {})


# -- drift ------------------------------------------------------------------------------


def test_psi_and_wasserstein_see_a_location_shift_and_its_direction() -> None:
    shifted = series([_kll(1), _kll(2, shift=0.2)])
    for detector in (PsiDrift(), WassersteinDrift()):
        (finding,) = detector.run(shifted, policy=FIX).findings
        assert finding.direction is Direction.UP
        assert finding.kind is EvidenceKind.DISTRIBUTION_SHIFT
        assert finding.p_value is not None and finding.p_value.reveal() < 1e-6
    wasserstein = WassersteinDrift().run(shifted, policy=FIX).findings[0]
    assert wasserstein.effect.unit == "column_units"
    assert 2.0 < wasserstein.effect.value.reveal() < 8.0


def test_drift_uses_the_probe_grid_when_there_is_one() -> None:
    grid = {**KLL, "cdf_grid": "10,20,30,40,60"}
    data = [KllQuantile.from_items(list(rng(s).lognormal(3.0, 0.7, 3000)), grid) for s in (1, 2)]
    result = PsiDrift().run(series(data), policy=FIX)
    assert result.tests == 1
    shifted = [data[0], KllQuantile.from_items(list(rng(2).lognormal(3.4, 0.7, 3000)), grid)]
    (finding,) = PsiDrift().run(series(shifted), policy=FIX).findings
    assert next(a.feature for a in finding.attribution).startswith("bin:")


def test_js_names_the_category_that_moved_only_through_a_tainted_identity() -> None:
    base = [30, 20, 15, 10, 8, 6, 5, 3, 2, 1]
    moved = [30, 20, 15, 10, 8, 6, 5, 3, 2, 12]
    (finding,) = (
        JensenShannonDrift().run(series([_hist(1, base), _hist(2, moved)]), policy=FIX).findings
    )
    top = finding.attribution[0]
    assert top.identity is not None and top.identity.reveal() == "s:c09"
    assert "c09" not in repr(finding) and "c09" not in str(
        finding.without_identities().model_dump()
    )


def test_drift_refuses_thin_sketches_gaps_and_mismatched_keying() -> None:
    thin = series([_kll(1, n=50), _kll(2, n=50)])
    assert PsiDrift().run(thin, policy=FIX).refusals[0].reason is RefusalReason.THIN_SKETCH
    gap = series([_kll(1), None])
    assert PsiDrift().run(gap, policy=FIX).refusals[0].reason is RefusalReason.GAP
    missing = series([_kll(1), _kll(2)])
    other = FixedReference(snapshot_id=snapshot(9))
    assert PsiDrift().run(missing, policy=other).refusals[0].reason is RefusalReason.NO_BASELINE
    plain = CountMinHeavy.from_items(categories(rng(1), [3, 2, 1], 500), {})
    hashed = CountMinHeavy.identity({}).with_hasher(
        KeyHasher.opaque(key=b"k" * 16, input_entropy_bits=64)
    )
    for item in categories(rng(2), [3, 2, 1], 500):
        hashed.update(item)
    result = PsiDrift().run(series([plain, hashed]), policy=FIX)
    assert result.refusals[0].reason is RefusalReason.INCOMPARABLE
    assert result.tests == 0


def test_dispersion_absorbs_reference_windows_that_already_disagree() -> None:
    """Six references that wobble a lot: a modest move should not be called drift."""
    wobble = [_hist(s, [30, 20, 15 + 6 * (s % 2), 10, 8]) for s in range(6)]
    current = _hist(99, [30, 20, 21, 10, 8])
    result = JensenShannonDrift().run(series([*wobble, current]), policy=Trailing(points=6))
    assert result.findings == ()
    naive = JensenShannonDrift().run(series([wobble[-2], current]), policy=Trailing(points=1))
    assert naive.findings


def test_sparse_bins_are_merged_before_testing() -> None:
    comparison = compare(
        [100, 100, 1, 1, 1], [100, 100, 1, 1, 1], n_current=203, n_reference=203, ordered=True
    )
    assert comparison.df == 1  # the three sparse tail bins fold into the last full one
    assert comparison.g_statistic == pytest.approx(0.0)
    assert effective_n(1000, 0.0) == 1000


# -- heavy hitters ---------------------------------------------------------------------


def test_a_key_from_nowhere_is_an_entrant_with_a_segment_on_its_value() -> None:
    before = categories(rng(1), [1 / (i + 1) for i in range(20)], 4000)
    after = [*categories(rng(2), [1 / (i + 1) for i in range(20)], 3400), *(["newcomer"] * 600)]
    data = [CountMinHeavy.from_items(before, {}), CountMinHeavy.from_items(after, {})]
    ctx = context("count_min:0", columns=("merchant",))
    result = HeavyHitterShift().run(series(data, ctx=ctx), policy=FIX)
    (entrant,) = [f for f in result.findings if f.method == "entrant"]
    assert entrant.direction is Direction.APPEARED
    assert entrant.segment.predicates[-1].values[0].reveal() == "newcomer"
    assert {m.name for m in entrant.shape} >= {"entrant_count", "entrant_share", "churn", "hhi"}
    assert result.tests >= 11


def test_hashed_keys_never_become_segment_predicates() -> None:
    hasher = KeyHasher.opaque(key=b"k" * 16, input_entropy_bits=64)
    sketches = []
    for seed, extra in ((1, 0), (2, 600)):
        sketch = CountMinHeavy.identity({}).with_hasher(hasher)
        for item in [*categories(rng(seed), [5, 4, 3, 2, 1], 3000), *(["newcomer"] * extra)]:
            sketch.update(item)
        sketches.append(sketch)
    ctx = context("count_min:0", columns=("device_id",))
    result = HeavyHitterShift().run(series(sketches, ctx=ctx), policy=FIX)
    assert result.findings
    assert all(not f.segment.predicates for f in result.findings)


def test_rank_churn_needs_history_and_gets_a_p_value_with_it() -> None:
    windows = [
        CountMinHeavy.from_items(categories(rng(s), [1 / (i + 1) for i in range(30)], 3000), {})
        for s in range(6)
    ]
    churned = CountMinHeavy.from_items(
        categories(rng(9), [1 / (30 - i) for i in range(30)], 3000), {}
    )
    detector = HeavyHitterShift(HeavyHitterSettings(min_history=5))
    result = detector.run(series([*windows, churned]), policy=Trailing(points=6))
    assert "rank_churn" in {f.method for f in result.findings}
    short = detector.run(series([windows[0], churned]), policy=FIX)
    assert "rank_churn" not in {f.method for f in short.findings}


@pytest.mark.parametrize(
    "value", ["s:PT", "i:-4", "b:true", "f:1.5", "d:1.25", "t:2024-01-31", "n:"]
)
def test_canonical_keys_invert(value: str) -> None:
    from godwit_contracts.segment import canonical_scalar

    assert canonical_scalar(parse_canonical_key(value)) == value


# -- segments --------------------------------------------------------------------------


def _panel(values: dict[str, list[float]], kind: str = "moments") -> PanelSnapshot:
    slices = []
    for name, data in values.items():
        sketch = (
            Moments.from_items(data, {}) if kind == "moments" else KllQuantile.from_items(data, KLL)
        )
        slices.append(
            SegmentSlice(
                context=context(
                    f"x:{name}", probe=f"prb_{name}", segment=eq_segment("country", name)
                ),
                envelope=envelope(sketch, 1, probe=f"prb_{name}"),
            )
        )
    return PanelSnapshot(snapshot_id=snapshot(1), at=EPOCH + DAY, slices=tuple(slices))


@pytest.mark.parametrize("kind", ["moments", "kll"])
def test_one_segment_out_of_line_is_the_only_one_reported(kind: str) -> None:
    values = {f"c{i}": list(rng(i).lognormal(3.0, 0.7, 500)) for i in range(8)}
    values["c3"] = list(rng(3).lognormal(3.8, 0.7, 500))
    result = SegmentDivergence().run(_panel(values, kind))
    assert [f.segment.predicates[0].values[0].reveal() for f in result.findings] == ["c3"]
    assert result.tests == 8
    assert result.findings[0].direction is Direction.UP


def test_ordinary_heterogeneity_between_segments_is_not_divergence() -> None:
    """Every segment differs from every other, by about as much. None is an outlier."""
    values = {f"c{i}": list(rng(i).lognormal(3.0 + 0.15 * i, 0.7, 3000)) for i in range(8)}
    assert SegmentDivergence().run(_panel(values)).findings == ()


def test_emerging_mode_ignores_a_segment_that_was_always_different() -> None:
    always = {f"c{i}": list(rng(i).lognormal(3.0, 0.7, 500)) for i in range(6)}
    always["c0"] = list(rng(0).lognormal(3.8, 0.7, 500))
    later = {name: list(rng(100 + i).lognormal(3.0, 0.7, 500)) for i, name in enumerate(always)}
    later["c0"] = list(rng(100).lognormal(3.8, 0.7, 500))
    detector = SegmentDivergence()
    assert detector.run(_panel(later)).findings
    assert detector.run(_panel(later), baseline=_panel(always)).findings == ()


def test_segment_divergence_on_categories_and_null_rates() -> None:
    slices = []
    for i in range(6):
        shares = [5, 3, 2, 9] if i == 2 else [5, 3, 2, 1]
        hist = CategoryHistogram.from_items(categories(rng(i), shares, 800), {})
        slices.append(
            SegmentSlice(
                context=context(f"h:{i}", probe=f"h{i}", segment=eq_segment("k", f"v{i}")),
                envelope=envelope(hist, 1, probe=f"h{i}"),
            )
        )
    result = SegmentDivergence().run(
        PanelSnapshot(snapshot_id=snapshot(1), at=EPOCH, slices=tuple(slices))
    )
    assert [f.segment.predicates[0].values[0].reveal() for f in result.findings] == ["v2"]
    slices = []
    for i in range(6):
        rate = 0.3 if i == 4 else 0.1
        nulls = NullRate.from_items([None if u < rate else 1.0 for u in rng(i).random(800)], {})
        slices.append(
            SegmentSlice(
                context=context(f"n:{i}", probe=f"n{i}", segment=eq_segment("k", f"v{i}")),
                envelope=envelope(nulls, 1, probe=f"n{i}"),
            )
        )
    result = SegmentDivergence().run(
        PanelSnapshot(snapshot_id=snapshot(1), at=EPOCH, slices=tuple(slices))
    )
    assert [f.segment.predicates[0].values[0].reveal() for f in result.findings] == ["v4"]


def test_too_few_peers_is_a_refusal_not_a_finding() -> None:
    values = {f"c{i}": list(rng(i).lognormal(3.0, 0.7, 500)) for i in range(3)}
    result = SegmentDivergence().run(_panel(values))
    assert result.refusals[-1].reason is RefusalReason.TOO_FEW_PEERS
    assert result.tests == 0


# -- structure, graph, scoring --------------------------------------------------------


def test_correlation_reports_edges_that_appear_not_ones_that_merely_wobble() -> None:
    result = SCENARIOS["correlation_shift"]()
    assert {f.segment.predicates[0].values[0].reveal() for f in result.findings} == {"north"}
    assert {f.direction for f in result.findings} == {Direction.APPEARED}
    assert all(len(f.columns) == 2 for f in result.findings)
    quiet = CorrelationPanel(
        snapshot_id=snapshot(1), at=EPOCH, slices=(correlation_slice(5, "a", 0.1),)
    )
    assert CorrelationShift().run(quiet).findings == ()


def test_graph_funnel_is_found_and_needs_history() -> None:
    result = SCENARIOS["graph_anomaly"]()
    methods = {f.method for f in result.findings}
    assert {"funnel_signature", "concentration_in", "fan_in_out_ratio"} <= methods
    funnel = next(f for f in result.findings if f.method == "funnel_signature")
    collectors = {f"s:collector{i}" for i in range(4)}
    assert collectors <= {i.reveal() for i in funnel.identities}
    short = series(
        [graph_window(0, funnel=False), graph_window(1, funnel=True)],
        ctx=context("count_min:graph"),
    )
    refused = GraphAnomaly().run(short, policy=FIX)
    assert refused.refusals[0].reason is RefusalReason.THIN_BASELINE


@pytest.mark.parametrize("name", ["ecod", "copod"])
def test_tail_scorers_rank_the_injected_rows_and_emit_the_nominal_share(name: str) -> None:
    result = SCENARIOS[name]()
    assert result.tests == len(scoring_rows())
    assert str(result.findings[0].probe_key) == "prb_score_23"
    assert len(result.findings) == 2
    assert result.findings[0].attribution[0].feature.startswith("moments_")


def test_matrix_profile_finds_the_recent_spike_without_a_p_value() -> None:
    result = SCENARIOS["matrix_profile"]()
    discord = next(f for f in result.findings if f.method == "discord")
    assert discord.p_value is None and discord.p_value_note
    assert discord.direction is Direction.UP


def test_heavy_series_rejects_foreign_sketches() -> None:
    result = HeavyHitterShift().run(series([_kll(1), _kll(2)]), policy=FIX)
    assert result.refusals[0].reason is RefusalReason.UNSUPPORTED_SKETCH


def test_settings_are_part_of_the_evidence() -> None:
    shifted = series([_kll(1), _kll(2, shift=0.2)])
    default = PsiDrift().run(shifted, policy=FIX).findings[0]
    tuned = PsiDrift(DriftSettings(bins=5)).run(shifted, policy=FIX).findings[0]
    assert default.settings_digest != tuned.settings_digest
