"""Champion/challenger: losses first, and a diff that refuses to compare unlike things."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from typing import Any

import pytest
from _replay_support import GoldenCandidateHandler
from godwit_contracts.discovery import Candidate
from godwit_replay.datasets import LoadedDataset
from godwit_replay.diff import PatternStatus, diff_reports, render_markdown
from godwit_replay.driver import ReplayConfig, replay
from godwit_replay.harness import METADATA_BUDGET
from godwit_replay.scoring import score_discovery, truth_from_golden_manifest
from godwit_replay.verdict import ReplayReport, build_report


def _report(
    *,
    loaded: LoadedDataset,
    history: tuple[Any, ...],
    handler: Any,
    config: ReplayConfig,
    truth: Any,
    as_of: _dt.datetime,
) -> ReplayReport:
    run = replay(
        dataset="golden-drift",
        history=history,
        clock_instants=loaded.clock_instants,
        period_keys=loaded.period_keys,
        handler=handler,
        config=config,
        budget=METADATA_BUDGET,
    )
    return build_report(run, as_of=as_of, score=score_discovery(run, truth=truth))


def test_two_identical_arms_are_reported_as_identical(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    """Two arms that were meant to differ and did not is a result worth seeing."""
    truth = truth_from_golden_manifest(golden_manifest)
    handler = GoldenCandidateHandler(candidates=golden_candidates)
    arm = {
        "loaded": golden_loaded,
        "history": golden_history,
        "handler": handler,
        "truth": truth,
        "as_of": frozen_now,
    }
    champion = _report(config=config.model_copy(update={"name": "a"}), **arm)  # type: ignore[arg-type]
    challenger = _report(config=config.model_copy(update={"name": "b"}), **arm)  # type: ignore[arg-type]
    comparison = diff_reports(champion, challenger)
    assert comparison.identical
    assert comparison.unchanged == len(champion.top)
    assert comparison.lost == 0
    assert comparison.gained == 0
    assert not comparison.regressed
    rendered = render_markdown(comparison)
    assert "produced identical findings" in rendered


def test_a_challenger_that_finds_nothing_is_reported_as_a_regression(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    """A lost pattern is the expensive kind of regression: nobody notices a missing alert."""
    truth = truth_from_golden_manifest(golden_manifest)
    champion = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates),
        config=config.model_copy(update={"name": "champion"}),
        truth=truth,
        as_of=frozen_now,
    )
    challenger = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=()),
        config=config.model_copy(update={"name": "challenger"}),
        truth=truth,
        as_of=frozen_now,
    )
    comparison = diff_reports(champion, challenger)
    assert comparison.lost == len(champion.top)
    assert comparison.gained == 0
    assert comparison.regressed
    assert not comparison.identical
    rendered = render_markdown(comparison)
    assert rendered.index("## Lost") < rendered.index("## Cost"), "losses are read first"
    assert "lost**" in rendered


def test_a_challenger_that_finds_more_is_reported_as_a_gain(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    truth = truth_from_golden_manifest(golden_manifest)
    champion = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates[:1]),
        config=config.model_copy(update={"name": "champion"}),
        truth=truth,
        as_of=frozen_now,
    )
    challenger = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates),
        config=config.model_copy(update={"name": "challenger"}),
        truth=truth,
        as_of=frozen_now,
    )
    comparison = diff_reports(champion, challenger)
    assert comparison.gained == 1
    assert comparison.lost == 0
    gains = [item for item in comparison.patterns if item.status is PatternStatus.GAINED]
    assert len(gains) == 1
    assert gains[0].challenger_rank is not None
    assert gains[0].champion_rank is None


def test_losses_are_listed_before_gains_in_the_pattern_order(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    truth = truth_from_golden_manifest(golden_manifest)
    champion = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates[:1]),
        config=config.model_copy(update={"name": "champion"}),
        truth=truth,
        as_of=frozen_now,
    )
    challenger = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates[1:]),
        config=config.model_copy(update={"name": "challenger"}),
        truth=truth,
        as_of=frozen_now,
    )
    comparison = diff_reports(champion, challenger)
    assert comparison.lost == 1
    assert comparison.gained == 1
    order = [item.status for item in comparison.patterns]
    assert order.index(PatternStatus.LOST) < order.index(PatternStatus.GAINED)


def test_the_diff_carries_metric_deltas_and_a_cost_delta(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    truth = truth_from_golden_manifest(golden_manifest)
    champion = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates),
        config=config.model_copy(update={"name": "champion"}),
        truth=truth,
        as_of=frozen_now,
    )
    challenger = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=()),
        config=config.model_copy(update={"name": "challenger"}),
        truth=truth,
        as_of=frozen_now,
    )
    comparison = diff_reports(champion, challenger)
    names = {item.metric for item in comparison.metrics}
    assert "precision_at_10" in names
    assert "time_to_detection_seconds" in names
    assert "novelty_rate" in names
    assert comparison.cost_delta.usd == 0
    assert comparison.cost_delta.llm_tokens == 0
    assert "## Cost" in render_markdown(comparison)


def test_the_diff_refuses_two_different_datasets(golden_run: Any, frozen_now: _dt.datetime) -> None:
    other = golden_run.report.model_copy(update={"dataset": "nyc-tlc"})
    with pytest.raises(ValueError, match="one dataset, two configurations"):
        diff_reports(golden_run.report, other)


def test_the_diff_is_committable_json(
    golden_loaded: LoadedDataset,
    golden_history: tuple[Any, ...],
    golden_candidates: tuple[Candidate, ...],
    golden_manifest: Mapping[str, Any],
    config: ReplayConfig,
    frozen_now: _dt.datetime,
) -> None:
    """Segment keys are hashes, so a diff of a customer run can live in a repository."""
    truth = truth_from_golden_manifest(golden_manifest)
    champion = _report(
        loaded=golden_loaded,
        history=golden_history,
        handler=GoldenCandidateHandler(candidates=golden_candidates),
        config=config.model_copy(update={"name": "champion"}),
        truth=truth,
        as_of=frozen_now,
    )
    comparison = diff_reports(champion, champion)
    rendered = comparison.model_dump_json()
    assert "PT" not in rendered
    assert "refund" not in rendered
