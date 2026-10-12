"""Against tests/golden/candidates.json: the documented PT drift in drift_table.

The fixture's `country = 'US'` segment is the false-positive control. Here it is used the
other way round: as the untouched peer that did NOT move, which is what lets a campaign
aimed at Portugal be confirmed as the explanation for a Portugal spike.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable
from typing import Any

import pytest
from _context_support import segment
from godwit_context import (
    ContextRouter,
    ContextType,
    CounterfactualVerdict,
    MemoryAuditSink,
    OverlapTier,
    PeerObservation,
    Route,
    import_records,
)
from godwit_contracts import Candidate, SourceId, derived_statistic


@pytest.fixture
def golden(golden_json: Callable[[str], Any]) -> list[Candidate]:
    return [Candidate.model_validate(c) for c in golden_json("candidates.json")["candidates"]]


def _peers(at: _dt.datetime, effect: float) -> list[PeerObservation]:
    return [
        PeerObservation(
            source_id=SourceId(source),
            segment=segment({"country": "US"}),
            family="rate_change",
            observed_at=at,
            effect=derived_statistic(effect),
        )
        for source in ("src_golden", "src_mirror_1", "src_mirror_2")
    ]


def _campaign(at: _dt.datetime) -> list[Any]:
    return list(
        import_records(
            [
                {
                    "id": "pt-launch",
                    "start": (at - _dt.timedelta(hours=10)).isoformat(),
                    "end": (at + _dt.timedelta(days=14)).isoformat(),
                    "kind": "portugal_launch",
                    "source_ids": "src_golden",
                    "segment": "country=PT",
                }
            ],
            context_type=ContextType.CAMPAIGN,
            origin="marketing",
        )
    )


def test_a_portugal_campaign_explains_the_portugal_spike(golden: list[Candidate]) -> None:
    at = golden[0].created_at
    router = ContextRouter(audit=MemoryAuditSink())
    decisions = router.route(golden, events=_campaign(at), peers=_peers(at, 0.2), at=at)
    share, refunds = decisions
    assert share.route is Route.EXPLAINED
    best = share.matches[0]
    assert best.tier is OverlapTier.SEGMENT
    assert best.counterfactual.verdict is CounterfactualVerdict.SUPPORTED
    # The refund-amount segment refines country=PT, so the campaign touches it too; but no
    # comparable peers were measured for that structure, so the check is untestable.
    assert refunds.matches[0].tier is OverlapTier.SEGMENT
    assert refunds.matches[0].counterfactual.verdict is CounterfactualVerdict.UNTESTABLE


def test_if_the_us_control_moved_too_the_campaign_is_not_the_explanation(
    golden: list[Candidate],
) -> None:
    at = golden[0].created_at
    router = ContextRouter(audit=MemoryAuditSink())
    share, _ = router.route(golden, events=_campaign(at), peers=_peers(at, 16.0), at=at)
    assert share.matches[0].counterfactual.verdict is CounterfactualVerdict.CONTRADICTED
    assert share.matches[0].downgraded
    assert share.route is Route.PROCEED


def test_routing_the_golden_batch_is_deterministic(golden: list[Candidate]) -> None:
    at = golden[0].created_at

    def run() -> str:
        router = ContextRouter(audit=MemoryAuditSink())
        decisions = router.route(golden, events=_campaign(at), peers=_peers(at, 0.2), at=at)
        return "".join(d.model_dump_json() for d in decisions)

    assert run() == run()
