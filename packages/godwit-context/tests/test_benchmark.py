"""The acceptance benchmark, pinned. See benchmark_context.py for the world it builds.

These are recorded numbers, not targets: a change to matching that moves them must move
these pins on purpose, and docs/packages/godwit-context.md with them.
"""

from __future__ import annotations

import pytest
from benchmark_context import run

PINNED_EXPLAINED = {
    "deploy": 83,
    "campaign": 24,
    "holiday": 29,
    "month_end": 36,
    "schema": 7,
    "isolated": 9,
    "wave": 1,
}
PINNED_TOTAL = {
    "deploy": 83,
    "campaign": 26,
    "holiday": 51,
    "month_end": 36,
    "schema": 7,
    "isolated": 79,
    "wave": 48,
}


def test_benchmark_is_deterministic_and_pinned() -> None:
    first, second = run(), run()
    assert first == second
    assert dict(first.explained) == PINNED_EXPLAINED
    assert dict(first.total) == PINNED_TOTAL


def test_benign_target_is_met() -> None:
    assert run().benign_rate() > 0.80


@pytest.mark.xfail(strict=True, reason="target not met: 7.9% here, 11.5% over ten seeds")
def test_genuine_wrongly_explained_target() -> None:
    """Under 5% of genuine anomalies wrongly explained. Not met at the default threshold;
    the documented sweep shows 3.1% at threshold 0.6, at a cost of benign coverage."""
    assert run().genuine_rate() < 0.05


def test_without_peers_the_layer_fails_closed() -> None:
    """No detector test list: almost nothing genuine is explained away, and less benign."""
    with_peers, without = run(), run(peers=False)
    assert without.genuine_rate() < with_peers.genuine_rate()
    assert without.benign_rate() < with_peers.benign_rate()
