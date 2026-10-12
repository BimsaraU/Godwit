"""With nothing injected, each detector's false-positive rate is at or below nominal alpha.

The suite runs a few hundred null worlds per detector so that it stays fast;
``tests/benchmark_detectors.py --null 1000`` runs the full thousand and its output is
the table recorded in ``docs/packages/godwit-detect.md``. Rates are per test: emitted
findings over every hypothesis the detector declared.
"""

from __future__ import annotations

import math

import pytest
from _detect_null import WORLDS, null_rate

ALPHA = 0.05
SERIES = {"graph_anomaly": 40}
DEFAULT_SERIES = 150


@pytest.mark.parametrize("world", sorted(WORLDS))
def test_false_positive_rate_is_not_above_alpha(world: str) -> None:
    emitted, tests = null_rate(WORLDS[world], SERIES.get(world, DEFAULT_SERIES))
    assert tests > 0
    rate = emitted / tests
    slack = 3.0 * math.sqrt(ALPHA * (1 - ALPHA) / tests)
    assert rate <= ALPHA + slack, f"{world}: {emitted}/{tests} = {rate:.3f}"


@pytest.mark.parametrize("world", ["ecod[location]", "copod[location]"])
def test_conformal_scorers_hit_alpha_exactly(world: str) -> None:
    """Exchangeable rows: the conformal p-value is exactly calibrated, not merely bounded."""
    emitted, tests = null_rate(WORLDS[world], 50)
    assert emitted / tests == pytest.approx(ALPHA, abs=0.01)
