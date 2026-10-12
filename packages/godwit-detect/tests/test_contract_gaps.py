"""What godwit-detect needed from the contracts and did not get. Each is a filed CR.

``strict=True``: the day a contract is changed, these XPASS and fail the run, so the
workaround is retired on purpose rather than forgotten.
"""

from __future__ import annotations

import inspect

import pytest
from godwit_contracts.discovery import Candidate, Evidence, Lineage
from godwit_contracts.protocols import Detector


@pytest.mark.xfail(strict=True, reason="CR-A7-detector-cannot-see-history-or-spec")
def test_the_detector_protocol_can_hand_over_a_history() -> None:
    """A seasonal baseline needs the same phase of several earlier cycles; the protocol
    passes one baseline bundle. A graph metric needs several windows to estimate a
    variance at all."""
    assert "history" in inspect.signature(Detector.detect).parameters


@pytest.mark.xfail(strict=True, reason="CR-A7-detector-cannot-see-history-or-spec")
def test_the_detector_protocol_says_what_a_bundle_measured() -> None:
    """Without the spec a detector cannot name the segment or columns of its evidence."""
    assert "spec" in inspect.signature(Detector.detect).parameters


@pytest.mark.xfail(strict=True, reason="CR-A7-evidence-has-no-structured-detail")
def test_evidence_carries_direction_window_and_method() -> None:
    """A11 needs these to turn a finding into a feature without parsing prose."""
    assert {"direction", "baseline_policy", "method"} <= set(Evidence.model_fields)


@pytest.mark.xfail(strict=True, reason="CR-A7-evidence-has-no-structured-detail")
def test_a_run_can_declare_how_many_hypotheses_it_tested() -> None:
    """L5 needs the test count to control FDR honestly; a Candidate cannot carry it."""
    assert "tests_in_run" in Candidate.model_fields or "tests_in_run" in Lineage.model_fields


@pytest.mark.xfail(strict=True, reason="CR-A7-evidence-has-no-structured-detail")
def test_lineage_records_detector_settings() -> None:
    """Replay needs the settings as well as the version; there is no field for them."""
    assert "settings_digest" in Lineage.model_fields
