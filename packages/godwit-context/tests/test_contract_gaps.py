"""What godwit-context needed from the contracts and the store and did not get.

``strict=True``: the day a gap is closed these XPASS and fail the run, so the workaround
is retired on purpose rather than forgotten.
"""

from __future__ import annotations

import godwit_contracts
import pytest
from godwit_contracts import Candidate
from godwit_store.schema import Base


@pytest.mark.xfail(strict=True, reason="CR-A8-candidate-has-no-window")
def test_a_candidate_says_when_its_change_began() -> None:
    """Temporal alignment needs the observed interval, not one instant."""
    assert "window_start" in Candidate.model_fields


@pytest.mark.xfail(strict=True, reason="CR-A8-context-has-no-contract-or-table")
def test_context_events_have_a_contract_home() -> None:
    assert hasattr(godwit_contracts, "ContextEvent")


@pytest.mark.xfail(strict=True, reason="CR-A8-context-has-no-contract-or-table")
def test_the_store_has_a_table_for_context() -> None:
    """Annotations are permanent context; decision records resolve a context_ref."""
    assert {"context_events", "context_decisions"} <= set(Base.metadata.tables)


@pytest.mark.xfail(strict=True, reason="CR-A8-no-type-for-an-unremarkable-test")
def test_the_contracts_can_carry_an_unremarkable_test() -> None:
    """The counterfactual needs observations of segments that did NOT change."""
    assert hasattr(godwit_contracts, "HypothesisTest")
