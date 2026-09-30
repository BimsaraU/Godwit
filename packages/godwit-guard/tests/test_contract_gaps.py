"""What godwit-guard needed from the contracts and could not have. One xfail per CR.

Each is ``strict``: when the change request lands, the test starts passing, strict
xfail turns that into a failure, and whoever sees it deletes the workaround named in the
CR and this marker together.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from godwit_contracts import Destination, EgressRecord, RedactionPolicy

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.xfail(strict=True, reason="CR-A5-issuer-claim-is-process-global")
def test_contracts_forgery_tests_can_share_a_process_with_the_gate() -> None:
    script = (
        "import sys, godwit_guard, pytest; "
        "sys.exit(pytest.main(['-q', '-p', 'no:cacheprovider', "
        "'packages/godwit-contracts/tests/test_safe_payload_forgery.py']))"
    )
    env = {k: v for k, v in os.environ.items() if k != "GODWIT_GUARD_ISOLATED"}
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert completed.returncode == 0


@pytest.mark.xfail(strict=True, reason="CR-A5-destination-vocabulary")
def test_metric_labels_and_trace_attributes_are_distinct_destinations() -> None:
    assert Destination("metric_label") is not Destination("trace_attribute")


@pytest.mark.xfail(strict=True, reason="CR-A5-access-modes-have-no-contract")
def test_access_modes_are_a_contract_type() -> None:
    import godwit_contracts

    assert hasattr(godwit_contracts, "AccessMode")
    assert hasattr(godwit_contracts, "AccessGrant")


@pytest.mark.xfail(strict=True, reason="CR-A5-egress-record-cannot-record-a-refusal")
def test_an_egress_record_can_say_refused_and_name_its_token_map() -> None:
    assert {"decision", "token_map_ref"} <= set(EgressRecord.model_fields)


@pytest.mark.xfail(strict=True, reason="CR-A5-min-cell-size-can-be-zero")
def test_a_policy_cannot_disable_k_anonymity() -> None:
    import datetime as _dt

    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RedactionPolicy(
            policy_id="p",
            version=1,
            min_cell_size=0,
            created_at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
        )
