"""Evidence for this package's change requests. Each is ``xfail(strict=True)``.

They start passing -- and so fail as XPASS -- the moment the change lands, which is how
A6 finds out a workaround can be retired.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import godwit_contracts
import pytest
from godwit_contracts import SketchBundle
from godwit_guard import DEFAULT_MIN_ENTROPY_BITS
from godwit_probe.testing import simulator_keyring
from godwit_sketch import MIN_OPAQUE_ENTROPY_BITS, GraphDegree

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.xfail(strict=True, reason="CR-A6-sketch-bundle-cannot-say-why")
def test_the_contract_can_express_a_refused_or_delta_probe() -> None:
    fields = SketchBundle.model_fields
    assert "since_snapshot_id" in fields
    assert hasattr(godwit_contracts, "ProbeOutcome")


@pytest.mark.xfail(strict=True, reason="CR-A6-opaque-entropy-floors-disagree")
def test_guard_and_sketch_agree_on_the_opaque_entropy_floor() -> None:
    assert DEFAULT_MIN_ENTROPY_BITS == MIN_OPAQUE_ENTROPY_BITS


@pytest.mark.xfail(strict=True, reason="CR-A6-access-modes-need-a-contract-home")
def test_a_data_plane_worker_does_not_hold_the_safe_payload_issuer() -> None:
    script = (
        "import godwit_probe\n"
        "from godwit_contracts import claim_safe_payload_issuer\n"
        "claim_safe_payload_issuer(claimant='someone-else')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0


@pytest.mark.xfail(strict=True, reason="CR-A6-graph-degree-hides-its-key-mode")
def test_a_hashed_graph_sketch_declares_its_key_mode() -> None:
    hasher = simulator_keyring().sketch_hasher(input_entropy_bits=64.0)
    sketch = GraphDegree.identity({}).with_hasher(hasher)
    assert sketch.params.get("key_mode") == "hashed"
