"""Run godwit-guard's suite in its own interpreter. Read ``conftest.py`` for why."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def test_guard_suite_passes_in_its_own_interpreter() -> None:
    env = {**os.environ, "GODWIT_GUARD_ISOLATED": "1"}
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(HERE), "-p", "no:cacheprovider", "-q"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=1800,
    )
    assert completed.returncode == 0, completed.stdout[-20000:] + completed.stderr[-5000:]
