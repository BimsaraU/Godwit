"""Fixtures for godwit-guard's tests, and the process isolation they need.

WHY THESE TESTS RUN IN THEIR OWN INTERPRETER
--------------------------------------------
Importing ``godwit_guard`` claims the process's single ``SafePayloadIssuer``, as the
contract says it must. The contracts test suite claims the same issuer for itself in a
session fixture. In one pytest process, whichever runs first makes the other fail. See
``docs/change-requests/CR-A5-issuer-claim-is-process-global.md``.

So when this directory is collected as part of a larger run, every module here except
``test_isolated_suite.py`` is skipped at collection, and that one test re-runs this
directory in a child interpreter with ``GODWIT_GUARD_ISOLATED=1``. Inside the child,
the modules collect normally and the launcher skips itself. Running
``pytest packages/godwit-guard/tests`` directly goes through the same launcher.
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
ISOLATED = os.environ.get("GODWIT_GUARD_ISOLATED") == "1"
LAUNCHER = "test_isolated_suite.py"

if str(_HERE) not in sys.path:
    # importlib mode cannot `import conftest`; the support module is imported by name,
    # and every package's name is distinct (godwit-store's is _store_support, and so on).
    sys.path.insert(0, str(_HERE))


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """Collect this directory in the child interpreter only; the launcher in the parent."""
    del config
    if collection_path.parent != _HERE or collection_path.suffix != ".py":
        return None
    if not collection_path.name.startswith("test_"):
        return None
    is_launcher = collection_path.name == LAUNCHER
    return is_launcher if ISOLATED else not is_launcher


@pytest.fixture
def at(frozen_now: _dt.datetime) -> _dt.datetime:
    """The one instant these tests use, derived from the repository-wide fixture."""
    return frozen_now
