"""Fixtures for godwit-sdk's tests, and the process isolation they need.

WHY THESE TESTS RUN IN THEIR OWN INTERPRETER
--------------------------------------------
A source plugin's first probe imports ``godwit_probe``, which imports ``godwit_guard``,
and importing ``godwit_guard`` claims the process's single ``SafePayloadIssuer``. The
contracts suite claims the same issuer for itself, so in one pytest process whichever
runs first breaks the other. godwit-guard and godwit-probe hit this first and solved it
this way; see ``docs/change-requests/CR-A5-issuer-claim-is-process-global.md``.

So when this directory is collected as part of a larger run, every module here except
``test_isolated_suite.py`` is skipped at collection, and that one test re-runs this
directory in a child interpreter with ``GODWIT_SDK_ISOLATED=1``.
"""

from __future__ import annotations

import datetime as _dt
import os
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
ISOLATED = os.environ.get("GODWIT_SDK_ISOLATED") == "1"
LAUNCHER = "test_isolated_suite.py"

if str(_HERE) not in sys.path:
    # importlib mode cannot `import conftest`; support modules are imported by name, and
    # each package's are distinct (this one's start with _sdk_).
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
    """The one instant these tests use."""
    return frozen_now


@pytest.fixture(scope="session")
def godwit_sentinels() -> tuple[str, ...]:
    """The PII torture fixture's distinctive values. Imported lazily: the kit imports guard."""
    from godwit_sdk.testing import torture

    return torture().sentinels
