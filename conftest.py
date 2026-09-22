"""Repo-wide pytest fixtures.

Every package's tests get these for free, so that seventeen packages do not each invent
their own way of locating the golden data or their own idea of "now".

Owner: A0. If you need a fixture here that is specific to your package, put it in your
package's own ``tests/conftest.py`` instead.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent


@pytest.fixture(scope="session")
def golden_dir() -> Path:
    """Path to ``tests/golden``. Regenerate its contents with ``make seed``."""
    return ROOT / "tests" / "golden"


@pytest.fixture(scope="session")
def golden_json(golden_dir: Path) -> Callable[[str], Any]:
    """Load a JSON fixture by path relative to ``tests/golden``."""

    def _load(relative: str) -> Any:
        return json.loads((golden_dir / relative).read_text(encoding="utf-8"))

    return _load


@pytest.fixture(scope="session")
def frozen_now() -> _dt.datetime:
    """The one instant tests use when they need a clock.

    Determinism (universal rule 5) means no test reads the wall clock either. If your
    test needs a different instant, derive it from this one.
    """
    return _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
