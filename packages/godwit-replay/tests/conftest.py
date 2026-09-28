"""Fixtures for the replay harness's own tests.

The golden drift fixture is materialised into an Iceberg table once per session, because
writing three commits costs more than every test that reads them put together. Everything
downstream of it is a pure function of that table, so sharing it does not share state.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from godwit_contracts.discovery import Candidate
from godwit_replay.datasets import LoadedDataset, materialise, resolve
from godwit_replay.driver import ReplayConfig
from godwit_replay.harness import HarnessResult, RunOptions, read_history, run_dataset
from godwit_source.metadata import SnapshotMetadata

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    # The workspace runs pytest with --import-mode=importlib, under which a test module
    # cannot import its siblings by package path. conftest is imported before the modules
    # beside it, so putting this directory on sys.path here is what makes
    # ``from _replay_support import ...`` work. The module is named per-package because the
    # first tests directory collected wins a shared name.
    sys.path.insert(0, _HERE)

from _replay_support import load_golden_candidates  # noqa: E402

CODE_VERSION = "godwit-replay/test"
SEED = 20240117


@pytest.fixture(scope="session")
def golden_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A directory holding the session's local Iceberg catalog and warehouse."""
    return tmp_path_factory.mktemp("replay-golden")


@pytest.fixture(scope="session")
def golden_loaded(golden_workspace: Path) -> LoadedDataset:
    """The golden drift fixture, materialised as three Iceberg commits."""
    return materialise(resolve("golden-drift"), workspace=golden_workspace)


@pytest.fixture(scope="session")
def golden_history(golden_loaded: LoadedDataset) -> tuple[SnapshotMetadata, ...]:
    """The metadata time-series for the golden table, re-timed to the data's own instants."""
    history, _ = read_history(golden_loaded)
    return history


@pytest.fixture(scope="session")
def golden_candidates(golden_dir: Path) -> tuple[Candidate, ...]:
    """The two golden candidates, whose segments quote real column values."""
    return load_golden_candidates(golden_dir)


@pytest.fixture
def config() -> ReplayConfig:
    """A default configuration with an explicit seed and code version."""
    return ReplayConfig(seed=SEED, code_version=CODE_VERSION, name="test")


@pytest.fixture(scope="session")
def golden_manifest(golden_dir: Path) -> Mapping[str, Any]:
    """The golden drift table's manifest, which states the drift and the control."""
    loaded = json.loads((golden_dir / "drift_table" / "manifest.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, Mapping)
    return loaded


@pytest.fixture
def golden_run(
    golden_workspace: Path,
    config: ReplayConfig,
    golden_manifest: Mapping[str, Any],
    frozen_now: Any,
) -> HarnessResult:
    """One end-to-end run over the golden fixture, with the fixture's own ground truth."""
    return run_dataset(
        "golden-drift",
        workspace=golden_workspace,
        config=config,
        as_of=frozen_now,
        options=RunOptions(golden_manifest=golden_manifest, repeats=1),
    )
