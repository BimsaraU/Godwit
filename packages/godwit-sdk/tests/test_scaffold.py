"""``godwit-sdk new``: every kind's skeleton passes conformance, ruff and mypy as generated."""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from godwit_sdk.cli import main, scaffold

ROOT = Path(__file__).resolve().parents[3]
KINDS = ("source", "sketch", "detector", "feature", "context", "panel")


def _run(*argv: str, cwd: Path, extra_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    if extra_path is not None:
        env["PYTHONPATH"] = os.pathsep.join([str(extra_path), env.get("PYTHONPATH", "")])
    return subprocess.run(
        [sys.executable, "-m", *argv],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )


@pytest.mark.parametrize("kind", KINDS)
def test_a_generated_plugin_passes_its_own_tests_lint_and_types(kind: str, tmp_path: Path) -> None:
    root = scaffold(kind, name="mongo-db", namespace="acme", directory=tmp_path)
    tests = _run(
        "pytest", "-q", "-p", "no:cacheprovider", "tests", cwd=root, extra_path=root / "src"
    )
    assert tests.returncode == 0, tests.stdout[-5000:] + tests.stderr[-3000:]
    lint = _run("ruff", "check", "--config", str(ROOT / "pyproject.toml"), ".", cwd=root)
    assert lint.returncode == 0, lint.stdout
    types = _run("mypy", "--strict", "--no-incremental", "src", cwd=root)
    assert types.returncode == 0, types.stdout


def test_the_generated_entry_point_names_the_plugin(tmp_path: Path) -> None:
    root = scaffold("source", name="mongodb", namespace="acme", directory=tmp_path)
    project = tomllib.loads((root / "pyproject.toml").read_text("utf-8"))
    entry = project["project"]["entry-points"]["godwit.plugins"]
    assert entry == {"acme.mongodb": "godwit_source_mongodb:MongodbSource"}


def test_scaffolding_refuses_to_overwrite_and_validates_names(tmp_path: Path) -> None:
    scaffold("panel", name="tiles", namespace="acme", directory=tmp_path)
    with pytest.raises(FileExistsError):
        scaffold("panel", name="tiles", namespace="acme", directory=tmp_path)
    with pytest.raises(ValueError, match="name must be"):
        scaffold("panel", name="Tiles!", namespace="acme", directory=tmp_path)


def test_the_cli_reports_where_it_wrote(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["new", "context", "--name", "deploys", "--dir", str(tmp_path)]) == 0
    assert "godwit-context-deploys" in capsys.readouterr().out
    assert main(["list"]) == 0
    assert "examples.benford" in capsys.readouterr().out
