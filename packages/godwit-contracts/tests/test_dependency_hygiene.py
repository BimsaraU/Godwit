"""godwit-contracts depends on Pydantic and the standard library. Nothing else.

Acceptance criterion from the brief: "No contract model imports anything outside
contracts and the stdlib." Pydantic is the exception the stack mandates.

The reason this is a test rather than a convention: contracts is imported by all
seventeen other packages. One dependency added here is a dependency added everywhere,
including inside the perimeter of a bank that reviews every transitive package.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "godwit_contracts"
ALLOWED_THIRD_PARTY = {"pydantic"}
MODULES = sorted(SRC.glob("*.py"))


def top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_there_are_modules_to_check() -> None:
    assert len(MODULES) >= 12


@pytest.mark.parametrize("path", MODULES, ids=lambda path: path.name)
def test_only_stdlib_and_pydantic(path: Path) -> None:
    foreign = {
        name
        for name in top_level_imports(path)
        if name not in sys.stdlib_module_names
        and name not in ALLOWED_THIRD_PARTY
        and name != "godwit_contracts"
    }
    assert not foreign, f"{path.name} imports {sorted(foreign)}"


@pytest.mark.parametrize("path", MODULES, ids=lambda path: path.name)
def test_no_other_godwit_package_is_imported(path: Path) -> None:
    """Contracts sits below everything. An import the other way is a dependency cycle
    waiting for the second package that needs it."""
    godwit = {name for name in top_level_imports(path) if name.startswith("godwit_")} - {
        "godwit_contracts"
    }
    assert not godwit, f"{path.name} imports {sorted(godwit)}"


@pytest.mark.parametrize("path", MODULES, ids=lambda path: path.name)
def test_no_io_no_clock_no_randomness(path: Path) -> None:
    """Contracts are data definitions and validation. Nothing else.

    Determinism (universal rule 5) starts here: if contracts could read a clock, every
    default value in the system would be a reproducibility hazard.
    """
    banned = {
        "socket",
        "http",
        "urllib",
        "requests",
        "httpx",
        "sqlite3",
        "subprocess",
        "random",
        "secrets",
        "os",
        "shutil",
        "asyncio",
        "logging",
        "time",
    }
    found = top_level_imports(path) & banned
    assert not found, f"{path.name} imports {sorted(found)}"


def test_the_declared_dependency_list_matches_reality() -> None:
    """pyproject must not quietly grow a dependency the tests above would miss."""
    pyproject = (SRC.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    line = next(text for text in pyproject.splitlines() if text.startswith("dependencies = "))
    assert "pydantic" in line
    for forbidden in ("pyarrow", "sqlalchemy", "fastapi", "duckdb", "lightgbm", "godwit-"):
        assert forbidden not in line, f"contracts must not depend on {forbidden}"


def test_no_suppression_comments_in_contracts_source() -> None:
    """Zero suppressions is a stated requirement, so check it rather than trust it.

    ``# type: ignore`` and ``# noqa`` in the contracts layer would mean the types the
    other seventeen packages rely on are only approximately true.
    """
    offenders: list[str] = []
    for path in MODULES:
        for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "# type: ignore" in text or "# noqa" in text:
                offenders.append(f"{path.name}:{number}")
    assert not offenders, "suppressions found: " + ", ".join(offenders)
