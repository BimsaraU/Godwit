"""No clock, no randomness, no network, no LLM, and only two ``.reveal()`` call sites.

A source scan, because "we never read the clock" is a statement about code paths and an
example test cannot prove it.
"""

from __future__ import annotations

import ast
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src" / "godwit_context"
FORBIDDEN_MODULES = {"random", "time", "socket", "urllib", "requests", "httpx", "secrets"}
FORBIDDEN_CALLS = {"now", "utcnow", "today", "time", "monotonic", "perf_counter"}


def _trees() -> list[tuple[Path, ast.Module]]:
    return [(p, ast.parse(p.read_text(encoding="utf-8"))) for p in sorted(SOURCE.glob("*.py"))]


def test_no_clock_randomness_or_network() -> None:
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for name in names:
                    assert name.split(".")[0] not in FORBIDDEN_MODULES, f"{path.name}: {name}"
                    assert "llm" not in name, f"{path.name} imports {name}"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in FORBIDDEN_CALLS, f"{path.name}: .{node.func.attr}()"


def test_reveal_is_called_in_one_module_only() -> None:
    sites = {
        path.name
        for path, tree in _trees()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "reveal"
    }
    assert sites == {"_unwrap.py"}
