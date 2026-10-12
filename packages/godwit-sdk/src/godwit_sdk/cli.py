"""``godwit-sdk``: scaffold a plugin, list installed plugins, run conformance over them.

::

    godwit-sdk new source --name mongodb --namespace acme   # a working, tested skeleton
    godwit-sdk list                                          # what is installed
    godwit-sdk check                                         # the battery, over all of them

``new`` writes ``godwit-<kind>-<name>/`` with a ``pyproject.toml`` that registers the
entry point, the plugin module, a conformance test and a README. It passes the battery
as generated. ``check`` exits non-zero when any plugin fails to load or fails a check.
"""

from __future__ import annotations

import argparse
import importlib
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from godwit_sdk._templates import CONFTEST, PLUGINS, PYPROJECT, README, TEST_CONFORMANCE
from godwit_sdk._version import __version__
from godwit_sdk.registry import PluginRegistry, discover

__all__ = ["main", "scaffold"]

_NAME: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*\Z")


def _camel(name: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[-_]", name))


def scaffold(kind: str, *, name: str, namespace: str, directory: Path) -> Path:
    """Write a new plugin package under ``directory`` and return its root."""
    if kind not in PLUGINS:
        raise ValueError(f"kind must be one of {sorted(PLUGINS)}")
    for label, value in (("name", name), ("namespace", namespace)):
        if not _NAME.match(value):
            raise ValueError(f"{label} must be lowercase letters and digits joined by - or _")
    template, suffix = PLUGINS[kind]
    module = f"godwit_{kind}_{name.replace('-', '_')}"
    cls = f"{_camel(name)}{suffix}"
    dist = f"godwit-{kind}-{name}"
    pins = kind == "detector"
    replacements = {
        "__DIST__": dist,
        "__MODULE__": module,
        "__CLASS__": cls,
        "__QUALIFIED__": f"{namespace}.{name}",
        "__NAMESPACE__": namespace,
        "__NAME__": name,
        "__KIND__": kind,
        "__SDK__": __version__,
        "__SUMMARY__": f"A {kind} plugin for Godwit.",
        "__PINS_IMPORT__": "\nfrom pathlib import Path\n" if pins else "",
        "__PINS_ARG__": (
            '\n    pins=Path(__file__).with_name("behaviour_pins.json"),' if pins else ""
        ),
    }

    def fill(text: str) -> str:
        for token, value in replacements.items():
            text = text.replace(token, value)
        return text

    root = directory / dist
    if root.exists():
        raise FileExistsError(f"{root} already exists; refusing to overwrite it")
    files = {
        root / "pyproject.toml": PYPROJECT,
        root / "README.md": README,
        root / "src" / module / "__init__.py": template,
        root / "src" / module / "py.typed": "",
        root / "tests" / "conftest.py": CONFTEST,
        root / "tests" / "test_conformance.py": TEST_CONFORMANCE,
    }
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(fill(text), encoding="utf-8")
    return root


def _list() -> int:
    registry = PluginRegistry()
    report = discover(registry)
    for info in report.loaded:
        capabilities = ", ".join(info.capabilities.describe()) or "none"
        print(
            f"{info.qualified_name} {info.version} [{info.kind.value}] "
            f"trust={info.trust_category.value} capabilities={capabilities}"
        )
    for entry, reason in report.failed:
        print(f"{entry}: NOT LOADED\n  {reason}")
    return 1 if report.failed else 0


def _check() -> int:
    # Imported here: the kit needs pytest and hypothesis (the `testing` extra), and
    # `new` and `list` must work without them.
    run_conformance = importlib.import_module("godwit_sdk.testing").run_conformance
    registry = PluginRegistry()
    report = discover(registry)
    failed = bool(report.failed)
    for entry, reason in report.failed:
        print(f"{entry}: NOT LOADED\n  {reason}")
    for info in report.loaded:
        result = run_conformance(registry.get(info.kind, info.qualified_name))
        print(result.render())
        failed = failed or not result.passed
    return 1 if failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``godwit-sdk`` command."""
    parser = argparse.ArgumentParser(prog="godwit-sdk", description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    new = commands.add_parser("new", help="scaffold a plugin package")
    new.add_argument("kind", choices=sorted(PLUGINS))
    new.add_argument("--name", required=True)
    new.add_argument("--namespace", default="local")
    new.add_argument("--dir", type=Path, default=Path())
    commands.add_parser("list", help="list installed plugins")
    commands.add_parser("check", help="run the conformance battery over installed plugins")
    args = parser.parse_args(argv)
    if args.command == "new":
        root = scaffold(args.kind, name=args.name, namespace=args.namespace, directory=args.dir)
        print(f"created {root}\nnext: cd {root} && pip install -e '.[test]' && pytest")
        return 0
    if args.command == "list":
        return _list()
    return _check()


if __name__ == "__main__":
    sys.exit(main())
