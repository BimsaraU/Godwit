"""The conformance kit: a pytest plugin that runs the full battery against one plugin.

USE IT
------
In your plugin's test suite, one line per plugin::

    # tests/test_conformance.py
    from godwit_sdk.testing import conformance_suite
    from my_package import MongoSource

    TestMongoSourceConformance = conformance_suite(MongoSource)

and ``pytest`` runs every check that applies to the plugin's kind, one test each, so a
failure names the check. Detectors take ``pins=Path(...)`` to pin their output per
version. Outside pytest, :func:`run_conformance` returns a :class:`ConformanceReport`,
and ``godwit-sdk check`` runs the battery over every installed plugin.

Enable the fixtures below with ``pytest_plugins = ["godwit_sdk.testing"]`` in a
``conftest.py``. The kit is deliberately *not* auto-registered through the ``pytest11``
entry point: it imports ``godwit_guard``, which claims the process's single
``SafePayloadIssuer``, and auto-loading would do that inside every pytest session in any
environment where the SDK is installed -- including the core repository's own.

WHAT IT CHECKS
--------------
Every kind: registration into a fresh registry, and *static hygiene* -- the plugin's
module may not import :mod:`logging`, call ``print``, or touch ``sys.stdout``,
``sys.stderr`` or ``os.write``. Then, per kind:

* **source** -- ``SourceAdapter`` conformance; profiling from metadata only; every probe
  over the PII torture table completes; BLIND and unclassified columns are refused and
  never requested from ``read``; zero budget refuses before any read; cancellation;
  cost accounting; byte-identical bundles across instances; JSON and codec round trips;
  and the leak test.
* **sketch** -- the monoid laws again, under :mod:`hypothesis`; ``Sketch`` conformance;
  the leak test over a sketch fed the fixture's strings.
* **detector** -- the contract adapter and ``ROLES``; minimum support (``examine`` never
  runs on a thin sketch); declared test counts; determinism and round trips; the leak
  test over poisoned categorical sketches; optional version pinning.
* **feature** -- the point-in-time property, directly: rows outside each event's window
  are changed and no value may move; determinism; round trips; leaks.
* **context** -- window filtering, tainted labels, determinism, round trips, leaks.
* **panel** -- a payload is cleared through the real gate and rendered; determinism;
  round trip; leaks.

THE LEAK TEST
-------------
Every channel a process writes text to -- logs at every level, stdout, stderr, warnings
-- is captured while the plugin runs over A0's PII torture fixture, along with the text
of anything it raised and a rendering of what it returned (minus payloads that are
DATA_VALUE by declaration). None of the fixture's distinctive values may appear. This is
a backstop: the control is the typed taint and the safe logger. A plugin that passes it
has not been proven safe; a plugin that fails it is certainly not.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from godwit_sdk.plugin import PluginBase, PluginKind
from godwit_sdk.testing._battery import CHECKS, Check, check_version_pin
from godwit_sdk.testing._capture import Capture, capture_egress
from godwit_sdk.testing._torture import Torture, torture

__all__ = [
    "Capture",
    "CheckResult",
    "ConformanceReport",
    "Torture",
    "capture_egress",
    "conformance_suite",
    "godwit_sentinels",
    "godwit_torture",
    "run_conformance",
    "torture",
]


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One check's outcome. ``detail`` is the failure message, or empty."""

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    """Every check run against one plugin."""

    plugin: str
    results: tuple[CheckResult, ...]

    @property
    def passed(self) -> bool:
        """True when every check passed."""
        return all(result.passed for result in self.results)

    def render(self) -> str:
        """A plain-text report, one line per check."""
        lines = [f"{self.plugin}: {'PASS' if self.passed else 'FAIL'}"]
        for result in self.results:
            lines.append(f"  [{'ok' if result.passed else 'FAIL'}] {result.name}")
            if result.detail:
                lines.append(f"        {result.detail}")
        return "\n".join(lines)


def _checks(plugin: type[PluginBase], pins: Path | None) -> list[tuple[str, Check]]:
    info = plugin.plugin_info()
    checks = list(CHECKS[info.kind])
    if pins is not None and info.kind is PluginKind.DETECTOR:
        checks.append(("version_pin", lambda cls: check_version_pin(cls, pins)))
    return checks


def run_conformance(plugin: type[PluginBase], *, pins: Path | None = None) -> ConformanceReport:
    """Run the battery and collect the results instead of raising."""
    results: list[CheckResult] = []
    for name, check in _checks(plugin, pins):
        try:
            check(plugin)
        except AssertionError as failure:
            results.append(CheckResult(name, passed=False, detail=str(failure)))
        except Exception as error:  # a check crashed on the plugin; report the type only
            results.append(CheckResult(name, passed=False, detail=f"raised {type(error).__name__}"))
        else:
            results.append(CheckResult(name, passed=True))
    return ConformanceReport(plugin.plugin_info().qualified_name, tuple(results))


def conformance_suite(plugin: type[PluginBase], *, pins: Path | None = None) -> type:
    """A pytest test class with one test per applicable check.

    Assign it to a module-level name starting with ``Test``; see the module docstring.
    """

    def make(check: Check) -> object:
        def test(self: object) -> None:
            del self
            check(plugin)

        return test

    members: dict[str, object] = {
        f"test_{name}": make(check) for name, check in _checks(plugin, pins)
    }
    members["__doc__"] = f"Godwit SDK conformance battery for {plugin.__name__}."
    return type(f"Conformance{plugin.__name__}", (), members)


@pytest.fixture(scope="session")
def godwit_torture() -> Torture:
    """A0's PII torture fixture: the table, its classes and the strings that must not leak."""
    return torture()


@pytest.fixture(scope="session")
def godwit_sentinels(godwit_torture: Torture) -> tuple[str, ...]:
    """The fixture's distinctive values, for your own leak assertions."""
    return godwit_torture.sentinels
