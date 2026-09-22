"""Static guarantees, checked by actually running mypy.

A type-level invariant that nobody runs a type checker against is a comment. This test
runs mypy over ``typing_cases/must_fail.py`` and asserts that each line marked
``# EXPECT: <code>`` produced exactly that error -- and, just as importantly, that no
unmarked line produced one.

It is slow by test standards (a few seconds for a mypy process). It is worth it: these
are the guarantees the brief asks for, and they are invisible to pytest otherwise.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

CASES = Path(__file__).resolve().parent / "typing_cases" / "must_fail.py"
REPO_ROOT = Path(__file__).resolve().parents[3]
_ERROR_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+): error: .*\[(?P<code>[a-z-]+)\]$")


def expected_errors() -> dict[int, str]:
    """Line number -> expected mypy error code, read from the EXPECT markers."""
    expected: dict[int, str] = {}
    for number, text in enumerate(CASES.read_text(encoding="utf-8").splitlines(), start=1):
        marker = re.search(r"#\s*EXPECT:\s*([a-z-]+)\s*$", text)
        if marker:
            expected[number] = marker.group(1)
    return expected


@pytest.fixture(scope="module")
def mypy_errors() -> dict[int, list[str]]:
    """Run mypy over the case file and index the error codes by line."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--no-incremental",
            "--hide-error-context",
            "--no-color-output",
            "--no-error-summary",
            str(CASES),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    if result.returncode == 0:
        pytest.fail(
            "mypy reported no errors for typing_cases/must_fail.py. Every static "
            "guarantee in this file has been lost.\n" + result.stdout
        )

    found: dict[int, list[str]] = {}
    for line in result.stdout.splitlines():
        match = _ERROR_RE.match(line.strip())
        if match and Path(match.group("file")).name == CASES.name:
            found.setdefault(int(match.group("line")), []).append(match.group("code"))
    return found


def test_the_case_file_actually_has_markers() -> None:
    """Guard against the markers being deleted and this suite quietly passing."""
    assert len(expected_errors()) >= 6


def test_every_expected_error_is_reported(mypy_errors: dict[int, list[str]]) -> None:
    missing: list[str] = []
    for line, code in expected_errors().items():
        if code not in mypy_errors.get(line, []):
            missing.append(f"line {line}: expected [{code}], mypy gave {mypy_errors.get(line, [])}")
    assert not missing, "static guarantees lost:\n" + "\n".join(missing)


def test_no_unexpected_errors(mypy_errors: dict[int, list[str]]) -> None:
    """The case file must fail only where it says it will.

    An error on an unmarked line means the fixture itself is broken, and the marked
    assertions above can no longer be trusted.
    """
    expected = expected_errors()
    unexpected = {line: codes for line, codes in mypy_errors.items() if line not in expected}
    assert not unexpected, f"unexpected mypy errors: {unexpected}"


def test_tainted_is_not_a_subclass_of_its_payload() -> None:
    """The runtime counterpart: no structural escape hatch either.

    If ``Tainted[str]`` were a ``str`` subclass, every f-string, every logger call and
    every SQL builder in the codebase would silently accept one.
    """
    from godwit_contracts import Acquisition, Tainted, data_value

    tainted = data_value("Aoife Brennan", acquisition=Acquisition.PG_STATS_MCV)
    assert not isinstance(tainted, str)
    assert str not in type(tainted).__mro__
    assert isinstance(tainted, Tainted)
