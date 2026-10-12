"""The plugin-facing logger: safe by construction, checked by mypy and at runtime."""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from godwit_contracts import Acquisition, data_value
from godwit_sdk import PluginLogger, ProbeRefusedError
from godwit_sdk.plugin import PluginBase

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CASES = HERE / "typing_cases" / "must_fail.py"
_ERROR = re.compile(r"^(?P<file>.+?):(?P<line>\d+): error: .*\[(?P<code>[a-z-]+)\]$")


def _records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [
        json.loads(r.getMessage()) for r in caplog.records if r.name.startswith("godwit.plugins")
    ]


def test_tainted_fields_are_withheld_and_plain_strings_refused(
    caplog: pytest.LogCaptureFixture,
) -> None:
    log = PluginLogger("acme.demo")
    secret = data_value("Aoife Brennan", acquisition=Acquisition.USER_SUPPLIED)
    with caplog.at_level(logging.DEBUG):
        log.info("probe.read", rows=3, ratio=0.5, ok=True, who=secret, name="Aoife Brennan")
    (record,) = _records(caplog)
    assert record["who"] == "<withheld:data_value>"
    assert record["name"] == "<refused>"
    assert record["rows"] == 3
    assert "Aoife" not in caplog.text


def test_an_event_that_is_not_a_plain_label_is_refused(caplog: pytest.LogCaptureFixture) -> None:
    log = PluginLogger("acme.demo")
    with caplog.at_level(logging.DEBUG):
        log.warning("read aoife.brennan@northfield-bank.test")
    (record,) = _records(caplog)
    assert record["event"] == "<refused>"


def test_enums_are_rendered_by_value(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        PluginLogger("acme.demo").error("probe.refused", why=ProbeRefusedError("x").reason == "x")
    assert _records(caplog)[0]["why"] is True


def test_there_is_no_route_to_the_raw_logger() -> None:
    log = PluginLogger("acme.demo")
    public = [name for name in dir(log) if not name.startswith("_")]
    assert sorted(public) == ["debug", "error", "info", "warning"]
    assert not any(
        isinstance(getattr(PluginBase, n, None), logging.Logger) for n in dir(PluginBase)
    )


def test_the_type_checker_rejects_values_in_log_calls() -> None:
    expected: dict[int, str] = {}
    for number, text in enumerate(CASES.read_text(encoding="utf-8").splitlines(), start=1):
        marker = re.search(r"#\s*EXPECT:\s*([a-z-]+)\s*$", text)
        if marker:
            expected[number] = marker.group(1)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--strict",
            "--no-incremental",
            "--no-color-output",
            "--no-error-summary",
            "--hide-error-context",
            str(CASES),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    found: dict[int, list[str]] = {}
    for line in result.stdout.splitlines():
        match = _ERROR.match(line.strip())
        if match and Path(match.group("file")).name == CASES.name:
            found.setdefault(int(match.group("line")), []).append(match.group("code"))
    missing = {n: c for n, c in expected.items() if c not in found.get(n, [])}
    unexpected = {n: c for n, c in found.items() if n not in expected}
    assert len(expected) == 3
    assert not missing, (missing, result.stdout)
    assert not unexpected, (unexpected, result.stdout)
