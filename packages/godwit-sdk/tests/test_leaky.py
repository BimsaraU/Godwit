"""Acceptance: a deliberately leaky plugin is caught by the conformance kit."""

from __future__ import annotations

import pytest
from _sdk_leaky import LoggingDetector, PrintingSource
from _sdk_leaky_dynamic import SneakyContext, SneakySource
from godwit_sdk import PluginBase
from godwit_sdk.testing import ConformanceReport, run_conformance


def _failed(report: ConformanceReport) -> set[str]:
    return {result.name for result in report.results if not result.passed}


def test_a_source_that_prints_rows_fails_static_hygiene_and_the_leak_test() -> None:
    report = run_conformance(PrintingSource)
    assert {"static_hygiene", "leaks"} <= _failed(report)
    detail = next(r.detail for r in report.results if r.name == "static_hygiene")
    assert "print() on line" in detail


def test_a_detector_with_a_raw_logger_fails_static_hygiene_and_the_leak_test() -> None:
    report = run_conformance(LoggingDetector)
    failed = _failed(report)
    assert "static_hygiene" in failed
    assert "import logging" in next(r.detail for r in report.results if r.name == "static_hygiene")
    assert "leaks" in failed


@pytest.mark.parametrize("plugin", [SneakySource, SneakyContext])
def test_a_plugin_that_evades_the_static_check_is_caught_at_runtime(
    plugin: type[PluginBase],
) -> None:
    report = run_conformance(plugin)
    failed = _failed(report)
    assert "static_hygiene" not in failed
    assert "leaks" in failed


def test_a_failure_message_never_quotes_the_leaked_value(
    godwit_sentinels: tuple[str, ...],
) -> None:
    report = run_conformance(SneakySource)
    rendered = report.render()
    assert not any(value in rendered for value in godwit_sentinels)


def test_the_reference_plugins_are_not_flagged() -> None:
    from godwit_sdk.examples.benford import BenfordDetector
    from godwit_sdk.examples.rest_source import RestOrdersSource

    for plugin in (RestOrdersSource, BenfordDetector):
        assert run_conformance(plugin).passed
