"""Acceptance: an adapter for a data source nobody mentioned, written from the docs alone.

See ``_sdk_sqlite_source.py`` and HANDOFF.md ("Dogfooding report") for where the docs
failed while writing it.
"""

from __future__ import annotations

from _sdk_sqlite_source import SqliteSource
from godwit_sdk import TrustCategory
from godwit_sdk.testing import run_conformance


def test_the_sqlite_adapter_passes_the_full_battery() -> None:
    report = run_conformance(SqliteSource)
    assert report.passed, report.render()


def test_it_is_stated_plainly_that_it_should_run_isolated() -> None:
    assert SqliteSource.plugin_info().trust_category is TrustCategory.ISOLATE
