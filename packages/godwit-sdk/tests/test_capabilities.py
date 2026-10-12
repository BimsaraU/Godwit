"""Capability declaration and enforcement, and exception sanitising.

A guardrail, not a sandbox: these tests show what it stops and, in the last two, what it
deliberately cannot.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from godwit_contracts import Sensitivity
from godwit_sdk import (
    Capabilities,
    CapabilityViolationError,
    PluginFailedError,
    PluginKind,
    ResourceLimitError,
    ResourceLimits,
    TrustCategory,
)
from godwit_sdk.capabilities import PluginRunner


def runner(capabilities: Capabilities | None = None, **limits: int) -> PluginRunner:
    return PluginRunner("acme.test", capabilities or Capabilities(), ResourceLimits(**limits))


def test_undeclared_network_is_refused_before_a_name_is_resolved() -> None:
    with pytest.raises(CapabilityViolationError, match="network access"):
        runner().call("read", lambda: socket.getaddrinfo("orders.api.example.com", 443))


def test_a_declared_host_is_allowed_and_any_other_is_not() -> None:
    allowed = runner(Capabilities(network=("localhost",)))
    assert allowed.call("read", lambda: socket.getaddrinfo("localhost", 80))
    with pytest.raises(CapabilityViolationError, match="not declared"):
        allowed.call("read", lambda: socket.getaddrinfo("exfil.example.net", 443))


def test_wildcard_hosts_match_subdomains_only() -> None:
    allowed = runner(Capabilities(network=("*.example.com",)))
    with pytest.raises(CapabilityViolationError):
        allowed.call("read", lambda: socket.getaddrinfo("example.com.evil.net", 443))


def test_a_violation_the_plugin_swallowed_is_still_raised() -> None:
    def sneaky() -> str:
        try:
            socket.getaddrinfo("exfil.example.net", 443)
        except Exception:  # the plugin hides the refusal and carries on
            return "fine"
        return "unreachable"

    with pytest.raises(CapabilityViolationError):
        runner().call("read", sneaky)


def test_writing_a_file_needs_the_directory_declared(tmp_path: Path) -> None:
    target = tmp_path / "cache.bin"
    with pytest.raises(CapabilityViolationError, match="writing a file"):
        runner().call("read", lambda: target.write_bytes(b"rows"))
    declared = runner(Capabilities(filesystem=(str(tmp_path),)))
    declared.call("read", lambda: target.write_bytes(b"rows"))
    assert target.read_bytes() == b"rows"


def test_reading_an_arbitrary_file_is_refused_but_importing_code_is_not(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("x", encoding="utf-8")
    with pytest.raises(CapabilityViolationError, match="reading a file"):
        runner().call("read", lambda: secret.read_text(encoding="utf-8"))
    sys.modules.pop("colorsys", None)
    module = runner().call("read", lambda: __import__("colorsys"))
    assert module.__name__ == "colorsys"


def test_subprocess_and_threads_are_refused() -> None:
    with pytest.raises(CapabilityViolationError, match="subprocess"):
        runner().call("read", lambda: subprocess.run([sys.executable, "-V"], check=False))
    with pytest.raises(CapabilityViolationError, match="thread"):
        runner(Capabilities(subprocess=True)).call(
            "read", lambda: threading.Thread(target=lambda: None).start()
        )


def test_a_declared_subprocess_is_allowed() -> None:
    done = runner(Capabilities(subprocess=True)).call(
        "read", lambda: subprocess.run([sys.executable, "-c", "pass"], check=False)
    )
    assert done.returncode == 0


def test_a_memory_ceiling_stops_a_call_that_allocates_past_it() -> None:
    with pytest.raises(ResourceLimitError, match="max_memory_bytes"):
        runner(max_memory_bytes=1_000_000).call("read", lambda: bytearray(20_000_000))


def test_a_time_ceiling_stops_a_call_at_its_next_audited_operation() -> None:
    with pytest.raises(ResourceLimitError, match="max_seconds"):
        runner(max_seconds=0).call("read", lambda: sum(range(200_000)))


def test_a_plugin_exception_is_defused_and_its_text_kept_tainted() -> None:
    row = "ERROR: duplicate key (customer_ssn)=(100-40-1000) already exists"

    def fail() -> None:
        raise ValueError(row)

    with pytest.raises(PluginFailedError) as error:
        runner().call("read", fail)
    assert "100-40-1000" not in str(error.value)
    assert "100-40-1000" not in repr(error.value)
    assert error.value.__context__ is None
    assert error.value.__cause__ is None
    assert error.value.classification == "constraint_violation"
    assert error.value.original is not None
    assert error.value.original.sensitivity is Sensitivity.DATA_VALUE
    assert error.value.original.reveal() == row


def test_trust_categories_are_stated_plainly() -> None:
    from godwit_sdk.examples.benford import BenfordDetector
    from godwit_sdk.examples.bloom import BloomMembership
    from godwit_sdk.examples.rest_source import RestOrdersSource

    assert RestOrdersSource.plugin_info().trust_category is TrustCategory.ISOLATE
    assert BloomMembership.plugin_info().trust_category is TrustCategory.IN_PROCESS
    assert BenfordDetector.plugin_info().trust_category is TrustCategory.IN_PROCESS
    assert BenfordDetector.plugin_info().kind is PluginKind.DETECTOR


def test_honest_limit_work_outside_the_scope_is_not_seen() -> None:
    """Code a plugin runs at import time, or that a caller runs for it, is unchecked."""
    assert socket.getaddrinfo("localhost", 80)  # no scope active: nothing to enforce


def test_honest_limit_native_io_bypasses_the_audit_points(tmp_path: Path) -> None:
    """SQLite opens its file in C, without CPython's ``open`` audit event."""
    import sqlite3

    database = tmp_path / "native.db"
    connection = runner().call("read", lambda: sqlite3.connect(database))
    connection.close()
    assert database.exists()
