"""The xfail that records what A1 needed and could not have.

See ``docs/change-requests/CR-A1-contracts-missing.md``. When ``godwit-contracts`` lands,
this test passes, ``godwit_source/_contracts_stub.py`` becomes dead code, and both should be
deleted in the same change.
"""

from __future__ import annotations

import importlib.util

import pytest

from godwit_source import CONTRACTS_ARE_PROVISIONAL


@pytest.mark.xfail(
    importlib.util.find_spec("godwit_contracts") is None,
    reason="godwit-contracts (A0) does not exist yet; see CR-A1-contracts-missing",
    strict=True,
)
def test_contracts_package_exists() -> None:
    import godwit_contracts  # noqa: F401

    assert not CONTRACTS_ARE_PROVISIONAL


def test_every_module_imports_contracts_through_the_switch() -> None:
    """No module may import the stub directly, or the swap to A0's types would miss it."""
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "src" / "godwit_source"
    offenders = [
        path.name
        for path in src.glob("*.py")
        if path.name not in {"_contracts.py", "_contracts_stub.py"}
        and "_contracts_stub" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
