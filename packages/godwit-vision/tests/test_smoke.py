"""Placeholder so a fresh checkout has a green pytest run for every package."""

from godwit_vision import __version__


def test_package_imports() -> None:
    assert __version__ == "0.1.0"
