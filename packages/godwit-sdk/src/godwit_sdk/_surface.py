"""The public API surface, rendered as data, for the compatibility snapshot test.

Every name in ``godwit_sdk.__all__`` is described: a function by its signature, a class
by its constructor and the signature of every public member, an enum by its values, a
constant by its value. ``tests/test_api_surface.py`` compares this against
``tests/api_surface.json`` and fails when they differ while the version has not moved.

Regenerate the snapshot after a deliberate, version-bumped change::

    uv run python -m godwit_sdk._surface > packages/godwit-sdk/tests/api_surface.json
"""

from __future__ import annotations

import enum
import importlib
import inspect
import json
import sys

__all__ = ["surface"]


def _signature(obj: object) -> str:
    if not callable(obj):
        return "<not callable>"
    try:
        return str(inspect.signature(obj))
    except (TypeError, ValueError):
        return "<no signature>"


def _member(cls: type, name: str) -> str:
    raw = inspect.getattr_static(cls, name)
    if isinstance(raw, property):
        return "property"
    if isinstance(raw, classmethod | staticmethod):
        return f"{type(raw).__name__}{_signature(getattr(cls, name))}"
    if callable(raw):
        return f"method{_signature(raw)}"
    return f"attribute: {type(raw).__name__}"


def _describe(obj: object) -> object:
    if isinstance(obj, type) and issubclass(obj, enum.Enum):
        return {"enum": sorted(str(member.value) for member in obj)}
    if isinstance(obj, type):
        members = {
            name: _member(obj, name)
            for name in sorted(dir(obj))
            if not name.startswith("_") and not name.startswith("model_")
        }
        return {"class": _signature(obj), "members": members}
    if callable(obj):
        return {"function": _signature(obj)}
    return {"value": repr(obj)}


def surface() -> dict[str, object]:
    """The SDK's version and the description of every public name."""
    sdk = importlib.import_module("godwit_sdk")
    return {
        "version": sdk.__version__,
        "surface": {name: _describe(getattr(sdk, name)) for name in sdk.__all__},
    }


if __name__ == "__main__":
    sys.stdout.write(json.dumps(surface(), indent=1, sort_keys=True) + "\n")
