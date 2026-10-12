"""The compatibility promise, enforced: the public surface changes only with the version."""

from __future__ import annotations

import json
from pathlib import Path

import godwit_sdk
from godwit_sdk._surface import surface

SNAPSHOT = Path(__file__).with_name("api_surface.json")
REGENERATE = "uv run python -m godwit_sdk._surface > packages/godwit-sdk/tests/api_surface.json"


def test_the_public_surface_matches_the_snapshot_for_this_version() -> None:
    recorded = json.loads(SNAPSHOT.read_text("utf-8"))
    current = json.loads(json.dumps(surface()))
    changed = sorted(
        name
        for name in set(recorded["surface"]) | set(current["surface"])
        if recorded["surface"].get(name) != current["surface"].get(name)
    )
    if recorded["version"] == current["version"]:
        assert not changed, (
            f"public names changed without a version bump: {changed}. If the change is "
            f"deliberate, bump godwit_sdk._version.__version__ and run: {REGENERATE}"
        )
    else:
        raise AssertionError(
            f"the snapshot records {recorded['version']} but the SDK is "
            f"{current['version']}; review the changes ({changed}) and run: {REGENERATE}"
        )


def test_everything_public_is_exported_explicitly() -> None:
    assert sorted(godwit_sdk.__all__) == sorted(set(godwit_sdk.__all__))
    for name in godwit_sdk.__all__:
        assert hasattr(godwit_sdk, name), name


def test_the_snapshot_would_catch_a_changed_signature(monkeypatch: object) -> None:
    import pytest

    patch = pytest.MonkeyPatch()
    try:
        patch.setattr(godwit_sdk, "check_compatible", lambda _info: None)
        assert surface()["surface"] != json.loads(SNAPSHOT.read_text("utf-8"))["surface"]
    finally:
        patch.undo()
