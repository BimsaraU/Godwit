"""Semantic versions, and the behaviour hash that forces a bump when output changes.

A3 lineage and A4 replay key on ``(detector, detector_version)``. If a detector's output
for identical input changes while its version stands still, stored lineage silently
points at behaviour that no longer exists. So every detector's golden scenario is run,
its result hashed, and the hash compared with ``behaviour_pins.json``:

* same version, same hash: fine;
* same version, different hash: **fail** -- bump ``VERSION``;
* different version: **fail** until the pin is updated with the new version and hash,
  so a bump is always a deliberate, reviewed edit of the pin file.

Run ``uv run python packages/godwit-detect/tests/test_registry.py`` to print fresh pins.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _detect_scenarios import SCENARIOS
from godwit_contracts.common import canonical_json, content_hash
from godwit_detect import REGISTRY, DetectionResult, lineage_version

PINS = Path(__file__).resolve().parent / "behaviour_pins.json"
SIGNIFICANT = 10


def _round(value: Any) -> Any:
    """Floats to ten significant figures, so last-bit libm differences do not move hashes."""
    if isinstance(value, float):
        if not math.isfinite(value) or value == 0.0:
            return repr(value)
        return f"{value:.{SIGNIFICANT}g}"
    if isinstance(value, dict):
        return {k: _round(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_round(v) for v in value]
    return value


def behaviour_digest(result: DetectionResult) -> str:
    return str(content_hash(canonical_json(_round(result.model_dump(mode="json"))), prefix="bhv"))


def _current() -> dict[str, dict[str, str]]:
    return {
        name: {"version": REGISTRY[name].VERSION, "digest": behaviour_digest(SCENARIOS[name]())}
        for name in sorted(REGISTRY)
    }


def test_every_detector_is_pinned() -> None:
    assert set(json.loads(PINS.read_text("utf-8"))) == set(REGISTRY)


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_behaviour_changes_only_with_a_version_bump(name: str) -> None:
    pin = json.loads(PINS.read_text("utf-8"))[name]
    version = REGISTRY[name].VERSION
    digest = behaviour_digest(SCENARIOS[name]())
    assert pin["version"] == version, (
        f"{name} is at {version} but pinned at {pin['version']}: update behaviour_pins.json "
        f"to version {version}, digest {digest}"
    )
    assert pin["digest"] == digest, (
        f"{name}'s output changed without a version bump. Bump {name}.VERSION (A3 lineage "
        f"and A4 replay key on it), then pin digest {digest}"
    )


def test_the_pin_notices_a_behaviour_change(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove the mechanism bites: a different default setting moves the hash."""
    from godwit_detect import DriftSettings, PsiDrift

    before = behaviour_digest(SCENARIOS["psi_drift"]())
    monkeypatch.setattr(
        PsiDrift, "default_settings", classmethod(lambda _cls: DriftSettings(bins=5))
    )
    assert behaviour_digest(SCENARIOS["psi_drift"]()) != before


def test_versions_are_semver_and_encode_monotonically() -> None:
    assert lineage_version("1.0.0") < lineage_version("1.0.1") < lineage_version("1.1.0")
    assert lineage_version("1.999.999") < lineage_version("2.0.0")
    with pytest.raises(ValueError, match="lineage encoding"):
        lineage_version("1.1000.0")


def test_names_are_unique_and_match_the_registry_keys() -> None:
    assert all(name == cls.NAME for name, cls in REGISTRY.items())


if __name__ == "__main__":
    print(json.dumps(_current(), indent=2, sort_keys=True))
