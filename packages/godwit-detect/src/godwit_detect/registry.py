"""Every detector, by name, with its semantic version.

A3 lineage and A4 replay key on ``(detector, detector_version)``. So a change that could
alter a detector's output for identical input **must** bump its ``VERSION``, and
``tests/test_registry.py`` enforces that: it runs every detector over golden fixtures,
hashes the result, and fails when the hash moves while the version stands still. The
pins live in ``tests/behaviour_pins.json``, next to the test that reads them.
"""

from __future__ import annotations

import re
from typing import Any, Final

from godwit_detect.base import DetectorBase
from godwit_detect.correlation import CorrelationShift
from godwit_detect.drift import JensenShannonDrift, PsiDrift, WassersteinDrift
from godwit_detect.evidence import lineage_version
from godwit_detect.graph import GraphAnomaly
from godwit_detect.heavy import HeavyHitterShift
from godwit_detect.scoring import CopodScorer, EcodScorer, MatrixProfile
from godwit_detect.segments import SegmentDivergence

__all__ = ["DETECTORS", "REGISTRY", "detector"]

_SEMVER: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")

DETECTORS: Final[tuple[type[DetectorBase[Any]], ...]] = (
    PsiDrift,
    WassersteinDrift,
    JensenShannonDrift,
    HeavyHitterShift,
    SegmentDivergence,
    CorrelationShift,
    GraphAnomaly,
    EcodScorer,
    CopodScorer,
    MatrixProfile,
)


def _build() -> dict[str, type[DetectorBase[Any]]]:
    registry: dict[str, type[DetectorBase[Any]]] = {}
    for cls in DETECTORS:
        if cls.NAME in registry:
            raise ValueError(f"detector name {cls.NAME!r} is registered twice")
        if not _SEMVER.match(cls.VERSION):
            raise ValueError(f"{cls.NAME} version {cls.VERSION!r} is not MAJOR.MINOR.PATCH")
        lineage_version(cls.VERSION)
        registry[cls.NAME] = cls
    return registry


REGISTRY: Final[dict[str, type[DetectorBase[Any]]]] = _build()


def detector(name: str) -> type[DetectorBase[Any]]:
    """The detector class registered under ``name``."""
    try:
        return REGISTRY[name]
    except KeyError:
        raise KeyError(f"no detector named {name!r}; known: {sorted(REGISTRY)}") from None
