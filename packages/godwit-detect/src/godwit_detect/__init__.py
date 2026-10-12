"""Detector library (L2): sketches in, candidates out.

Owner: A7. Plane: control. No I/O, no clock, no randomness, no LLM: every detector is a
pure function of its settings and the sketches it is handed.

The package reads sketches that contain row values -- heavy-hitter keys, category
labels, KLL samples -- and never emits one except inside a ``Tainted`` wrapper, in the
two places a :class:`~godwit_detect.evidence.Finding` keeps identities. Read
``docs/packages/godwit-detect.md`` before using anything here.
"""

from godwit_detect.adapter import BundleDetector
from godwit_detect.base import DetectorBase, SeriesDetector, Settings
from godwit_detect.correlation import (
    CorrelationPanel,
    CorrelationSettings,
    CorrelationShift,
    CorrelationSlice,
    pair_key,
)
from godwit_detect.drift import DriftSettings, JensenShannonDrift, PsiDrift, WassersteinDrift
from godwit_detect.evidence import (
    Attribution,
    DetectionResult,
    Direction,
    Finding,
    Measure,
    Refusal,
    RefusalReason,
    Window,
    lineage_version,
    to_candidate,
)
from godwit_detect.graph import GraphAnomaly, GraphSettings
from godwit_detect.heavy import HeavyHitterSettings, HeavyHitterShift
from godwit_detect.registry import DETECTORS, REGISTRY, detector
from godwit_detect.scoring import (
    CopodScorer,
    EcodScorer,
    FeatureRow,
    MatrixProfile,
    MatrixProfileSettings,
    ScoringSettings,
)
from godwit_detect.segments import (
    PanelSnapshot,
    SegmentDivergence,
    SegmentDivergenceSettings,
    SegmentSlice,
)
from godwit_detect.series import (
    BaselinePolicy,
    FixedReference,
    ProbeContext,
    Seasonal,
    SeriesPoint,
    SketchSeries,
    Trailing,
    select_baseline,
)

__all__ = [
    "DETECTORS",
    "REGISTRY",
    "Attribution",
    "BaselinePolicy",
    "BundleDetector",
    "CopodScorer",
    "CorrelationPanel",
    "CorrelationSettings",
    "CorrelationShift",
    "CorrelationSlice",
    "DetectionResult",
    "DetectorBase",
    "Direction",
    "DriftSettings",
    "EcodScorer",
    "FeatureRow",
    "Finding",
    "FixedReference",
    "GraphAnomaly",
    "GraphSettings",
    "HeavyHitterSettings",
    "HeavyHitterShift",
    "JensenShannonDrift",
    "MatrixProfile",
    "MatrixProfileSettings",
    "Measure",
    "PanelSnapshot",
    "ProbeContext",
    "PsiDrift",
    "Refusal",
    "RefusalReason",
    "ScoringSettings",
    "Seasonal",
    "SegmentDivergence",
    "SegmentDivergenceSettings",
    "SegmentSlice",
    "SeriesDetector",
    "SeriesPoint",
    "Settings",
    "SketchSeries",
    "Trailing",
    "WassersteinDrift",
    "Window",
    "__version__",
    "detector",
    "lineage_version",
    "pair_key",
    "select_baseline",
    "to_candidate",
]

__version__ = "1.0.0"
