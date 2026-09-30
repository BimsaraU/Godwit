"""The replay harness and the kill criterion (A4).

**Plane: both, and the seam is named.** :mod:`godwit_replay.datasets`,
:mod:`godwit_replay.split`, :mod:`godwit_replay.baseline` and
:mod:`godwit_replay.prediction` read rows and run in the **data plane**.
:mod:`godwit_replay.driver`, :mod:`godwit_replay.scoring`, :mod:`godwit_replay.verdict` and
:mod:`godwit_replay.diff` see only statistics and run in the **control plane**. Everything this
package writes to a file or prints to a terminal is an egress and is audited as one by
:mod:`godwit_replay.leak` before it is rendered.

WHAT THIS PACKAGE IS FOR
------------------------
The only honest evidence that Godwit works is: replay N months of real history and show the
system would have surfaced a known event before it was actually caught, without being told
what to look for. Everything else is assertion. This package is the adversary of every other
package, including the ones that do not exist yet. If the system is useless, the job here is
to prove it early.

WHERE TO START READING
----------------------
1. :mod:`godwit_replay.clock` -- the virtual clock, and the guard that catches wall-clock reads.
2. :mod:`godwit_replay.driver` -- snapshot-ordered replay, and why there are two digests.
3. :mod:`godwit_replay.datasets` -- the four public datasets and, more importantly, which of
   their label-time assumptions are fabricated.
4. :mod:`godwit_replay.verdict` -- the kill criterion, printed unsoftened.
5. :mod:`godwit_replay.baseline` -- the expert baseline A13 is graded against.
"""

from godwit_replay.baseline import (
    BaselineRecord,
    build_baseline,
    load_baseline,
    save_baseline,
    verify_baseline,
)
from godwit_replay.clock import Clock, VirtualClock, forbid_wall_clock
from godwit_replay.datasets import (
    REGISTRY,
    DatasetSpec,
    LabelDelay,
    LoadedDataset,
    Period,
    materialise,
    resolve,
)
from godwit_replay.diff import ChampionChallenger, diff_reports
from godwit_replay.driver import (
    MetadataOnlyHandler,
    ReplayConfig,
    ReplayHandler,
    ReplayRun,
    ReplayVerdict,
    ReplayView,
    StepOutcome,
    replay,
)
from godwit_replay.errors import (
    BaselineNotReproducibleError,
    DatasetNotAvailableError,
    FutureKnowledgeError,
    LeakDetectedError,
    ReplayError,
    WallClockAccessError,
)
from godwit_replay.harness import HarnessResult, MeterReading, read_history, retime, run_dataset
from godwit_replay.leak import LeakFinding, LeakKind, audit_egress, forbidden_strings
from godwit_replay.metrics import (
    Interval,
    average_precision,
    bootstrap_ci,
    brier,
    expected_calibration_error,
    precision_at_k,
    recall_at_k,
    roc_auc,
)
from godwit_replay.prediction import PredictionScore, score_predictions, to_evaluation_report
from godwit_replay.scoring import (
    DiscoveryScore,
    SegmentTruth,
    StabilityCheck,
    TruthSet,
    naive_threshold_keys,
    score_discovery,
    truth_from_golden_manifest,
)
from godwit_replay.split import HalfLabelled, MaskKind, SplitRecord, half_labelled
from godwit_replay.verdict import (
    KILL_SENTENCE,
    KILL_THRESHOLD,
    KillCriterion,
    PatternRow,
    ReplayReport,
    ReviewMark,
    assert_passed,
    build_report,
    render_markdown,
    render_review_template,
)

__version__ = "0.1.0"

__all__ = [
    "KILL_SENTENCE",
    "KILL_THRESHOLD",
    "REGISTRY",
    "BaselineNotReproducibleError",
    "BaselineRecord",
    "ChampionChallenger",
    "Clock",
    "DatasetNotAvailableError",
    "DatasetSpec",
    "DiscoveryScore",
    "FutureKnowledgeError",
    "HalfLabelled",
    "HarnessResult",
    "Interval",
    "KillCriterion",
    "LabelDelay",
    "LeakDetectedError",
    "LeakFinding",
    "LeakKind",
    "LoadedDataset",
    "MaskKind",
    "MetadataOnlyHandler",
    "MeterReading",
    "PatternRow",
    "Period",
    "PredictionScore",
    "ReplayConfig",
    "ReplayError",
    "ReplayHandler",
    "ReplayReport",
    "ReplayRun",
    "ReplayVerdict",
    "ReplayView",
    "ReviewMark",
    "SegmentTruth",
    "SplitRecord",
    "StabilityCheck",
    "StepOutcome",
    "TruthSet",
    "VirtualClock",
    "WallClockAccessError",
    "__version__",
    "assert_passed",
    "audit_egress",
    "average_precision",
    "bootstrap_ci",
    "brier",
    "build_baseline",
    "build_report",
    "diff_reports",
    "expected_calibration_error",
    "forbid_wall_clock",
    "forbidden_strings",
    "half_labelled",
    "load_baseline",
    "materialise",
    "naive_threshold_keys",
    "precision_at_k",
    "read_history",
    "recall_at_k",
    "render_markdown",
    "render_review_template",
    "replay",
    "resolve",
    "retime",
    "roc_auc",
    "run_dataset",
    "save_baseline",
    "score_discovery",
    "score_predictions",
    "to_evaluation_report",
    "truth_from_golden_manifest",
    "verify_baseline",
]
