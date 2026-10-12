"""The Godwit SDK: the public, stable surface plugins are built against.

Owner: A9. Plane: control + data -- a source plugin runs in the data plane and reads
customer rows; every other kind runs on sketches, statistics or gated payloads.

THE COMPATIBILITY PROMISE
-------------------------
Everything importable from ``godwit_sdk`` itself -- the names in ``__all__`` below -- is
covered: within one minor series (``0.1.x``) no public name is removed and no public
signature changes. Anything reached through a submodule (``godwit_sdk.source._...``,
``godwit_sdk._bridge``) or through another ``godwit_*`` package is *not* covered, even if
it happens to work. ``tests/test_api_surface.py`` snapshots the signature of every
public name and fails when one changes without a version bump.

A handful of names are re-exported from the packages that own them (``LogicalType``,
``EvidenceKind``, ``SafePayload``...), because a plugin cannot be written without them.
The SDK promises the *name*; the owning package defines the type.

Importing ``godwit_sdk`` has no side effects beyond defining classes. In particular it
does not import ``godwit_guard`` (which claims the process's ``SafePayloadIssuer``);
that happens on a source plugin's first probe.

Start with ``docs/packages/godwit-sdk.md``, then the three reference plugins in
``godwit_sdk.examples``.
"""

from godwit_context import ContextType
from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.features import FeatureKind, FillPolicy
from godwit_contracts.safe import SafePayload
from godwit_contracts.sketch import ErrorBound, SketchKind
from godwit_contracts.source import ColumnRole, LogicalType
from godwit_contracts.taint import Acquisition, Sensitivity
from godwit_detect import Direction
from godwit_sketch import BaseSketch, ItemFlavour, MergeExactness

from godwit_sdk._version import __version__
from godwit_sdk.capabilities import Capabilities, ResourceLimits
from godwit_sdk.context import ContextBase, ContextRecord, context
from godwit_sdk.detector import DetectorBase, HypothesisTest, detector
from godwit_sdk.errors import (
    CapabilityViolationError,
    IncompatiblePluginError,
    PluginFailedError,
    PluginRejectedError,
    ProbeRefusedError,
    ResourceLimitError,
    SdkError,
)
from godwit_sdk.feature import EVENT_TIME, FEATURE_VALUE, FeatureBase, feature
from godwit_sdk.log import LogValue, PluginLogger
from godwit_sdk.panel import PanelBase, PanelSeries, PanelView, panel
from godwit_sdk.plugin import (
    DEFAULT_REQUIREMENT,
    PluginBase,
    PluginInfo,
    PluginKind,
    TrustCategory,
    check_compatible,
)
from godwit_sdk.registry import ENTRY_POINT_GROUP, DiscoveryReport, PluginRegistry, discover
from godwit_sdk.sketch import SketchBase, sketch
from godwit_sdk.source import (
    PLUGIN_SOURCE_KIND,
    ColumnStats,
    Partition,
    Snapshot,
    SourceBase,
    TableName,
    logical_type,
    source,
)

__all__ = [
    "DEFAULT_REQUIREMENT",
    "ENTRY_POINT_GROUP",
    "EVENT_TIME",
    "FEATURE_VALUE",
    "PLUGIN_SOURCE_KIND",
    "Acquisition",
    "BaseSketch",
    "Capabilities",
    "CapabilityViolationError",
    "ColumnRole",
    "ColumnStats",
    "ContextBase",
    "ContextRecord",
    "ContextType",
    "DetectorBase",
    "Direction",
    "DiscoveryReport",
    "ErrorBound",
    "EvidenceKind",
    "FeatureBase",
    "FeatureKind",
    "FillPolicy",
    "HypothesisTest",
    "IncompatiblePluginError",
    "ItemFlavour",
    "LogValue",
    "LogicalType",
    "MergeExactness",
    "PanelBase",
    "PanelSeries",
    "PanelView",
    "Partition",
    "PluginBase",
    "PluginFailedError",
    "PluginInfo",
    "PluginKind",
    "PluginLogger",
    "PluginRegistry",
    "PluginRejectedError",
    "ProbeRefusedError",
    "ResourceLimitError",
    "ResourceLimits",
    "SafePayload",
    "SdkError",
    "Sensitivity",
    "SketchBase",
    "SketchKind",
    "Snapshot",
    "SourceBase",
    "TableName",
    "TrustCategory",
    "__version__",
    "check_compatible",
    "context",
    "detector",
    "discover",
    "feature",
    "logical_type",
    "panel",
    "sketch",
    "source",
]
