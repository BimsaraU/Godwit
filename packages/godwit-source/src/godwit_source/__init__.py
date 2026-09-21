"""godwit-source (A1): source adapters and the L-1 metadata detector layer.

**This package runs in the DATA PLANE and it is the origin point for most of the tainted
data in the system.** Iceberg manifest bounds and ``pg_stats.most_common_vals`` are row
values, not statistics about row values: the minimum of a name column is a real person's
name. Everything this package reads from those fields is ``Tainted[DATA_VALUE]`` from the
moment it is read and stays tainted forever. If this package tags lazily, no gate downstream
can recover.

The free tier -- manifests, Puffin, ``pg_stats`` -- exists so that paid scans are spent only
where something already looks wrong. See ``docs/packages/godwit-source.md``.
"""

from __future__ import annotations

from ._contracts import CONTRACTS_ARE_PROVISIONAL
from .access import (
    MIN_OPAQUE_ENTROPY_BITS,
    AccessPolicy,
    BlindColumnError,
    ColumnClassification,
    Projection,
    keyed_hash,
)
from .base import (
    BlindColumnLeak,
    ProbeResult,
    SnapshotRef,
    SourceAdapter,
    assert_plan_is_blind_safe,
    safe_backend_error,
)
from .detectors import (
    DEFAULT_DETECTORS,
    bounds_drift,
    file_layout_anomaly,
    ndv_ratio_shift,
    null_rate_shift,
    row_volume_anomaly,
    run_all,
    schema_change,
)
from .iceberg import DataFileStats, IcebergAdapter, ManifestReader, SchemaField
from .instrument import InstrumentedObjectStore, IoLedger, ObjectKind, classify_path
from .postgres import PostgresAdapter
from .profile import ColumnProfile, JoinEdge, candidate_join_edges, profile_column, profile_snapshot
from .puffin import Blob, PuffinError, read_puffin, write_puffin
from .stats import (
    ColumnBounds,
    ColumnCounts,
    ColumnMetadata,
    CommonValue,
    FileLayoutStats,
    SnapshotMetadata,
)
from .warehouse import ApproxDialect, WarehouseSqlAdapter

__all__ = [
    "CONTRACTS_ARE_PROVISIONAL",
    "DEFAULT_DETECTORS",
    "MIN_OPAQUE_ENTROPY_BITS",
    "AccessPolicy",
    "ApproxDialect",
    "BlindColumnError",
    "BlindColumnLeak",
    "Blob",
    "ColumnBounds",
    "ColumnClassification",
    "ColumnCounts",
    "ColumnMetadata",
    "ColumnProfile",
    "CommonValue",
    "DataFileStats",
    "FileLayoutStats",
    "IcebergAdapter",
    "InstrumentedObjectStore",
    "IoLedger",
    "JoinEdge",
    "ManifestReader",
    "ObjectKind",
    "PostgresAdapter",
    "ProbeResult",
    "Projection",
    "PuffinError",
    "SchemaField",
    "SnapshotMetadata",
    "SnapshotRef",
    "SourceAdapter",
    "WarehouseSqlAdapter",
    "assert_plan_is_blind_safe",
    "bounds_drift",
    "candidate_join_edges",
    "classify_path",
    "file_layout_anomaly",
    "keyed_hash",
    "ndv_ratio_shift",
    "null_rate_shift",
    "profile_column",
    "profile_snapshot",
    "read_puffin",
    "row_volume_anomaly",
    "run_all",
    "safe_backend_error",
    "schema_change",
    "write_puffin",
]
