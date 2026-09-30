"""Source adapters and the semantic catalog (L-1, L0).

Owner: A1. **Plane: data.** This package reads customer rows and customer catalogs, and
it is the origin point for most of the tainted values in Godwit. Read
``docs/packages/godwit-source.md`` before changing anything in it.

The package in one paragraph: three adapters turn a customer system into typed
metadata; six detectors turn a series of that metadata into candidates without reading a
byte of table data; a semantic layer infers what each column means without an LLM; and a
Puffin codec lets a probe result be cached next to the table that produced it.

WHAT IS TAINTED, AND WHY
------------------------
Iceberg manifest bounds and ``pg_stats.most_common_vals`` are *row values*. So are
``pg_stats.histogram_bounds`` and the items a heavy-hitter probe returns. Everything
this package reads from those becomes ``Tainted[DATA_VALUE]`` at the moment it is
decoded, with an ``Acquisition`` that says which leak path it came down. Counts are
``DERIVED_STATISTIC`` and live in different fields. Column and table names are
``SCHEMA_NAME``. There is no fourth category and nothing is left plain.
"""

from godwit_source.dbapi import (
    Connection,
    Cursor,
    ParamStyle,
    fetch,
    parse_pg_array,
    segment_clause,
    sql_dialect,
    table_ref,
    to_float,
)
from godwit_source.detectors import (
    DEFAULT_CONFIG,
    DETECTOR_VERSION,
    DeltaVerdict,
    DetectorConfig,
    bounds_drift,
    evaluate_deltas,
    file_layout_anomaly,
    ndv_ratio_shift,
    null_rate_shift,
    row_volume_anomaly,
    run_metadata_detectors,
    schema_change,
)
from godwit_source.errors import (
    MetadataUnavailableError,
    SanitisedDriverError,
    SourceError,
    UnsupportedProbeError,
    UnsupportedSourceError,
    sanitise_driver_error,
)
from godwit_source.iceberg import IcebergAdapter
from godwit_source.metadata import ColumnMetadata, FileLayoutStats, SnapshotMetadata
from godwit_source.objectstore import ByteMeter, MeteredFileIO, ReadClass, classify_location
from godwit_source.postgres import CATALOG_RELATIONS, PostgresAdapter
from godwit_source.puffin import (
    GODWIT_BLOB_PREFIX,
    SKETCH_ENVELOPE_BLOB,
    PuffinBlob,
    blob_to_sketch_envelope,
    godwit_blobs,
    read_puffin,
    sketch_envelope_blob,
    write_puffin,
)
from godwit_source.pushdown import (
    SqlProfile,
    aggregate_statement,
    probe_acquisition,
    result_to_values,
)
from godwit_source.scalars import as_axis, prefix_similarity, scalar_le
from godwit_source.semantic import (
    infer_join_edges,
    infer_pii_class,
    infer_role,
    pii_restrictiveness,
)
from godwit_source.sketches import SketchBuilder, SketchContext
from godwit_source.stats import log_ratio, robust_z, two_proportion_z, two_sided_p
from godwit_source.warehouse import BIGQUERY, SNOWFLAKE, WarehouseProfile, WarehouseSqlAdapter

__all__ = [
    "BIGQUERY",
    "CATALOG_RELATIONS",
    "DEFAULT_CONFIG",
    "DETECTOR_VERSION",
    "GODWIT_BLOB_PREFIX",
    "SKETCH_ENVELOPE_BLOB",
    "SNOWFLAKE",
    "ByteMeter",
    "ColumnMetadata",
    "Connection",
    "Cursor",
    "DeltaVerdict",
    "DetectorConfig",
    "FileLayoutStats",
    "IcebergAdapter",
    "MetadataUnavailableError",
    "MeteredFileIO",
    "ParamStyle",
    "PostgresAdapter",
    "PuffinBlob",
    "ReadClass",
    "SanitisedDriverError",
    "SketchBuilder",
    "SketchContext",
    "SnapshotMetadata",
    "SourceError",
    "SqlProfile",
    "UnsupportedProbeError",
    "UnsupportedSourceError",
    "WarehouseProfile",
    "WarehouseSqlAdapter",
    "__version__",
    "aggregate_statement",
    "as_axis",
    "blob_to_sketch_envelope",
    "bounds_drift",
    "classify_location",
    "evaluate_deltas",
    "fetch",
    "file_layout_anomaly",
    "godwit_blobs",
    "infer_join_edges",
    "infer_pii_class",
    "infer_role",
    "log_ratio",
    "ndv_ratio_shift",
    "null_rate_shift",
    "parse_pg_array",
    "pii_restrictiveness",
    "prefix_similarity",
    "probe_acquisition",
    "read_puffin",
    "result_to_values",
    "robust_z",
    "row_volume_anomaly",
    "run_metadata_detectors",
    "sanitise_driver_error",
    "scalar_le",
    "schema_change",
    "segment_clause",
    "sketch_envelope_blob",
    "sql_dialect",
    "table_ref",
    "to_float",
    "two_proportion_z",
    "two_sided_p",
    "write_puffin",
]

__version__ = "0.1.0"
