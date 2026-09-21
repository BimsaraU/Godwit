"""Typed metadata structures.

DATA PLANE. The taint split is structural here, not a convention: row values live in
:class:`ColumnBounds` and :class:`CommonValue`, aggregates live in :class:`ColumnCounts`,
and no type holds both. That is what "never mix them in one untyped structure" buys -- a
downstream consumer can drop the bounds object wholesale and keep the counts object without
inspecting a single field.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ._contracts import ColumnAccessMode, Tainted

__all__ = [
    "ColumnBounds",
    "ColumnCounts",
    "ColumnMetadata",
    "CommonValue",
    "FileLayoutStats",
    "SnapshotMetadata",
    "stat",
]

_DERIVED = "derived-statistic arithmetic inside the data plane"


def stat(value: Tainted[int] | Tainted[float] | None) -> float | None:
    """Unwrap a derived statistic for arithmetic. Never call this on a DATA_VALUE."""
    if value is None:
        return None
    return float(value.unwrap(_DERIVED))


@dataclass(frozen=True, slots=True)
class ColumnBounds:
    """Iceberg manifest lower/upper bounds. Every field is a real row value.

    Populated only for ``OPEN`` columns. For an ``OPAQUE`` column the adapter surfaces the
    derived statistics and leaves this ``None`` -- the bound is never constructed, so there
    is nothing to redact later.
    """

    lower: Tainted[object] | None = None
    upper: Tainted[object] | None = None


@dataclass(frozen=True, slots=True)
class CommonValue:
    """One ``pg_stats.most_common_vals`` entry: a literal row value plus its frequency."""

    value: Tainted[object]
    frequency: Tainted[float]


@dataclass(frozen=True, slots=True)
class ColumnCounts:
    """Aggregates only. Nothing here quotes a row."""

    row_count: Tainted[int]
    null_count: Tainted[int] | None = None
    value_count: Tainted[int] | None = None
    ndv: Tainted[int] | None = None

    @property
    def null_rate(self) -> float | None:
        rows = stat(self.row_count)
        nulls = stat(self.null_count)
        if rows is None or nulls is None or rows <= 0:
            return None
        return nulls / rows

    @property
    def ndv_ratio(self) -> float | None:
        rows = stat(self.row_count)
        ndv = stat(self.ndv)
        if rows is None or ndv is None or rows <= 0:
            return None
        return ndv / rows


@dataclass(frozen=True, slots=True)
class ColumnMetadata:
    """One column at one snapshot, as read from free metadata."""

    table: str
    column: str
    snapshot_id: str
    access_mode: ColumnAccessMode
    data_type: str
    counts: ColumnCounts
    bounds: ColumnBounds | None = None
    common_values: tuple[CommonValue, ...] = ()
    histogram_bounds: tuple[Tainted[object], ...] = ()


@dataclass(frozen=True, slots=True)
class FileLayoutStats:
    """Physical layout of a snapshot. Free from the manifest, and a reliable tell: a sudden
    change in file count or size distribution almost always means an upstream pipeline
    changed rather than that the business did."""

    file_count: int
    total_bytes: int
    median_file_bytes: float
    max_file_bytes: int


@dataclass(frozen=True, slots=True)
class SnapshotMetadata:
    """Everything free that one snapshot yields."""

    table: str
    snapshot_id: str
    sequence_number: int
    commit_ms: int
    columns: Mapping[str, ColumnMetadata]
    layout: FileLayoutStats | None = None
    schema_columns: tuple[str, ...] = field(default=())


MetadataHistory = Sequence[SnapshotMetadata]
