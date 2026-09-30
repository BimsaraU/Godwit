"""The typed metadata record. Data plane.

This is the deliverable the brief calls "never mix them in one untyped structure". A
column's free metadata splits cleanly in two and the split is load-bearing:

* **Counts** -- rows, nulls, values, NDV -- are aggregates. Nothing survives of any
  individual row. ``DERIVED_STATISTIC``.
* **Bounds, most-common-values and histogram boundaries** are row values wearing a
  catalog's clothes. The lower bound of a name column is a person's name; a
  ``pg_stats`` histogram boundary is whichever customer happened to fall on the
  percentile. ``DATA_VALUE``.

Both halves live in the same model, in separate fields, with a validator that refuses
the wrong taint on either side. A ``dict[str, object]`` carrying both would be a leak
the moment somebody iterated it.
"""

from __future__ import annotations

from typing import Self

from godwit_contracts.common import (
    GodwitModel,
    Instant,
    NonNegInt,
    ScalarValue,
    Version,
)
from godwit_contracts.source import (
    ColumnProfile,
    ColumnRef,
    ColumnRole,
    LogicalType,
    PiiClass,
    SnapshotRef,
    SourceRef,
    TableProfile,
)
from godwit_contracts.taint import Sensitivity, Tainted
from pydantic import Field, model_validator

__all__ = ["ColumnMetadata", "FileLayoutStats", "SnapshotMetadata"]


class FileLayoutStats(GodwitModel):
    """How a snapshot's data files are laid out.

    A sudden change in file count or size distribution almost always means an upstream
    pipeline changed -- a different writer, a different batch size, a backfill. It is
    the cheapest early warning in the system and it costs one manifest read.

    Every field is an aggregate over *files*, not over rows, so all of it is
    ``DERIVED_STATISTIC``. File sizes are not customer values; file *paths* would be,
    and are deliberately absent.
    """

    file_count: Tainted[int]
    total_bytes: Tainted[int]
    mean_file_bytes: Tainted[float]
    stdev_file_bytes: Tainted[float]

    @model_validator(mode="after")
    def _layout_is_statistical(self) -> Self:
        for name in ("file_count", "total_bytes", "mean_file_bytes", "stdev_file_bytes"):
            value: Tainted[int] | Tainted[float] = getattr(self, name)
            if value.sensitivity is not Sensitivity.DERIVED_STATISTIC:
                raise ValueError(f"FileLayoutStats.{name} is an aggregate over files")
        return self


class ColumnMetadata(GodwitModel):
    """Free metadata for one column at one snapshot (or snapshot delta).

    The two halves are separated by field, not by convention. Read the validator: it is
    the only thing standing between "we read the catalog" and "we exported a name".
    """

    ref: ColumnRef
    logical_type: LogicalType
    native_type: str = Field(description="The source's own type name, for diagnostics.")
    nullable: bool
    role: ColumnRole = ColumnRole.UNKNOWN
    pii_class: PiiClass = PiiClass.UNKNOWN

    # ---- aggregates: no row value survives -------------------------------------------
    row_count: Tainted[int] | None = None
    null_count: Tainted[int] | None = None
    value_count: Tainted[int] | None = Field(
        default=None, description="Non-null values counted for this column."
    )
    distinct_estimate: Tainted[int] | None = Field(
        default=None, description="NDV, from a Puffin theta sketch or pg_stats.n_distinct."
    )
    most_common_frequencies: tuple[Tainted[float], ...] = Field(
        default=(),
        description="Frequencies matching most_common_values positionally. A frequency "
        "is an aggregate; the value it belongs to is not.",
    )

    # ---- row values: LEAK PATHS ------------------------------------------------------
    lower_bound: Tainted[ScalarValue] | None = Field(
        default=None, description="LEAK PATH. An Iceberg manifest lower bound is a row value."
    )
    upper_bound: Tainted[ScalarValue] | None = Field(
        default=None, description="LEAK PATH. An Iceberg manifest upper bound is a row value."
    )
    most_common_values: tuple[Tainted[ScalarValue], ...] = Field(
        default=(), description="LEAK PATH. pg_stats.most_common_vals is the actual values."
    )
    histogram_bounds: tuple[Tainted[ScalarValue], ...] = Field(
        default=(),
        description="LEAK PATH. pg_stats.histogram_bounds are the values that fell on "
        "each percentile boundary. Over a small table they are individual people.",
    )

    @model_validator(mode="after")
    def _halves_are_typed_apart(self) -> Self:
        statistical: tuple[tuple[str, Tainted[int] | Tainted[float] | None], ...] = (
            ("row_count", self.row_count),
            ("null_count", self.null_count),
            ("value_count", self.value_count),
            ("distinct_estimate", self.distinct_estimate),
            *(
                (f"most_common_frequencies[{index}]", frequency)
                for index, frequency in enumerate(self.most_common_frequencies)
            ),
        )
        for name, statistic in statistical:
            if statistic is not None and statistic.sensitivity is not Sensitivity.DERIVED_STATISTIC:
                raise ValueError(f"ColumnMetadata.{name} is a count, not a row value")

        row_valued: list[tuple[str, Tainted[ScalarValue]]] = []
        if self.lower_bound is not None:
            row_valued.append(("lower_bound", self.lower_bound))
        if self.upper_bound is not None:
            row_valued.append(("upper_bound", self.upper_bound))
        row_valued.extend(
            (f"most_common_values[{index}]", value)
            for index, value in enumerate(self.most_common_values)
        )
        row_valued.extend(
            (f"histogram_bounds[{index}]", value)
            for index, value in enumerate(self.histogram_bounds)
        )
        for name, value in row_valued:
            if value.sensitivity not in (Sensitivity.DATA_VALUE, Sensitivity.TOKEN):
                raise ValueError(
                    f"ColumnMetadata.{name} came out of a row: it must be tainted "
                    "DATA_VALUE, or TOKEN once the gate has substituted it"
                )

        if len(self.most_common_frequencies) not in (0, len(self.most_common_values)):
            raise ValueError(
                "most_common_frequencies must be empty or align with most_common_values"
            )
        return self

    @property
    def null_fraction(self) -> Tainted[float] | None:
        """Nulls over rows, when both are known. A ratio of two counts is a count."""
        if self.null_count is None or self.row_count is None or self.row_count.reveal() == 0:
            return None
        return Tainted[float](
            value=self.null_count.reveal() / self.row_count.reveal(),
            sensitivity=Sensitivity.DERIVED_STATISTIC,
            provenance=self.null_count.provenance,
            population=self.row_count.reveal(),
        )

    def to_column_profile(self, *, observed_at: Instant, profile_version: Version) -> ColumnProfile:
        """Render into the L0 contract type.

        ``ColumnProfile`` is what the rest of Godwit consumes; ``ColumnMetadata`` is the
        richer thing L-1 detectors need. The narrowing is deliberate and one-way: counts
        the contract has no field for do not silently reappear somewhere else.
        """
        return ColumnProfile(
            ref=self.ref,
            logical_type=self.logical_type,
            native_type=self.native_type,
            nullable=self.nullable,
            role=self.role,
            pii_class=self.pii_class,
            null_fraction=self.null_fraction,
            distinct_estimate=self.distinct_estimate,
            row_count=self.row_count,
            min_bound=self.lower_bound,
            max_bound=self.upper_bound,
            most_common_values=self.most_common_values,
            observed_at=observed_at,
            profile_version=profile_version,
        )


class SnapshotMetadata(GodwitModel):
    """Everything free metadata knows about one table at one snapshot.

    L-1 detectors take a sequence of these, ordered oldest first, and report on the
    last one. That sequence is the "metadata time-series" -- no table was scanned to
    build it.

    ``observed_at`` is the snapshot's own commit time, not a clock reading. Universal
    rule 5: a detector's output must not depend on when it ran.
    """

    source: SourceRef
    snapshot: SnapshotRef
    columns: tuple[ColumnMetadata, ...]
    row_count: Tainted[int] | None = None
    layout: FileLayoutStats | None = None
    is_delta: bool = Field(
        default=False,
        description="True when these statistics cover only the files added since a "
        "baseline snapshot, rather than the whole table at this snapshot.",
    )
    baseline_snapshot_id: str | None = None
    observed_at: Instant
    profile_version: Version = 1
    scanned_bytes: NonNegInt = Field(
        default=0,
        description="Bytes of table data read to produce this. Zero is the whole point "
        "of L-1: every field above came from the catalog.",
    )

    @model_validator(mode="after")
    def _row_count_is_statistical(self) -> Self:
        if self.row_count is not None and (
            self.row_count.sensitivity is not Sensitivity.DERIVED_STATISTIC
        ):
            raise ValueError("SnapshotMetadata.row_count is a count, not a row value")
        return self

    def column(self, name: str) -> ColumnMetadata | None:
        """Look one column up by its revealed name. Data plane only."""
        for candidate in self.columns:
            if candidate.ref.column.reveal() == name:
                return candidate
        return None

    def to_table_profile(self) -> TableProfile:
        """Render into the L0 contract type that the rest of Godwit consumes."""
        return TableProfile(
            source=self.source,
            snapshot=self.snapshot,
            columns=tuple(
                column.to_column_profile(
                    observed_at=self.observed_at, profile_version=self.profile_version
                )
                for column in self.columns
            ),
            row_count_estimate=self.row_count,
            observed_at=self.observed_at,
            profile_version=self.profile_version,
        )
