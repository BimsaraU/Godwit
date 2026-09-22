"""Sources, snapshots and the semantic catalog (L-1 and L0).

Everything here describes customer data without being customer data -- with three
exceptions that are the whole reason the taint system exists:

* ``ColumnProfile.min_bound`` and ``max_bound`` are two real row values. Iceberg
  manifest bounds are our free metadata tier; the minimum of a name column is a name.
* ``ColumnProfile.most_common_values`` is ``pg_stats.most_common_vals``, which is
  literally the most common actual values.
* Table and column names are disclosures in their own right.

All three are ``Tainted`` and validated as such.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from godwit_contracts.common import (
    GodwitModel,
    Instant,
    NonNegInt,
    Probability,
    ScalarValue,
    SnapshotId,
    SourceId,
    Version,
)
from godwit_contracts.taint import Sensitivity, Tainted

__all__ = [
    "ColumnProfile",
    "ColumnRef",
    "ColumnRole",
    "JoinEdge",
    "LogicalType",
    "PiiClass",
    "SnapshotRef",
    "SourceKind",
    "SourceRef",
    "TableProfile",
]


class SourceKind(StrEnum):
    """Where rows physically live. Adding a kind needs a SourceAdapter in godwit-source."""

    ICEBERG = "iceberg"
    POSTGRES = "postgres"
    PARQUET = "parquet"
    DUCKDB = "duckdb"


class LogicalType(StrEnum):
    """A source-neutral type. Adapters map their native types onto this."""

    STRING = "string"
    INT = "int"
    FLOAT = "float"
    DECIMAL = "decimal"
    BOOL = "bool"
    DATE = "date"
    TIMESTAMP = "timestamp"
    BINARY = "binary"
    STRUCT = "struct"
    LIST = "list"
    MAP = "map"
    UNKNOWN = "unknown"


class ColumnRole(StrEnum):
    """What a column means, as inferred by the semantic catalog."""

    ENTITY_ID = "entity_id"
    EVENT_TIME = "event_time"
    LABEL = "label"
    AMOUNT = "amount"
    CATEGORY = "category"
    FREE_TEXT = "free_text"
    GEO = "geo"
    DEVICE = "device"
    JOIN_KEY = "join_key"
    MEASURE = "measure"
    UNKNOWN = "unknown"


class PiiClass(StrEnum):
    """How disclosive a column is.

    ``UNKNOWN`` is the default and is treated as the *most* restrictive class by the
    gate, not the least. Deny by default means an unclassified column is not a free one.
    """

    UNKNOWN = "unknown"
    NONE = "none"
    QUASI_IDENTIFIER = "quasi_identifier"
    DIRECT_IDENTIFIER = "direct_identifier"
    SENSITIVE_ATTRIBUTE = "sensitive_attribute"
    FINANCIAL = "financial"
    HEALTH = "health"
    CREDENTIAL = "credential"


class SourceRef(GodwitModel):
    """Addresses one table in one system.

    ``source_id`` and ``catalog`` are ours. ``namespace`` and ``table`` are the
    customer's names and are tainted SCHEMA_NAME.
    """

    source_id: SourceId
    kind: SourceKind
    catalog: str = Field(description="Our catalog handle, not a customer identifier.")
    namespace: Tainted[str]
    table: Tainted[str]

    @model_validator(mode="after")
    def _names_are_schema_tainted(self) -> Self:
        for field, value in (("namespace", self.namespace), ("table", self.table)):
            if value.sensitivity is not Sensitivity.SCHEMA_NAME:
                raise ValueError(f"SourceRef.{field} must be tainted SCHEMA_NAME")
        return self


class SnapshotRef(GodwitModel):
    """A point in a table's history. Every probe and every pattern names one.

    Invariant 7: a pattern is reproducible from (probe spec, snapshot id, version, seed).
    The snapshot id is half of that guarantee.
    """

    source_id: SourceId
    snapshot_id: SnapshotId
    sequence_number: NonNegInt
    committed_at: Instant
    parent_snapshot_id: SnapshotId | None = None
    row_count_estimate: Tainted[int] | None = None


class ColumnRef(GodwitModel):
    """Names one column of one table. Both parts are tainted SCHEMA_NAME."""

    source_id: SourceId
    table: Tainted[str]
    column: Tainted[str]

    @model_validator(mode="after")
    def _names_are_schema_tainted(self) -> Self:
        for field, value in (("table", self.table), ("column", self.column)):
            if value.sensitivity is not Sensitivity.SCHEMA_NAME:
                raise ValueError(f"ColumnRef.{field} must be tainted SCHEMA_NAME")
        return self


class ColumnProfile(GodwitModel):
    """Everything L0 knows about one column.

    Read the field notes. Three of these fields contain real row values.
    """

    ref: ColumnRef
    logical_type: LogicalType
    native_type: str = Field(description="The source's own type name, for diagnostics.")
    nullable: bool
    role: ColumnRole = ColumnRole.UNKNOWN
    pii_class: PiiClass = PiiClass.UNKNOWN

    null_fraction: Tainted[float] | None = None
    distinct_estimate: Tainted[int] | None = None
    row_count: Tainted[int] | None = None

    min_bound: Tainted[ScalarValue] | None = Field(
        default=None,
        description="LEAK PATH. An Iceberg manifest lower bound is a real row value.",
    )
    max_bound: Tainted[ScalarValue] | None = Field(
        default=None,
        description="LEAK PATH. An Iceberg manifest upper bound is a real row value.",
    )
    most_common_values: tuple[Tainted[ScalarValue], ...] = Field(
        default=(),
        description="LEAK PATH. pg_stats.most_common_vals is the actual values.",
    )

    observed_at: Instant
    profile_version: Version

    @model_validator(mode="after")
    def _row_values_are_data_tainted(self) -> Self:
        candidates: list[tuple[str, Tainted[ScalarValue]]] = []
        if self.min_bound is not None:
            candidates.append(("min_bound", self.min_bound))
        if self.max_bound is not None:
            candidates.append(("max_bound", self.max_bound))
        candidates.extend(
            (f"most_common_values[{index}]", value)
            for index, value in enumerate(self.most_common_values)
        )
        for field, value in candidates:
            if value.sensitivity not in (Sensitivity.DATA_VALUE, Sensitivity.TOKEN):
                raise ValueError(
                    f"ColumnProfile.{field} holds a row value: it must be tainted "
                    "DATA_VALUE, or TOKEN once the gate has substituted it"
                )
        return self


class TableProfile(GodwitModel):
    """L0's view of one table at one snapshot."""

    source: SourceRef
    snapshot: SnapshotRef
    columns: tuple[ColumnProfile, ...]
    row_count_estimate: Tainted[int] | None = None
    observed_at: Instant
    profile_version: Version


class JoinEdge(GodwitModel):
    """A believed join between two columns, with how much we believe it.

    The join graph is metadata-first (invariant 5): foreign keys, naming conventions and
    catalog constraints come free. Confirming an edge by scanning costs budget.
    """

    left: ColumnRef
    right: ColumnRef
    confidence: Probability
    inferred_from: str = Field(
        description="How this edge was inferred, e.g. 'declared_fk' or 'name_match'. "
        "Never a row value."
    )
    left_to_right_cardinality: Tainted[float] | None = None
    observed_at: Instant
