"""The sensitivity taint system. Read this before anything else in Godwit.

Invariant 2: *every value that came from customer data is typed as such and is denied
by default.* This module is the type-level half of that invariant. The enforcement half
lives in ``godwit-guard``.

The rule for the other nineteen agents is short:

    If a field can hold a value that was read out of, or computed from the contents of,
    a customer row, its type is ``Tainted[...]``. If a field's type does not say whether
    it is safe, the field is wrong.

``Tainted`` is a wrapper, not a subclass. ``Tainted[str]`` is not a ``str`` and mypy
will refuse to pass one where a ``str`` is expected. That refusal is the point.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Self

from pydantic import BaseModel, ConfigDict, model_validator

from godwit_contracts.common import NonNegInt

__all__ = [
    "ACQUISITION_MINIMUM_SENSITIVITY",
    "Acquisition",
    "Provenance",
    "Sensitivity",
    "Tainted",
    "data_value",
    "derived_statistic",
    "egress_risk_rank",
    "most_sensitive",
    "schema_name",
    "token",
]


class Sensitivity(StrEnum):
    """What kind of thing a value is, from the perimeter's point of view."""

    DERIVED_STATISTIC = "derived_statistic"
    """A count, moment, p-value, effect size or error bound.

    Contains no value drawn from a row. A mean is a derived statistic; the *maximum*
    of a column is not, because the maximum IS some row's value.
    """

    TOKEN = "token"
    """An opaque substitute issued by the gate.

    Safe to show, meaningless without the tokenisation map, which never leaves the
    data plane. Still gated, because a stable token is a stable pseudonym.
    """

    SCHEMA_NAME = "schema_name"
    """A customer table or column identifier.

    ``patient_hiv_status``, ``customer_ssn`` and ``salary_2024`` are each a disclosure
    on their own, before a single row is read.
    """

    DATA_VALUE = "data_value"
    """A value that came out of a row, by any route. The most restricted class."""


_EGRESS_RISK_RANK: Final[dict[Sensitivity, int]] = {
    Sensitivity.DERIVED_STATISTIC: 0,
    Sensitivity.TOKEN: 1,
    Sensitivity.SCHEMA_NAME: 2,
    Sensitivity.DATA_VALUE: 3,
}


def egress_risk_rank(sensitivity: Sensitivity) -> int:
    """Order sensitivities from least to most restricted. Higher means more restricted."""
    return _EGRESS_RISK_RANK[sensitivity]


def most_sensitive(*sensitivities: Sensitivity) -> Sensitivity:
    """Return the most restricted of the inputs.

    Combining tainted values combines their taint upwards, never downwards. A statistic
    computed over a segment inherits the segment's DATA_VALUE taint.
    """
    if not sensitivities:
        raise ValueError("most_sensitive() needs at least one sensitivity")
    return max(sensitivities, key=egress_risk_rank)


class Acquisition(StrEnum):
    """How a value was obtained.

    This enum is the leak-path list from ``docs/ARCHITECTURE.md`` expressed in code.
    Several of these are things we casually call "metadata" while they literally
    contain row values.
    """

    COMPUTED_STATISTIC = "computed_statistic"
    """Aggregated over many rows; no individual value survives."""

    SKETCH_SUMMARY = "sketch_summary"
    """A cardinality or distribution estimate out of a sketch. No stored items."""

    ICEBERG_MANIFEST_BOUNDS = "iceberg_manifest_bounds"
    """Column min/max from an Iceberg manifest. These are two real row values."""

    PG_STATS_MCV = "pg_stats_mcv"
    """``pg_stats.most_common_vals``. Literally the most common actual values."""

    COUNT_MIN_HEAVY_HITTER = "count_min_heavy_hitter"
    """Heavy hitters. On an identifier column the heavy hitters ARE the PII."""

    FREQUENT_ITEMS = "frequent_items"
    """Frequent-item sketch contents. Same hazard as heavy hitters."""

    CATEGORY_HISTOGRAM = "category_histogram"
    """Category labels with counts. Below the cardinality threshold these are exact."""

    SEGMENT_PREDICATE = "segment_predicate"
    """The value inside ``(column, operator, value)``. Travels in every candidate."""

    QUANTILE = "quantile"
    """A quantile. Over a small population this is one person's number."""

    DERIVED_FEATURE_NAME = "derived_feature_name"
    """``is_merchant_ACME_CORP``. Surfaces in SHAP output, importances, model cards."""

    CATALOG_IDENTIFIER = "catalog_identifier"
    """A customer table or column name read from a catalog."""

    MODEL_EXPLANATION = "model_explanation"
    """Attributions, rule extracts, surrogate trees. Can echo training values."""

    DRIVER_EXCEPTION = "driver_exception"
    """A database driver message. Routinely contains the offending row."""

    GATE_TOKENISATION = "gate_tokenisation"
    """Issued by godwit-guard in place of a more sensitive upstream value."""

    LLM_OUTPUT = "llm_output"
    """Text an LLM produced. It only ever saw a SafePayload, but it can echo tokens."""

    USER_SUPPLIED = "user_supplied"
    """Typed by a human operator. Assume they pasted a row, because they did."""


ACQUISITION_MINIMUM_SENSITIVITY: Final[dict[Acquisition, Sensitivity]] = {
    Acquisition.COMPUTED_STATISTIC: Sensitivity.DERIVED_STATISTIC,
    Acquisition.SKETCH_SUMMARY: Sensitivity.DERIVED_STATISTIC,
    Acquisition.ICEBERG_MANIFEST_BOUNDS: Sensitivity.DATA_VALUE,
    Acquisition.PG_STATS_MCV: Sensitivity.DATA_VALUE,
    Acquisition.COUNT_MIN_HEAVY_HITTER: Sensitivity.DATA_VALUE,
    Acquisition.FREQUENT_ITEMS: Sensitivity.DATA_VALUE,
    Acquisition.CATEGORY_HISTOGRAM: Sensitivity.DATA_VALUE,
    Acquisition.SEGMENT_PREDICATE: Sensitivity.DATA_VALUE,
    Acquisition.QUANTILE: Sensitivity.DATA_VALUE,
    Acquisition.DERIVED_FEATURE_NAME: Sensitivity.DATA_VALUE,
    Acquisition.CATALOG_IDENTIFIER: Sensitivity.SCHEMA_NAME,
    Acquisition.MODEL_EXPLANATION: Sensitivity.DATA_VALUE,
    Acquisition.DRIVER_EXCEPTION: Sensitivity.DATA_VALUE,
    Acquisition.GATE_TOKENISATION: Sensitivity.TOKEN,
    Acquisition.LLM_OUTPUT: Sensitivity.TOKEN,
    Acquisition.USER_SUPPLIED: Sensitivity.DATA_VALUE,
}
"""Floor sensitivity per acquisition route.

A ``Tainted`` may be declared *more* restricted than its route requires, never less.
This is what stops a well-meaning agent labelling a manifest bound as a statistic.
"""


class Provenance(BaseModel):
    """Where a tainted value came from.

    Provenance is itself disclosive: it names customer tables and columns. It is
    SCHEMA_NAME-class and must pass the gate like anything else.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    acquisition: Acquisition
    source_id: str | None = None
    table: str | None = None
    column: str | None = None
    snapshot_id: str | None = None
    detail: str | None = None
    """Free text for humans. MUST NOT contain a value drawn from a row. If you are
    tempted to put one here, what you want is another Tainted field."""

    upstream: Provenance | None = None
    """Set by the gate when it replaces a value, so a token still traces to its origin."""


class Tainted[T](BaseModel):
    """A value, plus the reason you may not simply use it.

    ``Tainted[T]`` is deliberately not a ``T``. Unwrapping is explicit and greppable:
    :meth:`reveal`. Repr and str never render the value, so an accidental f-string in a
    log line leaks the label rather than the data.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: T
    sensitivity: Sensitivity
    provenance: Provenance
    population: NonNegInt | None = None
    """How many rows stand behind this value, when that is known.

    ``None`` means unknown, which small-cell rules must treat as unsafe, not as large.
    """

    @model_validator(mode="after")
    def _sensitivity_meets_acquisition_floor(self) -> Self:
        floor = ACQUISITION_MINIMUM_SENSITIVITY[self.provenance.acquisition]
        if egress_risk_rank(self.sensitivity) < egress_risk_rank(floor):
            raise ValueError(
                f"{self.provenance.acquisition} requires at least {floor}, got {self.sensitivity}"
            )
        return self

    def reveal(self) -> T:
        """Return the underlying value.

        Legitimate only inside the data plane, or inside godwit-guard while applying a
        redaction policy. Every other call site is a bug. Grep for ``.reveal()`` when
        reviewing a diff.
        """
        return self.value

    def is_small_cell(self, threshold: int) -> bool:
        """Return True if the population behind this value is too small to disclose.

        Unknown population counts as small. "Segment X (n=3) is anomalous"
        re-identifies without quoting a single value.
        """
        return self.population is None or self.population < threshold

    def redacted(self) -> str:
        """Return a safe rendering: label only, never the value."""
        where = self.provenance.column or self.provenance.table or "unknown"
        return (
            f"<tainted {self.sensitivity.value} "
            f"via {self.provenance.acquisition.value} from {where}>"
        )

    def __repr__(self) -> str:
        return self.redacted()

    def __str__(self) -> str:
        return self.redacted()


def derived_statistic[T](
    value: T,
    *,
    acquisition: Acquisition = Acquisition.COMPUTED_STATISTIC,
    population: int | None = None,
    source_id: str | None = None,
    table: str | None = None,
    column: str | None = None,
    snapshot_id: str | None = None,
) -> Tainted[T]:
    """Wrap an aggregate that contains no row value."""
    return Tainted[T](
        value=value,
        sensitivity=Sensitivity.DERIVED_STATISTIC,
        provenance=Provenance(
            acquisition=acquisition,
            source_id=source_id,
            table=table,
            column=column,
            snapshot_id=snapshot_id,
        ),
        population=population,
    )


def data_value[T](
    value: T,
    *,
    acquisition: Acquisition,
    population: int | None = None,
    source_id: str | None = None,
    table: str | None = None,
    column: str | None = None,
    snapshot_id: str | None = None,
) -> Tainted[T]:
    """Wrap something that came out of a row. ``acquisition`` is mandatory: say how."""
    return Tainted[T](
        value=value,
        sensitivity=Sensitivity.DATA_VALUE,
        provenance=Provenance(
            acquisition=acquisition,
            source_id=source_id,
            table=table,
            column=column,
            snapshot_id=snapshot_id,
        ),
        population=population,
    )


def schema_name(
    name: str,
    *,
    source_id: str | None = None,
    table: str | None = None,
) -> Tainted[str]:
    """Wrap a customer table or column identifier."""
    return Tainted[str](
        value=name,
        sensitivity=Sensitivity.SCHEMA_NAME,
        provenance=Provenance(
            acquisition=Acquisition.CATALOG_IDENTIFIER,
            source_id=source_id,
            table=table,
            column=name,
        ),
    )


def token(
    opaque: str,
    *,
    upstream: Provenance | None = None,
    population: int | None = None,
) -> Tainted[str]:
    """Wrap a substitute the gate issued. Only godwit-guard should call this."""
    return Tainted[str](
        value=opaque,
        sensitivity=Sensitivity.TOKEN,
        provenance=Provenance(
            acquisition=Acquisition.GATE_TOKENISATION,
            upstream=upstream,
        ),
        population=population,
    )
