"""Semantic profiling without an LLM (L0). Data plane.

Invariant 7 says the LLM is out of the detection path, and invariant 4 says LLM cost
scales with hypotheses rather than data. Both mean the same thing here: the catalog must
be able to say what a column *means* on its own, from its name, its type, its
cardinality and its bounds. A15 can rename and re-rank afterwards; nothing in this
module waits on it.

Three inferences live here:

* :func:`infer_role` -- what the column is for.
* :func:`infer_pii_class` -- how disclosive it is. A first pass. A5 refines it and a
  human confirms it, and the gate treats ``UNKNOWN`` as the most restricted class, so
  guessing low is the only dangerous mistake. The rules below are deliberately
  over-inclusive: ``merchant_name`` comes back a direct identifier because it matches
  the name rule, which is more restrictive than a human would classify it and
  therefore the safe direction to be wrong in.
* :func:`infer_join_edges` -- candidate joins, by approximate inclusion dependency over
  NDV and bounds. Free: the inputs are all catalog statistics.

This module reveals bounds in order to compare them. That is legitimate -- it runs in
the data plane -- but nothing it returns carries a revealed value: a ``JoinEdge``
records *how* an edge was inferred, never *which* values overlapped.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from godwit_contracts.common import Instant, ScalarValue
from godwit_contracts.source import ColumnRole, JoinEdge, LogicalType, PiiClass
from godwit_contracts.taint import Acquisition, Tainted, derived_statistic

from godwit_source.metadata import ColumnMetadata, SnapshotMetadata
from godwit_source.scalars import scalar_le

__all__ = [
    "PII_RESTRICTIVENESS",
    "infer_join_edges",
    "infer_pii_class",
    "infer_role",
    "pii_restrictiveness",
]

# --------------------------------------------------------------------------------------
# PII classification
# --------------------------------------------------------------------------------------

PII_RESTRICTIVENESS: Final[dict[PiiClass, int]] = {
    PiiClass.NONE: 0,
    PiiClass.QUASI_IDENTIFIER: 1,
    PiiClass.FINANCIAL: 2,
    PiiClass.SENSITIVE_ATTRIBUTE: 2,
    PiiClass.DIRECT_IDENTIFIER: 3,
    PiiClass.HEALTH: 3,
    PiiClass.CREDENTIAL: 4,
    PiiClass.UNKNOWN: 5,
}
"""How restricted each class is, most permissive first.

``UNKNOWN`` ranks highest because the gate denies what it cannot classify. That makes
the ordering useful for one question only -- "is this classification at least as
restrictive as that one" -- and useless for ranking confidence.
"""


def pii_restrictiveness(pii_class: PiiClass) -> int:
    """Rank a PII class. Higher means more restricted."""
    return PII_RESTRICTIVENESS[pii_class]


_NAME_PII_RULES: Final[tuple[tuple[re.Pattern[str], PiiClass], ...]] = (
    (
        re.compile(r"password|passwd|secret|api_?key|token|credential|private_?key"),
        PiiClass.CREDENTIAL,
    ),
    (
        re.compile(r"hiv|diagnos|patient|medical|health|icd_?\d*|prescription|blood"),
        PiiClass.HEALTH,
    ),
    (
        re.compile(r"ssn|social_?security|passport|driver_?licen|national_?id|tax_?id"),
        PiiClass.DIRECT_IDENTIFIER,
    ),
    (
        re.compile(
            r"e?mail|phone|mobile|telephone|msisdn|full_?name|first_?name|last_?name|surname"
        ),
        PiiClass.DIRECT_IDENTIFIER,
    ),
    (re.compile(r"(^|_)name($|_)|_name$|^name$"), PiiClass.DIRECT_IDENTIFIER),
    (
        re.compile(
            r"iban|account_?number|card_?number|pan$|cvv|sort_?code|routing|salary|compensation|income"
        ),
        PiiClass.FINANCIAL,
    ),
    (
        re.compile(r"note|comment|description|message|memo|free_?text|remark"),
        PiiClass.SENSITIVE_ATTRIBUTE,
    ),
    (
        re.compile(r"religio|ethnic|orientation|political|union_?member|biometric"),
        PiiClass.SENSITIVE_ATTRIBUTE,
    ),
    (
        re.compile(r"address|street|postcode|post_?code|zip|city|latitude|longitude|geohash"),
        PiiClass.QUASI_IDENTIFIER,
    ),
    (
        re.compile(r"device|fingerprint|user_?agent|ip_?addr|cookie|session|imei|advertis"),
        PiiClass.QUASI_IDENTIFIER,
    ),
    (
        re.compile(r"cohort|segment|group|birth|dob|age$|gender|sex$|nationality|ethnicity"),
        PiiClass.QUASI_IDENTIFIER,
    ),
    (re.compile(r"amount|price|balance|revenue|fee|charge|payment"), PiiClass.FINANCIAL),
)
"""Column-name rules, most restrictive first. The first match wins.

Ordering is the whole design. ``patient_hiv_status`` matches both the health rule and
nothing else; ``salary_2024`` matches financial. A column that matches two rules gets
the more restricted one because the list is walked in that order.
"""

_VALUE_PII_RULES: Final[tuple[tuple[re.Pattern[str], PiiClass], ...]] = (
    (re.compile(r"\A\d{3}-\d{2}-\d{4}\Z"), PiiClass.DIRECT_IDENTIFIER),
    (re.compile(r"\A[^@\s]+@[^@\s]+\.[^@\s]+\Z"), PiiClass.DIRECT_IDENTIFIER),
    (re.compile(r"\A\+?\d[\d\s().-]{7,}\d\Z"), PiiClass.DIRECT_IDENTIFIER),
    (re.compile(r"\A(?:\d[ -]?){13,19}\Z"), PiiClass.FINANCIAL),
    (re.compile(r"\A[A-Z]{2}\d{2}[A-Z0-9]{10,30}\Z"), PiiClass.FINANCIAL),
    (
        re.compile(
            r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
        ),
        PiiClass.QUASI_IDENTIFIER,
    ),
)
"""Value-format rules, applied to bounds and most-common-values.

These look at data we already hold. They catch the case the name rules miss: a column
called ``col_7`` full of email addresses. They are a *second* first pass, not a scanner
at a boundary -- see invariant 2. Presidio, in A5, is the backstop; neither is the
control.
"""


def infer_pii_class(
    *,
    column_name: str,
    logical_type: LogicalType,
    sample_values: Sequence[ScalarValue] = (),
) -> PiiClass:
    """First-pass PII classification from a column name and whatever values we hold.

    Returns the more restrictive of the name verdict and the value verdict. Returns
    ``UNKNOWN`` when neither rule set fires, which the gate reads as "deny", not as
    "fine". Never returns ``NONE``: this function is not confident enough to grant
    anything, and only a human is.
    """
    verdicts: list[PiiClass] = []
    lowered = column_name.strip().casefold()
    for pattern, verdict in _NAME_PII_RULES:
        if pattern.search(lowered):
            verdicts.append(verdict)
            break
    for value in sample_values:
        if not isinstance(value, str):
            continue
        for pattern, verdict in _VALUE_PII_RULES:
            if pattern.match(value.strip()):
                verdicts.append(verdict)
                break
    if not verdicts:
        return PiiClass.UNKNOWN
    if logical_type is LogicalType.UNKNOWN:
        verdicts.append(PiiClass.UNKNOWN)
    return max(verdicts, key=pii_restrictiveness)


# --------------------------------------------------------------------------------------
# Role inference
# --------------------------------------------------------------------------------------

_NUMERIC_TYPES: Final[frozenset[LogicalType]] = frozenset(
    {LogicalType.INT, LogicalType.FLOAT, LogicalType.DECIMAL}
)
_TEMPORAL_TYPES: Final[frozenset[LogicalType]] = frozenset(
    {LogicalType.DATE, LogicalType.TIMESTAMP}
)

_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(label|target|outcome|y|is_fraud|fraud_flag|is_churn|churn|chargeback_flag)\Z"
)
_ID_RE: Final[re.Pattern[str]] = re.compile(r"\A(id|uuid|guid)\Z|_id\Z|_key\Z|\Aid_|uuid|guid")
_TIME_RE: Final[re.Pattern[str]] = re.compile(r"_at\Z|_time\Z|_date\Z|\Ats\Z|timestamp|_ts\Z")
_AMOUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"amount|\Aamt|price|total|cost|balance|salary|revenue|fee\Z|charge|payment|value\Z"
)
_GEO_RE: Final[re.Pattern[str]] = re.compile(
    r"country|city|state\Z|region|zip|postcode|post_?code|postal|latitude|longitude|\Alat\Z|\Alon\Z|geo"
)
_DEVICE_RE: Final[re.Pattern[str]] = re.compile(
    r"device|user_?agent|browser|\Aos\Z|os_|ip_?addr|\Aip\Z|fingerprint|imei"
)
_TEXT_RE: Final[re.Pattern[str]] = re.compile(r"note|comment|description|message|memo|body|remark")

UNIQUE_RATIO: Final[float] = 0.9
"""Distinct-over-rows above which a column is treated as identifying rather than joining."""

CATEGORY_RATIO: Final[float] = 0.05
"""Distinct-over-rows below which a column is treated as categorical."""

CATEGORY_MAX_DISTINCT: Final[int] = 50
"""Absolute distinct ceiling for a category, for tables too small for the ratio to mean much."""


def infer_role(
    *,
    column_name: str,
    logical_type: LogicalType,
    pii_class: PiiClass = PiiClass.UNKNOWN,
    distinct_estimate: int | None = None,
    row_count: int | None = None,
) -> ColumnRole:
    """Infer what a column is for, from its name, type and cardinality.

    Precedence, highest first: label, event time, device, geography, identifier, free
    text, amount, category, measure. The order matters more than any individual rule,
    and the two places it is surprising are deliberate:

    * ``device_id`` is a device before it is an identifier. It is both, but a feature
      builder does very different things with a device than with a join key, and
      device reuse across accounts is one of the signals the product exists to find.
    * ``country`` is geography before it is a category, for the same reason.
    """
    lowered = column_name.strip().casefold()
    ratio = _cardinality_ratio(distinct_estimate, row_count)

    if _LABEL_RE.search(lowered):
        return ColumnRole.LABEL
    if logical_type in _TEMPORAL_TYPES:
        return ColumnRole.EVENT_TIME
    if logical_type is LogicalType.INT and _TIME_RE.search(lowered):
        return ColumnRole.EVENT_TIME
    if _DEVICE_RE.search(lowered):
        return ColumnRole.DEVICE
    if _GEO_RE.search(lowered):
        return ColumnRole.GEO
    if _ID_RE.search(lowered):
        return ColumnRole.ENTITY_ID if _is_unique(ratio) else ColumnRole.JOIN_KEY
    if pii_class is PiiClass.DIRECT_IDENTIFIER and _is_unique(ratio):
        return ColumnRole.ENTITY_ID
    if _TEXT_RE.search(lowered):
        return ColumnRole.FREE_TEXT
    if _AMOUNT_RE.search(lowered) and logical_type in _NUMERIC_TYPES:
        return ColumnRole.AMOUNT
    if _is_categorical(logical_type, distinct_estimate, ratio):
        return ColumnRole.CATEGORY
    if logical_type in _NUMERIC_TYPES:
        return ColumnRole.MEASURE
    return ColumnRole.UNKNOWN


def _cardinality_ratio(distinct_estimate: int | None, row_count: int | None) -> float | None:
    if distinct_estimate is None or row_count is None or row_count <= 0:
        return None
    return distinct_estimate / row_count


def _is_unique(ratio: float | None) -> bool:
    return ratio is not None and ratio >= UNIQUE_RATIO


def _is_categorical(
    logical_type: LogicalType, distinct_estimate: int | None, ratio: float | None
) -> bool:
    if logical_type is LogicalType.BOOL:
        return True
    if logical_type not in (LogicalType.STRING, LogicalType.INT):
        return False
    if distinct_estimate is not None and distinct_estimate <= CATEGORY_MAX_DISTINCT:
        return True
    return ratio is not None and ratio < CATEGORY_RATIO


# --------------------------------------------------------------------------------------
# Join edges
# --------------------------------------------------------------------------------------

JOINABLE_ROLES: Final[frozenset[ColumnRole]] = frozenset(
    {ColumnRole.ENTITY_ID, ColumnRole.JOIN_KEY}
)

_CONTAINMENT_WEIGHT: Final[float] = 0.5
_NDV_WEIGHT: Final[float] = 0.3
_NAME_WEIGHT: Final[float] = 0.2


def infer_join_edges(
    tables: Sequence[SnapshotMetadata],
    *,
    observed_at: Instant,
    min_confidence: float = 0.5,
) -> tuple[JoinEdge, ...]:
    """Propose joins across tables by approximate inclusion dependency.

    The claim an edge makes is "the values of the left column look like a subset of the
    values of the right column". We can test that for free from two catalog facts: the
    left's distinct count is no larger than the right's, and the left's bounds sit
    inside the right's. Neither is proof -- bounds are two values and NDV is an estimate
    -- which is why the result is a confidence, and why confirming an edge costs a
    budgeted scan that somebody else decides to spend.

    Deterministic: edges come back sorted by descending confidence, then by the tables
    and columns involved, so two runs over the same catalog produce the same list.
    """
    edges: list[tuple[float, str, str, JoinEdge]] = []
    for left_table_index, left_table in enumerate(tables):
        for right_table in tables[left_table_index + 1 :]:
            for left in _joinable_columns(left_table):
                for right in _joinable_columns(right_table):
                    for ordered_left, ordered_right in ((left, right), (right, left)):
                        edge = _edge_for(
                            ordered_left,
                            ordered_right,
                            observed_at=observed_at,
                            min_confidence=min_confidence,
                        )
                        if edge is not None:
                            edges.append(
                                (
                                    -edge.confidence,
                                    ordered_left.ref.column.reveal(),
                                    ordered_right.ref.column.reveal(),
                                    edge,
                                )
                            )
    edges.sort(key=lambda item: (item[0], item[1], item[2]))
    return tuple(edge for _, _, _, edge in edges)


def _joinable_columns(table: SnapshotMetadata) -> tuple[ColumnMetadata, ...]:
    return tuple(column for column in table.columns if column.role in JOINABLE_ROLES)


def _edge_for(
    left: ColumnMetadata,
    right: ColumnMetadata,
    *,
    observed_at: Instant,
    min_confidence: float,
) -> JoinEdge | None:
    if left.logical_type is not right.logical_type:
        return None
    left_ndv = left.distinct_estimate.reveal() if left.distinct_estimate is not None else None
    right_ndv = right.distinct_estimate.reveal() if right.distinct_estimate is not None else None
    if left_ndv is None or right_ndv is None or left_ndv <= 0 or right_ndv <= 0:
        return None
    if left_ndv > right_ndv:
        return None

    containment = _bounds_containment(left, right)
    ndv_term = min(1.0, right_ndv / left_ndv) if left_ndv else 0.0
    name_term = _name_affinity(left.ref.column.reveal(), right.ref.column.reveal())
    confidence = (
        _CONTAINMENT_WEIGHT * containment + _NDV_WEIGHT * ndv_term + _NAME_WEIGHT * name_term
    )
    if confidence < min_confidence:
        return None

    reasons = ["ndv_inclusion"]
    if containment > 0.0:
        reasons.append("bounds_containment")
    if name_term > 0.0:
        reasons.append("name_affinity")
    return JoinEdge(
        left=left.ref,
        right=right.ref,
        confidence=min(1.0, confidence),
        inferred_from="+".join(reasons),
        left_to_right_cardinality=_cardinality_statistic(left, right_ndv / left_ndv),
        observed_at=observed_at,
    )


def _cardinality_statistic(left: ColumnMetadata, ratio: float) -> Tainted[float]:
    return derived_statistic(
        ratio,
        acquisition=Acquisition.SKETCH_SUMMARY,
        source_id=left.ref.source_id,
        column=left.ref.column.reveal(),
    )


def _bounds_containment(left: ColumnMetadata, right: ColumnMetadata) -> float:
    """1.0 when the left's bounds sit inside the right's, 0.0 when they cannot be compared.

    Bounds are revealed here and discarded here. Nothing derived from the comparison
    beyond a 0 or a 1 leaves this function.
    """
    corners = (left.lower_bound, left.upper_bound, right.lower_bound, right.upper_bound)
    if any(corner is None for corner in corners):
        return 0.0
    values = [corner.reveal() for corner in corners if corner is not None]
    left_low, left_high, right_low, right_high = values
    lower_ok = scalar_le(right_low, left_low)
    upper_ok = scalar_le(left_high, right_high)
    if lower_ok is None or upper_ok is None:
        return 0.0
    return 1.0 if (lower_ok and upper_ok) else 0.0


def _name_affinity(left_name: str, right_name: str) -> float:
    """How much two column names suggest the same thing. Names, never values."""
    left_lowered = left_name.casefold()
    right_lowered = right_name.casefold()
    if left_lowered == right_lowered:
        return 1.0
    left_stem = re.sub(r"_(id|key)\Z", "", left_lowered)
    right_stem = re.sub(r"_(id|key)\Z", "", right_lowered)
    if left_stem and left_stem == right_stem:
        return 0.9
    if (
        left_stem
        and right_stem
        and (left_stem.endswith(right_stem) or right_stem.endswith(left_stem))
    ):
        return 0.6
    return 0.0
