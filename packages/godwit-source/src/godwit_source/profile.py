"""Semantic profiling with no LLM in the path.

DATA PLANE. Roles, a first-pass PII class and candidate join edges, inferred from names,
types, cardinality ratios and -- for ``OPEN`` columns only -- the *format* of a manifest
bound. The format is emitted; the bound is not.

Two things this module is careful about:

- Nothing here is a classification. Everything it emits is ``confirmed=False``, which means
  :class:`godwit_source.access.AccessPolicy` resolves the column to ``BLIND``. A guess never
  unlocks a read. A5 refines these, a human confirms them.
- It never blocks on A15. The whole L-1 tier has to be useful with the LLM layer deleted,
  per invariant 7, and that includes deciding what a column probably is.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ._contracts import ColumnAccessMode, PiiClass, SemanticRole
from .stats import ColumnMetadata, SnapshotMetadata

__all__ = [
    "ColumnProfile",
    "JoinEdge",
    "candidate_join_edges",
    "profile_column",
    "profile_snapshot",
    "value_format",
]

_ENTITY_ID_RATIO = 0.9
_CATEGORY_RATIO = 0.05

_FORMATS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)),
    ("uuid", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("ipv4", re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")),
    ("iban", re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")),
    ("e164_phone", re.compile(r"^\+?[1-9]\d{7,14}$")),
    ("pan_like", re.compile(r"^\d{13,19}$")),
    ("us_ssn", re.compile(r"^\d{3}-\d{2}-\d{4}$")),
    ("iso_date", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
)

_SECRET = re.compile(
    r"pass(word|wd)?|secret|token|api_?key|private_?key|credential|cvv|cvc|\bpin\b|salt|otp", re.I
)
_FREE_TEXT = re.compile(r"note|comment|description|memo|body|message|remark|feedback|bio", re.I)
_DIRECT = re.compile(
    r"email|phone|mobile|msisdn|ssn|sin\b|nric|passport|iban|account_?(no|num|number)|"
    r"card_?(no|num|number)|pan\b|device_?id|imei|ip_?addr|ip\b|user_?name|login|"
    r"full_?name|first_?name|last_?name|surname|street|address",
    re.I,
)
_QUASI = re.compile(
    r"dob|birth|gender|sex\b|zip|postal|postcode|city|country|region|age\b|occupation|employer",
    re.I,
)
_SENSITIVE = re.compile(
    r"health|medical|diagnos|hiv|disease|religio|ethnic|race\b|political|union|"
    r"salary|income|wage|criminal|conviction|biometric|genetic|orientation",
    re.I,
)

_ID_NAME = re.compile(r"(^|_)(id|key|uuid|guid)$|^id$", re.I)
_TIME_NAME = re.compile(r"(_at$|_date$|_time$|^ts$|_ts$|timestamp|created|updated|occurred)", re.I)
_AMOUNT_NAME = re.compile(r"amount|amt|price|total|balance|fee|cost|value|revenue|charge", re.I)
_FLAG_NAME = re.compile(r"^(is|has|can|should)_", re.I)
_GEO_NAME = re.compile(r"lat(itude)?$|lon(g|gitude)?$|zip|postal|city|country|region|address", re.I)

_PROFILING = "format inference inside the data plane; only the format name is emitted"


@dataclass(frozen=True, slots=True)
class ColumnProfile:
    """A first-pass read of one column.

    ``confirmed`` is deliberately absent: a profile is never confirmed. Feed it to A5 and a
    reviewer; do not feed it to :class:`~godwit_source.access.AccessPolicy` as if it were a
    classification.
    """

    table: str
    column: str
    data_type: str
    semantic_role: SemanticRole
    pii_class: PiiClass
    cardinality_ratio: float | None
    value_format: str | None
    reasons: tuple[str, ...]


def value_format(value: object) -> str | None:
    """Name the format a value matches, without retaining the value.

    Runs inside the data plane against a manifest bound or a ``most_common_vals`` entry, and
    returns a format label such as ``"email"``. The label is a derived statistic; the value
    it was computed from stays where it was.
    """
    text = str(value).strip()
    if not text:
        return None
    for name, pattern in _FORMATS:
        if pattern.match(text):
            return name
    return None


def _infer_pii(column: str, fmt: str | None, data_type: str) -> tuple[PiiClass, list[str]]:
    reasons: list[str] = []
    if _SECRET.search(column):
        return PiiClass.SECRET, ["name matches secret pattern"]
    if _FREE_TEXT.search(column) and any(t in data_type for t in ("char", "string", "text")):
        return PiiClass.FREE_TEXT, ["prose-shaped name on a text type"]
    if _SENSITIVE.search(column):
        return PiiClass.SENSITIVE_ATTRIBUTE, ["name matches sensitive-attribute pattern"]
    if _DIRECT.search(column):
        reasons.append("name matches direct-identifier pattern")
        return PiiClass.DIRECT_IDENTIFIER, reasons
    if fmt in ("email", "e164_phone", "iban", "pan_like", "us_ssn", "ipv4"):
        return PiiClass.DIRECT_IDENTIFIER, [f"bound value matches {fmt} format"]
    if _QUASI.search(column):
        return PiiClass.QUASI_IDENTIFIER, ["name matches quasi-identifier pattern"]
    return PiiClass.UNKNOWN, ["no name or format signal; fails closed to BLIND"]


def _infer_role(
    column: str, data_type: str, ratio: float | None, fmt: str | None
) -> tuple[SemanticRole, list[str]]:
    lowered = data_type.lower()
    if _TIME_NAME.search(column) or any(t in lowered for t in ("timestamp", "date", "time")):
        return SemanticRole.TIMESTAMP, ["name or type indicates a time"]
    if lowered.startswith("bool") or _FLAG_NAME.search(column):
        return SemanticRole.BOOLEAN_FLAG, ["boolean type or is_/has_ prefix"]
    if _ID_NAME.search(column) or fmt == "uuid":
        if ratio is not None and ratio >= _ENTITY_ID_RATIO:
            return SemanticRole.ENTITY_ID, ["id-shaped name, near-unique"]
        return SemanticRole.FOREIGN_KEY, ["id-shaped name, repeating values"]
    if _AMOUNT_NAME.search(column) and any(
        t in lowered for t in ("int", "float", "double", "decimal", "numeric")
    ):
        return SemanticRole.AMOUNT, ["money-shaped name on a numeric type"]
    if _GEO_NAME.search(column):
        return SemanticRole.GEO, ["name indicates a place"]
    if _FREE_TEXT.search(column):
        return SemanticRole.FREE_TEXT, ["name indicates prose"]
    if ratio is not None and ratio <= _CATEGORY_RATIO:
        return SemanticRole.CATEGORY, ["low cardinality ratio"]
    return SemanticRole.UNKNOWN, ["no role signal"]


def profile_column(meta: ColumnMetadata) -> ColumnProfile:
    """Profile one column from free metadata alone.

    A bound is inspected only when the column is already ``OPEN``; for ``OPAQUE`` the
    adapter never surfaced one, so format inference simply has less to work with and the
    name patterns carry the whole inference.
    """
    ratio = meta.counts.ndv_ratio
    fmt: str | None = None
    if meta.access_mode is ColumnAccessMode.OPEN and meta.bounds is not None:
        for bound in (meta.bounds.lower, meta.bounds.upper):
            if bound is None:
                continue
            fmt = value_format(bound.unwrap(_PROFILING))
            if fmt is not None:
                break
    role, role_reasons = _infer_role(meta.column, meta.data_type, ratio, fmt)
    pii, pii_reasons = _infer_pii(meta.column, fmt, meta.data_type.lower())
    return ColumnProfile(
        table=meta.table,
        column=meta.column,
        data_type=meta.data_type,
        semantic_role=role,
        pii_class=pii,
        cardinality_ratio=ratio,
        value_format=fmt,
        reasons=tuple(role_reasons + pii_reasons),
    )


def profile_snapshot(snapshot: SnapshotMetadata) -> list[ColumnProfile]:
    """Profile every column in a snapshot, in schema order."""
    return [profile_column(meta) for meta in snapshot.columns.values()]


@dataclass(frozen=True, slots=True)
class JoinEdge:
    """A candidate join, scored by approximate inclusion dependency.

    ``containment`` is the NDV-ratio estimate of how much of the smaller column's domain
    could fit inside the larger one. It is an upper bound on real containment, not a
    measurement: two columns with disjoint values and equal NDV score 1.0 here. Confirming
    an edge costs a probe, which is exactly the trade this layer exists to set up.
    """

    left_table: str
    left_column: str
    right_table: str
    right_column: str
    containment: float
    score: float
    reasons: tuple[str, ...]


def _numeric_bounds(meta: ColumnMetadata) -> tuple[float, float] | None:
    if meta.access_mode is not ColumnAccessMode.OPEN or meta.bounds is None:
        return None
    lower, upper = meta.bounds.lower, meta.bounds.upper
    if lower is None or upper is None:
        return None
    try:
        return float(lower.unwrap(_PROFILING)), float(upper.unwrap(_PROFILING))
    except (TypeError, ValueError):
        return None


def _overlap(a: tuple[float, float], b: tuple[float, float]) -> float:
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    if hi <= lo:
        return 0.0
    span = max(a[1] - a[0], b[1] - b[0])
    return 1.0 if span <= 0 else (hi - lo) / span


def _name_affinity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    left_stem = re.sub(r"(_id|_key|_uuid)$", "", left)
    right_stem = re.sub(r"(_id|_key|_uuid)$", "", right)
    if left_stem and left_stem == right_stem:
        return 0.9
    if left_stem and (left_stem in right or right_stem in left):
        return 0.6
    return 0.0


def candidate_join_edges(
    snapshots: Iterable[SnapshotMetadata],
    *,
    min_score: float = 0.5,
    roles: Sequence[SemanticRole] = (SemanticRole.ENTITY_ID, SemanticRole.FOREIGN_KEY),
) -> list[JoinEdge]:
    """Propose join edges across tables from NDV, bounds overlap and name affinity.

    Works for ``OPAQUE`` columns, which is the point: the shared-attribute graph -- how many
    accounts share this device, this address, this phone -- is the strongest organised-fraud
    signal in the design, and every column in it is a direct identifier. NDV and name give
    us the edge; no value is needed to propose one.
    """
    profiled: list[tuple[ColumnMetadata, ColumnProfile]] = []
    for snapshot in snapshots:
        for meta in snapshot.columns.values():
            prof = profile_column(meta)
            if prof.semantic_role in roles:
                profiled.append((meta, prof))

    edges: list[JoinEdge] = []
    for i, (left_meta, left_prof) in enumerate(profiled):
        for right_meta, right_prof in profiled[i + 1 :]:
            if left_meta.table == right_meta.table:
                continue
            if left_meta.data_type != right_meta.data_type:
                continue
            left_ndv = left_meta.counts.ndv
            right_ndv = right_meta.counts.ndv
            if left_ndv is None or right_ndv is None:
                continue
            lo = float(left_ndv.unwrap(_PROFILING))
            ro = float(right_ndv.unwrap(_PROFILING))
            if lo <= 0 or ro <= 0:
                continue
            containment = min(lo, ro) / max(lo, ro)
            affinity = _name_affinity(left_prof.column, right_prof.column)
            reasons = [f"ndv containment {containment:.2f}", f"name affinity {affinity:.2f}"]
            bounds_term = 0.0
            left_bounds, right_bounds = _numeric_bounds(left_meta), _numeric_bounds(right_meta)
            if left_bounds is not None and right_bounds is not None:
                bounds_term = _overlap(left_bounds, right_bounds)
                reasons.append(f"bounds overlap {bounds_term:.2f}")
            score = 0.5 * containment + 0.4 * affinity + 0.1 * bounds_term
            if score < min_score or math.isnan(score):
                continue
            edges.append(
                JoinEdge(
                    left_table=left_meta.table,
                    left_column=left_meta.column,
                    right_table=right_meta.table,
                    right_column=right_meta.column,
                    containment=containment,
                    score=score,
                    reasons=tuple(reasons),
                )
            )
    edges.sort(key=lambda e: (-e.score, e.left_table, e.left_column, e.right_table))
    return edges
