"""Column access modes -- BLIND, OPAQUE, OPEN -- and the entropy check behind OPAQUE.

**Plane: both.** Mode resolution is control-plane state (no values). The keyed hasher,
the format-entropy estimator and the projection checks run in the DATA PLANE.

Excluding sensitive columns from probing is the obvious answer and it is wrong: the
strongest organised-fraud signal in the product is shared-attribute structure over
direct identifiers. So every column carries a mode instead of a yes/no flag:

``BLIND``   never enters a query projection. Enforced at PLAN time.
``OPAQUE``  read only through a keyed hash; the key stays in the data plane. The
            DEFAULT for identifiers, provided the column passes the entropy check.
``OPEN``    values retained, still gated on the way out. Needs an ALLOW guardrail and
            an AccessGrant.

RESOLUTION, IN ORDER
--------------------
1. No confirmed classification -> BLIND. Always. Grants do not apply.
2. Base mode from the confirmed class: NONE -> OPEN; CREDENTIAL or free text -> BLIND;
   every other class -> OPAQUE.
3. Active :class:`AccessGrant` s widen, never past a cap. A grant to OPEN must cite an
   ALLOW guardrail that matches the column.
4. Caps: a matching DENY guardrail caps at BLIND; REDACT or REQUIRE_APPROVAL cap at
   OPAQUE; a :class:`Narrowing` caps wherever it says. Narrowing is immediate.
5. OPAQUE must pass the minimum-entropy check, or the column resolves to BLIND with a
   remediation of BUCKET. Hashing a four-digit PIN is not anonymisation, and this is
   the place that refuses to pretend otherwise.

THE ENTROPY CHECK, AND ITS THREAT MODEL
---------------------------------------
With the key secret, a keyed hash cannot be enumerated at all. What it does NOT hide is
*frequency*: a hashed country column is a relabelled country column, and matching its
histogram to public country shares recovers it with no key. And if the key is ever
compromised, every value in a small space enumerates in seconds.

The check estimates the plausible input space as the smallest of the priors that apply
(name concept, logical type, observed format), floored at the observed distinct count,
and requires ``log2(space) >= min_bits``. The default of 24 bits rejects PINs, country
codes, postcodes, birth dates, sexes, ages and NIC prefixes. It does NOT make a keyed
hash of an SSN or a phone number safe against a key compromise: those spaces are ~2^30,
which a GPU walks in seconds. Raise ``min_bits`` to 40 if key compromise is in your
threat model; SSNs and phones then resolve to BLIND. Key custody is the control; the
entropy floor is what stops the tiny domains that no key can protect.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from collections.abc import Sequence
from enum import StrEnum
from typing import Final, NoReturn, Self

from godwit_contracts import (
    ColumnRef,
    ColumnRole,
    Guardrail,
    GuardrailAction,
    GuardrailAttribute,
    Instant,
    LogicalType,
    NonNegInt,
    PiiClass,
    Plane,
    ScalarValue,
    Sensitivity,
)
from godwit_contracts.common import GodwitModel
from godwit_contracts.segment import canonical_column, canonical_scalar
from pydantic import Field, model_validator

from godwit_guard.classify import ClassificationRegistry, match_concept, ref_key
from godwit_guard.errors import GrantError, OpaqueHashRefusedError, ProjectionViolationError
from godwit_guard.guardrails import AttrValue, applicable, is_access_guardrail
from godwit_guard.ledger import EgressLedger, audit_event

__all__ = [
    "DEFAULT_MIN_ENTROPY_BITS",
    "OPAQUE_SUFFIX",
    "AccessControl",
    "AccessGrant",
    "AccessMode",
    "AccessModeMap",
    "EntropyAssessment",
    "KeyedHasher",
    "ModeDecision",
    "Narrowing",
    "ProjectionPlan",
    "Remediation",
    "assess_entropy",
    "format_space_bits",
    "plan_projection",
    "verify_arrow_schema",
    "verify_sql",
]

DEFAULT_MIN_ENTROPY_BITS: Final[float] = 24.0
OPAQUE_SUFFIX: Final[str] = "__opaque"
"""An OPAQUE column appears in a result schema only as ``<name>__opaque``, hashed."""


class AccessMode(StrEnum):
    """How a column may be read. Ordered BLIND < OPAQUE < OPEN."""

    BLIND = "blind"
    OPAQUE = "opaque"
    OPEN = "open"


_RANK: Final[dict[AccessMode, int]] = {
    AccessMode.BLIND: 0,
    AccessMode.OPAQUE: 1,
    AccessMode.OPEN: 2,
}


def _narrowest(*modes: AccessMode) -> AccessMode:
    return min(modes, key=_RANK.__getitem__)


class Remediation(StrEnum):
    """What to do with a column that cannot be OPAQUE."""

    BUCKET = "bucket"
    BLIND = "blind"


# --------------------------------------------------------------------------------------
# Entropy
# --------------------------------------------------------------------------------------


class EntropyAssessment(GodwitModel):
    """How many distinct real-world values a column plausibly draws from."""

    bits: float
    min_bits: float
    observed_distinct: NonNegInt | None = None
    basis: tuple[str, ...]
    """Which priors applied, e.g. ``concept:postcode``. Names of rules, never values."""

    @property
    def passed(self) -> bool:
        """True when a keyed hash of this column is not trivially reversible."""
        return self.bits >= self.min_bits


_CHAR_CLASSES: Final[tuple[tuple[re.Pattern[str], int], ...]] = (
    (re.compile(r"\d"), 10),
    (re.compile(r"[a-z]"), 26),
    (re.compile(r"[A-Z]"), 26),
)
_MAX_BITS: Final[float] = 256.0


def format_space_bits(values: Sequence[ScalarValue]) -> float | None:
    """Estimate log2 of the space a column's *format* allows. **Data plane.**

    Each character contributes the size of its class (digit 10, letter 26); anything
    else is treated as a literal separator and contributes nothing. The widest sample
    wins. ``1234`` gives 13.3 bits; ``US`` gives 9.4; ``dev-0000-a4f7723b`` gives 50.
    Integers count their digits. Floats, dates and bytes return None: format says
    nothing useful about them, and a concept or type prior must speak instead.

    The result is a derived statistic about the column and may cross the boundary.
    """
    widest: float | None = None
    for value in values:
        if isinstance(value, bool) or value is None:
            continue
        if isinstance(value, int):
            text = str(abs(value))
        elif isinstance(value, str):
            text = value
        else:
            continue
        bits = 0.0
        for char in text:
            for pattern, size in _CHAR_CLASSES:
                if pattern.fullmatch(char):
                    bits += math.log2(size)
                    break
        widest = bits if widest is None else max(widest, bits)
    return None if widest is None else min(widest, _MAX_BITS)


SATURATION_FACTOR: Final[int] = 2
"""Rows per distinct value above which the observed domain is taken as the whole domain."""

_TYPE_PRIORS: Final[dict[LogicalType, int]] = {
    LogicalType.BOOL: 2,
    LogicalType.DATE: 73_050,
}


def assess_entropy(
    *,
    column_name: str,
    logical_type: LogicalType,
    observed_distinct: int | None,
    format_bits: float | None,
    row_count: int | None = None,
    min_bits: float = DEFAULT_MIN_ENTROPY_BITS,
) -> EntropyAssessment:
    """Decide whether a keyed hash of this column is worth anything.

    Plausible space = min(applicable priors), floored at the observed distinct count.
    With no prior at all, the observed distinct count is the only evidence, which on a
    small table fails -- fail closed.

    When `row_count` shows values repeating (at least :data:`SATURATION_FACTOR` rows
    per distinct value), the domain has been seen: the observed distinct count *is* the
    space, however long the values look. `negative` / `positive` / `unknown` is
    three values, not 2^37 strings of eight letters, and its hashes fall to frequency
    analysis with no key at all.
    """
    priors: list[tuple[str, float]] = []
    concept = match_concept(column_name)
    if concept is not None and concept.space is not None:
        priors.append((f"concept:{concept.name}", float(concept.space)))
    type_prior = _TYPE_PRIORS.get(logical_type)
    if type_prior is not None:
        priors.append((f"type:{logical_type.value}", float(type_prior)))
    if format_bits is not None:
        priors.append(("format", 2.0 ** min(format_bits, _MAX_BITS)))
    if (
        row_count is not None
        and observed_distinct is not None
        and observed_distinct * SATURATION_FACTOR <= row_count
    ):
        priors.append(("observed_domain_saturated", float(max(1, observed_distinct))))
    floor = float(max(1, observed_distinct or 1))
    if priors:
        label, space = min(priors, key=lambda item: item[1])
        basis = [label]
    else:
        space, basis = floor, ["no_prior:observed_distinct_only"]
    if space < floor:
        space = floor
        basis.append("floored_at_observed_distinct")
    return EntropyAssessment(
        bits=round(math.log2(space), 4),
        min_bits=min_bits,
        observed_distinct=observed_distinct,
        basis=tuple(basis),
    )


# --------------------------------------------------------------------------------------
# Grants and narrowings
# --------------------------------------------------------------------------------------


class AccessGrant(GodwitModel):
    """A widening of one column's mode. Needs a reason, an approver and an expiry.

    Grants expire by default. A permanent grant is a deliberate, separately audited
    act: it must set ``permanent=True`` and leave ``expires_at`` empty, and
    :meth:`AccessControl.grant` writes a second audit event for it.
    """

    grant_id: str = Field(min_length=1)
    column: ColumnRef
    from_mode: AccessMode
    to_mode: AccessMode
    reason: str = Field(min_length=1)
    requested_by: str = Field(min_length=1)
    approved_by: str = Field(min_length=1)
    granted_at: Instant
    expires_at: Instant | None = None
    permanent: bool = False
    authorising_guardrail_id: str | None = Field(
        default=None,
        description="Required for OPEN: the ALLOW guardrail that authorises raw values.",
    )

    @model_validator(mode="after")
    def _is_a_real_grant(self) -> Self:
        if _RANK[self.to_mode] <= _RANK[self.from_mode]:
            raise ValueError("a grant must widen; narrowing needs no grant")
        if self.approved_by == self.requested_by:
            raise ValueError("a grant cannot be approved by the person who requested it")
        if self.permanent == (self.expires_at is not None):
            raise ValueError("a grant has an expiry, or is explicitly permanent; not both")
        if self.expires_at is not None and self.expires_at <= self.granted_at:
            raise ValueError("a grant must expire after it is granted")
        if self.to_mode is AccessMode.OPEN and not self.authorising_guardrail_id:
            raise ValueError("widening to OPEN must cite an authorising ALLOW guardrail")
        return self

    def active_at(self, at: Instant) -> bool:
        """True between ``granted_at`` and ``expires_at``, or forever if permanent."""
        if at < self.granted_at:
            return False
        return self.permanent or (self.expires_at is not None and at < self.expires_at)


class Narrowing(GodwitModel):
    """An immediate cap on a column's mode. Needs no approval."""

    narrowing_id: str = Field(min_length=1)
    column: ColumnRef
    to_mode: AccessMode
    reason: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    at: Instant


class ModeDecision(GodwitModel):
    """The resolved mode of one column, and every reason it is what it is."""

    column: ColumnRef
    mode: AccessMode
    pii_class: PiiClass
    confirmed: bool
    reasons: tuple[str, ...]
    entropy: EntropyAssessment | None = None
    remediation: Remediation | None = None
    grant_id: str | None = None
    guardrail_ids: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        """The column key this decision is filed under."""
        return ref_key(self.column)


class AccessModeMap(GodwitModel):
    """The current mode of every known column, as queryable state.

    A18 asserts on it; A17 renders it. Column names inside are SCHEMA_NAME-tainted
    ``ColumnRef`` s, so showing this to a person is itself an egress through the gate.
    A column that is not in the map is BLIND.
    """

    resolved_at: Instant
    decisions: tuple[ModeDecision, ...]

    def decision(self, ref: ColumnRef) -> ModeDecision | None:
        """The decision for exactly this column, or None."""
        wanted = ref_key(ref)
        return next((d for d in self.decisions if d.key == wanted), None)

    def mode_of(self, ref: ColumnRef) -> AccessMode:
        """The column's mode; BLIND if it is unknown."""
        found = self.decision(ref)
        return AccessMode.BLIND if found is None else found.mode

    def decision_for(self, source_id: str | None, table: str, column: str) -> ModeDecision | None:
        """Look a decision up by plain names. **Data plane**: it takes revealed names."""
        wanted = (canonical_column(table), canonical_column(column))
        for decision in self.decisions:
            ref = decision.column
            if source_id is not None and ref.source_id != source_id:
                continue
            if (
                canonical_column(ref.table.reveal()),
                canonical_column(ref.column.reveal()),
            ) == wanted:
                return decision
        return None

    def counts(self) -> dict[str, int]:
        """How many columns sit in each mode. Safe to show: counts, no names."""
        tally = {mode.value: 0 for mode in AccessMode}
        for decision in self.decisions:
            tally[decision.mode.value] += 1
        return tally


# --------------------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------------------


class AccessControl:
    """Resolves and records access modes. Every change is an audited event."""

    def __init__(
        self,
        registry: ClassificationRegistry,
        *,
        ledger: EgressLedger,
        min_entropy_bits: float = DEFAULT_MIN_ENTROPY_BITS,
    ) -> None:
        self._registry = registry
        self._ledger = ledger
        self._min_bits = min_entropy_bits
        self._grants: dict[str, AccessGrant] = {}
        self._revoked: set[str] = set()
        self._narrowings: dict[str, Narrowing] = {}
        self._entropy: dict[str, EntropyAssessment] = {}

    def record_entropy(self, column: ColumnRef, assessment: EntropyAssessment) -> None:
        """Store the data plane's entropy assessment for a column."""
        self._entropy[ref_key(column)] = assessment

    def grant(self, grant: AccessGrant, *, actor: str) -> None:
        """Record a widening. Audited; a permanent grant is audited twice."""
        if grant.grant_id in self._grants:
            raise GrantError("grant ids are unique; issue a new grant instead")
        self._grants[grant.grant_id] = grant
        detail = {
            "from": grant.from_mode.value,
            "to": grant.to_mode.value,
            "permanent": grant.permanent,
            "approved_by": grant.approved_by,
        }
        self._ledger.append_audit(
            audit_event(
                action="access.grant",
                actor=actor,
                subject_kind="access_grant",
                subject_id=grant.grant_id,
                at=grant.granted_at,
                detail=detail,
                plane=Plane.CONTROL,
            )
        )
        if grant.permanent:
            self._ledger.append_audit(
                audit_event(
                    action="access.grant.permanent",
                    actor=actor,
                    subject_kind="access_grant",
                    subject_id=grant.grant_id,
                    at=grant.granted_at,
                    detail=detail,
                    plane=Plane.CONTROL,
                )
            )

    def revoke(self, grant_id: str, *, actor: str, at: Instant) -> None:
        """Revoke a grant. Revocation narrows, so it is immediate and needs no approver."""
        if grant_id not in self._grants:
            raise GrantError("unknown grant")
        self._revoked.add(grant_id)
        self._ledger.append_audit(
            audit_event(
                action="access.revoke",
                actor=actor,
                subject_kind="access_grant",
                subject_id=grant_id,
                at=at,
                plane=Plane.CONTROL,
            )
        )

    def narrow(self, narrowing: Narrowing) -> None:
        """Cap a column's mode, immediately. Audited; no approval needed."""
        self._narrowings[narrowing.narrowing_id] = narrowing
        self._ledger.append_audit(
            audit_event(
                action="access.narrow",
                actor=narrowing.actor,
                subject_kind="column",
                subject_id=ref_key(narrowing.column),
                at=narrowing.at,
                detail={"to": narrowing.to_mode.value},
                plane=Plane.CONTROL,
            )
        )

    def lift(
        self, narrowing_id: str, *, actor: str, approved_by: str, reason: str, at: Instant
    ) -> None:
        """Remove a narrowing. That widens, so it needs a second person and a reason."""
        if narrowing_id not in self._narrowings:
            raise GrantError("unknown narrowing")
        if not reason or not approved_by or approved_by == actor:
            raise GrantError("lifting a narrowing needs a reason and a different approver")
        del self._narrowings[narrowing_id]
        self._ledger.append_audit(
            audit_event(
                action="access.lift",
                actor=actor,
                subject_kind="narrowing",
                subject_id=narrowing_id,
                at=at,
                detail={"approved_by": approved_by},
                plane=Plane.CONTROL,
            )
        )

    def resolve(
        self, column: ColumnRef, *, guardrails: Sequence[Guardrail], at: Instant
    ) -> ModeDecision:
        """Resolve one column's mode. See the module docstring for the order."""
        entry = self._registry.entry(column)
        if entry is None or not entry.confirmed:
            pii = PiiClass.UNKNOWN if entry is None else entry.effective_class
            return ModeDecision(
                column=column,
                mode=AccessMode.BLIND,
                pii_class=pii,
                confirmed=False,
                reasons=("no confirmed classification: fails closed",),
            )
        pii = entry.effective_class
        role = entry.proposal.role
        reasons: list[str] = []
        concept = entry.proposal.concept
        if pii is PiiClass.NONE:
            mode, reasons = AccessMode.OPEN, ["confirmed NONE"]
        elif pii is PiiClass.CREDENTIAL or role is ColumnRole.FREE_TEXT or concept == "free_text":
            mode, reasons = AccessMode.BLIND, ["pure liability: credential or free text"]
        else:
            mode, reasons = AccessMode.OPAQUE, [f"identifier-bearing class {pii.value}"]

        attrs: dict[GuardrailAttribute, AttrValue] = {
            GuardrailAttribute.PII_CLASS: pii.value,
            GuardrailAttribute.SOURCE_ID: column.source_id,
            GuardrailAttribute.COLUMN_NAME: column.column.reveal(),
            GuardrailAttribute.TABLE_NAME: column.table.reveal(),
            GuardrailAttribute.SENSITIVITY: Sensitivity.DATA_VALUE.value,
            GuardrailAttribute.PLANE: Plane.DATA.value,
        }
        fired = applicable([g for g in guardrails if is_access_guardrail(g)], attrs)
        allow_ids = {g.guardrail_id for g in fired if g.action is GuardrailAction.ALLOW}
        caps: list[AccessMode] = []
        for g in fired:
            if g.action is GuardrailAction.DENY:
                caps.append(AccessMode.BLIND)
            elif g.action is not GuardrailAction.ALLOW:
                caps.append(AccessMode.OPAQUE)

        grant_id: str | None = None
        for grant in self._active_grants(column, at):
            if grant.to_mode is AccessMode.OPEN and grant.authorising_guardrail_id not in allow_ids:
                reasons.append(f"grant {grant.grant_id} ignored: no matching ALLOW guardrail")
                continue
            if _RANK[grant.to_mode] > _RANK[mode]:
                mode, grant_id = grant.to_mode, grant.grant_id
                reasons.append(f"widened by grant {grant.grant_id}")

        caps.extend(
            n.to_mode
            for n in self._narrowings.values()
            if ref_key(n.column) == ref_key(column) and n.at <= at
        )
        if caps and _RANK[_narrowest(*caps)] < _RANK[mode]:
            mode = _narrowest(*caps)
            reasons.append("capped by guardrail or narrowing")

        entropy = self._entropy.get(ref_key(column))
        remediation: Remediation | None = None
        if mode is AccessMode.OPAQUE:
            if entropy is None:
                mode, remediation = AccessMode.BLIND, Remediation.BLIND
                reasons.append("no entropy assessment: keyed hashing cannot be certified")
            elif not entropy.passed:
                mode, remediation = AccessMode.BLIND, Remediation.BUCKET
                reasons.append(
                    f"entropy {entropy.bits:.1f} bits below {entropy.min_bits:.0f}: "
                    "a keyed hash would be enumerable"
                )
        return ModeDecision(
            column=column,
            mode=mode,
            pii_class=pii,
            confirmed=True,
            reasons=tuple(reasons),
            entropy=entropy,
            remediation=remediation,
            grant_id=grant_id,
            guardrail_ids=tuple(g.guardrail_id for g in fired),
        )

    def mode_map(self, *, guardrails: Sequence[Guardrail], at: Instant) -> AccessModeMap:
        """Resolve every column the registry knows about."""
        return AccessModeMap(
            resolved_at=at,
            decisions=tuple(
                self.resolve(entry.proposal.column, guardrails=guardrails, at=at)
                for entry in self._registry.entries()
            ),
        )

    def _active_grants(self, column: ColumnRef, at: Instant) -> list[AccessGrant]:
        key = ref_key(column)
        live = [
            g
            for g in self._grants.values()
            if g.grant_id not in self._revoked and ref_key(g.column) == key and g.active_at(at)
        ]
        return sorted(live, key=lambda g: (_RANK[g.to_mode], g.grant_id))


# --------------------------------------------------------------------------------------
# DATA PLANE: the keyed hasher and plan-time projection checks
# --------------------------------------------------------------------------------------


_MIN_KEY_BYTES: Final[int] = 32


class KeyedHasher:
    """HMAC-SHA256 with a data-plane key. Stable, so joins on OPAQUE columns still work.

    Refuses to hash any column whose decision is not OPAQUE-with-a-passing-entropy-check.
    The key is never rendered, copied or pickled.
    """

    __slots__ = ("_key", "key_id")

    def __init__(self, key: bytes, *, key_id: str) -> None:
        if len(key) < _MIN_KEY_BYTES:
            raise ValueError("a keyed-hash key must be at least 32 bytes")
        self._key = key
        self.key_id = key_id

    def digest(self, value: ScalarValue) -> str:
        """The keyed hash of one canonicalised value. Callers must hold a decision."""
        mac = hmac.new(self._key, canonical_scalar(value).encode("utf-8"), hashlib.sha256)
        return "h_" + mac.hexdigest()[:32]

    def hash_for(self, value: ScalarValue, *, decision: ModeDecision) -> str:
        """Hash a value of a column, if and only if that column may be OPAQUE."""
        if decision.mode is not AccessMode.OPAQUE or decision.entropy is None:
            raise OpaqueHashRefusedError("this column is not OPAQUE; refusing to hash it")
        if not decision.entropy.passed:
            raise OpaqueHashRefusedError(
                "this column failed the minimum-entropy check; a keyed hash of it is "
                "enumerable. Bucket it or blind it."
            )
        return self.digest(value)

    def __repr__(self) -> str:
        return f"<KeyedHasher key_id={self.key_id}>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("a KeyedHasher holds a data-plane key and cannot be serialised")


class ProjectionPlan(GodwitModel):
    """What a query may read from one table. **Data plane**: plain column names."""

    open_columns: tuple[str, ...]
    opaque_columns: tuple[str, ...]
    dropped: tuple[str, ...]
    """Requested but BLIND or unknown. They never reach SQL."""


def plan_projection(
    requested: Sequence[str], mode_map: AccessModeMap, *, source_id: str | None, table: str
) -> ProjectionPlan:
    """Split requested columns by mode, dropping BLIND and unknown ones at plan time."""
    open_cols: list[str] = []
    opaque_cols: list[str] = []
    dropped: list[str] = []
    for name in requested:
        decision = mode_map.decision_for(source_id, table, name)
        mode = AccessMode.BLIND if decision is None else decision.mode
        {AccessMode.OPEN: open_cols, AccessMode.OPAQUE: opaque_cols, AccessMode.BLIND: dropped}[
            mode
        ].append(name)
    return ProjectionPlan(
        open_columns=tuple(open_cols), opaque_columns=tuple(opaque_cols), dropped=tuple(dropped)
    )


_SQL_STRING: Final[re.Pattern[str]] = re.compile(r"'(?:[^']|'')*'")
_SQL_IDENT: Final[re.Pattern[str]] = re.compile(r'"((?:[^"]|"")+)"|([A-Za-z_][A-Za-z0-9_$]*)')


def verify_sql(sql: str, *, blind_columns: Sequence[str]) -> None:
    """Refuse SQL that mentions a BLIND column anywhere -- projection, WHERE, JOIN.

    A BLIND column in a WHERE clause is still read: its values pass through the engine,
    its memory and possibly a driver error. String literals are ignored; identifiers,
    quoted or bare, are compared after casefolding. The error names the column by its
    position in ``blind_columns``, never by name: an exception is a log line waiting to
    happen.
    """
    stripped = _SQL_STRING.sub("''", sql)
    idents = {
        canonical_column(quoted.replace('""', '"') if quoted else bare)
        for quoted, bare in _SQL_IDENT.findall(stripped)
    }
    for index, name in enumerate(blind_columns):
        if canonical_column(name) in idents:
            raise ProjectionViolationError(f"planned SQL reads BLIND column #{index}")


def verify_arrow_schema(
    field_names: Sequence[str], mode_map: AccessModeMap, *, source_id: str | None, table: str
) -> None:
    """Refuse a result schema that carries a BLIND, raw-OPAQUE or unknown column.

    Every field must be an OPEN column by name, or an OPAQUE column as
    ``<name>__opaque``. Anything else -- including a field that maps to no classified
    column -- is refused. Fail closed.
    """
    for index, field in enumerate(field_names):
        hashed = field.endswith(OPAQUE_SUFFIX)
        base = field[: -len(OPAQUE_SUFFIX)] if hashed else field
        decision = mode_map.decision_for(source_id, table, base)
        mode = AccessMode.BLIND if decision is None else decision.mode
        if mode is AccessMode.BLIND:
            raise ProjectionViolationError(f"result field #{index} is BLIND or unclassified")
        if mode is AccessMode.OPAQUE and not hashed:
            raise ProjectionViolationError(f"result field #{index} is OPAQUE but unhashed")
        if mode is AccessMode.OPEN and hashed:
            raise ProjectionViolationError(f"result field #{index} is OPEN but named as hashed")
