"""The egress gate. The only legitimate producer of ``SafePayload``.

Invariant 2 lives or dies here. :meth:`Gate.clear` takes tainted material, a
destination and a policy, and returns either a ``SafePayload`` with the
``EgressRecord`` that authorised it, or raises :class:`~godwit_guard.errors.EgressRefusedError`
carrying a :class:`~godwit_guard.errors.Refusal` that says why.

THE ISSUER
----------
This module claims the process's single ``SafePayloadIssuer`` at import time and keeps
it inside a closure. Nothing else in the codebase may claim it, and
``tests/test_gate.py::test_nothing_else_in_the_workspace_mints_payloads`` scans every
package for an attempt. The honest limit is the contracts' own: this stops ordinary
code, accidents and anything that wants an audit trail, not a hostile in-process caller
with ``ctypes``. See ``docs/specs/pii-threat-model.md``.

THE ORDER OF OPERATIONS
-----------------------
1. Destination known, destination policy present, redaction policy present and sane
   (k >= 2), purpose and actor stated. Otherwise: refused.
2. Field names are our own vocabulary and do not contain a customer schema name.
3. Segments are k-enforced (suppressed or generalised), checked against the release
   ledger, and flattened into fields.
4. Guardrails are evaluated per field; DENY refuses, REQUIRE_APPROVAL refuses unless a
   matching approved request is supplied, REDACT forbids ALLOW, ALLOW authorises it.
5. Every field is redacted. An UNCLASSIFIED field refuses the whole call.
6. The backstop scans the cleared fields. Any hit is a defect: audited, paged, refused.
7. The EgressRecord is written. If that fails, nothing leaves.
8. The payload is minted, citing the record.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, NoReturn

from godwit_contracts import (
    ApprovalRequest,
    ApprovalStatus,
    Destination,
    EgressRecord,
    Evidence,
    Guardrail,
    GuardrailAction,
    GuardrailAttribute,
    Instant,
    PiiClass,
    Plane,
    RedactionAction,
    RedactionPolicy,
    SafePayload,
    SafeScalar,
    Segment,
    Sensitivity,
    Tainted,
    canonical_json,
    claim_safe_payload_issuer,
    content_hash,
    derived_statistic,
    most_sensitive,
)
from godwit_contracts.segment import canonical_column

from godwit_guard.access import AccessModeMap, KeyedHasher
from godwit_guard.classify import CONCEPTS, ClassificationRegistry
from godwit_guard.destinations import DEFAULT_DESTINATION_POLICIES, DestinationPolicy
from godwit_guard.disclosure import MIN_K, ReleaseLedger, enforce_segment_k
from godwit_guard.errors import (
    ApprovalRequiredError,
    BackstopHitError,
    EgressRefusedError,
    LedgerWriteError,
    Refusal,
    RefusalReason,
)
from godwit_guard.guardrails import (
    AttrValue,
    applicable,
    strongest_action,
)
from godwit_guard.ledger import EgressLedger, audit_event
from godwit_guard.redactor import PolicyRedactor, Redaction
from godwit_guard.scanner import Backstop
from godwit_guard.schema_names import ROLE_PHRASES, TYPE_PHRASES, SchemaNameMode
from godwit_guard.transforms import BUILTIN_HIERARCHIES, Generaliser, TokenVault

__all__ = [
    "GATE_CLAIMANT",
    "EgressOptions",
    "Gate",
    "evidence_fields",
]

GATE_CLAIMANT: Final[str] = "godwit_guard.gate"

type _Mint = Callable[[str, Mapping[str, SafeScalar], str, int, str], SafePayload]


def _claim() -> _Mint:
    issuer = claim_safe_payload_issuer(claimant=GATE_CLAIMANT)

    def mint(
        purpose: str,
        fields: Mapping[str, SafeScalar],
        policy_id: str,
        policy_version: int,
        egress_record_id: str,
    ) -> SafePayload:
        return issuer.issue(
            purpose=purpose,
            fields=fields,
            policy_id=policy_id,
            policy_version=policy_version,
            egress_record_id=egress_record_id,
        )

    return mint


_mint: Final[_Mint] = _claim()

_FIELD_NAME: Final[re.Pattern[str]] = re.compile(r"[a-z][a-z0-9_]{0,47}(?:\.[a-z0-9_]{1,47}){0,5}")
_REQUEST_ATTRIBUTES: Final[frozenset[GuardrailAttribute]] = frozenset(
    {GuardrailAttribute.DESTINATION, GuardrailAttribute.PURPOSE, GuardrailAttribute.PLANE}
)
_MIN_NAME_LENGTH: Final[int] = 4
_VOCABULARY: Final[frozenset[str]] = frozenset(
    {c.phrase for c in CONCEPTS} | set(ROLE_PHRASES.values()) | set(TYPE_PHRASES.values())
)
"""Our own description vocabulary. A column literally named ``country`` is described as
``country``: the echo check must not call our vocabulary a leak of itself."""
_ECHO_SENSITIVITIES: Final[frozenset[Sensitivity]] = frozenset(
    {Sensitivity.DATA_VALUE, Sensitivity.SCHEMA_NAME}
)


def evidence_fields(evidence: Evidence, *, prefix: str) -> dict[str, Tainted[Any]]:
    """Flatten an Evidence's numbers into gate fields.

    A statistic without its own population inherits the evidence's population, which
    the contract defines as the rows behind the statistic. The segment is NOT included:
    pass it to :meth:`Gate.clear` under ``segments`` so it is k-enforced and
    release-checked.
    """
    out: dict[str, Tainted[Any]] = {}
    for name in ("statistic", "baseline", "effect_size", "p_value"):
        value: Tainted[float] | None = getattr(evidence, name)
        if value is None:
            continue
        population = value.population if value.population is not None else evidence.population
        out[f"{prefix}.{name}"] = Tainted[float](
            value=value.reveal(),
            sensitivity=value.sensitivity,
            provenance=value.provenance,
            population=population,
        )
    return out


def _release_scope(segment: Segment) -> str:
    places = {
        (p.column.provenance.source_id or "", canonical_column(p.column.provenance.table or ""))
        for p in segment.predicates
    }
    if len(places) != 1:
        return "unscoped"
    return content_hash(canonical_json(sorted(places)), prefix="pop")


@dataclass(frozen=True, slots=True)
class EgressOptions:
    """Everything :meth:`Gate.clear` accepts beyond the contract's EgressGate protocol."""

    literals: Mapping[str, StrEnum | bool] = field(default_factory=dict)
    """Our own vocabulary: booleans and members of a Godwit ``StrEnum``. Never data."""
    segments: Mapping[str, Segment] = field(default_factory=dict)
    """Segments to release. k-enforced, release-checked, then flattened into fields."""
    token_scope: str | None = None
    """The vault scope to tokenise into -- typically one per pattern. None: no tokens."""
    approval: ApprovalRequest | None = None
    """An approved request, when a REQUIRE_APPROVAL guardrail has asked for one."""


@dataclass(frozen=True, slots=True)
class _Request:
    dest: Destination
    purpose: str
    actor: str
    at: Instant
    request_id: str


class Gate:
    """The egress gate. Construct one per boundary process; it holds the issuer."""

    def __init__(
        self,
        *,
        ledger: EgressLedger,
        registry: ClassificationRegistry,
        backstop: Backstop,
        destinations: Mapping[Destination, DestinationPolicy] = DEFAULT_DESTINATION_POLICIES,
        vault: TokenVault | None = None,
        hasher: KeyedHasher | None = None,
        modes: AccessModeMap | None = None,
        hierarchies: Mapping[str, Generaliser] = BUILTIN_HIERARCHIES,
        schema_mode: SchemaNameMode = SchemaNameMode.DESCRIBED,
        releases: ReleaseLedger | None = None,
    ) -> None:
        self._ledger = ledger
        self._registry = registry
        self._backstop = backstop
        self._destinations = destinations
        self._vault = vault
        self._hasher = hasher
        self._modes = modes
        self._hierarchies = hierarchies
        self._schema_mode = schema_mode
        self._releases = releases
        self._sequence = 0

    @property
    def backstop(self) -> Backstop:
        """The backstop, for its hit-rate metrics."""
        return self._backstop

    def clear(
        self,
        *,
        fields: Mapping[str, Tainted[Any]],
        destination: Destination,
        purpose: str,
        policy: RedactionPolicy | None,
        guardrails: Sequence[Guardrail],
        actor: str,
        occurred_at: Instant,
        options: EgressOptions | None = None,
    ) -> tuple[SafePayload, EgressRecord]:
        """Clear tainted fields for one destination, or refuse. See the module docstring."""
        opts = options or EgressOptions()
        names = sorted([*fields, *opts.literals, *opts.segments])
        request_id = content_hash(
            canonical_json([str(destination), purpose, actor, names]), prefix="req"
        )

        def refuse(
            reason: RefusalReason,
            detail: str,
            *,
            which: Sequence[str] = (),
            guardrail_ids: Sequence[str] = (),
        ) -> NoReturn:
            refusal = Refusal(
                reason=reason,
                fields=tuple(which),
                detail=detail,
                guardrail_ids=tuple(guardrail_ids),
            )
            self._audit_refusal(refusal, actor=actor, request_id=request_id, at=occurred_at)
            raise EgressRefusedError(refusal)

        dest, checked_policy = self._preflight(destination, policy, purpose, actor, refuse)
        req = _Request(
            dest=dest, purpose=purpose, actor=actor, at=occurred_at, request_id=request_id
        )
        self._check_names(names, refuse)
        all_fields, released = self._expand_segments(fields, opts.segments, checked_policy, refuse)
        keys = sorted([*all_fields, *opts.literals])
        self._check_names(keys, refuse)
        self._check_schema_names_in_keys(keys, all_fields, refuse)
        fired_ids, per_field, approval_id = self._guardrails(
            all_fields, req, guardrails, opts.approval, refuse
        )

        redactor = PolicyRedactor(
            registry=self._registry,
            at=occurred_at,
            destinations=self._destinations,
            vault=self._vault,
            scope_id=opts.token_scope,
            hasher=self._hasher,
            modes=self._modes,
            hierarchies=self._hierarchies,
            schema_mode=self._schema_mode,
        )
        out: dict[str, SafeScalar] = {}
        decisions: dict[str, Redaction] = {}
        unclassified = [name for name in sorted(all_fields) if self._unclassified(all_fields[name])]
        if unclassified:
            refuse(
                RefusalReason.UNCLASSIFIED_FIELD,
                "a field's column has no classification; deny by default",
                which=unclassified,
            )
        for name in sorted(all_fields):
            action = per_field.get(name)
            decision = redactor.decide(
                all_fields[name],
                policy=checked_policy,
                destination=dest,
                allow_authorised=action is GuardrailAction.ALLOW,
                force_redact=action is GuardrailAction.REDACT,
            )
            if decision.unclassified:
                refuse(
                    RefusalReason.UNCLASSIFIED_FIELD,
                    "a field's column has no classification; deny by default",
                    which=[name],
                )
            decisions[name] = decision
            if decision.emitted:
                out[name] = decision.scalar
        for name in sorted(opts.literals):
            literal = _literal(opts.literals[name])
            if literal is None:
                refuse(
                    RefusalReason.UNSUPPORTED_VALUE,
                    "literals must be booleans or members of a Godwit StrEnum",
                    which=[name],
                )
            out[name] = literal

        self._backstop_check(out, all_fields, decisions, req)
        record = self._record(
            out, all_fields, decisions, req, checked_policy, fired_ids, approval_id
        )
        token_map_ref = None
        if (
            self._vault is not None
            and opts.token_scope is not None
            and any(d.emitted and d.sensitivity is Sensitivity.TOKEN for d in decisions.values())
        ):
            token_map_ref = self._vault.map_ref(opts.token_scope)
        try:
            self._ledger.append_egress(record, token_map_ref=token_map_ref)
        except Exception as exc:
            refusal = Refusal(
                reason=RefusalReason.LEDGER_UNAVAILABLE,
                detail="the egress record could not be written; nothing leaves",
            )
            raise LedgerWriteError(refusal) from exc
        payload = _mint(
            purpose,
            dict(sorted(out.items())),
            checked_policy.policy_id,
            checked_policy.version,
            record.record_id,
        )
        if self._releases is not None:
            for scope, segment in released:
                self._releases.record(segment, scope=scope)
        return payload, record

    # ---------------------------------------------------------------------------------

    def _preflight(
        self,
        destination: Destination,
        policy: RedactionPolicy | None,
        purpose: str,
        actor: str,
        refuse: Callable[..., NoReturn],
    ) -> tuple[Destination, RedactionPolicy]:
        try:
            dest = Destination(destination)
        except ValueError:
            refuse(RefusalReason.UNKNOWN_DESTINATION, "destination is not a known Destination")
        if dest not in self._destinations:
            refuse(
                RefusalReason.NO_DESTINATION_POLICY,
                "no policy is configured for this destination; deny by default",
            )
        if policy is None:
            refuse(RefusalReason.MISSING_POLICY, "no redaction policy supplied")
        if policy.min_cell_size < MIN_K:
            refuse(RefusalReason.INVALID_POLICY, "min_cell_size below 2 disables k-anonymity")
        if policy.default_action is RedactionAction.ALLOW:
            refuse(RefusalReason.INVALID_POLICY, "a default of ALLOW is not deny-by-default")
        if not purpose.strip() or not actor.strip():
            refuse(RefusalReason.MISSING_PURPOSE, "purpose and actor are required for the audit")
        return dest, policy

    @staticmethod
    def _check_names(names: Sequence[str], refuse: Callable[..., NoReturn]) -> None:
        bad = [index for index, name in enumerate(names) if not _FIELD_NAME.fullmatch(name)]
        if bad:
            refuse(
                RefusalReason.UNSAFE_FIELD_NAME,
                "field names must be lower-case identifiers from our own vocabulary",
                which=[f"#{index}" for index in bad],
            )
        if len(set(names)) != len(names):
            refuse(RefusalReason.UNSAFE_FIELD_NAME, "duplicate field names")

    def _check_schema_names_in_keys(
        self,
        keys: Sequence[str],
        all_fields: Mapping[str, Tainted[Any]],
        refuse: Callable[..., NoReturn],
    ) -> None:
        """A key is itself a disclosure if it spells a sensitive column's name.

        Refused keys are reported by position, never by name.
        """
        disclosive: set[str] = set()
        for value in all_fields.values():
            prov = value.provenance
            candidates = [prov.column, prov.table]
            if value.sensitivity is Sensitivity.SCHEMA_NAME and isinstance(value.reveal(), str):
                candidates.append(value.reveal())
            entry = self._registry.lookup(prov)
            if entry is not None and entry.effective_class is PiiClass.NONE:
                continue
            disclosive.update(
                canonical_column(c) for c in candidates if c and len(c) >= _MIN_NAME_LENGTH
            )
        bad = [i for i, key in enumerate(keys) if any(n in key.casefold() for n in disclosive)]
        if bad:
            refuse(
                RefusalReason.UNSAFE_FIELD_NAME,
                "a field name spells a customer schema name; field names are disclosures",
                which=[f"#{index}" for index in bad],
            )

    def _expand_segments(
        self,
        fields: Mapping[str, Tainted[Any]],
        segments: Mapping[str, Segment],
        policy: RedactionPolicy,
        refuse: Callable[..., NoReturn],
    ) -> tuple[dict[str, Tainted[Any]], list[tuple[str, Segment]]]:
        out: dict[str, Tainted[Any]] = dict(fields)
        released: list[tuple[str, Segment]] = []
        for name in sorted(segments):
            kept = enforce_segment_k(segments[name], k=policy.min_cell_size)
            if kept is None or kept.population is None:
                continue
            scope = _release_scope(kept)
            if self._releases is not None:
                verdict = self._releases.check(kept, scope=scope)
                if not verdict.allowed:
                    refuse(RefusalReason.RELEASE_NARROWS_POPULATION, verdict.reason, which=[name])
            released.append((scope, kept))
            out[f"{name}.population"] = derived_statistic(
                kept.population, population=kept.population
            )
            for i, predicate in enumerate(kept.predicates):
                out[f"{name}.p{i}.column"] = predicate.column
                out[f"{name}.p{i}.op"] = derived_statistic(
                    predicate.op.value, population=kept.population
                )
                for j, value in enumerate(predicate.values):
                    out[f"{name}.p{i}.v{j}"] = Tainted[Any](
                        value=value.reveal(),
                        sensitivity=value.sensitivity,
                        provenance=value.provenance,
                        population=kept.population
                        if value.population is None
                        else min(value.population, kept.population),
                    )
        return out, released

    def _guardrails(
        self,
        all_fields: Mapping[str, Tainted[Any]],
        req: _Request,
        guardrails: Sequence[Guardrail],
        approval: ApprovalRequest | None,
        refuse: Callable[..., NoReturn],
    ) -> tuple[set[str], dict[str, GuardrailAction], str | None]:
        fired_ids: set[str] = set()
        per_field: dict[str, GuardrailAction] = {}
        denied: list[str] = []
        needs_approval: list[str] = []
        request_attrs: dict[GuardrailAttribute, AttrValue] = {
            GuardrailAttribute.DESTINATION: req.dest.value,
            GuardrailAttribute.PURPOSE: req.purpose,
            GuardrailAttribute.PLANE: Plane.BOUNDARY.value,
        }
        request_fired = applicable(
            [g for g in guardrails if _is_request_guardrail(g)], request_attrs
        )
        field_level = [g for g in guardrails if not _is_request_guardrail(g)]
        targets: list[tuple[str, tuple[Guardrail, ...]]] = [
            (name, (*request_fired, *applicable(field_level, self._attrs(all_fields[name], req))))
            for name in sorted(all_fields)
        ]
        if not all_fields:
            targets.append(("(request)", request_fired))
        for name, fired in targets:
            fired_ids.update(g.guardrail_id for g in fired)
            action = strongest_action(g.action for g in fired)
            if action is not None:
                per_field[name] = action
            if action is GuardrailAction.DENY:
                denied.append(name)
            elif action is GuardrailAction.REQUIRE_APPROVAL:
                needs_approval.append(name)
        if denied:
            refuse(
                RefusalReason.GUARDRAIL_DENY,
                "a guardrail denies this egress",
                which=denied,
                guardrail_ids=sorted(fired_ids),
            )
        if not needs_approval:
            return fired_ids, per_field, None
        if (
            approval is not None
            and approval.status is ApprovalStatus.APPROVED
            and approval.subject_kind == "egress"
            and approval.subject_id == req.request_id
            and (approval.expires_at is None or req.at < approval.expires_at)
        ):
            return fired_ids, per_field, approval.request_id
        request = ApprovalRequest(
            request_id=content_hash(
                canonical_json([req.request_id, req.at.isoformat()]), prefix="apr"
            ),
            subject_kind="egress",
            subject_id=req.request_id,
            requested_by=req.actor,
            requested_at=req.at,
            reason=f"guardrails {', '.join(sorted(fired_ids))} require approval for this egress",
        )
        refusal = Refusal(
            reason=RefusalReason.APPROVAL_REQUIRED,
            fields=tuple(needs_approval),
            detail="a guardrail requires human approval",
            guardrail_ids=tuple(sorted(fired_ids)),
        )
        self._audit_refusal(refusal, actor=req.actor, request_id=req.request_id, at=req.at)
        raise ApprovalRequiredError(refusal, request)

    def _unclassified(self, value: Tainted[Any]) -> bool:
        """Checked before any redaction, so a small cell cannot hide an unknown column."""
        prov = value.provenance
        if value.sensitivity is Sensitivity.DATA_VALUE:
            return self._registry.lookup(prov) is None
        if value.sensitivity is Sensitivity.SCHEMA_NAME:
            name = value.reveal()
            if (
                prov.table is None
                and isinstance(name, str)
                and self._registry.is_known_table(prov.source_id, name)
            ):
                return False
            return self._registry.lookup(prov) is None
        return False

    def _attrs(self, value: Tainted[Any], req: _Request) -> dict[GuardrailAttribute, AttrValue]:
        prov = value.provenance
        entry = self._registry.lookup(prov)
        return {
            GuardrailAttribute.SENSITIVITY: value.sensitivity.value,
            GuardrailAttribute.PII_CLASS: None if entry is None else entry.effective_class.value,
            GuardrailAttribute.DESTINATION: req.dest.value,
            GuardrailAttribute.PLANE: Plane.BOUNDARY.value,
            GuardrailAttribute.POPULATION: value.population,
            GuardrailAttribute.SOURCE_ID: prov.source_id,
            GuardrailAttribute.COLUMN_NAME: prov.column,
            GuardrailAttribute.TABLE_NAME: prov.table,
            GuardrailAttribute.PURPOSE: req.purpose,
            GuardrailAttribute.ACQUISITION: prov.acquisition.value,
        }

    def _backstop_check(
        self,
        out: Mapping[str, SafeScalar],
        all_fields: Mapping[str, Tainted[Any]],
        decisions: Mapping[str, Redaction],
        req: _Request,
    ) -> None:
        allowed = {
            str(d.scalar).casefold()
            for d in decisions.values()
            if d.emitted and d.action is RedactionAction.ALLOW
        }
        forbidden = {
            str(all_fields[name].reveal())
            for name, d in decisions.items()
            if all_fields[name].sensitivity in _ECHO_SENSITIVITIES
            and d.action is not RedactionAction.ALLOW
            and isinstance(all_fields[name].reveal(), str | int)
        }
        forbidden = {
            f
            for f in forbidden
            if f.casefold() not in allowed and not any(f.casefold() in p for p in _VOCABULARY)
        }
        findings = self._backstop.scan(out, forbidden=forbidden)
        if not findings:
            return
        refusal = Refusal(
            reason=RefusalReason.BACKSTOP_HIT,
            fields=tuple(sorted({f.field for f in findings})),
            detail="DEFECT: the backstop found data the taint system should have stopped; "
            + ", ".join(sorted({f.recogniser for f in findings})),
        )
        with contextlib.suppress(Exception):
            self._ledger.append_audit(
                audit_event(
                    action="egress.backstop_hit",
                    actor=req.actor,
                    subject_kind="egress_request",
                    subject_id=req.request_id,
                    at=req.at,
                    detail=refusal.model_dump(mode="json"),
                )
            )
        raise BackstopHitError(refusal)

    def _record(
        self,
        out: Mapping[str, SafeScalar],
        all_fields: Mapping[str, Tainted[Any]],
        decisions: Mapping[str, Redaction],
        req: _Request,
        policy: RedactionPolicy,
        fired_ids: set[str],
        approval_id: str | None,
    ) -> EgressRecord:
        self._sequence += 1
        digest = content_hash(canonical_json(dict(sorted(out.items()))))
        emitted = [name for name, d in decisions.items() if d.emitted]
        populations = [p for n in emitted if (p := all_fields[n].population) is not None]
        befores = [v.sensitivity for v in all_fields.values()]
        afters = [decisions[n].sensitivity for n in emitted]
        return EgressRecord(
            record_id=content_hash(
                canonical_json([req.request_id, req.at.isoformat(), digest, self._sequence]),
                prefix="egr",
            ),
            occurred_at=req.at,
            destination=req.dest,
            purpose=req.purpose,
            actor=req.actor,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            guardrail_ids=tuple(sorted(fired_ids)),
            content_digest=digest,
            field_names=tuple(sorted(out)),
            source_ids=tuple(
                sorted({s for n in emitted if (s := all_fields[n].provenance.source_id)})
            ),
            sensitivity_before=most_sensitive(*befores)
            if befores
            else Sensitivity.DERIVED_STATISTIC,
            sensitivity_after=most_sensitive(*afters) if afters else Sensitivity.DERIVED_STATISTIC,
            actions_applied=tuple(
                sorted({d.action for d in decisions.values()}, key=lambda a: a.value)
            ),
            min_population=min(populations, default=None),
            approval_id=approval_id,
        )

    def _audit_refusal(self, refusal: Refusal, *, actor: str, request_id: str, at: Instant) -> None:
        # Best effort: a refusal must happen whether or not it can be recorded.
        with contextlib.suppress(Exception):
            self._ledger.append_audit(
                audit_event(
                    action=f"egress.refused.{refusal.reason.value}",
                    actor=actor,
                    subject_kind="egress_request",
                    subject_id=request_id,
                    at=at,
                    detail=refusal.model_dump(mode="json"),
                )
            )


def _literal(value: object) -> SafeScalar | None:
    """A literal's scalar, or None if it is not one of ours."""
    if type(value) is bool:
        return value
    if isinstance(value, StrEnum) and type(value).__module__.startswith("godwit_"):
        return value.value
    return None


def _is_request_guardrail(guardrail: Guardrail) -> bool:
    scope = guardrail.scope
    if scope.sensitivities or scope.pii_classes or scope.source_ids:
        return False
    if scope.min_population is not None:
        return False
    return all(c.attribute in _REQUEST_ATTRIBUTES for c in guardrail.predicate.all_of)
