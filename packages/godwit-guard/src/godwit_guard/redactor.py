"""The policy redactor: one tainted value in, one cleared scalar (or nothing) out.

Implements the contract ``Redactor`` protocol and its five laws:

1. **Total.** Every input comes back redacted or suppressed; nothing raises to mean "not
   allowed". A transform that cannot apply suppresses -- it never falls back to the raw
   value.
2. **Monotone.** A rule's action is only ever escalated towards SUPPRESS, never relaxed.
3. **Deterministic.** Same value, policy, destination and scope, same result.
4. **Tokens are one-way outside the data plane.** The vault stays here.
5. **Small cells first.** Population is checked before any rule is considered.

ESCALATION
----------
If the matched rule's action is not permitted at the destination -- ALLOW to an LLM,
HASH to a log -- or ALLOW lacks the ALLOW guardrail the destination demands, the action
escalates to TOKENISE when the destination accepts tokens and a live scope exists, and
to SUPPRESS otherwise. It never escalates sideways into a transform that needs
parameters nobody supplied.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final

from godwit_contracts import (
    Acquisition,
    ColumnRole,
    Destination,
    Instant,
    PiiClass,
    Provenance,
    RedactionAction,
    RedactionPolicy,
    SafeScalar,
    Sensitivity,
    Tainted,
)
from godwit_contracts.segment import canonical_column

from godwit_guard.access import AccessModeMap, KeyedHasher
from godwit_guard.classify import CatalogEntry, ClassificationRegistry, match_concept
from godwit_guard.destinations import DEFAULT_DESTINATION_POLICIES, DestinationPolicy
from godwit_guard.errors import OpaqueHashRefusedError
from godwit_guard.schema_names import SchemaNameMode, describe, narrower_schema_mode
from godwit_guard.transforms import (
    BUILTIN_HIERARCHIES,
    Generaliser,
    TokenVault,
    bucket,
    generalise,
    to_safe_scalar,
)

__all__ = [
    "ACTION_RESTRICTIVENESS",
    "PolicyRedactor",
    "Redaction",
]

_R = RedactionAction

ACTION_RESTRICTIVENESS: Final[dict[RedactionAction, int]] = {
    _R.ALLOW: 0,
    _R.BUCKET: 1,
    _R.GENERALISE: 2,
    _R.HASH: 3,
    _R.TOKENISE: 4,
    _R.SUPPRESS: 5,
}

_SMALL_POPULATION_ACQUISITIONS: Final[frozenset[Acquisition]] = frozenset(
    {Acquisition.QUANTILE, Acquisition.ICEBERG_MANIFEST_BOUNDS}
)
"""Quantiles and extrema: over a small population, one person's value."""

_CONCEPT_NAMESPACES: Final[dict[str, str]] = {
    "person_name": "PERSON",
    "email": "EMAIL",
    "phone": "PHONE",
    "government_id": "NATIONALID",
    "counterparty": "MERCHANT",
    "device": "DEVICE",
    "network": "NETADDR",
    "card": "CARD",
    "bank_account": "ACCOUNT",
    "identifier": "ENTITY",
    "grouping": "GROUP",
    "country": "COUNTRY",
    "location": "PLACE",
    "postcode": "PLACE",
    "health": "HEALTHVALUE",
    "income": "AMOUNT",
    "money": "AMOUNT",
}
_ROLE_NAMESPACES: Final[dict[ColumnRole, str]] = {
    ColumnRole.ENTITY_ID: "ENTITY",
    ColumnRole.JOIN_KEY: "KEY",
    ColumnRole.DEVICE: "DEVICE",
    ColumnRole.GEO: "PLACE",
    ColumnRole.AMOUNT: "AMOUNT",
    ColumnRole.CATEGORY: "CATEGORY",
}


@dataclass(frozen=True, slots=True)
class Redaction:
    """What the redactor decided about one value."""

    action: RedactionAction
    reason: str
    output: Tainted[Any] | None = None
    """The cleared value, still wrapped, or None when suppressed."""
    scalar: SafeScalar = None
    sensitivity: Sensitivity = Sensitivity.DERIVED_STATISTIC
    """What class of thing left, for the EgressRecord's ``sensitivity_after``."""
    unclassified: bool = False
    """True when the value's column is unknown to the registry. The gate refuses."""

    @property
    def emitted(self) -> bool:
        """True if something leaves."""
        return self.output is not None


def _suppress(reason: str, *, unclassified: bool = False) -> Redaction:
    return Redaction(action=_R.SUPPRESS, reason=reason, unclassified=unclassified)


def _rewrap(original: Tainted[Any], text: str, action: RedactionAction) -> Tainted[str]:
    """Wrap a transformed value. Still DATA_VALUE: a bucket is coarse data, not a statistic."""
    return Tainted[str](
        value=text,
        sensitivity=Sensitivity.DATA_VALUE,
        provenance=Provenance(
            acquisition=Acquisition.GATE_TOKENISATION,
            upstream=original.provenance,
            detail=action.value,
        ),
        population=original.population,
    )


class PolicyRedactor:
    """Applies a ``RedactionPolicy`` to tainted values for a destination.

    Holds everything a transform might need: the classification registry, the
    destination policies, and -- in the data plane -- the token vault and keyed hasher.
    """

    def __init__(
        self,
        *,
        registry: ClassificationRegistry,
        at: Instant,
        destinations: Mapping[Destination, DestinationPolicy] = DEFAULT_DESTINATION_POLICIES,
        vault: TokenVault | None = None,
        scope_id: str | None = None,
        hasher: KeyedHasher | None = None,
        modes: AccessModeMap | None = None,
        hierarchies: Mapping[str, Generaliser] = BUILTIN_HIERARCHIES,
        schema_mode: SchemaNameMode = SchemaNameMode.DESCRIBED,
    ) -> None:
        self._registry = registry
        self._at = at
        self._destinations = destinations
        self._vault = vault
        self._scope_id = scope_id
        self._hasher = hasher
        self._modes = modes
        self._hierarchies = hierarchies
        self._schema_mode = schema_mode

    # The Redactor protocol -------------------------------------------------------------

    def redact(
        self, value: Tainted[Any], *, policy: RedactionPolicy, destination: Destination
    ) -> Tainted[Any] | None:
        """Redact one value, or return None to suppress it entirely."""
        return self.decide(value, policy=policy, destination=destination).output

    # The full decision, for the gate --------------------------------------------------

    def decide(
        self,
        value: Tainted[Any],
        *,
        policy: RedactionPolicy,
        destination: Destination,
        allow_authorised: bool = False,
        force_redact: bool = False,
    ) -> Redaction:
        """Decide one value. ``allow_authorised``: an ALLOW guardrail matched.
        ``force_redact``: a REDACT guardrail matched, so ALLOW is off the table."""
        dest = self._destinations.get(destination)
        if dest is None:
            return _suppress("no destination policy")
        sensitivity = value.sensitivity
        if sensitivity is Sensitivity.SCHEMA_NAME:
            return self._schema(value, dest)
        if sensitivity is Sensitivity.TOKEN:
            raw = value.reveal()
            if dest.allow_tokens and isinstance(raw, str):
                return Redaction(
                    action=_R.ALLOW,
                    reason="token",
                    output=value,
                    scalar=raw,
                    sensitivity=Sensitivity.TOKEN,
                )
            return _suppress("tokens are not accepted at this destination")
        if value.is_small_cell(policy.min_cell_size):
            return _suppress("small cell: population below k, or unknown")
        if sensitivity is Sensitivity.DERIVED_STATISTIC:
            return self._statistic(value, dest)
        return self._data_value(
            value,
            policy=policy,
            dest=dest,
            allow_authorised=allow_authorised,
            force_redact=force_redact,
        )

    def _statistic(self, value: Tainted[Any], dest: DestinationPolicy) -> Redaction:
        if not dest.allow_statistics:
            return _suppress("statistics are not accepted at this destination")
        scalar = to_safe_scalar(value.reveal()) if _is_scalar(value.reveal()) else None
        if scalar is None:
            return _suppress("statistic is not a finite flat scalar")
        return Redaction(
            action=_R.ALLOW,
            reason="derived statistic",
            output=value,
            scalar=scalar,
            sensitivity=Sensitivity.DERIVED_STATISTIC,
        )

    def _data_value(
        self,
        value: Tainted[Any],
        *,
        policy: RedactionPolicy,
        dest: DestinationPolicy,
        allow_authorised: bool,
        force_redact: bool,
    ) -> Redaction:
        prov = value.provenance
        if prov.acquisition in _SMALL_POPULATION_ACQUISITIONS and (
            value.population is None or value.population < policy.quantile_min_population
        ):
            return _suppress("quantile or extremum over a small population")
        entry = self._registry.lookup(prov)
        if entry is None:
            return _suppress("unclassified column", unclassified=True)
        raw = value.reveal()
        if not _is_scalar(raw):
            return _suppress("not a flat scalar")
        action, params = _match_rule(
            policy, entry.effective_class, entry.proposal.column.column.reveal()
        )
        if action is _R.ALLOW and (
            force_redact or (dest.allow_requires_guardrail and not allow_authorised)
        ):
            action = self._escalation(dest)
        if action not in dest.data_value_actions:
            action = self._escalation(dest)
        return self._apply(value, action, params, entry)

    def _escalation(self, dest: DestinationPolicy) -> RedactionAction:
        live = (
            self._vault is not None
            and self._scope_id is not None
            and self._vault.has_live_scope(self._scope_id, at=self._at)
        )
        return _R.TOKENISE if live and _R.TOKENISE in dest.data_value_actions else _R.SUPPRESS

    def _apply(
        self,
        value: Tainted[Any],
        action: RedactionAction,
        params: Mapping[str, int | float | str | bool],
        entry: CatalogEntry,
    ) -> Redaction:
        raw = value.reveal()
        if action is _R.ALLOW:
            scalar = to_safe_scalar(raw)
            if scalar is None:
                return _suppress("value has no safe scalar form")
            return Redaction(
                action=action,
                reason="allowed by policy and guardrail",
                output=value,
                scalar=scalar,
                sensitivity=Sensitivity.DATA_VALUE,
            )
        if action is _R.TOKENISE:
            return self._tokenise(value, params, entry)
        if action is _R.HASH:
            return self._hash(value, entry)
        if action in (_R.BUCKET, _R.GENERALISE):
            text = (
                bucket(raw, params)
                if action is _R.BUCKET
                else generalise(raw, params, self._hierarchies)
            )
            if text is None:
                return _suppress(f"{action.value} does not apply to this value")
            return Redaction(
                action=action,
                reason=action.value,
                output=_rewrap(value, text, action),
                scalar=text,
                sensitivity=Sensitivity.DATA_VALUE,
            )
        return _suppress("suppressed by policy")

    def _tokenise(
        self,
        value: Tainted[Any],
        params: Mapping[str, int | float | str | bool],
        entry: CatalogEntry,
    ) -> Redaction:
        if (
            self._vault is None
            or self._scope_id is None
            or not self._vault.has_live_scope(self._scope_id, at=self._at)
        ):
            return _suppress("no live token scope")
        namespace = _namespace(value, params, entry)
        issued = self._vault.tokenise(
            value, scope_id=self._scope_id, namespace=namespace, at=self._at
        )
        return Redaction(
            action=_R.TOKENISE,
            reason="tokenised",
            output=issued,
            scalar=issued.reveal(),
            sensitivity=Sensitivity.TOKEN,
        )

    def _hash(self, value: Tainted[Any], entry: CatalogEntry) -> Redaction:
        if self._hasher is None or self._modes is None:
            return _suppress("no keyed hasher at this boundary")
        decision = self._modes.decision(entry.proposal.column)
        if decision is None:
            return _suppress("column has no access decision")
        try:
            digest = self._hasher.hash_for(value.reveal(), decision=decision)
        except OpaqueHashRefusedError:
            return _suppress("hash refused: column is not OPAQUE-with-sufficient-entropy")
        wrapped = Tainted[str](
            value=digest,
            sensitivity=Sensitivity.TOKEN,
            provenance=Provenance(
                acquisition=Acquisition.GATE_TOKENISATION,
                upstream=value.provenance,
                detail="keyed_hash",
            ),
            population=value.population,
        )
        return Redaction(
            action=_R.HASH,
            reason="keyed hash",
            output=wrapped,
            scalar=digest,
            sensitivity=Sensitivity.TOKEN,
        )

    def _schema(self, value: Tainted[Any], dest: DestinationPolicy) -> Redaction:
        name = value.reveal()
        if not isinstance(name, str):
            return _suppress("schema name is not a string")
        mode = narrower_schema_mode(self._schema_mode, dest.max_schema_mode)
        prov = value.provenance
        is_table = prov.table is None and self._registry.is_known_table(prov.source_id, name)
        entry = None if is_table else self._registry.lookup(prov)
        if not is_table and entry is None:
            return _suppress("unclassified schema name", unclassified=True)
        if mode is SchemaNameMode.FULL:
            return Redaction(
                action=_R.ALLOW,
                reason="schema name, full",
                output=value,
                scalar=name,
                sensitivity=Sensitivity.SCHEMA_NAME,
            )
        alias = self._alias(value, "TABLE" if is_table else "COLUMN")
        text = (alias or "table") if entry is None else describe(entry, mode, alias=alias)
        wrapped = Tainted[str](
            value=text,
            sensitivity=Sensitivity.TOKEN,
            provenance=Provenance(
                acquisition=Acquisition.GATE_TOKENISATION,
                upstream=prov,
                detail=f"schema_{mode.value}",
            ),
        )
        return Redaction(
            action=_R.TOKENISE if alias else _R.GENERALISE,
            reason=f"schema name, {mode.value}",
            output=wrapped,
            scalar=text,
            sensitivity=Sensitivity.TOKEN,
        )

    def _alias(self, value: Tainted[Any], namespace: str) -> str | None:
        if (
            self._vault is None
            or self._scope_id is None
            or not self._vault.has_live_scope(self._scope_id, at=self._at)
        ):
            return None
        return self._vault.tokenise(
            value, scope_id=self._scope_id, namespace=namespace, at=self._at
        ).reveal()


def _is_scalar(raw: object) -> bool:
    return raw is None or isinstance(raw, str | int | float | Decimal | _dt.date | bytes)


def _match_rule(
    policy: RedactionPolicy, pii: PiiClass, column: str
) -> tuple[RedactionAction, Mapping[str, int | float | str | bool]]:
    """The most restrictive matching rule, or the policy's default. Never ALLOW by default."""
    lowered = canonical_column(column)
    best: tuple[RedactionAction, Mapping[str, int | float | str | bool]] | None = None
    for rule in policy.rules:
        if rule.pii_class is not None and rule.pii_class is not pii:
            continue
        if rule.column_pattern is not None:
            try:
                hit = re.search(rule.column_pattern, lowered) is not None
            except re.error:
                hit = rule.action is not _R.ALLOW
            if not hit:
                continue
        if best is None or ACTION_RESTRICTIVENESS[rule.action] > ACTION_RESTRICTIVENESS[best[0]]:
            best = (rule.action, rule.params)
    return best if best is not None else (policy.default_action, {})


def _namespace(
    value: Tainted[Any], params: Mapping[str, int | float | str | bool], entry: CatalogEntry
) -> str:
    configured = params.get("namespace")
    if isinstance(configured, str) and configured:
        return configured
    if value.provenance.acquisition is Acquisition.DERIVED_FEATURE_NAME:
        return "FEATURE"
    concept = match_concept(entry.proposal.column.column.reveal())
    if concept is not None and concept.name in _CONCEPT_NAMESPACES:
        return _CONCEPT_NAMESPACES[concept.name]
    return _ROLE_NAMESPACES.get(entry.proposal.role, "VALUE")
