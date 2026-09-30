"""Per-destination egress policy, as versioned data.

A value safe for the UI -- where an authorised viewer may legitimately see it -- is not
safe for an LLM provider, a log line or a metric label. Each destination therefore has
its own :class:`DestinationPolicy`, and the gate refuses any destination that has none.

``MODEL_ARTIFACT_STORE`` deliberately has no default: model artifacts leave through the
memorisation audit (``certify_deployable``), not through a field-level gate.

The contract's ``Destination`` enum has one ``TELEMETRY`` value where the brief asks for
``METRIC_LABEL`` and ``TRACE_ATTRIBUTE`` separately. Until
``CR-A5-destination-vocabulary`` lands, TELEMETRY gets the stricter of the two: no data
values, no tokens (a token is a stable pseudonym and a high-cardinality label), and
opaque schema names.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from godwit_contracts import Destination, GodwitModel, RedactionAction
from pydantic import Field

from godwit_guard.schema_names import SchemaNameMode

__all__ = [
    "DEFAULT_DESTINATION_POLICIES",
    "DestinationPolicy",
]

_R = RedactionAction


class DestinationPolicy(GodwitModel):
    """What may reach one destination. Versioned; never edited in place."""

    destination: Destination
    version: int = Field(ge=1)
    data_value_actions: frozenset[RedactionAction]
    """Redactions a DATA_VALUE may leave under. A rule asking for anything else is
    escalated to TOKENISE (if allowed here) or SUPPRESS."""
    allow_requires_guardrail: bool = True
    """ALLOW -- a raw value -- additionally needs a matching ALLOW guardrail."""
    allow_tokens: bool
    allow_statistics: bool = True
    max_schema_mode: SchemaNameMode = SchemaNameMode.DESCRIBED
    """The most disclosive schema-name rendering this destination may receive."""


_STRICT: Final[frozenset[RedactionAction]] = frozenset(
    {_R.SUPPRESS, _R.TOKENISE, _R.BUCKET, _R.GENERALISE}
)
_VIEWER: Final[frozenset[RedactionAction]] = frozenset(RedactionAction)
_EXPORT: Final[frozenset[RedactionAction]] = frozenset(
    {_R.SUPPRESS, _R.HASH, _R.BUCKET, _R.GENERALISE, _R.ALLOW}
)
_NOTHING: Final[frozenset[RedactionAction]] = frozenset({_R.SUPPRESS})


def _policy(
    destination: Destination,
    actions: frozenset[RedactionAction],
    *,
    tokens: bool,
    schema: SchemaNameMode,
) -> DestinationPolicy:
    return DestinationPolicy(
        destination=destination,
        version=1,
        data_value_actions=actions,
        allow_tokens=tokens,
        max_schema_mode=schema,
    )


DEFAULT_DESTINATION_POLICIES: Final[Mapping[Destination, DestinationPolicy]] = MappingProxyType(
    {
        # Zero raw values to a model provider. Tokens, buckets and generalisations only;
        # no HASH either, because a stable hash is linkable across every call we ever make.
        Destination.LLM_PROVIDER: _policy(
            Destination.LLM_PROVIDER, _STRICT, tokens=True, schema=SchemaNameMode.DESCRIBED
        ),
        Destination.ALERT_CHANNEL: _policy(
            Destination.ALERT_CHANNEL, _STRICT, tokens=True, schema=SchemaNameMode.DESCRIBED
        ),
        Destination.WEBHOOK: _policy(
            Destination.WEBHOOK, _STRICT, tokens=True, schema=SchemaNameMode.DESCRIBED
        ),
        # Authorised viewers may see raw values, but only under an ALLOW guardrail, and the
        # Board resolves tokens locally for roles that permit it.
        Destination.UI: _policy(
            Destination.UI, _VIEWER, tokens=True, schema=SchemaNameMode.DESCRIBED
        ),
        Destination.HUMAN_REVIEW: _policy(
            Destination.HUMAN_REVIEW, _VIEWER, tokens=True, schema=SchemaNameMode.DESCRIBED
        ),
        # Tokens are meaningless outside the perimeter's vault, so exports hash instead.
        Destination.EXPORT_FILE: _policy(
            Destination.EXPORT_FILE, _EXPORT, tokens=False, schema=SchemaNameMode.DESCRIBED
        ),
        # Logs and telemetry get statistics and our own vocabulary. Nothing else.
        Destination.LOG: _policy(
            Destination.LOG, _NOTHING, tokens=False, schema=SchemaNameMode.OPAQUE
        ),
        Destination.TELEMETRY: _policy(
            Destination.TELEMETRY, _NOTHING, tokens=False, schema=SchemaNameMode.OPAQUE
        ),
    }
)
