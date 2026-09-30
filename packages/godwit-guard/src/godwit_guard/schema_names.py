"""Schema-name handling. Column and table names are disclosures on their own.

``patient_hiv_status`` and ``customer_ssn`` say something about a person's data before a
single row is read. Three modes:

``FULL``       the literal name. Only for destinations that may see it.
``DESCRIBED``  an alias plus a generated description and the semantic role, e.g.
               ``COLUMN_3: health attribute (categorical attribute, string)``. The
               default. The description comes from a closed vocabulary
               (:data:`godwit_guard.classify.CONCEPTS`), never from the name's own
               characters, so it cannot echo the name.
``OPAQUE``     alias, role and type only: ``COLUMN_3: categorical attribute, string``.

Aliases are tokens (namespace ``COLUMN`` / ``TABLE``) from the scope's
:class:`~godwit_guard.transforms.TokenVault`, so the Vision Board can resolve them back
to names locally for viewers allowed to see them.

What each mode costs is measured, not asserted:
``tests/test_schema_names.py::test_capability_loss_is_measured`` and
``docs/packages/godwit-guard.md``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from godwit_contracts import ColumnRole, LogicalType

from godwit_guard.classify import CatalogEntry, match_concept

__all__ = [
    "SchemaNameMode",
    "describe",
    "narrower_schema_mode",
]


class SchemaNameMode(StrEnum):
    """How much of a customer schema name may leave. FULL > DESCRIBED > OPAQUE."""

    FULL = "full"
    DESCRIBED = "described"
    OPAQUE = "opaque"


_DISCLOSURE: Final[dict[SchemaNameMode, int]] = {
    SchemaNameMode.OPAQUE: 0,
    SchemaNameMode.DESCRIBED: 1,
    SchemaNameMode.FULL: 2,
}


def narrower_schema_mode(*modes: SchemaNameMode) -> SchemaNameMode:
    """The least disclosive of the inputs."""
    return min(modes, key=_DISCLOSURE.__getitem__)


ROLE_PHRASES: Final[dict[ColumnRole, str]] = {
    ColumnRole.ENTITY_ID: "entity identifier",
    ColumnRole.EVENT_TIME: "event time",
    ColumnRole.LABEL: "outcome label",
    ColumnRole.AMOUNT: "amount",
    ColumnRole.CATEGORY: "categorical attribute",
    ColumnRole.FREE_TEXT: "free text",
    ColumnRole.GEO: "location",
    ColumnRole.DEVICE: "device attribute",
    ColumnRole.JOIN_KEY: "join key",
    ColumnRole.MEASURE: "numeric measure",
    ColumnRole.UNKNOWN: "unclassified role",
}
"""Deliberately avoids the word "unknown": it is a real category value in the PII
torture fixture, and a description must never be mistakable for data."""

TYPE_PHRASES: Final[dict[LogicalType, str]] = {
    **{logical: logical.value for logical in LogicalType},
    LogicalType.UNKNOWN: "untyped",
}


def describe(entry: CatalogEntry, mode: SchemaNameMode, *, alias: str | None) -> str:
    """Render one column in ``mode``. FULL returns the literal name.

    Pure vocabulary lookups: the concept phrase, the role phrase and the logical type.
    No character of the name reaches the output in DESCRIBED or OPAQUE mode.
    """
    proposal = entry.proposal
    if mode is SchemaNameMode.FULL:
        return proposal.column.column.reveal()
    role = ROLE_PHRASES[proposal.role]
    kind = TYPE_PHRASES[proposal.logical_type]
    label = alias or "column"
    if mode is SchemaNameMode.OPAQUE:
        return f"{label}: {role}, {kind}"
    concept = match_concept(proposal.column.column.reveal())
    phrase = role if concept is None else concept.phrase
    return f"{label}: {phrase} ({role}, {kind})"
