"""Builders shared by godwit-guard's tests. Imported by name; see conftest.py."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence
from typing import Any

from godwit_contracts import (
    Acquisition,
    ColumnProfile,
    ColumnRef,
    ColumnRole,
    Destination,
    Guardrail,
    GuardrailAction,
    GuardrailCondition,
    GuardrailPredicate,
    GuardrailScope,
    LogicalType,
    PiiClass,
    ScalarValue,
    SourceId,
    Tainted,
    data_value,
    derived_statistic,
    schema_name,
)
from godwit_guard import (
    AccessControl,
    Backstop,
    ClassificationRegistry,
    Gate,
    MemoryLedger,
    TokenVault,
    assess_entropy,
    format_space_bits,
    propose,
)

SOURCE = SourceId("src_pii")
TABLE = "customers"
SCOPE = "pattern_1"


def col_ref(column: str, *, table: str = TABLE, source: str = SOURCE) -> ColumnRef:
    return ColumnRef(
        source_id=SourceId(source),
        table=schema_name(table, source_id=source),
        column=schema_name(column, source_id=source, table=table),
    )


def value(
    raw: ScalarValue,
    column: str | None,
    *,
    acquisition: Acquisition = Acquisition.SEGMENT_PREDICATE,
    population: int | None = 10_000,
    table: str = TABLE,
    source: str = SOURCE,
) -> Tainted[ScalarValue]:
    return data_value(
        raw,
        acquisition=acquisition,
        population=population,
        source_id=source,
        table=table,
        column=column,
    )


def stat(raw: float, *, population: int | None = 10_000) -> Tainted[float]:
    return derived_statistic(raw, population=population, source_id=SOURCE, table=TABLE)


def make_profile(
    column: str,
    logical_type: LogicalType = LogicalType.STRING,
    *,
    at: _dt.datetime,
    role: ColumnRole = ColumnRole.UNKNOWN,
    pii_class: PiiClass = PiiClass.UNKNOWN,
    rows: int | None = None,
    ndv: int | None = None,
    table: str = TABLE,
) -> ColumnProfile:
    return ColumnProfile(
        ref=col_ref(column, table=table),
        logical_type=logical_type,
        native_type=logical_type.value,
        nullable=True,
        role=role,
        pii_class=pii_class,
        row_count=None if rows is None else stat(rows),
        distinct_estimate=None if ndv is None else stat(ndv),
        observed_at=at,
        profile_version=1,
    )


def classify(
    registry: ClassificationRegistry,
    column: str,
    logical_type: LogicalType = LogicalType.STRING,
    *,
    at: _dt.datetime,
    confirm: PiiClass | None,
    role: ColumnRole = ColumnRole.UNKNOWN,
    sample: Sequence[ScalarValue] = (),
    rows: int | None = None,
    ndv: int | None = None,
    table: str = TABLE,
) -> ColumnRef:
    """Propose, record and (optionally) confirm one column. Returns its ref."""
    profile = make_profile(column, logical_type, at=at, role=role, rows=rows, ndv=ndv, table=table)
    registry.record(propose(profile, sample=sample))
    if confirm is not None:
        registry.confirm(profile.ref, confirm, by="dpo@bank.test", at=at)
    return profile.ref


def record_entropy(
    access: AccessControl,
    ref: ColumnRef,
    logical_type: LogicalType,
    sample: Sequence[ScalarValue],
    *,
    ndv: int | None = None,
    min_bits: float = 24.0,
) -> None:
    access.record_entropy(
        ref,
        assess_entropy(
            column_name=ref.column.reveal(),
            logical_type=logical_type,
            observed_distinct=ndv if ndv is not None else len(set(sample)),
            format_bits=format_space_bits(sample),
            min_bits=min_bits,
        ),
    )


def make_vault(at: _dt.datetime, *, scope: str = SCOPE) -> TokenVault:
    vault = TokenVault("vault_test", restore_roles={"*": frozenset({"investigator"})})
    vault.open_scope(scope, expires_at=at + _dt.timedelta(days=30))
    return vault


def make_gate(
    registry: ClassificationRegistry,
    *,
    at: _dt.datetime,
    presidio: bool = False,
    **kwargs: Any,
) -> tuple[Gate, MemoryLedger, TokenVault]:
    ledger = MemoryLedger()
    vault = kwargs.pop("vault", None) or make_vault(at)
    backstop = kwargs.pop("backstop", None) or Backstop(use_presidio=presidio)
    gate = Gate(ledger=ledger, registry=registry, backstop=backstop, vault=vault, **kwargs)
    return gate, ledger, vault


def guardrail(
    gid: str,
    action: GuardrailAction,
    *conditions: GuardrailCondition,
    at: _dt.datetime,
    destinations: tuple[Destination, ...] = (),
    version: int = 1,
) -> Guardrail:
    return Guardrail(
        guardrail_id=gid,
        name=gid,
        version=version,
        scope=GuardrailScope(destinations=destinations),
        predicate=GuardrailPredicate(all_of=conditions),
        action=action,
        rationale="test",
        created_at=at,
    )


def cond(attribute: Any, op: str, *values: str | int | float | bool) -> GuardrailCondition:
    return GuardrailCondition(attribute=attribute, op=op, values=values)
