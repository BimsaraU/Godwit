"""Builders shared by godwit-probe's tests. Imported by name; see conftest.py."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping
from typing import Any

from godwit_contracts import (
    Acquisition,
    Guardrail,
    GuardrailAction,
    GuardrailAttribute,
    GuardrailCondition,
    GuardrailPredicate,
    GuardrailScope,
    Operator,
    Predicate,
    ScalarValue,
    Segment,
    data_value,
    schema_name,
)
from godwit_guard import AccessMode
from godwit_probe.plan import PLAIN_KEYS_PURPOSE
from godwit_probe.testing import (
    Distribution,
    ProbeSimulator,
    SyntheticColumn,
    SyntheticCommit,
    SyntheticTable,
)

COUNTRY = SyntheticColumn(
    "country", Distribution.CATEGORICAL, categories=("US", "DE", "PT"), weights=(0.6, 0.37, 0.03)
)
STATUS = SyntheticColumn(
    "status",
    Distribution.CATEGORICAL,
    categories=("settled", "refund", "chargeback"),
    weights=(0.9, 0.08, 0.02),
)
AMOUNT = SyntheticColumn("amount", Distribution.LOGNORMAL, mean=3.2, sigma=0.7, null_fraction=0.05)
EMAIL = SyntheticColumn("email", Distribution.IDENTIFIER, prefix="user-")
DEVICE = SyntheticColumn("device_id", Distribution.IDENTIFIER, prefix="dev-")
NOTES = SyntheticColumn("notes", Distribution.IDENTIFIER, prefix="note-")
UNCLASSIFIED = SyntheticColumn("customer_email_v2", Distribution.IDENTIFIER, prefix="v2-")
SEQUENCE = SyntheticColumn("row_no", Distribution.SEQUENCE)

MODES: Mapping[str, AccessMode] = {
    "country": AccessMode.OPEN,
    "status": AccessMode.OPEN,
    "amount": AccessMode.OPEN,
    "row_no": AccessMode.OPEN,
    "email": AccessMode.OPAQUE,
    "device_id": AccessMode.OPAQUE,
    "notes": AccessMode.BLIND,
}
"""``customer_email_v2`` is deliberately absent: a column nobody classified."""

PT_SURGE = SyntheticColumn(
    "country", Distribution.CATEGORICAL, categories=("US", "DE", "PT"), weights=(0.6, 0.22, 0.18)
)


def orders(
    *,
    commits: tuple[SyntheticCommit, ...] | None = None,
    seed: int = 20240117,
    rows_per_file: int = 20_000,
    block_rows: int = 8_192,
) -> SyntheticTable:
    """An orders table: three appends, the third with PT surging, as in the golden fixture."""
    return SyntheticTable(
        namespace="shop",
        name="orders",
        columns=(COUNTRY, STATUS, AMOUNT, EMAIL, DEVICE, NOTES, UNCLASSIFIED, SEQUENCE),
        commits=commits
        or (
            SyntheticCommit(rows=30_000),
            SyntheticCommit(rows=30_000),
            SyntheticCommit(rows=30_000, overrides={"country": PT_SURGE}),
        ),
        seed=seed,
        rows_per_file=rows_per_file,
        block_rows=block_rows,
    )


def simulator(table: SyntheticTable | None = None, **kwargs: Any) -> ProbeSimulator:
    """A simulator over :func:`orders` with the standard modes."""
    return ProbeSimulator(table or orders(), modes=MODES, **kwargs)


def predicate(column: str, op: Operator, *values: ScalarValue) -> Predicate:
    """One segment predicate with properly tainted parts."""
    return Predicate(
        column=schema_name(column),
        op=op,
        values=tuple(data_value(v, acquisition=Acquisition.SEGMENT_PREDICATE) for v in values),
    )


def segment(*predicates: Predicate) -> Segment:
    """A segment of the given predicates."""
    return Segment(predicates=predicates)


def plain_keys_guardrail(
    column: str, *, action: GuardrailAction = GuardrailAction.ALLOW, purpose: bool = True
) -> Guardrail:
    """A guardrail about plain heavy-hitter keys on one column."""
    conditions = [
        GuardrailCondition(attribute=GuardrailAttribute.COLUMN_NAME, op="eq", values=(column,))
    ]
    if purpose:
        conditions.append(
            GuardrailCondition(
                attribute=GuardrailAttribute.PURPOSE, op="eq", values=(PLAIN_KEYS_PURPOSE,)
            )
        )
    return Guardrail(
        guardrail_id=f"g-{column}-{action.value}",
        name="plain keys",
        version=1,
        scope=GuardrailScope(),
        predicate=GuardrailPredicate(all_of=tuple(conditions)),
        action=action,
        rationale="test",
        created_at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
    )
