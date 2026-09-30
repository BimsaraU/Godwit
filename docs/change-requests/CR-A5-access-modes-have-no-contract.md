# CR-A5-access-modes-have-no-contract

**Filed by:** A5 (`godwit-guard`)
**Against:** `godwit-contracts`
**Status:** open
**Priority:** high for A6 / A17 / A18, which all need to read the same mode map

## The problem

The shared brief makes column access modes load-bearing — **BLIND / OPAQUE / OPEN**,
enforced at plan time, widened only by an **AccessGrant** with a reason, approver, expiry
and audit record — and says A5 must *"emit the current mode map as queryable state so
A18 can assert on it and A17 can show it"*.

None of these types exist in `godwit_contracts`:

* no `AccessMode` enum;
* no `AccessGrant` model;
* no per-column mode map type, and nothing on `ColumnProfile` or `ProbeSpec` that says
  which mode a probe must respect.

godwit-guard therefore defines them itself (`godwit_guard.access`). That works for A5,
but A6 (probes, which must enforce BLIND at plan time), A17 (which shows the map) and A18
(which asserts on it) would have to import godwit-guard to read one enum. The conformance
auditor in A18 is supposed to be *independent* of the thing it audits.

## Why it matters

Three agents will either depend on godwit-guard for a vocabulary type or invent their own
copies, and a mode map that two packages spell differently is not a control.

## The smallest sufficient change

Move the *data* types to contracts; keep resolution logic in godwit-guard:

```python
# godwit_contracts/governance.py (proposed)
class AccessMode(StrEnum):
    BLIND = "blind"
    OPAQUE = "opaque"
    OPEN = "open"


class AccessGrant(GodwitModel):
    grant_id: str
    column: ColumnRef
    from_mode: AccessMode
    to_mode: AccessMode  # validated: must widen
    reason: str
    requested_by: str
    approved_by: str  # validated: != requested_by
    granted_at: Instant
    expires_at: Instant | None  # validated: None iff permanent
    permanent: bool = False
    authorising_guardrail_id: str | None  # required when to_mode is OPEN


class ColumnModeEntry(GodwitModel):
    column: ColumnRef
    mode: AccessMode
    reasons: tuple[str, ...]


class AccessModeMap(GodwitModel):
    resolved_at: Instant
    entries: tuple[ColumnModeEntry, ...]
```

The shapes above are exactly what `godwit_guard.access` implements today, so the move is
mechanical.

## Who else this affects

* **A6** — plan-time BLIND enforcement reads the map.
* **A17** — renders it.
* **A18** — asserts on it independently of A5.
* **A3** — may want to persist grants; today they live in godwit-guard's memory.

## What I did instead

`godwit_guard.access.AccessMode`, `AccessGrant`, `Narrowing`, `ModeDecision` and
`AccessModeMap`, exported from `godwit_guard`.

```
packages/godwit-guard/tests/test_contract_gaps.py::test_access_modes_are_a_contract_type
@pytest.mark.xfail(strict=True, reason="CR-A5-access-modes-have-no-contract")
```

## Decision

_Left blank by the filer. A human fills this in._
