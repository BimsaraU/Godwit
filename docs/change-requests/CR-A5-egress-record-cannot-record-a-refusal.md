# CR-A5-egress-record-cannot-record-a-refusal

**Filed by:** A5 (`godwit-guard`)
**Against:** `godwit-contracts` — `godwit_contracts.governance.EgressRecord`
**Status:** open
**Priority:** medium
**Related:** `CR-A3-ledger-fields-missing` (A3 filed the token-map half independently)

## The problem

The A5 brief: *"Every call writes an EgressRecord to A3: destination, policy version, a
hash of the exact bytes emitted, the token map reference, the caller, the decision."*

`EgressRecord` has no **decision** and no **token map reference**. It is shaped for
successful egress only: `content_digest` is mandatory, and `sensitivity_after` has no
value meaning "nothing left". A refusal written as an `EgressRecord` would have to invent
a digest and claim a sensitivity for content that never existed — a misleading audit row,
which is worse than a missing one.

## Why it matters

An auditor asking *"show me every attempt to send something to a model provider, allowed
or not"* has to union two tables (`egress_records` and `audit_events`) and know that
refusals live in the second under `egress.refused.<reason>`. It works; it is not one
query, and the brief wanted one.

## The smallest sufficient change

```python
# current: no such fields

# proposed
class EgressDecision(StrEnum):
    ALLOWED = "allowed"
    REFUSED = "refused"


class EgressRecord(GodwitModel):
    ...
    decision: EgressDecision = EgressDecision.ALLOWED
    refusal_reason: str | None = None  # our own code, never a value
    token_map_ref: str | None = None  # a reference, never the map
    content_digest: ContentHash | None  # None iff decision is REFUSED (validated)
```

## Who else this affects

* **A3** — `egress_records` gains three columns; A3 already stores `token_map_ref` as a
  side column and would fold it in.
* **A16, A17** — the egress audit view.

## What I did instead

* Allowed egress: `EgressRecord` via A3's `append_egress(..., token_map_ref=...)`, the
  keyword argument A3 added for exactly this gap.
* Refused egress: an `AuditEvent` with `action="egress.refused.<reason>"`,
  `subject_kind="egress_request"`, and a `detail_digest` over the `Refusal` (field *names*
  and reason, never values). Backstop hits are `egress.backstop_hit`.

```
packages/godwit-guard/tests/test_contract_gaps.py::test_an_egress_record_can_say_refused_and_name_its_token_map
@pytest.mark.xfail(strict=True, reason="CR-A5-egress-record-cannot-record-a-refusal")
```

## Decision

_Left blank by the filer. A human fills this in._
