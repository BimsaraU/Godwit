# CR-A3-ledger-fields-missing

**Filed by:** A3 (`godwit-store`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

The brief's deliverable 8 specifies the two ledgers field by field:

> - `audit_events`: every state change, who, when, **from what, to what, under which
>   guardrail**.
> - `egress_records`: every payload that left the perimeter — destination, policy
>   version, a hash of the exact bytes, **the token map reference**, and the caller.

Four of those fields do not exist on the contract types.

`godwit_contracts.governance.AuditEvent` has `actor`, `action`, `subject_kind`,
`subject_id`, `plane`, `detail_digest` and `correlation_id`. It has **no `from_state`,
no `to_state` and no guardrail reference.** The nearest thing is `action`, a free string,
and `detail_digest`, a hash of something the reader cannot see.

`godwit_contracts.governance.EgressRecord` has the destination, the policy, the
guardrail ids, the content digest, the field names and the sensitivities. It has **no
token-map reference.**

## Why it matters

Both are answers to questions somebody asks out loud.

"Who moved this pattern from proposed to confirmed?" is answerable today only by
convention: an implementer has to encode both states into the `action` string and hope
that every other implementer picked the same format. A convention that two independent
agents have to guess identically is not an audit trail.

The token-map reference is worse, because its absence is silent. A token in an alert is
a stable pseudonym; the map that resolves it lives in the data plane and never crosses.
Without a reference on the record, an investigator holding an egress record cannot ask
the data plane "which map entry was this", and nobody can answer "we tokenised this
entity under key version 4, which we have since rotated".

Neither field carries a value, so neither widens the leak surface. `from_state` and
`to_state` are members of `PatternLifecycle`; the token-map reference is a URI pointing
at something inside the perimeter.

## The smallest sufficient change

```python
# godwit_contracts.governance.AuditEvent -- add three optional fields
class AuditEvent(GodwitModel):
    ...
    from_state: str | None = None
    to_state: str | None = None
    guardrail_id: str | None = None
    guardrail_version: Version | None = None


# godwit_contracts.governance.EgressRecord -- add one
class EgressRecord(GodwitModel):
    ...
    token_map_ref: str | None = Field(
        default=None,
        description="Reference to the tokenisation map entry in the data plane. A "
        "reference, never a map: the map does not cross the boundary.",
    )
```

All optional, so nothing that constructs either type today breaks.

`AuditEvent` might also usefully validate that `from_state` and `to_state` are either
both set or both absent — a half-recorded transition is a worse audit row than none —
but that is a refinement, not the request.

## Who else this affects

* **A5 (`godwit-guard`)** produces every `EgressRecord` and is the one that knows the
  token-map reference. Nobody else can fill it in.
* **A16 (`godwit-vision`)** and **A17 (`apps/vision-board`)** render audit trails; today
  they would have to parse `action` to show a transition.
* **A18 (`godwit-policy`)** writes conformance rules over guardrail application, and
  cannot currently check "which guardrail authorised this state change".
* **A3 (`godwit-store`)** stores both ledgers.

Nothing migrates: the columns already exist in the store's schema.

## What I did instead

Stored all four in columns of their own and accepted them as keyword arguments beside
the contract object:

```python
append_audit(
    session,
    event,
    from_state="proposed",
    to_state="confirmed",
    guardrail_id="gr_review",
    guardrail_version=2,
)
append_egress(session, record, token_map_ref="tokmap://data-plane/...")
```

The columns are `audit_events.from_state`, `.to_state`, `.guardrail_id`,
`.guardrail_version` and `egress_records.token_map_ref`, and all five are inside the
hash chain, so a later contract change can move them onto the models without
invalidating a single stored row.

```
packages/godwit-store/tests/test_store.py::test_an_audit_event_can_carry_the_states_it_moved_between
packages/godwit-store/tests/test_store.py::test_an_egress_record_can_carry_its_token_map_reference
@pytest.mark.xfail(reason="CR-A3-ledger-fields-missing", strict=True)
```

Both start passing the moment this is accepted. A third test,
`test_the_workaround_for_those_gaps_actually_stores_the_fields`, passes today and shows
that nothing was lost in the meantime.

## Decision

_Left blank by the filer. A human fills this in._
