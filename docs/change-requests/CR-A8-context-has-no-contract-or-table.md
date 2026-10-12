# CR-A8-context-has-no-contract-or-table

**Filed by:** A8 (`godwit-context`)
**Against:** `godwit-contracts`, `godwit-store`
**Status:** open

## The problem

L3 produces three kinds of thing that need to outlive a process. None of them has a
contract type or a table.

1. **Context events.** These are deploys, campaigns, holidays and analyst annotations. The
   brief says annotations "become permanent context". An event's scope names customer
   columns (SCHEMA_NAME) and segments (DATA_VALUE). Its label is imported free text
   (USER_SUPPLIED). It therefore needs the tainted four-column storage that A3 uses
   everywhere else. The audit ledger cannot hold it, because it stores digests only.
2. **Routing decisions.** Each decision records which candidate was explained away, by
   which event, at what strength, with the counterfactual counts behind it, and any
   reversal that followed. A decision holds no value, only ids and derived numbers.
   godwit-store's `EXPLAINED_AWAY` transition requires a `context_ref: str` and gives
   nowhere to resolve that reference.
3. **Learned priors**, which are counts per (context type, detector family, source).

## Why it matters

Priors survive a restart: I persist them as append-only observations in A3's audit
ledger, and that works well (see below).

Annotations do not survive a restart. Neither do full decision records. The audit ledger
still holds proof that each suppression and each reversal happened (who, when, and a
digest of the decision). But "show me the explanation behind `context_ref` X" can only be
answered while the router that made X is still in memory. A regulator can ask exactly
that question.

## The smallest sufficient change

A0 adds `ContextEvent` and `ContextScope`, as defined in `godwit_context/events.py`, to the
contracts. A3 adds two tables:

```
context_events     event_id PK, context_type, kind, origin, start, end, permanent,
                   derived_from, scope_* (tainted column group), label_* (tainted column group)
context_decisions  decision_id PK, candidate_id, source_id, family, route, threshold,
                   decided_at, actor, reverses FK -> context_decisions, reason,
                   matches JSONB (ids and numbers only)
```

`patterns.context_ref` would then be a foreign key to `context_decisions.decision_id`.

## Who else this affects

A0 (types). A3 (tables, plus the FK on the EXPLAINED_AWAY transition). A16 and A17: the
Vision Board will want to list "what was explained away this week" and the reversals.
A18 should check that `context_events.label` is stored as tainted.

## What I did instead

- Every suppression and every reversal goes through `StoreAuditSink` and becomes an
  `audit_events` row: action `context_explain` or `context_reverse`, subject the
  candidate id, `detail_digest` the digest of the decision, `correlation_id` the reversed
  decision.
- Every prior observation is an `audit_events` row: subject `context_prior`, subject id
  `type|family|source`, `to_state` the outcome. `PriorBook.load` rebuilds the counts by
  replaying these rows.
- Annotations are audited (`context_annotate`) and held by `AnnotationBook` in process.

```
packages/godwit-context/tests/test_contract_gaps.py::test_context_events_have_a_contract_home
packages/godwit-context/tests/test_contract_gaps.py::test_the_store_has_a_table_for_context
@pytest.mark.xfail(strict=True, reason="CR-A8-context-has-no-contract-or-table")
```

## Decision

_Left blank by the filer. A human fills this in._
