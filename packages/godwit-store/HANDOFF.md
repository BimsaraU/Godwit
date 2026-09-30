# godwit-store — HANDOFF

**Owner:** A3 **Layer:** L5 **Plane:** control
**Status:** complete. `ruff`, `mypy --strict` and `pytest` green from a clean checkout.

**This package stores data-derived values.** Segment predicates, label values,
explanation text, model cards and column profiles all sit in tainted payload columns
here, each with its sensitivity recorded beside it. It is not an egress boundary —
`godwit-guard` is — but a bank's security team will read this schema.

Full documentation: **`docs/packages/godwit-store.md`**. Read §1 before using anything
here. This file is the orientation; that one is the reference.

---

## What it does

```
godwit_store/
  schema.py      27 tables, 4 safe views, the deployability foreign key
  columns.py     the three dialect differences: UTC instants, JSONB, pgvector
  engine.py      engines, sessions, bootstrap
  appendonly.py  the grants and triggers that make the ledgers append-only
  taint.py       the two unwraps this package is allowed to perform
  signature.py   the three dedup keys and the redacted rendering
  fdr.py         Benjamini-Hochberg, the declared family, the holdout
  lifecycle.py   allowed transitions, required evidence, automatic staleness
  ranking.py     the two queues. Pure functions: no session, no clock, no LLM
  labels.py      the label ledger. Reads require an explicit instant
  ledger.py      hash-chained audit and egress, and the export a bank asks for
  registry.py    model registry metadata and the refusal to deploy an unaudited model
  reproduce.py   reproduce(pattern_id) — the regulator-facing capability
  store.py       PatternStore: ingest, dedup, merge, suppression, queues
  migrations/    Alembic; the initial revision builds from the ORM metadata
```

---

## The six things you need to know

**1. `PatternStore.ingest` — the protocol method — bars everything from the operational
queue.** It carries no run metadata, so there is no test count and no holdout, so every
candidate is `NOT_TESTED` and none of them can page a human. That is the safe default
and it is deliberate. Use `ingest_batch(family=..., candidates=..., holdout=...,
holdout_candidates=..., at=...)` for anything real. Filed as
`CR-A3-pattern-store-ingest-has-no-run-metadata.md` — **read that one first.**

**2. `test_count` is how many hypotheses the detector EXAMINED, not how many candidates
it emitted.** A detector that examined ten thousand segments and emitted its best five
must say ten thousand. Saying five makes each survivor look two thousand times more
significant than it is. A count smaller than the number of candidates supplied raises
`UnboundedHypothesisFamilyError` rather than being clamped.

**3. Every label read takes `instant` keyword-only, with no default.** There is no
`all()`, no `latest()` and no `as_of=None` meaning "now". This is the whole design of
`LabelLedger`, not an inconvenience — the most common leakage bug in the industry is a
pipeline that quietly used the wall clock.

**4. The dedup embedding never sees a value, and the test proves it three ways.** It is
built from a rendering that uses predicate *arity* rather than predicate type, so the
function does not touch a `DATA_VALUE` at all. The strongest proof monkeypatches
`Tainted.reveal` to raise on `DATA_VALUE` and builds a rendering anyway. Do not add a
token to that rendering without reading `signature.py`'s module docstring.

**5. FDR is not controlled under adaptive probing, and nothing here claims it is.** A
bandit changes the size of the hypothesis family as it goes and enriches it with
hypotheses selected for looking significant. The implemented fallback is a declared
ceiling per snapshot. `CR-A3-fdr-hypothesis-space.md` lays out the three real options
and needs a human to pick one. This is the weakest part of the package.

**6. The append-only ledgers are tamper-evident, not tamper-proof.** Grants stop the
service role, a trigger stops the table owner, and the hash chain makes any tampering
detectable. None of them stops a superuser. The deployment property that follows: the
ledgers' owner must not be the role the service connects as.

---

## If you are…

**A7 (detectors)** — emit raw p-values; FDR control is L5's job and yours cannot see the
whole space (protocol law 5). Report how many hypotheses you examined. If you can re-run
over a reserved slice, pass those candidates as `holdout_candidates` — without them
nothing you produce reaches the operational queue.

**A10 (orchestrator)** — you own the holdout policy, the q target and the hypothesis
ceiling. `store.queue(queue=..., at=..., capacity=...)` gives you a ranked queue with
the components that produced each score, so "why is this at the top" is answerable
without a debugger. Read `CR-A3-fdr-hypothesis-space.md`: the decision is yours and A3's
jointly.

**A4 (replay)** — `reproduce(session, pattern_id)` gives you a `ReproductionRequest` with
every probe key, both snapshot ids, the detector version, the code version and the seed.
Run it; hand the result to `verify_reproduction`. `HoldoutPolicy.canonical_form()` is
what lets you rebuild the reserved slice.

**A12 (subtractor) and A13 (prediction)** — use `LabelLedger`. `visible_as_of(instant=…)`
for training labels, `assert_covered(…)` before reporting any metric. Do not use
`patterns.confirmations` as precision: it is reviewer agreement, and the 90-day
reconciliation has no contract yet
(`CR-A3-label-reconciliation-has-no-contract.md`).

**A5 (guard)** — `append_egress(session, record, token_map_ref=…)` writes the egress
record and links it into the chain. `EgressRecord` has no token-map field yet, hence the
keyword argument; see `CR-A3-ledger-fields-missing.md`. `egress_query` and
`export_egress` answer "show me everything you ever sent to a model provider".

**A11 (features)** — `feature_sets.derived_from_patterns` is lifted out of the payload
into a column of its own, so "which discovered patterns is this model built on" is a
query in both directions.

**A14 (serving)** — `ModelRegistryStore.certify` is the only route to a
`DeployableModel`, and the database refuses a deployment of anything else through a
composite foreign key. There is no override, and adding one would need three separate
changes.

**A16 / A17 (Vision Board)** — query the `*_safe` views. They expose every safe column
and no tainted one, so a dashboard cannot reach a merchant name by accident. Anything
you show a human is still an egress and still goes through A5.

**A18 (policy)** — the storage convention is four columns per tainted value
(`_value`, `_sensitivity`, `_acquisition`, `_population`) and it is machine-checkable.
`audit_events` and `egress_records` have no column that could hold a tainted value,
which is also checkable.

---

## Running it

```sh
uv run pytest packages/godwit-store          # no docker needed; SQLite in memory
GODWIT_STORE_TEST_URL=postgresql+psycopg://... uv run pytest packages/godwit-store
```

The suite runs on SQLite so that `make test` works on a clean checkout. The three
dialect differences are wrapped in `columns.py` and the append-only DDL is wrapped in
`appendonly.py`; everything else is the same SQL. What SQLite does **not** cover, and
what therefore needs the Postgres path in CI: ivfflat behaviour, grant-based
enforcement, advisory locks and JSONB operators.

Migrations:

```sh
export GODWIT_STORE_URL=postgresql+psycopg://godwit@localhost/godwit
export GODWIT_STORE_ROLE=godwit_service     # optional; names the role in the grants
uv run alembic -c packages/godwit-store/alembic.ini upgrade head
```

---

## Change requests filed

| File | What it is about |
|---|---|
| `CR-A3-pattern-store-ingest-has-no-run-metadata.md` | the protocol signature cannot satisfy its own law 3. **Read first.** |
| `CR-A3-fdr-hypothesis-space.md` | FDR under adaptive probing. Needs a human decision. |
| `CR-A3-ledger-fields-missing.md` | four fields the brief requires and the contracts do not have |
| `CR-A3-lifecycle-has-no-stale.md` | `PatternLifecycle` has `EXPIRED`, the brief asks for `STALE` |
| `CR-A3-label-reconciliation-has-no-contract.md` | the 90-day reconciliation in the objective function is not modelled |

Four of the five carry `xfail(strict=True)` tests that start passing the moment the
request is accepted. The fifth (`label-reconciliation`) does not, because what is missing
there is a design decision rather than a specific API, and guessing at a signature would
make the request harder to answer.

---

## Known limits

Full list in `docs/packages/godwit-store.md` §10. The three that will bite first:

* **Dedup is exact.** A segment that gained one predicate is a different pattern. The
  golden fixture contains an instance. Conservative on purpose.
* **FDR under adaptive probing is not controlled.** See above.
* **The hash chain is serial.** One ledger append per transaction. If that becomes the
  bottleneck the fix is batching, not removing the lock.

One packaging note for whoever writes tests next: this package's shared test helpers are
in `tests/_store_support.py`, not `tests/_support.py`. Every package puts its tests
directory on `sys.path` in its `conftest`, so the first one collected wins a generic
module name — `godwit-sketch` already owns `_support`.
