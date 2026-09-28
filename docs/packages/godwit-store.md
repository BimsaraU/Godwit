# godwit-store

**Owner:** A3 **Layer:** L5 **Plane:** control
**Status:** complete. `ruff`, `mypy --strict` and `pytest` green from a clean checkout.

Pattern store, deduplication, false-discovery control, lifecycle, lineage, the label
ledger, model registry metadata, and the append-only audit and egress ledgers.

Read §1 before using anything here.

---

## 1. Disclosure — what this package stores

**This package holds data-derived values.** It is *not* an egress boundary —
`godwit-guard` is — but a bank's security team will read this schema, so it is written
to be read.

Every tainted value is stored in a dedicated column group:

```
<name>_value          JSONB   the value, and nothing else
<name>_sensitivity    text    what it is
<name>_acquisition    text    how it was obtained
<name>_population     int     rows behind it; NULL means unknown, which means unsafe
```

| Table | What is tainted | Which leak path |
|---|---|---|
| `candidates` | the whole `Candidate`: its segment predicates quote real values | 4 |
| `patterns` | the `Segment` | 4 |
| `column_profiles` | manifest bounds, most-common-values | 1, 2 |
| `sketch_envelopes` | Count-Min, frequent-items and quantile payloads | 3, 7 |
| `labels` | entity id and label value | — (row values) |
| `label_coverage` | the population `Segment` | 4 |
| `explanations` | LLM text, which can echo tokens | — |
| `feedback` | reviewer notes; assume they pasted a row | — |
| `feature_sets` | feature *names* — `is_merchant_ACME_CORP` | 8 |
| `model_artifacts` | the `ModelCard` | 8 |
| `evaluation_reports` | slice metrics, which are segments | 4 |
| `patterns.embedding` | customer **column names**, never values (see §3) | 9 |

**Never tainted, by construction:** `audit_events` and `egress_records`. Every column on
both is a plain type, so there is no field a tainted value could sit in even by
accident. `audit_events` stores `detail_digest`, never `detail`: an audit log full of
PII is a second breach with better indexing.

### The safe views

`patterns_safe`, `candidates_safe`, `column_profiles_safe` and `labels_safe` expose
every safe column of their table and none of its tainted ones. This is what "make the
safe query the easy one" means in practice:

```sql
SELECT pattern_id, q_value, score FROM patterns_safe WHERE lifecycle = 'proposed';
```

answers what a queue needs and touches nothing tainted. There is no version of that
query that accidentally selects a merchant name.

`column_profiles_safe` additionally drops `column_key`, because a customer column name
is a disclosure on its own and a profile view is exactly the thing somebody points a
dashboard at.

### Two unwraps, and only two

`godwit_store.taint` holds the only `.reveal()` calls in the package.
`reveal_statistic` accepts `DERIVED_STATISTIC` and `reveal_schema_name` accepts
`SCHEMA_NAME`; both **raise** on anything else. Reading a `DATA_VALUE` is not on the
list, because there is nothing this package could correctly do with one. Grep for
`.reveal()` and you will find it in one file.

One unwrap happens outside that file and is worth knowing about: computing
`Segment.key` reveals predicate values, inside `godwit_contracts.segment`. That is the
contract's own canonicalisation, every agent performs it, and this package only ever
holds the resulting hash.

---

## 2. The failure this package prevents

A system testing thousands of hypotheses an hour produces findings that are
statistically significant and meaningless, and reports the same finding for ever. Alert
fatigue kills this product faster than poor accuracy does.

Measured, on two hundred noise hypotheses per run
(`tests/test_fdr.py::test_without_adjustment_the_same_noise_floods_the_queue`):

| | Findings per run, pure noise |
|---|---|
| Raw `p < 0.05` | ~10 |
| After Benjamini-Hochberg at q = 0.10 | ~0.16 |

Ten a run, for ever, into a queue the objective function caps at fifty a day. That is
what the adjustment is for.

There are four answers to that failure and they are independent:

1. **Dedup**, so the same finding is one pattern (§3).
2. **False-discovery control**, so noise does not clear the bar (§4).
3. **A holdout**, so a finding has to reproduce on data the detector did not see (§4).
4. **Suppression**, so a human can say "stop showing me this" and have it stick (§5).

---

## 3. Dedup — three keys, three jobs

Confusing these is how a store either reports the same finding for ever or silently
merges two different ones.

| Key | Built from | Decides |
|---|---|---|
| `signature` | source, segment key, column set, detector family, effect **direction** | whether two candidates are the **same finding** |
| `structure_key` | the same, minus values *and* direction | which pattern a new one **shifted away from** |
| `embedding` | the redacted rendering the structure key hashes | "what else **looks like** this" |

**`signature` is the only thing that decides a merge.** An arriving candidate either
extends a pattern's evidence or opens a new one; there is no third case. A change of
direction or of segment produces a different signature, which is why "a material shift
opens a new pattern" falls out of the key rather than out of a heuristic.

**`structure_key` ignores direction on purpose.** A material shift *is* a change of
segment or of direction, so the shape has to ignore both or it could never find the
ancestor it shifted away from. `pattern_ancestry` records the link and the reason
(`segment_shift`, `direction_shift`, `family_shift`).

**Detector family is the claim, not the code.** It is the sorted set of `EvidenceKind`
values, so two detectors that both find a segment divergence in the same segment are one
finding, and a detector version bump does not fork every pattern in the store.

### The embedding is built from a redacted rendering

An embedding computed over raw values is an egress channel. It is a lossy but real
encoding of its input, it lives in a control-plane table, it gets served to a UI to draw
a similarity map, and nobody thinks of it as data because it is a list of floats.

The rendering contains: our source id, a population *bucket*, evidence kinds, canonical
column names, and one token per predicate of the form `pred:<column>:<operator>:<arity>`.
**Arity, not type and never the value** — so the function does not touch a `DATA_VALUE`
at all.

`tests/test_embedding_is_redacted.py` proves that three ways against the PII torture
fixture, in increasing order of strength:

1. no string from `expected_leaks.json` appears in the rendering — a backstop, and
   worth very little alone;
2. two candidates differing *only* in their predicate values produce byte-identical
   renderings and identical vectors;
3. `Tainted.reveal` is monkeypatched to raise on `DATA_VALUE` for the duration of the
   call, and the rendering still builds.

The third is the one that matters: it is a statement about the code path rather than
about this particular data. A fourth test monkeypatches the same guard onto
`Segment.key` and asserts it *does* fire, so the proof is known to be capable of
failing.

The vector is 256-dimensional, unit-normalised, and produced by a signed hashing trick
over BLAKE2b — no learned model, no network, no seed to forget. It is
`SCHEMA_NAME`-class, recorded as such in `patterns.embedding_sensitivity`, excluded from
`patterns_safe`, and constrained so it can never be labelled `DATA_VALUE`.

### Measured

`tests/test_dedup.py`, 200 candidates of which 40 are duplicates by construction, scored
pairwise over every unordered pair:

| | |
|---|---|
| True positives | 40 |
| False positives | 0 |
| False negatives | 0 |
| **Precision** | **1.00** |
| **Recall** | **1.00** |

Reproduce with
`uv run pytest packages/godwit-store/tests/test_dedup.py -q`.

Both are 1.0 and they should be: dedup here is an exact key, not a similarity threshold,
so on a population whose ground truth is *defined* by that key there is nothing to trade
off. The value of the fixture is that the 160 distinct findings differ along four
different axes — segment value, column set, evidence kind, direction — and none of them
collided. Where the number would stop being 1.0 is in §10.

---

## 4. False-discovery control

Two independent controls, because neither is sufficient alone.

**Benjamini-Hochberg**, over a family declared per detector run. `HypothesisFamily`
carries `test_count` — how many hypotheses the detector *examined*, not how many
candidates it emitted — and that field is mandatory with no default. A count smaller
than the number of p-values supplied raises `UnboundedHypothesisFamilyError` rather than
being clamped: the more aggressively a detector prefilters, the more significant its
survivors look, and absorbing that would understate every q-value in the batch.
Unobserved tests are treated as `p = 1`, the conservative reading.

Both the raw `p` and the adjusted `q` are stored, always. The raw value is what the
detector claimed; the adjusted one is what it means.

**A holdout**, reserved before generation and never used to generate. A candidate that
does not reproduce there is `UNVALIDATED` and never reaches the operational queue,
whatever its q-value says. A run that reserved nothing produces `NOT_TESTED`, which is
*also* barred — "we did not look" is not evidence, and treating an absent holdout as a
pass would make the weakest run look like the strongest.

Matching against the holdout is by signature, not by score. Reproducing a finding weakly
is still reproducing it, and demanding a similar effect size would be re-testing on the
holdout, which is the thing a holdout exists to prevent.

### What is claimed, and what is not

| Claim | Status |
|---|---|
| FDR ≤ q over a fixed family of independent tests | tested (`test_pure_noise_rejects_at_most_the_target_rate`, 2000 trials, 3 Monte Carlo standard errors of slack) |
| Realised FDR ≤ q on a mixture of 20 real effects and 180 nulls | tested |
| All 20 real effects still found | tested |
| FDR ≤ q under **adaptive** probing | **not claimed.** See `CR-A3-fdr-hypothesis-space.md` |

The last row is the weakest part of this package and it is somebody's decision, not an
implementation gap. A bandit changes the size of the family as it goes *and* enriches it
with hypotheses selected for looking significant, which no post-hoc adjustment repairs.
The implemented fallback is a declared ceiling per snapshot
(`conservative_test_count`), and the change request lays out the three real options.

---

## 5. Lifecycle

```
                      ┌──────────────► DUPLICATE  (terminal)
                      │
   ┌──────────► PROPOSED ◄──────────┐
   │            │  │  │             │
   │            │  │  └──► SUPPRESSED
   │            │  └─────► REJECTED ─┘
   │            └────────► CONFIRMED ──► EXPLAINED_AWAY
   │                           │              │
   └──────── EXPIRED ◄─────────┴──────────────┘
```

Every transition is checked against `ALLOWED_TRANSITIONS`, requires the evidence in
`REQUIRED_EVIDENCE`, and appends a row to the hash-chained audit ledger recording who
moved it, when, from what and to what.

| Destination | Requires |
|---|---|
| `CONFIRMED` | a `feedback_id` |
| `REJECTED` | a `feedback_id` |
| `EXPLAINED_AWAY` | a `context_ref` from L3 |
| `DUPLICATE` | the `duplicate_of` pattern id |
| `SUPPRESSED` | an actor and a reason |
| `EXPIRED` | a window count |
| `PROPOSED` | a candidate or a reason |

"Confirmed by whom?" is the first question in a model risk review, and a state machine
that accepts a confirmation with nothing behind it answers it with a shrug.

**`DUPLICATE` is the only terminal state.** Findings recur and reviewers change their
minds, so `EXPIRED` and `REJECTED` both lead back to `PROPOSED` *with evidence* — neither
is a quiet undo. A pattern that turned out to be another pattern has handed over its
evidence and has nothing of its own left.

**Staleness is counted in detector runs, not in days.** A source probed hourly and one
probed weekly must not age at the same rate because a clock ticked; it is also why
nothing on this path reads one. Three unsupported windows (`DEFAULT_STALE_WINDOWS`) and
a pattern expires. It is not deleted: a seasonal pattern that returns moves back to
`PROPOSED` and keeps its id, its history and its feedback. That is the difference between
a store and a cache.

The contract has no `STALE`; `EXPIRED` is used and the distinction is carried by the
audit event's `action` (`expire_stale`). See `CR-A3-lifecycle-has-no-stale.md`.

**A rejection also suppresses the signature.** Dismissing a finding should silence the
instance of it that next week's snapshot produces, not just this one. Suppression is by
signature, recorded, and reversible with `unsuppress`; the row is updated rather than
deleted, so "who silenced this, when, and who turned it back on" stays answerable.

---

## 6. Reproduction — the regulator-facing capability

> *"You alerted on this in March. Show me that the same data and the same code produce
> the same finding today."*

`reproduce(session, pattern_id)` returns a `ReproductionRequest` carrying every probe
key, both snapshot ids, the detector and its version, the code version and the seed —
for every distinct key behind the pattern, not just the representative.
`verify_reproduction` grades what comes back.

The split is deliberate: the store defines the request and holds the expected answer,
the data plane executes it (A4), and the grading happens in the control plane. That is
the only arrangement in which a regulator's question is answerable without a row
crossing the boundary.

Comparison is over canonical JSON — identity, not similarity. A candidate that came back
*almost* the same is reported separately from one that disappeared, because it means the
pipeline is not deterministic, which is a harder problem and a much worse answer to
give.

Nothing an LLM produced is in the key. Delete every explanation in the system and it is
unchanged: invariant 7, as a checkable statement.

---

## 7. The label ledger

Every leakage bug in supervised learning is, underneath, someone reading a label that
did not exist yet.

`LabelLedger.visible_as_of(instant=..., entity_type=...)` takes `instant` **keyword-only,
with no default**. There is no `all()`, no `latest()`, no `labels` property and no
`as_of=None` meaning "now". Every read path in the module — rows, counts, the per-entity
lookup, the `LabelSet` builder — filters on `label_time <= instant`, because a leak needs
only one unfiltered route.

`tests/test_labels.py` attacks it along six routes, in the order somebody reaches for
them when the first is inconvenient: the listing, the per-entity lookup (the one that
tempts an implementation into ordering before filtering), the aggregate, the `LabelSet`
builder, the contract filter on what came back, and the coverage query. All six hold.
A seventh test asserts the *signatures* — keyword-only, no default — rather than the
behaviour, because that is what makes writing the bug impossible rather than merely
discouraged.

**Coverage is a different question from visibility.** Visibility asks "did we know this
on that date". Coverage asks "was this population exhaustively labelled over that
window", and it is what distinguishes an unlabelled entity that is a negative from one
that is unknown. `assert_covered` refuses to let a metric be computed over an uncovered
region — those are not conservative estimates, they are numbers about a population
nobody promised to have labelled. Two adjacent windows with a gap between them do not
cover the period, and are not stitched together.

`entity_key` is a BLAKE2b pseudonym of the entity id, so a plain identifier does not sit
in an index every query touches. **A pseudonym, not an anonymisation**: over a small or
guessable id space it is enumerable in seconds, exactly as `SegmentKey` is. Unsalted,
because two independently written processes must produce the same key or the ledger
cannot be joined.

`patterns.confirmations` and `patterns.rejections` are **reviewer agreement, not
precision.** The 90-day reconciliation the objective function asks for has no contract;
see `CR-A3-label-reconciliation-has-no-contract.md`.

---

## 8. The ledgers, and what "append-only" is worth

`audit_events` and `egress_records` support INSERT and SELECT. Three layers stop
anything else, each covering a hole in the next:

| Layer | Stops | Does not stop |
|---|---|---|
| Grants (`REVOKE UPDATE, DELETE, TRUNCATE`) | the application role | the table's owner, who holds every privilege implicitly |
| A refusing trigger | the owner, and a hand-typed `DELETE` | a superuser, who can disable it |
| The hash chain | nothing — but makes any of the above **evident** | somebody who rebuilds every subsequent hash |

Tamper-**evident**, not tamper-proof, and the docs say so rather than implying otherwise.
What makes rebuilding expensive is verifying from outside: export the head hash, sign
it, keep it somewhere the database cannot reach. `verify_chain` names the first sequence
number that does not reconcile; `tests/test_ledger.py` drops the triggers, tampers, and
asserts it is caught.

The deployment property the layers imply: **the ledgers' owner must not be the role the
service connects as, and the superuser must not be a person.**

### The query a bank asks for

```python
sent = egress_query(session, destination="llm_provider")
print(export_egress(sent))
```

*"Show me everything you ever sent to a model provider"*, answered exactly, in one
query, in front of them. The export is newline-delimited canonical JSON — grep-able, and
byte-identical between two exports of the same rows, so it can be diffed or signed.
Every field in it is a name, a hash, a count or a decision, which is what makes handing
the file over not itself an egress.

---

## 9. Model registry metadata

Invariant 3 is enforced three times over, and each mechanism is tested on its own:

1. **The type.** `Deployment.model` is a `DeployableModel`, produced only by
   `certify_deployable`, which has no `force` and no `skip_audit`.
2. **A check constraint.** `model_artifacts.deployable` cannot be true unless
   `audit_passed` is true. The test that pins this runs raw SQL — it is the query a
   well-meaning operator runs at two in the morning to unblock a release.
3. **A composite foreign key.** `deployments(artifact_id, artifact_deployable)`
   references `model_artifacts(artifact_id, deployable)`, with
   `CHECK (artifact_deployable)`. An artifact whose audit failed has **no row a
   deployment could point at**. Delete every line of Python in `registry.py` and the
   database still refuses it.

Mechanism 3 catches the case the type system cannot: an artifact certified earlier and
re-audited since at different bytes, while a `DeployableModel` minted before that still
exists in some caller's memory.

An audit is bound to bytes. Re-train and the old verdict means nothing: the audit is
still stored — it is a fact about *something* — but the artifact stays undeployable,
because what was audited is not what would ship.

Artifacts are content-addressed. Registering the same digest under a second id is
refused, because two ids for one digest would let an audit on one appear to cover the
other.

---

## 10. Known limits

**Dedup is exact, so near-duplicates are not merged.** A segment that gained one
predicate, or the same divergence in an adjacent time bucket, is a different signature
and gets its own pattern. The golden fixture contains an instance: `country = PT` and
`country = PT AND status = refund` are two patterns, and a human would probably call
them one story. This is the conservative side of the trade — showing a reviewer two
related findings is recoverable, merging two different ones is a silent loss — and it is
what the embedding and `dedup_group` exist to mitigate in a UI rather than in the merge
rule.

**FDR under adaptive probing is not controlled.** §4 and
`CR-A3-fdr-hypothesis-space.md`. This is the most important limit in the package.

**90-day reconciliation is not modelled.** §7 and
`CR-A3-label-reconciliation-has-no-contract.md`. `confirmations`/`rejections` measure
reviewer agreement and must not be reported as precision.

**The hash chain is serial.** One writer per chain. On Postgres a transaction-scoped
advisory lock serialises them and the unique `seq` constraint is the backstop that turns
a missed lock into a refused write rather than a forked chain. Throughput is one ledger
append per transaction; if that becomes the bottleneck, the fix is batching appends, not
removing the lock.

**Similarity search is Postgres-only.** The ivfflat index is created by the migration on
Postgres. On SQLite the vector is a JSON array and `cosine` computes similarity in
Python — fine for tests, not fine for a queue.

**Ranking weights are judgements, not fits.** Nothing in `RankingWeights` was fitted to
data. They are exposed as data so a deployment that measures its own precision can
adjust them deliberately rather than by editing code.

**The ancestor lookup takes the most recent match.** A shape with several concurrent
patterns links the newest one, not the most similar. With `structure_key` equality as
the filter that is usually the same thing; where it is not, the link is a hint for a
human rather than an assertion.

**No benchmark script.** The dedup and FDR numbers in §3 and §4 are produced by the test
suite and recorded here. A separate benchmark harness would be a second copy of the same
fixture to keep in step, which is a cost with no reader.

---

## 11. Using it

```python
from godwit_store import (
    HoldoutKind,
    HoldoutPolicy,
    HypothesisFamily,
    PatternStore,
    bootstrap_schema,
    create_store_engine,
    session_factory,
)

engine = create_store_engine("postgresql+psycopg://godwit@localhost/godwit")
bootstrap_schema(engine)  # tests and throwaway databases; production uses Alembic

with session_factory(engine)() as session:
    store = PatternStore(session)
    report = store.ingest_batch(
        family=HypothesisFamily(
            run_id=run_id,
            snapshot_id=snapshot_id,
            detector="segment_divergence",
            detector_version=1,
            test_count=10_000,  # hypotheses EXAMINED, not candidates emitted
            q_target=0.10,
            declared_at=now,
        ),
        candidates=candidates,
        holdout=HoldoutPolicy(kind=HoldoutKind.TIME_SLICE, time_from=a, time_to=b),
        holdout_candidates=reserved_slice_candidates,
        at=now,
    )
    session.commit()

    queue = store.queue(queue=AlertQueue.OPERATIONAL, at=now, capacity=50)
```

Migrations:

```sh
export GODWIT_STORE_URL=postgresql+psycopg://godwit@localhost/godwit
export GODWIT_STORE_ROLE=godwit_service      # optional; names the role in the grants
uv run alembic -c packages/godwit-store/alembic.ini upgrade head
```

The URL is never in `alembic.ini`: a connection string in a file in the repository is a
credential in the repository.

The initial migration calls `Base.metadata.create_all` rather than listing 27 tables, so
there is exactly one definition of the schema.
`tests/test_migration.py::test_the_migration_and_the_metadata_agree` runs the real
migration against a real file database and compares tables, views, indexes and triggers
with what `bootstrap_schema` produces. Later revisions are ordinary autogenerated
`op.add_column` migrations.
