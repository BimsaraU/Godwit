# Godwit — architecture

Read this before you write a line in any package. It is the shared context for twenty
agents who cannot talk to each other.

Written by A0. If something here is wrong, missing or impossible, **do not fix it in
place**: write `docs/change-requests/CR-<your-id>-<slug>.md`, implement against the
contract exactly as written, and leave an `xfail` test showing what you needed.

---

## 1. What this is

Two capabilities on one substrate.

**Discovery** finds emerging patterns nobody asked it to look for — payment fraud,
churn, silent data-quality collapse, novel abuse — by watching the *statistics* of
tables change over time rather than by scanning rows.

**Prediction** takes a partially labelled dataset, works out what the labels mean, and
predicts the rest, producing a deployable, versioned prediction engine.

They are one product because of a single idea:

> **A discovered pattern is a feature.**

The segment divergences, graph anomalies and heavy-hitter shifts the detectors find are
exactly what a human would hand-engineer into a fraud model. Discovery feeds the feature
factory, which feeds the prediction engine, whose residuals feed discovery again.

The name is from the bird: a godwit works a mudflat by pushing a long, nerve-rich bill
into water it cannot see through, finding prey by touch. It moves nothing and it is told
nothing. It is a codename; replace it freely.

---

## 2. The control plane / data plane boundary

This split is load-bearing. Get it wrong and the product is unsellable to a bank.

```
                     ┌──────────────────────── CONTROL PLANE ────────────────────────┐
                     │  orchestrator · pattern store · Vision Board · LLM layer       │
                     │  model registry metadata · detectors · context                 │
                     │                                                                │
                     │  Sees: sketches, gated statistics, metrics, artifact metadata  │
                     │  Never sees: a row                                             │
                     └───────────────────────────────▲────────────────────────────────┘
                                                     │
                            ╔════════════════════════╪════════════════════════╗
                            ║      godwit-guard — THE EGRESS GATE             ║
                            ║  classify · redact · tokenise · audit · deny    ║
                            ╚════════════════════════▲════════════════════════╝
                                                     │
                     ┌───────────────────────────────┴────────────────────────────────┐
                     │  probe workers · feature computation · training · inference    │
                     │  the tokenisation map                                          │
                     │                                                                │
                     │  Reads rows in place. Emits gated artifacts only.              │
                     └──────────────────────── DATA PLANE ────────────────────────────┘
```

**Compute goes to the data. The data never moves.**

### Exactly what crosses, upward

| Crosses | Type | Notes |
|---|---|---|
| Sketch envelopes | `SketchEnvelope` | Opaque payload. Count-Min and frequent-items envelopes carry `DATA_VALUE` and are gated before display. |
| Column profiles | `ColumnProfile` | Contains manifest bounds and most-common-values. **These are row values.** Tainted. |
| Aggregated statistics | `Tainted[float]` as `DERIVED_STATISTIC` | Counts, moments, p-values, effect sizes. |
| Segments | `Segment` | Predicates quote real values. Tainted throughout. |
| Cost actually spent | `CostSpend` | Numbers only. |
| Model artifact **metadata** | `ModelArtifact` | The bytes stay in object storage inside the perimeter; the metadata and the audit cross. |
| Feature matrix **handle** | `FeatureMatrixRef` | A URI and a row count. Never the values. |
| Prediction records | `Prediction` | Entity ids and attributions are tainted. |

### What never crosses, in either direction

Rows. Cursors. Result sets. Driver objects. Exception objects from a database driver.
Raw feature values. The tokenisation map. "A few rows for debugging". Ever.

### What crosses outward, to an LLM, a UI, an alert, a log or an export

Exactly one type: `SafePayload`, produced by `godwit-guard` and by nothing else, and
only after an `EgressRecord` has been written.

---

## 3. The seven invariants, and what each one costs you in code

### 1. No raw rows leave the perimeter

Feature computation, training and inference run in the data plane.

*Code-level consequence.* No protocol in `godwit_contracts.protocols` has a method that
returns rows. `SourceAdapter` returns profiles, snapshots and sketch bundles.
`FeatureComputer` returns a `FeatureMatrixRef` — a URI, a row count and a digest —
never a frame. If you find yourself wanting a `fetch_sample()` for debugging, that is a
contract change, and the answer is no.

### 2. Everything data-derived is typed as such and denied by default

*Code-level consequence.* `Tainted[T]` is a wrapper, not a subclass. `Tainted[str]` is
not a `str`, and mypy rejects passing one where a `str` is expected — there is a test
that proves it (`test_static_typing.py`). `__repr__` and `__str__` render a label, never
the value, so an accidental f-string in a log line leaks
`<tainted data_value via pg_stats_mcv from customer_ssn>` instead of an SSN. The only
way out is `.reveal()`, which is greppable, and which is legitimate only inside the data
plane or inside the gate.

`Provenance.acquisition` records *how* a value was obtained, and
`ACQUISITION_MINIMUM_SENSITIVITY` is a validated floor: you cannot label an Iceberg
manifest bound as a derived statistic. Upgrading a value's sensitivity is always
allowed; downgrading is a validation error.

### 3. Model artifacts are audited for memorisation before they cross

A model can memorise its training rows. Target encoding on a high-cardinality column
bakes identifiers straight into the artifact. An unaudited artifact is a data leak
wearing a hat.

*Code-level consequence.* `Deployment.model` has type `DeployableModel`, not
`ModelArtifact`. `DeployableModel` is produced only by `certify_deployable()`, which
refuses without a passing `MemorisationAudit` at the artifact's own digest, and which
has no `force`, no `skip_audit` and no override parameter. `audit_passed` is typed
`Literal[True]`, so a *failed* deployable is not a representable value — it will not
construct and it will not parse from JSON. `MemorisationAudit.passed` is validated to
equal the conjunction of its checks, and `REQUIRED_MEMORISATION_CHECKS` must all be
present, so an incomplete audit is not a quiet way to skip one.

### 4. LLM cost scales with hypotheses, not data volume

*Code-level consequence.* `LLMAdapter.complete()` takes one `SafePayload` and one
`CostBudget`. There is no batch method that takes rows, and no adapter should ever loop
over a dataset. An LLM names, explains, ranks and proposes where to look next. It never
scans.

### 5. Metadata first

Any signal obtainable from catalog metadata must be obtained there. Paid scans are spent
only where metadata already flagged something.

*Code-level consequence.* `ProbeKind.COLUMN_BOUNDS`, `ROW_COUNT` and `FRESHNESS` are
answerable from a catalog with no table scan. `SourceAdapter.profile_table` takes a
budget and must not scan unless that budget allows it. The orchestrator's job (L4) is to
spend scans where the free tier already pointed.

The trap: the free tier reads manifest bounds, and **manifest bounds are row values**.
Cheap is not the same as safe.

### 6. Every sketch is a mergeable monoid

`merge(a, b)` associative and commutative, with an identity and a documented error
bound. This is what lets batch and streaming run identical code.

*Code-level consequence.* The `Sketch` protocol states seven laws; laws 1–3 are
mathematical claims and owe **property tests** (hypothesis), not example tests. Merging
sketches with different construction parameters must *raise*, never silently produce a
wrong answer. `SketchEnvelope.error_bound` is mandatory.

Related: `CostBudget.compose()` is a field-wise minimum — a meet — which is associative,
commutative and idempotent, and can only ever tighten a budget. That is what makes it
safe to hand a nested budget to code you did not write.

### 7. The LLM is out of the detection and prediction paths

Every pattern and prediction must be reproducible from (probe spec, snapshot id,
version, seed) with the whole LLM layer deleted. The reason is auditability in regulated
industries, not cost.

*Code-level consequence.* `Lineage` carries exactly that tuple and is mandatory on every
`Candidate`. `Explanation` is a separate model attached to a `Pattern` after the fact;
deleting every explanation in the system changes no pattern and no prediction.
`Detector` takes sketches and a seed and returns candidates — it has no network and no
LLM. `ProbeSpec.seed` has no default, because a default seed is an unseeded run wearing
a hat, and `ProbeSpec.as_of` is injected because nothing reads a clock.

---

## 4. The leak paths — memorise this list

Several things we casually call "metadata" literally contain row values. If you touch
any of these, you are handling customer data and invariant 2 applies to you.

| # | Path | Why it is a leak | `Acquisition` |
|---|---|---|---|
| 1 | Iceberg manifest min/max **bounds** | The min and max of a name column are two real names. Of an email column, two real emails. Our entire free metadata tier reads these. | `ICEBERG_MANIFEST_BOUNDS` |
| 2 | `pg_stats.most_common_vals` | Literally the most common actual values in the column. | `PG_STATS_MCV` |
| 3 | Count-Min **heavy hitters** | On an identifier column the heavy hitters *are* the PII. | `COUNT_MIN_HEAVY_HITTER` |
| 4 | **Segment predicates** | A `Segment` is `(column, operator, VALUE)` and that value is real data. Segments travel inside every candidate, pattern and alert. | `SEGMENT_PREDICATE` |
| 5 | Category histograms below the cardinality threshold | They store exact category values. | `CATEGORY_HISTOGRAM` |
| 6 | **Small cells** | "Segment X (n=3) is anomalous" re-identifies without quoting any value. | — (population, not a value) |
| 7 | Quantiles over a small population | The median salary of a twelve-person team. | `QUANTILE` |
| 8 | Derived **feature names** | `is_merchant_ACME_CORP` surfaces in SHAP output, importance tables and model cards. | `DERIVED_FEATURE_NAME` |
| 9 | **Column and table names** | `patient_hiv_status`, `customer_ssn`, `salary_2024`. Disclosive before a single row is read. | `CATALOG_IDENTIFIER` |
| 10 | Driver **exception messages** | They routinely contain the offending row. | `DRIVER_EXCEPTION` |

> **A regex or NER scanner at the boundary catches almost none of these.** The control
> is the typed taint plus the gate. Scanning — Presidio — is a backstop and must never
> be described, documented or demoed as the control. If a scanner is the only thing that
> stopped a value, that is a bug in the taint typing, and it must be reported as one.

`tests/golden/pii_torture/` contains all ten in one table, with
`expected_leaks.json` listing every string that must never appear in any egress
artifact. Every package should test its own leak paths against it.

---

## 5. Layer map and ownership

| Layer | What it does | Package | Owner | Plane |
|---|---|---|---|---|
| L-1 | Metadata detectors: free signals from catalogs, no table scan | `godwit-source` | A1 | data |
| L0 | Semantic catalog: per-column profile, role, join graph, PII class | `godwit-source` | A1 | data |
| L1 | Probes: data-plane workers running a `ProbeSpec` → `SketchBundle` | `godwit-probe`, `godwit-sketch` | A6, A2 | data |
| L2 | Detectors: drift statistics and unsupervised scoring over sketches | `godwit-detect` | A7 | control |
| L3 | Context: the explained-away layer — deploys, campaigns, holidays, DQ failures | `godwit-context` | A8 | control |
| L4 | Orchestrator: belief state, budgeted bandit allocation over the probe space | `godwit-orchestrator` | A10 | control |
| L5 | Pattern store: pattern, evidence, lineage, lifecycle, dedup, FDR control | `godwit-store` | A3 | control |
| L6 | Feature factory: entity, graph and time features, plus patterns as features | `godwit-features` | A11 | data |
| L7 | Prediction engine: semi-supervised training, model search, calibration, evaluation | `godwit-predict` | A13 | data |
| L8 | Serving: artifact registry, provisioning, shadow deploy, drift, rollback | `godwit-serve` | A14 | data |
| L9 | LLM layer: naming, explanation, ranking, hypothesis proposal | `godwit-llm` | A15 | control |
| L10 | Vision Board: datasources, dashboards, guardrails, actions | `godwit-vision` | A16 | control |
| — | Deterministic replay from lineage | `godwit-replay` | A4 | control |
| — | Subtractor: removes already-explained signal so detectors see the residual | `godwit-subtractor` | A12 | control |
| GATE | Classification, redaction, tokenisation, egress audit | `godwit-guard` | A5 | boundary |
| SDK | Public extension surface | `godwit-sdk` | A9 | both |
| — | Contracts: types, taint, protocols | `godwit-contracts` | A0 | both |
| UI | Vision Board front end | `apps/vision-board` | A17 | control (browser) |

---

## 6. The loop

```
   metadata (free)          L-1/L0   ──────────┐
        │                                      │
        ▼                                      │
   probe space  ──► L4 orchestrator ──► L1 probes ──► sketches
                         ▲                                 │
                         │                                 ▼
                    belief state                      L2 detectors
                         │                                 │
                         │                                 ▼
                         │                          candidates
                         │                                 │
                         │                                 ▼
                    L3 context ──── explains away ──► L5 pattern store
                         │                                 │
                         │                         confirmed patterns
                         │                                 │
                         │                                 ▼
                         │                          L6 feature factory
                         │                                 │
                         │                  "a discovered pattern is a feature"
                         │                                 │
                         │                                 ▼
                         │                          L7 prediction engine
                         │                                 │
                         └────── residual structure ◄──────┘
                                 (L12 subtractor removes
                                  what is already explained)
```

Concretely: a confirmed `Pattern` becomes a `FeatureSpec` with
`kind=PATTERN_INDICATOR` and `derived_from_pattern` set. A trained model's residuals are
probed like any other column, and structure found there arrives back as `Evidence` with
`kind=RESIDUAL_STRUCTURE`.

The subtractor exists so detectors do not keep rediscovering the same Black Friday.

---

## 7. Objective function

**Discovery.** Precision@k where *k* is human review capacity, after label
reconciliation; and dollars per human-confirmed pattern. Two queues:

| Queue | Volume | Target |
|---|---|---|
| `OPERATIONAL` | ~50 alerts/day | precision ≥ 30% after 90-day reconciliation |
| `DISCOVERY` | ~5 items/week | ≥ 1 confirmed-novel pattern per month |

**Prediction.** On a half-labelled dataset with no human in the loop, land within
**0.02 AUC** of a tuned expert baseline. On IEEE-CIS that is roughly 0.92–0.94 against a
competent hand-built baseline near 0.90.

Be honest about what that claim is: **parity with a good data scientist working for a
week, not parity with a mature in-house system** carrying years of consortium data,
device intelligence and investigator feedback. Never claim the latter. It will be
tested. `EvaluationReport.baseline_note` exists so that the claim is written down next
to the number.

`tests/golden/classification/meta.json` carries `bayes_auc` — the AUC of the true
generating probabilities — and `target_auc = bayes_auc - 0.02`. Scoring *above*
`bayes_auc` means the generating process leaked, not that the model is good.

---

## 8. Conventions every package follows

**Taint.** If a field can hold a value read out of, or computed from the contents of, a
customer row, its type is `Tainted[...]`. If a field's type does not say whether it is
safe, the field is wrong. Customer table and column names are `Tainted[str]` with
`SCHEMA_NAME`; our own identifiers (`SourceId`, `PatternId`, catalog handles) are plain.

**Identifiers.** `NewType` over `str`, because a `PatternId` where a `SourceId` belongs
is a real bug. `Version` is a plain `int` alias, because a version where another version
belongs is not.

**Determinism.** No wall-clock reads, no unseeded randomness, anywhere on a path that
can produce a pattern or a prediction. Time is injected (`Instant`, always tz-aware,
normalised to UTC; naive datetimes are rejected at validation). Seeds are explicit and
have no defaults.

**Budgets.** Anything that can issue a billable query or a training run takes a
`CostBudget` and refuses rather than exceeds it. **Refusing is a normal outcome, not an
error.** `TrainingStatus.REFUSED_BUDGET` exists for exactly this. Catch
`BudgetExceededError`, record the refusal, stop.

**Keys.** `segment_key` and `probe_key` are specified character by character in the
`godwit_contracts.segment` and `godwit_contracts.probe` module docstrings, and pinned by
`tests/golden/segment_key_vectors.json`. Two agents who cannot talk to each other must
produce the same key. If your implementation disagrees with a vector, your
implementation is wrong.

**Errors.** Never propagate a driver exception. Catch it, classify it, and raise your
own message. `TrainingRun.failure_reason` is documented as "our own message, never a
driver exception" for this reason.

**Tests.** Unit tests for logic, at least one against `tests/golden/`, and property
tests (hypothesis) for anything claiming a mathematical property.

---

## 9. Open questions I could not resolve

These are genuinely unresolved. A human decides. Do not guess and do not silently pick
one — if your package forces the issue, file a change request.

1. **`SafePayload` is unforgeable by ordinary code, not by hostile in-process code.**
   Construction is refused, subclassing is refused, copy and pickle are refused, and the
   contents live in a module-private `WeakKeyDictionary` so a shell built with
   `object.__new__` is inert. But `ctypes`, a debugger or a monkeypatched module can
   still reach in, and `claim_safe_payload_issuer()` is single-holder rather than
   cryptographically bound to `godwit-guard` — the contracts tests claim it themselves,
   which is how you know. If the threat model includes hostile code running *inside* the
   control plane, this needs process separation, not a Python type. **Someone has to
   decide whether that threat model applies.**

2. **`Provenance` is disclosive and is not itself `Tainted`.** It names customer tables
   and columns, which is leak path 9, but making it `Tainted[Provenance]` would make
   every tainted value doubly wrapped and every call site unreadable. It is currently
   documented as SCHEMA_NAME-class and gated as part of whatever carries it. That is a
   judgement call and it may be the wrong one.

3. **`SegmentKey` is a pseudonym, not an anonymisation.** It is BLAKE2b over the
   canonical form. For a low-cardinality domain — `country = 'US'` — the key is
   trivially brute-forced by anyone who can guess the domain. It is typed as a plain
   `NewType` string rather than `Tainted`, because it is a join key used everywhere.
   **A5 must decide** whether guardrails treat a `SegmentKey` as `DATA_VALUE` when the
   population behind it is small, and whether keys need a per-tenant salt (which would
   break cross-tenant dedup).

4. **`ProbeSpec.snapshot` may be `None` at scheduling time.** The orchestrator schedules
   before knowing which snapshot will be current when the probe runs. The worker records
   the resolved snapshot in the `SketchBundle`, and replay uses that. This is a hole in
   "determinism from the spec alone" and A4 and A10 must agree on how the orchestrator
   stores the resolution.

5. **Sketch payload codecs are not specified.** Contracts define the envelope; A2 owns
   the bytes. The golden fixture ships opaque placeholder payloads for KLL and Count-Min
   so that downstream can agree on the *shape* now. **A2 must replace them** and must
   decide the forward-compatibility rule: the pattern store will hold envelopes written
   by older versions indefinitely.

6. **Where FDR control is applied is stated but not designed.** L5 applies
   Benjamini-Hochberg over the whole hypothesis space of a snapshot. What counts as "the
   whole hypothesis space" when the orchestrator is adaptively choosing probes — a
   bandit changes the number of tests as it goes — is a real statistical problem I have
   not solved. A3 and A10 need a shared answer, and the honest fallback is a
   conservative fixed hypothesis count per snapshot.

7. **Label reconciliation over 90 days is in the objective but has no contract.**
   `Label` carries `event_time` and `label_time` and `LabelSet` carries a
   `CoverageScope`, which is enough to *measure* precision after the fact. The process
   that goes back and re-scores a 90-day-old alert queue is not modelled. Whoever owns
   the operational queue needs it.

8. **The `Segment` vocabulary is closed and probably too small.** Twelve operators, no
   disjunction, no nesting. A detector that finds "high amount in PT *or* ES" must emit
   two segments. Adding an operator changes every `segment_key` in the store, so it is a
   migration, not a patch. I chose the small set deliberately; someone will need more.

9. **Streaming is claimed but not exercised.** Invariant 6 says the monoid laws let
   batch and streaming run identical code. Nothing in this scaffold runs a stream. The
   claim is untested until someone builds one.

10. **Multi-tenancy is absent.** There is no tenant id in any contract model.
    `SourceId` is global. If two customers' data is ever in one control plane, every key,
    every dedup group and every guardrail scope needs a tenant dimension, and retrofitting
    that is a migration across every package. **This is the single most expensive open
    question here.** It was out of scope for the brief, and it should be answered before
    A3 writes a schema.
