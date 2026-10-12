# godwit-probe

**Owner:** A6 · **Layer:** L1 (probes) · **Plane: DATA**

> **This package runs in the DATA PLANE.** It reads customer rows in place. What it
> emits -- sketch bundles, outcomes, log lines, spans, metric labels, job rows, exceptions
> -- is something a bank's security team will read line by line, and it is built so that
> none of it carries a row value. Invariant 1 is enforced here: no raw row leaves this
> package, not in a result, not in a log, not in an exception, not in a trace.

A probe worker takes a `ProbeSpec`, executes it against a source, and returns a
`SketchBundle` -- or a refusal, or "nothing changed", or a cancellation, each with its
cost. It is stateless, cancellable and budget-bound. It decides nothing about *what* to
probe (that is A10) and detects nothing (that is A7).

---

## 1. The package in one screen

```python
from godwit_probe import ProbeExecutor, MemoryProbeState, IcebergProbeSource, ProbeKeyring

executor = ProbeExecutor(
    IcebergProbeSource(catalog),  # metadata reads + metered data reads
    access=control.mode_map(guardrails=rails, at=now),  # godwit_guard.AccessControl
    state=MemoryProbeState(),  # "since the last probed snapshot"
    keyring=ProbeKeyring(column_key=k1, sketch_key=k2),  # OPAQUE columns; from your KMS
    guardrails=rails,
)
outcome = executor.execute(spec, budget=budget)
outcome.status  # COMPLETED | NO_CHANGE | REFUSED | CANCELLED
outcome.bundle  # a SketchBundle when COMPLETED
outcome.refusal  # why not, by reason and column *position*, with the estimate
outcome.cost_spent  # what it actually read
```

| Module | What it does |
|---|---|
| `executor.py` | `ProbeExecutor`, `ProbeOutcome`, cancellation tokens, the cost model. The seven steps below. |
| `plan.py` | Access modes as a planning constraint. `ProbeSpec` → SQL with bound parameters, or a `Refusal`. |
| `engine.py` | DuckDB over a stream of Arrow batches, with the OPAQUE keyed-hash functions registered. |
| `accumulate.py` | Feeding result batches into `godwit_sketch` classes, one batch at a time. |
| `source.py` | The `ProbeSource` protocol (metadata vs data split) and `IcebergProbeSource`. |
| `state.py` | The last snapshot each probe key covered. |
| `stream.py` | Catalog polling (`CatalogPoller`), `backfill`, and `SketchSeries` over `TimeHierarchy`. |
| `worker.py` | The Postgres jobs table: SKIP LOCKED claims, leases, idempotent writes, per-source limits. |
| `errors.py` | The only exceptions that leave the package, and the boundary that strips driver text. |
| `telemetry.py` | The only emitter of logs, spans and metrics; typed so a customer value does not fit. |
| `keyring.py` | The two data-plane keys behind OPAQUE columns. |
| `testing.py` | **Public.** The probe simulator: a synthetic source with known statistics. |

---

## 2. What one `execute()` call does, in order

1. **Resolve** the end snapshot (argument, `spec.snapshot`, or the newest) and the start:
   the last snapshot this probe key covered (`INCREMENTAL`, the default) or none (`FULL`).
   The resolved snapshot is always recorded on the outcome -- `ProbeSpec.snapshot` may be
   `None` at scheduling time.
2. **Stop if nothing changed.** Same snapshot: one catalog read, zero bytes, `NO_CHANGE`.
   A compaction-only commit (`replace`): `NO_CHANGE` after one manifest walk.
3. **List the delta** from manifests: the data files added in `(since, until]`. A delete
   or overwrite in the range cannot be subtracted from a sketch, so the probe re-measures
   the whole snapshot and sets `full_rescan`.
4. **Plan** against the access modes. An unsatisfiable spec is `REFUSED` with a reason.
5. **Estimate** from manifest column sizes and **refuse** if `CostBudget.compose(budget,
   spec.budget)` cannot afford it -- *before a single data byte is read*. The refusal
   carries the estimate so A10 learns what the probe would have cost.
6. **Execute** file by file, batch by batch, into sketches. Between batches: check the
   cancel token and the actual bytes against the budget.
7. **Serialise** into a `SketchBundle`. Every field is a function of (spec, since, until,
   data): `produced_at` is the snapshot's commit instant, `bundle_id` hashes (probe key,
   since, until, seed). Nothing reads a clock.

The executor does **not** advance the incremental state. Whoever persists the bundle does,
after it is durable (`ProbeOutcome.covers_snapshot` says when that is allowed). The worker
does it in the same transaction as the bundle write.

---

## 3. Access modes are a planning constraint

Every column's mode is resolved while the plan is built, from the guard's `AccessModeMap`.

| Mode | In the plan | Predicates | Sketches allowed |
|---|---|---|---|
| **BLIND** / unclassified | absent from projection, predicates and read list; a spec that needs it is **refused** | refused | none |
| **OPAQUE** | `godwit_opaque_<type>("col") AS "col__opaque"` -- a keyed HMAC computed by the engine | `=`, `<>`, `IN`, `NOT IN`, null tests, hash against hash; ranges refused | Theta, HLL, NullRate, Count-Min (hashed), GraphDegree (hashed) |
| **OPEN** | `"col" AS "col"` | any operator; values are **bound parameters**, never SQL text | all; value-bearing sketches on a `DIRECT_IDENTIFIER` store hashed keys unless a guardrail permits plain |

Three checks prove it rather than promise it:

* The emitted SQL is checked with `godwit_guard.verify_sql` against **every BLIND column
  of the table** before the plan is returned. Tests assert on the SQL text itself.
* The first batch the *source* hands over must contain only planned columns -- a BLIND
  column there means it was read, which is a defect even if the query ignored it.
* The first batch the *query* returns is checked with `godwit_guard.verify_arrow_schema`
  before any sketch sees a value.

**Honest limit:** the raw values of an OPAQUE column do exist, transiently, in the Arrow
batch read from the file and inside DuckDB before the hash is applied -- hashing needs the
input. They never exist in a result batch, a sketch, a log or an error.

### Plain heavy-hitter keys on identifiers

A value-bearing sketch over an OPAQUE column, or over an OPEN column classified
`DIRECT_IDENTIFIER`, stores keys hashed with `godwit_sketch.KeyHasher` in OPAQUE mode
(digests of digests for an OPAQUE column). Plain keys need an `ALLOW` guardrail that fires
for the column **and** names the purpose `probe.plain_keys` (`PLAIN_KEYS_PURPOSE`); a
generic ALLOW is not explicit permission, and any DENY / REDACT / REQUIRE_APPROVAL that
also fires wins. The permission is recorded on `ProbeOutcome.permissions`, per sketch --
the bundle cannot hold it (`CR-A6-sketch-bundle-cannot-say-why`).

A hashed sketch needs `entropy.bits >= 32` (godwit-sketch's floor), which is stricter than
the guard's 24 (`CR-A6-opaque-entropy-floors-disagree`).

### Refusal reasons

`budget`, `unsupported_probe`, `unknown_column`, `unclassified_column`, `blind_column`,
`opaque_operator`, `opaque_type`, `no_keyring`, `sketch_forbidden_for_mode`,
`sketch_type_mismatch`, `plain_keys_not_permitted`, `entropy_below_sketch_floor`,
`plan_verification`. A refusal names a column by its **position** in `spec.columns` or
`spec.segment.predicates`, never by name. `Refusal.explanation` is a fixed sentence.

---

## 4. What a probe measures

| `ProbeKind` | Default sketches (when `spec.sketches` is empty) |
|---|---|
| `ROW_COUNT` | `EXACT_COUNT` → `NullRate` over `count(*)`; over the universe segment, **from manifests, zero bytes** |
| `NULL_RATE` | `EXACT_COUNT` → `NullRate` |
| `DISTINCT_COUNT` | `THETA` |
| `QUANTILES` | `KLL` |
| `HEAVY_HITTERS` | `COUNT_MIN` |
| `CATEGORY_HISTOGRAM` | `FREQUENT_ITEMS` → `CategoryHistogram` |
| `GRAPH_DEGREE` | exactly two columns (source, target) → `GraphDegree` |
| `COLUMN_BOUNDS`, `FRESHNESS` | refused: metadata tier, use `godwit_source` |
| `SEGMENT_AGGREGATE`, `JOIN_CARDINALITY` | refused: need a join plan |

`EXACT_COUNT` means `NullRate` unless `spec.params["exact_count"] == "moments"`. Sketch
names in a bundle are `f"{kind}:{index}"` (index into `spec.columns`), `f"{kind}:table"`
for a row count, `"count_min:graph"` for a graph -- the same convention as godwit-source,
and never a column name. Each sketch class receives only its own parameters from
`spec.params` (`lg_k`, `k`, `cdf_grid`, `width`, `depth`, `capacity`, `seed`,
`max_exact_cardinality`); anything else stays out of the envelope, where it would become
merge identity.

---

## 5. Cost

| Charged | How it is estimated | How it is measured |
|---|---|---|
| `bytes_scanned` | per file: projected column-chunk sizes from the manifest + everything that is not a column chunk (footer, magic) | the source's instrument: `godwit_source.ByteMeter` for Iceberg, a byte counter in the simulator |
| `usd` | `CostModel(usd_per_gib)` over the estimate | the same model over the actual |
| `wall_seconds` | never charged: measuring it needs a clock (rule 5) | measure from outside |

The Iceberg reader reads each file's footer **by hand, to the byte**, then opens the
Parquet reader with that metadata and pre-buffering off. Left alone, pyarrow fetches the
last 64 KiB of every file to find the footer -- twenty times the projected column on the
golden fixture -- and the actual would exceed the estimate. With the footer supplied, the
actual is the footer plus the projected chunks: `test_golden.py` asserts
`0 < actual <= estimate < whole files` on a real table.

---

## 6. Streaming is catalog polling; batch is the same loop

`advance(executor, state, spec, budget=...)` walks the commits in `(last, newest]` one at
a time and runs the executor once per commit. `CatalogPoller.poll` calls it on the commit
cadence; `backfill` calls it once over history. It stops at the first run that does not
cover its snapshot (refusal, cancellation) so the state never skips a commit.

A poll with nothing new is one catalog read and zero data bytes. Data is never polled.

`SketchSeries` folds bundles into one `godwit_sketch.TimeHierarchy` per sketch name, at
each bundle's `produced_at`. The acceptance test publishes commits one at a time and polls
(streaming), backfills the same table in one call (batch), and asserts the bundles are
**byte-identical** and the series' `canonical_bytes()` equal; a hypothesis property does
the same for arbitrary commit sizes, poll schedules and batch sizes.

---

## 7. The worker runtime

Three tables, created by `JobQueue.create_schema()`:

| Table | Key | Holds |
|---|---|---|
| `godwit_probe_jobs` | `seq`, unique `job_id` (= `spec.probe_id`) | the spec JSON (**tainted**: segment values), budget, state, lease, attempts, `error_code` (an enum), cost |
| `godwit_probe_bundles` | `(probe_key, since_snapshot_id, snapshot_id)` | bundle JSON and outcome JSON |
| `godwit_probe_state` | `probe_key` | last covered snapshot |

* **Claims** use `SELECT ... FOR UPDATE SKIP LOCKED`; a claim is a lease.
* **At least once**: an expired lease is reclaimed. Bundle writes are `ON CONFLICT DO
  NOTHING` on the key above, and the state advances in the same transaction, so a re-run
  writes nothing new. Tested with a worker that stalls past its lease and completes late.
* **Cancellation**: `request_cancel` cancels a queued job outright, or flags a running one;
  the worker reads the flag at its next heartbeat (every `heartbeat_every` batches) and the
  probe stops at a batch boundary with its partial cost recorded.
* **Per-source concurrency**: a claim skips any source with `per_source_limit` live
  leases. On Postgres the count is taken under `pg_advisory_xact_lock(hashtext(source))`,
  so two pools cannot both win the last slot; on SQLite, `BEGIN IMMEDIATE` serialises all
  claims. Tested with two pools of three workers against one source limited to two.
* **Failures** are recorded by `ErrorCode` and retried until `max_attempts`.
* The **clock** (`SystemClock`) is the only wall-clock read in the package and decides only
  when a lease expires; tests inject a manual one.

Every database call is wrapped by the error boundary, because a SQLAlchemy error renders
its bound parameters -- which include the spec.

---

## 8. Leak prevention, implemented

| Path | Control | Proof |
|---|---|---|
| Exceptions | Everything from a dependency becomes `ProbeError(code, stage)`, built from two closed enums and raised **outside** the `except` block, so no `__context__` survives. | `test_leaks.py`: poisoned messages through RESOLVE, DELTA, SCHEMA, READ_OPEN, READ_MID (four exception types each), a real DuckDB conversion error quoting the predicate value, a failing keyed hash inside the engine, a failing sketch update, a failing serialisation, a store failure rendering bound parameters. |
| Logs | `ProbeTelemetry.event(Event, Mapping[Field, SafeValue])`; `SafeValue` has no `str`. Free-form ids go through `SafeId.of`, a hash. No row counts or populations are logged (small cells). Runtime re-check replaces anything else with `<refused>` and counts it. | `typing_cases/must_fail.py` run under mypy (7 expected errors); runtime smuggling test. |
| Spans | Same types; `record_exception=False`, `set_status_on_exception=False`; status description is an enum value. | Leak tests read every span name, attribute, status and event from an in-memory exporter. |
| Metric labels | enum members only (`status`, `kind`, `reason`). | Leak tests read every data point's attributes. |
| Job rows | `error_code` is an `ErrorCode`; no message column exists. | Worker leak test. |
| Bundles | OPAQUE columns reach sketches as digests; value-bearing sketches over them re-hash. | Leak and golden tests search raw payload bytes for identifiers and column digests. |

The string searches are a **backstop**. The controls are the closed vocabularies, the types
and the plan-time access modes. Four golden strings (`general`, `negative`, `positive`,
`unknown`) are excluded from the search because they are also ordinary English, and our own
hex identifiers are scrubbed before searching because a 32-digit hex digest contains a
five-digit salary often enough to matter -- the golden probe key does.

---

## 9. The simulator (`godwit_probe.testing`) -- for A7, A10, A11, A19

```python
from godwit_probe.testing import (
    Distribution,
    ProbeSimulator,
    SyntheticColumn,
    SyntheticCommit,
    SyntheticTable,
)
from godwit_guard import AccessMode

table = SyntheticTable(
    namespace="shop",
    name="orders",
    seed=1,
    columns=(
        SyntheticColumn(
            "country",
            Distribution.CATEGORICAL,
            categories=("US", "DE", "PT"),
            weights=(0.6, 0.37, 0.03),
        ),
        SyntheticColumn("amount", Distribution.LOGNORMAL, mean=3.2, sigma=0.7, null_fraction=0.05),
        SyntheticColumn("email", Distribution.IDENTIFIER, prefix="user-"),
    ),
    commits=(
        SyntheticCommit(rows=30_000),
        SyntheticCommit(
            rows=30_000,
            overrides={
                "country": SyntheticColumn(  # drift
                    "country",
                    Distribution.CATEGORICAL,
                    categories=("US", "DE", "PT"),
                    weights=(0.6, 0.22, 0.18),
                )
            },
        ),
    ),
)
sim = ProbeSimulator(
    table,
    modes={"country": AccessMode.OPEN, "amount": AccessMode.OPEN, "email": AccessMode.OPAQUE},
    visible_commits=1,
)
spec = sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["country"])
first = sim.run(spec)  # commit 0
sim.source.publish()  # a writer commits
second = sim.run(spec)  # commit 1 only: PT at ~18%
```

* It is the real executor, planner, engine and sketches over a synthetic source -- not a
  mock. Bundles are the same bytes production would produce for the same data.
* Values are a pure function of (seed, commit, file, block, column): identical whatever
  the batch size, column subset or visiting order.
* Ground truth: each column's parameters, `SyntheticColumn.probabilities()`,
  `SyntheticTable.rows_between(since, until)`, `column(name, commit)` with drift applied.
* Commits can append, overwrite (`DeltaKind.NON_ADDITIVE`) or compact
  (`NO_LOGICAL_CHANGE`).
* Instruments: `source.bytes_read`, `source.reads` (every file and column list opened),
  `source.metadata_calls`. `source.inject(FailurePoint.X, lambda: SomeError(...))` makes a
  call fail.
* `access_map(table_or_ref, modes, at=...)` builds a mode map; columns left out are
  unclassified. `simulator_keyring()` is deterministic and **for tests only**.

---

## 10. Benchmarks

Recorded on the reference machine (Windows 11, Python 3.12, DuckDB 1.5.6, pyarrow 25).

**Memory, `tests/test_memory.py`.** Each run is a fresh interpreter; the figure is the
process's peak working set (Python heap, Arrow and DuckDB together), batch 262,144 rows.

| Probe | Rows | Peak RSS | Wall | Bytes charged |
|---|---|---|---|---|
| null rate on a float column | 500,000 | 196.1 MB | 0.05 s | 4.0 MB |
| null rate on a float column | **100,000,000** | **193.8 MB** | 2.57 s | 800 MB |
| KLL + HLL on a float column | 100,000 | 196.0 MB | 0.46 s | 0.8 MB |
| KLL + HLL on a float column | 1,000,000 | 203.2 MB | 5.53 s | 8.0 MB |

A two-hundred-fold larger table, the same peak: memory is set by the batch and the sketch
parameters. About 180 MB of each figure is the interpreter with pyarrow, DuckDB, pyiceberg,
presidio and spaCy imported. Reproduce the 100M row with
`GODWIT_PROBE_BIG_ROWS=100000000 uv run pytest packages/godwit-probe -k memory -s`.

**Throughput.** Null rates stay in Arrow and run at ~40M rows/s. Sketches fed value by value
in Python (Theta, HLL, KLL, Count-Min) run at roughly 180k rows/s for a KLL+HLL pair; see
known limits.

---

## 11. Tests

`uv run pytest packages/godwit-probe` runs one launcher test that re-runs the directory in
a child interpreter (the guard issuer; see `CR-A6-access-modes-need-a-contract-home`).
Directly: `GODWIT_PROBE_ISOLATED=1 uv run pytest packages/godwit-probe/tests`.
111 tests: 107 pass, 4 strict xfails (one per change request).

| File | What it holds the line on |
|---|---|
| `test_leaks.py` | **ACCEPTANCE.** Poisoned sentinels through every error path, telemetry included; mypy over `typing_cases/must_fail.py`. |
| `test_stream.py` | **ACCEPTANCE.** Streaming vs backfill: byte-identical bundles and series; a hypothesis property over poll schedules; merged exact deltas equal a full probe. |
| `test_memory.py` | **ACCEPTANCE.** Peak RSS flat from 500k to 5M rows by default, 100M on request. |
| `test_executor.py` | **ACCEPTANCE** (refusal before any byte; no-change near zero), plus deltas, overwrites, compaction, cancellation, determinism, recovery of the generating statistics. |
| `test_plan.py` | Access modes asserted on the SQL text and read list; every refusal reason; plain-key permission rules. |
| `test_golden.py` | Real Iceberg tables from the golden fixtures: the documented drift at `snap_2` with the US control still, zero data bytes on refusal and no-change, estimate bounds actual, PII torture. |
| `test_worker.py` | Claims, leases, redelivery, cancellation with partial cost, retries, per-source limit across two pools. SQLite by default; `GODWIT_PROBE_PG_URL` for Postgres. |
| `test_units.py` | Error boundary, keyring, SafeId, telemetry, cost and estimate properties. |
| `test_contract_gaps.py` | Four strict xfails. |

---

## 12. Known limits

* **Python-speed sketch feeding.** Theta, HLL, KLL, Count-Min and the histogram are fed
  one value at a time through godwit-sketch's canonicalisation (~180k rows/s for two
  sketches). Memory is bounded; wall time on a 100M-row KLL probe is minutes, not seconds.
  Vectorised update paths in godwit-sketch are the fix.
* **Merge-on-read deletes are not applied.** Delete manifests (Iceberg v2 position and
  equality deletes) are skipped; a table written merge-on-read over-counts deleted rows.
  pyiceberg writes copy-on-write, where deletes are overwrites and trigger a full rescan.
* **Only Iceberg and the simulator implement `ProbeSource`.** Postgres and warehouse probes
  still go through godwit-source's own `execute_probe`, which has no access-mode planning
  and no delta. A `ProbeSource` over them is a SQL `delta` of "everything" plus a pushdown
  `read`.
* **Postgres claims are untested here.** No Docker on the reference machine; the SKIP LOCKED
  and advisory-lock branch runs only with `GODWIT_PROBE_PG_URL` set.
* **No Alembic migration.** Tables are created with `metadata.create_all`. A migration
  belongs with the deployment that owns the database.
* **OPAQUE types.** `TIMESTAMP`, `DECIMAL` and `BINARY` columns cannot be OPAQUE (no exact
  canonical form under a keyed hash) and are refused `opaque_type`.
* **Categorical sketches** accept string, integer, float and boolean columns; dates and
  decimals are refused `sketch_type_mismatch`. Graph endpoints are stringified, so an OPEN
  integer id keys as `s:123`, not `i:123` as a segment would.
* **Graph degree quantiles** are not fed: `observe_degree` requires entity-partitioned
  input, which a file-at-a-time scan is not.
* **`wall_seconds` is never charged** (no clock). The orchestrator measures wall time.
* **The in-memory state and the SQL state are separate.** A `CatalogPoller` over
  `MemoryProbeState` forgets on restart; use `SqlProbeState` (the queue's) in production.
* **GraphDegree envelopes do not declare their key mode** (`CR-A6-graph-degree-hides-its-key-mode`).
  The payload is hashed; the parameters do not say so.

## 13. Change requests filed

| CR | Against | Ask |
|---|---|---|
| `CR-A6-sketch-bundle-cannot-say-why` | contracts | a `ProbeOutcome` (status, refusal, estimate, since, permissions) |
| `CR-A6-opaque-entropy-floors-disagree` | guard, sketch | one entropy floor, not 24 vs 32 |
| `CR-A6-access-modes-need-a-contract-home` | contracts | access-mode types out of `godwit_guard`, so a worker does not hold the issuer |
| `CR-A6-graph-degree-hides-its-key-mode` | sketch | `GraphDegree.with_hasher` publishes the hasher's params |

Concurs with, and works around: `CR-A1-sketch-serialise-needs-context` /
`CR-A2-serialise-needs-context` (A2's `SketchContext` used), `CR-A2-sketch-kind-vocabulary`
(`EXACT_COUNT` disambiguated by a parameter), `CR-A2-kll-is-item-bearing` (KLL envelopes
arrive `DATA_VALUE` from A2), `CR-A4-probe-snapshot-resolution-is-unrecorded` (the resolved
snapshot is on every outcome, refused ones included).
