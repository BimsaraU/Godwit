# godwit-source (A1) — source adapters and L-1 metadata detectors

> **This package runs in the DATA PLANE, and it is the origin point for most of the tainted
> data in the system.** Iceberg manifest bounds and `pg_stats.most_common_vals` are not
> statistics *about* row values — they *are* row values. The minimum of a name column is a
> real person's name. The most common value of an email column is a real email. Everything
> this package reads from those fields is `Tainted[DATA_VALUE]` from the moment it is read
> and stays tainted for the rest of its life. If this package tags lazily, no gate
> downstream can recover. A bank's security team will read this code; assume they will.

## What it is for

Iceberg manifests already carry, per data file per column: row counts, lower and upper
bounds, null counts and value counts. Puffin already carries Theta sketches with an `ndv`
property. Postgres already maintains `most_common_vals`, `most_common_freqs`,
`histogram_bounds` and `n_distinct` in `pg_stats`. None of it costs a scan.

This package turns that free metadata into a first-pass signal, so paid scans are spent only
where something already looks wrong. Measured on a 10,000-file table (see
[Benchmark](#benchmark)): the metadata pass over eight snapshots reads **33.6 MB** and finds
the injected drift, against **10.7 TB** for a full scan of the same data. Ratio 1 : 319,566.

## Layout

| Module | Role |
| --- | --- |
| `access.py` | Column access modes. Plan-time resolution, fails closed. |
| `stats.py` | Typed metadata structures. Row values and aggregates live in different types. |
| `base.py` | The `SourceAdapter` protocol and the plan-time checks every adapter shares. |
| `iceberg.py` | `IcebergAdapter` — the full-strength tier. |
| `pyiceberg_reader.py` | `ManifestReader` backed by pyiceberg against a REST catalog. |
| `postgres.py` | `PostgresAdapter` — `pg_stats`, zero table scans. |
| `warehouse.py` | `WarehouseSqlAdapter` — the degraded tier, and honest about it. |
| `detectors.py` | The six L-1 detectors. |
| `profile.py` | Semantic role, first-pass PII class, candidate join edges. No LLM. |
| `puffin.py` | Read and write GODWIT's own Puffin blobs. |
| `instrument.py` | Object-store client that counts bytes by kind, so "zero data bytes" is testable. |
| `_contracts.py` | Import switch for A0's contracts. See `docs/change-requests/CR-A1-contracts-missing.md`. |

## Column access modes

Excluding sensitive columns from probing is the obvious answer and it is wrong. The
strongest organised-fraud signal in the whole design is shared-attribute graph structure —
how many accounts share this device, this address, this phone — and every one of those
columns is a direct identifier. Skipping them protects the data by deleting the product.

`AccessPolicy.mode(column)` resolves one of three modes, in this order:

1. No classification, or an unconfirmed one → **BLIND**.
2. `SECRET`, `FREE_TEXT` or `UNKNOWN` → **BLIND**, overriding any request.
3. `OPEN` requested without a recorded guardrail id → downgraded to **OPAQUE**.
4. Otherwise: identifiers default to **OPAQUE**, non-PII to **OPEN**.
5. **OPAQUE** that fails the minimum-entropy check → **BLIND**.

### BLIND

The column never enters a query projection, a predicate, an `ORDER BY` or a metadata read.
Enforced at plan time. `AccessPolicy.plan()` drops it before any SQL exists, and
`assert_plan_is_blind_safe()` verifies against the generated SQL string and the result
schema — not against the returned data, because a value that was read has already passed
through process memory, a query log and possibly a driver error message.

### OPAQUE — the default for identifiers

Read only through a keyed hash, with the key held in the data plane. You keep cardinality,
velocity, fan-in and fan-out, join behaviour and collision structure. You never see a value.

Per backend:

- **Postgres and warehouses** push the hash down into SQL, so the server never returns the
  value at all.
- **Iceberg** cannot: Parquet has no server-side compute. The value is materialised in the
  data-plane worker and replaced by `keyed_hash` before anything aggregates it. The raw
  value never reaches a result, a log or an exception. Stated explicitly because it is the
  one place in this package where a raw value exists in memory by design.

For metadata, an OPAQUE column surfaces **derived statistics only** — how many distinct, how
the count moved. Its `ColumnBounds` is never constructed, and `pg_stats.most_common_vals`
for it is discarded inside the row loop, before entering any structure. There is no object
holding them that a downstream consumer could forget to redact.

### The minimum-entropy check

**Keyed hashing is not anonymisation when the input space is small.** A hashed four-digit
PIN is 13.3 bits, an ISO country code about 7.8, a date of birth over a century about 15.2 —
all enumerable in under a second. `MIN_OPAQUE_ENTROPY_BITS` is 30.0; a column below it
resolves to BLIND rather than being hashed and called safe. Bucketing it is a legitimate
alternative and is the caller's decision, not this package's.

Where `input_space_bits` is not declared, it is estimated as `log2(ndv)` from free metadata.
That is a proxy, marked `ponytail:` in the source, and it tracks the cases that matter:
PINs, country codes and dates of birth all have small NDV.

### Failing closed on schema change

A newly discovered column arrives BLIND and stays there until a classification is recorded.
`tests/test_schema_evolution_fails_closed.py` adds `customer_email_v2` to the golden fixture
mid-replay and asserts it is never read — not in metadata, not in a probe — until then. The
`schema_change` detector reports the new column's name (tainted) so a human can classify it.

## The detectors

All six are pure functions over a metadata time-series. No clock, no randomness, no I/O.
`run_all()` runs them in fixed order and sorts by p-value.

| Detector | Metadata fields used | Emits a value? |
| --- | --- | --- |
| `null_rate_shift` | `null_count`, `row_count` | No — a rate and a z-score |
| `ndv_ratio_shift` | Puffin `ndv`, `row_count` | No |
| `row_volume_anomaly` | `record_count` | No |
| `file_layout_anomaly` | `file_size_in_bytes`, entry count | No |
| `bounds_drift` | `lower_bounds`, `upper_bounds` | Only on request |
| `schema_change` | schema columns | **Yes, necessarily** |

### Which detectors need the value, and why

The brief asks for the derived form wherever it loses no information, and five of six
comply. Two deserve explanation:

**`bounds_drift` emits the distance by default.** How far a bound moved carries the signal;
the bound itself is a real name or a real email. `include_bound_values=True` attaches the
bound as `DATA_VALUE`, and exists for one case: a human reviewer who needs to see *which*
value appeared before they can judge the finding. Nothing automated should ask for it.

**`schema_change` must carry values.** The finding *is* the column name. A column name is a
leak path in its own right — `patient_hiv_status`, `customer_ssn`, `salary_2024` — and there
is no derived form of "which column appeared" that preserves what a reviewer needs. So the
names travel as `DATA_VALUE` and the gate decides.

### The statistics

- **`null_rate_shift`** uses a pooled two-proportion z-test, not a robust z over rates,
  because the denominator is known exactly from the manifest. A 10% null rate out of 20 rows
  and out of 20 million rows are not the same evidence, and a proportion test knows that.
- **The other four** use a median/MAD robust z-score. Robust because a metadata series
  contains the very outliers we are hunting, and a mean/stdev score lets one big spike hide
  the next one. Volume and layout statistics are scored on `log1p` because they are
  multiplicative: a doubling means the same at a thousand rows and at a million.
- **A constant baseline** has no scale, so the score saturates at |z| = 8 rather than
  returning infinity. An infinite z outranks every real finding in a 50-alerts-a-day queue.
- **Non-numeric bounds** have no distance. The signal is "a bound that had been stable has
  left the set it lived in", with `p = 1/(n+1)`, the exchangeability bound. Honest and weak,
  which is the right shape for a free signal whose job is to aim a paid scan.

Scale and translation equivariance of the robust z, antisymmetry of the two-proportion z,
and the p-value's monotonicity are property-tested in `tests/test_properties.py`.

## Semantic profiling, no LLM

`profile.py` infers a semantic role and a first-pass PII class from name patterns, type,
cardinality ratio and — for OPEN columns only — the *format* of a manifest bound. The format
label (`"email"`, `"uuid"`, `"e164_phone"`) is emitted; the bound is not.

Everything it produces is a guess and is never `confirmed`, which means an `AccessPolicy`
resolves the column to BLIND regardless. A profile is advisory input to A5 and to a human
reviewer; it never unlocks a read.

`candidate_join_edges()` proposes joins from NDV containment, name affinity and (where
available) bounds overlap. It works on OPAQUE columns, which is the whole point: the
shared-attribute graph is built entirely from direct identifiers, and no value is needed to
propose an edge. `containment` is an upper bound on real containment, not a measurement —
two columns with disjoint values and equal NDV score 1.0. Confirming an edge costs a probe,
which is exactly the trade this layer exists to set up.

## The three adapters

### `IcebergAdapter` — full strength

Reads manifests and Puffin **directly from object storage**, never through a warehouse query
engine: routing a metadata read through a billed engine turns the free tier into the
expensive tier and puts row values through a third party's logs.

`read_metadata_stats()` walks a snapshot window and, by default, restricts each snapshot's
statistics to the files that snapshot *added*. That `delta_only` default is what makes the
series a series — full-table statistics move slowly and hide exactly the shifts we are
looking for.

`execute_probe()` estimates bytes from manifest file sizes **before** reading anything and
refuses if over budget, so refusing is free. It then spends per file, so a budget that was
estimated optimistically still bites mid-scan.

The `ManifestReader` protocol is injected rather than constructed, which is what lets the
golden fixture drive the entire metadata tier with no catalog, no object store and provably
zero data bytes. `PyIcebergManifestReader` is the real implementation; pyiceberg is an
optional extra and is imported lazily, so the package installs and tests without it.

### `PostgresAdapter` — free statistics, pushdown probes

Metadata comes from `pg_stats`, `pg_class.reltuples` and `information_schema.columns`.
`tests/test_postgres.py::test_metadata_path_never_touches_the_user_table` asserts
structurally that every statement names a catalog relation and none names the table being
profiled.

Postgres has no snapshot history, so `list_snapshots()` returns empty and `snapshot_id` is a
required parameter of `read_metadata_stats()`. Inventing one from a clock would break
determinism; supplying one keeps replay honest.

Probe SQL wraps every projected column in an aggregate, so the result has one row by
construction. There is no shape of that query that could return rows, and no `SELECT *`.

### `WarehouseSqlAdapter` — the degraded tier

**Sell it as one.** Without Iceberg manifests there are no free per-column bounds, no free
null counts per commit and no Puffin NDV. `INFORMATION_SCHEMA` gives types and a column
list. The free L-1 tier on this path is roughly: schema change, and nothing else. Scan cost
dominates the economics.

Row counts are deliberately reported as absent rather than estimated: warehouse row-count
views are stale by hours on every engine worth naming, and a stale denominator turns every
rate detector into a noise generator. Likewise this adapter never scans on the metadata
path — a metadata read that silently bills is worse than an absent one.

Byte budgets apply only when the caller supplies an estimate (BigQuery's dry run gives one
for free). Without it, only the query budget protects the call. Documented here rather than
hidden.

## Driver errors

Driver messages routinely quote the offending row — `duplicate key value violates …
(email)=(ada@example.com)`. Every adapter replaces the original exception wholesale via
`safe_backend_error()` rather than scrubbing it. A regex over a driver message is a guess,
and a guess is not a control.

## Cost budgets

Every billable path takes a `CostBudget` and raises `CostBudgetExceeded` rather than
overspending. **Refusing is a normal outcome, not an error.** `iceberg.probe_or_refuse()`
returns `None` for callers that treat it as a scheduling outcome, which is what it is.

## Benchmark

`python benchmarks/bench_metadata.py`, 10,000 files per snapshot × 8 snapshots × 24 columns:

| Measure | Value |
| --- | --- |
| Metadata read | 0.89 s |
| Detector pass | 0.001 s |
| Metadata bytes read | 33,600,000 |
| **Data bytes read** | **0** |
| Bytes a full scan would have cost | 10,737,418,240,000 |
| Ratio | 1 : 319,566 |

Byte counts come from the instrumented object-store client, not from an estimate.

## Known limits

- **`godwit-contracts` does not exist.** This package runs against a provisional stub inside
  its own tree. See `docs/change-requests/CR-A1-contracts-missing.md`, which also lists four
  contract questions A0 must settle — notably whether `Candidate.p_value` is tainted and
  whether column names are.
- **Puffin blobs are sidecars, never registered in `statistics-files`,** because pyiceberg
  0.12 rejects unknown blob types and would fail the whole table load for every reader. See
  `docs/specs/puffin-blobs.md`.
- **`_bits_from_ndv` is a heuristic.** NDV proxies the plausible input space. A column whose
  NDV is large but whose domain is guessable would pass the entropy check wrongly; declare
  `input_space_bits` explicitly for such a column.
- **Non-numeric bounds are ordered as text when types are mixed.** `_merge_bound` falls back
  to string comparison, which is wrong for numbers stored as strings. The resulting bound is
  a hint for a detector, never an arithmetic input beyond the distance the detector reports.
- **Warehouse row counts are absent, not estimated**, so `null_rate_shift`,
  `ndv_ratio_shift` and `row_volume_anomaly` do not fire on that tier.
- **`schema_columns` carries BLIND column names in plain form.** It is a plan-time structure
  that never leaves the data plane, and detectors tag names when emitting them. If A0 rules
  that column names are always tainted, this is the field that changes.
- **No sketch implementations.** A1 codes against the `SketchBundle` protocol only; A2
  supplies the classes. `execute_probe` takes an `aggregate` callable as the seam.
- **The benchmark measures in-process cost**, not network latency against a real object
  store. Manifest fetch over S3 will dominate the 0.89 s figure in production.
