# godwit-source

**Owner:** A1 · **Layers:** L-1 (metadata detectors), L0 (semantic catalog)

> **This package runs in the DATA PLANE.** It reads customer catalogs and customer rows.
> It is the origin point for most of the tainted values in Godwit: if it tags lazily,
> nothing downstream can recover. Treat every output as something a bank's security team
> will read line by line.

---

## Why this package exists

Iceberg manifests already record, per data file and per column, the row count, the null
count, the value count and the lower and upper bounds. Puffin already records a distinct
count. Postgres already records a null fraction, a distinct count, the most common values
with their frequencies, and histogram boundaries. Somebody else's pipeline wrote all of
it, for somebody else's reasons, and reading it costs a handful of small files.

godwit-source turns that free metadata into a first-pass signal, so that invariant 5 --
*metadata first* -- has something concrete to mean: a paid scan is spent only where the
free tier already flagged something.

Measured on a ten-thousand-file table, a full metadata pass reads **1.94 MiB in 0.87
seconds and touches zero bytes of table data**. The equivalent scan would read the whole
table.

---

## READ THIS TWICE: what here is a row value

Three of the things this package reads are advertised as statistics and are lists of
customer values.

| Source | What it actually is |
|---|---|
| Iceberg manifest `lower_bounds` / `upper_bounds` | Two real row values per column. The minimum of a name column is a person's name. Iceberg truncates string bounds to sixteen characters, which makes them a *prefix* of a real value and not one byte less sensitive. |
| `pg_stats.most_common_vals` | Literally the most common actual values in the column. |
| `pg_stats.histogram_bounds` | The values that fell on each percentile boundary. On a twelve-row table, twelve people. |

Plus two more that arrive through the probe path:

| Source | What it actually is |
|---|---|
| A `heavy_hitters` or `category_histogram` probe result | The grouped values themselves. On an identifier column the heavy hitters **are** the PII. |
| A driver exception message | Routinely quotes the offending row: `Key (customer_ssn)=(100-40-1000) already exists`. |

Every one of these becomes `Tainted[DATA_VALUE]` at the moment it is read, with an
`Acquisition` naming the route it came down. Counts are `DERIVED_STATISTIC` and live in
**different fields of the same model** -- see `ColumnMetadata`, whose validator refuses
the wrong taint on either half. Table and column names are `SCHEMA_NAME`.

There is no fourth category and nothing is left plain.

---

## The modules

| Module | What it does |
|---|---|
| `metadata.py` | `ColumnMetadata`, `FileLayoutStats`, `SnapshotMetadata`. The typed record, with the statistic half and the row-value half separated by field and enforced by a validator. Converts to the contract's `TableProfile`. |
| `iceberg.py` | `IcebergAdapter`. Manifests and Puffin read **directly from object storage**, never through a query engine. Bound decoding, per-snapshot reduction, delta reads, budgeted probes, Puffin write-back. |
| `postgres.py` | `PostgresAdapter`. `pg_stats`, `pg_class`, `pg_stat_all_tables`, `information_schema.columns`. Zero table scans, asserted. Synthesises a pseudo-snapshot from the last `ANALYZE`. |
| `warehouse.py` | `WarehouseSqlAdapter`. The degraded tier: `INFORMATION_SCHEMA` and nothing else for free. Two presets, `SNOWFLAKE` and `BIGQUERY`. |
| `detectors.py` | The six L-1 detectors, as pure functions over a metadata time-series. |
| `semantic.py` | Role, PII class and join-edge inference. No LLM, ever. |
| `puffin.py` | The Puffin codec: writes `godwit-` blobs, reads anyone's. See `docs/specs/puffin-blobs.md`. |
| `objectstore.py` | `ByteMeter` and `MeteredFileIO`: the instrumented object-store client that makes "zero bytes of table data" a measurement rather than a claim. |
| `pushdown.py` | `ProbeSpec` → aggregate SQL, and result set → Arrow. Shared by both SQL adapters. |
| `dbapi.py` | The DB-API protocols, the SQLAlchemy Core helpers, and the Postgres array-literal parser. |
| `sketches.py` | `SketchBuilder`: the one seam where A2's sketch classes plug in. This package owns no sketch code. |
| `stats.py` | Four statistics, stdlib only: two-sided normal p, robust z, two-proportion z, log ratio. |
| `scalars.py` | Comparing and measuring bounds without leaking them. |
| `errors.py` | The error hierarchy, and `sanitise_driver_error` -- the one place a driver message is defused. |

---

## The six L-1 detectors

Each is a pure function `(history, *, code_version, seed, config) -> tuple[Candidate, ...]`
over a sequence of `SnapshotMetadata`, oldest first, reporting on the last element.
`run_metadata_detectors` runs all six and returns them sorted by candidate id.

| Detector | Metadata fields used | Statistic |
|---|---|---|
| `bounds_drift` | `manifest.lower_bound`, `manifest.upper_bound` | Log of the column's range, and midpoint movement in units of the previous range. String columns: prefix divergence per bound. |
| `null_rate_shift` | `manifest.null_value_counts`, `manifest.record_count` | Pooled two-proportion z. |
| `ndv_ratio_shift` | `puffin.ndv`, `manifest.record_count` | Pooled two-proportion z on the distinct-to-row ratio. |
| `row_volume_anomaly` | `manifest.record_count` | Log row count, second difference. |
| `file_layout_anomaly` | `manifest.file_count`, `manifest.file_size_in_bytes` | Log file count and log mean file size, second difference. |
| `schema_change` | `schema.columns`, `schema.logical_type` | Count of columns added, removed and retyped. |

Each candidate's `Evidence.sketch_names` carries exactly the metadata fields the claim
was computed from.

### Which detectors need the value, and which do not

The brief asks for a preference: a detector reporting *how far* a bound moved emits a
derived statistic, while one reporting *which* bound it moved to is handling a row value.

**None of the six needs the value.** That is a design choice and it cost something:

* Numeric and temporal bounds are measured on a numeric axis, which loses the value and
  keeps the distance.
* String bounds are measured by shared-prefix ratio, which survives Iceberg's
  sixteen-character truncation and returns a number between 0 and 1.
* `schema_change` reports a *count* of changed columns and never their names, because a
  column name is a disclosure on its own -- `patient_hiv_status` says something before a
  single row is read.

The consequence is that a human reading an L-1 alert learns "the `amount` column's range
tripled, having been stable" and not "the maximum went from 326.33 to 899.60". The
second is more useful and it is a row value; getting it requires the gate, a redaction
policy and a destination, which is A5's job and not this layer's.

The segments L-1 emits are `column IS NULL` and `column NOT NULL`. Both operators are
nullary, so an L-1 segment carries **no predicate value at all** -- which also happens to
keep two columns' candidates from colliding on the universe segment during dedup.

### Relative, never absolute

Every detector measures the *latest transition against the previous transitions*, never
the latest value against a threshold.

This is the single most important thing about the detector layer and it is easy to get
wrong. A table whose `order_id` prefix advances with every load shows a large bound
change at every snapshot; a table whose amount range triples once, having been stable, is
drifting. Only the second difference tells those apart. `evaluate_deltas` takes a series
of *changes* rather than a series of values for exactly this reason, and the golden
fixture contains the identifier case on purpose.

Two regimes, chosen by how much history exists and never by which gives a more
interesting answer:

* **Four or more snapshots** -- a robust z of the latest change against the previous ones,
  converted to a two-sided p-value.
* **Three snapshots** -- the latest change must clear an absolute threshold *and* be at
  least twice the largest previous change. No p-value is reported, because none was
  computed. A missing p-value and a p-value of 1.0 are different claims.
* **Two snapshots** -- nothing fires. One transition with nothing to compare it against is
  not evidence.

Raw p-values only. FDR control belongs to L5, which can see the whole hypothesis space.

---

## Cost and budgets

Every path that can spend takes a `CostBudget` and refuses rather than exceeds it.
Refusing raises `BudgetExceededError`, which invariant 6 calls a normal outcome.

| Path | What is charged | When |
|---|---|---|
| `IcebergAdapter.read_metadata_stats` | Sum of `manifest_length` | Before any manifest opens |
| `IcebergAdapter.execute_probe` | Sum of `file_size_in_bytes` over the delta's data files | Before any data file opens |
| `PostgresAdapter.read_metadata_stats` | Nothing | Catalog reads cost no table pages |
| `PostgresAdapter.execute_probe` | `pg_class.relpages * 8192` | Before the query is issued |
| `WarehouseSqlAdapter.execute_probe` | Catalog row count × `bytes_per_row_estimate` | Before the query is issued |

BigQuery exposes no row-count estimate on `INFORMATION_SCHEMA.TABLES`, so a probe there
cannot be bounded before it runs and is **refused**. Running an unbounded query against a
per-byte biller because there was no estimate is the failure invariant 6 exists to stop.

`wall_seconds` is never charged. Measuring it requires a clock, and universal rule 5
forbids reading one anywhere that can produce a pattern. The orchestrator measures wall
time from outside.

---

## The degraded tier, stated plainly

A customer weighing Iceberg against a warehouse should be given this table, not a
diplomatic version of it.

| Signal | Iceberg | Postgres | Snowflake / BigQuery |
|---|---|---|---|
| Column bounds | free | free (`most_common_vals`, `histogram_bounds`) | **scan** |
| Null counts | free | free (`null_frac`) | **scan** |
| Distinct counts | free with Puffin | free (`n_distinct`) | **scan** |
| Row counts | free | free (`reltuples`) | free on Snowflake, **scan** on BigQuery |
| File layout | free | n/a | n/a |
| Snapshot history | free | **none** | **none** |

What survives at L-1 on a warehouse is `schema_change`, and `row_volume_anomaly` where a
catalog row count exists. Everything else moves into the paid tier where scan cost
dominates.

Neither Postgres nor a warehouse keeps a statistics history: each `ANALYZE` overwrites the
last. A metadata time-series over those sources has to be **accumulated by storing
snapshots as they are observed**, which is L5's job and not this adapter's. The adapters
synthesise a stable pseudo-snapshot id so those stored observations can be keyed and
compared.

---

## Benchmark

Recorded on the reference machine with `GODWIT_BENCH_FILES=10000 uv run pytest
packages/godwit-source/tests/test_benchmark.py -s`. Ten thousand single-row-group Parquet
files, three columns, one commit.

| Measure | Value |
|---|---|
| Data files | 10,000 |
| Rows | 100,000 |
| **Metadata bytes read** | **2,032,428** (1.94 MiB, ~203 B/file) |
| **Data bytes read** | **0** |
| **Wall seconds** | **0.865** |

The per-file cost is a property of the schema -- one manifest entry holds a fixed set of
per-column statistics -- not of the table's size, so it stays flat as the table grows.
The default test size is 1,000 files, which keeps `make test` quick; the per-file figure
matches.

---

## Testing

| File | What it proves |
|---|---|
| `test_golden_drift.py` | **ACCEPTANCE.** Against a real Iceberg table built from the golden fixture: the injected drift is found on the `amount` column at `snap_2` and not before, the `country = 'US'` control is never flagged, and `meter.data_bytes == 0`. |
| `test_pii_taint.py` | **ACCEPTANCE.** Walks every field of every emitted object and asserts no untainted string contains a PII-fixture identifier, or a twelve-character prefix of one. |
| `test_puffin.py` | Round-trip under hypothesis, plus a read-back through pyiceberg's own `PuffinFile`. |
| `test_postgres.py` | Zero table scans, against a recording connection. Array-literal parsing. |
| `test_warehouse.py` | The degradation, pinned as tests. |
| `test_iceberg_probe.py` | Budgets refuse before anything opens; segments filter; projection works. |
| `test_stats.py`, `test_scalars.py` | Property tests: translation invariance, scale invariance, antisymmetry, monotonicity. |
| `test_detectors.py` | Every detector's firing case and its several silent cases. |
| `test_semantic.py` | Roles, PII classes, join edges. |
| `test_contract_gaps.py` | Three `xfail`s, one per filed change request. |
| `test_benchmark.py` | The figures above. |

Two tests deserve a word about what they are *not*.

The PII walker is a **backstop**. The control is the taint type plus the gate. A passing
string search proves only that this fixture's particular values did not appear in this
run; it cannot prove the typing is right and it never will. Most of the leak paths in the
list above are things a regex would never recognise as sensitive.

The zero-scan tests are the opposite: they are the real control for the economic claim,
because they instrument the object store and the database driver rather than inspecting
the code.

---

## Known limits

* **`execute_probe` on Iceberg reads whole data files.** Columns are projected, so
  Parquet's column chunks do most of the work, but there is no row-group pruning from the
  segment predicate. The budget is charged from the manifest's file sizes, which is an
  upper bound, so a probe is never cheaper than it was charged -- it is sometimes dearer
  than it needed to be. Row-group pruning via `pyarrow.dataset` is the obvious next step.
* **No sketches.** A stated non-goal. `SketchBuilder` is the seam and A2 fills it. Until
  then `execute_probe` refuses with `UnsupportedProbeError`.
* **`SEGMENT_AGGREGATE`, `JOIN_CARDINALITY` and `GRAPH_DEGREE` probes are unsupported**
  on every adapter. They need a join plan this package does not build. Refusing beats
  returning something that looks like an answer.
* **Postgres `DISTINCT_COUNT` is exact, not a sketch.** `count(DISTINCT ...)` returns a
  number; there is no theta sketch to merge with another snapshot's. The result reaches
  the builder as a population with no values.
* **Table-metadata JSON is not metered.** `catalog.load_table` uses the catalog's own
  `FileIO` before this package can wrap it. Only data-file reads matter to the acceptance
  claim, and every one of those goes through the meter.
* **Godwit Puffin blobs are not registered in table metadata.** pyiceberg 0.12 types the
  registered blob type as a two-member `Literal`, so registering a `godwit-` blob there
  makes the table's metadata unreadable -- including by us. Ours live in an unregistered
  sidecar addressed by location. See `docs/specs/puffin-blobs.md`.
* **Join edges are proposals, not facts.** Approximate inclusion dependency over an NDV
  estimate and two bounds is suggestive, not conclusive. Confirming an edge costs a
  budgeted scan that somebody else decides to spend.
* **`infer_pii_class` over-restricts on purpose.** `merchant_name` comes back a direct
  identifier because it matches the name rule. Over-restricting is the safe direction;
  A5 refines and a human confirms.
* **Three filed change requests** are implemented around rather than patched:
  `CR-A1-sketch-serialise-needs-context`, `CR-A1-evidence-kind-has-no-schema-change`,
  `CR-A1-source-kind-has-no-warehouse`.
