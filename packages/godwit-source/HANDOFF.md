# godwit-source -- HANDOFF

**Owner:** A1
**Plane:** data
**Purpose:** Source adapters and the semantic catalog (L-1, L0).

> **This package runs in the DATA PLANE.** It reads customer rows and customer catalogs.
> Everything it emits must be gated. It is the origin point for most of the tainted
> values in Godwit -- if it tags lazily, no gate downstream can save the project.

Full reference: [`docs/packages/godwit-source.md`](../../docs/packages/godwit-source.md).
Blob format: [`docs/specs/puffin-blobs.md`](../../docs/specs/puffin-blobs.md).

## Status

Complete. `ruff`, `mypy --strict` and `pytest` green from a clean checkout. Three change
requests filed, each with a matching `xfail` in `tests/test_contract_gaps.py`.

## What you get

| Import | What it is |
|---|---|
| `IcebergAdapter`, `PostgresAdapter`, `WarehouseSqlAdapter` | the three backends |
| `SnapshotMetadata`, `ColumnMetadata`, `FileLayoutStats` | the typed metadata record |
| `run_metadata_detectors` and the six detectors by name | L-1 |
| `infer_role`, `infer_pii_class`, `infer_join_edges` | L0, no LLM |
| `ByteMeter`, `MeteredFileIO` | the instrumented object-store client |
| `write_puffin`, `read_puffin`, `sketch_envelope_blob` | the Puffin codec |
| `SketchBuilder`, `SketchContext` | A2's seam |
| `sanitise_driver_error`, `SanitisedDriverError` | defusing a driver message |

All of it is exported from `godwit_source` directly.

A one-minute tour:

```python
adapter = IcebergAdapter(catalog, meter=ByteMeter())
history = [
    adapter.read_metadata_stats(source, snapshot, budget=budget)
    for snapshot in adapter.list_snapshots(source)[-4:]
]
candidates = run_metadata_detectors(history, code_version=git_describe, seed=1)
assert adapter.meter.data_bytes == 0  # nothing was scanned
```

## The three things to know before you use it

**1. Bounds and most-common-values are row values.** `ColumnMetadata` splits its fields
in two halves -- counts are `DERIVED_STATISTIC`, bounds and MCVs and histogram boundaries
are `DATA_VALUE` -- and a validator refuses the wrong taint on either side. Do not
flatten the model into a dict. Do not call `.reveal()` outside the data plane.

**2. Detectors measure the second difference.** A change is compared against the previous
changes, never against a threshold. Fewer than three snapshots and nothing fires, because
one transition with nothing to compare it against is not evidence. That is why
`DetectorConfig.min_history` defaults to 3 and why the golden fixture's steadily
advancing `order_id` is correctly ignored.

**3. Refusing is normal.** Every adapter charges its budget from catalog metadata
*before* it opens anything, and raises `BudgetExceededError` rather than overspending.
Catch it, record the refusal, and stop.

## For specific agents

| You are | What you need from here |
|---|---|
| **A2 (`godwit-sketch`)** | Implement `godwit_source.sketches.SketchBuilder` and pass it to an adapter's constructor. `values` is an Arrow table with `value` and `count` columns, or `None` when the measurement has no values of its own -- a scan gives count 1 per row, a SQL pushdown gives the group size. **A builder that ignores `count` gets a warehouse probe wrong by orders of magnitude.** See `CR-A1-sketch-serialise-needs-context`: this seam exists because `Sketch.serialise()` cannot know its envelope's context, and it collapses into a direct call if that CR lands. |
| **A5 (`godwit-guard`)** | Every `Acquisition` this package can emit: `ICEBERG_MANIFEST_BOUNDS`, `PG_STATS_MCV`, `QUANTILE` (histogram boundaries), `COUNT_MIN_HEAVY_HITTER`, `CATEGORY_HISTOGRAM`, `SEGMENT_PREDICATE`, `DRIVER_EXCEPTION`, `COMPUTED_STATISTIC`, `SKETCH_SUMMARY`, `CATALOG_IDENTIFIER`. `infer_pii_class` gives you a first pass to refine -- it never returns `NONE` and it errs towards restriction. `SanitisedDriverError.original` holds a tainted driver message you may want a policy for. |
| **A6 (`godwit-probe`)** | `execute_probe(spec, snapshot, budget=...)` on all three adapters. It returns a `SketchBundle` and never rows. It refuses `SEGMENT_AGGREGATE`, `JOIN_CARDINALITY` and `GRAPH_DEGREE` on every backend. Sketch names in the bundle are `f"{kind}:{index}"` where `index` is the position in `spec.columns` -- a readable name would be a customer column name in an untainted dict key. |
| **A7 (`godwit-detect`)** | L-1 candidates arrive with a complete `Lineage`, raw p-values (or `None`, never a substituted 1.0), and segments whose predicates are nullary. Reuse `godwit_source.stats` if you want the same normal CDF and robust z; it is stdlib-only and property-tested. |
| **A8 (`godwit-context`)** | `metadata.schema_change` and `metadata.file_layout_anomaly` are your explained-away signals: a schema change or a new writer accounts for most drift found at the same snapshot. Match on `Lineage.detector`, not on `EvidenceKind` -- see `CR-A1-evidence-kind-has-no-schema-change` for why that is currently necessary. |
| **A10 (`godwit-orchestrator`)** | L-1 is free and should run first, always. `METADATA_PROBE_BUDGET` is all zeros and that is the true cost. The paid tier's estimates come from the manifest (Iceberg), `relpages` (Postgres) or the catalog row count (Snowflake); BigQuery has none and refuses. |
| **A3/A5 (pattern store)** | Candidate ids are deterministic over (detector, version, probe key, snapshot, segment key), so ingesting the same finding twice yields one pattern. Dedup by segment plus detector family works here because L-1 segments are per-column `IS NULL` / `NOT NULL` rather than the universe. |
| **A16/A17 (Vision Board)** | Nothing here is safe to render directly. Every `SnapshotMetadata` holds bounds; every candidate holds a column name. Go through the gate. |

## Adding a fourth backend

1. Add a `SourceKind` member -- that is a contract change and needs a CR (see
   `CR-A1-source-kind-has-no-warehouse` for the shape of one).
2. Write an adapter with `resolve_snapshot`, `read_metadata_stats`, `profile_table` and
   `execute_probe`. Emit `ColumnMetadata`, taint everything at the point of reading, and
   leave a field `None` rather than guessing it.
3. Reuse `godwit_source.pushdown` if the backend speaks SQL: a `SqlProfile` is two
   strings, and `aggregate_statement` and `result_to_values` do the rest.
4. Catch every driver exception and re-raise through `sanitise_driver_error`.

## Known limits

* **No sketches.** A stated non-goal. `execute_probe` refuses until a `SketchBuilder` is
  injected.
* **No row-group pruning.** Iceberg probes project columns but read whole files. The
  budget is charged from the manifest's file sizes, so a probe is never cheaper than it
  was charged -- occasionally dearer than it needed to be.
* **`SEGMENT_AGGREGATE`, `JOIN_CARDINALITY`, `GRAPH_DEGREE`** are unsupported everywhere.
* **Postgres `DISTINCT_COUNT` is exact, not a sketch**, so there is nothing to merge
  across snapshots.
* **Postgres and warehouses keep no statistics history.** A metadata time-series over
  them has to be accumulated by storing observations; the adapters mint a stable
  pseudo-snapshot id so those observations can be keyed.
* **Table-metadata JSON is not metered** -- `catalog.load_table` uses the catalog's own
  `FileIO` before this package can wrap it. Every data-file read is metered, which is
  what the acceptance claim rests on.
* **Godwit Puffin blobs are not registered in table metadata** because pyiceberg 0.12
  would then fail to parse the table. They live in a sidecar addressed by location.
* **Join edges are proposals.** Approximate inclusion dependency is suggestive, not
  conclusive; confirming one costs a budgeted scan.
* **`infer_pii_class` over-restricts on purpose** and never returns `NONE`.
