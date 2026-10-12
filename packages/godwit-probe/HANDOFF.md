# godwit-probe -- HANDOFF

**Owner:** A6 · **Layer:** L1 · **Plane: data** · **Status:** complete

> **This package runs in the DATA PLANE.** It reads customer rows in place and emits
> sketch bundles, outcomes, logs, spans, metrics and job rows -- none of which may carry a
> row value. Treat every output as something a bank's security team will inspect.

Full reference: [`docs/packages/godwit-probe.md`](../../docs/packages/godwit-probe.md).

## State

* `ruff`, `ruff format --check` and `mypy --strict` clean with zero suppressions.
* 111 tests: 107 pass, 4 strict xfails (one per change request). The suite runs in a
  child interpreter (`tests/conftest.py`), exactly like godwit-guard's, because importing
  `godwit_guard` claims the process's `SafePayloadIssuer`.
* Dependencies added: `godwit-source`, `godwit-sketch`, `godwit-guard`, `duckdb`,
  `sqlalchemy`, `numpy`, `opentelemetry-api`, `opentelemetry-sdk`. `uv.lock` updated.
* Every acceptance item has a named test:

| Acceptance | Test |
|---|---|
| Poisoned sentinels, every error path, telemetry | `test_leaks.py` (29 tests) |
| No-change costs near zero and says so | `test_executor.py::test_a_no_change_probe_costs_one_catalog_read_and_says_so`, `test_golden.py::test_no_change_on_a_real_table_reads_no_data` |
| Memory bounded on 100M rows | `test_memory.py` -- 193.8 MB peak at 100M vs 196.1 MB at 500k (run with `GODWIT_PROBE_BIG_ROWS=100000000`) |
| Budget refusal before any byte, instrumented client | `test_executor.py::test_budget_refusal_happens_before_any_byte_is_read`, `test_golden.py::test_budget_refusal_reads_zero_data_bytes_on_a_real_table` |
| Batch and streaming identical | `test_stream.py` (byte-identical bundles and `TimeHierarchy` bytes, plus a hypothesis property) |

## Decisions a successor should know about

1. **The executor does not use godwit-source's `execute_probe`.** That method materialises
   the whole snapshot (`concat_tables`), charges the whole snapshot rather than the delta,
   and has no access modes. A1's adapter is used for snapshot resolution and history;
   manifests are walked here for per-file added-by snapshot and column sizes.
2. **DuckDB over Arrow streams, not DuckDB over files.** Data files are opened through
   `godwit_source.MeteredFileIO`, so every data byte is metered; DuckDB runs the planned
   SQL over the resulting batches. `threads = 1` for deterministic row order.
3. **Footers are read by hand.** pyarrow's 64 KiB speculative footer read made actual
   bytes exceed a column-size estimate by 20×. See §5 of the doc.
4. **`ProbeOutcome` wraps `SketchBundle`** because the contract cannot say refused /
   no-change / cancelled / since (`CR-A6-sketch-bundle-cannot-say-why`).
5. **`produced_at` is the snapshot's commit instant**, never `spec.as_of`: two runs of
   the same measurement must produce the same bytes whenever they run.
6. **Double hashing on OPAQUE heavy hitters.** HMAC in the query (guard key), then
   godwit-sketch's OPAQUE `KeyHasher` in the sketch (sketch key) -- so the envelope's
   `key_mode = hashed` is true and a column-key holder alone cannot read it.
7. **Plain-key permission = ALLOW guardrail naming purpose `probe.plain_keys`.** Recorded
   on `ProbeOutcome.permissions`.
8. **No row counts in logs**, only bytes and file counts: a segment's row count is a small
   cell.

## For other agents

| You are | Use |
|---|---|
| **A10 (orchestrator)** | `ProbeExecutor.execute` or the `JobQueue`. Read `outcome.status`; on `REFUSED`, `outcome.refusal.reason` and `.estimated_cost` are your signal. `NO_CHANGE` costs one catalog read. `CatalogPoller` follows streaming tables. |
| **A7 (detect)**, **A11 (features)**, **A19** | `godwit_probe.testing.ProbeSimulator` -- real probes over synthetic data with known truth; §9 of the doc. `SketchSeries` gives you `TimeHierarchy` per sketch name. |
| **A4 (replay)** | Bundles are deterministic in (spec, since, until, data); `bundle_id(...)` reproduces the id. The resolved snapshot is on every outcome. |
| **A3 (store)** | Bundles are keyed `(probe_key, since_snapshot_id, snapshot_id)`; `outcome_json` sits beside `bundle_json`. |
| **A2 (sketch)** | `CR-A6-graph-degree-hides-its-key-mode`. Also: Python-speed `update()` is this package's throughput ceiling. |
| **A5 (guard)** | `CR-A6-opaque-entropy-floors-disagree`, `CR-A6-access-modes-need-a-contract-home`. |

## Change requests filed

`CR-A6-sketch-bundle-cannot-say-why`, `CR-A6-opaque-entropy-floors-disagree`,
`CR-A6-access-modes-need-a-contract-home`, `CR-A6-graph-degree-hides-its-key-mode`.

## Known limits

Full list in §12 of the doc. The ones most likely to bite:

* Sketches fed value by value in Python: ~180k rows/s for a KLL+HLL pair.
* Merge-on-read (v2 delete-file) deletes are not applied.
* Only Iceberg and the simulator implement `ProbeSource`; Postgres and warehouses do not.
* The Postgres SKIP LOCKED / advisory-lock path is only exercised with
  `GODWIT_PROBE_PG_URL` set; locally the suite runs on SQLite.
* No Alembic migration; tables come from `metadata.create_all`.
