# godwit-source — handoff

Written for whoever picks this package up next. Assume no prior contact with A1.

## Read this first

This package is **data plane**, and it is where most of the system's tainted data is born.
Iceberg manifest bounds and `pg_stats.most_common_vals` are row values, not statistics about
row values. Before changing anything here, read the "Column access modes" and "Which
detectors need the value" sections of `docs/packages/godwit-source.md`.

## Getting it running

```bash
cd packages/godwit-source
uv venv --python 3.12 .venv
uv pip install -e ".[dev]"

.venv/Scripts/python -m pytest -q          # 93 tests
.venv/Scripts/python -m mypy --strict src tests benchmarks
.venv/Scripts/python -m ruff check src tests benchmarks
.venv/Scripts/python benchmarks/bench_metadata.py
```

All three are green from a clean checkout with no pyiceberg installed; two Puffin tests skip
in that case. `uv pip install -e ".[dev,iceberg]"` runs them.

Nothing in the test suite needs Postgres, an object store, a catalog or a network. Adapters
take their backend as an injected callable, which is deliberate — see below.

## The shape of the design, in five points

1. **Backends are injected, not constructed.** `IcebergAdapter` takes a `ManifestReader`;
   `PostgresAdapter` and `WarehouseSqlAdapter` take a `query(sql, params) -> rows` callable.
   This is what lets the golden fixture drive the entire metadata tier and lets a test
   assert on *the SQL text that was actually sent*. That assertion is the access-mode
   control; without the seam there is no honest way to make it.

2. **Access modes resolve at plan time and the plan is what gets checked.** A BLIND column is
   dropped from `AccessPolicy.plan()` before SQL exists. `assert_plan_is_blind_safe()`
   checks the generated SQL and the result schema. It never checks returned data, because by
   then the value has been read.

3. **The taint split is structural.** Row values live in `ColumnBounds` and `CommonValue`;
   aggregates live in `ColumnCounts`. No type holds both. A consumer can drop the bounds
   object wholesale and keep the counts object without inspecting a field.

4. **Detectors are pure functions over a time-series.** No clock, no randomness, no I/O. They
   take `Sequence[SnapshotMetadata]` and return `list[Candidate]`. Adding one is a function
   plus an entry in `DEFAULT_DETECTORS`.

5. **The LLM is not in this path and never will be.** `profile.py` does role inference and
   first-pass PII classification with regexes and cardinality ratios, because invariant 7
   requires L-1 to work with the whole LLM layer deleted.

## Things that will surprise you

- **`godwit-contracts` does not exist.** Everything imports contract types from
  `godwit_source._contracts`, which prefers the real package and falls back to
  `_contracts_stub.py`. When A0 lands: delete the stub, delete the `try`/`except`, delete
  `tests/test_contracts_gap.py`. Read `docs/change-requests/CR-A1-contracts-missing.md`
  first — it lists four decisions A0 has to make that will change code here.

- **Puffin files are sidecars.** pyiceberg 0.12 rejects unknown blob types in
  `statistics-files` and fails the whole table load, so registering ours would break every
  pyiceberg reader of the customer's table. `test_pyiceberg_rejects_unknown_blob_types_in_table_metadata`
  pins that. If it starts failing, pyiceberg relaxed the rule and the decision is worth
  revisiting.

- **`merchant_country` in the test fixture is OPEN, not OPAQUE.** Not an oversight: a hashed
  ISO country code is about 7.8 bits and enumerable in microseconds, so OPAQUE is not
  available for it. The entropy floor is real and it bites.

- **`IcebergAdapter` hashes OPAQUE columns in-process.** Parquet has no server-side compute.
  This is the one place in the package where a raw value exists in memory by design. The SQL
  adapters push the hash down and never see one.

- **`delta_only=True` is the default** on the Iceberg metadata path. Full-table statistics
  move too slowly to detect anything.

## Where to make common changes

| Want to | Go to |
| --- | --- |
| Add a detector | `detectors.py`, then `DEFAULT_DETECTORS` |
| Add a backend | implement `SourceAdapter` in a new module; reuse `AccessPolicy` and `assert_plan_is_blind_safe` |
| Change how sensitive a column is treated | `access.py`, `AccessPolicy.mode()` — one method, whole policy |
| Add a PII or role pattern | the compiled regexes at the top of `profile.py` |
| Add a Puffin blob type | `docs/specs/puffin-blobs.md` first, then `puffin.py` |
| Connect real sketches | `execute_probe(..., aggregate=...)` is the seam; code against the `SketchBundle` protocol, never against A2's classes |

## Tests worth understanding before you edit

- `test_taint_torture.py` walks every field of every emitted object and fails if a fixture
  row value appears outside a `Tainted`. `test_the_walk_can_actually_fail` is a guard on the
  guard — without it, a broken walker would make the whole file pass forever.
- `test_detectors_golden.py::test_metadata_read_touches_zero_data_bytes` is the acceptance
  test for the free tier, proven with an instrumented object-store client.
- `test_no_candidates_on_the_stable_prefix` is the one that catches a noisy detector.
  Snapshots s01–s07 are stable by construction; anything firing there is noise, and noise at
  50 alerts a day is the difference between 30% precision and none.
- `test_schema_evolution_fails_closed.py` is the fail-closed scenario end to end.

## What is not here

No sketch implementations (A2). No orchestration (A10), storage (A3), redaction (A5) or LLM
(A15). No `TODO` comments — unfinished work is under "Known limits" in
`docs/packages/godwit-source.md`, which is the list to read before assuming something was
forgotten rather than decided.
