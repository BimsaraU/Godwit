# godwit-sketch — HANDOFF

**Owner:** A2 **Layer:** L1 **Plane:** data
**Status:** complete. `ruff`, `mypy --strict` and `pytest` green from a clean checkout.

**This package runs in the DATA PLANE.** It reads values out of customer rows, and five
of its eight sketches hold row values in their serialised state. Treat every output as
something a bank's security team will read line by line.

Full documentation: **`docs/packages/godwit-sketch.md`**. Read §1 (disclosure) before
using anything here. This file is the orientation; that one is the reference.

---

## What it does

Eight mergeable-monoid sketches (invariant 6), a versioned binary codec for each, a time
hierarchy that makes batch and streaming produce byte-identical artifacts, and a
fixed-length feature vector that A7, A11, A12 and A13 consume.

```
godwit_sketch/
  base.py          BaseSketch, the registry, MergeExactness, SketchContext
  codec.py         the self-describing container; producer fingerprints
  items.py         canonical keys; KeyHasher (OPAQUE mode + the entropy floor)
  distinct.py      ThetaNdv          (wraps DataSketches; Iceberg Puffin interop)
  hll.py           HllCount          (dense registers, written here — see below)
  quantile.py      KllQuantile       (deterministic KLL, written here — see below)
  frequency.py     CountMinHeavy, CategoryHistogram
  moments.py       Moments, NullRate
  graph.py         GraphDegree       (fan-in/fan-out; the structuring signal)
  hierarchy.py     TimeHierarchy     (the batch/streaming equivalence)
  features.py      FEATURE_LAYOUT, extract_features
  varint.py        LEB128, for sparse Count-Min matrices
  deterministic.py hash-derived synthetic data for tests and benchmarks
```

---

## The five things you need to know

**1. Two sketches are written here rather than wrapped, and the stack list says
otherwise.** The DataSketches KLL binding is *not deterministic* — the same values give
different bytes in the same process, starting at the first compaction — which breaks
universal rule 5 and invariant 7 outright. The DataSketches HLL *is* deterministic but is
not *byte-canonical* below its sparse threshold, which breaks the hierarchy's equivalence
guarantee. `ThetaNdv` is a genuine wrapper and does the Iceberg Puffin interop. Filed as
`CR-A2-kll-determinism.md`; pinned by tests that **fail** if upstream is ever fixed.

**2. Contract law 1 cannot hold as exact equality for three kinds.** A bounded lossy
summary discards information to stay inside its size limit, and a different bracketing
discards a different part. Every class declares `MergeExactness.EXACT` or `.BOUNDED`.
Filed as `CR-A2-monoid-law-exactness.md`.

**3. Batch/streaming equivalence does not depend on merge being order-free.**
`TimeHierarchy` retains leaves and folds in a **canonical order derived from content**,
so the sequence of merge operations is a pure function of the data. That is why the
guarantee survives point 2. `tests/test_hierarchy.py` is the most important test here.

**4. A KLL payload contains real row values, and the contract says it does not.**
`ITEM_BEARING_KINDS` omits `KLL`, and `tests/golden/sketch_envelopes.json` ships a `kll`
envelope declared `derived_statistic`. **This is a leak path.** This package declares
`DATA_VALUE` anyway so nothing leaks from here, but A5 and A18 should read
`CR-A2-kll-is-item-bearing.md` before writing a guardrail.

**5. Four sketches borrow another kind's `SketchKind`** because the vocabulary has no
member for them. **The registry and `decode_envelope` dispatch on `codec`, not `kind`.**
If you switch on `envelope.kind` you cannot tell a moment summary from a row count.
Filed as `CR-A2-sketch-kind-vocabulary.md`.

---

## If you are…

**A6 (probes)** — build sketches with `from_items` or `update`, then
`serialise(SketchContext(...))`. The context is required; see
`CR-A2-serialise-needs-context.md`, which concurs with A1's identical finding. For
identifier columns pass `KeyHasher.opaque(key=..., input_entropy_bits=...)`; it refuses
below 32 bits, and that refusal is correct — bucket or blind the column instead.
`ThetaNdv.from_iceberg_blob` reads an existing NDV sketch for free (invariant 5).

**A7 (detectors), A11 (features), A12, A13** — `extract_features(envelope)` returns a
tuple that is always `len(FEATURE_LAYOUT)` long. Address columns via
`feature_index("name")`, never a literal offset; the full table is generated into the
package doc. Inapplicable slots are `NaN`, never `0.0`. There is **no** minimum, maximum
or quantile slot, and that is deliberate — §6 of the doc explains why a standardised
extreme is not a workaround. Compare distributions with `KllQuantile.cdf()` on a grid
supplied in the probe's `cdf_grid` parameter.

**A5 (guard) and A18 (policy)** — read §1 of the package doc in full. The short version:
value-bearing sketches expose state only as `Tainted`; a keyed hash is a pseudonym and
not a downgrade, so heavy hitters are `DATA_VALUE` in both key modes; and a
distinct-count sketch over a low-cardinality column is a membership oracle
(`ThetaNdv.is_membership_oracle()`).

**A3 (store)** — envelope payloads are self-describing and versioned. An older reader
refuses a newer payload loudly rather than misreading it. Do not index on `kind` until
`CR-A2-sketch-kind-vocabulary.md` is decided.

**A4 (replay)** — everything here is deterministic. Same items and parameters give the
same bytes on any machine, in any process. No wall clock, no unseeded randomness; time
is injected into `TimeHierarchy` as `epoch`.

---

## Tests

```
uv run pytest packages/godwit-sketch          # 243 passed, 3 xfailed
```

The three `xfail`s are the change requests, each `strict=True`, so they announce
themselves as `XPASS` the moment a contract is fixed.

| File | What it protects |
|---|---|
| `test_monoid_laws.py` | invariant 6, property-tested over the whole registry |
| `test_hierarchy.py` | batch == shuffled == reversed, byte for byte, every level |
| `test_no_plain_value_path.py` | invariant 2; structural + behavioural + PII backstop |
| `test_serialisation.py` | version refusal, digest checks, fingerprints, varints |
| `test_features.py` | fixed length, layout stability, no extremes, small cells |
| `test_golden.py` | the documented drift is visible; the control stays still |
| `test_contract_gaps.py` | the CR evidence, and pins on upstream behaviour |

Benchmarks are separate and not part of the suite:

```
uv run python packages/godwit-sketch/benchmarks/run_benchmarks.py
```

---

## Known limits

Full list in §10 of the package doc. The ones most likely to bite:

* **`GraphDegree` degree quantiles require entity-partitioned input.** Everything else in
  that sketch merges however the data was sharded; the degree quantiles do not. The
  precondition travels in the parameters and `observe_degree` refuses without it.
* **`lg_k = 10` is too small for million-scale cardinalities** — the observed spread runs
  above the nominal bound there. Use 12 or more.
* **Count-Min heavy hitters are Misra-Gries candidates, not a certified top-k.** Report
  `underestimate()` alongside any list.
* **Revealed keys are canonical and tagged** — `"s:key-3"`, matching
  `canonical_scalar`, so they line up with `Segment` predicates.
* **Canonicalising every item costs throughput.** It is what makes `1`, `"1"` and `True`
  distinct and what makes two agents agree. First place to look if probe throughput ever
  matters more.
* **`src/datasketches-stubs/`** is a PEP 561 workaround for a missing mypy override in
  the root config, which this package does not own. See
  `CR-A2-datasketches-needs-a-mypy-override.md`; delete the directory when that lands.

## Change requests filed

| File | Severity |
|---|---|
| `CR-A2-kll-is-item-bearing.md` | high — a leak path classified as safe |
| `CR-A2-kll-determinism.md` | high — resolved in code, deviation recorded |
| `CR-A2-monoid-law-exactness.md` | high — the law as written is unsatisfiable |
| `CR-A2-sketch-kind-vocabulary.md` | medium — stored envelopes would migrate |
| `CR-A2-serialise-needs-context.md` | low — concurs with `CR-A1-sketch-serialise-needs-context` |
| `CR-A2-datasketches-needs-a-mypy-override.md` | trivial |
