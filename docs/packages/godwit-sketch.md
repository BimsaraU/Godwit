# godwit-sketch

**Owner:** A2 **Layer:** L1 **Plane: DATA**

> **This package runs in the data plane and several of its outputs contain values taken
> from customer rows.** Everything it emits should be read as something a bank's security
> team will inspect line by line. The disclosure table below is the first thing to read;
> the rest of this document assumes you have.

Mergeable monoid sketches (invariant 6), and the time hierarchy that makes batch and
streaming produce the same artifact.

---

## 1. Disclosure — which sketches hold row values

| Class | Value-bearing? | What is in the payload |
|---|---|---|
| `ThetaNdv` | no | hashes of values, never values |
| `HllCount` | no | register maxima, never values |
| `NullRate` | no | two integer counters |
| `KllQuantile` | **yes** | a retained sample of real items, plus the exact min and max |
| `Moments` | **yes** | the exact minimum and maximum |
| `CountMinHeavy` | **yes** | heavy-hitter keys — on an identifier column, the PII itself |
| `CategoryHistogram` | **yes** | exact category labels below the cardinality threshold |
| `GraphDegree` | **yes** | fan-in / fan-out heavy hitters — entity identifiers |

Every value-bearing class exposes its stored state **only** as
`godwit_contracts.taint.Tainted`. There is no plain-string path to a key or an extreme
anywhere in this package, and `tests/test_no_plain_value_path.py` proves it structurally
— by walking the return annotation of every public member — rather than by asserting it
case by case.

Two entries in that table disagree with the contracts as currently written, and both are
filed rather than patched:

* **`KllQuantile` is item-bearing and `SketchKind.KLL` is not in `ITEM_BEARING_KINDS`.**
  A quantile sketch retains real items; the shipped golden fixture declares one a
  derived statistic. See `CR-A2-kll-is-item-bearing.md`. This package declares
  `DATA_VALUE` anyway, so nothing leaks from here today.
* **`Moments` is item-bearing** because it holds the maximum, and the taint module
  already says a maximum is some row's value. Same treatment.

### Two hazards that are not on the table

**A distinct-count sketch over a low-cardinality column is a membership oracle.** Theta
and HLL store hashes, and the hash seed travels in the envelope. Anyone holding the
envelope can hash a guess and test whether it is present, so for `country` or `status`
the set of values present is fully disclosed. That does not make the payload
item-bearing — nothing is stored verbatim — but a guardrail that treats distinct-count
sketches as unconditionally safe is wrong. Ask `ThetaNdv.is_membership_oracle()`.

**Hashing does not lower the taint class.** OPAQUE mode stores keyed digests instead of
values, which is the right default for identifiers and buys real blast-radius reduction:
a leaked payload is useless without a key held on the other side of the perimeter. But a
stable digest is a stable pseudonym, and a pseudonym re-identifies across alerts and
across time. Only the gate in `godwit-guard` can issue a `TOKEN`. Heavy hitters come back
`DATA_VALUE` in **both** key modes.

---

## 2. What this package is for

Batch merges sketches per data file. Streaming merges per micro-window. Both must land
on one artifact — a sketch time-series — and no detector above should be able to tell
which produced it. If the two modes diverge, nothing above L1 catches it: a detector
reads the divergence as drift and reports the ingestion mode change as a pattern.

**Non-goals.** No detection logic, no I/O beyond serialisation, no redaction. If
something here were deciding whether a value is anomalous, it would have left its scope.

---

## 3. The eight sketches

| Class | Kind it serialises as | Codec | Merge | Parameters |
|---|---|---|---|---|
| `ThetaNdv` | `THETA` | `godwit-theta-v1` | exact | `lg_k`, `seed` |
| `HllCount` | `HLL` | `godwit-hll-v1` | exact | `lg_k`, `seed` |
| `KllQuantile` | `KLL` | `godwit-kll-v1` | bounded | `k`, `seed`, `cdf_grid` |
| `CountMinHeavy` | `COUNT_MIN` | `godwit-cm-v1` | bounded | `width`, `depth`, `seed`, `capacity`, key mode |
| `Moments` | `EXACT_COUNT` | `godwit-moments-v1` | bounded | none |
| `NullRate` | `EXACT_COUNT` | `godwit-nullrate-v1` | exact | none |
| `CategoryHistogram` | `FREQUENT_ITEMS` | `godwit-cathist-v1` | bounded | `max_exact_cardinality` + Count-Min params |
| `GraphDegree` | `COUNT_MIN` | `godwit-graphdegree-v1` | bounded | every component's params |

Four of these borrow another kind's name because `SketchKind` has no member for them —
see `CR-A2-sketch-kind-vocabulary.md`. **The registry is keyed by `codec`, not by
`kind`, and so is `decode_envelope`.** A detector that switches on `envelope.kind`
cannot tell a moment summary from a row count today; switch on `codec`.

### Merge exactness — read this before testing the laws

The `Sketch` protocol states law 1 as exact equality:
`a.merge(b).merge(c) == a.merge(b.merge(c))`. That holds for five kinds here and is
**provably impossible** for the other three. A bounded summary must discard information
to stay inside its size limit, and a different bracketing discards a different part;
nothing can recover it. Separately, IEEE-754 addition is not associative, which rules out
exact equality for any float-valued summary.

So every class declares `MergeExactness.EXACT` or `.BOUNDED`, the property suite applies
the matching assertion, and `CR-A2-monoid-law-exactness.md` proposes the restatement.

**None of this weakens the batch/streaming guarantee**, because that guarantee never
rested on merge being order-free. See §5.

---

## 4. Two sketches are written here rather than wrapped, and why

Both decisions were forced by measurement, not preference. Both are pinned by tests that
**fail** if upstream is fixed, so the workaround can be retired deliberately rather than
rediscovered.

**`KllQuantile`.** The DataSketches KLL binding is not deterministic: building the same
sketch from the same values twice *in the same process* gives two different
serialisations, starting exactly at the first compaction (`n = k + 1`) and never before.
The constructor exposes `k` and no seed. That breaks universal rule 5 and invariant 7
outright, and — because it is invisible below `k` — it would have survived a test suite
built on small fixtures and appeared only on real volumes. The in-package version keeps
KLL's capacity schedule and replaces the compaction coin with a keyed hash of the buffer
being compacted: a pure function of content. See `CR-A2-kll-determinism.md`.

**`HllCount`.** A weaker reason, and a different one. The upstream HLL *is* deterministic
across runs. It is not *canonical*: below its sparse threshold it stores a coupon list in
insertion order, so two unions of the same pair in opposite orders agree on the estimate
and disagree on the bytes. Fatal to a byte-level equivalence guarantee, so this is a
dense-register implementation with no sparse mode and therefore no representation
ambiguity.

**`ThetaNdv` is a genuine wrapper.** It was measured to be deterministic and
byte-identical across all 24 permutations of four inputs, and it is the one that must
read Iceberg's `apache-datasketches-theta-v1` Puffin blobs — `ThetaNdv.from_iceberg_blob`.
Invariant 5: when a table already carries an NDV sketch in its statistics file, reading
it costs nothing and a distinct-count probe should never be scheduled.

One wrinkle worth knowing: a Theta sketch has more than one byte representation of the
same set (`update_theta_sketch.compact()` retains up to `2k` entries, a union result
trims to exactly `k`). `_resolved()` pushes everything through a union, which is
idempotent, so law 3 holds.

---

## 5. TimeHierarchy — how batch and streaming actually agree

Not by assuming merge is order-free. It is not, for three kinds. Instead:

1. **Leaves are retained, not folded on arrival**, so the fold can be redone.
2. **Contributions within a window are folded in a canonical order** — sorted by their
   own serialised bytes. Content, not arrival time.
3. **Coarse levels are derived, never accumulated**, by folding children in ascending
   window order every time.

The *sequence of merge operations* is therefore a pure function of the data. Same data,
same bytes, whether it arrived in one batch, in reverse, or in a thousand shuffled
micro-batches — including a straggler for a window that has already been folded and read.

`tests/test_hierarchy.py` drives every registered kind three ways (batch, shuffled,
reversed) and compares `canonical_bytes()` at every level. It is the most important test
in the package.

**Gaps are gaps.** `query()` returns one `Bucket` per window with `sketch=None` where no
data arrived, and never interpolates. "No rows landed this hour" is usually a broken
pipeline; "rows landed and summed to zero" is usually a quiet Sunday. A series that fills
the first with the second hides exactly the silent data-quality collapse this product
exists to catch.

**Cost:** a window holds its contributions rather than one merged sketch. Kinds whose
merge is EXACT are folded eagerly, since bracketing provably cannot matter for them.

---

## 6. The feature vector

`extract_features(envelope) -> tuple[float, ...]`, one pure function, **always
`len(FEATURE_LAYOUT)` long regardless of kind**. A slot that does not apply is `NaN`,
never `0.0`: zero is a measurement, NaN is the absence of one, and a model that cannot
tell them apart will learn that a missing Theta sketch means a column with no distinct
values.

Address columns by name — `feature_index("freq_top1_share")` — never by a literal offset.
The layout is data (`FEATURE_LAYOUT`), and this table is generated from it.

**No extreme, and nothing that recovers one.** The tempting fix is to export a
standardised extreme, `(max - mean) / stddev`, instead of `max`. It does not work: the
vector already carries `mean` and `stddev`, so any standardised extreme solves straight
back to the extreme with school algebra. The same applies to the range and to every other
rearrangement. The extremes are simply absent. If a detector needs to know the maximum
moved, the honest route is `KllQuantile.cdf()` on a fixed grid — what fraction is above
this threshold — which names nobody's number.

**Small cells.** `moments_mean`, `moments_stddev` and `moments_sum` are blanked to NaN
below `small_cell_threshold` (default 20), because the mean of one row *is* that row.
This is defence in depth, **not** a control: redaction belongs to `godwit-guard`. Inside
the data plane, pass `small_cell_threshold=0`.

<!-- generated from FEATURE_LAYOUT; regenerate rather than hand-editing -->

| # | Slot | Meaning |
|---|------|---------|
| 0 | `population` | Items fed into the sketch. 0 for an empty sketch. |
| 1 | `log1p_population` | log(1 + population). Population spans orders of magnitude across probes; the log is what a linear model can use. |
| 2 | `error_epsilon` | Epsilon from the envelope's ErrorBound, or 0.0 when the bound is exact. Lets a detector discount a divergence that is inside the sketch's noise. |
| 3 | `error_delta` | Delta from an epsilon_delta bound; NaN for other kinds. |
| 4 | `value_bearing` | 1.0 if the source sketch's state contains row values, else 0.0. Metadata about the sketch, not about the data; useful for routing, never a signal. |
| 5 | `merge_is_exact` | 1.0 if the kind's merge is exactly associative, 0.0 if bounded. |
| 6 | `distinct_estimate` | Estimated distinct values. Theta and HLL only. |
| 7 | `distinct_ratio` | distinct_estimate / population, in [0, 1]. Near 1.0 means a near-unique column (an identifier); a sharp fall is a join key losing uniqueness. |
| 8 | `distinct_lower_bound` | Two-standard-deviation lower bound on the estimate. |
| 9 | `distinct_upper_bound` | Two-standard-deviation upper bound on the estimate. |
| 10 | `distinct_retained` | Hashes the sketch holds. A size diagnostic. |
| 11 | `quantile_retained` | Items retained across all KLL levels. |
| 12 | `quantile_levels` | KLL weight levels in use. Grows with log(n). |
| 13 | `quantile_nonfinite_rate` | Share of observations dropped as NaN or infinite, over the total offered. A data-quality signal: a column that starts emitting NaN moves this. |
| 14 | `cdf_00` | Cumulative fraction at grid point 0 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 15 | `cdf_01` | Cumulative fraction at grid point 1 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 16 | `cdf_02` | Cumulative fraction at grid point 2 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 17 | `cdf_03` | Cumulative fraction at grid point 3 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 18 | `cdf_04` | Cumulative fraction at grid point 4 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 19 | `cdf_05` | Cumulative fraction at grid point 5 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 20 | `cdf_06` | Cumulative fraction at grid point 6 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 21 | `cdf_07` | Cumulative fraction at grid point 7 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 22 | `cdf_08` | Cumulative fraction at grid point 8 of the envelope's cdf_grid parameter. NaN when the grid does not reach this slot. Comparing two snapshots on one grid is the cheap way to compare distributions. |
| 23 | `freq_distinct_categories` | Categories held exactly, or retained heavy-hitter candidates once the histogram has degraded. |
| 24 | `freq_top1_share` | Share of the population in the single most frequent key, in [0, 1]. The headline segment-divergence signal: a country going from 1% to 18% of rows shows up here and nowhere cheaper. |
| 25 | `freq_top5_share` | Share of the population in the top five keys. |
| 26 | `freq_top10_share` | Share of the population in the top ten keys. |
| 27 | `freq_underestimate_rate` | Misra-Gries counter mass lost to shrinking, over the population. High values mean the heavy-hitter list is not exhaustive. |
| 28 | `freq_regime_exact` | 1.0 when a category histogram is still exact, 0.0 once degraded to Count-Min. NaN for kinds that have no regime. |
| 29 | `moments_mean` | Arithmetic mean. BLANKED to NaN below small_cell_threshold: the mean of one row is that row. |
| 30 | `moments_stddev` | Sample standard deviation. Blanked below small_cell_threshold. |
| 31 | `moments_sum` | Sum of observations. Blanked below small_cell_threshold. |
| 32 | `moments_cv` | Coefficient of variation, stddev/\|mean\|. Scale-free, so it compares across snapshots whose absolute scale has drifted. |
| 33 | `moments_skewness` | Population skewness. NaN below three observations. |
| 34 | `moments_kurtosis` | Excess kurtosis, zero for a normal distribution. NaN below four observations. A fat tail appearing is a classic fraud signature. |
| 35 | `moments_nonfinite_rate` | Share of numeric observations dropped as NaN or infinite. |
| 36 | `null_rate` | Nulls over total rows, in [0, 1]. NaN over an empty population -- 'no rows' and 'no nulls' are different findings. |
| 37 | `graph_edges` | Total directed edges observed, counting repeats. |
| 38 | `graph_distinct_sources` | Estimated distinct source entities. |
| 39 | `graph_distinct_targets` | Estimated distinct target entities. |
| 40 | `graph_distinct_edges` | Estimated distinct (source, target) pairs. |
| 41 | `graph_mean_out_degree` | Edges per source entity. |
| 42 | `graph_mean_in_degree` | Edges per target entity. A funnel raises this while out-degree stays flat. |
| 43 | `graph_edge_multiplicity` | Edges over distinct edges. Near 1.0 means almost every pair transacts once, which is what a burst of one-shot mule transfers looks like. |
| 44 | `graph_fan_in_out_ratio` | Distinct sources over distinct targets. Well above 1.0 is a funnel: many payers, few payees. |
| 45 | `graph_concentration_in_top10` | Share of all edges arriving at the ten busiest targets, in [0, 1]. Rises sharply when a structuring ring starts collecting. |
| 46 | `graph_concentration_out_top10` | Share of all edges leaving the ten busiest sources, in [0, 1]. |
| 47 | `graph_degree_population_in` | How many in-degrees were recorded. 0 means the degree quantiles are empty because the probe did not pre-aggregate by entity. |
| 48 | `graph_degree_population_out` | How many out-degrees were recorded. |

---

## 7. Measured accuracy and memory

Reproduce with:

```
uv run python packages/godwit-sketch/benchmarks/run_benchmarks.py --rows 1000000 --distinct 1000000
```

Seeded and hash-derived throughout, so rerunning gives byte-identical numbers.

### KLL rank error, 1,000,000 lognormal rows, 3 seeds

| k | bound (1sd) | p67 error | p67 / bound | median max | max / bound |
|---|---|---|---|---|---|
| 100 | 0.02608 | 0.00737 | 0.28 | 0.02606 | 1.00 |
| 200 | 0.01329 | 0.00289 | 0.22 | 0.00991 | 0.75 |
| 400 | 0.00678 | 0.00217 | 0.32 | 0.01235 | 1.82 |
| 800 | 0.00345 | 0.00076 | 0.22 | 0.00530 | 1.54 |

**Compare `p67` against the bound, not `max`.** The declared bound is one standard
deviation of a *single* query's rank error. `max` here is the worst of 99 correlated
probes, so on any one seed it lands anywhere between 0.5x and 2x the bound by luck alone —
which is how a healthy sketch gets mistaken for a broken one. `p67` is the like-for-like
figure, and it sits at 0.22–0.32 of the bound at every `k`, halving as `k` doubles
exactly as `2.296 / k**0.9723` predicts.

### Distinct counts, 1,000,000 distinct values, 7 seeds

| sketch | lg_k | bias | observed sd | bound (1sd) |
|---|---|---|---|---|
| Theta | 10 | −0.725% | 4.513% | 3.125% |
| HLL | 10 | −1.477% | 4.095% | 3.250% |
| Theta | 12 | +0.854% | 1.367% | 1.562% |
| HLL | 12 | +0.118% | 1.988% | 1.625% |
| Theta | 14 | −0.143% | 0.744% | 0.781% |
| HLL | 14 | −0.081% | 0.953% | 0.812% |

Both estimators are unbiased. At `lg_k >= 12` the observed spread is in line with the
bound (a sample standard deviation from 7 draws carries roughly 27% standard error of its
own, so 1.99% against 1.63% is within noise).

**At `lg_k = 10` the spread runs clearly above the nominal bound, and that is real rather
than noise:** 1,000,000 distinct values into 1,024 retained hashes or registers is far
into extrapolation. Treat `lg_k = 12` as the floor for cardinalities at this scale, and
do not quote the nominal bound for a sketch that is this saturated.

### Count-Min frequency, 1,000,000 Zipf rows

| width | depth | bound (eps·N) | max over-count | mean over-count | top-10 recall |
|---|---|---|---|---|---|
| 2718 | 5 | 1000.1 | 488 | 51.40 | 10/10 |
| 8192 | 5 | 331.8 | 106 | 9.12 | 10/10 |

Never under-counts — asserted in the benchmark, since that is Count-Min's one hard
guarantee — and the observed over-count stays at roughly half the bound.

### Moments, 1,000,000 lognormal rows

| statistic | exact | streamed | merged (7 shards) | relative error |
|---|---|---|---|---|
| mean | 31.307692099 | 31.307692099 | 31.307692099 | 9.1e-15 |
| variance | 618.944725780 | 618.944725780 | 618.944725780 | 4.5e-14 |

Accurate to floating-point rounding, and the merged path agrees with the streamed one.

### Memory, at 1,000,000 and 100,000,000 distinct values

| sketch | distinct | live peak | serialised payload | estimate | error |
|---|---|---|---|---|---|
| Theta (`lg_k=12`) | 1,000,000 | 96.7 KiB | 32.1 KiB | — | — |
| HLL (`lg_k=12`) | 1,000,000 | 46.1 KiB | 10.1 KiB | — | — |
| Count-Min (2718x5) | 1,000,000 | 643.6 KiB | 26.9 KiB | — | — |
| Theta (`lg_k=12`) | **100,000,000** | — | **32.1 KiB** | 100,988,085 | +0.99% |
| HLL (`lg_k=12`) | **100,000,000** | — | **9.9 KiB** | 101,728,784 | +1.73% |

**A hundredfold more distinct values, and the payload does not move** — 32.1 KiB either
way for Theta. That is the property being demonstrated rather than an artefact of the
measurement: every structure here is fixed-size by construction, so footprint is a
function of the parameters and never of the cardinality. (HLL's payload is fractionally
*smaller* at 100M: the run-length encoding has fewer distinct runs to describe once every
register is occupied.) Both estimates land inside their 1.56% / 1.63% bounds.

The 100M run takes about four minutes for Theta and three and a half for HLL, which is
why it is not in the test suite. `tracemalloc` is left off at that scale — its
per-allocation overhead roughly doubles the runtime, and the number being demonstrated is
the fixed allocation, not the transient churn. Reproduce with `--distinct 100000000`.

Serialised sizes are well below live size because the payload encodings exploit what is
actually there: varints for Count-Min's mostly-small counters, and run-length encoding for
the long runs of zero registers a sparsely-populated HLL leaves behind.

---

## 8. Using it

```python
from godwit_sketch import CountMinHeavy, KllQuantile, SketchContext, TimeHierarchy

# Build. from_items, or update() in a loop on the ingestion path.
amounts = KllQuantile.from_items(rows, {"k": 200, "seed": 7, "cdf_grid": "10,100,1000"})

# Merge. Refuses across differing parameters rather than guessing.
combined = shard_a.merge(shard_b)

# Serialise. The context comes from the probe; see CR-A2-serialise-needs-context.
envelope = combined.serialise(
    SketchContext(
        source_id=source_id,
        snapshot_id=snapshot_id,
        produced_for=probe_key,
        produced_at=as_of,
        table="orders",
        column="amount",
    )
)

# Read it back — dispatches on codec, no need to name the class.
from godwit_sketch import decode_envelope

rebuilt = decode_envelope(envelope)
```

**OPAQUE columns** (the default for identifiers):

```python
from godwit_sketch import KeyHasher

hasher = KeyHasher.opaque(key=data_plane_key, input_entropy_bits=64.0)
sketch = CountMinHeavy.identity(params).with_hasher(hasher)
```

`KeyHasher.opaque` **refuses** below 32 bits of declared input entropy. A hashed
four-digit PIN, country code or date of birth is enumerable in seconds by anyone holding
the key; such a column must be bucketed or blinded, never hashed and called safe. Declare
the plausible input space, not the observed cardinality — the latter is a lower bound and
would let a sampled column look safer than it is.

**Revealed keys are in canonical tagged form** — `"s:key-3"`, not `"key-3"` — matching
`godwit_contracts.segment.canonical_scalar`. That is deliberate: it is the same form a
`Segment` predicate uses, so heavy hitters line up with segment keys, and `1`, `"1"` and
`True` cannot collide into one bucket.

---

## 9. Adding a sketch

The registry makes non-compliance structurally hard rather than merely discouraged.

1. Subclass `BaseSketch` and declare `KIND`, `CODEC`, `SCHEMA_VERSION`, `VALUE_BEARING`,
   `MERGE_EXACTNESS`, `ITEM_FLAVOUR`, `ACQUISITION`.
2. Implement `merge`, `identity`, `from_items`, `error_bound`, `encode`, `_decode_body`.
3. Decorate with `@register`. It refuses a class missing any of the above, or reusing a
   codec.

`tests/test_monoid_laws.py` iterates the registry, so the new kind is swept into the full
property suite without anyone wiring it up. Skipping registration is not an escape: an
unregistered sketch cannot be decoded by `decode_envelope` and so cannot cross a package
boundary.

Then add its slots to `FEATURE_LAYOUT` and a branch in `extract_features`.

---

## 10. Known limits

* **Four kinds borrow another kind's `SketchKind`.** `codec` is the real discriminator
  until `CR-A2-sketch-kind-vocabulary.md` is decided.
* **`GraphDegree` degree quantiles need entity-partitioned input.** Edge counts,
  distinct-entity counts and fan-in/fan-out summaries merge correctly however the data was
  partitioned. The *degree quantiles* do not: a degree is a per-entity aggregate, so
  merging two shards that both contain account `A` records it twice with two partial
  degrees, understating exactly the account a mule detector most wants. The precondition
  travels in the parameters as `degrees_partitioned_by_entity`, is part of the merge
  identity, and `observe_degree` refuses without it.
* **Canonicalisation costs throughput.** Every item is rendered through
  `canonical_scalar` before hashing, which is what makes `1`, `"1"` and `True` distinct
  and makes two agents agree. It is not free; if probe throughput ever matters more than
  cross-agent agreement, this is the first thing to look at.
* **The KLL error constants are empirical**, quoted from DataSketches for the same
  capacity schedule, and were fitted for independent fair coins. Hash-derived bits are
  deterministic, so the guarantee holds against inputs chosen without knowledge of the
  seed and is **not** a guarantee against an adversary who knows the seed and crafts a
  stream to defeat the compaction schedule. §7 is the evidence for the bound.
* **`lg_k = 10` is too small for million-scale cardinalities.** See §7.
* **Count-Min heavy hitters are Misra-Gries candidates, not a certified top-k.** Report
  `underestimate()` alongside any list, or it reads as exhaustive when it is not.
* **The PII backstop cannot check four of the fixture's strings.** `positive`,
  `negative`, `unknown` and `general` are real row values in the torture fixture and also
  ordinary English that appears in redaction labels. That collision is the demonstration
  that scanning is a backstop and the typed taint is the control.
* **No `TOKEN` path.** This package never downgrades sensitivity; only the gate can.
* **`datasketches-stubs/` is a workaround** for a missing mypy override — see
  `CR-A2-datasketches-needs-a-mypy-override.md`. Delete it when that lands.
