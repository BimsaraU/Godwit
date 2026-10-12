# godwit-detect

**Owner:** A7 **Layer:** L2 (detectors) **Plane: CONTROL, handles data-derived values**

> **This package never reads a row, but it reads sketches that contain row values:**
> heavy-hitter keys, category labels, and the samples a KLL sketch retains. It emits
> those values in exactly two places, `Finding.identities` and `Attribution.identity`,
> and both are typed `Tainted`. Segment predicates quote values (leak path 4), and column
> names are schema names (leak path 9). Everything else it emits is a derived statistic.
> Treat every output as something a bank's security team will read line by line.

Every detector is a pure, deterministic function from sketches to findings. There is no
I/O, no wall clock, no randomness and no LLM. `tests/test_properties.py` enforces this
by parsing the source for clock, random, I/O and file access.

---

## 1. The package in one screen

```python
from godwit_detect import (
    SketchSeries,
    SeriesPoint,
    ProbeContext,
    Seasonal,
    PsiDrift,
    to_candidate,
)

series = SketchSeries(
    context=ProbeContext.from_spec(spec, "kll:0"),  # which probe, segment, column
    points=tuple(
        SeriesPoint(
            at=b.produced_at, snapshot_id=b.snapshot_id, envelope=b.sketches.get("kll:0")
        )  # None = a gap
        for b in bundles_oldest_first
    ),
)
result = PsiDrift().run(series, policy=Seasonal(period=7, cycles=4))
result.findings  # tuple[Finding, ...] -- only those with p <= alpha
result.tests  # every hypothesis examined, for L5's FDR control
result.refusals  # what was not tested, and why (thin_sketch, gap, ...)
candidates = [to_candidate(f, code_version=build, seed=seed) for f in result.findings]
```

| Detector (`NAME`) | Input | Evidence kind | Effect size | p-value |
|---|---|---|---|---|
| `psi_drift` | series of KLL / category histogram / Count-Min | DISTRIBUTION_SHIFT | PSI | `PSI/(1/n+1/m) ~ chi2(B-1)` (Yurdakul 2018) |
| `wasserstein_drift` | series of KLL | DISTRIBUTION_SHIFT | W1, column units | KS on bin edges (conservative) |
| `js_drift` | series of category histogram / Count-Min | DISTRIBUTION_SHIFT | JS divergence, bits | G test, `G = 2(n+m)·JS_w` |
| `heavy_hitter_shift` | series of Count-Min / category histogram | HEAVY_HITTER_SHIFT | share change; HHI change; churn change | two-proportion z; HHI delta method or t prediction; churn t prediction |
| `segment_divergence` | panel of segments (Moments, NullRate, KLL, categorical) | SEGMENT_DIVERGENCE | Cohen's d; rate difference; JS bits | Welch z / two-proportion z / G, over robust panel dispersion; diff-in-diff when emerging |
| `correlation_shift` | panel of pair-sum Moments | DISTRIBUTION_SHIFT | Δr | Fisher z |
| `graph_anomaly` | series of GraphDegree | GRAPH_ANOMALY | ratio / share change; funnel shift in sd | t prediction per metric; Fisher combination for the funnel |
| `ecod`, `copod` | rows of `extract_features` vectors | DISTRIBUTION_SHIFT | tail improbability, nats | conformal rank |
| `matrix_profile` | series, one feature slot | RATE_CHANGE | distance / median neighbour distance | **none**, see §6 |

## 2. Baselines, and why seasonality is handled by time

`FixedReference(snapshot_id)`, `Trailing(points)` and `Seasonal(period, cycles)` choose
the reference windows. The chosen windows are **merged** into one reference sketch,
which is possible because every sketch is a monoid (invariant 6).

`Seasonal` counts phase by *time*, not by list position. If a window is missing, earlier
Mondays do not slide onto Sundays. It therefore refuses series with uneven spacing
(`irregular_series`). The seasonality acceptance test runs six weeks of daily windows
with a strong weekly cycle in both amounts and channel mix. Under
`Seasonal(period=7, cycles=4)`, `psi_drift`, `wasserstein_drift`, `js_drift` and
`heavy_hitter_shift` emit **nothing**. Under `Trailing(points=3)`, the same series fires,
and the test asserts that too.

**Dispersion.** When three or more reference windows are chosen, the detector also
compares each of them with the merge of the others (G statistic). The median of those
statistics, scaled to its null median, estimates how much the reference moves beyond
sampling noise. The test statistic is divided by that factor, which is never less than
1. This quasi-likelihood correction is what stops real-world week-to-week wobble from
reading as drift (`stats.dispersion_factor`).

## 3. The evidence payload

`Finding` is written for two readers.

* **A11**, which converts a finding into a feature mechanically. It reads
  `segment`, `columns`, `method`, `window.baseline_policy`, `window.baseline_snapshot_ids`,
  `direction` and `effect.name`/`effect.unit`. None of these are prose.
* **A reviewer with identities suppressed.** `Finding.without_identities()` removes
  `identities` and every `Attribution.identity`. What remains is the effect, the direction,
  the p-value (or `p_value_note`), attribution by *our* labels (`bin:3`, `rank:2`,
  `graph_mean_in_degree`, `moments_skewness`), and `shape`, a set of identity-free
  derived statistics. For example: `entrant_count`, `entrant_share`, `churn`, `hhi`,
  `gini`, `concentration_in`, `fan_in_out_ratio`, `dispersion`, `effective_rows`.

**Suppression test result:** `test_every_finding_survives_identity_suppression` runs
every detector's scenario. Every finding still has a finite effect, a direction and a
p-value or a reason. Every finding that carried identities keeps at least one shape
measure. **No detector failed this.** The heavy-hitter detector depends on it most: with
the keys stripped, a finding still reads "two new keys took 19% of volume, churn 0.3, HHI
up 0.08".

`to_candidate()` projects a finding onto the contract `Candidate`. The projection is
lossy (see `CR-A7-evidence-has-no-structured-detail`). The candidate id is a hash of the
finding's identity, and `created_at` is the window's own instant.

## 4. Statistical details that matter

**Binning** (`histograms.py`). If the probe supplied `cdf_grid`, that grid is used,
because it was fixed before any data was seen. Otherwise the detector uses equal-mass
bins at the reference's `1/bins … (bins-1)/bins` quantiles. Those cut points are row
values: they live only inside `numeric_edges` and its caller, and no finding ever names
one. Before a test, bins whose expected count on either side is below 5 are merged
(adjacent bins for numeric data, an "other" bin for categories). Effect sizes use the
unmerged bins.

**KLL sketch noise.** The error in a KLL bin-mass estimate has a standard deviation of
about `0.2 × epsilon`, where epsilon is the sketch's declared rank bound. That figure is
flat in both `n` and `k`:

| k | n=500 | n=2,000 | n=20,000 | n=100,000 |
|---|---|---|---|---|
| 100 | 0.172 ε | 0.207 ε | 0.247 ε | 0.187 ε |
| 200 | 0.194 ε | 0.208 ε | 0.186 ε | 0.198 ε |
| 400 | 0.196 ε | 0.199 ε | 0.214 ε | 0.207 ε |

Tests therefore use `n_eff = 1/(1/n + (0.2ε)²/(p(1-p)))` with `p = 0.1`. Without this
correction, PSI on `k=200` sketches of 2,000 rows rejected at 0.117 under the null. With
it, the rate is 0.054. On larger windows the correction dominates and the tests become
conservative (0.003 at n=20,000). Being conservative is the honest direction to be wrong
in.

**Heavy-hitter selection bias.** Testing only the keys that crossed into or out of the
top-k selects on the outcome: a key is an entrant *because* its count happened to rise.
In a null run that approach rejected at 0.16. The detector instead tests every key in
the union of both top-k sets and labels each result entrant, exit or share shift. The
rate is then 0.052.

**Segment heterogeneity.** Segments ordinarily differ. Each segment's chi-square is
divided by the median chi-square over every *pair* of segments. One outlier appears in
only `2/K` of the pairs, so it cannot inflate that median. References are also trimmed
sequentially, in the manner of a generalised ESD test, so the outlier does not
contaminate every other segment's leave-one-out reference. On the golden fixture,
before trimming, every cell looked significantly low against a reference that contained
the PT/refund surge. After trimming, only PT/refund is reported and the US control stays
quiet.

**Conformal p-values** (ECOD/COPOD): `p_i = #{j: s_j ≥ s_i}/n` is exactly
super-uniform under exchangeability, whatever the dependence between features. The
consequence is that `alpha × n` rows are emitted even under the null. That is the
nominal rate, and L5's FDR control handles it.

## 5. Measured false-positive rates (null test)

1,000 synthetic null series per detector at `alpha = 0.05`, rate = emitted ÷ declared
tests. Reproduce with
`uv run python packages/godwit-detect/tests/benchmark_detectors.py --null 1000 --sims 60`.
Worlds are defined in `tests/_detect_null.py`. One binomial standard deviation at 1,000
tests is 0.007.

| detector | series | tests | emitted | rate |
|---|---|---|---|---|
| psi_drift[kll] | 1000 | 1000 | 54 | 0.0540 |
| psi_drift[categorical] | 1000 | 1000 | 58 | 0.0580 |
| wasserstein_drift | 1000 | 1000 | 15 | 0.0150 |
| js_drift | 1000 | 1000 | 60 | 0.0600 |
| heavy_hitter_shift | 1000 | 11651 | 606 | 0.0520 |
| segment_divergence | 1000 | 8000 | 140 | 0.0175 |
| correlation_shift | 1000 | 24000 | 232 | 0.0097 |
| graph_anomaly | 1000 | 7000 | 381 | 0.0544 |
| ecod[location] | 1000 | 40000 | 1996 | 0.0499 |
| ecod[shape] | 1000 | 40000 | 1996 | 0.0499 |
| copod[location] | 1000 | 40000 | 1999 | 0.0500 |
| copod[shape] | 1000 | 40000 | 1999 | 0.0500 |
| matrix_profile[white] | 1000 | 2000 | 18 | 0.0090 |
| matrix_profile[periodic] | 1000 | 2000 | 72 | 0.0360 |

Reading the table:

* **Calibrated:** `psi_drift`, `js_drift`, `heavy_hitter_shift`, `ecod`, `copod`.
* **Conservative by construction:**
  * `wasserstein_drift`, because its KS statistic is taken on bin edges only;
  * `segment_divergence`, because the dispersion floor is 1 and pairwise dispersion
    carries twice the between-segment variance;
  * `correlation_shift`, because a pair is emitted only when it also crosses the edge
    threshold;
  * `graph_anomaly`.
* `matrix_profile` has no p-value. Its rows are discord/motif emission rates at the
  default thresholds: 0.009 on white noise, which is what the default was calibrated on.
  On a 12-window cycle plus noise, the default discord ratio of 1.5 would fire 43% of the
  time. The periodic row therefore uses 2.1, the 95th percentile of that world's null.
  **Recalibrate `discord_ratio` for the kind of series you feed it.**

## 6. Minimum detectable effect at 80% power

Bisection over the effect size, with 60 simulations per point, `alpha = 0.05`, and the
same worlds as §5. The effect units are per detector. "Detected" means the *injected*
change was found: the right segment, the right row, a discord and not only a motif.
`> x` means 80% power was not reached at the largest effect tried. **Downstream agents:
this is what the system cannot see.**

| detector | effect unit | sizes | minimum effect at 80% power |
|---|---|---|---|
| psi_drift[kll] | location shift, sd of log-amount | (200, 1000, 5000) | 200: 0.453, 1000: 0.203, 5000: 0.109 |
| psi_drift[categorical] | share moved into one category | (200, 1000, 5000) | 200: 0.156, 1000: 0.0508, 5000: 0.0234 |
| wasserstein_drift | location shift, sd of log-amount | (200, 1000, 5000) | 200: 0.391, 1000: 0.172, 5000: 0.0938 |
| js_drift | share moved into one category | (200, 1000, 5000) | 200: 0.156, 1000: 0.0508, 5000: 0.0234 |
| heavy_hitter_shift | share gained by one key | (500, 3000, 20000) | 500: 0.0273, 3000: 0.0117, 20000: 0.0117 |
| segment_divergence | Cohen's d of one segment in eight | (50, 200, 1000) | 50: 0.562, 200: 0.328, 1000: 0.141 |
| correlation_shift | correlation gained by one pair, from 0.25 | (100, 500, 2000) | 100: 0.273, 500: 0.12, 2000: 0.0766 |
| graph_anomaly | share of edges diverted to four collectors | (300, 800, 3000) | 300: 0.0844, 800: 0.0281, 3000: 0.00469 |
| ecod[location] | location shift of one row in forty, sd | (50, 300, 2000) | 50: > 4, 300: > 4, 2000: > 4 |
| ecod[shape] | location and spread shift of one row in forty | (50, 300, 2000) | 50: > 4, 300: 0.5, 2000: 0.25 |
| copod[location] | location shift of one row in forty, sd | (50, 300, 2000) | 50: > 4, 300: > 4, 2000: > 4 |
| copod[shape] | location and spread shift of one row in forty | (50, 300, 2000) | 50: > 4, 300: 0.344, 2000: 0.125 |
| matrix_profile[white] | spike height, noise sd | (60, 120, 240) | 60: > 40, 120: > 40, 240: > 40 |
| matrix_profile[periodic] | spike height, noise sd (ratio 2.1) | (60, 120, 240) | 60: 7.5, 120: 6.25, 240: 5.94 |

Reading the power table:

* **ECOD and COPOD cannot see a pure location shift of one row, at any size.** Mean,
  standard deviation and sum move together, and a naturally extreme row is extreme on
  the same three slots. A rank-based scorer caps each slot at `-log(1/n)`, so the
  injected row only ties with the natural extremes. A row that changes *shape* as well
  (spread, and so skewness, CV and kurtosis) is found at half a standard deviation.
  Use `segment_divergence` for location shifts.
* **Matrix profile cannot see an isolated spike in white noise, at any height.**
  z-normalisation removes amplitude, and noise alone supplies similar one-point shapes.
  It finds shape anomalies in *structured* series. Use a prediction test or drift
  detector for level shifts in residuals.
* **At `n = 50`, ECOD and COPOD refuse** every row, because 50 is below `min_support`
  (100). The `> 4` in that column means "not tested", not "not powerful enough".
* **Bisection resolution is `max_effect / 128`.** For the heavy-hitter detector that is
  0.004, which is why `n=3000` and `n=20000` read the same.

## 7. Versions and replay

`VERSION` is semantic. `Lineage.detector_version` holds
`major×1,000,000 + minor×1,000 + patch`, which is lossless and monotone.
`tests/test_registry.py` runs each detector's golden scenario (`tests/_detect_scenarios.py`)
and hashes the result, with floats rounded to 10 significant figures. It compares the
hash with `tests/behaviour_pins.json` and fails if:

* the hash changed but the version did not ("bump it"), or
* the version changed but the pin did not ("re-pin").

Each scenario is built from the shared golden fixtures or from `godwit_sketch.deterministic`
hashes, never from numpy streams, so a numpy upgrade does not move a pin. The settings
digest is part of every finding, so changing a default setting also moves the hash.
`test_the_pin_notices_a_behaviour_change` proves the mechanism works.

## 8. Refusal vocabulary

| Reason | Meaning |
|---|---|
| `thin_sketch` | Population below `min_support`. This is where spurious findings are manufactured. It is also used for a metric that cannot be computed (`metric:<name>`). |
| `thin_baseline` | Too few reference windows, or too few rows in them. |
| `no_baseline` | The policy selected nothing. |
| `incomparable` | Different codecs, keys hashed under different keys, or parameters that cannot merge. |
| `unsupported_sketch` | This detector does not read that codec. |
| `irregular_series` | A seasonal baseline was asked for on unevenly spaced windows. |
| `gap` | The current window received no data. That is a pipeline issue, not drift. |
| `too_few_peers` | Segment divergence or scoring had too few comparable segments or rows. |

Refusals carry no values. The subject is our label: `segment:<segment key>`,
`metric:<name>`, `peers:<count>`.

## 9. Known limits

* **The contract `Detector` protocol takes one baseline bundle and no spec.** Through
  `BundleDetector`, seasonal and trailing baselines are unreachable and `graph_anomaly`
  always refuses. See `CR-A7-detector-cannot-see-history-or-spec`.
* **`correlation_shift` needs Moments of row-wise pair sums.** No probe produces those
  today. The detector is complete and tested, but has no producer.
* **`graph_anomaly` degree tails need per-entity degrees** (`degrees_partitioned_by_entity`
  in godwit-sketch). Without them the two tail metrics refuse on every run.
* **GraphDegree does not declare its key mode** (`CR-A6-graph-degree-hides-its-key-mode`).
  `same_keying` therefore cannot tell a hashed graph from a plain one. Collectors are
  compared within one probe's series, where the keying is constant.
* **Heavy-hitter share tests are compositional.** When PT rises from 3% to 18%, US falls,
  and US's fall is reported too. The golden test asserts that the strongest finding is
  PT, and that US is never reported *rising*.
* **KLL-based tests lose power at large n** (§4). A `cdf_grid` does not change this.
  Larger `k` does.
* **ECOD/COPOD are rank-based.** An outlier cannot score more than `-log(1/n)` per
  feature, and correlated features (mean, sd and sum) count three times. A pure location
  shift of one row is invisible to them (§6). With 40 rows and alpha 0.05, exactly two
  rows are emitted per run.
* **Matrix profile has no p-value.** A valid null needs random surrogate series, and
  surrogates need randomness. Its thresholds are calibrated on white noise, where it
  cannot see isolated spikes (§6). On structured series it needs a recalibrated
  `discord_ratio`, and on a raw seasonal series the season is the motif.
* **Emerging divergence for distributions is a filter, not a test.** For Moments and
  NullRate, emerging divergence is a genuine difference-in-differences z test. For
  categorical and KLL panels, the current divergence is tested and emitted only if the
  baseline panel showed none.
* **No Isolation Forest.** It is not mergeable, not incremental, and its randomness
  conflicts with invariant 7. The brief allows it as an optional comparator; it was not
  needed.
