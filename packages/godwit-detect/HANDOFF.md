# godwit-detect — HANDOFF

**Owner:** A7 **Layer:** L2 **Plane:** control
**Status:** complete. `ruff`, `mypy --strict` and `pytest` pass from a clean checkout.

**This package handles data-derived values.** It runs in the control plane and never
reads a row. But the sketches it reads contain row values: heavy-hitter keys, category
labels, and KLL samples. It emits those values in exactly two places, both typed
`Tainted`: `Finding.identities` and `Attribution.identity`. Treat every output as
something a bank's security team will inspect.

Full reference: **`docs/packages/godwit-detect.md`**. This file is the orientation.

---

## What it does

Ten pure, deterministic detectors. Sketches go in; findings, a test count and refusals
come out. There is no I/O, no clock, no randomness and no LLM, and a test enforces that
by parsing the source.

```
godwit_detect/
  stats.py        chi-square, t, Kolmogorov and normal tails; dispersion; prediction test
  series.py       SketchSeries, ProbeContext, FixedReference / Trailing / Seasonal
  evidence.py     Finding, Measure, Attribution, Refusal, DetectionResult, to_candidate
  base.py         DetectorBase, SeriesDetector, Claim, item_key (the one reveal of items)
  histograms.py   binning strategy, sparse-bin merging, KLL noise model, G / PSI / JS
  drift.py        psi_drift, wasserstein_drift, js_drift
  heavy.py        heavy_hitter_shift
  segments.py     segment_divergence
  correlation.py  correlation_shift
  graph.py        graph_anomaly (fan-in/out, degree tails, mule funnel signature)
  scoring.py      ecod, copod, matrix_profile
  registry.py     REGISTRY by name, semantic versions
  adapter.py      BundleDetector: the contract Detector protocol over a series detector
```

## The five things you need to know

1. **The contract `Detector` protocol cannot express a history or say which segment or
   columns a bundle measured.** The detectors take a `SketchSeries` and a baseline
   policy directly. `BundleDetector` adapts them to the protocol with a fixed
   single-bundle baseline. Filed as `CR-A7-detector-cannot-see-history-or-spec`.
2. **`Finding` is richer than `Evidence`.** It adds direction, window, method, units, a
   reason when there is no p-value, identity-free shape statistics, attribution and a
   settings digest. `to_candidate()` projects a finding onto the contract and drops
   those fields. A11 should consume `Finding`. Filed as
   `CR-A7-evidence-has-no-structured-detail`.
3. **`DetectionResult.tests` is the number of hypotheses a run tested**, including the
   ones that were not emitted. L5 needs that number to control FDR, and a `Candidate`
   cannot carry it.
4. **Every p-value divides out ordinary variation.** Drift detectors scale their test
   statistic by how much the reference windows disagree with each other. Segment
   divergence scales by how much segments ordinarily differ. KLL tests shrink their
   sample size to account for measured sketch noise. Without these corrections, real
   tables fire constantly.
5. **Changing a detector's behaviour requires a version bump.** `tests/test_registry.py`
   hashes each detector's output on its golden scenario against
   `tests/behaviour_pins.json`. The test fails if the hash moves while the version stays
   the same. Regenerate the pins with
   `uv run python packages/godwit-detect/tests/test_registry.py`.

## If you are…

**A10 (orchestrator):** keep the bundle history for each probe key and run detectors on
a `SketchSeries`. Use `Seasonal(period=7, cycles=4)` for daily windows of anything that
people generate. Read `DetectionResult.refusals`: `thin_sketch` and `thin_baseline` tell
you where more data or more history would buy a test.

**A3 (store):** use `DetectionResult.tests` as the per-run family size. p-values are raw.
`Lineage.detector_version` is `major*1e6 + minor*1e3 + patch`.

**A11 (features):** `(segment, columns, method, window.baseline_policy, direction,
effect.name)` is the feature definition. `shape` holds identity-free covariates.

**A5 / A18 (guard, policy):** identities appear only in `Finding.identities` and
`Attribution.identity`, and `Finding.without_identities()` strips both. Segment
predicates still quote values, including the equality predicate that heavy-hitter
entrants get on a plain key. Hashed keys never become predicates.

## Tests

```
uv run pytest packages/godwit-detect     # 137 passed, 5 strict xfails, about 1.5 minutes
uv run python packages/godwit-detect/tests/benchmark_detectors.py --null 1000 --sims 60
```

| File | What it protects |
|---|---|
| `test_properties.py` | purity (property + scenario), no clock/random/I-O in source, seasonality, suppression |
| `test_null.py` | false-positive rate at or below alpha, per detector; conformal scorers exactly at alpha |
| `test_golden.py` | drift_table drift found, US control quiet; PII torture refused or leak-free |
| `test_registry.py` | behaviour-hash pins, semver, lineage encoding |
| `test_detectors.py` | each detector's findings and refusals |
| `test_adapter.py` | the contract `Detector` protocol |
| `test_contract_gaps.py` | the two CRs, as strict xfails |

## Cross-platform test data (2026-10-13)

Two tests failed in Linux CI and passed on Windows. The cause was the test data, not the
detectors. `godwit_sketch.deterministic` and numpy's `lognormal` used the C library's
`exp`/`log`, which differ in the last bit between platforms, and KLL turned that into
different sketches. The data generator is now portable (see godwit-sketch's HANDOFF),
`test_properties._weekly` uses it instead of numpy, and the `wasserstein_drift` pin was
re-recorded for the new scenario data. Its version did not change, because its code
did not change. The weekly seasonal test used to assert zero findings across 14 raw
tests at alpha = 0.05, where chance alone gives 0.7 on average. It now allows three
(the 99.6% binomial bound).

## Known limits

Full list in §9 of the package doc. The ones most likely to bite:

* **Correlation shift has no producer yet.** It needs Moments over row-wise pair sums
  (`x_i + x_j`), and godwit-probe does not schedule those.
* **The graph detector needs at least five reference windows.** Through the contract
  protocol it always refuses. The degree-tail metrics also need per-entity degrees
  (`degrees_partitioned_by_entity`); without them those two metrics refuse.
* **KLL-based tests are conservative on large windows.** Sketch noise, not sampling,
  dominates above a few thousand rows.
* **ECOD and COPOD cannot see a pure location shift of one row**, at any size, because
  they are rank-based and a natural extreme ties with the injected one. They find shape
  changes at 0.3–0.5 sd. At `alpha = 0.05` they emit one row in twenty under the null,
  which is the honest calibration; L5's FDR control filters it.
* **Matrix profile has no p-value and cannot see a spike in white noise.**
  z-normalisation removes amplitude. On structured series it works, but only after
  `discord_ratio` is recalibrated (2.1 for a noisy 12-window cycle).
* **Heavy-hitter share tests are compositional.** When one key's share rises, the others
  fall, and they may be reported falling.
