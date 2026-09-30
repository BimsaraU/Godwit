# godwit-replay -- HANDOFF

**Owner:** A4
**Plane:** both — `datasets`, `split`, `baseline`, `prediction` are **data plane**;
`driver`, `scoring`, `verdict`, `diff` are control plane. The seam is `SnapshotMetadata`.
**Purpose:** Replay history as if it were arriving live, score what came out, and refuse to
let a change ship that made things worse.

> Everything this package writes to a file or prints to a terminal is an **egress** and is
> audited as one before it is rendered. Read `docs/packages/godwit-replay.md` first — it is
> the long version of this file and it contains the numbers.

## Status

Complete and green. `ruff`, `ruff format --check`, `mypy --strict` and `pytest` all pass from
a clean checkout, with no suppressions anywhere in the package.

133 tests, no network, no docker, roughly 90 seconds (most of it LightGBM).

### Acceptance criteria

| Criterion | Status |
|---|---|
| Replay over a golden fixture is bit-identical across two runs | **done** — `test_golden.py::test_replay_over_the_golden_fixture_is_bit_identical` compares full JSON, not just a digest |
| A deliberately leaky configuration is caught and fails the run | **done** — `test_golden.py::test_a_leaky_configuration_fails_the_run`, and the assertion is that the *typed* arm fired, not the string scan |
| The verdict command runs end to end on a real public dataset using only metadata detectors | **partly** — the command works end to end against a real Iceberg table driven by A1's six metadata detectors, proven on the in-repo golden fixture (`test_cli.py::test_verdict_runs_end_to_end_on_metadata_detectors_alone`). The NYC TLC run needs the parquet files, which are not redistributable. Nothing about the dataset path is stubbed; `godwit-replay verdict --dataset nyc-tlc --months 12` will run once the files are present |
| The IEEE-CIS expert baseline is built, recorded and reproducible | **partly** — the builder, the half-labelled splits and `verify-baseline` at tolerance zero are complete and tested. The recorded artifact is `baselines/golden-classification.json`, because IEEE-CIS raw data is not in this repository. One command with the CSV in place produces `baselines/ieee-cis.json` |

Saying "partly" twice is deliberate. Both gaps are the same gap — this repository holds no
copies of non-redistributable public datasets — and a harness whose job is honesty should not
round that up.

## What another agent needs from this package

```python
from godwit_replay import ReplayConfig, replay, run_dataset, build_report, score_discovery
```

* **To replay your layer**, implement one method: `observe(view: ReplayView) -> tuple[Candidate, ...]`.
  The driver builds the view, so you cannot see a future snapshot, a future schema or a future
  label — `view.labels` is already filtered by `LabelSet.visible_as_of`. Anything you emit that
  names a snapshot outside `view.visible_snapshot_ids`, or is dated after `view.now`, fails the
  whole run with `FutureKnowledgeError`.
* **The clock guard is active around your `observe`.** Reading wall time raises out of the
  driver rather than becoming a verdict.
* **To be graded against the expert baseline** (this is A13): `load_baseline(dataset)` gives
  the record and `record.comparison_note()` gives the sentence that must travel with any
  comparison. `PredictionScore.within_objective` is the 0.02 answer.
* **To check your own output is safe to print**: `audit_egress(artifact, small_cell_threshold=...)`.

## Known limits

Full list with reasoning in `docs/packages/godwit-replay.md`. The ones that change what you
should believe:

1. **No IEEE-CIS baseline record is committed**, so the 0.02 objective on IEEE-CIS is
   currently unmeasured. `golden-classification` is the only recorded baseline: held-out AUC
   **0.8911**, under the fixture's Bayes ceiling of 0.9222.
2. **The kill criterion has not been run on NYC TLC**, so the thesis is untested, not
   supported and not refuted. The tool prints exactly that.
3. **Three of the four public datasets have fabricated label delays and calendar anchors.**
   Every one is marked in `DatasetSpec`, printed by `godwit-replay datasets`, and echoed into
   every report. A time-to-detection number on those datasets measures our assumption.
4. **At L-1 alone the harness scores zero covered patterns on the golden drift fixture.** That
   is the correct answer: the documented drift needs L1 probes that do not exist yet. The
   metadata tier did find a real shadow of it (the `amount` column's range tripling), and that
   is reported as a separate number rather than folded into precision.
5. **`ReplayRun.digest` is not portable across materialisations** — Iceberg mints fresh
   snapshot ids. Use `content_digest` anywhere that crosses a machine or a reload.
6. **The clock guard cannot see inside C extensions**, and a module imported lazily inside a
   hot path escapes it.
7. **Small-cell suppression is a threshold, not differential privacy.**
8. **`naive_threshold_keys` is my own invention**, so the novelty rate is only as meaningful
   as that rule is representative.

## Change requests filed

Implemented against the contract as written, each with a `strict=True` xfail in
`tests/test_contract_gaps.py`.

* `CR-A4-evaluation-report-has-no-intervals` — `EvaluationReport` cannot carry a confidence
  interval, and on a 1,200-row held-out half the interval is as wide as the objective.
* `CR-A4-probe-snapshot-resolution-is-unrecorded` — a probe refused on budget leaves no record
  of the snapshot it resolved. `docs/ARCHITECTURE.md` open question 4; needs A10 to agree.

## Two things found outside this package, for A2

`pytest packages/godwit-sketch` **intermittently** fails. Two different tests failed on two
different full-workspace runs during this work and neither reproduced on three reruns, which
is what a rare hypothesis search hit looks like. Both predate this package and neither is mine
to fix (universal rule 1), so they are reported rather than patched.

**1. `Moments.skewness` divides by an underflowed denominator.**

```
test_monoid_laws.py::test_merge_order_does_not_change_the_estimate_beyond_the_bound[Moments]
ZeroDivisionError: float division by zero
  godwit_sketch/moments.py:216  ->  math.sqrt(self._n) * self._m3 / math.pow(self._m2, 1.5)
  failing case: parts=[0.0, 0.0, 0.0, 8.116056666782835e-115]
```

Confirmed by hand: that input gives `_m2 = 6.587e-229`, which passes the `self._m2 <= 0`
guard, and `math.pow(6.587e-229, 1.5)` underflows to exactly `0.0`. So the guard does not
cover the case it was written for. `kurtosis()` at line 219 has the same guard and the same
exposure. A guard on the *result* of the power, or on `_m2` against a floor near
`sys.float_info.min ** (2/3)`, would close it.

**2. `KllQuantile` merge commutativity.**

```
test_monoid_laws.py::test_merge_is_commutative[KllQuantile]
AssertionError at test_monoid_laws.py:108
```

Not diagnosed here — it is A2's invariant and A2's sketch. Worth noting that
`docs/change-requests/CR-A2-kll-determinism.md` and `CR-A2-monoid-law-exactness.md` already
exist, so this may be the same known issue surfacing rather than a new one.

## Commands

```
godwit-replay datasets                                   # every dataset and its assumptions
godwit-replay verdict --dataset nyc-tlc --months 12      # the kill criterion
godwit-replay diff --dataset golden-drift --challenger-seed 99
godwit-replay baseline --dataset ieee-cis                # build and record the expert baseline
godwit-replay verify-baseline --dataset golden-classification
```

Exit `0` passed, `1` failed, `2` raw files absent. A failing run still prints its report.
