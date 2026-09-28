# godwit-replay

**Owner:** A4 · **Layer:** none — this package is the adversary of every other layer

> **Part of this package runs in the DATA PLANE.** `datasets`, `split`, `baseline` and
> `prediction` read customer rows, write Iceberg tables and train models. `driver`, `scoring`,
> `verdict` and `diff` see only statistics. The seam is `SnapshotMetadata`: everything before
> it reads files, everything after it reads numbers.
>
> **Everything this package writes to a file or prints to a terminal is an egress** and is
> audited as one before it is rendered. A verdict report is a document a human reads, which is
> precisely what invariant 2 is about.

---

## Why this package exists

The only honest evidence that Godwit works is this: replay N months of real history, and show
that the system would have surfaced a known event before it was actually caught, without being
told what to look for. Everything else is assertion.

That is why this exists early, before the interesting parts are built. It is the only thing
that can tell you they are wrong.

This package will not make anyone's numbers look better. It builds the expert baseline that
A13 is graded against, so A13 cannot grade its own work. It fails a run that leaks. It fails a
run that saw the future. It prints "the thesis is not supported" in its own output when the
review says so, and the sentence is not softened anywhere in the codebase.

---

## The five deliverables, and where each one lives

| Deliverable | Module | The thing worth knowing |
|---|---|---|
| A virtual clock, plus a guard that catches wall-clock reads | `clock.py` | The guard patches *other packages'* module namespaces and is tested against `godwit_contracts.common`, not against a toy |
| Snapshot-ordered replay driver | `driver.py` | Two digests, for two different questions. Future knowledge fails the run |
| Public dataset loaders | `datasets.py` | Three of the four label delays are **fabricated** and every one of them says so |
| Discovery and prediction scoring | `scoring.py`, `prediction.py`, `metrics.py` | Precision is reported with the coverage it was computed over. Time-to-detection is the headline |
| Champion/challenger and the kill criterion | `diff.py`, `verdict.py`, `cli.py` | `godwit-replay verdict --dataset nyc-tlc --months 12` |

Plus `leak.py` (the egress audit the harness runs on itself), `harness.py` (end to end),
`baseline.py` (the expert baseline) and `errors.py`.

---

## The command

```
godwit-replay datasets                                  # every dataset and its assumptions
godwit-replay verdict --dataset nyc-tlc --months 12     # the kill criterion
godwit-replay diff --dataset golden-drift --challenger-seed 99
godwit-replay baseline --dataset ieee-cis               # build and record the expert baseline
godwit-replay verify-baseline --dataset golden-classification
```

Exit codes: `0` passed, `1` failed (a leak, future knowledge, or a baseline that did not
reproduce), `2` the dataset's raw files are absent. **A failing run still prints its report**,
because the failure is the evidence.

`--as-of` defaults to the last instant in the dataset's own history, not to now. Two runs over
the same data therefore produce the same report timestamp, which is what makes them
comparable. There is no wall-clock read anywhere in the package.

---

## THE LABEL-TIME ASSUMPTIONS: READ THIS BEFORE QUOTING A NUMBER

Three of the four public datasets have no label timestamp. A chargeback lands sixty days after
the transaction; none of these files says when anybody learned anything. A delay had to come
from somewhere, and where it came from is recorded on every dataset.

**A fabricated delay that looks real is worse than no delay at all.**

| Dataset | Event time | Label | Delay | Fabricated? |
|---|---|---|---|---|
| `ieee-cis` | `TransactionDT` seconds after an anchor | `isFraud` | 60 days | **anchor and delay both fabricated** |
| `paysim` | `step` hours after an anchor | `isFraud` | 24 hours | **anchor and delay both fabricated** |
| `telco-churn` | derived from the real `tenure` column, before an anchor | `Churn` | 30 days | **anchor and delay both fabricated** |
| `nyc-tlc` | `tpep_pickup_datetime` | none | n/a | no labels at all, which is the point |
| `golden-drift` | `created_at` | none | n/a | in-repo fixture |
| `golden-classification` | `event_time` | `label` | in the data | **real** — the fixture ships `label_time` |

Specifics, so nobody has to go digging:

* **IEEE-CIS.** `TransactionDT` is an integer offset from an undisclosed reference. The anchor
  used here is `2017-12-01`, which is the community's consensus reading and **is not stated in
  the data**. Sixty days is the card-network chargeback window: a plausible order of magnitude
  and not a measurement.
* **PaySim.** `step` is an hour index. Anchor `2020-01-01`, chosen. Twenty-four hours stands for
  a same-day mule investigation.
* **Telco churn.** The file has no dates at all. Churn is a state, not an event. Event time is
  derived from the real `tenure` column — an account with tenure 24 started before one with
  tenure 3 — so **the ordering history replays in is real**, and only its position on a
  calendar is ours. Thirty days stands for one billing cycle.
* **NYC TLC.** Real timestamps, no labels, genuine multi-year drift including regime changes.
  This is the unsupervised case and the one the kill criterion is meant to run on.

`godwit-replay datasets` prints every one of these caveats. They are also echoed into each
verdict report's "Read these before you read a number" section, and `DatasetSpec.caveats`
generates them from the spec rather than from prose, so a new dataset cannot arrive without
them. `test_datasets.py::test_every_fabricated_assumption_is_marked_and_explained` enforces
it.

**Raw files are not redistributed.** Nothing downloads anything, nothing ships a copy. Put the
files under `$GODWIT_REPLAY_DATA` (default `./data/replay/<dataset>`) and the loader finds
them; leave them out and it refuses, naming the files and their origin. It never substitutes a
synthetic stand-in, because a synthetic dataset presented as a public benchmark is a lie that
passes CI.

---

## How a dataset becomes a replay

1. **Two tables, not one.** The *event* table gets the label column removed from its Iceberg
   schema entirely. The *label* set is built separately with `event_time` and `label_time`.
   Dropping the column is not tidiness — it is the only structural guarantee that a handler
   cannot reach a label by reading the table, whatever it does with its budget. Labels reach a
   handler through `LabelSet.visible_as_of` and nowhere else.
2. **One commit per period.** One Iceberg commit is one snapshot is one replay step. The period
   is a property of the dataset (`month` for IEEE-CIS and TLC, `day` for PaySim, one commit per
   file for the fixtures), because it sets the resolution of every time-to-detection number.
3. **The history is re-timed.** An Iceberg snapshot's `committed_at` is the wall-clock moment
   the loader ran: different on every machine, nothing to do with the data. `harness.retime`
   replaces it with the instant the *data* says that period closed. Without this,
   `Candidate.created_at` would be a clock reading and the driver would — correctly — reject
   it as future knowledge.
4. **Metadata only.** `read_history` drives A1's `IcebergAdapter.read_metadata_stats`, which
   reads manifests through the object store and touches no table data. The meter proves it:
   `MeterReading.data_bytes` is a field, and the tests assert it is zero rather than trusting
   the claim.

---

## WHY THERE ARE TWO DIGESTS

This is the part most likely to confuse a reader, so it is worth the paragraph.

`ReplayRun.digest` is **strict**. It includes candidate ids. A candidate id hashes the Iceberg
snapshot id, and Iceberg mints a fresh snapshot id on every commit — so two *separate
materialisations* of the same data produce different strict digests for the same finding.
Within one materialisation, the strict digest is exactly the acceptance criterion: replay
twice, compare, any difference at all is a bug.

`ReplayRun.content_digest` is **portable**. Step index, period key, segment key, detector,
detector version and the statistics, rounded to twelve decimal places. Every identifier a
reload would renumber is excluded. This is what a champion/challenger diff compares across
arms and what CI can assert against a recorded value.

Observed, across two separate `godwit-replay verdict --dataset golden-drift` invocations that
each materialised the fixture afresh:

```
run digest      rpl_9a14819c68499c2b1e0c7302e98166b3   →  rpl_e83b5629e095fc9d5b1c04c8c4a316fb
content digest  rpc_e9c62381bdd912451b9be3cf56251c81   →  rpc_e9c62381bdd912451b9be3cf56251c81
```

Neither digest includes a commit time. Twelve decimal places rather than seventeen: a float
that differs in its last bit between two BLAS builds is not a behaviour change, and a digest
that claimed otherwise would cry wolf on every upgrade.

---

## The clock guard, and what it cannot see

`datetime.datetime.now` lives on a C type and cannot be patched in place. What can be patched
is the name each module reached for. So `forbid_wall_clock()` walks `sys.modules` and, in every
module whose name starts with `godwit_`, replaces:

* an attribute that **is** the `datetime` module (`import datetime as _dt`; `_dt.datetime.now()`)
* an attribute that **is** `datetime.datetime` or `datetime.date` (`from datetime import datetime`)
* an attribute that **is** the `time` module or one of its clock functions
* an attribute that **is** the `random` module or one of its module-level functions, which draw
  on the shared unseeded generator

The `datetime` replacement is a class whose metaclass forwards `isinstance`, `issubclass`,
construction and every non-forbidden attribute, so `isinstance(value, _dt.datetime)` inside
`godwit_contracts.segment` keeps working while `_dt.datetime.now()` raises
`WallClockAccessError`. A seeded `random.Random(seed)` stays reachable; only the global
convenience functions are blocked.

The driver holds the guard around every `handler.observe` call. A handler that reads a clock
raises **out of the driver** rather than producing a verdict: a component reading a clock is a
code defect, not a run outcome, and turning it into a verdict would let the defect ship.

**Limits, stated rather than hidden.** A module imported after the guard is entered is not
patched. `godwit_replay.clock` itself is exempt — it holds the real references the guards
forward to, and patching its own `_dt` recurses until the stack runs out. C extensions that
read a clock internally (LightGBM's own timers) are invisible to this and always will be; the
determinism tests are what actually prove those do not influence output. Nothing outside
`godwit_` is touched, so the guard has no global side effects and pytest's own timing is
unaffected.

---

## Scoring: the three numbers and the one that matters

### Discovery

* **precision@k for k in {10, 25, 50, 100}, over label-covered segments only.** A ranked list
  contains confirmed items, rejected items, and items nobody has looked at. Scoring the third
  kind as wrong makes the number meaningless; scoring it as right makes it a lie. So the
  ranking is restricted to segments the truth set has an opinion about, and
  `considered_at_k` reports how many that was. **A precision@50 over four covered items is
  reported as being over four items.** With no ground truth at all, precision is `NaN` over
  zero — not 0.0, not 0.5.
* **Time-to-detection — the headline.** Signed seconds between when the world knew and when we
  surfaced it. Negative means we were ahead, which is the point of the product. Where the
  dataset's delay is fabricated, `time_to_detection_is_fabricated` travels with the number and
  the report prints `<-- the reference instant is FABRICATED for this dataset` on the same
  line.
* **Novelty rate**, against `naive_threshold_keys`: a deliberately stupid rule that flags the
  whole table when the row count moves by more than 0.5 in log units, plus any column more than
  half null. Anything Godwit finds that this also finds is not novel.
* **Cost per confirmed pattern.** Reported in dollars *and* in bytes scanned, because the
  metadata tier costs no money and a dollars-per-pattern of zero is uninformative.
* **Stability.** "Two identical runs agree exactly" is in the objective function, so it is a
  recorded field on the score, not only an assertion in a test. A run that is not reproducible
  has no precision, because the number would be different tomorrow.

### Prediction

AUC, PR-AUC, precision@k and recall@k each with a **percentile bootstrap interval** (seeded,
reproducible, recorded with its resample count); expected calibration error and Brier on
probabilities; slices by time and by segment with small-cell suppression counted rather than
silently applied.

The metrics are implemented in numpy here rather than imported. Four reasons: tie handling is a
correctness question (average ranks are the only rule under which `auc(y, s) + auc(y, -s) == 1`,
and a property test pins that identity); a scorer that shares a dependency with the thing it
scores can share a bug with it; every resample draws from an explicitly seeded generator; and
it is two hundred lines.

`EvaluationReport` has no field for an interval, so `to_evaluation_report` flattens the bounds
into `<metric>_ci_low` / `<metric>_ci_high` keys. That is a workaround and it is filed as
`CR-A4-evaluation-report-has-no-intervals`, not patched.

---

## The expert baseline

Built here so A13 cannot grade its own work.

"Tuned" is a reproducible procedure, not an adjective: a fixed four-candidate grid, searched on
a validation slice carved from the *training* half by a seeded permutation, with the grid and
the winner both recorded. IEEE-CIS gets its own deeper grid because 590,000 rows and 393
columns reward capacity.

**What the baseline deliberately does not do**, because each of these would beat the honest
version and be worthless:

* **No target encoding, anywhere.** Categoricals get *frequency* encoding, which cannot
  memorise an outcome. Target encoding a high-cardinality column is invariant 3's whole
  subject.
* **No identifier columns.** `TransactionID`, `entity_id`, `customerID`, `nameOrig`,
  `nameDest` are dropped by name. A string column with more than 512 distinct values is dropped
  rather than encoded, because a frequency encoding of a near-unique column is the same hazard
  in a new hat.
* **No feature named after a value.** One column in, one column out, named after the input, so
  `is_merchant_ACME_CORP` cannot arise.

Training time is charged against `CostBudget.train_seconds` using a **deterministic proxy** —
rounds × rows ÷ 10⁶ — because measuring elapsed time would be a wall-clock read in a prediction
path. It is a budget device, not a performance claim.

`build_baseline` refuses any dataset not marked `is_public`, because the record stores feature
names and a feature name is a leak path. That refusal is what makes the plain `str` type on
`BaselineRecord.feature_names` honest.

### Recorded: `golden-classification`

`packages/godwit-replay/src/godwit_replay/baselines/golden-classification.json`, verified by
`godwit-replay verify-baseline` at **tolerance zero** in CI.

| | |
|---|---|
| library | lightgbm 4.7.0, `deterministic=True`, `force_row_wise=True`, `num_threads=1` |
| seed | 20240117 |
| chosen candidate | `num_leaves=31, learning_rate=0.05, min_data_in_leaf=20, num_boost_round=300` |
| features | `merchant, x1, x2, x3, x4` (5 kept, 5 dropped) |
| train rows | 2,360 labelled |
| held-out rows | 1,200 at a 24.75% positive rate |
| validation AUC | 0.9210 |
| **held-out AUC** | **0.8911** |
| held-out PR-AUC | 0.7518 |

The fixture's `meta.json` records `bayes_auc = 0.9222` — the AUC of the *true* generating
probabilities. The baseline lands 0.031 below it, which is the expected shape of an honest
result. **A model scoring above 0.9222 on this fixture has leaked the generating process into
its features and should be treated as failing**, however good the number looks;
`test_baseline.py` asserts the baseline stays under the ceiling.

Note that two different bars exist for A13 and both should be reported:

* **parity with this baseline**: within 0.02 of 0.8911, i.e. ≥ 0.8711
* **the fixture's own `target_auc`**: `bayes_auc − 0.02` = 0.9022, which is *stricter*

### Not yet recorded: `ieee-cis`

The brief names IEEE-CIS as the prediction benchmark and asks for its baseline to be built,
recorded and reproducible. The code path is complete and tested, including the half-labelled
temporal and random-mask splits. **The record does not exist in this repository because the raw
data is not here and is not redistributable.** Run:

```
GODWIT_REPLAY_DATA=/path/to/data godwit-replay baseline --dataset ieee-cis
```

with `train_transaction.csv` in place, and commit the resulting
`baselines/ieee-cis.json`. Then `godwit-replay verify-baseline --dataset ieee-cis` gates it at
tolerance zero like the other one. Saying this plainly is better than shipping a number
produced from something that is not IEEE-CIS.

---

## The egress audit: the control, and the backstop

The **control** is the typed taint. `audit_object` walks the object graph of whatever is about
to be written and finds every `Tainted` in it *by type*, before anything is rendered. It does
not look at characters; it looks at declarations. That is what catches an Iceberg manifest
bound, a Count-Min heavy hitter and a segment predicate — none of which a scanner would
recognise as sensitive.

Four rules:

| Finding | When |
|---|---|
| `DATA_VALUE_EGRESS` | a value more disclosive than the configured ceiling (default `SCHEMA_NAME`) |
| `UNKNOWN_POPULATION` | a DATA_VALUE or TOKEN with no population, or a non-universe segment with none. Unknown means unsafe |
| `SMALL_CELL` | a known population below the threshold. `Segment X (n=3) is anomalous` re-identifies without quoting anything |
| `FORBIDDEN_STRING` | the backstop fired |

The **backstop** is a substring scan against `tests/golden/pii_torture/expected_leaks.json`,
including sixteen-character prefixes because Iceberg truncates string bounds and a prefix of an
email address is still that person. Matches are reported by position and length only — a
finding that quoted the match would have leaked it into the findings file.

If the backstop fires and the typed arm did not, **that is a bug in the taint typing** and
`assert_passed` says so in its message rather than treating the two arms as equivalent
(`EgressGate` law 6).

**The needle list belongs to its own dataset.** That list contains the words `unknown`,
`general`, `positive` and `negative`, because in that fixture they are column values.
Searching an NYC-taxi report for them fails the run on the sentence "segment population:
unknown". So the backstop is applied only to output derived from the dataset whose values the
list came from, and `_forbidden()` in the CLI returns empty for every dataset in the registry.
Passing one dataset's needles at another dataset's report is a category error, not extra
safety. This was found by running it: the first golden verdict run failed on the word
"unknown".

### What a reviewer sees, and what they lose

A reviewer sees *"the `country` column's category mix moved, p = 0.0004, over 2,000 rows"* and
not *"`country = 'PT'` went from 3% to 18%"*. The second is more useful and it is a row value.
Getting it requires the gate, a redaction policy and a destination, which is A5's job. The
report prints the stable segment key, so a reviewer inside the perimeter can look the segment
up and a reviewer outside it cannot.

`ReplayConfig.reveal_values_in_output` is the deliberately leaky configuration. It renders
values into the report *and* records them in `PatternRow.disclosed` typed honestly as
DATA_VALUE, so the typed arm fires on the type before anything is rendered and the run's
verdict becomes `FAILED_LEAK`. The audit runs either way.

---

## The kill criterion

```
godwit-replay verdict --dataset nyc-tlc --months 12
```

Prints the top twenty patterns with evidence a domain expert can judge in under an hour, plus a
template for marking each one *obvious* / *known* / *non-obvious-and-real* / *wrong*, plus this
sentence, every time, in the tool's own output:

> If fewer than 3 of these come back non-obvious-and-real, the thesis is not supported.

With nothing marked, the tool says `UNREVIEWED: ... the thesis is neither supported nor
refuted — it is untested`. With marks below the threshold it says `NOT SUPPORTED` and repeats
the sentence. Feed marks back with `--marks marks.json` (a JSON object mapping segment key to
mark). `KILL_THRESHOLD` is 3 and `KILL_SENTENCE` is a module constant, so softening it would be
a visible diff.

---

## What a metadata-only replay actually found

Recorded so the next reader does not have to rerun it, and because an early negative result is
the most useful thing this package can produce.

**`godwit-replay verdict --dataset golden-drift`**, three snapshots, A1's six metadata
detectors, 39,745 manifest bytes read and **zero bytes of table data**:

* 1 candidate surfaced: `metadata.bounds_drift` on the `amount` column, segment
  `amount NOT NULL`, score 1.02, from `manifest.lower_bound` / `manifest.upper_bound`
* precision@k: **NaN over 0 covered items**
* reproducible: yes, both digests

The fixture's documented drift is `country = 'PT'` rising from 3% to 18%, and
`country = 'PT' AND status = 'refund'` moving `amount` from lognormal(3.2, 0.7) to
uniform(400, 900). The manifest itself says those are detectable by "category histogram or
heavy hitters" and "KLL quantiles within the segment" — L1 probes, which do not exist yet.

So at L-1 alone, **the harness scores zero covered patterns on a fixture with documented
drift in it.** That is the correct answer and it is worth stating plainly rather than tuning
around. What the metadata tier did find is a real *shadow* of the drift: the `amount` column's
range tripled precisely because one segment's amounts moved. Segment-key matching scores that
as a miss.

This is a genuine methodology problem, not a bug, and it is reported as a third number rather
than folded into either side. `DiscoveryScore.surfaced_on_truth_columns` lists truth-set
columns the run said *something* about without naming the truth segment. Folding that into
precision would overstate the system; ignoring it understates it; so it is reported separately
and a reader decides. On this fixture it is empty, because the golden manifest states the drift
segments' *predicate* columns (`country`, `status`) and not the column whose distribution
moved (`amount`) — see "Known limits".

---

## Testing

`pytest packages/godwit-replay` — 133 tests, no network, no docker, about 90 seconds (most of
it LightGBM).

The ones that carry weight:

| Test | What it establishes |
|---|---|
| `test_golden.py::test_replay_over_the_golden_fixture_is_bit_identical` | acceptance: two runs, identical JSON |
| `test_golden.py::test_a_leaky_configuration_fails_the_run` | acceptance: the leak is caught **by the typed arm**, and the same run with the flag off is clean |
| `test_golden.py::test_the_metadata_tier_reads_no_table_data` | `data_bytes == 0`, measured |
| `test_cli.py::test_verdict_runs_end_to_end_on_metadata_detectors_alone` | acceptance: the command works before Wave 2 |
| `test_cli.py::test_the_audit_can_fail_the_command_not_merely_annotate_it` | the audit gates the exit code |
| `test_clock.py::test_guard_fires_on_a_real_godwit_package` | the guard reaches into code we did not write |
| `test_driver.py::test_a_candidate_naming_a_future_snapshot_fails_the_run` | the bug the harness exists to catch |
| `test_driver.py::test_a_handler_only_ever_sees_labels_that_already_existed` | label counts `[1, 2, 3]` across three steps |
| `test_metrics.py::test_auc_of_negated_scores_is_one_minus_auc` | property: the identity that only holds under average-rank ties |
| `test_baseline.py::test_the_baseline_lands_below_the_fixtures_bayes_ceiling` | a score above the ceiling is a failing result |
| `test_baseline.py::test_rebuilding_reproduces_the_numbers_exactly` | tolerance zero |
| `test_leak.py::test_the_backstop_alone_would_have_missed_a_leak_no_list_knows_about` | why scanning is a backstop and not the control |
| `test_datasets.py::test_the_event_table_does_not_contain_the_label_column` | the structural guarantee |
| `test_datasets.py::test_every_fabricated_assumption_is_marked_and_explained` | no unmarked inventions |

`tests/_replay_support.py` holds handlers that misbehave on purpose:
`FutureSnapshotHandler`, `FutureDateHandler`, `ClockReadingHandler`, and
`GoldenCandidateHandler`, which replays `tests/golden/candidates.json` because A1's metadata
detectors emit only nullary segments and therefore carry no value to leak.

No fixtures were added to `tests/golden`. The existing three were enough.

---

## Change requests filed

Implemented against the contract as written, with `strict=True` xfail tests in
`tests/test_contract_gaps.py`.

| CR | In one line |
|---|---|
| `CR-A4-evaluation-report-has-no-intervals` | On a 1,200-row held-out half the AUC interval is as wide as the 0.02 objective; the report can only carry a point estimate |
| `CR-A4-probe-snapshot-resolution-is-unrecorded` | A probe refused on budget produces no `SketchBundle`, so nothing records which snapshot it resolved. `ARCHITECTURE.md` open question 4 |

---

## Known limits

Nothing here is a TODO. These are things a reader should know before trusting an output.

1. **No IEEE-CIS baseline record is committed.** The code path is complete and tested; the raw
   data is not redistributable. One command with the file in place produces it. Until then the
   0.02 objective on IEEE-CIS is unmeasured, and the golden-classification baseline is the only
   recorded one.
2. **The kill criterion has not been run on NYC TLC.** The command works end to end on a real
   Iceberg table with real metadata detectors; it has been exercised on the in-repo fixture. The
   twelve-month TLC run needs the parquet files. Nothing about the thesis is established until
   a domain expert marks that run's twenty patterns.
3. **Cross-layer credit is under-counted.** The golden manifest names the drift segments'
   *predicate* columns and not the column whose distribution moved, so
   `surfaced_on_truth_columns` is empty on the fixture even though `bounds_drift` found a real
   shadow of the drift on `amount`. Fixing it well needs either a fixture field naming the
   measured column, or hand-written `SegmentTruth.columns_of_interest` entries — which the type
   already accepts.
4. **`--reveal-values` has nothing to reveal through the CLI today.** The only handler is A1's
   metadata detectors, whose segments use nullary operators. The flag changes the config digest
   and produces no finding. The audit *is* proven, by
   `test_golden.py::test_a_leaky_configuration_fails_the_run`, which drives the harness with
   candidates that carry values, and `test_cli.py` pins the CLI limitation so a passing exit
   code is not mistaken for a sleeping audit.
5. **The strict digest is not portable across materialisations.** By design, because candidate
   ids hash Iceberg snapshot ids. Use `content_digest` for anything that crosses a machine or a
   reload. Both are recorded on every run.
6. **The clock guard cannot see inside C extensions.** LightGBM reads a clock internally. That
   does not influence output; the determinism tests are the actual evidence.
7. **The training-cost proxy is not a measurement.** `rounds × rows ÷ 10⁶` charged against
   `train_seconds`. It bounds a runaway grid search and says nothing about how long anything
   takes.
8. **A handler imported lazily inside a hot path escapes the guard**, because the guard
   snapshots `sys.modules` on entry.
9. **Small-cell suppression here is a threshold, not differential privacy.** It refuses to
   report a cell below a count. It makes no formal disclosure claim, and two overlapping
   segments each above the threshold can still narrow an individual down.
10. **`naive_threshold_keys` is my own invention.** Novelty is measured against it, so the
    novelty rate is only as meaningful as that rule is representative. It flags the whole
    table on a row-count move and any column more than half null. On the golden fixture it
    fires, because cumulative Iceberg appends double the row count — which is correct
    behaviour and worth knowing when reading a novelty number.

---

## Reading order

1. `clock.py` — the clock, and the guard that proves nothing read the real one.
2. `driver.py` — snapshot-ordered replay, and why there are two digests.
3. `datasets.py` — the four public datasets and, more importantly, which assumptions are
   fabricated.
4. `leak.py` — the audit the harness runs on itself.
5. `verdict.py` — the kill criterion, printed unsoftened.
6. `baseline.py` — the number A13 is graded against.
