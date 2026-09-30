# CR-A5-kill-criterion-needs-a-probe-tier

**Filed by:** A5 (`godwit-guard`), at the human owner's direction, after running the gate
**Against:** the Wave-2 plan (programme owner), `godwit-replay` (A4), plus requirements for
`godwit-probe` (A6), `godwit-detect` (A7) and `godwit-context` (A8)
**Status:** proposed. Nothing in this CR has been implemented in any package.

## The rule being tested

> Before Wave 2, run A4's verdict command and have a domain expert judge the output. If fewer
> than three of the top twenty patterns come back non-obvious and real, stop and change the
> thesis. Sixteen more agents will not fix a premise that does not hold.

## What happened

`godwit-replay verdict --dataset nyc-tlc --months 12` ran on full 2024 yellow-taxi data
(41,169,664 trips). The run used the output fixes from `CR-A5-verdict-signal-quality`. The
reviewer's evidence was: every row checked against the raw data, plus 28 public Kaggle
notebooks on the same schema.

**Result at the tier the command runs today (L-1, metadata only): 0 of 3. NOT SUPPORTED.**

| Row | Marked (draft) | Why |
|---|---|---|
| `total_amount` / `fare_amount` / `trip_distance` / `tolls` / `mta_tax` / `extra` / `tip` bounds | obvious | Single extreme records that every notebook filters out |
| 5 columns go null together | known | This block is exactly the Flex Fare rows (`payment_type = 0`). One notebook states it; three chart the yearly Flex Fare share |
| File layout | wrong | Our own loader wrote the files |

This outcome was predictable, and A4's own docs already record the same thing on the golden
drift fixture (0 covered patterns at L-1). Manifest statistics are null counts, extrema, row
counts and NDV. Extrema track outliers. Segment behaviour is not in the manifest.

## Why this is not simply "change the thesis"

The thesis is *discovery from how table statistics change over time*. L-1 is its free subset,
defined by invariant 5 ("metadata first") as a cost filter, not as the discovery engine. To see
whether the premise holds one tier down, a stand-in for a minimal Wave-2 L1 + L2 was run on
the same data:

* **Probe:** per-month category counts for 16 dimensions, in the whole table, per vendor and per
  payment type.
* **Detector:** segment share month over month and against the Jan–Mar baseline, Cohen's
  h ≥ 0.05, −log10 p ≥ 6, minimum cell 20.
* **Grouping:** mirror, lockstep, cross-scope and profile-shift rows are merged.
* **Explained-away:** the detector's own strongest block is conditioned out.

No labels, no LLM, no hand-picked segments.

In its top 20, three rows are verified in the raw data **and absent from all 28 notebooks**:

1. **CMT (vendor 1) Flex Fare trips report zero distance 45–54% of the time in Jan–Mar, then 3%
   from April.** Non-Flex trips stay near 1.8%. This is a silent reporting change in one
   vendor's meter feed.
2. **About 14,000 Curb (vendor 2) Flex Fare rows a month (3–4%) have `fare_amount < 0` and
   `total_amount ≥ 0`.** The fare components do not add up to the total (September: mean fare
   −$1.97, mean total +$2.13). Notebooks drop negative fares without looking at them.
3. **Vendor 6 (Myle) sends only Flex Fare trips.** Every pickup location Jan–Jun is 265
   ("unknown"); locations are real from September. Vendor 7 (Helix) first appears in December.
   Every notebook's vendor mapping lists only 1 and 2.

Two more are for the reviewer to decide: Flex Fare tip share falling from 33% to 11% at Curb
in March, and CMT store-and-forward dropping from 2.2% to 0.8% in November. The remaining rows
are obvious, known or duplicates. The full table with per-row evidence is in
`data/replay/nyc-tlc/verdict/benchmark-vs-public.md` (local, gitignored).

Two observations matter for invariant 5:

* **Metadata worked as a router.** All three findings sit *inside* the segment the L-1 tier
  flagged (the null block, which is Flex Fare). The L-1 tier said where to look; the probe
  tier found what was there.
* **It was not enough on its own.** Finding #3 is in a sub-population too small (2,069 rows)
  to move any manifest statistic.

The draft tally at the probe tier is 3. That is at the threshold, not comfortably over it, and
the marks are an analyst's, not a domain expert's.

## An expert-free check: PaySim with an answer key

To test the premise without waiting for a domain expert, PaySim was seeded with 5 labelled
novel patterns (dev set) and, separately, 5 more written before the final detector ran
(held-out set). The detector's top 20 was then scored against that answer key mechanically.
The full method is in `docs/specs/expert-free-discovery-benchmark.md`. Count of injected
patterns in the top 20 (threshold 3):

| Detector | Dev | Held-out |
|---|---|---|
| Naive: whole table, raw columns | 0 | 2 |
| Probe tier, unsupervised | 2 | **1** |
| Probe tier + label-rate detector | 5 | **4** (3 at 10% label coverage) |

The unsupervised tier found both silent data-quality injections but did not pass. The
label-aware tier passed on held-out data. Scope the thesis accordingly: discovery that uses
the labels as they arrive, which is the Discovery ↔ Prediction loop the brief already
describes. Label-free statistics-watching alone does not pass on this benchmark.

## The smallest sufficient change

1. **Record the L-1 verdict as NOT SUPPORTED for metadata-only discovery.** State in the
   architecture docs that L-1 routes and triages; it does not discover. No contract changes.
   This *is* the thesis change the rule asks for, and it is narrow: invariant 5 stands as a
   cost rule, not as a source of findings.
2. **Split Wave 2 into two parts. Wave 2a is A6 + A7, plus A8 only for explained-away.**
   They deliver a replay handler that runs probes (category histograms, scoped by the
   lowest-cardinality columns) and a share detector over them. A4 adds `--handler probe` to
   `verdict`. This is three agents, not sixteen.
3. **Rerun the gate** with that handler on the same data. A human domain expert marks the
   rows. `KILL_THRESHOLD` stays at 3 and `KILL_SENTENCE` is unchanged. **If fewer than 3,
   stop.** The spike above is not a substitute for that run.
4. **Wave 2b (all remaining agents) starts only after step 3 passes.**

### Requirements the spike showed Wave 2a needs (for A6/A7/A8)

Each of these was needed to get anything a reviewer could use into the top 20:

* **Scoped shares.** Every finding above is an interaction (vendor × payment type). The
  whole-table view hides all three.
* **Grouping.** Four rules were needed: mirror (a two-valued shift is one finding), lockstep
  (identical shares in one scope and month), cross-scope (the same `dim=value` in several
  scopes), and profile shift (three or more dimensions of one sub-population moving in the
  same month). Without these, one phenomenon filled 18 of 20 rows.
* **Explained-away before ranking.** Conditioning out the strongest block removed the mixture
  echoes of Flex Fare (card share, standard-rate share, congestion share). It must *not* be
  applied inside the block's own scope, because that is where findings #1 and #2 live.
* **Effect-size floor, and scores that do not underflow.** Already applied at L-1 in
  `CR-A5-verdict-signal-quality`; A7 should adopt the same.
* **Min cell of 20** on both periods. This also satisfies A5's disclosure rule.

The PaySim benchmark added these:

* **A label-rate detector family (A7).** Compare the labelled-positive rate inside each
  segment, using labels as they arrive after `label_delay`. This family is what made the
  benchmark pass.
* **Rank by a conservative effect size (A7).** Use |h| − 3·√(1/n₁ + 1/n₂), not |h|.
  Otherwise 20-row cells on low-volume periods fill the top 20.
* **Volume-comparable references (A7).** Only compare periods whose volume is within 4×.
* **Episodes, not one row per segment (A7).** A segment that fires on separate occasions is
  separate findings.
* **Group rows by row overlap (A7 with A2).** Use Theta-sketch intersections. One injected
  pattern took 6 of the top 20 because it moved several dimensions in different scopes.
* **Seasonality and volume context (A8).** Hour-of-day and per-period degree bands need
  explaining away.
* **An answer-key benchmark mode (A4).** `verdict --inject <spec>` would seed patterns with a
  hidden `pattern_id` and score the top 20 mechanically, so this check runs in CI rather than
  from local scripts.

## Who this affects

* **Programme owner:** Wave 2 sequencing.
* **A4:** adds a `--handler` option to `verdict`, plus the answer-key benchmark mode.
  `KILL_THRESHOLD` and `KILL_SENTENCE` are unchanged.
* **A6, A7, A8:** the requirements above.
* **A5:** nothing new. Segment predicates from scoped probes carry real values (`VendorID=6`)
  and must go through `Gate.clear` before a reviewer sees them. The spike rendered them only
  because NYC TLC is public data classified NONE.

## What this CR does not claim

* That the thesis holds. It claims the gate as run tested the wrong tier. It also claims one
  run at the right tier, by a stand-in detector with draft marks, landed exactly at the
  threshold.
* That the spike is A7's design. It is 200 lines of DuckDB counting, in
  `data/replay/nyc-tlc/verdict/probe_spike.py` (local).

## Decision

_Left blank. A human fills this in._
