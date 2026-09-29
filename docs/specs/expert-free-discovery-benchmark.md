# Expert-free discovery benchmark: PaySim with an answer key

**Owner:** A5. **Status:** evidence for `CR-A5-kill-criterion-needs-a-probe-tier`.
**Data:** public (Kaggle `ealaxi/paysim1`, 6.36M rows over 31 days, labelled `isFraud`).
Nothing here touches customer data.

## Why

The kill criterion needs a domain expert to mark each pattern *obvious / known /
non-obvious-and-real / wrong*. Until one is available, this benchmark replaces the expert
with an answer key. It seeds PaySim with labelled patterns that the public analyses do not
contain, then scores the detector's top 20 against that key mechanically.

## Method

1. **Obvious and known, taken from public work.** The 10 most-voted PaySim notebooks on
   Kaggle were pulled with `kaggle kernels pull`. Between them they document all of PaySim's
   natural fraud structure:
   * fraud only in TRANSFER / CASH_OUT;
   * zero destination balances;
   * balance-arithmetic errors;
   * fraud flat over time while genuine volume collapses;
   * `isFlaggedFraud` is meaningless.

   So a natural (non-injected) finding confirmed by the labels is scored **known**.
2. **Injected answer key.** Every injected row carries a hidden `pattern_id` that the
   detector never reads. Injection is deterministic, using a fixed multiplicative hash of the
   row index and no RNG.

   **Dev set** (used while developing the detector):

   | # | Pattern | Label | Days | Rows |
   |---|---|---|---|---|
   | 1 | Mule fan-in: 600 new TRANSFERs from fresh origins into 6 accounts | fraud | 12–13 | 600 |
   | 2 | Full-balance drains through PAYMENT (fraud never occurs in PAYMENT naturally) | fraud | 11–16 | 4,009 |
   | 3 | CASH_IN stops updating the originator balance on 30% of rows | not fraud (DQ) | 13–16 | 106,190 |
   | 4 | Structuring: 2% of CASH_OUTs re-amounted to 9,000–9,990 | fraud | 10–16 | 19,651 |
   | 5 | Card testing: 3,000 DEBITs of 1–5 units at night | fraud | 14–15 | 3,000 |

   **Held-out set.** Written before detector v3 was run; the frozen script's sha256 starts
   `a09309f7`. It was never used for tuning.

   | # | Pattern | Label | Days | Rows |
   |---|---|---|---|---|
   | 6 | Cash-out velocity: 200 new origins × 15 CASH_OUTs | fraud | 9 | 3,000 |
   | 7 | Payment diversion: 1% of PAYMENTs go to customer accounts, not merchants | fraud | 12–16 | 6,821 |
   | 8 | TRANSFER leaves the destination balance uncredited on 25% of rows | not fraud (DQ) | 8–10 | 25,284 |
   | 9 | 3% of TRANSFERs re-amounted to exact multiples of 10,000 | fraud | 13–15 | 2,958 |
   | 10 | 4,000 small CASH_INs at night | fraud | 11–12 | 4,000 |

3. **Scoring (replaces the expert).** Each top-20 row is scored as it would be shown to a
   reviewer:
   * **non-obvious-and-real:** rows of one injected pattern explain at least half of the row's
     excess count, on either the current side or the reference side (a pattern ending counts).
   * **known:** not injected, but the fraud labels confirm it (lift ≥ 3 with ≥ 20 frauds, or a
     label-rate finding).
   * **no label signal:** everything else.
   * **Kill criterion:** at least 3 distinct injected patterns in the top 20.

## Detector (a stand-in for A6/A7, not their design)

**Probe.** Per-day counts for 13 dimensions, over the whole table and within each transaction
type:
* type, hour band, and amount in quarter-decade bands;
* first digit of the amount (Benford);
* amount compared with balance;
* four balance-arithmetic flags;
* whether the destination is a merchant;
* fan-in and fan-out bands, computed from each account's per-day degree. This is a
  heavy-hitter probe over the OPAQUE account columns, so no account value is used.

**Detectors.** Two families:
* **Share shift (unsupervised):** each segment's share of its scope. It is compared with the
  previous day and with the last 3 comparable days, where a day only counts as comparable if
  its volume is within 4×.
* **Label-rate shift:** the fraud rate inside each segment, compared the same way. Replay
  delivers labels one period late; this spike ignores the delay.

**Thresholds.** Cohen's h ≥ 0.05, −log10 p ≥ 6, minimum cell 20. Rows are ranked by a
conservative effect size, |h| − 3·√(1/n₁ + 1/n₂), so a 20-row cell cannot outrank a
20,000-row cell.

**Grouping.**
* Episodes: firings more than 2 days apart are separate rows.
* Mirror: both sides of one shift are one row.
* Lockstep: identical shares in the same scope and day are one row.
* Cross-scope: the same segment firing in several scopes is one row.
* Profile shift: three or more dimensions of one sub-population moving on the same day are one
  row.

**L3 stand-in (`--l3`).** Hour of day and per-day degree bands are shaped by that day's own
volume, so they are treated as context (seasonality) rather than as findings.

## Results

Count of distinct injected patterns in the top 20 (threshold 3), with precision@20 in
parentheses.

| Detector | Dev, `--l3` | Dev | **Held-out, `--l3`** | Held-out |
|---|---|---|---|---|
| A4 `verdict`, metadata only (L-1) | 0 of 18 surfaced | – | – | – |
| Naive: whole table, raw columns | 0 (0.15) | 0 | 2 (0.40) | 2 (0.35) |
| Probe tier, unsupervised only | 2 (0.35) | 2 (0.20) | **1 (0.30)** | 1 (0.15) |
| Probe tier + label-rate | 5 (0.90) | 4 (0.75) | **4 (0.90)** | 5 (0.75) |

Held-out, `--l3`, first rank of each pattern:

| Pattern | Unsupervised | + labels |
|---|---|---|
| 6 velocity | 45 | 3 |
| 7 payment diversion | 87 | 40 |
| 8 DQ, destination not credited | 5 | 5 |
| 9 round amounts | 22 | 8 |
| 10 night CASH_IN | 23 | 1 |

**Label coverage.** Real fraud is under-labelled, so the held-out run was repeated with only
part of the injected fraud rows keeping `isFraud = 1`, using the frozen detector:

| Injected fraud labelled | Patterns in top 20 | precision@20 |
|---|---|---|
| 100% | 4 | 0.90 |
| 30% | 3 | 0.85 |
| 10% | 3 | 0.85 |

## What this says

1. **The unsupervised share-shift tier does not pass on its own.** It scores 2 of 5 on dev and
   1 of 5 held out; on held-out data it is worse than the naive baseline. Patterns that touch
   0.5–3% of one transaction type are buried under large, real, benign shifts. PaySim's daily
   volume swings 500×.
2. **It does find silent data-quality failures.** Both non-fraud injections (#3 and #8) reach
   the top 5 without labels. That is the "silent data-quality collapse" use case, and it works.
3. **With labels, the probe tier passes, and passes on held-out data.** It scores 4–5 of 5 at
   full label coverage, and 3 of 5 at 10% coverage, which is at the threshold with no margin.
   This supports the product thesis as stated ("a discovered pattern is a feature";
   Discovery ↔ Prediction). It does not support a pure label-free statistics-watching thesis
   at small effect sizes.
4. **Metadata alone (L-1) sees none of these patterns.** `godwit-replay verdict --dataset
   paysim` over the dev data surfaced 18 candidates: bound jumps in amount, balance and
   account-name columns, plus one row-volume change. None of them is attributable to an
   injection; for example, the daily min/max of `nameDest` is identical with and without the
   injected rows.

## Honest limits

* PaySim is synthetic, and the injected patterns were designed by the same author as the
  detector. The held-out set limits tuning bias but does not remove design bias. For
  example, the probes include balance-arithmetic flags because PaySim has balances.
* Injected fraud is fully labelled, and in segments with almost no natural fraud. That flatters
  the label-rate family; the coverage table is the partial correction.
* This is one run on one dataset, with no variation over seeds or injection sizes.
* One injected pattern often fills several rows: #5 took 6 of the top 20. The row counts use
  distinct patterns, but a reviewer's budget is spent on the duplicates. Grouping by row
  overlap (Theta-sketch intersection, which A2 already provides) is required.
* The scripts are local (`data/replay/paysim/{inject,inject_holdout,discover_frozen}.py`,
  gitignored with the data). Making the benchmark reproducible in CI is a proposed A4 change
  in the CR.
