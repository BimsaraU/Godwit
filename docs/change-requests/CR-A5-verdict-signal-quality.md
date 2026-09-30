# CR-A5-verdict-signal-quality

**Filed by:** A5 (`godwit-guard`), at the human owner's direction
**Against:** `godwit-source` (A1, `detectors.py`) and `godwit-replay` (A4, `verdict.py`)
**Status:** **applied** — the human owner asked for these fixes to be made rather than only
filed. A1 and A4 should review and either adopt or revert.

## The problem

The pre-Wave-2 kill criterion (`godwit-replay verdict --dataset nyc-tlc --months 12`) was
run on the full 2024 NYC TLC yellow-taxi data (41,169,664 trips). Its top 20 could not be
judged by a domain expert:

1. **Eighteen of twenty rows were one phenomenon.** Five columns (`passenger_count`,
   `RatecodeID`, `store_and_fwd_flag`, `congestion_surcharge`, `Airport_fee`) have
   identical null counts every month — one block of trips missing its optional fields —
   and each column re-fired in several months. No grouping, no de-duplication.
2. **Every score was exactly 300.** `DeltaVerdict.score` is `-log10(max(p, 1e-300))`;
   past |z| ≈ 37 the p-value underflows and every strong finding ties. The ranking inside
   the top 20 meant nothing.
3. **Whole-table comparisons diluted real changes.** On an append-only table the null
   rate of *new* rows went from 6.2% (Feb) to 11.9% (Mar); the cumulative table rate the
   detector compared moved from 8.9% to 9.3%.
4. **Significant but trivial moves fired.** With tens of millions of rows a 0.4-point
   change has p = 0. There was no effect-size floor.
5. **Nothing said what a pattern was.** A reviewer saw a segment key, a redacted
   predicate and raw statistics.

## What was changed (minimal)

### godwit-source (A1) — `detectors.py`, `DETECTOR_VERSION` 1 → 2

* `DeltaVerdict.score` uses an underflow-free `-log10 p` from the z-score (Mills-ratio
  asymptote past the double-precision floor). Scores keep ranking beyond |z| = 37.
* `DetectorConfig.min_effect_h` (default 0.1, Cohen's h): proportion detectors
  (`null_rate_shift`, `ndv_ratio_shift`) require it on top of `max_p_value`.
* `null_rate_shift` on an append-only table compares **per-period increments** (rows and
  nulls added in the latest period vs the period before). Tables that were rewritten or
  shrank fall back to the snapshot view, so every existing test still holds. NDV is not
  additive and keeps the snapshot view.
* New public helper `cohens_h`.
* Tests: `test_null_rate_shift_compares_periods_not_cumulative_totals`,
  `test_null_rate_shift_ignores_a_significant_but_trivial_move`,
  `test_scores_keep_ranking_past_the_underflow_point`.

### godwit-replay (A4) — `verdict.py`

* `group_candidates`: candidates from the same detector at the same snapshot with
  identical statistics are folded into one row (columns moving in lockstep); a segment
  already shown is not shown again.
* `PatternRow` gains `label` (one deterministic sentence from statistics and column
  names — no LLM, no predicate value), `triage` (the system's own hypotheses:
  co-missing block, extreme value, persistent, one-off), `recurrences` and `merged`.
  The markdown report renders them.
* Kill-criterion counting is unchanged: only human marks count. The triage is a
  hypothesis for the reviewer, never a mark.
* Tests: `tests/test_grouping.py`.

## Effect on the NYC run

| | before | after |
|---|---|---|
| candidates surfaced | 60 | 20 |
| distinct rows in the top list | 7 among 20 | 9 among 9 |
| score ties at the top | 20-way tie at 300 | none |
| co-missing block | 18 rows, cumulative 8.9% → 9.3% | 1 row, new rows 6.2% → 11.9%, "5 columns go null together" |

## Who else this affects

* **A1** — detector output changes for identical input, hence the version bump. Stored
  lineage from v1 remains replayable against v1 code.
* **A4** — `PatternRow` has four new defaulted fields; `ReplayReport` JSON gains them.
* **A7** — should adopt the same effect-size floor and underflow-free scoring for L2.
* **A3** — the report's grouping is a stand-in for the store's dedup; once the harness
  routes through `PatternStore`, `group_candidates` should defer to it.

## What remains, honestly

On NYC TLC the free metadata tier now yields one candidate worth expert time (the
co-missing block) plus bound jumps that are, as the triage says, mostly single outliers.
Metadata bounds are extrema, and extrema track outliers. Segment-level discovery needs
the probe + L2 path (A6/A7). The gate outcome, the Kaggle benchmark and a proposal for
sequencing Wave 2 are in `CR-A5-kill-criterion-needs-a-probe-tier`.

## Decision

_Left blank. A human fills this in._
