# godwit-context

**Owner:** A8 **Layer:** L3 (explained-away) **Plane: CONTROL, handles data-derived values**

> **This package never reads a row, but it holds values that came from rows.** Candidate
> segments quote predicate values (leak path 4). Context scopes name customer columns
> (leak path 9). Imported labels are free text: a deploy description, a campaign name,
> an analyst note. All of these stay `Tainted`. A label is `USER_SUPPLIED`, so it is
> `DATA_VALUE`. Everything this package *emits* holds only our ids, context types,
> canonical kinds and derived numbers: `Match`, `RoutingDecision` and every audit
> record. Two `.reveal()` calls exist, both in `_unwrap.py`. One accepts only
> `SCHEMA_NAME`, the other only `DERIVED_STATISTIC`, and each raises on anything else.
> Predicates are compared by the hash of the contract's canonical form, never by value.
> `tests/test_purity.py` enforces this.

No LLM, no clock, no randomness, no billable query. Time is injected as `at`.

---

## 1. Why this layer exists

Most statistical anomalies in production data are boring. A batch reran, a schema
migrated, a campaign launched, it was Easter Monday, a corporate client made its
quarterly transfer. A product that reports these teaches its users to ignore it. This
layer joins every candidate against those reasons, and only the unexplained residual
goes on to L5.

```python
from godwit_context import (
    ContextRouter,
    StoreAuditSink,
    PriorBook,
    HolidaySource,
    BusinessCalendarSource,
    collect_events,
    data_quality_from_candidates,
    PeerObservation,
)

sink = StoreAuditSink(session)  # A3's hash-chained audit ledger
router = ContextRouter(audit=sink, priors=PriorBook.load(sink))
events = collect_events(
    [holidays, business, deploys, campaigns, annotations], start=run_start - lookback, end=run_end
)
events += data_quality_from_candidates(l1_candidates)  # A1 schema migrations
decisions = router.route(candidates, events=events, peers=peer_observations, at=now)
session.commit()

for d in decisions:
    d.route  # EXPLAINED or PROCEED
    d.explanation  # the attached Match when EXPLAINED, else None
    d.matches  # EVERY aligned explanation, strongest first
```

---

## 2. Context sources

A source is anything with `name` and `events(start=, end=) -> tuple[ContextEvent, ...]`
(the `ContextSource` protocol). Deployments add their own.

| Source | What | Notes |
|---|---|---|
| `parse_deploy_webhook(payload)` | deploys, releases, rollbacks | `deployed_at`/`started_at`, `finished_at`, scope fields |
| `import_records(records, context_type=, origin=)` | generic API import | campaigns, market/macro feeds, pipeline failures, late partitions |
| `import_csv(text, ...)` | the same, from CSV | header row names the fields |
| `StaticSource(name, events)` | holds an imported list | dedups by event id |
| `HolidaySource({jurisdiction: [source_ids]})` | public holidays | §3 |
| `BusinessCalendarSource([BusinessCalendarSpec])` | month, quarter and fiscal year end, payroll, settlement | business days in the source's own jurisdiction |
| `data_quality_from_candidates(cands)` | A1 `metadata.schema_change` → DATA_QUALITY | the event records `derived_from`, so it never explains itself |
| `AnnotationBook(sink).annotate(...)` | analyst annotations | permanent, audited |

**Import fields:** `start` (required, ISO-8601 *with* timezone), `end`, `kind` (plain
identifier), `source_ids` and `columns` (list, or `;`-separated; empty `source_ids` means
global), `segment` (`col=value&col=value`, string values), `label` (free text, tainted),
and `id` (the upstream id; only its hash is kept). An import error names the field and
never echoes the value, because an error message is a log line.

**Scope** is what an event touches: sources, plus optional columns or segments inside
them. A deploy that only changed the refund pipeline should say so. A deploy scoped to
a whole source explains less than one scoped to its columns (§4).

## 3. Holidays

Holidays are rules, not a downloaded list. Each holiday is a date rule (fixed date,
n-th weekday, or Easter-relative under the Western or the Orthodox computus) plus an
observance rule:

- `ACTUAL`: the holiday never moves (DE, FR, GR).
- `NEAREST_WEEKDAY`: Saturday moves to Friday, Sunday to Monday (US federal, OPM).
- `NEXT_FREE_WEEKDAY`: UK substitute days roll forward past each other. Christmas on a
  Saturday plus Boxing Day on a Sunday gives Monday 27th and Tuesday 28th.

Regions inherit from their country (`DE-BY` = `DE` + Epiphany, Corpus Christi,
Assumption, All Saints). One-off holidays and one-off moves are data: the jubilees, the
2022 state funeral, the 2023 coronation, VE Day 2020.

**When a holiday is moved, both days are emitted.** The actual day changes behaviour
(shops shut). The observed day changes operations (banks shut, settlement shifts).
Either one can explain a change. US New Year on a Saturday is observed on 31 December
of the previous year, and it appears there.

Built-in: `US`, `GB-ENG` (alias `GB-WLS`), `GB-SCT`, `DE`, `DE-BY`, `DE-BE`, `FR`,
`FR-57/67/68` (Alsace-Moselle), `GR`. Each is tested against published dates in
`tests/test_holidays.py`. Events are local midnight to midnight in the jurisdiction's
timezone, converted to UTC.

---

## 4. Matching: a strength, never a boolean

```
strength = temporal × overlap × (0.3·prior + 0.3·specificity + 0.4·corroboration)
           × 0.25 if the counterfactual downgraded it
```

Each component is stored on the `Match`, so "why was this suppressed?" can be answered
without a debugger.

**temporal.** This is 1.0 when the candidate's window meets the event. Within the
type's `lead` (anticipation) or `lag` (delay), the credit decays with `half_life`.
Beyond them it is 0.

| Type | lead | lag | half-life | Why |
|---|---|---|---|---|
| DEPLOY | 0 | 2d | 12h | a deploy explains from its own time, never before |
| CAMPAIGN | 1d | 7d | 2d | traffic arrives hours to days after launch |
| HOLIDAY | 2d | 2d | 1d | pre-holiday shopping, post-holiday catch-up |
| BUSINESS_CALENDAR | 1d | 3d | 1d | settlement lands after month end |
| DATA_QUALITY | 0 | 3d | 1d | a broken pipeline shows in the next windows |
| MARKET | 0 | 3d | 1d | |
| ANNOTATION | 0 | 0 | 1h | an analyst's window means exactly that window |

A candidate's window is `[created_at − span, created_at]`, where the span comes from
`MatchPolicy.window_by_source` or `default_window` (1 day). The contract carries only
`created_at`; see `CR-A8-candidate-has-no-window`. `route(..., windows=)` overrides it.

**overlap.** This measures whether the event touches what changed.

| Tier | Score | Meaning |
|---|---|---|
| SEGMENT | 1.0 | event names this segment, or one it refines (predicate-hash subset) |
| COLUMN | 0.9 | event names a column this candidate is about |
| SOURCE | 0.8 | event covers the whole source |
| COARSER | 0.7 | event names a sub-segment of this candidate: it explains part of it |
| GLOBAL | 0.6 | event covers every source |
| OUT_OF_SCOPE | 0 | same source, other columns or segments |
| DISJOINT | 0 | other source |

Temporal and overlap are gates. An event that did not happen then, or did not touch
this, explains nothing, however good its history.

**prior.** This is learned context (§6).

**specificity.** Narrow and short beats broad and long. The breadth score runs from
segment 1.0 down to global 0.3, then is divided by `1 + 0.5·ln(n_sources)` and by
`1 + days/30`. A three-month global campaign "explains" everything a little, and so it
explains nothing much.

**Competing explanations are all kept.** `decision.matches` holds every aligned event,
ordered by (strength desc, event id). The winner is attached. The rest stay as context.

---

## 5. The counterfactual check

> A deploy at 14:00 on source A lines up perfectly with a refund spike on A. If sources
> B, C and D, which the deploy never touched, spiked the same way at the same time, the
> deploy did not cause it.

**Comparable peers** have the same detector family (the sorted evidence kinds, as A3
dedups on) and the same segment *structure* (predicate columns, not values). They were
observed inside the candidate's window, and they are not the candidate itself.

A peer is **untouched** if the event's scope does not reach it (tier `OUT_OF_SCOPE` or
`DISJOINT`). It has **changed** if its effect has the same sign as the candidate's and
at least half the candidate's magnitude.

| Verdict | Rule | Effect |
|---|---|---|
| CONTRADICTED | `untouched_rate ≥ 0.5 × touched_rate` (the candidate counts as touched and changed) | corroboration 0, strength × 0.25 |
| INCONSISTENT | the event touched ≥ 2 *other* comparable peers and < 25% of them moved | corroboration 0, strength × 0.25 |
| UNTESTABLE | no effect size, or < 3 untouched peers observed | corroboration 0.5 |
| SUPPORTED | otherwise | corroboration 1.0 |

The two halves check different things. CONTRADICTED catches a bigger cause: things
outside the scope moved too. INCONSISTENT catches a cause that was not this cause:
things inside the scope did not move. "A holiday closed every shop in the country"
does not explain one shop's spike when the rest were flat.

**Confounded peers are excluded.** If an untouched peer is touched by another aligned
event of the *same type*, it is no control. On New Year's Day a German source is
untouched by the US holiday but touched by its own. Without this rule the US holiday
would be "contradicted" by Germany's drop. The excluded count is recorded
(`Counterfactual.confounded`).

**Where peers come from.** There are two sources:

1. `PeerObservation` values. These are every hypothesis a detector examined,
   significant or not, and they are the only way to know a segment did *not* change.
   A7's `DetectionResult.tests` holds exactly this. The orchestrator converts it.
2. The other candidates in the batch, which changed by construction. A detector's own
   observation of a segment wins over the batch candidate for the same segment, so
   nothing is counted twice.

Without (1), the check can still contradict, but it can never support. The layer then
explains less, which is the safe way to fail (§7). The contract has no type for (1):
`CR-A8-no-type-for-an-unremarkable-test`.

Tested: `tests/test_counterfactual.py::test_coincident_but_causally_irrelevant_context_is_downgraded`.
In that test a deploy is temporally perfect and in scope. Three untouched sources show
the same spike, so the match is CONTRADICTED, its strength falls below 0.2, and the
candidate proceeds. With the same sources flat, it is SUPPORTED and explained.

---

## 6. Learned context

`PriorBook` keeps plain counts per (context type, detector family, source): how often an
event of that type was the accepted explanation, and how often it was offered and was
not. The estimate is a Beta-smoothed rate with back-off from source to family to type,
using pseudo-count 4. With no history it is 0.5, neither for nor against.

What it learns from:

| Signal | Outcome |
|---|---|
| a context type wins and the candidate is EXPLAINED | `explained` for the winner |
| a human reverses a suppression (`reverse`) | the success is taken back |
| a human rules on a candidate that proceeded (`verdict`) | `explained` for the named type, or `not_explained` for every aligned type |

It does **not** learn from losing a competition, or from a candidate that proceeded
without a human verdict. Both were tried. Counting them let one busy campaign week drag
the holiday and month-end priors to 0.1, after which holidays could never win again. That is a
self-reinforcing collapse, not learning.

The remaining self-reinforcement goes upward: winners raise their own prior. The prior
carries a weight of 0.3, so the most it can add is +0.15 over no history, and reversals
correct it.

**Persistence is A3's audit ledger.** Every observation is one append-only, hash-chained
`audit_events` row: subject `context_prior`, subject id `type|family|source`, `to_state`
the outcome. `PriorBook.load(sink)` replays these rows, so the prior on any past date
can be reconstructed exactly.

---

## 7. Residual routing, audit and reversal

The best match is compared with `RoutingPolicy.threshold_for(source)`: default 0.5,
with a per-source override.

- At or above the threshold, the candidate is **EXPLAINED**, with the explanation
  attached and an `audit_events` row `context_explain`. That row carries the subject
  candidate id, `event_id = decision_id`, and `detail_digest` = the hash of the
  decision.
- Below the threshold, it **PROCEEDS**, with all matches recorded as context.

**Every suppression is reversible.** `router.reverse(decision_id, actor=, reason=, at=)`:

- appends a new PROCEED decision with `reverses = decision_id`;
- appends `context_reverse` (`from_state explained → proceed`,
  `correlation_id = decision_id`);
- takes the success out of the prior.

Nothing is updated in place. A reversal sticks: routing the same candidate id again
records its matches but does not suppress it a second time. `actor` and `reason` must be
plain identifiers, never free text.

**Handing off to L5.** A PROCEED candidate is ingested normally. An EXPLAINED one need
not be. If it is ingested, so that someone can see what was explained away, move its
pattern to `EXPLAINED_AWAY` with `context_ref = decision.decision_id`.

---

## 8. Acceptance benchmark

`tests/benchmark_context.py`. Run it with
`uv run python packages/godwit-context/tests/benchmark_context.py`.

The setup is twelve sources in US, GB-ENG and DE, with daily windows over 2024-H1.

- **Benign anomalies** come from deploys (40% of deploys cause one), channel campaigns,
  real public holidays, month ends on finance sources, and A1 schema migrations.
- **Genuine anomalies** are isolated, or come in coordinated waves across five to eight
  sources. Half the waves are placed on a public holiday.
- **Unrelated context** is everywhere: 60% of deploys cause nothing.

The policy is the package default. **Nothing was tuned on this benchmark.** Two
mechanisms were added after the first run. Both are principled, and both are documented
above with the failure each one fixed:

- The same-type confounder exclusion. Without it, New Year "contradicted" itself across
  jurisdictions.
- Winner-only learning. Without it, the prior collapsed.

The weights and thresholds were not changed.

**Default seed (pinned in `tests/test_benchmark.py`):**

| class | n | explained | rate |
|---|---|---|---|
| deploy | 83 | 83 | 100.0% |
| campaign | 26 | 24 | 92.3% |
| holiday | 51 | 29 | 56.9% |
| month_end | 36 | 36 | 100.0% |
| schema | 7 | 7 | 100.0% |
| **benign** | | | **88.2%** |
| isolated | 79 | 9 | 11.4% |
| wave | 48 | 1 | 2.1% |
| **genuine wrongly explained** | | | **7.9%** |

**Ten seeds (1–10), pooled:** 86.6% of benign anomalies are explained. **11.5% of genuine
anomalies are wrongly explained.** Per seed, the genuine rate ranges from 4.8% to 20.2%.

| Target | Result |
|---|---|
| > 80% of benign explained | **met** (86.6% pooled) |
| < 5% of genuine wrongly explained | **not met** (11.5% pooled, 7.9% at the default seed) |

**Where the false explanations come from.** The default seed has ten false explanations:

| Context that took the blame | Count |
|---|---|
| a month end on a finance source | 5 |
| a deploy on the same source and the same column | 3 |
| a schema migration | 1 |
| a campaign explaining a whole-source change (tier COARSER) | 1 |

Each one is a coincidence driven by base rates. A month end has an effective window of
about five days (lead 1d, lag 3d), so it covers about 16% of a finance source's days.
Deploys hit 10% of source-days. A genuine anomaly that lands inside one of those windows
on an in-scope column cannot be told apart from a mundane one using statistics alone.
No change to the scoring fixes that. Three things would reduce it:

- narrower scopes, such as deploy segments rather than columns;
- shorter probe windows;
- tighter lags for recurring calendar contexts. A recurring context's typical effect day
  can be learned, but this package does not learn it yet.

**Threshold sweep (default seed, with peers):**

| threshold | benign explained | genuine wrongly explained |
|---|---|---|
| 0.4 | 88.2% | 10.2% |
| 0.5 (default) | 88.2% | 7.9% |
| 0.6 | 60.1% | 3.1% |
| 0.7 | 53.7% | 1.6% |
| 0.8 | 6.9% | 0.0% |

This is why the threshold is per source. A source that pages a human should run at
0.6. A source feeding the discovery queue can run at 0.5.

**Without peer observations** (batch candidates only), the layer explains 55.2% of
benign anomalies and wrongly explains 0.8% of genuine ones. It fails closed. Wiring
A7's full test list into `peers` is worth roughly thirty points of benign coverage.

Holidays are the weakest benign class, at 56.9%. The 22 misses break down as follows:

- **New Year's Day (11 misses):** every jurisdiction is on holiday, so after the
  confounder exclusion no control is left. The check is UNTESTABLE, and partial credit
  is not enough.
- **Three holiday days (11 misses)** where a coordinated wave was deliberately placed:
  1 May (DE), 9 May (DE) and 19 June (US). Untouched sources moved too, so the
  counterfactual correctly contradicts the holiday.

Both are the intended behaviour. The cost is benign coverage, not a wrong answer.

---

## 9. Known limits

- **The genuine-anomaly target is not met** (§8). This is the most important limit.
- **Lunar and observation-based holidays** (Eid, Diwali, Lunar New Year) are not
  computed. They cannot be derived from rules a regulator would accept. Supply them as
  `HolidayCalendar.one_off` dates or through a `StaticSource`.
- **Greek Labour Day moves** (it is moved when it falls in Holy Week) are not modelled.
  Scottish spring-holiday moves before 2020 are not modelled. Bavaria's Assumption Day
  is a holiday only in Catholic-majority municipalities. It is modelled state-wide.
- **Annotations and full decision records are in-process.** Their audit trail is durable
  in A3's ledger. Their content is not, because no table exists for it:
  `CR-A8-context-has-no-contract-or-table`.
- **Candidate windows are configured, not carried**: `CR-A8-candidate-has-no-window`.
- **Imported segments are string-valued `EQ` predicates.** A context scoped to
  `amount > 100`, or to an integer-typed column, needs a `ContextScope` built in code.
- **Weights (0.3/0.3/0.4), tier scores and verdict ratios are judgements, not fits.**
  They are data (`MatchPolicy`, `StrengthWeights`, `CounterfactualPolicy`), so a
  deployment that measures its own reversal rate can adjust them deliberately.
- **`audit_query` has no cursor.** `StoreAuditSink` reads up to ten million prior
  observations. Past that, `PriorBook.load` truncates silently. Snapshotting the
  counts would need a table.
