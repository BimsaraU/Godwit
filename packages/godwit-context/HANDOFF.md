# godwit-context — HANDOFF

**Owner:** A8 **Layer:** L3 **Plane:** control. **Handles data-derived values:**
candidate segments quote row values, context scopes name customer columns, and imported
labels are tainted free text. Its outputs (`Match`, `RoutingDecision`, audit rows) hold
only ids, kinds and derived numbers.
**Status:** complete. `ruff`, `mypy --strict` and `pytest` are green.

Full documentation: **`docs/packages/godwit-context.md`**.

## What it does

It joins every candidate against the mundane reasons the world changed: deploys,
campaigns, holidays, business calendars, data-quality incidents, market moves and
analyst notes. Only the unexplained residual proceeds to L5.

```
godwit_context/
  events.py      ContextEvent, ContextScope, ContextType
  sources.py     ContextSource protocol, webhook/CSV/API import, A1 DQ, AnnotationBook
  holidays.py    rule-based calendars: US, GB-ENG/SCT, DE(+BY, BE), FR(+Alsace-Moselle), GR
  business.py    month/quarter/fiscal-year end, payroll, settlement, on business days
  matching.py    temporal x overlap x (prior, specificity, counterfactual) -> Match
  priors.py      learned context: Beta-smoothed counts, persisted in A3's audit ledger
  routing.py     ContextRouter: route, reverse, verdict; every suppression audited
  audit.py       AuditSink protocol: StoreAuditSink (A3) and MemoryAuditSink
  _unwrap.py     the only two .reveal() calls (SCHEMA_NAME, DERIVED_STATISTIC)
```

## The five things you need to know

1. **A match is a strength, and every match is kept.** `decision.matches` holds every
   aligned explanation, strongest first. `decision.explanation` is the attached one
   when EXPLAINED.
2. **The counterfactual check needs peers.** Pass A7's full list of examined hypotheses
   as `PeerObservation`s. Without them the layer can contradict but never support, and
   it explains about 30 points less (it fails closed).
3. **Every suppression is an audit row and is reversible.** `reverse()` appends a new
   decision, never edits an old one, and a reversal sticks across later runs.
4. **The genuine-anomaly target (< 5% wrongly explained) is not met at the default
   threshold:** 7.9% at the pinned seed, 11.5% over ten seeds. Benign coverage is
   86.6%, against a target above 80%. At threshold 0.6 the genuine rate is 3.1%, but
   benign coverage drops to 60.1%. The threshold is per source. See §8 of the docs.
5. **Lunar holidays are not computed.** Supply them as dates.

## If you are…

**A10 (orchestrator):** call `router.route(candidates, events=..., peers=..., at=...)`
after L2 and before `PatternStore.ingest_batch`. Ingest PROCEED candidates. For an
EXPLAINED candidate you choose to ingest, transition it to `EXPLAINED_AWAY` with
`context_ref = decision.decision_id`. Convert `DetectionResult.tests` into
`PeerObservation`s. Set `MatchPolicy.window_by_source` to each source's probe cadence.

**A3 (store):** this package writes `audit_events` rows with the actions
`context_explain`, `context_reverse`, `context_verdict`, `context_annotate` and
`context_prior_observe`. Read `CR-A8-context-has-no-contract-or-table`: annotations and
decision records need a home.

**A16/A17 (Vision Board):** reversal is `reverse(decision_id, actor=<reviewer id>,
reason=<code>, at=)`. A human ruling on a candidate that proceeded is
`verdict(decision_id, explained_by=<ContextType|None>, actor=, at=)`. Annotations go
through `AnnotationBook.annotate`.

**A1 (source):** `metadata.schema_change` candidates become DATA_QUALITY context through
`data_quality_from_candidates`.

## Running it

```sh
uv run pytest packages/godwit-context
uv run python packages/godwit-context/tests/benchmark_context.py
```

## Change requests filed

- `CR-A8-candidate-has-no-window`: a candidate carries one instant, but temporal
  alignment needs the interval.
- `CR-A8-context-has-no-contract-or-table`: no contract types for context events, and
  no store tables for events or decisions.
- `CR-A8-no-type-for-an-unremarkable-test`: the counterfactual needs "did not change"
  observations, and the contracts have no type for them.

Each one has a strict xfail in `tests/test_contract_gaps.py`.

## Known limits

See §9 of the docs. In brief: the genuine target is missed; lunar holidays are not
computed; annotations and decision records live in process; windows are configured
rather than carried; imported segments are string `EQ` only; the weights are
judgements.
