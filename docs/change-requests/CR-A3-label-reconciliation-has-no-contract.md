# CR-A3-label-reconciliation-has-no-contract

**Filed by:** A3 (`godwit-store`)
**Against:** `godwit-contracts`, and `docs/ARCHITECTURE.md` open question 7
**Status:** open

## The problem

The discovery objective is stated in terms of a process nothing models:

> `OPERATIONAL`: ~50 alerts/day, target precision ≥ **30% after 90-day reconciliation**.

`docs/ARCHITECTURE.md` open question 7 says the same:

> `Label` carries `event_time` and `label_time` and `LabelSet` carries a
> `CoverageScope`, which is enough to *measure* precision after the fact. The process
> that goes back and re-scores a 90-day-old alert queue is not modelled. Whoever owns
> the operational queue needs it.

A3 owns the label ledger and the queues, so this lands here. The pieces that exist:

* `Feedback` — a human's verdict on a pattern, at a `decided_at`.
* `Label` — an outcome about an *entity*, with an `event_time` and a `label_time`.
* `CoverageScope` — which population was exhaustively labelled, over which window.

The piece that does not exist is the join. Precision@k asks: *of the 50 alerts raised on
day D, how many turned out to be real, judged by everything known at D + 90 days?* That
needs a link from a **pattern** (a segment, a statistical claim) to the **entities** whose
labels settle it, and no contract type carries one.

`Pattern.segment` is close — it names a population — but a segment is a predicate over a
table, and the label ledger is keyed by an entity pseudonym. Resolving one to the other
means running a query in the data plane, which is exactly what the control plane cannot
do.

## Why it matters

Without it, "precision ≥ 30% after 90-day reconciliation" is not measurable, and the two
things that will be measured instead are both wrong:

* **Reviewer agreement** — the fraction of alerts a human marked `CONFIRMED`. That is
  precision against opinion at the moment of review, which is the number the 90-day
  window exists to correct.
* **Nothing** — the target quietly becomes aspirational, which is the more likely
  outcome, and the one that is hardest to notice.

It also matters for what the store can refuse. `LabelLedger.assert_covered` already
refuses to let a metric be computed over an uncovered region. It cannot refuse a
*precision* computation, because it does not know which labels that computation should
have consulted.

## The smallest sufficient change

Two additions, both small:

```python
# godwit_contracts.discovery


class Reconciliation(GodwitModel):
    """The outcome of re-scoring an alert once its labels have settled."""

    pattern_id: PatternId
    alert_id: str
    queue: AlertQueue
    raised_at: Instant
    reconciled_as_of: Instant = Field(
        description="The instant labels were read at. Explicit, never 'now': a "
        "reconciliation that used 'now' is not reproducible and not auditable."
    )
    entity_count: NonNegInt
    positive_count: NonNegInt
    coverage_id: str = Field(description="Which coverage declaration made this region reportable.")
    verdict: Verdict
```

and, on `Pattern` or alongside it, a way to say which entities a pattern is about:

```python
    entity_type: str | None = None
    """Which entity the pattern's segment selects, when it selects one. Without this a
    pattern cannot be joined to the label ledger, and its precision cannot be measured."""
```

The resolution from segment to entity ids stays in the **data plane** — it is a query
over rows — and what crosses is a count, not a list. That keeps invariant 1 intact and
is why `Reconciliation` carries `entity_count` and `positive_count` rather than ids.

## Who else this affects

* **A3 (`godwit-store`)** — would store `Reconciliation` rows and could then compute and
  refuse precision honestly.
* **A11 (`godwit-features`)** or **A6 (`godwit-probe`)** — one of them has to run the
  data-plane query that resolves a segment to labelled entities.
* **A10 (`godwit-orchestrator`)** — the reconciled precision is the feedback signal its
  bandit should be learning from, and today it is not there to learn from.
* **A16 / A17 (Vision Board)** — the 30% number is a headline on somebody's dashboard.

## What I did instead

Built everything the reconciliation needs except the join, and left the join absent
rather than guessing at it:

* `LabelLedger.visible_as_of(instant=...)` reads labels at any past instant, which is
  precisely "everything known at D + 90 days".
* `LabelLedger.assert_covered(...)` refuses a metric over an uncovered or
  non-exhaustive region, so a reconciliation cannot be computed over a population nobody
  promised to have labelled.
* `patterns.confirmations` and `patterns.rejections` count reviewer verdicts, and are
  documented in `docs/packages/godwit-store.md` as **reviewer agreement, not precision**,
  so that nobody reports one as the other.

There is no xfail for this one: an xfail asserts a specific missing API, and what is
missing here is a design decision about where the segment-to-entity resolution runs.
Guessing at the signature would make the request harder to answer, not easier.

## Decision

_Left blank by the filer. A human fills this in._
