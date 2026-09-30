# CR-A2-kll-is-item-bearing

**Filed by:** A2 (`godwit-sketch`)
**Against:** `godwit-contracts`
**Status:** open

> **A leak path that is currently classified as safe.** Of the requests A2 has filed,
> read this one first.

## The problem

`godwit_contracts.sketch.ITEM_BEARING_KINDS` lists `COUNT_MIN` and `FREQUENT_ITEMS`,
with the note:

> An envelope of one of these kinds must declare DATA_VALUE (or TOKEN, after the gate
> has substituted the items). Declaring one as a derived statistic is a validation
> error, not a review comment.

`KLL` is not in that set. It should be. **A KLL payload contains real row values**, by
construction and not by accident:

- A quantile sketch answers rank queries by retaining a weighted *sample of the actual
  items it saw*. Those items are serialised verbatim into the payload.
- It additionally holds the exact minimum and the exact maximum, which the contracts'
  own taint module already calls out: "A mean is a derived statistic; the *maximum* of a
  column is not, because the maximum IS some row's value."

Point a KLL sketch at `salary_2024` and its bytes contain real salaries. Point it at a
date-of-birth column and they are real dates of birth. `Acquisition.QUANTILE` already
carries a `DATA_VALUE` floor in `ACQUISITION_MINIMUM_SENSITIVITY`, so the taint module
and the sketch module currently disagree with each other.

Runnable demonstration, in
`packages/godwit-sketch/tests/test_contract_gaps.py::test_a_kll_payload_really_does_contain_row_values`:
a distinctive value is fed in among four hundred ordinary ones and then found, byte for
byte, in the serialised payload.

## Why it matters

A quantile sketch is the default way to summarise any numeric column, which in a bank
means salary, balance, transaction amount and date of birth. The contract currently
tells nineteen other agents that such a payload is a derived statistic — that is,
cleared to reach an LLM, a log line, an alert or a UI without passing the gate.

## It has already produced one wrong artifact

`tests/golden/sketch_envelopes.json` ships a `kll` envelope declaring
`"sensitivity": "derived_statistic"`. That fixture is what nineteen other agents are
building against, and it currently tells them a quantile sketch is safe to hand to an
LLM, a log line or a UI. A2 does not edit that file (universal rule 1) and has pinned
its current state in `test_the_golden_kll_envelope_declares_a_derived_statistic` so this
request has a citation that fails when it is fixed.

## The smallest sufficient change

Add `KLL` to `ITEM_BEARING_KINDS`:

```python
ITEM_BEARING_KINDS: Final[frozenset[SketchKind]] = frozenset(
    {SketchKind.COUNT_MIN, SketchKind.FREQUENT_ITEMS, SketchKind.KLL}
)
```

and regenerate `tests/golden/sketch_envelopes.json` so the `kll` envelope declares
`data_value`. The existing `_item_bearing_kinds_are_data_tainted` validator then does
the rest with no other change.

Please also consider the accompanying docstring, which currently reads "Two sketch kinds
-- Count-Min and frequent-items -- store observed items". The general rule is better
stated as: *any sketch that answers a query about a value, rather than about a count, has
to retain values to do it.* That covers quantile sketches, reservoir samples, t-digests
and anything else added later, rather than enumerating two kinds and inviting the next
implementer to conclude theirs is not on the list.

## Who else this affects

* **A0** owns `ITEM_BEARING_KINDS` and the golden fixture that contradicts it.
* **A5 (`godwit-guard`)** decides what clears the gate; this changes what it must stop.
* **A18 (`godwit-policy`)** writes the conformance rules, and would today write one
  that lets quantile payloads through.
* **A6 (`godwit-probe`)** builds the envelopes.
* **A2 (`godwit-sketch`)** already declares `DATA_VALUE` regardless, so nothing leaks
  from here today.

No stored key migrates, but **stored envelopes do**: any `kll` envelope already
written as `derived_statistic` keeps that declaration and needs re-tagging.

## What I did instead

Implemented against the contract exactly as written, and took the more restrictive side
everywhere the contract allows a choice:

- `KllQuantile.SENSITIVITY` is `DATA_VALUE`. An envelope may always be declared *more*
  restricted than its floor, so this is contract-legal today and nothing leaks.
- `quantile()`, `minimum()` and `maximum()` return `Tainted[float]` with
  `Acquisition.QUANTILE`, so the population rides along for small-cell rules.
- `cdf()` is offered as the safe alternative and is what detectors are pointed at: a
  cumulative fraction at a caller-supplied grid point is a count over a population, not
  a value out of a row.
- `extract_features` exports no quantile, no minimum and no maximum, and the feature
  layout has no slot that could be rearranged back into one.
- `tests/test_contract_gaps.py::test_kll_is_listed_as_item_bearing` is an
  `xfail(strict=True)` that starts passing the moment this is accepted.

## Decision

_Left blank by the filer. A human fills this in._

## A related note, not part of this request

`ThetaNdv` and `HllCount` store hashes, not values, and are correctly
`DERIVED_STATISTIC`. But over a **low-cardinality** column either one is a membership
oracle: the hash seed travels in the envelope, so anyone holding it can hash a guess and
test for presence. For `country` or `status` that discloses the full set of values
present. `ThetaNdv.is_membership_oracle()` exists so a caller can ask, but a guardrail in
A5 or A18 that treats distinct-count sketches as unconditionally safe would be wrong.
Raised here for visibility rather than as a change to this contract.
