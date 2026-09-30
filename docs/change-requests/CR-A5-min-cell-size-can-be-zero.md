# CR-A5-min-cell-size-can-be-zero

**Filed by:** A5 (`godwit-guard`)
**Against:** `godwit-contracts` — `RedactionPolicy.min_cell_size`, `quantile_min_population`
**Status:** open
**Priority:** low — the gate already refuses; this moves the check to where it belongs

## The problem

The brief: *"k-anonymity enforcement ... Default k = 10, configurable, never zero."*

`RedactionPolicy.min_cell_size` is `NonNegInt`, so `0` and `1` validate. Either value
disables small-cell suppression entirely: every population is `>= 0`. The contract already
refuses a default action of ALLOW for the same reason — "deny by default is not a
convention we hope people follow" — and k deserves the same treatment.

A smaller note, no change requested: the contract's default is `20`, the brief's is `10`.
The stricter value wins and godwit-guard's `DEFAULT_POLICY` uses 20.

## Why it matters

A policy with `min_cell_size=0` is storable, versionable and publishable today. Only the
gate stops it at use time.

## The smallest sufficient change

```python
# current
min_cell_size: NonNegInt = Field(default=20, ...)

# proposed
min_cell_size: int = Field(default=20, ge=2, ...)
quantile_min_population: int = Field(default=100, ge=2, ...)
```

## Who else this affects

* **A18** — policy packs; any pack with k < 2 stops validating, which is the point.
* **A13** — `Evaluator` law 3 (slice suppression) reads the same threshold.

## What I did instead

`Gate.clear` refuses a policy with `min_cell_size < 2` as `INVALID_POLICY`;
`enforce_segment_k`, `ReleaseLedger` and `quasi_identifier_combinations` raise on k < 2.

```
packages/godwit-guard/tests/test_contract_gaps.py::test_a_policy_cannot_disable_k_anonymity
@pytest.mark.xfail(strict=True, reason="CR-A5-min-cell-size-can-be-zero")
```

## Decision

_Left blank by the filer. A human fills this in._
