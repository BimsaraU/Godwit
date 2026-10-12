# CR-A9-feature-expression-semantics-unspecified

**Filed by:** A9 (`godwit-sdk`)
**Against:** `godwit-contracts` (`godwit_contracts.features.FeatureSpec.expression`)
**Status:** open

## The problem

`FeatureSpec.expression` is "the computation, in the data plane's SQL dialect (DuckDB)".
Two readings are both defensible:

1. a **row expression**, evaluated per history row, which A11 then windows and
   aggregates according to `kind` (`amount * 100`);
2. an **aggregate over the point-in-time window's rows** (`sum(amount)`), which A11
   evaluates once per entity per event.

The SDK's `@feature` needs one of them, because it is where the point-in-time rule is
made mandatory: a plugin writes an aggregate, and the SDK builds the window around it
(`FeatureBase.evaluate`). It chose reading 2 for `TIME_WINDOW`. If A11 implements
reading 1, every plugin feature computes the wrong thing silently -- an aggregate
evaluated per row is either an error or, worse, a running total.

## Why it matters

A disagreement here is a silent wrong answer in training data, the most expensive kind.

## The smallest sufficient change

State it on the type.

```python
# proposed
class FeatureSpec(GodwitModel):
    ...
    expression_kind: Literal["row", "window_aggregate"] = Field(
        description="'window_aggregate': one aggregate over the rows the point-in-time "
        "rule admits for each entity at its event time. 'row': evaluated per row."
    )
```

## Who else this affects

A11 (`godwit-features`) above all; A13 and A14 consume the specs.

## What I did instead

`FeatureBase.spec()` emits `TIME_WINDOW` specs whose `expression` is a window aggregate,
documented in `godwit_sdk.feature` and the package doc, and `FeatureBase.evaluate()` is
the reference evaluator for that reading.

```
packages/godwit-sdk/tests/test_contract_gaps.py::test_a_feature_spec_says_what_its_expression_is
@pytest.mark.xfail(strict=True, reason="CR-A9-feature-expression-semantics-unspecified")
```

## Decision

_Left blank by the filer. A human fills this in._
