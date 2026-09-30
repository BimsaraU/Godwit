# CR-A4-evaluation-report-has-no-intervals

**Filed by:** A4 (`godwit-replay`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

`EvaluationReport.metrics` is a `Mapping[str, float]`: one number per metric name. There is
no field anywhere on the report for a confidence interval, and `SliceMetric` has the same
shape — a single `Tainted[float]` value plus a population.

My brief asks for prediction metrics "with confidence intervals", and the reason is not
decoration. The prediction objective is *within 0.02 AUC of a tuned expert baseline*. On the
golden classification fixture the held-out half is 1,200 rows at a 26% positive rate, and a
percentile bootstrap over that gives an AUC interval roughly ±0.02 wide. In other words the
interval is the same size as the thing being decided. A report that carries `auc: 0.9311`
and nothing else cannot distinguish "we met the objective" from "we cannot tell".

`EvaluationReport` is also the type A13 and A14 will hand to a human and to a deployment
gate, which is exactly where the distinction has to survive.

## Why it matters

Concretely: a model that scores 0.9311 against a baseline of 0.9400 is inside the objective
by the point estimate and outside it by the lower bound. Today the contract can only express
the first reading. The consequence is a deployment gate that says "shipped" on a coin flip,
and a model card that reports a precision it cannot support.

Nothing crashes. The report validates and the numbers are real. What is lost is the ability
to say how sure we are, which on a 1,200-row held-out half is most of the information.

## The smallest sufficient change

Not a new type, not a generic `Measurement` wrapper across the whole contract. One optional
field on `EvaluationReport`, defaulting to empty, which existing producers can ignore:

```python
# current
class EvaluationReport(GodwitModel):
    metrics: Mapping[str, float]
    ...


# proposed
class MetricInterval(GodwitModel):
    """A metric's uncertainty. Percentile bootstrap, not a normal approximation: AUC near
    1.0 is badly skewed and a symmetric interval there is a fiction."""

    low: float
    high: float
    level: Probability = 0.95
    resamples: NonNegInt
    seed: int


class EvaluationReport(GodwitModel):
    metrics: Mapping[str, float]
    intervals: Mapping[str, MetricInterval] = Field(
        default_factory=dict,
        description="Keyed by the same names as ``metrics``. A metric with no interval is "
        "a point estimate of unknown precision, and a gate must treat it as such.",
    )
    ...
```

A validator that every key of `intervals` also appears in `metrics` would be welcome and is
not required.

## Who else this affects

* **A13** (`godwit-predict`) produces `EvaluationReport` and is the package graded against
  the 0.02 objective. It is the main beneficiary.
* **A14** (`godwit-serve`) gates deployment on evaluation results and would be able to gate
  on a bound rather than on a point.
* **A16/A17** (Vision Board) render metrics to humans.
* **A5** (`godwit-guard`): `MetricInterval` holds derived statistics only — no row value —
  so it is DERIVED_STATISTIC-class and needs no new gate rule.

No key changes. Nothing stored is migrated. `segment_key` and `probe_key` are untouched.

## What I did instead

Implemented against the contract as written. `godwit_replay.metrics.Interval` carries the
point estimate, the bounds, the level, the resample count and the seed, and
`PredictionScore.metrics` is a `Mapping[str, Interval]`. When that has to become an
`EvaluationReport`, `to_evaluation_report` flattens each interval into three sibling keys:

```
auc            -> the point estimate
auc_ci_low     -> the lower bound
auc_ci_high    -> the upper bound
```

This works and it is a workaround. The bounds are untyped, indistinguishable from any other
metric to a consumer that does not know the naming convention, and a gate reading
`metrics["auc"]` sees no signal that an interval exists at all.

```
packages/godwit-replay/tests/test_contract_gaps.py::test_evaluation_report_carries_an_interval
@pytest.mark.xfail(reason="CR-A4-evaluation-report-has-no-intervals")
```

## Decision

_Left blank by the filer. A human fills this in._
