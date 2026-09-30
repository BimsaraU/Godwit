# CR-A3-fdr-hypothesis-space

**Filed by:** A3 (`godwit-store`)
**Against:** `godwit-orchestrator` (A10), and `docs/ARCHITECTURE.md` open question 6
**Status:** open

> This is a statistics problem, not an API problem. It needs a decision from a human who
> is willing to own the answer, and it is the weakest part of A3's false-discovery
> control.

## The problem

`docs/ARCHITECTURE.md` open question 6 states it exactly:

> L5 applies Benjamini-Hochberg over the whole hypothesis space of a snapshot. What
> counts as "the whole hypothesis space" when the orchestrator is adaptively choosing
> probes — a bandit changes the number of tests as it goes — is a real statistical
> problem I have not solved. A3 and A10 need a shared answer, and the honest fallback is
> a conservative fixed hypothesis count per snapshot.

Benjamini-Hochberg controls the false-discovery rate over a family of `m` tests that
were **fixed before the data were seen**. A bandit violates that in two ways at once:

1. **`m` is not fixed.** The orchestrator decides what to probe next partly on the basis
   of what earlier probes returned, so the size of the family is a random variable.
2. **The tests are not independent, and not in a benign way.** Benjamini-Yekutieli
   handles arbitrary dependence at a cost of a `log(m)` factor, but the dependence here
   is *adaptive*: the bandit preferentially probes where it already saw signal, which
   enriches the family with hypotheses selected for looking significant. That is
   selection on the outcome, which no post-hoc adjustment repairs.

The failure is not that q-values come out slightly wrong. It is that they come out
**too small in exactly the cases the orchestrator considered most promising**, which is
the population the operational queue is drawn from.

## Why it matters

The product's discovery objective is precision at or above 30% after 90-day label
reconciliation. If the q-values are optimistic on the adaptively-probed patterns, the
measured precision will come in under target and the visible symptom will be "the
detectors are not very good", which is the wrong diagnosis and leads to the wrong fix.

It also matters for what can be said out loud. "We control the false discovery rate at
10%" is a claim a bank's model risk function will test. Under adaptive probing it is
currently not one A3 can defend.

## The smallest sufficient change

A3 cannot fix this inside the store, because the store never sees the probe space. What
is needed is a decision, and three options are worth putting in front of whoever makes
it:

**Option 1 — a declared ceiling per snapshot (implemented today).** The orchestrator
declares, before any probe runs, an upper bound on how many hypotheses the snapshot may
contain. BH adjusts against the ceiling. Conservative, simple, defensible; costs
sensitivity in proportion to how loose the ceiling is.

**Option 2 — split the sample.** The bandit explores on one slice and the reported
findings come from another it did not steer. Statistically clean, and it composes with
the holdout the store already requires. Costs roughly half the data.

**Option 3 — alpha-investing.** An online procedure that spends an error budget as tests
arrive and is designed for exactly this setting. Correct under adaptivity, and a
substantially larger piece of work: it changes the orchestrator's allocation loop, not
just the store's arithmetic.

A3's recommendation is **option 1 now, option 2 as the path to a defensible claim**.
Option 2 also happens to be what the existing holdout requirement is already half-way
towards.

The API change either way is small: `HypothesisFamily.test_count` is already a declared
field, and `conservative_test_count(emitted=..., declared_ceiling=...)` already takes a
ceiling. What is missing is the orchestrator declaring one.

## Who else this affects

* **A10 (`godwit-orchestrator`)** — owns the probe space and the bandit, and is the only
  package that can declare a ceiling or split a sample.
* **A7 (`godwit-detect`)** — reports raw p-values and the number of hypotheses examined
  within one run, which is the inner loop of the same count.
* **A3 (`godwit-store`)** — applies the adjustment.
* **A18 (`godwit-policy`)** — if the claim "we control FDR at q" appears in a policy
  pack, it inherits whatever is decided here.

## What I did instead

Implemented option 1 and refused to guess anything:

* `HypothesisFamily.test_count` is mandatory, has no default, and a family of size zero
  is a validation error.
* `benjamini_hochberg` raises `UnboundedHypothesisFamilyError` when the declared count is
  smaller than the number of p-values supplied, rather than clamping. Surfacing a
  detector bug beats absorbing it.
* Unobserved tests are treated as `p = 1`, the conservative reading.
* `conservative_test_count(emitted=..., declared_ceiling=...)` takes the ceiling when
  there is one and the emitted count when there is not — the latter being the least
  conservative honest choice, which is why it has to be explicit rather than a default.

```
packages/godwit-store/tests/test_fdr.py::test_conservative_test_count_prefers_the_declared_ceiling
packages/godwit-store/tests/test_fdr.py::test_a_larger_declared_family_makes_findings_less_significant
```

Both pass. Neither of them makes the adaptive case correct, and no test in this package
claims to: `test_pure_noise_rejects_at_most_the_target_rate` measures the **fixed,
independent** case, which is the case the implementation is entitled to claim.

## Decision

_Left blank by the filer. A human fills this in._
