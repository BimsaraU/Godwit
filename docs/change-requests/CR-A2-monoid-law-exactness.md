# CR-A2-monoid-law-exactness

**Filed by:** A2 (`godwit-sketch`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

`godwit_contracts.protocols.Sketch` states:

> 1. `merge` is associative: `a.merge(b).merge(c) == a.merge(b.merge(c))`.

For an additive or idempotent summary this is achievable and this package achieves it.
For a **bounded lossy** summary it is not achievable by any implementation, and the
reason is structural rather than a matter of care.

A bounded summary has a size limit. When a merge would exceed it, the summary must
discard information to stay inside it. `a.merge(b)` discards whatever is least important
*in `a ∪ b`*; the discarded part is gone before `c` arrives. Bracketing the other way,
`b.merge(c)` discards whatever is least important in `b ∪ c` — a different set, because
it was chosen against a different population. Neither result can recover what the other
kept, so the two internal states differ.

Concretely, with a Misra-Gries capacity of two:

```
a = {x:9, y:7}   b = {z:8, w:6}   c = {y:5, v:4}
(a·b)·c  drops y at the first step, because y is fourth of four there.
a·(b·c)  keeps y, because b·c does not contain it and a·(b·c) ranks it second.
```

The counts still satisfy the published Misra-Gries error bound in both cases. The
*states* are not equal, and no tie-breaking rule fixes it: the information needed to
agree was destroyed by the first merge.

The same argument applies to every quantile sketch (KLL discards half a buffer on
compaction) and, for an unrelated reason, to every float-valued summary: IEEE-754
addition is not associative, so `(a+b)+c != a+(b+c)` in the last bits regardless of how
the merge is written.

Of the eight kinds this package implements, five satisfy law 1 exactly and three cannot:

| Kind | Exact? | Why |
|---|---|---|
| `ThetaNdv` | yes | bottom-*k* of a union is a pure function of the union |
| `HllCount` | yes | registers hold a maximum; maximum is associative |
| `NullRate` | yes | two integer counters |
| `CategoryHistogram` (exact regime) | yes | integer counts per key |
| `CountMinHeavy` (matrix only) | yes | integer addition |
| `KllQuantile` | **no** | bounded, lossy compaction |
| `CountMinHeavy` (heavy hitters) | **no** | bounded Misra-Gries counters |
| `Moments` | **no** | float addition is not associative |

## Why it matters

The law as written is impossible to satisfy for three of the eight kinds, so any
package that tests it literally will either fail or quietly weaken the test without
recording that it did. The second outcome is the dangerous one: a weakened assertion
looks exactly like a passing one.

Nothing is unsafe and nothing downstream is blocked — see "What I did instead".

## The smallest sufficient change

Restate law 1 so that it distinguishes the two cases, and require implementations to
declare which they are:

> 1. `merge` is associative. For a kind that declares exact merging, `a.merge(b).merge(c)`
>    equals `a.merge(b.merge(c))` in full internal state. For a kind that declares
>    bounded merging, the two agree on the estimate to within the kind's documented
>    `ErrorBound`, and on `population` exactly. A kind must declare which it is, and a
>    bounded kind must document what the bracketing can cost.

Optionally, add the declaration to the protocol itself, so it is machine-readable
rather than prose:

```python
@property
def merge_is_exact(self) -> bool:
    """True when law 1 holds in full internal state, not only within the bound."""
```

## Who else this affects

* **A0** owns the protocol.
* **A2 (`godwit-sketch`)** implements every kind and is the only package that can
  satisfy or violate the law.
* **A6, A7, A11, A12, A13** read sketches and may reasonably assume merge order cannot
  matter. It cannot, for the five exact kinds. For the other three the guarantee they
  actually get is the error bound, and the contract should say so rather than leaving
  them to discover it.

No stored key migrates.

## What I did instead

Implemented against the contract as written, and declared the gap rather than hiding it:

- `godwit_sketch.base.MergeExactness` carries `EXACT` / `BOUNDED` on every class.
- `tests/test_monoid_laws.py` applies exact byte equality to the five exact kinds, and
  to the three bounded ones asserts that `population` is exact and that the extracted
  feature vectors agree on which slots apply.
- `tests/test_contract_gaps.py::test_bounded_kinds_are_exactly_associative` is an
  `xfail(strict=True)` that demonstrates the failure with the counter-example above. If
  this CR is accepted and the law restated, that test starts `XPASS`ing and the suite
  says so.

**Nothing downstream is weakened by the gap.** Batch and streaming still produce
byte-identical artifacts, because `TimeHierarchy` folds in a **canonical order** derived
from content rather than arrival, so the sequence of merge operations is a pure function
of the data. Order-independence of the merge was never what that guarantee rested on.

## Decision

_Left blank by the filer. A human fills this in._

## A second, smaller point in the same law

Law 6 says `error_bound()` "is a property of the construction parameters and the item
count". For Theta and KLL it also depends on whether the sketch has entered estimation
mode, which is a function of the *distinct* count and of how many compactions have
happened — both data-dependent. This package reports the honest bound (`exact` while the
sketch is still exact, the estimated bound afterwards) rather than pessimistically
reporting an estimation-mode bound for a sketch that is exact, because a detector
subtracts that bound before deciding something moved, and an inflated bound costs real
recall. Suggested wording: "a property of the construction parameters and the sketch's
own size, never of the values themselves".
