# CR-A6-opaque-entropy-floors-disagree

**Filed by:** A6 (`godwit-probe`)
**Against:** `godwit-guard` (A5) and `godwit-sketch` (A2)
**Status:** open

## The problem

Two packages each implement "a keyed hash of a small input space is not anonymisation",
and they chose different floors:

| Package | Constant | Value |
|---|---|---|
| `godwit-guard` | `access.DEFAULT_MIN_ENTROPY_BITS` | **24** bits |
| `godwit-sketch` | `items.MIN_OPAQUE_ENTROPY_BITS` | **32** bits |

The guard decides whether a column may be OPAQUE at all. The sketch decides whether a
heavy-hitter sketch may store keyed digests of it. A column whose plausible input space is
between 2^24 and 2^32 -- a seven-digit account number, a nine-digit national id prefix, a
phone number without its country code -- is therefore readable as OPAQUE (the guard says
yes) but cannot have a hashed Count-Min (the sketch refuses to construct the hasher).

## Why it matters

Nothing leaks: the stricter floor wins, because the sketch refuses. But the shared-attribute
graph signal the brief calls "the strongest organised-fraud signal in the whole design" is
exactly heavy hitters and fan-in over identifier columns, and some real identifier columns
fall in that band. A probe on one is refused with
`RefusalReason.ENTROPY_BELOW_SKETCH_FLOOR`, and nobody can tell from the guard's mode map
that it will be.

## The smallest sufficient change

One number, owned in one place. Either:

```python
# godwit_guard.access
DEFAULT_MIN_ENTROPY_BITS: Final[float] = 32.0  # was 24.0; matches godwit-sketch
```

or have `godwit-sketch` import the guard's constant (it would then depend on
`godwit-guard`, which it does not today). If `CR-A5-access-modes-have-no-contract` lands,
the floor belongs next to `AccessMode` in contracts and both read it from there.

## Who else this affects

* **A5** owns the access-mode floor; A5's HANDOFF already notes 40 bits is the right
  answer if key compromise is in scope, which would make this disagreement moot.
* **A2** owns the sketch floor.
* **A18 (policy)** audits the mode map and would want the two to agree.

## What I did instead

The planner checks both: the guard's decision must be OPAQUE, and a value-bearing hashed
sketch additionally requires `entropy.bits >= godwit_sketch.MIN_OPAQUE_ENTROPY_BITS`, else
the probe is refused with `ENTROPY_BELOW_SKETCH_FLOOR` before any read. Distinct-count and
null-rate probes on the same column still run, because their payloads hold no keys.

```
packages/godwit-probe/tests/test_contract_gaps.py::test_guard_and_sketch_agree_on_the_opaque_entropy_floor
@pytest.mark.xfail(strict=True, reason="CR-A6-opaque-entropy-floors-disagree")
packages/godwit-probe/tests/test_plan.py::test_entropy_between_the_guard_and_sketch_floors_refuses_heavy_hitters
```

## Decision

_Left blank by the filer. A human fills this in._
