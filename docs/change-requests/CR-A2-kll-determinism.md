# CR-A2-kll-determinism

**Filed by:** A2 (`godwit-sketch`)
**Against:** the stack list in the shared brief
**Status:** open — already resolved in code; filed so the deviation is recorded

## The problem

The stack section of the brief says:

> Sketches: apache datasketches python bindings (Theta, KLL, HLL); Count-Min in-package.

Using the KLL binding is incompatible with universal rule 5 ("no unseeded randomness,
anywhere in a path that can produce a pattern or a prediction") and with invariant 7
(every pattern reproducible from `(probe spec, snapshot id, version, seed)`).

Measured on `datasketches==5.2.0`, and pinned in
`packages/godwit-sketch/tests/test_contract_gaps.py`:

1. Building the **same** sketch from the **same** 2000 values **twice in the same
   process** produces two different serialisations.
2. It is exactly reproducible while `n <= k`, and stops being reproducible at the first
   compaction, `n = k + 1`. So the problem is invisible on small test data and appears
   on real volumes.
3. `quantiles_floats_sketch` behaves the same way, and so does `req_floats_sketch`.
4. The constructor takes `k` and nothing else. There is no seed to pin.

KLL compacts by discarding either the odd- or the even-indexed half of a sorted buffer,
chosen by a fair coin drawn from a process RNG the Python binding does not expose. That
is a reasonable choice for a general-purpose library and an impossible one here.

## Why it matters

If the upstream binding were used as the stack instructs, two probe runs over
identical data would produce different sketches. A detector comparing snapshot *n*
against *n-1* cannot distinguish "the data moved" from "the sketch was rebuilt", so
this would surface as unexplainable false positives at L2 that no threshold tuning
could remove, and `godwit-replay` could never reproduce a pattern.

Nothing is broken today: the package does not use the upstream KLL. What needs
recording is that it deliberately departs from the stack list.

## What I did instead

Implemented KLL in-package (`godwit_sketch.quantile`), keeping the same `2/3` capacity
schedule and the same published error constants, with the coin replaced by a **keyed
hash of the buffer being compacted, its level, and the sketch's explicit seed**. The
compaction choice is a pure function of content, so the sketch is byte-reproducible on
any machine, in any process, for ever.

Measured against exact quantiles on a million lognormal rows across seeds, the observed
rank error tracks the documented bound at every `k` and halves as `k` doubles. Numbers
are in `docs/packages/godwit-sketch.md`.

One honest caveat, stated in the module and repeated here: the published KLL constants
were fitted for independent fair coins. Hash-derived bits are deterministic, so the
guarantee holds against inputs chosen without knowledge of the seed and is *not* a
guarantee against an adversary who knows the seed and crafts a stream to defeat the
compaction schedule. For a probe running inside a customer's perimeter on their own
data that is an acceptable threat model; if it ever stops being one, the seed becomes a
secret rather than a parameter.

`HllCount` was hand-written for a **different and weaker** reason, recorded here so the
two are not confused. The upstream HLL *is* deterministic across runs. It is not
*canonical*: below its sparse threshold it stores a coupon list in insertion order, so
two unions of the same pair in opposite orders agree on the estimate and disagree on the
bytes. That is fatal to a hierarchy whose equivalence guarantee is byte-level, so HLL is
a dense-register implementation here.

`ThetaNdv` **is** a DataSketches wrapper. It was measured to be both deterministic and
byte-identical across every permutation of its inputs, and it is the one that has to read
Iceberg's `apache-datasketches-theta-v1` Puffin blobs, which is a hard requirement of the
brief and not something worth re-implementing.

## The smallest sufficient change

Amend the stack line to say what is actually true:

> Sketches: apache datasketches python bindings for Theta, including Iceberg Puffin blob
> interop. KLL, HLL and Count-Min are in-package, because the upstream quantile sketches
> are not reproducible and the upstream HLL is not byte-canonical below its sparse
> threshold — both of which break invariant 7 and the batch/streaming equivalence
> guarantee.

## Who else this affects

* **A0** owns the stack list.
* **A4 (`godwit-replay`)** depends on sketches reproducing exactly, and would have
  been the package to discover this the hard way.
* **A7 (`godwit-detect`)** would have seen the non-determinism as drift.
* Anyone tempted to reach for `datasketches.kll_floats_sketch` directly.

## How to revisit this

`test_upstream_kll_is_still_non_deterministic` and
`test_upstream_hll_is_deterministic_but_not_canonical` will **fail** if a future
DataSketches release fixes either problem. That failure is the signal that
`godwit_sketch.quantile` or `godwit_sketch.hll` can be retired in favour of the upstream
one — a deliberate trip-wire rather than a test that needs maintaining.

## Decision

_Left blank by the filer. A human fills this in._
