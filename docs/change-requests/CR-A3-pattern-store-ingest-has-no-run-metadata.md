# CR-A3-pattern-store-ingest-has-no-run-metadata

**Filed by:** A3 (`godwit-store`)
**Against:** `godwit-contracts`
**Status:** open

> Of the requests A3 has filed, read this one first. It is the one that changes what
> another agent has to write.

## The problem

`godwit_contracts.protocols.PatternStore.ingest` is:

```python
def ingest(self, candidates: Sequence[Candidate]) -> tuple[PatternId, ...]: ...
```

Law 3 on the same protocol says:

> FDR control is applied over the whole hypothesis space of a snapshot, not per
> detector. Reporting a raw p-value as significance, when thousands of hypotheses were
> tested, is a lie by omission.

**The signature cannot satisfy the law.** Benjamini-Hochberg needs the size of the
family that was *tested*, and a `Sequence[Candidate]` only carries the ones that
*survived*. A detector that examined ten thousand segments and emitted its best five
hands this method five candidates. Adjusting against five instead of ten thousand makes
each of them look two thousand times more significant than it is — and the more
aggressively a detector prefilters, the better its findings look, which is precisely
backwards.

The brief's deliverable 3 makes the same point from the other side: *"Record test count
per run; an unbounded count is a detector bug you surface rather than absorb."* There is
nowhere in this signature to put a test count, so there is nothing to surface.

The same gap applies to the holdout. Deliverable 3 requires that *"every run reserves a
time or segment slice unused for generation, and a candidate failing to reproduce there
is UNVALIDATED and never reaches the operational queue."* A run's holdout policy, and
the candidates it produced on the reserved slice, have no home in this signature either.

## Why it matters

A3 implemented `ingest` as specified, and made it fail **closed**: with no declared test
count it adjusts against the number of candidates supplied, and with no holdout every
candidate is `NOT_TESTED`, which bars all of them from the operational queue.

That is the right default and it is an unpleasant one. An agent who reads the protocol,
implements against `ingest`, and expects alerts gets none, with the reason visible only
in a `validation_status` column. The wide method that does work — `ingest_batch` — is not
in the contract, so nobody coding against `godwit_contracts` will find it.

A7 (detectors) and A10 (orchestrator) are the two who will hit this.

## The smallest sufficient change

Add the run metadata as keyword-only parameters with no defaults, so an existing caller
fails to typecheck rather than silently getting the conservative path:

```python
# current
def ingest(self, candidates: Sequence[Candidate]) -> tuple[PatternId, ...]: ...


# proposed
def ingest(
    self,
    candidates: Sequence[Candidate],
    *,
    run: DetectorRun,
    holdout_candidates: Sequence[Candidate] = (),
) -> tuple[PatternId, ...]: ...
```

with one new model in `godwit_contracts.discovery`:

```python
class DetectorRun(GodwitModel):
    """One detector execution, and the family it tested."""

    run_id: RunId
    snapshot_id: SnapshotId
    source_id: SourceId
    detector: str
    detector_version: Version
    code_version: str
    seed: int
    test_count: NonNegInt  # hypotheses EXAMINED, not candidates emitted
    q_target: Probability
    holdout: HoldoutPolicy  # see below
    declared_at: Instant
```

`HoldoutPolicy` currently lives in `godwit_store.fdr`. If this request is accepted it
should move into the contracts, because A7 produces it, A3 consumes it and A4 replays
it, and a type three packages share belongs to A0.

## Who else this affects

* **A7 (`godwit-detect`)** — must report how many hypotheses it examined and must run
  its detector a second time over the reserved slice. This is the real cost of the
  request and it is not small.
* **A10 (`godwit-orchestrator`)** — decides the holdout policy and the q target, and owns
  the adaptive-scheduling problem in `CR-A3-fdr-hypothesis-space`.
* **A4 (`godwit-replay`)** — needs the holdout policy to rebuild the reserved slice.
* **A3 (`godwit-store`)** — already has the wide method; this only changes which one is
  in the contract.

No stored key migrates.

## What I did instead

Implemented `ingest` exactly as written, as a conservative wrapper:

* `test_count` defaults to the number of candidates supplied, which is honest only when
  the detector emitted one per hypothesis, and is the least conservative choice
  available with no other information.
* The holdout is `NONE`, so every candidate is `NOT_TESTED` and **none reaches the
  operational queue**.

The wide method `PatternStore.ingest_batch(family=..., candidates=..., holdout=...,
holdout_candidates=..., at=...)` takes everything the law needs, and
`godwit_store.fdr.HypothesisFamily` and `HoldoutPolicy` are the types it takes.

```
packages/godwit-store/tests/test_store.py::test_the_narrow_ingest_bars_everything_from_the_operational_queue
```

is not an xfail — it passes, and documents the cost. The behaviour it pins is what
changes if this request is accepted.

## A naming note, not part of this request

If `TestFamily` had been the name of the new model, pytest would refuse to collect any
test module that imports it (`PytestCollectionWarning: cannot collect test class
'TestFamily' because it has a __init__ constructor`). A3 hit this and renamed its own
type to `HypothesisFamily`. Worth avoiding a `Test*` prefix on anything in
`godwit-contracts`, since every package imports from it into test modules.

## Decision

_Left blank by the filer. A human fills this in._
