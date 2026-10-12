# CR-A6-sketch-bundle-cannot-say-why

**Filed by:** A6 (`godwit-probe`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

The brief says a probe over budget returns "a REFUSED bundle, explaining what it would have
cost", that "refusal is a first-class signal the orchestrator uses", that a no-change probe
"costs near zero and says so", that a cancelled probe records its partial cost, and that a
plain-key permission on an identifier column is "recorded in the bundle".

`SketchBundle` can express none of that. Its fields are `bundle_id`, `probe_key`,
`source_id`, `snapshot_id`, `sketches`, `cost_spent`, `produced_at`, `worker_version` and
`seed`. Specifically:

1. **No status.** A refused, a cancelled and a no-change run would all be a bundle with an
   empty `sketches` map and a zero or partial `cost_spent`. They are three different signals
   to the orchestrator (A10) and indistinguishable here.
2. **No refusal reason and no estimate.** "Over budget: would have cost 2.1 GB" and "column
   3 is BLIND" need different reactions. The contract has nowhere to put either.
3. **No start of the snapshot range.** An incremental probe measures `(since, until]`. The
   bundle records `until` only. Two bundles for the same probe key and the same `until` --
   one incremental, one a full re-probe after an overwrite -- cannot be told apart, and a
   consumer merging deltas cannot check it has a contiguous chain.
4. **No record of a plain-key permission.** `SketchEnvelope.params` is documented as "OUR
   parameters" and is the merge identity; putting a guardrail id there would make two
   otherwise identical sketches unmergeable.

## Why it matters

The orchestrator's bandit learns from refusals (invariant 6: refusing is a normal outcome).
If a refusal is not representable in the contract type, every consumer has to import
`godwit_probe.ProbeOutcome` -- a data-plane package -- to learn why a probe did not run.
And replay (A4) cannot reconstruct which snapshot range a stored bundle covered; this is
the same hole `CR-A4-probe-snapshot-resolution-is-unrecorded` describes from the other side.

Nothing is unsafe today. It is a contract that cannot carry what the brief requires.

## The smallest sufficient change

Add one model to `godwit_contracts.probe` (or `sketch`), shaped like the one A6 already
ships, and leave `SketchBundle` unchanged:

```python
class ProbeStatus(StrEnum):
    COMPLETED = "completed"; NO_CHANGE = "no_change"; REFUSED = "refused"; CANCELLED = "cancelled"

class ProbeOutcome(GodwitModel):
    status: ProbeStatus
    probe_key: ProbeKey
    source_id: SourceId
    since_snapshot_id: SnapshotId | None       # start of the measured range, exclusive
    snapshot_id: SnapshotId                    # the resolved end, inclusive
    bundle: SketchBundle | None                # present iff COMPLETED
    refusal_reason: str | None                 # a closed vocabulary; never a value
    refusal_column_index: int | None           # position, never a name
    estimated_cost: CostSpend
    cost_spent: CostSpend
    full_rescan: bool
    plain_key_guardrails: tuple[tuple[str, str, Version], ...]  # (sketch name, guardrail id, version)
```

A lighter alternative is two optional fields on `SketchBundle` (`since_snapshot_id`,
`plain_key_guardrails`) plus the outcome model for the no-bundle cases. Neither changes
`probe_key` or `segment_key`.

## Who else this affects

* **A10 (orchestrator)** consumes refusals and estimates.
* **A4 (replay)** needs the range to replay a bundle faithfully.
* **A3 (store)** persists bundles and may want the range as part of the key.
* **A7 / A11** merge delta bundles and would like to verify contiguity.

## What I did instead

`godwit_probe.executor.ProbeOutcome` carries exactly the fields above, validates that the
status matches what is present (a `COMPLETED` outcome has a bundle, a `REFUSED` one has a
refusal, and so on), and wraps an unmodified `SketchBundle`. The worker stores the bundle
and the outcome side by side, keyed on `(probe_key, since_snapshot_id, snapshot_id)`.

```
packages/godwit-probe/tests/test_contract_gaps.py::test_the_contract_can_express_a_refused_or_delta_probe
@pytest.mark.xfail(strict=True, reason="CR-A6-sketch-bundle-cannot-say-why")
```

## Decision

_Left blank by the filer. A human fills this in._
