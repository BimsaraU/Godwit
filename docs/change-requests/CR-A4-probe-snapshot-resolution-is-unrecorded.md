# CR-A4-probe-snapshot-resolution-is-unrecorded

**Filed by:** A4 (`godwit-replay`)
**Against:** `godwit-contracts` (and by consequence A10, `godwit-orchestrator`)
**Status:** open

This is `docs/ARCHITECTURE.md` open question 4, which names A4 and A10 as the agents who have
to agree. Here is A4's half.

## The problem

`ProbeSpec.snapshot` is `SnapshotRef | None`, and the docstring says:

> ``snapshot`` may be ``None`` at scheduling time, meaning "whatever is current when this
> runs". The worker MUST record the snapshot it resolved in the returned ``SketchBundle``;
> replay uses the resolved one, never ``None``.

That is a clear instruction and it is not sufficient, for two reasons.

**First, the resolution is only recorded where the result survives.** `SketchBundle` carries
`snapshot_id`, so a successful run is reproducible. A run that was *refused on budget*, or
that failed, produces no bundle — and therefore no record of which snapshot it would have
measured. Invariant 6 makes refusal a normal outcome, so this is not an edge case: it is the
ordinary path for every probe the orchestrator's bandit declines to pay for. Replaying "what
did the system decide, and against what" cannot be done from a spec whose snapshot is `None`
and a bundle that does not exist.

**Second, `probe_key` deliberately excludes the snapshot**, which is right — the same
measurement at two snapshots must share a key. But it means that given a stored `ProbeKey`
and a stored `SnapshotId`, nothing in the contract *binds* them as "this key was resolved
against this snapshot at this scheduling instant". The pairing lives only inside whatever the
orchestrator happens to persist, which is A10's private choice and therefore not something
a replay written by a different agent can rely on.

A concrete reading problem: `Lineage` has `snapshot_id` and `baseline_snapshot_id`, so a
*candidate* is reproducible. There is no equivalent for a *scheduling decision*.

## Why it matters

The brief asks me to replay history "as if it were arriving live" and to diff two
configurations over the same replay. A champion/challenger diff whose arms disagree about
which snapshots were even attempted is not a comparison of the configurations; it is a
comparison of two different experiments. Today I cannot tell those apart from contract types
alone, because a refused probe leaves no trace with a snapshot in it.

What breaks in practice, today: nothing, because the orchestrator does not exist yet and my
driver materialises its own snapshot sequence. What will break: the first time a real
orchestrator run is replayed and a bandit's refusals are silently absent from the record.

## The smallest sufficient change

One small type, and one field on `ProbeSpec`. Not a redesign of scheduling.

```python
# current
class ProbeSpec(GodwitModel):
    snapshot: SnapshotRef | None = None
    ...


# proposed -- in godwit_contracts.probe
class SnapshotResolution(GodwitModel):
    """What a scheduled probe was resolved against, recorded whether or not it ran.

    Written by whoever resolves ``ProbeSpec.snapshot`` from None, before the work is
    attempted. A refusal on budget still produces one of these; that is the point.
    """

    probe_key: ProbeKey
    resolved_snapshot_id: SnapshotId
    resolved_at: Instant
    resolver_version: Version


class ProbeSpec(GodwitModel):
    snapshot: SnapshotRef | None = None
    resolution: SnapshotResolution | None = Field(
        default=None,
        description="Set once the snapshot has been resolved. A spec with snapshot=None "
        "and resolution=None has not been scheduled yet; one with a resolution has, and "
        "replay reads the snapshot from here rather than from the bundle.",
    )
```

Alternatively, and even smaller: leave `ProbeSpec` alone and state in the docstring that the
orchestrator must persist `(probe_key, resolved_snapshot_id, resolved_at)` for **every**
resolution including refusals, and give that triple a name in contracts so two agents mean
the same thing by it. I would accept either. The one outcome I want to avoid is the current
one, where the rule exists in prose and the type that carries it does not.

## Who else this affects

* **A10** (`godwit-orchestrator`) is the resolver and the other half of this decision. The
  cost falls on A10: it has to write a record before spending rather than after.
* **A6** (`godwit-probe`) fills `SketchBundle.snapshot_id` today and would keep doing so; the
  resolution record is upstream of it.
* **A3** (`godwit-store`) may want to store resolutions alongside candidates.
* **A4** (this package) consumes it.

`probe_key` and `segment_key` are untouched, so nothing stored is migrated.

## What I did instead

`godwit_replay.driver.replay` never accepts a `ProbeSpec` with an unresolved snapshot. It
takes an explicit, ordered `history` of `SnapshotMetadata` plus the clock instants and period
keys that correspond to it, and it *rejects* any candidate whose lineage names a snapshot
outside the visible set — including one that arrives from a spec resolved after the fact. The
resolution problem is pushed onto the caller, which today is my own harness, and which
tomorrow will be A10.

`godwit_replay.harness.retime` additionally overwrites each snapshot's `committed_at` with the
instant the data's own period closed, because an Iceberg commit time is the wall clock of
whichever machine loaded the table. That is a separate honesty problem with the same root:
the contract's snapshot record carries a time that is about the loader, not about the data.

```
packages/godwit-replay/tests/test_contract_gaps.py::test_a_refused_probe_records_the_snapshot_it_resolved
@pytest.mark.xfail(reason="CR-A4-probe-snapshot-resolution-is-unrecorded")
```

## Decision

_Left blank by the filer. A human fills this in._
