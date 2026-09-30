# CR-A1-sketch-serialise-needs-context

**Filed by:** A1 (`godwit-source`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

`Sketch.serialise()` in `godwit_contracts.protocols` takes no arguments and returns a
`SketchEnvelope`. A `SketchEnvelope` requires seven fields that a sketching algorithm
cannot know:

| Field | Known by |
|---|---|
| `source_id` | the adapter |
| `snapshot_id` | the adapter |
| `produced_for` (a `ProbeKey`) | the probe spec |
| `produced_at` | the caller, who injects time |
| `provenance` | the adapter, which knows the acquisition route |
| `sensitivity` | jointly: the *kind* implies a floor, the route decides the rest |
| `population` | whoever counted the rows |

A `Theta` sketch built by A2 has a serialised payload, a set of construction parameters
and an error bound. It has never heard of a snapshot.

## Why it matters

It blocks the seam between A1 and A2 that my brief names as a non-goal for me: *"no
sketch implementations -- code against the Protocol; A2 provides the classes."* I cannot
code against `Sketch` alone, because calling `serialise()` on an A2 object cannot
produce a valid envelope without data only I have.

The workarounds are all worse than the fix:

* `envelope.model_copy(update={...})` after the fact bypasses the validators that make
  `SketchEnvelope` worth having, including the one that stops an item-bearing sketch
  declaring itself a derived statistic.
* Passing the context into every `Sketch` constructor makes the monoid laws awkward:
  `merge(a, b)` then has to reconcile two snapshots' worth of context, and
  `identity(params)` has none at all.

## The smallest sufficient change

Give `serialise` the context as keyword arguments. The monoid laws are untouched --
`merge`, `identity` and `decode` keep their current shapes, and `decode` still reads a
whole envelope.

```python
# current
def serialise(self) -> SketchEnvelope:
    """Encode to a storable envelope, tagged with the correct sensitivity."""
    ...


# proposed
def serialise(
    self,
    *,
    source_id: SourceId,
    snapshot_id: SnapshotId,
    produced_for: ProbeKey,
    produced_at: Instant,
    provenance: Provenance,
) -> SketchEnvelope:
    """Encode to a storable envelope, tagged with the correct sensitivity.

    The caller supplies the context: a sketch knows its own bytes, parameters and
    error bound, and nothing about where the rows came from. `sensitivity` is still
    the sketch's own decision -- an item-bearing kind must declare DATA_VALUE -- and
    `population` is still its own count.
    """
    ...
```

An alternative that also works, and is smaller still, is a `SketchContext` model in
contracts passed as one argument. I have no preference; the point is that the context
has to arrive from outside.

## Who else this affects

* **A2 (`godwit-sketch`)** implements `serialise`. This is their signature.
* **A6 (`godwit-probe`)** calls it from the worker and already holds every field.
* **A1 (`godwit-source`)** calls it from `execute_probe` for both the Iceberg and the
  SQL paths.
* **A4 (`godwit-replay`)** reads envelopes back and is unaffected: `decode` is unchanged.

It does **not** change `segment_key` or `probe_key`, and no stored key migrates.

## What I did instead

`godwit-source` defines its own narrow injection point,
`godwit_source.sketches.SketchBuilder`, which takes the context explicitly and returns a
finished `SketchEnvelope`. Both adapters call it and this package still owns no sketch
code. If this CR is accepted, `SketchBuilder` collapses into a direct
`Sketch.serialise(...)` call and the module is deleted.

```
packages/godwit-source/tests/test_contract_gaps.py::test_a_sketch_can_serialise_itself
@pytest.mark.xfail(reason="CR-A1-sketch-serialise-needs-context")
```

## Decision

_Left blank by the filer. A human fills this in._
