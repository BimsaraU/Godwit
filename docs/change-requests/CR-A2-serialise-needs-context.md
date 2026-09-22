# CR-A2-serialise-needs-context

**Filed by:** A2 (`godwit-sketch`)
**Against:** `godwit-contracts`
**Status:** open — **concurs with `CR-A1-sketch-serialise-needs-context`**

> This is not an independent finding. A1 hit the same wall from the calling side and
> filed it first. A2 owns `serialise`, so this records the implementer's view and, since
> A1 explicitly wrote "I have no preference" between the two proposed shapes, argues for
> one of them. **Decide the two together; they are one change.**

## The problem

Exactly as A1 describes it: `Sketch.serialise()` takes no arguments and must return a
`SketchEnvelope` carrying `source_id`, `snapshot_id`, `produced_for` and `produced_at`,
none of which a summary can know.

One correction to A1's table, from the implementing side. A1 lists `provenance`,
`sensitivity` and `population` as also unknowable by the sketch. Two of those three the
sketch can and should own:

* **`sensitivity`** is the sketch's own call and must stay there. It is the one field
  where the class knows something the caller does not — that a KLL payload retains row
  values, that a Count-Min's heavy hitters are the keys themselves. If the caller
  supplied it, a caller who got it wrong would defeat the validator that exists to stop
  exactly that.
* **`population`** is the sketch's own counter. Contract law 7 makes it additive under
  merge, so nobody else can supply it correctly after a fold.
* **`provenance`** genuinely does need the caller: only the adapter knows the table and
  column. But it needs only those two strings, not a constructed `Provenance` — the
  sketch already knows its own `Acquisition`, which is what sets the taint floor.

So the context the sketch actually needs from outside is six optional-ish strings, not
seven fields.

## Why it matters

Same as A1: it blocks the A1/A2/A6 seam. Nothing is unsafe, and there is a clean
workaround on both sides, so this is low severity and should not hold anyone up.

## The smallest sufficient change

A1 offered two shapes and preferred neither. A2 prefers the **`SketchContext` model**,
for a reason that only shows up when implementing it: keyword arguments would have to be
repeated on every override, and `TimeHierarchy` passes the same context through many
folds, where one frozen object is easier to keep honest than five parallel arguments.

```python
# current
def serialise(self) -> SketchEnvelope: ...


# proposed — add to godwit_contracts.sketch, beside SketchEnvelope
class SketchContext(GodwitModel):
    """The run context an envelope needs and a sketch has no business holding."""

    source_id: SourceId
    snapshot_id: SnapshotId
    produced_for: ProbeKey
    produced_at: Instant
    table: str | None = None
    column: str | None = None


def serialise(self, context: SketchContext) -> SketchEnvelope: ...
```

`table` and `column` feed `Provenance`, so a redaction label can say which column a
value came from instead of rendering `from unknown` — which, as it happens, is currently
the only reason `godwit-sketch`'s PII backstop test has to special-case the string
"unknown".

Holding the context *inside* the sketch instead would be worse, and this is the part A1
could not see from the calling side: two sketches from two data files of the same
snapshot would then differ in fields unrelated to their contents, so `merge` would need
a reconciliation rule for run metadata, and `TimeHierarchy` merges across time windows by
design — `produced_at` genuinely differs there, with no sensible answer.

## Who else this affects

* **A2 (`godwit-sketch`)** implements it. Deletes its local `SketchContext` and imports
  the contract one.
* **A1 (`godwit-source`)** calls it; `godwit_source.sketches.SketchBuilder` collapses.
* **A6 (`godwit-probe`)** calls it from the worker and already holds every field.
* **A4 (`godwit-replay`)** unaffected — `decode` is unchanged.

No stored key migrates. `segment_key` and `probe_key` are untouched.

## What I did instead

Defined `godwit_sketch.base.SketchContext` locally with exactly the shape above, and:

```python
def serialise(self, context: SketchContext | None = None) -> SketchEnvelope: ...
```

The default keeps the zero-argument call shape the protocol declares, so
`isinstance(sketch, Sketch)` still holds. Calling it that way raises `ValueError` naming
this CR, because an envelope without a snapshot cannot be stored or replayed.

```
packages/godwit-sketch/tests/test_contract_gaps.py::test_serialise_without_context_refuses_rather_than_inventing_one
```

Not marked `xfail`: the refusal is the correct behaviour under the contract as written,
so it is an ordinary passing test rather than a pending one.

## Decision

_Left blank by the filer. A human fills this in._
