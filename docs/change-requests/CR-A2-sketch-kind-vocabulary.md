# CR-A2-sketch-kind-vocabulary

**Filed by:** A2 (`godwit-sketch`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

`godwit_contracts.sketch.SketchKind` names six kinds and is explicitly closed:

> The sketch vocabulary. A kind not listed here cannot cross a package boundary.

The A2 brief requires eight sketches. Four of them have no member:

| Sketch | Brief requires it | `SketchKind` member |
|---|---|---|
| `ThetaNdv` | yes | `THETA` |
| `HllCount` | yes | `HLL` |
| `KllQuantile` | yes | `KLL` |
| `CountMinHeavy` | yes | `COUNT_MIN` |
| `Moments` | yes | **none** |
| `NullRate` | yes | **none** |
| `CategoryHistogram` | yes | **none** |
| `GraphDegree` | yes | **none** |

`ProbeKind` in `godwit_contracts.probe` already names `NULL_RATE`, `CATEGORY_HISTOGRAM`
and `GRAPH_DEGREE` as things a probe measures, so the layer above can *ask* for these
measurements but there is no vocabulary for the sketches that come back.

## Why it matters

Nothing is unsafe. The vocabulary is simply not expressive enough to say what a
payload is, so `codec` has to carry information `kind` should be carrying, and a
detector switching on `kind` sees four classes wearing another kind's name.

## What I did instead

Implemented against the contract exactly as written. Each of the four serialises under
the nearest existing kind, with a distinct codec as the real discriminator:

| Class | `kind` it serialises as | `codec` |
|---|---|---|
| `Moments` | `EXACT_COUNT` | `godwit-moments-v1` |
| `NullRate` | `EXACT_COUNT` | `godwit-nullrate-v1` |
| `CategoryHistogram` | `FREQUENT_ITEMS` | `godwit-cathist-v1` |
| `GraphDegree` | `COUNT_MIN` | `godwit-graphdegree-v1` |

`godwit_sketch.SKETCH_REGISTRY` is therefore keyed by **codec, not kind**, and
`decode_envelope` dispatches on codec.

The consequences are real but bounded, and every one of them is a readability problem
rather than a safety one:

- A detector switching on `envelope.kind` cannot tell a moment summary from a row count,
  or a graph-degree sketch from a plain Count-Min. It has to switch on `codec`.
- `GraphDegree` and `CategoryHistogram` land inside `ITEM_BEARING_KINDS` by inheritance
  from the kind they borrow, which happens to be correct — both *are* item-bearing — but
  it is correct by luck rather than by statement.
- `Moments` is item-bearing (it holds the minimum and maximum) while `EXACT_COUNT` is
  not in `ITEM_BEARING_KINDS`. A2 declares its envelopes `DATA_VALUE` explicitly, which
  is contract-legal because an envelope may always be *more* restricted than its floor.
  But a future implementer serialising something else as `EXACT_COUNT` gets no help from
  the validator.

## The smallest sufficient change

Add four members:

```python
class SketchKind(StrEnum):
    ...
    MOMENTS = "moments"
    """Count, sum, extremes and central moments. LEAK PATH: min and max are row values."""

    NULL_RATE = "null_rate"
    """Nulls over total. Two counters, no value retained."""

    CATEGORY_HISTOGRAM = "category_histogram"
    """Category counts. LEAK PATH: below the cardinality threshold the labels are exact."""

    GRAPH_DEGREE = "graph_degree"
    """Fan-in and fan-out structure. LEAK PATH: the heavy hitters are entity identifiers."""
```

and extend the item-bearing set to `{COUNT_MIN, FREQUENT_ITEMS, KLL, CATEGORY_HISTOGRAM,
GRAPH_DEGREE, MOMENTS}` — `KLL` for the reason in `CR-A2-kll-is-item-bearing.md`, and
`MOMENTS` because the maximum of a column is some row's value, as the taint module
already says.

A2 will then move each class onto its own kind and keep the codec as the payload
version, which is what codecs are for.

## Who else this affects

* **A0** owns `SketchKind` and `ITEM_BEARING_KINDS`.
* **A7 (`godwit-detect`)** and **A11 (`godwit-features`)** switch on what a sketch is.
* **A3 (`godwit-store`)** persists envelopes and may index on `kind`.
* **A6 (`godwit-probe`)** already has `ProbeKind.NULL_RATE`, `CATEGORY_HISTOGRAM` and
  `GRAPH_DEGREE` with no matching sketch kind to return.

**Stored envelopes migrate.** Anything already written as `EXACT_COUNT` that is really
a moment summary needs re-tagging, so this is cheaper done early than late.

## Evidence

`packages/godwit-sketch/tests/test_contract_gaps.py::test_sketch_kind_covers_every_kind_the_brief_requires`
is an `xfail(strict=True)` asserting the four names exist. It starts `XPASS`ing the
moment this is accepted, which is how A2 finds out.

## Decision

_Left blank by the filer. A human fills this in._
