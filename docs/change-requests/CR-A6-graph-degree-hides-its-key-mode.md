# CR-A6-graph-degree-hides-its-key-mode

**Filed by:** A6 (`godwit-probe`)
**Against:** `godwit-sketch` (A2)
**Status:** open

## The problem

`CountMinHeavy.with_hasher(h)` changes the sketch's `params` to include `key_mode`,
`key_id` and `input_entropy_bits`, so an envelope says truthfully that its keys are
hashed, and two sketches keyed differently refuse to merge.

`GraphDegree.with_hasher(h)` does not. It passes `params=self._params` through unchanged,
so a GraphDegree whose entity keys are hashed under a data-plane key serialises with the
same `params` -- and the same `producer_fingerprint` -- as one storing plain entity ids:

```python
sketch = GraphDegree.identity({}).with_hasher(KeyHasher.opaque(key=k, input_entropy_bits=64))
sketch.params.get("key_mode")  # None; the inner Count-Min pair *is* hashed
```

## Why it matters

1. **Merge identity.** Invariant 6 law 4: merging sketches with different construction
   parameters must raise. A hashed and a plain GraphDegree, or two hashed under different
   keys, currently merge silently and add unrelated counters.
2. **Disclosure.** A guardrail or a reviewer reading the envelope cannot tell that the
   fan-in / fan-out heavy hitters are pseudonyms rather than account ids.

Nothing leaks from A6 today: the payload really is hashed (asserted by
`test_executor.py::test_graph_degree_over_opaque_identifiers_completes`, which checks that
neither raw ids nor column digests appear in the bytes). The envelope just does not say so.

## The smallest sufficient change

In `GraphDegree.with_hasher`, merge the hasher's parameters in, exactly as `CountMinHeavy`
does:

```python
params = ({**self._params, **hasher.params()},)
```

This changes the fingerprint of hashed GraphDegree envelopes, which is the point. No stored
key (`probe_key`, `segment_key`) changes.

## Who else this affects

* **A2** owns the class.
* **A7 / A11** read graph envelopes and may merge them.
* **A5 / A18** write guardrails over envelope parameters.

## What I did instead

Nothing to work around in A6: the probe hashes both endpoint columns before they reach the
sketch (OPAQUE columns arrive as HMAC digests) and gives the sketch an OPAQUE-mode hasher
on top. The missing declaration is recorded here and in the HANDOFF.

```
packages/godwit-probe/tests/test_contract_gaps.py::test_a_hashed_graph_sketch_declares_its_key_mode
@pytest.mark.xfail(strict=True, reason="CR-A6-graph-degree-hides-its-key-mode")
```

## Decision

_Left blank by the filer. A human fills this in._
