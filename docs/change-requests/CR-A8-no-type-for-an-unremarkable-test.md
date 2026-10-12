# CR-A8-no-type-for-an-unremarkable-test

**Filed by:** A8 (`godwit-context`)
**Against:** `godwit-contracts` (`godwit_contracts.protocols.Detector`)
**Status:** open

## The problem

The counterfactual check asks one question: did comparable segments that this context did
NOT touch show the same change? Answering it needs observations of segments that did not
change, with their effect sizes. The `Detector` protocol returns only `Candidate`s, and a
candidate exists only when something changed. A7 records every hypothesis it examined
(`DetectionResult.tests`), but that type belongs to A7 and is not in the contracts.

## Why it matters

Without "did not change" observations, the check can only count untouched peers that DID
change: the other candidates in the batch. That half catches contradictions. A deploy on A,
with the same spike on B, C and D, is still downgraded. But it can never mark a match
SUPPORTED. Every match then gets the partial UNTESTABLE credit, and fewer benign anomalies
are explained away. Nothing becomes unsafe: the failure is conservative. The cost is
mainly utility.

## The smallest sufficient change

```python
# proposed, in godwit_contracts.discovery
class HypothesisTest(GodwitModel):
    """One hypothesis a detector examined, whether or not it became a candidate."""
    source_id: SourceId
    segment: Segment
    columns: tuple[Tainted[str], ...] = ()
    kind: EvidenceKind
    observed_at: Instant
    effect_size: Tainted[float]          # DERIVED_STATISTIC
    p_value: Tainted[float] | None = None
```

The protocol then returns `(candidates, tests)`, or puts `tests` on a result object. A3's
FDR control needs the same thing: it needs to know how many hypotheses were examined (see
CR-A7-evidence-has-no-structured-detail, CR-A3-fdr-hypothesis-space).

## Who else this affects

A0, A7 (already has the data), A3 (FDR family size), A10 (passes the tests on to L3 and L5).

## What I did instead

`godwit_context.PeerObservation` is my own type with exactly these fields. The orchestrator
converts A7's `DetectionResult.tests` into it. When no peers are supplied, the other
candidates in the batch serve as peers that changed.

```
packages/godwit-context/tests/test_contract_gaps.py::test_the_contracts_can_carry_an_unremarkable_test
@pytest.mark.xfail(strict=True, reason="CR-A8-no-type-for-an-unremarkable-test")
```

## Decision

_Left blank by the filer. A human fills this in._
