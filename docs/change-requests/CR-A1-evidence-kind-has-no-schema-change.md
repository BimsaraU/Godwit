# CR-A1-evidence-kind-has-no-schema-change

**Filed by:** A1 (`godwit-source`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

My brief lists `schema_change` as one of the six L-1 metadata detectors. Its output does
not fit any member of `godwit_contracts.discovery.EvidenceKind`:

```
SEGMENT_DIVERGENCE  DISTRIBUTION_SHIFT  RATE_CHANGE  CARDINALITY_SHIFT
HEAVY_HITTER_SHIFT  NULL_RATE_SHIFT     FRESHNESS_STALL
GRAPH_ANOMALY       JOIN_DEGRADATION    RESIDUAL_STRUCTURE
```

The enum's own docstring says it describes "what kind of **statistical claim** a piece of
evidence makes". A schema change is not a statistical claim. A column was added, removed
or retyped; it either happened or it did not, and there is no p-value to report.

## Why it matters

Not much breaks, and I should say so honestly: I emit `RATE_CHANGE` with a p-value of
0.0 and an effect size that counts the changed columns, and everything downstream
validates and stores. The cost is in interpretation, and it lands on two agents:

* **A3/A5 (pattern store)** deduplicate by segment plus *detector family*. A schema
  change and a row-volume anomaly on the same table both arrive as `RATE_CHANGE` over
  the universe segment, which makes the kind useless for telling them apart at a glance.
* **A8 (context)** is the one that really wants this. A schema change *explains away*
  most of what the other five detectors will say about the same snapshot -- a retyped
  column moves its bounds, a dropped column takes its null rate with it. L3's whole job
  is finding that kind of explanation, and it currently has to match on the detector
  name string rather than on a typed kind.

A p-value of 0.0 for a certainty is also mildly dishonest-looking in an audit. It is
true -- the event is certain -- but it reads like a numerical accident.

## The smallest sufficient change

One new member.

```python
# current
class EvidenceKind(StrEnum):
    ...
    JOIN_DEGRADATION = "join_degradation"
    RESIDUAL_STRUCTURE = "residual_structure"


# proposed
class EvidenceKind(StrEnum):
    ...
    JOIN_DEGRADATION = "join_degradation"
    SCHEMA_CHANGE = "schema_change"
    """A column was added, removed or retyped. Not a statistical claim: it is an
    observed event, and it explains away most drift found at the same snapshot."""
    RESIDUAL_STRUCTURE = "residual_structure"
```

Adding a member to `EvidenceKind` changes no key: it appears in `Evidence.kind`, which
is not part of `segment_key` or `probe_key`, and it is not part of a candidate's
deterministic id as computed in this package.

## Who else this affects

* **A1 (`godwit-source`)** emits it from `schema_change`.
* **A7 (`godwit-detect`)** may want it for a schema-aware L2 detector.
* **A8 (`godwit-context`)** consumes it as an explained-away signal.
* **A5 / A3 (pattern store)** store and group it.
* **A16/A17 (Vision Board)** render it, and will want a different icon than a rate change.

No stored key migrates. An older stored `Evidence` carrying `RATE_CHANGE` stays valid.

## What I did instead

`godwit_source.detectors.schema_change` emits `EvidenceKind.RATE_CHANGE`, with the
misfit documented in its docstring, `p_value = 0.0`, and `statistic` set to the count of
columns added, removed or retyped. The names of the changed columns are deliberately not
reported: a column name is a disclosure on its own (`patient_hiv_status`), and a count is
enough for a human to go and look.

```
packages/godwit-source/tests/test_contract_gaps.py::test_schema_change_has_an_evidence_kind
@pytest.mark.xfail(reason="CR-A1-evidence-kind-has-no-schema-change")
```

## Decision

_Left blank by the filer. A human fills this in._
