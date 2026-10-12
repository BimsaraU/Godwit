# CR-A7-evidence-has-no-structured-detail

**Filed by:** A7 (`godwit-detect`)
**Against:** `godwit-contracts` (`Evidence`, `Candidate`, `Lineage`)
**Status:** open

## The problem

The brief asks for three things the contract types cannot hold:

* evidence "mechanically convertible into a feature definition -- name the segment,
  columns, window and direction in a structured way";
* a p-value, *or a documented reason there is none*;
* "a declared test count per run so A3 can control false discovery honestly".

`Evidence` has fields for the segment and the columns. It has no field for anything else
in that list:

| Needed | Where it can go today |
|---|---|
| Direction (up / down / appeared / vanished / changed) | Nowhere. The sign of `effect_size` covers some cases, but not "appeared" and not a change in a categorical mix |
| Window: the baseline policy and the *range* of reference snapshots | One `baseline_snapshot_id` |
| The method used inside the detector (`psi`, `entrant`, `funnel_signature`) | Nowhere. `Lineage.detector` names only the detector |
| Units of `statistic` and `effect_size` | Nowhere |
| Why `p_value` is None | Nowhere |
| Shape statistics that carry no identities, and per-feature attribution | Nowhere |
| Number of hypotheses the run tested | Nowhere. There is one `Candidate` per finding |
| Detector settings (thresholds, bins) | Nowhere. Replay from `(spec, snapshot, version, seed)` assumes the defaults |

## Why it matters

* **A11** cannot turn a candidate into a feature from the candidate alone, because the
  information is not there to parse. It has to use `godwit_detect.Finding` instead.
* **A3** receives only the emitted candidates. It cannot tell whether a run tested one
  hypothesis or four hundred. That understates the family size in exactly the way
  `CR-A3-fdr-hypothesis-space` warns about, one level down.
* **A4** cannot replay a run whose settings differed from the defaults.
* A missing p-value (the matrix profile has no valid null) looks the same as a p-value
  someone forgot to fill in.

## The smallest sufficient change

```python
class Evidence(GodwitModel):
    ...
    direction: str | None = None  # "up" | "down" | "appeared" | "vanished" | "changed"
    method: str | None = None
    baseline_policy: str | None = (
        None  # "fixed(<snap>)" | "trailing(points=n)" | "seasonal(period=p,cycles=c)"
    )
    baseline_snapshot_ids: tuple[SnapshotId, ...] = ()
    effect_unit: str | None = None
    p_value_note: str = ""
    shape: Mapping[str, Tainted[float]] = {}  # DERIVED_STATISTIC only


class Lineage(GodwitModel):
    ...
    settings_digest: str | None = None
    tests_in_run: NonNegInt | None = None
```

Every new field is optional, so existing producers stay valid. No key changes.

## Who else this affects

* **A3** persists evidence and lineage.
* **A4** replays from lineage.
* **A11** consumes the evidence.
* **A5** gates the new fields. `shape` holds statistics only; the other fields use our
  own vocabulary.
* **A15** explains the evidence.

## What I did instead

* `godwit_detect.Finding` carries all of the fields above, and `DetectionResult.tests`
  carries the test count.
* `to_candidate()` projects a finding onto the contract types and documents what it
  drops. The most recent reference snapshot becomes `baseline_snapshot_id`.
* Detector semantic versions are encoded into the integer `Lineage.detector_version` as
  `major*1e6 + minor*1e3 + patch`. That encoding needs no contract change.

```
packages/godwit-detect/tests/test_contract_gaps.py::test_evidence_carries_direction_window_and_method
packages/godwit-detect/tests/test_contract_gaps.py::test_a_run_can_declare_how_many_hypotheses_it_tested
packages/godwit-detect/tests/test_contract_gaps.py::test_lineage_records_detector_settings
@pytest.mark.xfail(strict=True, reason="CR-A7-evidence-has-no-structured-detail")
```

## Decision

_Left blank by the filer. A human fills this in._
