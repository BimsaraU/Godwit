# CR-A7-detector-cannot-see-history-or-spec

**Filed by:** A7 (`godwit-detect`)
**Against:** `godwit-contracts` (`godwit_contracts.protocols.Detector`)
**Status:** open

## The problem

```python
def detect(
    self,
    *,
    current: SketchBundle,
    baseline: SketchBundle | None,
    profiles: Sequence[ColumnProfile],
    seed: int,
) -> tuple[Candidate, ...]: ...
```

The brief requires two things that this signature cannot express.

1. **One baseline bundle is not a history.** The brief asks for three baseline policies:
   fixed reference, trailing, and seasonal same-period-last-cycle. It says the seasonal one
   must be implemented properly because a trailing baseline "fires every Monday morning".
   A seasonal baseline needs the same phase of *several* earlier cycles, such as the last
   four Mondays. Several detectors also need more than one reference window to produce a
   p-value at all. A fan-in ratio built from three Theta estimates has no closed-form
   variance, so the graph detector estimates it from the spread across reference windows.
   Rank churn is tested against the churn between consecutive references. With one
   baseline bundle, both have to refuse.
2. **A bundle does not say what it measured.** `SketchBundle` carries a probe key and
   sketch names such as `frequent_items:0`. The segment, and the column behind index `0`,
   are in the `ProbeSpec`, which the detector never sees. `profiles` does not fill the gap,
   because nothing maps a profile to a sketch index. So a detector cannot fill
   `Evidence.segment` or `Evidence.columns`, which are the structured fields A11 needs to
   turn a finding into a feature.

## Why it matters

Through the protocol as written:

* the seasonal baseline, the one the brief singles out, cannot be reached;
* the graph (mule) detector always refuses;
* every candidate carries the universe segment and no columns, unless the caller passes
  the spec some other way.

## The smallest sufficient change

```python
# proposed
def detect(
    self,
    *,
    spec: ProbeSpec,
    current: SketchBundle,
    history: Sequence[SketchBundle],
    profiles: Sequence[ColumnProfile],
    seed: int,
) -> tuple[Candidate, ...]: ...
```

`history` holds every earlier bundle for the same probe key, oldest first, with gaps
omitted. The detector's own baseline policy chooses from it, so today's `baseline` is
`history[-1:]`. No key changes.

## Who else this affects

* **A10 (orchestrator)** calls `detect`, so it must pass history and spec. It already
  holds both.
* **A4 (replay)** must replay with the same history. The lineage's `baseline_snapshot_id`
  names only one of the windows (see `CR-A7-evidence-has-no-structured-detail`).
* **A9 (SDK)**, if it re-exports the protocol.

## What I did instead

The detectors take a `SketchSeries` (from `godwit_detect.series`) and a baseline policy
directly. `godwit_detect.BundleDetector` adapts any series detector to the protocol:

* it takes the `ProbeSpec` when it is constructed;
* it uses the single baseline bundle as a fixed reference;
* it lets detectors that need history refuse, and the refusal is visible in
  `last_results`.

```
packages/godwit-detect/tests/test_contract_gaps.py::test_the_detector_protocol_can_hand_over_a_history
packages/godwit-detect/tests/test_contract_gaps.py::test_the_detector_protocol_says_what_a_bundle_measured
@pytest.mark.xfail(strict=True, reason="CR-A7-detector-cannot-see-history-or-spec")
```

## Decision

_Left blank by the filer. A human fills this in._
