# CR-A8-candidate-has-no-window

**Filed by:** A8 (`godwit-context`)
**Against:** `godwit-contracts` (`godwit_contracts.discovery.Candidate`)
**Status:** open

## The problem

Matching a candidate against a deploy, a campaign or a holiday is temporal alignment:
did the context happen when the change happened? A candidate carries one instant,
`created_at`. The time span in which the change happened is not in the contract.

A7 sets `created_at` to the instant of the current window (`evidence.py`, `to_candidate`).
The window's length is the probe cadence, and that is in the orchestrator's schedule. It is
not in the candidate, the lineage or the evidence. `Lineage.baseline_snapshot_id` names the
reference snapshot, but with a seasonal baseline that reference is four weeks back. Using
it as the window start would make every context in the last month "temporally aligned".

## Why it matters

Something does break. A deploy at 02:00 explains a daily-window candidate stamped 23:59
the same day. It does not explain an hourly-window candidate stamped 23:59. With only
`created_at`, the context layer cannot tell these two apart.

## The smallest sufficient change

```python
# current
class Candidate(GodwitModel):
    ...
    created_at: Instant

# proposed
class Candidate(GodwitModel):
    ...
    created_at: Instant
    window_start: Instant | None = Field(
        default=None,
        description="Start of the interval in which the change was observed. "
        "created_at is its end. None means unknown.",
    )
```

The field is optional, so no existing producer breaks. It does not affect `segment_key` or
`probe_key`.

## Who else this affects

A0 (the field). A7 and A1 should fill it, since both know the window they measured. A3
stores candidates as a payload and needs no change beyond accepting the field. A10 can stop
passing windows to A8 by hand.

## What I did instead

`MatchPolicy.window_by_source` and `default_window` (one day) give each source a window
length. A candidate's window is `[created_at - span, created_at]`.
`ContextRouter.route(..., windows=...)` accepts an explicit per-candidate window and lets
the orchestrator override this.

```
packages/godwit-context/tests/test_contract_gaps.py::test_a_candidate_says_when_its_change_began
@pytest.mark.xfail(strict=True, reason="CR-A8-candidate-has-no-window")
```

## Decision

_Left blank by the filer. A human fills this in._
