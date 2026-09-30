# CR-A3-lifecycle-has-no-stale

**Filed by:** A3 (`godwit-store`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

The brief's deliverable 4 asks for automatic staleness:

> Staleness automatic: no supporting candidate in N windows -> STALE.

`godwit_contracts.discovery.PatternLifecycle` has seven members and none of them is
`STALE`. The nearest is `EXPIRED`, documented only by the enum's own class docstring.

`EXPIRED` and `STALE` are not the same fact. "Nothing has supported this for three
detector runs" is a statement about the world, and it reverses itself the moment the
finding recurs. "This has expired" reads like a retirement — a decision somebody made,
or a retention window elapsing. A reviewer looking at a list of closed patterns needs to
tell those apart, because one of them is worth re-opening and the other is not.

## Why it matters

Honestly: not much breaks. The store needs *a* closed-but-reopenable state and `EXPIRED`
serves, so this is a naming and reporting problem rather than a functional one.

What it costs is in the Vision Board and in any report over lifecycle states. Today
`EXPIRED` conflates "we stopped seeing it" with "we retired it", and the only way to
separate them is to join to `audit_events` and look at the `action` string —
`expire_stale` versus anything else. That works, it is what A3 implemented, and it is
the kind of thing that gets lost the first time somebody writes a dashboard query
against `patterns_safe` alone.

## The smallest sufficient change

Add one member:

```python
class PatternLifecycle(StrEnum):
    PROPOSED = "proposed"
    CONFIRMED = "confirmed"
    EXPLAINED_AWAY = "explained_away"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    EXPIRED = "expired"
    STALE = "stale"
    """No supporting candidate in N detector windows. Automatic and reversible: a
    seasonal pattern that returns moves STALE -> PROPOSED and keeps its id, its history
    and its feedback."""
    SUPPRESSED = "suppressed"
```

`EXPIRED` then means what its name suggests — deliberately retired — and `STALE` means
unsupported.

This is additive. Nothing that reads the enum today breaks; anything that exhaustively
matches on it gains a branch, which is the point.

## Who else this affects

* **A3 (`godwit-store`)** owns the lifecycle and would change one transition table entry.
* **A16 / A17 (Vision Board)** would show the two states differently, which is the
  reason for the request.
* **A10 (`godwit-orchestrator`)** reads lifecycle when deciding where to spend probes; a
  stale pattern is a reason to look again, a retired one is not.
* **A11 (`godwit-features`)** turns confirmed patterns into features and ignores both.

No stored key migrates. Stored rows holding `expired` would need a one-time decision
about which of them were stale, and the audit trail has the answer.

## What I did instead

Used `EXPIRED`, and carried the distinction in the audit event's `action` field:
`expire_stale` for the automatic path, anything else for a deliberate one.
`expire_stale()` is the only caller that writes that action.

```
packages/godwit-store/tests/test_store.py::test_the_lifecycle_has_a_state_for_unsupported_patterns
@pytest.mark.xfail(reason="CR-A3-lifecycle-has-no-stale", strict=True)
```

The transition table already allows `EXPIRED -> PROPOSED` with evidence, so the
reopening behaviour the brief wants works today under the other name:
`test_an_expired_pattern_reopens_when_the_finding_returns` passes.

## Decision

_Left blank by the filer. A human fills this in._
