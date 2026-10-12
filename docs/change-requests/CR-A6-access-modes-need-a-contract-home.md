# CR-A6-access-modes-need-a-contract-home

**Filed by:** A6 (`godwit-probe`)
**Against:** `godwit-contracts` (concurs with `CR-A5-access-modes-have-no-contract` and
`CR-A5-issuer-claim-is-process-global`)
**Status:** open

## The problem

A probe worker must resolve every column's access mode at plan time. The only
implementation of `AccessMode`, `ModeDecision`, `AccessModeMap`, `verify_sql` and
`verify_arrow_schema` lives in `godwit_guard`. Importing *anything* from `godwit_guard`
runs its `__init__`, which imports `godwit_guard.gate`, which calls
`claim_safe_payload_issuer()` at import time.

So every data-plane probe worker process now holds the single `SafePayloadIssuer` -- the
capability to mint the one type that may leave the perimeter to an LLM, a UI or an alert.
A probe worker has no business holding it: it produces sketch bundles, not egress payloads.

## Why it matters

1. **Least privilege, in the process that reads rows.** The architecture's threat model
   (open question 1) already concedes that the issuer is single-holder, not
   cryptographically bound. The process with raw rows in memory is the last place it should
   be held.
2. **Test isolation.** Like godwit-guard, this package's suite must run in a child
   interpreter because the contracts suite claims the same issuer. Every future data-plane
   package that needs an access mode inherits the same workaround.

## The smallest sufficient change

The one `CR-A5-access-modes-have-no-contract` already proposes: move `AccessMode`,
`ModeDecision` (or a value-free projection of it), `AccessModeMap` and `EntropyAssessment`
into `godwit_contracts`. Then A6 imports types from contracts and the two pure verifiers
(`verify_sql`, `verify_arrow_schema`) from a guard submodule that does not import the gate
-- which additionally needs `godwit_guard/__init__.py` to stop importing `gate` eagerly, or
the verifiers to move to contracts too (they are pure functions over those types).

## Who else this affects

* **A5** owns the code being moved.
* **A11, A13, A14** (other data-plane packages) will need access modes for feature
  computation, training and serving, and will hit the same import.
* **A18** audits the mode map.

## What I did instead

Imported from `godwit_guard` as documented in its HANDOFF, and copied its child-interpreter
test launcher (`tests/conftest.py`, `tests/test_isolated_suite.py`).

```
packages/godwit-probe/tests/test_contract_gaps.py::test_a_data_plane_worker_does_not_hold_the_safe_payload_issuer
@pytest.mark.xfail(strict=True, reason="CR-A6-access-modes-need-a-contract-home")
```

## Decision

_Left blank by the filer. A human fills this in._
