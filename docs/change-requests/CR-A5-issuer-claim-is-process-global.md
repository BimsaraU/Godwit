# CR-A5-issuer-claim-is-process-global

**Filed by:** A5 (`godwit-guard`)
**Against:** `godwit-contracts` (its test suite, `packages/godwit-contracts/tests/conftest.py`)
**Status:** open
**Priority:** high — every package whose tests import `godwit_guard` hits this

## The problem

`godwit_contracts.safe` says: *"godwit-guard claims it at import time"*, and
`claim_safe_payload_issuer()` succeeds exactly once per process. godwit-guard does exactly
that (`godwit_guard/gate.py`, module level).

The contracts test suite *also* claims the issuer, in a session fixture
(`issuer`, claimant `godwit_contracts.tests`). The workspace runs one pytest process over
every package. So:

* if any collected test module imports `godwit_guard` (collection happens before any test
  runs), the gate holds the issuer and every contracts test that uses the `issuer` fixture
  errors with `IssuerAlreadyClaimedError`;
* if godwit-guard deferred its claim, the contracts fixture would win and the gate could
  never mint a payload in that process.

Both readings of the contract cannot hold in one interpreter. This is not specific to A5:
A15 (LLM layer), A16 (Vision Board server) and anyone else whose tests import
`godwit_guard` will break the contracts suite the same way.

## Why it matters

A red `make check` from a clean checkout, caused by nobody's bug. I had to route
godwit-guard's entire suite through a child interpreter to keep the workspace green (see
below), which costs ~1 minute of wall clock and one layer of indirection when reading a
failure.

## The smallest sufficient change

In `packages/godwit-contracts/tests/conftest.py`, run the tests that need an issuer only
when the issuer is still free, and otherwise skip them with a reason:

```python
# current
@pytest.fixture(scope="session")
def issuer() -> SafePayloadIssuer:
    return claim_safe_payload_issuer(claimant=TEST_CLAIMANT)


# proposed
@pytest.fixture(scope="session")
def issuer() -> SafePayloadIssuer:
    held = issuer_claimant()
    if held is not None:
        pytest.skip(f"issuer already held by {held!r}; run the contracts suite on its own")
    return claim_safe_payload_issuer(claimant=TEST_CLAIMANT)
```

plus a `Makefile` line that runs `pytest packages/godwit-contracts` in its own process so
those tests are never merely skipped in CI. No change to `safe.py`.

The larger alternative — a test-only `_release_issuer()` in `safe.py` — weakens the
single-holder guarantee in production code and is not recommended.

## Who else this affects

* **A0** — owns the contracts tests and the Makefile.
* **A15, A16, A17's server-side tests, A18** — anyone importing `godwit_guard` in tests.

## What I did instead

`packages/godwit-guard/tests/conftest.py` skips every guard test module at collection in
the shared run and `tests/test_isolated_suite.py` re-runs the directory in a child
interpreter with `GODWIT_GUARD_ISOLATED=1`. Inside the child, the modules collect and the
launcher skips itself. The xfail showing what I needed:

```
packages/godwit-guard/tests/test_contract_gaps.py::test_contracts_forgery_tests_can_share_a_process_with_the_gate
@pytest.mark.xfail(strict=True, reason="CR-A5-issuer-claim-is-process-global")
```

If this CR lands, delete `pytest_ignore_collect` from the guard conftest and
`test_isolated_suite.py`, and the strict xfail will tell you it is time.

## Decision

_Left blank by the filer. A human fills this in._
