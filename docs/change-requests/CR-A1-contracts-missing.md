# CR-A1-contracts-missing — `godwit-contracts` does not exist

**Filed by:** A1 (godwit-source)
**Affects:** every agent. A0 decides.
**Status:** open

## Problem

`packages/godwit-contracts/` is absent from the repository. A1 owns `packages/godwit-source/`
and is required to code against A0's contracts, but there is nothing to import. Universal
rule 2 says a missing contract must not be fixed by the agent who finds it, so this package
does not create `godwit-contracts` and does not write into it.

## What A1 did instead

`godwit_source._contracts` is an import switch, nothing more:

```python
try:
    from godwit_contracts import Tainted, ColumnAccessMode, CostBudget, ...
    CONTRACTS_ARE_PROVISIONAL = False
except ImportError:
    from ._contracts_stub import Tainted, ColumnAccessMode, CostBudget, ...
    CONTRACTS_ARE_PROVISIONAL = True
```

`godwit_source/_contracts_stub.py` is a provisional stand-in that lives inside A1's own
package. Every module in `godwit-source` imports contract types from `_contracts`, never
from the stub directly, so the day `godwit-contracts` is installed the real types win
unconditionally, with no merge step and no compatibility layer. The stub then becomes dead
code and should be deleted in the same change.

`CONTRACTS_ARE_PROVISIONAL` is exported from the package so a smoke test anywhere in the
repo can assert it is `False` once A0 has landed.

## The smallest sufficient change

A0 publishes `packages/godwit-contracts/` exporting at least these names, after which A1
deletes `_contracts_stub.py` and the `try`/`except` in `_contracts.py`:

| Name | What A1 needs from it |
| --- | --- |
| `Tainted`, `TaintKind` | a generic wrapper whose payload is not rendered by `repr`/`str`, read only through an explicit call, with kinds `DATA_VALUE` and `DERIVED_STATISTIC` |
| `data_value`, `derived_statistic` | constructors that take a value and an origin string |
| `ColumnAccessMode` | `BLIND` / `OPAQUE` / `OPEN` |
| `PiiClass` | at least: direct identifier, quasi-identifier, sensitive attribute, free text, secret, non-PII, unknown |
| `SemanticRole` | entity id, foreign key, timestamp, amount, category, boolean flag, free text, geo, unknown |
| `CostBudget`, `CostBudgetExceeded` | a byte ceiling checkable *before* a read and a query counter; exceeding raises |
| `Segment` | `(column, operator, value)` with the value tainted |
| `Candidate`, `Evidence` | detector, table, column, snapshot id, effect size, p-value, evidence mapping |
| `ProbeSpec` | table, columns, snapshot id, version, seed |
| `SketchBundle` | a Protocol with `merge` and `serialize`; A2 supplies the classes |

## Open questions for A0

These are guesses A1 had to make. Each one is a place where the stub may diverge from what
A0 lands, and each one changes code outside this package.

1. **Is `Tainted` generic over the value type or over the taint kind?** The brief writes
   `Tainted[DATA_VALUE]`, which reads as a phantom type parameter. The stub instead makes it
   `Tainted[V]` over the *value* type with the kind as a runtime field, because that is what
   keeps `mypy --strict` useful for a consumer: `Tainted[int]` tells you what `unwrap`
   returns, while `Tainted[DATA_VALUE]` does not. If A0 prefers the phantom form, A1 needs a
   second parameter (`Tainted[K, V]`) or the value type is lost.

2. **Are `Candidate.effect_size` and `Candidate.p_value` tainted?** Invariant 2 says every
   value derived from customer data is typed as such, and a p-value is derived from customer
   data. The stub leaves them as plain `float`, treating them as test statistics about the
   evidence rather than as evidence, and taints the evidence entries instead. This is a
   judgement call with real consequences for every consumer of a `Candidate` and A0 should
   settle it.

3. **Are column names tainted?** The leak-path list says yes (`patient_hiv_status`,
   `salary_2024`). But a column name is also the key by which every structure in the system
   is indexed, and a `Mapping[Tainted[str], X]` is unusable. A1 resolved this by keeping
   names plain where they are *structural* (a dict key, `ColumnMetadata.column`,
   `SnapshotMetadata.schema_columns`) and tainting them where the name is itself the
   *finding* (`schema_change` evidence). A0 should either confirm this split or state a
   different one, because A5's gate has to know which is which.

4. **Does `CostBudget` mutate, or is it threaded functionally?** The stub mutates, which
   makes a partially-spent budget visible to the caller after a refusal. A functional budget
   would be cleaner to reason about but changes every adapter signature.

## Failing test showing what was needed

`packages/godwit-source/tests/test_contracts_gap.py::test_contracts_package_exists` is
`xfail`. It passes the moment `godwit-contracts` is importable, at which point the stub and
that test should both be deleted.
