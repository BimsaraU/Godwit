# ADR-0001: Sensitivity is carried by the type system, not detected by a scanner

**Status:** accepted
**Date:** 2024-01-17
**Decided by:** A0

## Context

Invariant 2 says every value that came from customer data is denied by default. There
are two ways to know whether a value is data-derived:

1. **Detect it at the boundary.** Run a classifier — regex, NER, Presidio — over
   everything about to leave, and block what looks sensitive.
2. **Track it in the type.** Wrap every data-derived value at the moment it is
   obtained, and refuse to unwrap it outside the perimeter.

Option 1 is the industry default and it is much less work.

## Decision

Sensitivity is carried by `Tainted[T]`, checked by mypy, and enforced at the egress
gate. Presidio is a **backstop only** and must never be described as the control.

## Why

Look at the leak-path list in `docs/ARCHITECTURE.md` and ask what a scanner would catch.

* An Iceberg manifest min/max bound on a `country` column is `"AD"` and `"ZW"`. No
  scanner flags that. It is still two real row values, and on a `full_name` column the
  same code path yields two real names.
* `"Segment (cohort = 'pilot_group_a') is anomalous, n=3"` contains no identifier at
  all and re-identifies three people.
* A quantile is a number. The median salary of a twelve-person team is a number. One of
  them is a disclosure.
* `is_merchant_ACME_CORP` is a feature name, and it will appear in a SHAP plot in a
  slide deck.
* `patient_hiv_status` is a column name, and it is disclosive before a single row is
  read.

A scanner sees strings and guesses. The type system sees *where the value came from*,
which is the thing that actually determines whether it is sensitive. Provenance is
knowable exactly, at zero cost, at the moment of acquisition. Sensitivity is not
recoverable from the bytes afterwards.

The second reason is auditability. A bank's security team can read
`ACQUISITION_MINIMUM_SENSITIVITY` and verify the policy in thirty seconds. They cannot
verify a classifier's recall on their own data without running it on their own data,
which is the thing we are trying not to do.

## Consequences

* Every package pays a verbosity tax. `Tainted[str]` where a `str` would do, `.reveal()`
  where an attribute access would do. This is deliberate and it is the price.
* Mislabelling is possible but hard: `ACQUISITION_MINIMUM_SENSITIVITY` is a validated
  floor, so you cannot call a manifest bound a statistic.
* A leak test that only greps for known strings proves almost nothing. The golden
  `expected_leaks.json` is explicitly documented as a backstop.
* If a scanner is ever the only thing that stopped a value, that is a **bug in the taint
  typing** and must be reported as one, not celebrated as defence in depth working.

## Alternatives rejected

* **Scanner as the control.** Rejected: see above. Kept as a backstop.
* **Taint tracking at runtime only** (a registry of tainted object ids). Rejected: no
  static checking, and it does not survive serialisation to Postgres and back.
* **Separate "clean" and "dirty" packages** with no shared types. Rejected: the boundary
  would live in seventeen places instead of one, and `Segment` has to cross it.
