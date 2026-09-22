# ADR-0002: `segment_key` is a hash of canonical JSON, specified to the character

**Status:** accepted
**Date:** 2024-01-17
**Decided by:** A0

## Context

A detector (A7) finds a segment. A pattern store (A3) deduplicates it. A subtractor
(A12) subtracts it. A feature factory (A11) turns it into a feature. Four agents, four
sessions, no conversation between them. They must all compute the same key for the same
slice, forever, including for segments written to Postgres a year earlier.

Getting this wrong does not produce an error. It produces silent duplicate patterns, a
dedup table that grows without bound, and an alert queue that shows the same finding
four times.

## Decision

`segment_key = "seg_" + blake2b(canonical_json, digest_size=16).hexdigest()`, where the
canonical form is a sorted, de-duplicated JSON array of `[column, operator, values]`
triples, with every value rendered by a type-tagged scalar encoder.

The full specification is in the `godwit_contracts.segment` module docstring, and twenty
test vectors are pinned in `tests/golden/segment_key_vectors.json`.

## Why the specific choices

**JSON as the container, not a delimiter-joined string.** JSON already has an escaping
rule that everyone implements the same way. A hand-rolled `col|op|value` format needs a
hand-rolled escape, and hand-rolled escapes are where collisions live.

**Type tags on values.** `1`, `"1"`, `True` and `Decimal("1")` are four different
predicates. Without tags they render identically and collide.

**Column names casefolded, values not.** SQL identifiers are case-insensitive in
practice, so `Country` and `country` are the same column. Values are data: `"PT"` and
`"pt"` are different customers' rows and must not collide.

**Floats via `repr`, decimals via `format(normalize(), "f")`.** CPython's float `repr`
is the shortest round-tripping representation and is stable across versions. `"f"` on a
normalised `Decimal` avoids scientific notation, so `Decimal("100")` and
`Decimal("1E+2")` agree. `-0.0` collapses to `0.0`; NaN and infinity are spelled out for
floats and rejected for decimals.

**Timestamps in UTC with exactly six fractional digits, `Z`-suffixed.** Naive datetimes
are rejected outright: otherwise the key would depend on the timezone of whoever ran the
detector.

**NFC normalisation.** `"São Paulo"` composed and decomposed are the same city and must
produce the same key. This one is easy to forget and impossible to notice in testing
with ASCII data.

**Predicates sorted and de-duplicated; sets sorted, de-duplicated and escaped.** A
segment is a *set* of predicates, so order cannot matter. Inside an `IN` list, members
are escaped before joining, so `IN ('a,b')` and `IN ('a','b')` do not collide.

**Population excluded from the key.** Two snapshots of the same slice must share a key.
That is the entire premise of watching statistics change over time.

**128 bits.** These are identity and dedup keys, not MACs. Nothing relies on a key being
unguessable — see below.

## Consequences

* Adding an `Operator` changes nothing about existing keys, but **removing or renaming
  one does**, and changing the normalisation invalidates every stored key. Either is a
  migration, not a patch. File a change request.
* The twenty golden vectors are the arbiter. If an implementation disagrees with a
  vector, the implementation is wrong — including mine.
* **A `SegmentKey` is a pseudonym, not an anonymisation.** `country = 'US'` hashes to a
  key that anyone who can guess the domain can brute-force in microseconds. It is typed
  as a plain string rather than `Tainted`, because it is a join key used in every table,
  and that is a trade-off, not an oversight. A5 must decide whether guardrails treat a
  key over a small population as `DATA_VALUE`, and whether a per-tenant salt is needed —
  which would break cross-tenant dedup. Tracked as ARCHITECTURE open question 3.

## Alternatives rejected

* **Hash the rendered SQL predicate.** Rejected: dialect-dependent, whitespace-dependent,
  and it pushes the collision problem into a SQL formatter.
* **Hash the Pydantic `model_dump_json()`.** Rejected: it includes the taint wrappers,
  the provenance and the population, so two snapshots of the same slice would key
  differently. It also changes whenever a model gains a field.
* **A random surrogate key assigned on first sight.** Rejected: requires a central
  allocator, which the data plane cannot reach, and it breaks replay.
