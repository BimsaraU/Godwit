# godwit-contracts — HANDOFF

**Owner:** A0
**Plane:** both
**Status:** complete for the scaffold phase. `make check` is green from a clean
checkout.

Full documentation: [`docs/packages/godwit-contracts.md`](../../docs/packages/godwit-contracts.md).
Read [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md) before either.

---

## What you get

Pydantic v2 models, enums and Protocols for the whole system. Validation only — no I/O,
no clock, no randomness, no dependency beyond Pydantic and the standard library.

Import everything from the top level: `from godwit_contracts import ...`.

## What you must not do

Edit this package. If a contract is wrong, missing or impossible, file
`docs/change-requests/CR-<your-id>-<slug>.md` from
[the template](../../docs/change-requests/TEMPLATE.md), implement against the contract
as written, and leave one `xfail` test showing what you needed.

That rule exists because seventeen packages are being written in parallel. A local fix
here is a silent disagreement everywhere else.

## The four things that will bite you

1. **`Tainted[T]` is not `T`.** mypy rejects the assignment; `repr` will not print the
   value. Unwrap with `.reveal()`, only in the data plane or the gate.
2. **`ProbeSpec.seed` and `ProbeSpec.as_of` have no defaults.** Determinism, invariant 7.
   Inject them.
3. **`LabelSet.visible_as_of(instant=...)` is keyword-only with no default.** There is
   no way to ask for "all labels". That is the point.
4. **`FeatureSpec.point_in_time` is mandatory.** A spec that cannot state its rule does
   not validate.

## Fixtures you should use

`tests/golden/` — see [its README](../../tests/golden/README.md).

* `segment_key_vectors.json` — twenty vectors. If your key disagrees, your key is wrong.
* `pii_torture/expected_leaks.json` — every string that must never appear in an egress
  artifact. Add a leak test for your package against it. It is a **backstop**: the
  control is the taint type plus the gate.
* `drift_table/` — three snapshots with documented drift at `snap_2`, and a
  false-positive control (`country = 'US'`) that must not be flagged.
* `classification/meta.json` — `bayes_auc` is the ceiling; `target_auc` is
  `bayes_auc - 0.02`. Scoring above the ceiling means something leaked.

## Known limits

Listed in full under "Known limits" in the package doc, and as numbered open questions
in `docs/ARCHITECTURE.md`. The three that most likely affect you:

* **No tenant dimension anywhere.** Open question 10.
* **`SegmentKey` is a pseudonym, not an anonymisation.** Open question 3 — A5 decides.
* **Sketch payload codecs are unspecified.** The golden envelopes carry placeholder
  bytes for KLL and Count-Min so the *shape* can be agreed now. A2 replaces them. Open
  question 5.
