# godwit-guard — HANDOFF

**Owner:** A5 · **Plane:** boundary (both) · **Status:** complete

Classification, redaction, tokenisation, column access modes, disclosure control and the
egress gate. **This package IS the boundary**: the only producer of `SafePayload` and the
only writer of `EgressRecord`.

Read first: `docs/packages/godwit-guard.md` (how to use it), then
`docs/specs/pii-threat-model.md` (what it protects, what it does not).

## State

* `ruff`, `ruff format --check`, `mypy --strict` clean; 127 tests plus 5 strict xfails
  (one per change request) pass in the isolated run.
* Every acceptance item in the A5 brief has a named test — listed in the package doc §8.
* Dependencies added: `godwit-store` (the production ledger), `presidio-analyzer`, and
  spaCy's `en_core_web_sm` pinned by URL in `[tool.uv.sources]`. spaCy pulled numpy from
  2.5.3 back to 2.4.6 in `uv.lock`; the rest of the workspace suite is green on it.

## Decisions a successor should know about

1. **The gate claims the issuer at import** (as the contract says). That conflicts with
   the contracts' own test fixture, so this suite runs in a child interpreter.
   `tests/conftest.py::pytest_ignore_collect` + `tests/test_isolated_suite.py`.
2. **Unclassified is refused, unconfirmed is restricted.** A field whose column is not in
   the `ClassificationRegistry` refuses the whole call; a column with an unconfirmed
   proposal is handled at its most restrictive plausible class.
3. **Refusals are AuditEvents** (`egress.refused.<reason>`), not EgressRecords — the
   contract's record cannot represent one.
4. **k defaults to 20** (the contract's), not the brief's 10. Stricter wins.
5. **Entropy floor is 24 bits** — blocks tiny domains and frequency analysis; does not
   protect SSN/phone hashes from a key compromise. 40 does. Configurable
   (`AccessControl(min_entropy_bits=...)`).
6. **DESCRIBED schema names come from a closed vocabulary** (`classify.CONCEPTS`), so they
   cannot echo a name's characters — except that a column literally named after a concept
   ("country") is described as that concept. The echo check exempts our vocabulary.
7. **SegmentKey never leaves through the gate** (architecture open question 3). No
   per-tenant salt: that would break dedup, and multi-tenancy is unresolved.
8. **Presidio does not scan payload keys**: NER tags dotted identifiers like `hh.c0.n0`
   as PERSON. Keys are regex-validated and still echo- and format-checked.

## Change requests filed

| CR | Ask | Workaround in place |
|---|---|---|
| `CR-A5-issuer-claim-is-process-global` | contracts tests skip when the issuer is held | child-interpreter launcher |
| `CR-A5-destination-vocabulary` | split TELEMETRY into METRIC_LABEL / TRACE_ATTRIBUTE | TELEMETRY gets the stricter policy |
| `CR-A5-access-modes-have-no-contract` | move AccessMode / AccessGrant / mode map to contracts | defined in `godwit_guard.access` |
| `CR-A5-egress-record-cannot-record-a-refusal` | `decision`, `refusal_reason`, `token_map_ref` on EgressRecord | AuditEvent for refusals; A3's `token_map_ref` kwarg |
| `CR-A5-min-cell-size-can-be-zero` | `ge=2` on the k fields | gate refuses k < 2 |

## Known limits

* **In-process adversary.** Single-holder issuer in a closure; ctypes or monkeypatching
  can still reach it. Process separation is the fix and is a deployment decision.
* **Complementary releases**: nested differencing only. Non-nested overlaps, three-way
  differences and reconstruction attacks are not detected. The `ReleaseLedger` is in
  memory, per process, so it forgets on restart and is not shared between gate replicas.
* **State is in memory**: `ClassificationRegistry`, `AccessControl` grants and
  narrowings, `PolicyRegistry` history and `TokenVault` scopes. Their audit events go to
  the ledger (durable via `StoreLedger`), but the state itself needs persisting — the
  registry and grants in A3's store, the vault in data-plane storage — before production.
* **Upward generalisation** needs a `population_of` callback (from sketches); the gate
  does not have one, so small segments are suppressed there rather than coarsened.
* **Quasi-identifier combinations are flagged, not enforced.** Average equivalence-class
  size under an independence assumption; skewed distributions have smaller classes.
* **DP noise source** is hash-based and reproducible, not a hardened DP library.
* **Schema capability numbers** come from a keyword matcher standing in for A15; rerun the
  benchmark with a real model once A15 exists.
* **Provider quality** for local models is documented, not measured — A15 owns the calls.
* **Presidio** uses `en_core_web_sm` (English only, small model) for PERSON; other
  languages rely on the echo and format layers.
* **Classifier vocabulary** is English-centric in its name patterns.
* An unrelated flaky test in godwit-source (`test_stats.py::test_two_proportion_z_is_antisymmetric`)
  sometimes trips a hypothesis `filter_too_much` health check in the full workspace run.
  Not caused by this package; reported to A1 by this note.
