# PII threat model

**Owner:** A5 (`godwit-guard`) · **Status:** current as of the first complete godwit-guard
**Applies to:** everything that leaves the Godwit perimeter towards a language model, a
log, telemetry, an alert, an export, a webhook or a human-facing UI.

This document lists every path by which customer data could leave, the control on each,
how that control is tested, and what risk remains. Where a control is partial, it says so.
Where something is out of scope, it names who owns it.

---

## 1. What we protect, and from whom

**Assets.** Row values from customer tables, and anything computed from them that still
identifies a person or a small group: identifiers, quasi-identifiers, sensitive
attributes, small-population statistics, and customer schema names.

**Boundary.** Godwit has a DATA PLANE (probe workers, feature computation, training,
inference, the token vault, the keyed-hash key) that reads rows in place, and a CONTROL
PLANE (orchestrator, pattern store, Vision Board, LLM layer) that never sees a row. The
egress gate, `godwit_guard.Gate`, is the only path from tainted material to anything that
leaves. Its output type, `SafePayload`, is the only input the LLM adapter accepts.

**Adversaries considered.**

| Adversary | In scope? |
|---|---|
| A model provider, or anyone who compromises one, reading every prompt we send | Yes |
| Anyone reading our logs, traces, metrics, alerts or exports | Yes |
| A control-plane compromise: an attacker holding the pattern store, the audit ledger and every payload ever sent, but not the data-plane key or vault | Yes |
| A well-meaning engineer in another package who puts the wrong thing in the wrong field | Yes — this is the most likely source of a leak |
| A data-plane key compromise | Partly — see §4, the entropy check is sized for it only if configured to be |
| Hostile code executing inside the control-plane process | **No** — see §7 |
| Authorised viewers of the Vision Board misusing what they are authorised to see | No — that is access policy, not egress control |

---

## 2. The control, in one paragraph

Every value that came from customer data is wrapped in `Tainted[T]` at the moment it is
read, labelled with how it was obtained (`Acquisition`) and a sensitivity that cannot be
set below the floor for that route. The gate is deny-by-default: it takes tainted fields,
a destination and a versioned policy, and either returns a `SafePayload` of flat scalars
together with the `EgressRecord` it wrote *first*, or refuses. Every field is classified
by its column, k-anonymity-checked, guardrail-checked and transformed according to its
class and its destination. **That is the control.**

A scanner — Presidio plus custom recognisers plus an echo check — runs over every
outbound payload after transformation. **It is a backstop, not the control.** A hit is
treated as a defect in the taint system: the call fails, a person is paged, and the hit
rate is tracked as a quality metric that must stay at zero. Most leak paths below are
invisible to any scanner, which is exactly why it cannot be the control.

---

## 3. The leak-path register

"Test" names are under `packages/godwit-guard/tests/`. "Torture" means
`test_torture.py`, which runs every path below through the full pipeline to an LLM
provider, at the fixture's real populations and again at populations inflated to 10,000
so that class-based transforms (not only small-cell rules) are exercised, and searches
every captured byte for every identifier in `tests/golden/pii_torture/expected_leaks.json`
— raw, casefolded, base64, URL-encoded, hex, and concatenated across pairs of text fields.

| # | Path | Why it leaks | Control | Test | Residual risk |
|---|---|---|---|---|---|
| 1 | Iceberg manifest min/max bounds | The min of a name column is a real name | `ICEBERG_MANIFEST_BOUNDS` floor is DATA_VALUE. Extrema are suppressed below `quantile_min_population` (default 100) regardless of class; above it, the column's class decides (tokenise, band, suppress). ALLOW never reaches an LLM | torture; `test_transforms.py::test_quantiles_and_extrema_need_a_large_population` | A NONE-confirmed column's bounds can reach the UI raw under an ALLOW guardrail — by design, for an authorised viewer |
| 2 | `pg_stats.most_common_vals` | Literally the commonest values | DATA_VALUE; class rules; small cells first | torture | As #1 |
| 3 | Count-Min heavy hitters | On an identifier column they *are* the identifiers | DATA_VALUE; identifiers tokenise; estimates are statistics with their own population and are suppressed below k | torture | Token frequency still leaks *relative* frequency within a scope |
| 4 | Segment predicates | `(column, op, VALUE)` quotes a value | Segments go through `EgressOptions.segments`: k-enforced (generalised by dropping predicates, or suppressed), release-checked (§5), then each value redacted by class. Column becomes a DESCRIBED alias | torture; `test_disclosure.py::test_the_gate_never_emits_a_segment_below_k` (property) | Operator and population leave; see §5 for combinations |
| 5 | Category histograms | Labels below the cardinality threshold are exact values | DATA_VALUE labels; counts suppressed below k | torture | A histogram over a NONE-confirmed column may show labels to authorised UI viewers |
| 6 | Small cells | "n=3" re-identifies without a value | `Redactor` law 5: population below `min_cell_size` (default 20) **or unknown** suppresses the field before any rule is considered; k < 2 is refused | torture; `test_transforms.py::test_small_cells_go_first` | k-anonymity is an average-case guarantee; it does not stop attribute disclosure within a k-sized group (l-diversity is not implemented) |
| 7 | Quantiles over small populations | The median salary of a 12-person team | `QUANTILE` suppressed below `quantile_min_population` (100) | torture | Above 100 a quantile is released as a band (FINANCIAL → order-of-magnitude) or tokenised; DP is available but off (§5) |
| 8 | Derived feature names | `is_merchant_ACME_CORP` in SHAP output | `DERIVED_FEATURE_NAME` floor is DATA_VALUE; tokenised as `FEATURE_n` | torture | Feature *importances* leave as statistics; a model card rendered outside the gate is out of scope (A13/A14) |
| 9 | Column and table names | `patient_hiv_status` discloses before any row is read | SCHEMA_NAME taint; three modes (§6), default DESCRIBED: an alias token plus a phrase from a closed vocabulary; FULL only where a destination policy permits it (none do by default). **Field names** (the payload's keys) are refused if they spell a non-NONE column name | torture; `test_gate.py::test_field_names_are_disclosures_too`; `test_schema_names.py` | DESCRIBED discloses the *concept* ("health attribute"). A column literally named after a generic concept ("country") is described as that concept |
| 10 | Driver exception messages | They routinely contain the offending row | `DRIVER_EXCEPTION` floor is DATA_VALUE and has no column, so it is UNCLASSIFIED and the call is **refused** | torture (refused both runs); `test_gate.py::test_an_unclassified_field_refuses_the_whole_call` | Only covers exceptions that are wrapped. A package that logs a raw driver exception without the gate is outside this control (A1/A3/A6 sanitise theirs) |
| 11 | Free text | Notes contain names, numbers, anything | Free text resolves to BLIND at the access layer (never read); if a value reaches the gate, SENSITIVE_ATTRIBUTE suppresses | `test_access.py::test_credentials_and_free_text_are_blind`; torture | None known |
| 12 | Keyed hashes (OPAQUE columns) | A hash of a small domain is a lookup table | Minimum-entropy check (§4). A column that fails resolves to BLIND with remediation BUCKET; `KeyedHasher.hash_for` refuses it | `test_access.py::test_worked_enumeration_attack_recovers_every_hashed_pin`, `test_frequency_attack_needs_no_key_at_all` | At the default 24 bits, SSN and phone hashes pass and fall to a key compromise (§4) |
| 13 | Tokens | A token is a stable pseudonym | Tokens are scoped (one scope per pattern), numbered by first appearance, and restart per scope, so two narratives cannot be joined on tokens. Scopes expire and are purged. The map stays in the data plane; the record carries only a `tmap_…` reference | `test_transforms.py::test_tokens_are_stable_within_a_scope_and_unlinkable_across_scopes`; torture (`test_tokens_round_trip_and_the_map_never_leaves`) | Within one scope, token co-occurrence is visible to the provider |
| 14 | Restored narratives | Restoring tokens puts values back | `TokenVault.restore` runs in the data plane, only for roles the namespace permits, and returns DATA_VALUE-tainted text — showing it is itself a UI egress | `test_transforms.py::test_restore_round_trips_for_permitted_roles_only` | Depends on the Vision Board enforcing roles (A16/A17) |
| 15 | Quasi-identifier combinations | Postcode + birth date + sex re-identifies most people | `quasi_identifier_combinations` flags minimal combinations whose expected equivalence class is below k (pessimistic independence estimate) and the known triad by name | `test_classify.py::test_the_postcode_birthdate_sex_triad_is_flagged` | Flags, does not block: it informs classification and guardrails. Average class size hides skew |
| 16 | Complementary releases | Two safe releases intersect | `ReleaseLedger` refuses nested releases whose population difference is 1..k-1 | `test_disclosure.py::test_nested_releases_that_isolate_fewer_than_k_are_refused` | **Substantial** — see §5 |
| 17 | Logs and telemetry | The paths people forget | `LOG` and `TELEMETRY` destination policies admit statistics and our own vocabulary only: no data values, no tokens, schema names OPAQUE | `test_gate.py::test_one_value_three_destinations_three_outcomes` | Only covers what is sent *through* the gate; see §8 |
| 18 | The audit trail itself | An audit log full of PII is a second breach | `EgressRecord` holds names, digests, counts and decisions; refusals and backstop hits hold a digest of the refusal (field names and reason, never values). Refusal messages name fields by key or by position, never by value | `test_gate.py::test_the_record_is_written_first_and_matches_the_payload` | Field *keys* are recorded; they are validated identifiers and may not spell sensitive column names |
| 19 | Provenance | Names tables and columns | Provenance never leaves: a `SafePayload` holds flat scalars only | contracts' `safe.py` validation | Provenance is visible to any control-plane code holding a `Tainted` (architecture open question 2) |
| 20 | `SegmentKey` | A pseudonym; brute-forceable over small domains | The gate never emits a SegmentKey; segments leave as tokens and bands (§9) | — | A package that puts a SegmentKey into a UI or alert outside the gate bypasses this |
| 21 | LLM output | The model can echo tokens it saw | `LLMResponse.text` becomes `Tainted[str]` on `Explanation`; it contains tokens, not values, because the model only ever saw a `SafePayload` | torture shows no values in any payload | A model can *infer* things from tokens and descriptions (e.g., a health-attribute column exists) |
| 22 | Model artifacts | Memorised training rows | Out of scope here. Invariant 3: `certify_deployable` + memorisation audit (A13/A14). `MODEL_ARTIFACT_STORE` has no destination policy, so the field gate refuses it | `test_gate.py::test_a_destination_without_a_policy_is_refused` | Owned by A13/A14 |

---

## 4. Access modes and the keyed-hash threat model

Excluding identifier columns would delete the strongest fraud signal the product has
(how many accounts share a device, a phone, an address). So identifiers default to
**OPAQUE**: read only through HMAC-SHA256 with a data-plane key, stable so joins work.
**BLIND** columns never enter a projection; `verify_sql` refuses SQL that names one
anywhere (including `WHERE`), and `verify_arrow_schema` refuses a result schema with a
BLIND, unhashed-OPAQUE or unclassified field. Unconfirmed columns are BLIND, always;
grants cannot rescue them.

**What a keyed hash protects against.** With the key secret, the hashes cannot be
enumerated. That is the whole protection, and key custody is therefore the control.

**What it does not protect against, and the check that catches it.**

1. *Frequency analysis, no key needed.* A hashed country column is a relabelled country
   column; rank hashes by frequency, rank public country shares, zip. The test does it.
2. *Key compromise.* Every value in a small space enumerates. The test recovers every PIN
   from its hash in 10,000 HMACs.

`assess_entropy` estimates the plausible input space as the smallest applicable prior —
name concept (PIN 10^4, country 250, postcode 1.8·10^6, birth date 36,525, sex 16, NIC
prefix 73,200, SSN 10^9, phone 10^10, email 2^32, personal name 2^30), logical type
(DATE, BOOL), observed format (character classes), and **observed saturation** (when
values repeat at least twice on average, the observed distinct count *is* the domain) —
floored at the observed distinct count. OPAQUE requires `log2(space) >= min_bits`.

**The default, 24 bits, is a floor against tiny domains and frequency analysis. It is not
protection against key compromise**: an SSN (≈2^30) or phone (≈2^33) hash passes at 24 bits
and falls to a GPU in seconds once the key is known. A buyer whose threat model includes
key compromise sets `min_bits=40`; SSNs and phones then resolve to BLIND and graph signals
must use a surrogate key. `test_access.py::test_raising_min_bits_to_40_blinds_ssn_against_key_compromise`.

**Widening** is an `AccessGrant`: reason, requester, a *different* approver, an expiry (or
an explicit, separately audited `permanent=True`), and, for OPEN, a matching ALLOW
guardrail. **Narrowing** is immediate and needs no approval; lifting a narrowing is a
widening and needs a second person. A matching DENY guardrail caps at BLIND whatever grants
say.

---

## 5. Disclosure control: what is and is not solved

* **k-anonymity** on every segment and every evidence payload, default k = 20 (the
  contract's default; the brief's 10 is weaker), never below 2. Property-tested on the
  function and through the gate.
* **Quantiles and extrema** below 100 rows are suppressed.
* **Complementary releases.** Implemented: a per-population ledger of released predicate
  *hashes* and populations that refuses a nested release (one predicate set contains the
  other) differing by 1..k-1 rows. **Not detected:** differences across three or more
  releases; overlaps of non-nested segments (`A∧B` vs `A∧C` — pinned as a known gap by
  `test_non_nested_overlaps_are_the_documented_residual_risk`); reconstruction from many
  counts; anything released through statistics rather than segments; anything released
  before the ledger existed or by another gate process (the ledger is in memory per
  process). Statistical disclosure control in general is not solved here.
* **Differential privacy** is available (`laplace_count`, exponential-mechanism
  `dp_quantile`) and **off by default**. The trade-off, measured in
  `test_dp_noise_swamps_a_small_segment_rate_change`: for a 3-row rise in a 40-row
  segment, ~6% of single comparisons see the change in the wrong direction at ε = 1, and
  over 35% do at ε = 0.1. That is the sensitivity a detector gives up. The noise source is
  a reproducible hash-based generator suitable for research; a production DP deployment
  should use a vetted library (OpenDP) that defends against floating-point attacks.

---

## 6. Schema names

Three modes; default **DESCRIBED**. Measured cost on a column-grounding benchmark
(`tests/golden/schema_grounding/questions.json`, 21 questions over the three golden
tables, a deterministic keyword matcher standing in for an LLM):

| Mode | Accuracy | What is lost |
|---|---|---|
| FULL | 95.2% | — |
| DESCRIBED | 85.7% | Columns that share a concept become indistinguishable (`x1`..`x4`; `event_time` vs `label_time`) |
| OPAQUE | 28.6% | Everything except role and type; chance is ~13% |

The matcher is a stand-in: these numbers measure *relative* loss, not any model's
accuracy.

---

## 7. The gate's own guarantees, and their limit

* `SafePayload` has no public constructor, cannot be subclassed, copied or pickled, and
  keeps its contents outside the instance (contracts). godwit-guard claims the single
  issuer at import and keeps it in a closure. `test_gate.py::test_nothing_else_in_the_workspace_mints_payloads`
  parses every package's source and fails if anything else imports or calls the claim, or
  calls `.issue(purpose=...)`.
* The `EgressRecord` is written before the payload exists; if the write raises, the call
  is refused and nothing is minted.
* **Limit (architecture open question 1).** This stops ordinary code, accidents, and
  anything that wants to leave an audit trail. It does not stop hostile code running
  inside the same Python process (ctypes, a debugger, monkeypatching the gate module). If
  that threat applies, the gate must run in a separate process with the vault and key,
  and the control plane must talk to it over an authenticated channel. That is a
  deployment decision, not something this package can make true.

---

## 8. What the backstop is, and is not

Three layers over every cleared payload: an **echo** check that looks for every value the
gate revealed in this call and did not clear as ALLOW (raw, casefolded, URL/base64/hex
decoded, digits-only, and concatenated across pairs of text fields); **format
recognisers** (SSN, Luhn card, mod-97 IBAN, email, E.164 phone, Sri Lankan NIC, UK NINO);
and **Presidio** with spaCy `en_core_web_sm` over string values (our own tokens and hashes
masked first). A hit fails the call with `BackstopHitError`, writes `egress.backstop_hit`,
pages via the configured pager, and increments `BackstopMetrics.hits`.

Hit rate on the torture fixture: **zero** (`test_torture.py::test_the_backstop_hit_rate_is_zero`).
A non-zero rate in production means a package mislabelled a value; the fix goes in that
package, not in the scanner.

It does **not** see a country code, a cohort label, a count of three, or anything a
human would not recognise as sensitive. It does not see logs written without the gate.
It is not a DLP product and must not be described as one.

---

## 9. Decisions taken on the architecture's open questions

* **Q1 (in-process adversary):** out of scope for this package; see §7 for what closes it.
* **Q2 (Provenance is not Tainted):** acceptable for egress, because provenance never
  enters a `SafePayload`. It remains visible to control-plane code that holds tainted
  values.
* **Q3 (SegmentKey):** the gate never emits a SegmentKey. Segments leave as tokens,
  bands and aliases, k-enforced. No per-tenant salt is added now: it would break
  cross-tenant dedup and multi-tenancy is itself unresolved (Q10). A package that must
  expose a stable segment reference outside the perimeter should ask for an HMAC of the
  key under the data-plane key, per destination — not the raw key.

---

## 10. Provider controls

`select_provider` routes a payload to a configured model endpoint only if it meets the
buyer's `ProviderPolicy`: zero-retention required by default, optional residency
allow-list, and `local_only` for buyers who run the whole cascade in their own network.
Local models work and are worse — weaker names and explanations, more template
fallbacks; each `ProviderProfile` carries a `quality_note` so the cost is visible where
the choice is made. Detection and prediction are unaffected: the LLM is not in those
paths (invariant 7).

---

## 11. What we do not claim

* That scanning finds PII. It finds some; the taint type is the control.
* That keyed hashing is anonymisation. It is pseudonymisation whose strength is the key
  and, for small domains, nothing.
* That k-anonymity or the release ledger solve statistical disclosure control.
* That DP is on, or free.
* That a Python type stops a hostile in-process attacker.
* That anything sent *around* the gate — a raw `logger.info(row)` in some package — is
  covered. The type system makes that hard to write by accident; it does not make it
  impossible.
