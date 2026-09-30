# godwit-guard

**Owner:** A5 **Layer:** GATE **Plane:** boundary — both planes
**Status:** complete. `ruff`, `mypy --strict` and `pytest` green from a clean checkout.

Classification, redaction, tokenisation, column access modes, disclosure control, and the
egress gate: the only producer of `SafePayload`.

Read §1 before using anything here, and `docs/specs/pii-threat-model.md` before changing
anything here.

---

## 1. Disclosure — which parts touch data

**This package handles data-derived values and spans both planes.**

| Runs in the DATA PLANE (reads values; never leaves) | Runs at the boundary / control plane (no values) |
|---|---|
| `propose()` — value-format recognisers over samples | `ClassificationRegistry` — proposals and confirmations |
| `format_space_bits()` — entropy from observed formats | `AccessControl`, `AccessModeMap` — resolved modes, grants |
| `KeyedHasher` — holds the HMAC key | `Gate.clear()` — reveals values *only* to transform them |
| `TokenVault` — the token-to-value map | `PolicyRegistry`, guardrail evaluation |
| `plan_projection`, `verify_sql`, `verify_arrow_schema` | `ReleaseLedger` — predicate *hashes* only |
| `dp_quantile()` — reads the values it perturbs | `Backstop` — scans cleared output |

`KeyedHasher` and `TokenVault` refuse to be pickled, copied or rendered. Nothing in this
package logs a value, and no exception it raises quotes one: refusals name fields by key
or by position.

**The control is the typed taint plus the gate. The scanner is a backstop.** A backstop
hit is a defect in the taint system and is handled as one (§5).

---

## 2. The gate, in one call

```python
from godwit_guard import DEFAULT_POLICY, EgressOptions, Gate, EgressRefusedError

try:
    payload, record = gate.clear(
        fields={"effect": evidence.effect_size, "merchant": merchant_value},  # Tainted[...]
        destination=Destination.LLM_PROVIDER,
        purpose="explain_pattern",
        policy=DEFAULT_POLICY,                  # a versioned RedactionPolicy
        guardrails=policy_registry.active_guardrails(),
        actor="godwit-llm",
        occurred_at=now,                        # injected; nothing here reads a clock
        options=EgressOptions(
            segments={"seg": pattern.segment},  # k-enforced, release-checked, flattened
            literals={"kind": EvidenceKind.SEGMENT_DIVERGENCE},  # our vocabulary only
            token_scope=pattern.pattern_id,     # one token scope per pattern
        ),
    )
except EgressRefusedError as refused:
    ...  # refused.refusal.reason — a normal outcome. Record it, fall back, carry on.

llm.complete(payload=payload, ...)   # payload.fields == {"effect": 17.05, "merchant": "MERCHANT_1", ...}
```

`Gate.clear` satisfies the contract's `EgressGate` protocol (the seven protocol arguments
are unchanged; `options` is an optional extra). Order of operations:

1. **Preflight** — destination known and has a `DestinationPolicy`; a redaction policy is
   supplied, its `min_cell_size >= 2` and its default is not ALLOW; purpose and actor
   stated. Otherwise refused.
2. **Names** — every key matches `[a-z][a-z0-9_]*(\.[a-z0-9_]+)*` and does not spell a
   non-NONE customer column or table name. Keys are disclosures too.
3. **Segments** — `enforce_segment_k` (generalise by dropping predicates if a
   `population_of` is available, else suppress), `ReleaseLedger.check`, then flattened
   into `seg.population`, `seg.p0.column`, `seg.p0.op`, `seg.p0.v0`, …
4. **Guardrails** — per field, most restrictive wins: DENY refuses; REQUIRE_APPROVAL
   raises `ApprovalRequiredError` carrying an `ApprovalRequest` (resubmit with it
   approved, as `options.approval`); REDACT forbids ALLOW; ALLOW authorises raw values
   where the destination demands authorisation. A condition on a missing attribute fires
   for restrictive rules and never for ALLOW.
5. **Classification** — any DATA_VALUE or SCHEMA_NAME field whose column is not in the
   registry refuses the call (`UNCLASSIFIED_FIELD`) — before small-cell rules, so a small
   population cannot hide an unknown column.
6. **Redaction** — `PolicyRedactor.decide` per field (§3).
7. **Backstop** — any hit refuses with `BackstopHitError`, audits and pages.
8. **Record** — the `EgressRecord` is written; if the write fails, `LedgerWriteError` and
   nothing leaves. `record.content_digest == payload.digest`.
9. **Mint** — the payload cites `record.record_id`, `policy_id` and `policy_version`.

Refusals are written as `AuditEvent`s (`egress.refused.<reason>`), because the contract's
`EgressRecord` cannot say "refused" (`CR-A5-egress-record-cannot-record-a-refusal`).

### Destinations are not collapsed

| Destination | DATA_VALUE may leave as | Tokens | Schema names |
|---|---|---|---|
| `LLM_PROVIDER`, `ALERT_CHANNEL`, `WEBHOOK` | token, band, generalisation | yes | DESCRIBED |
| `UI`, `HUMAN_REVIEW` | anything, raw only under an ALLOW guardrail | yes (restored locally) | DESCRIBED |
| `EXPORT_FILE` | hash, band, generalisation, raw under ALLOW | no | DESCRIBED |
| `LOG`, `TELEMETRY` | nothing | no | OPAQUE |
| `MODEL_ARTIFACT_STORE` | — no policy: refused (artifacts go through the memorisation audit) | | |

`TELEMETRY` gets the metric-label policy because the contract has one value where the
brief has two (`CR-A5-destination-vocabulary`). Destination policies are data
(`DestinationPolicy`), passed to the `Gate` constructor.

---

## 3. Transforms and the default policy

`DEFAULT_POLICY` (`godwit.default@1`): UNKNOWN, CREDENTIAL, HEALTH, SENSITIVE_ATTRIBUTE →
**suppress**; DIRECT and QUASI identifiers → **tokenise**; FINANCIAL → **generalise** to an
order-of-magnitude band; NONE → **allow** (still subject to destination and guardrails).
`min_cell_size=20`, `quantile_min_population=100`.

| Transform | Function | Notes |
|---|---|---|
| suppress | — | the field is omitted |
| hash | `KeyedHasher` | HMAC-SHA256, data-plane key; refused unless the column resolved OPAQUE with a passing entropy check |
| bucket | `bucket(value, {"width": w})`, `{"period": "month"\|"quarter"\|"year"}` | `[40000, 50000)`, `2024-Q2` |
| generalise | `generalise(value, {"hierarchy": h, "level": n})` | built-in `postcode`, `prefix`, `magnitude`, `date`; add your own with `mapping_hierarchy({...})` (occupation → category) |
| tokenise | `TokenVault.tokenise` | `MERCHANT_7`; namespace from rule params or the column's concept, never from data |

A rule's action escalates towards suppression when the destination does not permit it:
to TOKENISE if the destination accepts tokens and a live scope exists, else SUPPRESS.
A transform that cannot apply (a bucket over a string) suppresses; it never falls back
to the raw value.

### Tokenise and restore

```python
vault = TokenVault(
    "vault-1", restore_roles={"MERCHANT": frozenset({"investigator"}), "*": frozenset({"dpo"})}
)
vault.open_scope(pattern_id, expires_at=now + timedelta(days=30))
# ... the gate tokenises into that scope ...
shown = vault.restore(llm_text, scope_id=pattern_id, roles=viewer.roles, at=now)
# `shown` is Tainted[str] DATA_VALUE: displaying it is a UI egress.
```

Tokens are stable within a scope and restart in every scope, so narratives cannot be
joined on tokens. `vault.purge_expired(at=...)` deletes expired maps. The EgressRecord
carries `vault.map_ref(scope)` — a reference, never the map.

---

## 4. Classification and access modes

```python
registry = ClassificationRegistry()
registry.record(propose(column_profile, sample=values))  # data plane
registry.confirm(column_profile.ref, PiiClass.DIRECT_IDENTIFIER, by="dpo", at=now)

access = AccessControl(registry, ledger=ledger)
access.record_entropy(
    ref,
    assess_entropy(
        column_name=...,
        logical_type=...,
        observed_distinct=ndv,
        row_count=rows,
        format_bits=format_space_bits(values),
    ),
)
mode_map = access.mode_map(guardrails=guardrails, at=now)  # queryable state
```

* **Proposals** combine A1's first pass, a name vocabulary (`CONCEPTS`), value-format
  recognisers (US SSN, EIN; UK NINO, postcode; Sri Lankan NIC; Indian PAN; E.164 phone;
  email; Luhn card; mod-97 IBAN; IPv4; ISO dates; person names by format and a small
  given-name vocabulary) and cardinality. **Unconfirmed columns are treated at their most
  restrictive plausible class.** A new proposal with more restrictive evidence revokes
  an existing confirmation.
* **Quasi-identifier combinations** — `quasi_identifier_combinations(entries, k=...)`.
* **Modes** — unconfirmed → BLIND; NONE → OPEN; credential / free text → BLIND; else
  OPAQUE if the entropy check passes, otherwise BLIND with remediation BUCKET. Grants
  widen (reason, a different approver, expiry or explicit `permanent=True`, and an ALLOW
  guardrail for OPEN). Narrowing is immediate. Every change is an `AuditEvent`.
* **Plan-time enforcement** — `plan_projection` drops BLIND and unknown columns;
  `verify_sql` refuses SQL naming a BLIND column anywhere; `verify_arrow_schema` refuses
  BLIND, raw-OPAQUE (must be `<name>__opaque`) and unclassified fields.
* **Entropy threat model** — see `pii-threat-model.md` §4. Default `min_bits=24`; set 40
  if key compromise is in scope.

These types live here until `CR-A5-access-modes-have-no-contract` moves them.

---

## 5. Backstop, disclosure control, providers, policy

* **Backstop** — `Backstop(use_presidio=True, pager=...)`. Echo + format recognisers +
  Presidio (`en_core_web_sm`, loaded once per process, ~10 s). `backstop.metrics.hit_rate`
  is the quality metric of the primary control. Zero on the torture fixture.
* **k-anonymity** — `enforce_segment_k`, `enforce_evidence_k`; k never below 2.
* **Complementary releases** — `ReleaseLedger(k=...)`, passed to the `Gate`. Nested
  differencing only; the residual risk is documented and pinned by a test.
* **Differential privacy** — `laplace_count`, `dp_quantile`; `DifferentialPrivacy` is off by
  default. At ε = 1, ~6% of single comparisons of a 3-row change in a 40-row segment
  point the wrong way; at ε = 0.1, over 35%.
* **Providers** — `select_provider(ProviderPolicy(...), profiles)`: zero retention by
  default, residency allow-list, `local_only`. Local is supported and weaker; say so in
  `ProviderProfile.quality_note`.
* **Policy as data** — `PolicyRegistry.publish_policy` / `publish_guardrail`: versions must
  be exactly latest + 1, every publish is audited, every old version stays readable.

---

## 6. Schema names — measured cost

| Mode | Column-grounding accuracy | Lost |
|---|---|---|
| FULL | 95.2% | — |
| DESCRIBED (default) | 85.7% | columns sharing a concept blur (`x1`..`x4`) |
| OPAQUE | 28.6% | all but role and type; chance ≈ 13% |

21 questions over the three golden tables, `tests/golden/schema_grounding/questions.json`
(an A5 fixture). The scorer is a deterministic keyword matcher standing in for A15, so
the numbers measure relative loss. `test_schema_names.py::test_capability_loss_is_measured`
pins them; if they move, update this table in the same commit.

---

## 7. For other packages

| You are | Use |
|---|---|
| A1 (source) | Your `ColumnProfile.pii_class` is the first pass; call `propose` in the data plane and `registry.record` the result |
| A6 (probe) | `mode_map.decision_for(...)`, `plan_projection`, `verify_sql`, `verify_arrow_schema`, `KeyedHasher.hash_for` |
| A7 / A3 | `evidence_fields(evidence, prefix=...)` + `EgressOptions(segments=...)` when anything goes to a human |
| A15 (LLM) | `Gate.clear(destination=LLM_PROVIDER, ...)`, then `select_provider`; never construct a payload |
| A16 / A17 (Vision Board) | `Destination.UI`; `TokenVault.restore` in the data plane for permitted roles; `AccessModeMap` for the mode view |
| A18 (policy) | `PolicyRegistry`, `DestinationPolicy`, `AccessModeMap.counts()`/`decisions` to assert on |

**Tests that import `godwit_guard` claim the process's issuer.** If your test suite
imports it, read `CR-A5-issuer-claim-is-process-global` first.

---

## 8. Tests

`uv run pytest packages/godwit-guard` runs one launcher test, which re-runs the directory
in a child interpreter (see `tests/conftest.py` and the CR above). To run the modules
directly: `GODWIT_GUARD_ISOLATED=1 uv run pytest packages/godwit-guard/tests`.

Acceptance tests: `test_torture.py` (full pipeline, every leak path, every encoding,
backstop hit rate zero, token map absent), `test_gate.py::test_adversarial_attempts_to_forge_a_payload`
and `test_nothing_else_in_the_workspace_mints_payloads`,
`test_disclosure.py::test_the_gate_never_emits_a_segment_below_k` (hypothesis),
`test_access.py::test_worked_enumeration_attack_recovers_every_hashed_pin`,
`test_schema_names.py::test_capability_loss_is_measured`.

---

## 9. Known limits

See `packages/godwit-guard/HANDOFF.md`.
