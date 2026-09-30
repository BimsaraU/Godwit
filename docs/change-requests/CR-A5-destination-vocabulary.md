# CR-A5-destination-vocabulary

**Filed by:** A5 (`godwit-guard`)
**Against:** `godwit-contracts` — `godwit_contracts.governance.Destination`
**Status:** open
**Priority:** medium

## The problem

The A5 brief lists seven typed destinations and says *"Do not collapse these"*:
`LLM_PROVIDER, LOG, METRIC_LABEL, TRACE_ATTRIBUTE, ALERT, EXPORT, UI`.

The contract has nine, and **one `TELEMETRY` where the brief has two**:
`LLM_PROVIDER, ALERT_CHANNEL, UI, LOG, TELEMETRY, EXPORT_FILE, MODEL_ARTIFACT_STORE,
HUMAN_REVIEW, WEBHOOK`.

Metric labels and trace attributes deserve different policies:

* A **metric label** becomes a time-series dimension. A stable token there is a pseudonym
  *and* a cardinality explosion; nothing but our own vocabulary belongs in one.
* A **trace attribute** is per-span and short-lived; a scoped token can be reasonable
  there, and trace exporters are often third-party (an OpenTelemetry collector, a vendor
  APM), which argues for its own policy and its own guardrails.

The naming differences (`ALERT` vs `ALERT_CHANNEL`, `EXPORT` vs `EXPORT_FILE`) are
cosmetic and I have not asked to change them.

## Why it matters

Nothing breaks today. The cost is that the gate cannot give trace attributes the
slightly more permissive treatment they could safely have, and that a guardrail author
cannot write a rule that targets one without the other.

## The smallest sufficient change

```python
# current
class Destination(StrEnum):
    ...
    TELEMETRY = "telemetry"


# proposed: keep TELEMETRY for compatibility, add the two the brief names
class Destination(StrEnum):
    ...
    TELEMETRY = "telemetry"  # deprecated: resolves to METRIC_LABEL policy
    METRIC_LABEL = "metric_label"
    TRACE_ATTRIBUTE = "trace_attribute"
```

Additive; no stored key changes. `EgressRecord.destination` rows already written keep
their value.

## Who else this affects

* **A3** — `egress_records.destination` is a string column; no migration, but any enum
  check constraint would need the two values.
* **A15, A16** — whoever emits OpenTelemetry spans and metrics through the gate.
* **A18** — policy packs that name destinations.

## What I did instead

`TELEMETRY` gets the stricter of the two policies (`godwit_guard.destinations`):
statistics and our own vocabulary only, no data values, no tokens, schema names OPAQUE.

```
packages/godwit-guard/tests/test_contract_gaps.py::test_metric_labels_and_trace_attributes_are_distinct_destinations
@pytest.mark.xfail(strict=True, reason="CR-A5-destination-vocabulary")
```

## Decision

_Left blank by the filer. A human fills this in._
