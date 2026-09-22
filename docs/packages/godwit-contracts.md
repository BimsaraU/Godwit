# godwit-contracts

**Owner:** A0
**Plane:** both — these types cross the boundary, which is exactly why they carry their
own sensitivity.
**Depends on:** Pydantic and the standard library. Nothing else, enforced by a test.

> **This package defines how data-derived values are typed.** It reads no rows itself,
> but every leak path in the system is represented here, and a mistake in this package
> is a mistake in seventeen others. Treat changes accordingly.

---

## What this is for

Seventeen packages are written by agents who cannot talk to each other. This package is
the only thing they all agree on. It contains Pydantic models, enums and Protocols —
validation and nothing else. No I/O, no clock, no randomness.

If you are reading this because you are about to write a package, read
[ARCHITECTURE.md](../ARCHITECTURE.md) first, then come back.

---

## Module map

| Module | What is in it |
|---|---|
| `taint` | `Sensitivity`, `Acquisition`, `Provenance`, `Tainted[T]`. **Read this first.** |
| `safe` | `SafePayload` and its issuer. The only type the LLM adapter accepts. |
| `errors` | Every exception the contracts layer raises. |
| `common` | Base model, identifiers, `Instant`, canonical JSON, content hashing. |
| `cost` | `CostBudget`, `CostSpend`. |
| `source` | `SourceRef`, `SnapshotRef`, `ColumnProfile`, `PiiClass`, `JoinEdge`. |
| `segment` | `Operator`, `Predicate`, `Segment`, and the `segment_key` normalisation. |
| `probe` | `ProbeKind`, `ProbeSpec`, `probe_key`. |
| `sketch` | `SketchKind`, `ErrorBound`, `SketchEnvelope`, `SketchBundle`. |
| `discovery` | `Evidence`, `Lineage`, `Candidate`, `Pattern`, `Explanation`, `Feedback`, `Alert`, `Label`, `LabelSet`, `CoverageScope`. |
| `features` | `PointInTimeRule`, `FeatureSpec`, `FeatureSet`. |
| `training` | `TrainingTask`, `SplitSpec`, `TrainingRun`, `MemorisationAudit`, `ModelArtifact`, `DeployableModel`, `certify_deployable`, `EvaluationReport`. |
| `serving` | `Prediction`, `FeatureAttribution`, `Deployment`. |
| `governance` | `Guardrail`, `RedactionPolicy`, `EgressRecord`, `ApprovalRequest`, `AuditEvent`, `SecretRef`, `DatasourceConfig`. |
| `protocols` | The twelve extension points, with their laws. |

Everything public is re-exported from `godwit_contracts`. Import from the top level.

---

## The five things you must not get wrong

### 1. `Tainted[T]` is not `T`

```python
from godwit_contracts import Acquisition, data_value

name = data_value(
    "Aoife Brennan",
    acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS,
    column="full_name",
)

logger.info(f"found {name}")  # -> "<tainted data_value via iceberg_manifest_bounds from full_name>"
logger.info(name.reveal())  # -> a real person's name. Data plane only.
```

`repr` and `str` render a label, never the value. mypy rejects passing a `Tainted[str]`
where a `str` is expected; `tests/typing_cases/must_fail.py` proves it by running mypy.

`.reveal()` is the only way out. It is deliberately greppable. Legitimate call sites:
inside the data plane, and inside `godwit-guard` while applying a redaction policy.
Everywhere else it is a bug, and it should be caught in review.

### 2. Say how you obtained a value, and the floor is enforced

```python
Tainted[str](
    value="Aoife Brennan",
    sensitivity=Sensitivity.DERIVED_STATISTIC,  # <- refused
    provenance=Provenance(acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS),
)
# ValueError: Acquisition.ICEBERG_MANIFEST_BOUNDS requires at least
#             Sensitivity.DATA_VALUE, got Sensitivity.DERIVED_STATISTIC
```

`ACQUISITION_MINIMUM_SENSITIVITY` is the leak-path list as code. Declaring a value
*more* restricted than its route requires is always fine. Less is a validation error.

Use the helpers rather than building `Tainted` by hand:
`derived_statistic()`, `data_value()`, `schema_name()`, `token()`.

### 3. `population` is part of the value

```python
evidence.statistic.is_small_cell(threshold=20)  # True when population is None
```

`None` means unknown, and unknown must mean **unsafe**. "Segment X (n=3) is anomalous"
re-identifies without quoting a value. Carry the population wherever you can compute it.

### 4. `SafePayload` cannot be constructed

```python
SafePayload()  # SealedConstructionError
SafePayload.__new__(SafePayload)  # SealedConstructionError
object.__new__(SafePayload)  # succeeds, and is inert: every accessor raises
copy.deepcopy(authentic)  # SealedConstructionError


class Evil(SafePayload): ...  # TypeError: final
```

The contents live in a module-private `WeakKeyDictionary`, so bypassing the constructor
gains you an empty husk. The only producer is
`claim_safe_payload_issuer(claimant=...)`, which succeeds once per process — in
production, from `godwit-guard` at import time — and `issue()` requires an
`egress_record_id`, because **a `SafePayload` exists if and only if an `EgressRecord`
exists**.

The honest limit is written down in ARCHITECTURE open question 1: this resists ordinary
code and accident, not a hostile in-process caller.

### 5. An unaudited model is not deployable, in the type system

```python
Deployment(model=artifact)  # mypy: arg-type. It wants a DeployableModel.
certify_deployable(unaudited_artifact)  # MemorisationAuditFailedError
```

`DeployableModel.audit_passed` is `Literal[True]`, so a failed deployable does not
construct and does not parse from JSON. `certify_deployable()` has no `force` and no
`skip_audit`. `MemorisationAudit.passed` is validated against its own checks, and
`REQUIRED_MEMORISATION_CHECKS` must all be present.

---

## `segment_key` and `probe_key`

Both are specified character by character in their module docstrings, because two agents
who cannot talk to each other must produce the same key.

* **`segment_key`** identifies a slice. Column names are NFC-normalised, stripped and
  casefolded; values are NFC-normalised with case **preserved** (values are data); every
  value carries a type tag so `1`, `"1"` and `True` never collide; `IN` members are
  sorted, de-duplicated and escaped; predicates are de-duplicated and sorted. Pinned by
  `tests/golden/segment_key_vectors.json`, twenty vectors.
* **`probe_key`** identifies a *measurement*, not a run. It excludes the snapshot, the
  budget, the probe id and the scheduling time, so the same measurement at two snapshots
  shares a key — which is the entire premise of discovery.

A `SegmentKey` is a **pseudonym, not an anonymisation**: over a low-cardinality domain it
is brute-forceable. See ARCHITECTURE open question 3.

---

## Budgets

```python
remaining = budget.spend(CostSpend(bytes_scanned=400_000))  # or BudgetExceededError
nested = CostBudget.compose(outer, inner)  # field-wise minimum
```

`compose` is a meet: associative, commutative, idempotent, and it can only ever tighten.
That is what makes it safe to hand a nested budget to code you did not write. There is
no `unlimited()`, because "I forgot to set a ceiling" and "there is no ceiling" must not
look alike.

Refusing is a normal outcome. Catch `BudgetExceededError`, record the refusal, stop.

---

## Labels and point-in-time

`Label` carries `event_time` (when it happened) and `label_time` (when we learned). A
chargeback lands sixty days after the transaction; training on the label at its event
time leaks sixty days of future knowledge.

```python
labels.visible_as_of(instant=task.labels_as_of)  # keyword-only, no default
labels.coverage_at(instant=...)  # False => unlabelled means UNKNOWN
```

There is no `all()` and no default instant. That is deliberate.

`FeatureSpec.point_in_time` is mandatory. A spec that cannot state its rule does not
validate. This is where leakage comes from, so there is no `None` and no flag that turns
the check off.

---

## The twelve protocols

`SourceAdapter`, `Sketch`, `Detector`, `PatternStore`, `Redactor`, `EgressGate`,
`LLMAdapter`, `FeatureComputer`, `Trainer`, `Evaluator`, `ModelRegistry`, `Predictor`.

Each carries a **LAWS** section in its docstring. They are promises about behaviour, not
just shapes. Where a law is a mathematical claim — `Sketch` laws 1 to 3 — the
implementing package owes a property test, not an example test.

---

## Tests in this package

| File | What it holds the line on |
|---|---|
| `test_taint.py` | Ordering, acquisition floors, small cells, repr safety. |
| `test_safe_payload_forgery.py` | Five forgery attempts, all failing, plus the issuer. |
| `test_segment_key.py` | The twenty golden vectors and the normalisation properties. |
| `test_cost.py` | Spending, refusing, and that `compose` is a meet. |
| `test_deployable.py` | Invariant 3 at runtime. |
| `test_roundtrip.py` | JSON and Python round-trips for every model; key stability. |
| `test_golden.py` | That the fixtures say what they claim to say. |
| `test_static_typing.py` | Runs mypy over `typing_cases/must_fail.py`. |
| `test_dependency_hygiene.py` | Pydantic and stdlib only; no suppressions. |

---

## Known limits

* **No tenant dimension.** No contract model carries a tenant id. See ARCHITECTURE open
  question 10 — it is the most expensive thing on that list and it should be answered
  before A3 writes a schema.
* **`Provenance` is not itself `Tainted`** although it names customer tables and
  columns. Documented as SCHEMA_NAME-class and gated by whatever carries it. Open
  question 2.
* **`SegmentKey` is a pseudonym, not an anonymisation.** Open question 3.
* **`ProbeSpec.snapshot` may be `None`** at scheduling time, which is a hole in
  "reproducible from the spec alone". Open question 4.
* **The `Segment` vocabulary is closed and small**: twelve operators, no disjunction, no
  nesting. Adding one is a migration of every stored key. Open question 8.
* **Sketch payload codecs are not specified here.** Contracts define the envelope; A2
  owns the bytes and the forward-compatibility rule. Open question 5.
* **`Explanation.payload_digest` and `prompt_digest` are plain strings**, not a
  structured reference to an `EgressRecord`. A15 and A5 may want that tightened.
