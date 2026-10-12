# godwit-sdk

**Owner:** A9 · **Plane:** both. **A source plugin runs in the DATA PLANE** and reads
customer rows; every other kind runs on sketches, statistics or gated payloads. Treat a
plugin as code a bank's security team will read -- because before it runs in a bank,
somebody there will.

The public, stable surface people outside this project build against. Someone with a
proprietary data source should be able to write an adapter in an afternoon from this
page alone, and the result should be impossible to get subtly wrong: the SDK does the
parts that are easy to get wrong (budgets, tainting, sanitising, access modes, lineage),
and checks the rest when the plugin is imported and again in its test suite.

Read in order: §1 the fifty-line source, §2 the promise, then the section for your kind.
The three reference plugins in `godwit_sdk.examples` are the worked tutorial.

---

## 1. A source in fifty lines

```python
import datetime as dt
from collections.abc import Iterable, Mapping, Sequence
from typing import Self

import pyarrow as pa
from godwit_sdk import (
    Capabilities,
    LogicalType,
    Partition,
    Snapshot,
    SourceBase,
    TableName,
    logical_type,
    source,
)

EPOCH = dt.datetime(2024, 1, 1, tzinfo=dt.UTC)


@source(
    name="mongodb",
    namespace="acme",
    version="0.1.0",
    summary="Collections from MongoDB.",
    capabilities=Capabilities(network=("mongo.internal.acme.com",)),
)
class MongoSource(SourceBase):
    def __init__(self, client: "MyClient") -> None:
        self._client = client

    def snapshot(self, table: TableName, *, at: dt.datetime | None) -> Snapshot:
        version = self._client.collection_version(table.name)  # metadata only
        return Snapshot(
            snapshot_id=version.id, sequence_number=version.seq, committed_at=version.at
        )  # tz-aware, never now()

    def columns(self, table: TableName, snapshot: Snapshot) -> Mapping[str, LogicalType]:
        return {f.name: logical_type(f.type) for f in self._client.arrow_schema(table.name)}

    def partitions(self, table: TableName, snapshot: Snapshot) -> Sequence[Partition]:
        return [
            Partition(key=str(s.id), estimated_bytes=s.bytes, row_count=s.rows)
            for s in self._client.shards(table.name)
        ]  # estimates, from metadata

    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        yield self._client.scan(
            table.name, shard=partition.key, projection=list(columns)
        )  # ONLY these columns

    @classmethod
    def for_conformance(cls, tables: Mapping[str, pa.Table]) -> Self:
        return cls(MyClient.in_memory(tables))  # same code path, fake backend
```

That is the whole plugin. The base class turns it into a
`godwit_contracts.SourceAdapter` (`resolve_snapshot`, `profile_table`, `execute_probe`)
that plans every probe against the column access modes, refuses before reading when the
budget cannot cover the estimate, stops mid-read when actual bytes overrun it, checks
cancellation between batches, hashes OPAQUE columns with the data-plane key, sketches
the values, taints everything, and sanitises every exception. It does this by running
`godwit-probe`'s own `ProbeExecutor` -- the same code that probes Iceberg -- over the five
methods above, so a plugin source is not a second-class path.

Scaffold it instead of typing it: `godwit-sdk new source --name mongodb --namespace acme`
writes a package that passes the conformance battery on its first `pytest` (§13).

## 2. The compatibility promise

**Everything importable from `godwit_sdk` itself is covered; nothing else is.** Within a
minor series (`0.1.x`) no name in `godwit_sdk.__all__` is removed and no public signature
changes. A submodule (`godwit_sdk.source`, `godwit_sdk._bridge`), the examples, and any
other `godwit_*` package are not covered, even where they work.

Enforcement: `tests/test_api_surface.py` renders the signature of every public name --
classes with every public member, enums with their values -- and compares it with
`tests/api_surface.json`. A difference with an unchanged `__version__` fails CI. A
deliberate change bumps `godwit_sdk._version.__version__` and regenerates the snapshot:

```
uv run python -m godwit_sdk._surface > packages/godwit-sdk/tests/api_surface.json
```

Some names are re-exported from the packages that own them (`LogicalType`,
`EvidenceKind`, `Direction`, `ContextType`, `SafePayload`, `BaseSketch`...) because no
plugin can be written without them. The SDK promises the name; the owner defines the
type, and the snapshot includes their shapes so that an upstream change is caught here.
That arrangement is weaker than it should be:
`CR-A9-sdk-surface-rests-on-unpromised-types`.

A plugin states which SDK it targets with `requires_sdk` (a PEP 440 specifier, default
`~=<this version>`). A plugin that targets another core fails at import with
`IncompatiblePluginError` naming both versions.

Importing `godwit_sdk` has no side effects beyond defining classes. It does **not**
import `godwit_guard`, which claims the process's single `SafePayloadIssuer`; that
happens on a source's first probe, or when the conformance kit is imported.

## 3. The six extension points

| Decorator | Base class | You implement | The base does |
|---|---|---|---|
| `@source` | `SourceBase` | `snapshot`, `columns`, `partitions`, `read`, `for_conformance` (+ optional `column_stats`) | §4 |
| `@sketch` | `SketchBase` | the `godwit_sketch.BaseSketch` surface + `estimate`, declarations | monoid laws at registration, law 4 enforced, registry |
| `@detector` | `DetectorBase` | `examine`, declarations | versioning, minimum support, test counts, lineage, contract adapter |
| `@feature` | `FeatureBase` | `aggregate`, window declarations | the point-in-time window, the `FeatureSpec` |
| `@context` | `ContextBase` | `fetch`, `for_conformance` | tainting, ids, windowing, `ContextSource` |
| `@panel` | `PanelBase` | `render`, declarations | gated input only, output checked against it |

Every decorator takes `name`, `namespace`, `version` (`MAJOR.MINOR.PATCH`), and
optionally `summary`, `requires_sdk`, `capabilities` and `limits`. **The decorator is
registration.** It collects every problem with the class and raises one
`PluginRejectedError` listing all of them, at import, on the author's machine:

```
godwit_sdk.errors.PluginRejectedError: plugin acme.lefty was rejected at registration:
  - commutativity fails: the two results differ in state (declared EXACT)
  - identity fails: merging with identity() changed the sketch
```

Common rules: names are lowercase letters and digits joined by `-` or `_`; the
namespaces `godwit` and `core` are reserved; a plugin must not override the methods the
SDK implements for its kind (listed in each base's `SDK_METHODS`) -- overriding
`execute_probe` is exactly how a source gets subtly wrong.

Every base gives the plugin `self.log` (§10) and runs every call into plugin code under
the plugin's declared capabilities (§11). Nothing a plugin raises leaves as itself: it
becomes `PluginFailedError` naming the plugin, the stage, the exception type and a fixed
classification. The message is withheld; the original text is kept on `.original` as
`Tainted[str]` (DATA_VALUE), for data-plane code with a reason to read it.

## 4. Sources

Reference plugin: `godwit_sdk.examples.rest_source` (a paginated REST API). Dogfood:
`tests/_sdk_sqlite_source.py` (SQLite, written from this page).

**The five methods.**

* `snapshot(table, *, at)` -- the version current at `at`, or now. `snapshot_id` must be
  a plain identifier (letters, digits, `_.-`) that changes whenever the data does.
  `committed_at` must be tz-aware and must not be a clock read.
* `columns(table, snapshot)` -- name to `LogicalType`. `godwit_sdk.logical_type(arrow_type)`
  maps an Arrow type; for a backend with its own type names, map them yourself
  (the SQLite dogfood maps declared-type affinities).
* `partitions(table, snapshot)` -- the units a full read consists of, with
  `estimated_bytes` and `row_count` from metadata. `key` is yours; it comes back to
  `read` and goes nowhere else. Keep it a plain string.
* `read(table, partition, columns)` -- Arrow batches or tables carrying **exactly**
  `columns`. If the backend returns more, `batch.select(columns)` inside `read`. A batch
  with an extra column fails the probe (`plan_violation`): a BLIND column in a batch
  means it was read. `read` gets names, not types; call your own `columns` if you need
  them.
* `for_conformance(tables)` -- an instance serving the given Arrow tables (keyed by table
  name, namespace ignored) through the code path production uses: a fake transport, a
  throwaway in-memory database. The kit calls it with poisoned data.
* `column_stats(table, snapshot)` (optional) -- `ColumnStats` with **plain** values from
  the backend's catalog. Do not compute them by scanning, and do not wrap them: the base
  taints min/max/common values as DATA_VALUE and counts as statistics.

**Snapshots when the backend has no versions.** Derive an id from metadata that moves
when the data does: a high-water mark (`max(rowid)`, a sequence, an updated-at maximum
read from an index), an etag, a schema version. Say in your docs which changes it
misses -- a high-water mark misses an update in place. If there is no commit time, use a
fixed epoch: a clock read would make two identical probes different.

**Estimates.** `estimated_bytes` is checked against the budget before anything is read.
An over-estimate refuses probes that would have fit; an under-estimate is caught
mid-read, when the bytes actually handed over (measured from the Arrow batches, not
reported by you) pass the budget -- the probe is then cancelled with
`BUDGET_EXHAUSTED`. A coarse upper bound (the whole file, the whole collection) is
acceptable; zero is not honest.

**Governance.** Call `plugin.govern(access=..., keyring=...)` with the access-mode map
from `godwit_guard.AccessControl.mode_map` and the data-plane `ProbeKeyring`. Without it,
every column is BLIND and every reading probe is refused -- the fail-closed default.

**Refs.** Build refs with `MySource.source_ref(source_id=..., namespace=..., table=...)`.
It taints the names and stamps `catalog = "plugin:<namespace>.<name>"`; a probe whose ref
names another plugin is refused (`wrong_source`). `kind` is `PARQUET` as a stand-in
(`CR-A9-source-kind-is-closed-to-plugins`).

**Calling it.** `execute_probe(spec, snapshot, budget=...)` is the contract method: a
`SketchBundle`, or `BudgetExceededError` (refused up front or overran mid-read), or
`ProbeRefusedError(reason)` for any other refusal (`blind_column`, `unclassified`,
`unsupported_probe`...). `run_probe(spec, budget=..., cancel=...)` returns the same as a
`godwit_probe.ProbeOutcome` value, cancellation included. Probes are always full: a
plugin source has no file-level history to measure incrementally.

## 5. Sketches

Reference plugin: `godwit_sdk.examples.bloom` (Bloom-filter membership).

A sketch is `godwit_sketch.BaseSketch` plus a plugin identity: declare `KIND`, `CODEC`
(must start with `<namespace>-`), `SCHEMA_VERSION`, `VALUE_BEARING`, `SENSITIVITY`,
`MERGE_EXACTNESS`, `ITEM_FLAVOUR`, `ACQUISITION` and `DEFAULT_PARAMS`; implement
`params`, `population`, `merge`, `identity`, `from_items`, `error_bound`, `encode`,
`_decode_body` and `estimate`. Read `godwit_sketch.base` for what each declaration means.

At registration the decorator runs, over a fixed hash-derived sample with operands of
unequal size: determinism; commutativity and associativity (byte-identical state for
`EXACT`, `estimate()` within twice the error bound for `BOUNDED`); identity on both
sides; population additivity; `decode(serialise(x)) == x`; an error bound independent of
the data; and value-bearing honesty -- a sketch declaring `VALUE_BEARING = False` is fed
poisoned strings and rejected if its payload contains one. Contract law 4 (merging
different parameters must raise) is enforced, not tested: `SketchBase` wraps every
subclass's `merge` to call `require_mergeable` first. The kit re-runs the laws under
hypothesis.

**Value-bearing means more than "stores items".** If anyone holding the payload can test
whether a value was present, the sketch discloses values. A Bloom filter stores bits,
but its hash parameters travel in the envelope, so it answers "was Aoife Brennan here?"
for anyone. The reference plugin is therefore `VALUE_BEARING = True`, `DATA_VALUE`, and its
query takes a `Tainted` value. The contract's `SketchKind` vocabulary is closed; borrow
the nearest kind, as A2 does (`CR-A2-sketch-kind-vocabulary`) -- the codec identifies the
payload.

A registered sketch joins `godwit_sketch.SKETCH_REGISTRY` and decodes through
`decode_envelope` like a core one. Register a sketch plugin before a detector that reads
its codec.

## 6. Detectors

Reference plugin: `godwit_sdk.examples.benford` (Benford's law over money columns).

Declare `EVIDENCE` (an `EvidenceKind`), `CODECS` (the codecs you read), and
`TESTS_PER_SKETCH`; optionally `ROLES` (e.g. `{ColumnRole.AMOUNT}`), `MIN_SUPPORT`
(default 100) and `ALPHA` (default 0.05). Implement
`examine(current, reference) -> Sequence[HypothesisTest]`: decoded sketches in, plain
numbers and your own labels out. Pure -- no I/O, clock or randomness. Never put a value
in `method`, `note` or a unit.

The base: refuses a sketch or reference window below `MIN_SUPPORT` before `examine` runs;
fails a plugin that returns more tests than `TESTS_PER_SKETCH`; reports the number of
tests run on every result (L5 needs it for FDR, which is not the detector's job);
emits a finding for each test with `p_value <= ALPHA`; records lineage under the plugin's
qualified name and semantic version. A test with `p_value=None` must say why in `note`
and is neither counted nor emitted -- that is how a detector abstains.

`detector.run(series, policy=...)` uses `godwit-detect`'s series machinery (trailing,
seasonal and fixed baselines). `detector.as_contract(spec=..., code_version=...)` returns
a `godwit_contracts.Detector`; `ROLES` is applied there from the column profiles, so the
Benford detector never tests an identifier column.

**Versioning.** Bump the version whenever output could change for identical input.
Pass `pins=Path(...)` to `conformance_suite`: the kit records a hash of the detector's
output per version and fails when the output moves while the version does not.

**The Benford lesson.** A sketch's error is part of the statistics. A plain chi-square on
a million KLL-summarised rows detects the sketch's own rank error and fires on
everything. The reference detector caps its effective sample size where worst-case
sketch error alone reaches the test's degrees of freedom, and abstains when the
reference never followed Benford. Read its module docstring before writing a detector
over approximate sketches.

## 7. Features

A feature plugin writes one DuckDB **aggregate** over the rows of its point-in-time
window -- `f"avg({columns['amount']})"` -- and declares `DTYPE`, `INPUTS` (role names,
not customer columns), `LOOKBACK` (mandatory, positive), and optionally `EMBARGO`,
`LABEL_LAG`, `FILL`, `KIND`. The SDK builds the window: each event sees only its own
entity's rows in `[event_time - LOOKBACK, event_time - EMBARGO)`.

* `feature.spec(feature_id=, source_id=, entity_key=, timestamp_column=, columns=)` binds
  roles to customer columns and returns the contract `FeatureSpec` with its
  `PointInTimeRule`.
* `feature.evaluate(spec, events=, history=)` is the reference evaluator: `events` has
  the entity key and `event_time`; the result gains a `value` column, in event order.

Rejected at registration: no `LOOKBACK`, an `EMBARGO` at least as long as it, an
aggregate that is not deterministic, not valid DuckDB over the window, or contains a
string literal, a comment, `;` or a subquery (a literal from data belongs in a tainted
segment; a subquery can read outside the window). The kit checks the property directly:
it changes every row outside each event's window and asserts no value moves. The
contract does not yet say that `expression` is a window aggregate:
`CR-A9-feature-expression-semantics-unspecified`.

## 8. Context sources

Implement `fetch(start=, end=)` returning `ContextRecord`s (plain fields: `key`,
`context_type`, `kind`, `start`, `end`, `label`, `source_ids`, `columns`, `permanent`) and
`for_conformance(records)`. The base builds `godwit_context.ContextEvent`s: `label`
becomes `Tainted` USER_SUPPLIED (DATA_VALUE), `columns` SCHEMA_NAME, `key` is hashed into
the event id and dropped. `kind` must be a plain identifier (`deploy.payments`); free
text is refused. Events are filtered to the window, deduplicated and sorted, so the
output is a function of what the backend returned. The instance is a
`godwit_context.ContextSource`.

## 9. Panels

Declare `TITLE`, `FIELDS` (gate field keys, e.g. `open_patterns`) and optionally
`LABELS`; implement `render(self, payload: SafePayload) -> PanelView`. Registration
rejects a `render` that accepts anything but a `SafePayload`. `panel.view(payload)`
refuses a payload missing a declared field, and refuses a view containing any string
that is not the title, a declared label or a payload value, or any value not in the
payload: a panel cannot add what the gate did not clear. The Vision Board (A16) reads
panels from `PluginRegistry.of_kind(PluginKind.PANEL)`, clears a payload for
`Destination.UI` naming `FIELDS`, and calls `view`.

## 10. Logging

`self.log` is a `PluginLogger`, the only logger the SDK hands out:

```python
self.log.info("page.fetched", rows=len(batch), page=index, account=tainted_value)
# {"event": "page.fetched", "plugin": "acme.mongodb", "rows": 500, "page": 3,
#  "account": "<withheld:data_value>"}
```

Field values are `bool`, `int`, `float`, `None`, a member of your own `StrEnum`, or a
`Tainted` (rendered as `<withheld:...>`, never unwrapped). A plain `str` is a mypy error
and renders `<refused>` at runtime. The event must look like `page.fetched`; anything else
renders `<refused>`. **mypy does not enforce that the event is a literal** -- it treats
`LiteralString` as `str`; pyright does. There is no `exc_info` and no route to the
underlying `logging.Logger`. Records go to `godwit.plugins.<namespace>.<name>` as JSON.

Do not `import logging`, `print`, or write to `sys.stdout`, `sys.stderr` or `os.write` in
a plugin module. The conformance kit fails all of them statically, and captures every
output channel at runtime for the ones a determined author hides.

## 11. Capabilities and trust -- read this before deploying a plugin

```python
@source(..., capabilities=Capabilities(network=("api.acme.com",), filesystem=("/var/cache/acme",)),
        limits=ResourceLimits(max_bytes_read=10**9, max_seconds=600, max_memory_bytes=2**30))
```

A plugin declares the network hosts (`"host"`, `"*.suffix"`, `"*"`), directories and
subprocess access it needs. While the SDK runs plugin code, a CPython audit hook refuses
anything undeclared, and always refuses starting a thread (it would escape the check) and
loading native code with `ctypes`. A refusal the plugin catches is still raised when the
call returns. `ResourceLimits` caps bytes handed over per probe, seconds and traced
memory per call; seconds and memory are checked at audited operations, between batches
and on return.

**This is a guardrail, not a sandbox, and it must not be described as one.** It stops an
honest plugin from doing something its author forgot -- a stray `requests.get`, a cache
file, a helper library that shells out -- and makes that fail on the author's machine.
It does not contain a hostile plugin: in-process Python can reach the interpreter through
`ctypes` (before the scope), `gc`, frame introspection or a C extension, and switch the
checks off. Native libraries do their own I/O without CPython's audit points -- SQLite
opens its database file in C, and `tests/test_capabilities.py` demonstrates the
filesystem declaration not seeing it. Code a plugin runs at import time, before the SDK
calls it, is not checked at all. A per-call time limit cannot interrupt a pure-Python
loop; it fires when the loop next touches I/O or returns.

So each plugin's `trust_category` says where it should run:

* **`ISOLATE`** -- every source (it reads customer rows) and every plugin that declares
  any capability. Unless you wrote and reviewed it, run it in its own process, under its
  own OS user, with only the credentials and network routes it declared, and with OS
  resource limits. A probe worker is already a separate process (`godwit-probe`'s
  `WorkerPool`); run untrusted sources there, never in the orchestrator.
* **`IN_PROCESS`** -- a sketch, detector, feature, context source or panel declaring no
  capability: a pure computation over what the SDK hands it. Reviewed code may run
  in-process. Unreviewed code should still be isolated.

`godwit-sdk list` prints every installed plugin's category and declared capabilities.

## 12. Packaging and discovery

```toml
[project.entry-points."godwit.plugins"]
"acme.mongodb" = "godwit_source_mongodb:MongoSource"
```

One entry point per plugin in the group `godwit.plugins`, named by the plugin's qualified
name. `godwit_sdk.discover(registry)` loads every installed one, checks it is a decorated
plugin whose name matches the entry point and whose `requires_sdk` admits this core, and
registers it. Failures are reported in the `DiscoveryReport` with the reason and the rest
still load; `strict=True` raises the first instead. `PluginRegistry` keys plugins by kind
and qualified name, so two publishers' `memory` sources coexist as `acme.memory` and
`globex.memory`, and a second plugin under a taken name is refused.

## 13. The conformance kit -- `godwit_sdk.testing`

```python
# tests/test_conformance.py
from godwit_sdk.testing import conformance_suite
from my_package import MongoSource

TestMongoSourceConformance = conformance_suite(MongoSource)
```

`pytest` then runs one test per check that applies to the plugin's kind. Requires the
`testing` extra (`pip install "godwit-sdk[testing]"`). For the kit's fixtures
(`godwit_torture`, `godwit_sentinels`), add `pytest_plugins = ["godwit_sdk.testing"]` to
your tests' `conftest.py`, as the scaffold does. The kit is deliberately not auto-registered through
`pytest11`: it imports `godwit_guard`, and auto-loading would claim the process's
`SafePayloadIssuer` in every pytest session wherever the SDK is installed.
`run_conformance(plugin)` returns a `ConformanceReport` outside pytest, and
`godwit-sdk check` runs the battery over every installed plugin.

| Kind | Checks |
|---|---|
| all | registration into a fresh registry; static hygiene (no `logging`, `print`, stdout/stderr, `os.write`; no `.reveal()` in a control-plane panel, context or feature) |
| source | `SourceAdapter`; profiling reads no data; every probe over the PII torture table completes; BLIND and unclassified columns refused and never requested; zero budget refuses before `read`; cancellation; bytes accounted; byte-identical bundles across instances; JSON and codec round trips; leaks, including a poisoned driver error |
| sketch | `Sketch`; monoid laws under hypothesis; leaks |
| detector | contract adapter and `ROLES`; `examine` never runs on a thin sketch; test counts; determinism and round trips; leaks over poisoned categorical sketches; optional version pin |
| feature | point-in-time property; determinism and round trips; leaks |
| context | window filtering, tainted labels, determinism, round trips; leaks |
| panel | a payload cleared through the real gate renders; determinism; round trip; leaks |

**The leak test** runs the plugin over A0's PII torture fixture (shipped in the kit;
`tests/test_golden.py` keeps the copy identical to `tests/golden/pii_torture`) while
capturing every log record at every level, stdout, stderr and every warning, plus the
text of anything raised and a rendering of what was returned (payloads declared
DATA_VALUE excluded). None of the fixture's distinctive values may appear. The
fixture's generic words (`unknown`, `general`) and bare salaries are not searched for:
they occur in any rendering without being a leak. **This is a backstop, not the control**
-- the control is the typed taint and the safe logger. Passing it does not prove a plugin
safe; failing it proves the plugin is not.

## 14. Scaffolding -- `godwit-sdk new`

```
godwit-sdk new source --name mongodb --namespace acme [--dir .]
```

Kinds: `source`, `sketch`, `detector`, `feature`, `context`, `panel`. Writes
`godwit-<kind>-<name>/` with a `pyproject.toml` registering the entry point (and a
`[tool.mypy]` section), the plugin module, `tests/conftest.py`, `tests/test_conformance.py`
and a README. `tests/test_scaffold.py` generates every kind and requires each to pass its
own conformance tests, `ruff` with this repository's configuration, and `mypy --strict`.

## 15. Known limits

* **Capabilities are a guardrail** (§11): native I/O, import-time code, threads started
  from C and in-process tampering are outside them. Isolation is a deployment decision
  this package recommends and does not implement.
* **Capabilities are fixed per plugin class**, in the decorator. A deployment cannot
  narrow or redirect a plugin's declared host or directory without a new release.
* **Plugin sources always probe in full.** There is no incremental (delta) path, because
  a plugin exposes partitions without history.
* **The kit's source probes assume the backend can hold strings and 64-bit integers**
  (the torture table's types). A backend that cannot store one of them cannot pass.
* **The leak test searches only distinctive values** -- see §13.
* **`PanelView` is defined here**, not in contracts, until A16 and A0 agree on one.
* **Re-exported types are promised by name only** (§2,
  `CR-A9-sdk-surface-rests-on-unpromised-types`).
* **mypy does not enforce literal log events** (§10); the runtime shape check does.
* **Feature evaluation is a reference implementation** in DuckDB, one correlated subquery
  per event: correct, not fast. A11 owns the production path.
