# godwit-sdk -- HANDOFF

**Owner:** A9 · **Plane:** both · **Status:** complete

> **A source plugin runs in the DATA PLANE** and reads customer rows. Every other kind
> runs on sketches, statistics or gated payloads. The SDK's job is to make the safe path
> the default one for code nobody here wrote.

Full reference and tutorial: [`docs/packages/godwit-sdk.md`](../../docs/packages/godwit-sdk.md).

## State

* `ruff`, `ruff format --check`, `mypy --strict` clean, zero suppressions in `src/`.
* The suite runs in a child interpreter (`tests/test_isolated_suite.py`), like guard's
  and probe's, because a source probe imports `godwit_guard`, which claims the
  process's `SafePayloadIssuer`. `GODWIT_SDK_ISOLATED=1 uv run pytest packages/godwit-sdk/tests`
  runs it directly. Four strict xfails, one per change request.
* `tests/test_scaffold.py` is the slow one (about two minutes): it generates all six
  kinds and runs pytest, ruff and mypy on each.
* Dependencies added: `packaging` (version specifiers); `pytest` and `hypothesis` as the
  `testing` extra. The workspace dev group already had both.

## Layout

| Module | What it is |
|---|---|
| `__init__.py` | the public surface; everything in `__all__` is promised |
| `plugin.py` | `PluginInfo`, `PluginKind`, `TrustCategory`, registration (`decorator_for`) |
| `capabilities.py` | `Capabilities`, `ResourceLimits`, the audit-hook scope, `PluginRunner` |
| `log.py` | `PluginLogger`, the only logger a plugin gets |
| `errors.py` | every SDK error; `PluginFailedError` withholds the plugin's text |
| `source.py`, `_bridge.py` | `@source`; the bridge runs `godwit_probe.ProbeExecutor` over a plugin (imported lazily) |
| `sketch.py` | `@sketch`; the monoid-law checks (`law_problems`) |
| `detector.py` | `@detector`; a `godwit_detect.SeriesDetector` shim and contract adapter |
| `feature.py` | `@feature`; the point-in-time window and reference evaluator (DuckDB) |
| `context.py`, `panel.py` | `@context`, `@panel` |
| `registry.py` | `PluginRegistry`, entry-point `discover` |
| `testing/` | the conformance kit (pytest plugin) and its copy of the PII torture fixture |
| `cli.py`, `_templates.py` | `godwit-sdk new | list | check` |
| `_surface.py` | renders the public surface for the snapshot test |
| `examples/` | REST source, Bloom sketch, Benford detector (entry points in `pyproject.toml`) |

## Acceptance, item by item

| Brief | Where |
|---|---|
| A source written from the docs alone, against an unmentioned source | `tests/_sdk_sqlite_source.py`, `tests/test_dogfood.py`; report below |
| Non-conformant plugin of each kind rejected with an exact message | `tests/test_rejections.py` |
| A leaky plugin (prints a tainted value) caught by the kit | `tests/test_leaky.py` -- static and runtime, including one that hides `print` |
| API surface snapshot in CI | `tests/test_api_surface.py`, `tests/api_surface.json` |
| Every reference plugin passes conformance | `tests/test_examples.py` |
| Capability enforcement, stated honestly | `tests/test_capabilities.py`, the last two tests show what it cannot do |
| Scaffold passes conformance on first run | `tests/test_scaffold.py` |
| Golden fixtures | `tests/test_golden.py` (kit's torture copy == A0's), Benford over `drift_table` |

## Decisions a successor should know about

1. **A plugin source is `godwit-probe`, not a reimplementation.** The bridge adapts five
   plugin methods onto `ProbeSource`, so access modes, OPAQUE hashing, budget refusal,
   mid-read budget stops, cancellation and sanitising are exactly the core path. Bytes
   are measured from the Arrow batches handed over, not from the plugin.
2. **Fail closed.** An ungoverned source treats every column as BLIND.
3. **The decorator is registration** and reports *every* problem at once. A plugin that
   overrides an SDK-implemented method (`SDK_METHODS`) is rejected.
4. **Contract law 4 is enforced, not tested**: `SketchBase` wraps each subclass's `merge`.
5. **The kit is not a `pytest11` auto-plugin**: importing it claims the issuer, which
   would break the contracts suite in any environment where the SDK is installed.
6. **Importing `godwit_sdk` does not import `godwit_guard`.** Keep it that way; the
   bridge and the kit are the only modules that do.
7. **The leak test searches only distinctive sentinels** (names, emails, SSNs, device
   ids, merchant names, notes). `unknown`, `general` and bare salaries appear in honest
   renderings.
8. **Benford caps its effective n by the KLL rank error** and abstains when the reference
   did not conform. Without the cap it fires on the sketch's own error.

## Dogfooding report -- where the docs failed

Writing `tests/_sdk_sqlite_source.py` from the package doc alone surfaced these gaps.
Each is now fixed in the doc (§4 unless stated):

1. **No guidance for a backend without versions.** SQLite has no snapshot id. The doc
   said "must change whenever the data does" and nothing about how. Added "Snapshots when
   the backend has no versions" (high-water mark, what it misses, fixed epoch).
2. **`logical_type` only maps Arrow types.** A backend with its own type names (SQLite
   declared types) needs its own mapping; the doc now says so.
3. **Estimates without per-partition metadata.** SQLite knows page count, not bytes per
   rowid range. The doc did not say whether a coarse upper bound was acceptable or what
   an over/under-estimate does. Added "Estimates".
4. **`read` gets names, not types.** Building an Arrow schema in `read` needed the types;
   both the REST example and the dogfood re-fetch them. Now stated.
5. **`for_conformance` for a database.** Unclear whether a fake could bypass the real
   client. Now: "through the code path production uses -- a throwaway in-memory
   database". The SQLite version loads the tables into `:memory:`.
6. **The filesystem capability does not see SQLite** (native I/O). The declaration
   `filesystem=("./data",)` is honest but unenforced. Now in §11 and known limits, with a
   test demonstrating it. Also: the database path differs per deployment, but
   capabilities are fixed per class -- recorded as a known limit.

## Change requests filed

| CR | Ask | Workaround |
|---|---|---|
| `CR-A9-source-kind-is-closed-to-plugins` | `SourceKind.PLUGIN` | `PARQUET` stand-in; plugin named in `SourceRef.catalog` |
| `CR-A9-acquisition-has-no-generic-catalog-route` | `CATALOG_BOUNDS`, `CATALOG_VALUE_LIST` | Iceberg-bounds and pg-MCV routes (same DATA_VALUE floor) |
| `CR-A9-sdk-surface-rests-on-unpromised-types` | access modes, probe outcome, detection result, context event, panel view into contracts | re-export + surface snapshot catches upstream drift |
| `CR-A9-feature-expression-semantics-unspecified` | `FeatureSpec.expression_kind` | SDK emits window aggregates, documented |

Concurs with, without a separate filing: `CR-A2-sketch-kind-vocabulary` (the Bloom
plugin borrows `THETA`), `CR-A2-serialise-needs-context`, `CR-A5-issuer-claim-is-process-global`.

## For specific agents

| You are | What you need from here |
|---|---|
| **A10 (orchestrator)** | `discover(PluginRegistry())` at startup; run `ISOLATE` plugins in worker processes. A plugin source is a `SourceAdapter`; call `govern()` with the mode map first. |
| **A11 (features)** | `FeatureSpec`s from plugins carry a window aggregate in `expression` (see the CR). `FeatureBase.evaluate` is the reference semantics to match. |
| **A16 (Vision Board)** | Panels: `registry.of_kind(PluginKind.PANEL)`, clear `FIELDS` for `Destination.UI`, call `view(payload)`; render the `PanelView`. |
| **A5 / A18** | Plugin catalog statistics are tainted with the nearest acquisition (CR above). `PluginFailedError.original` is DATA_VALUE text. |
| **Everyone** | Changing a type the SDK re-exports fails `tests/test_api_surface.py`. Tell A9, or bump and regenerate per the doc §2. |

## Known limits

See the package doc §15. The ones that matter most: capabilities are a guardrail and not
a sandbox; they are fixed per plugin class; plugin sources always probe in full; the
panel view type lives here until contracts adopt one.
