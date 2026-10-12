# CR-A9-sdk-surface-rests-on-unpromised-types

**Filed by:** A9 (`godwit-sdk`)
**Against:** `godwit-contracts`; `godwit-guard`, `godwit-probe`, `godwit-detect`, `godwit-context`
**Status:** open

## The problem

The brief: *if a core package needs something the SDK cannot express, either the SDK is
too narrow or that package reached where it should not have.* Building the SDK found the
inverse: the SDK cannot express its own public surface in contract types, because the
types a plugin must touch live in packages that make no stability promise.

| SDK public API | needs | lives in |
|---|---|---|
| `SourceBase.govern(access=...)` | `AccessModeMap` | `godwit_guard` |
| `SourceBase.run_probe(...)` | `ProbeOutcome`, `CancelToken`, `ProbeKeyring` | `godwit_probe` |
| `DetectorBase.run(...)`, `HypothesisTest.direction` | `SketchSeries`, `DetectionResult`, `Direction` | `godwit_detect` |
| `ContextRecord.context_type`, `ContextBase.events()` | `ContextType`, `ContextEvent` | `godwit_context` |
| `PanelBase.render(...) -> PanelView` | a panel view type A16 will consume | nowhere; the SDK defines it |

`godwit_sdk` re-exports the names a plugin cannot be written without, and promises the
*names*. It cannot promise the *shapes*: A5, A6, A7 or A8 can change any of these in a
patch release and break every published plugin. The API-surface snapshot test catches it
-- after the fact, and in this repository, not in a plugin author's.

## Why it matters

A plugin ecosystem pins to the SDK's version. If the SDK's version does not move when a
type under it moves, the pin is worthless.

## The smallest sufficient change

Each of these is already requested by its owner; this CR concurs, and adds the SDK as a
consumer that needs them settled:

* `AccessMode`, `AccessModeMap`, `ModeDecision` into contracts --
  `CR-A5-access-modes-have-no-contract`, `CR-A6-access-modes-need-a-contract-home`.
* A probe outcome that can say refused / cancelled / no-change --
  `CR-A6-sketch-bundle-cannot-say-why`.
* `Direction`, and a detection result with test counts and refusals --
  `CR-A7-evidence-has-no-structured-detail`, `CR-A7-detector-cannot-see-history-or-spec`.
* `ContextEvent`, `ContextType` -- `CR-A8-context-has-no-contract-or-table`.
* New: a `PanelView` in contracts, so A16 and the SDK agree on what a panel returns.

```python
# proposed, new module godwit_contracts.vision
class PanelSeries(GodwitModel):
    label: str
    values: tuple[SafeScalar, ...]


class PanelView(GodwitModel):
    title: str
    chart: Literal["stat", "bar", "line", "table"]
    series: tuple[PanelSeries, ...] = ()
```

## Who else this affects

A5, A6, A7, A8 (types move), A16 and A17 (panel view), every plugin author.

## What I did instead

Re-exported the names from `godwit_sdk`, defined `PanelView` in `godwit_sdk.panel`, and
snapshotted the full public surface -- including the re-exported types' shapes -- in
`tests/api_surface.json`, so an upstream change to any of them fails this package's
tests.

```
packages/godwit-sdk/tests/test_contract_gaps.py::test_the_types_under_the_sdk_surface_are_contracts
@pytest.mark.xfail(strict=True, reason="CR-A9-sdk-surface-rests-on-unpromised-types")
```

## Decision

_Left blank by the filer. A human fills this in._
