# CR-A9-source-kind-is-closed-to-plugins

**Filed by:** A9 (`godwit-sdk`)
**Against:** `godwit-contracts` (`godwit_contracts.source.SourceKind`)
**Status:** open

## The problem

`SourceRef.kind` is a `SourceKind`, a closed enum: `ICEBERG`, `POSTGRES`, `PARQUET`,
`DUCKDB`. Its docstring says "adding a kind needs a SourceAdapter in godwit-source". The
whole point of the SDK is that adding a source does *not* need a change to
`godwit-source` or to the contracts: `pip install godwit-source-mongodb` should be enough.
A plugin source has no truthful `SourceKind` to put in its refs.

## Why it matters

Nothing crashes. But every `SourceRef` a plugin emits claims to be something it is not,
and anything that dispatches on `SourceRef.kind` (an orchestrator choosing an adapter, a
cost model, a UI icon) will treat a REST API as a Parquet file.

## The smallest sufficient change

```python
# current
class SourceKind(StrEnum):
    ICEBERG = "iceberg"
    POSTGRES = "postgres"
    PARQUET = "parquet"
    DUCKDB = "duckdb"


# proposed: one member, meaning "ask the plugin registry"
class SourceKind(StrEnum):
    ...
    PLUGIN = "plugin"
    """A third-party adapter. ``SourceRef.catalog`` is ``plugin:<namespace>.<name>``."""
```

No stored key changes: `probe_key` hashes `source_id`, namespace and table, not `kind`.

## Who else this affects

`godwit-source` (unaffected; it never sees a plugin ref), A10 (adapter dispatch), A16/A17
(display). Concurs in spirit with `CR-A1-source-kind-has-no-warehouse`, which hit the
same closed vocabulary from the other side.

## What I did instead

`godwit_sdk.PLUGIN_SOURCE_KIND = SourceKind.PARQUET`, documented as a stand-in. The
plugin is identified by `SourceRef.catalog = "plugin:<namespace>.<name>"`, which
`SourceBase.run_probe` checks before running anything.

```
packages/godwit-sdk/tests/test_contract_gaps.py::test_a_plugin_source_has_a_kind_of_its_own
@pytest.mark.xfail(strict=True, reason="CR-A9-source-kind-is-closed-to-plugins")
```

## Decision

_Left blank by the filer. A human fills this in._
