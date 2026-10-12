# CR-A9-acquisition-has-no-generic-catalog-route

**Filed by:** A9 (`godwit-sdk`)
**Against:** `godwit-contracts` (`godwit_contracts.taint.Acquisition`)
**Status:** open

## The problem

A source plugin can publish catalog statistics: a column's minimum, maximum and most
common values, read from the backend's own metadata (MongoDB's `$collStats`, a REST
API's schema endpoint, a warehouse's information schema). The SDK taints these for the
plugin -- that is the point -- and must give each `Tainted` value an `Acquisition`.

The vocabulary names two *specific* catalogs: `ICEBERG_MANIFEST_BOUNDS` and
`PG_STATS_MCV`. There is no route for "bounds from some other catalog" or "a value list
from some other catalog". The SDK has to pick one of the two, and either is a false
statement about provenance.

## Why it matters

The *sensitivity* is right either way -- both floors are DATA_VALUE, and that is what
the gate decides on. What is wrong is the audit trail: an egress record for a MongoDB
bound will say it came from an Iceberg manifest. A reviewer reading provenance to
understand a leak path will be misled.

## The smallest sufficient change

```python
# proposed, both with a DATA_VALUE floor in ACQUISITION_MINIMUM_SENSITIVITY
class Acquisition(StrEnum):
    ...
    CATALOG_BOUNDS = "catalog_bounds"
    """Column min/max from any source catalog. Two real row values."""
    CATALOG_VALUE_LIST = "catalog_value_list"
    """Common or sample values from any source catalog. Real row values."""
```

## Who else this affects

A5 (`godwit-guard`) and A18 (`godwit-policy`), if any rule switches on acquisition. No
stored key changes.

## What I did instead

`godwit_sdk.source.BOUNDS_ACQUISITION = ICEBERG_MANIFEST_BOUNDS` and
`VALUE_LIST_ACQUISITION = PG_STATS_MCV`, documented as the nearest routes.

```
packages/godwit-sdk/tests/test_contract_gaps.py::test_plugin_catalog_statistics_have_their_own_route
@pytest.mark.xfail(strict=True, reason="CR-A9-acquisition-has-no-generic-catalog-route")
```

## Decision

_Left blank by the filer. A human fills this in._
