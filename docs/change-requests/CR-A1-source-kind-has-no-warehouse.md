# CR-A1-source-kind-has-no-warehouse

**Filed by:** A1 (`godwit-source`)
**Against:** `godwit-contracts`
**Status:** open

## The problem

`godwit_contracts.source.SourceKind` has four members:

```python
ICEBERG    POSTGRES    PARQUET    DUCKDB
```

Its docstring says "Adding a kind needs a `SourceAdapter` in godwit-source", which is
the right rule and is why this is a CR rather than a patch. My brief names a third
adapter -- `WarehouseSqlAdapter`, "a generic DB-API adapter for Snowflake/BigQuery-style
backends" -- and there is no `SourceKind` a Snowflake table can honestly declare.

## Why it matters

`WarehouseSqlAdapter._require_warehouse` cannot reject what it cannot read, because
there is no value that says "this is a Snowflake table". Today it accepts `DUCKDB`,
`PARQUET` and `POSTGRES`, which means:

* A Snowflake source has to be registered as, say, `DUCKDB`. That is a lie in a field
  the orchestrator uses for routing, and it will end up in a lineage record that a
  regulator reads.
* `PostgresAdapter` and `WarehouseSqlAdapter` both accept `POSTGRES`, so the kind no
  longer selects an adapter. Picking the right one becomes configuration held somewhere
  else, which is exactly the kind of implicit coupling this enum exists to prevent.

Nothing crashes. It is a correctness-of-record problem rather than a runtime one, which
should set the priority.

## The smallest sufficient change

One member, generic rather than per-vendor, with the vendor recorded where vendor
details already live.

```python
# current
class SourceKind(StrEnum):
    ICEBERG = "iceberg"
    POSTGRES = "postgres"
    PARQUET = "parquet"
    DUCKDB = "duckdb"


# proposed
class SourceKind(StrEnum):
    ICEBERG = "iceberg"
    POSTGRES = "postgres"
    PARQUET = "parquet"
    DUCKDB = "duckdb"
    WAREHOUSE_SQL = "warehouse_sql"
    """A SQL warehouse reached over DB-API: Snowflake, BigQuery, Redshift and
    relatives. Which one is a property of the adapter's profile, not of the source
    kind: they differ in catalog spelling and approximate-aggregate names, not in what
    Godwit can read from them, and enumerating vendors here would mean a contract
    change every time a customer buys a different warehouse."""
```

One member, not two. `SNOWFLAKE` and `BIGQUERY` would be a contract change per vendor
for a distinction that `WarehouseProfile` already carries.

Adding a member does not change `segment_key` or `probe_key`: `SourceKind` appears in
`SourceRef.kind`, and `probe_key` hashes `source_id`, namespace and table, not the kind.
No stored key migrates.

## Who else this affects

* **A1 (`godwit-source`)** gates `WarehouseSqlAdapter` on it.
* **A10 (`godwit-orchestrator`)** routes probes by kind and needs to know the warehouse
  tier is the expensive one.
* **A16/A17 (Vision Board)** shows the source kind when a datasource is registered.
* **A5 (`godwit-guard`)** may want a per-kind policy: a warehouse probe returns
  pre-aggregated values with counts, which is a different egress shape from a scan.

## What I did instead

`WarehouseSqlAdapter._require_warehouse` accepts `DUCKDB`, `PARQUET` and `POSTGRES` --
the SQL-reachable kinds that exist -- and the module docstring says that a Snowflake or
BigQuery source has no honest kind to declare yet. Registering one means choosing a
member that is not true, which is a thing a reader should know about rather than
discover.

```
packages/godwit-source/tests/test_contract_gaps.py::test_a_warehouse_source_has_a_kind
@pytest.mark.xfail(reason="CR-A1-source-kind-has-no-warehouse")
```

## Decision

_Left blank by the filer. A human fills this in._
