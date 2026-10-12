"""The in-perimeter query engine: DuckDB over a stream of Arrow batches.

DATA PLANE. One :class:`QueryEngine` per probe run. Each data file's projected batches
are registered as the view ``godwit_src`` and the planned SQL runs over them, streaming:
DuckDB pulls batches from the reader as it needs them and hands result batches back the
same way, so neither side ever holds a whole file, let alone a table.

Three settings are deliberate:

* ``threads = 1``. With more, DuckDB may emit result rows in a different order from run
  to run, and three of the sketches (KLL, Count-Min's heavy hitters, the category
  histogram once degraded) are bounded summaries whose bytes depend on arrival order.
  Determinism beats parallelism inside one probe; parallelism lives across probes.
* ``memory_limit``. A backstop so that a plan the planner got wrong cannot take the
  worker down; the streaming shape is what actually bounds memory.
* The OPAQUE functions are registered only when a keyring is present, so a plan that
  names one without a keyring fails to bind rather than hashing under nothing.

The keyed-hash functions call ``godwit_guard.KeyedHasher.digest``, which renders a value
through ``canonical_scalar`` and HMACs it -- the same pseudonym ``hash_for`` gives the
planner for predicate values, so a hashed predicate matches a hashed column.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Final

import duckdb
import pyarrow as pa
from duckdb import func as duckdb_func
from duckdb import sqltypes
from godwit_contracts import LogicalType
from godwit_guard import KeyedHasher

from godwit_probe.keyring import ProbeKeyring
from godwit_probe.plan import OPAQUE_FUNCTIONS, SOURCE_VIEW, ProbePlan

__all__ = ["DEFAULT_MEMORY_LIMIT", "QueryEngine"]

DEFAULT_MEMORY_LIMIT: Final[str] = "512MB"

_PARAMETER_TYPES: Final[dict[LogicalType, sqltypes.DuckDBPyType]] = {
    LogicalType.STRING: sqltypes.VARCHAR,
    LogicalType.INT: sqltypes.BIGINT,
    LogicalType.FLOAT: sqltypes.DOUBLE,
    LogicalType.BOOL: sqltypes.BOOLEAN,
    LogicalType.DATE: sqltypes.DATE,
}


def _keyed(hasher: KeyedHasher) -> Callable[[pa.Array], pa.Array]:
    def digest(values: pa.Array) -> pa.Array:
        return pa.array(
            [None if value is None else hasher.digest(value) for value in values.to_pylist()],
            type=pa.string(),
        )

    return digest


class QueryEngine:
    """Runs planned SQL over Arrow batches. Not thread-safe; one per probe run."""

    def __init__(
        self, keyring: ProbeKeyring | None, *, memory_limit: str = DEFAULT_MEMORY_LIMIT
    ) -> None:
        self._con = duckdb.connect(":memory:", config={"threads": 1, "memory_limit": memory_limit})
        if keyring is not None:
            function = _keyed(keyring.column_hasher)
            for logical, name in OPAQUE_FUNCTIONS.items():
                self._con.create_function(
                    name,
                    function,
                    [_PARAMETER_TYPES[logical]],
                    sqltypes.VARCHAR,
                    type=duckdb_func.ARROW,
                )

    def run(
        self,
        plan: ProbePlan,
        batches: Iterator[pa.RecordBatch],
        *,
        schema: pa.Schema,
        batch_rows: int,
    ) -> Iterator[pa.RecordBatch]:
        """Stream the plan's result over one file's batches."""
        reader = pa.RecordBatchReader.from_batches(schema, batches)
        self._con.register(SOURCE_VIEW, reader)
        try:
            result = self._con.execute(plan.sql, list(plan.parameters))
            yield from result.to_arrow_reader(batch_rows)
        finally:
            self._con.unregister(SOURCE_VIEW)

    def close(self) -> None:
        """Release the connection."""
        self._con.close()
