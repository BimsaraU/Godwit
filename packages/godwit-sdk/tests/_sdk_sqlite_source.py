"""The acceptance exercise: a source adapter written from the SDK docs alone. DATA PLANE.

The brief asks for proof that someone who has never seen the codebase can write a
working adapter from the documentation. This one was written against a backend no other
part of Godwit mentions -- SQLite, through the standard library's :mod:`sqlite3` --
using only ``docs/packages/godwit-sdk.md`` and the docstrings it points to. Where the
docs failed, the gap is recorded in ``HANDOFF.md`` ("Dogfooding report") and fixed in the
docs, not papered over here.

Snapshot: SQLite has no table versions, so the snapshot id is derived from metadata the
database keeps cheaply -- ``PRAGMA schema_version`` and ``max(rowid)`` (an index lookup,
not a scan). That is correct for append-only tables and documented as such; an UPDATE
in place is not visible to it.
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from typing import Final, Self

import pyarrow as pa
from godwit_sdk import (
    Capabilities,
    ColumnStats,
    LogicalType,
    Partition,
    Snapshot,
    SourceBase,
    TableName,
    source,
)

__all__ = ["SqliteSource"]

_EPOCH: Final[_dt.datetime] = _dt.datetime(1970, 1, 1, tzinfo=_dt.UTC)
"""SQLite records no commit time; snapshots are dated at a fixed epoch, never the clock."""
_PAGE_ROWS: Final[int] = 5
_PAGE_FILTER: Final[str] = "WHERE rowid > ? AND rowid <= ? ORDER BY rowid"
_AFFINITY: Final[tuple[tuple[str, LogicalType], ...]] = (
    ("INT", LogicalType.INT),
    ("CHAR", LogicalType.STRING),
    ("TEXT", LogicalType.STRING),
    ("CLOB", LogicalType.STRING),
    ("REAL", LogicalType.FLOAT),
    ("FLOA", LogicalType.FLOAT),
    ("DOUB", LogicalType.FLOAT),
    ("BOOL", LogicalType.BOOL),
)
_ARROW: Final[Mapping[LogicalType, pa.DataType]] = {
    LogicalType.INT: pa.int64(),
    LogicalType.STRING: pa.string(),
    LogicalType.FLOAT: pa.float64(),
    LogicalType.BOOL: pa.bool_(),
}


def _ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _logical(declared: str) -> LogicalType:
    upper = declared.upper()
    return next((kind for key, kind in _AFFINITY if key in upper), LogicalType.UNKNOWN)


@source(
    name="sqlite",
    namespace="dogfood",
    version="0.1.0",
    summary="Tables in a SQLite database file.",
    capabilities=Capabilities(filesystem=("./data",)),
)
class SqliteSource(SourceBase):
    """One SQLite database. Tables are addressed by name; the namespace is ignored."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._db = connection

    def snapshot(self, table: TableName, *, at: _dt.datetime | None) -> Snapshot:
        del at  # SQLite keeps no history; only the current version exists
        (schema,) = self._db.execute("PRAGMA schema_version").fetchone()
        statement = " ".join(["SELECT max(rowid) FROM", _ident(table.name)])
        (high,) = self._db.execute(statement).fetchone()
        mark = int(high or 0)
        return Snapshot(
            snapshot_id=f"s{int(schema)}-r{mark}", sequence_number=mark, committed_at=_EPOCH
        )

    def columns(self, table: TableName, snapshot: Snapshot) -> Mapping[str, LogicalType]:
        del snapshot
        rows = self._db.execute(f"PRAGMA table_info({_ident(table.name)})").fetchall()
        return {str(row[1]): _logical(str(row[2])) for row in rows}

    def partitions(self, table: TableName, snapshot: Snapshot) -> Sequence[Partition]:
        del table
        high = snapshot.sequence_number
        (page_size,) = self._db.execute("PRAGMA page_size").fetchone()
        (pages,) = self._db.execute("PRAGMA page_count").fetchone()
        whole_file = int(page_size) * int(pages)
        return [
            Partition(key=str(start), estimated_bytes=whole_file, row_count=_PAGE_ROWS)
            for start in range(0, high, _PAGE_ROWS)
        ]

    def column_stats(self, table: TableName, snapshot: Snapshot) -> Mapping[str, ColumnStats]:
        del table, snapshot
        return {}  # sqlite_stat1 holds index statistics only; nothing per column

    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        types = self.columns(table, Snapshot("", 0, _EPOCH))
        start = int(partition.key)
        projection = ", ".join(_ident(name) for name in columns)
        statement = " ".join(["SELECT", projection, "FROM", _ident(table.name), _PAGE_FILTER])
        rows = self._db.execute(statement, (start, start + _PAGE_ROWS)).fetchall()
        schema = pa.schema([(name, _ARROW[types[name]]) for name in columns])
        yield pa.Table.from_pylist([dict(zip(columns, row, strict=True)) for row in rows], schema)

    @classmethod
    def for_conformance(cls, tables: Mapping[str, pa.Table]) -> Self:
        connection = sqlite3.connect(":memory:", check_same_thread=False)
        for name, data in tables.items():
            declared = {
                pa.int64(): "INTEGER",
                pa.string(): "TEXT",
                pa.float64(): "REAL",
                pa.bool_(): "BOOLEAN",
            }
            columns = ", ".join(f"{_ident(f.name)} {declared[f.type]}" for f in data.schema)
            connection.execute(f"CREATE TABLE {_ident(name)} ({columns})")
            marks = ", ".join("?" for _ in data.schema)
            insert = " ".join(["INSERT INTO", _ident(name), "VALUES", f"({marks})"])
            connection.executemany(insert, [tuple(row.values()) for row in data.to_pylist()])
        return cls(connection)
