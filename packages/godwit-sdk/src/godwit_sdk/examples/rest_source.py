"""Reference plugin 1: a source over a paginated REST API. **DATA PLANE.**

TUTORIAL. Read this after ``docs/packages/godwit-sdk.md`` section 4. Everything a source
plugin has to write is here, and nothing else is.

THE API IT READS
----------------
An imaginary orders service, chosen because it is shaped like most real ones:

``GET /tables/{t}/version``  ``{"version": "v42", "sequence": 42, "updated_at": "...Z"}``
``GET /tables/{t}/schema``   ``{"columns": {"amount": "float", "status": "string"}}``
``GET /tables/{t}/pages``    ``{"pages": [{"page": 0, "rows": 500, "bytes": 81234}]}``
``GET /tables/{t}/rows?page=N&fields=a,b``  ``{"rows": [{"a": 1, "b": "x"}, ...]}``

``version`` is the snapshot: it changes whenever the data does. ``pages`` is metadata --
row and byte counts per page -- which is what the budget is checked against before a
single row is fetched. ``rows`` takes a field list, so the plugin asks only for the
columns the probe planned; a BLIND column is never requested, let alone returned.

THE TRANSPORT
-------------
All HTTP goes through one callable, ``Transport = Callable[[str], bytes]``. In
production it is :class:`UrlTransport`, which uses the standard library and is the only
code here that touches the network -- hence ``capabilities=Capabilities(network=(...))``
naming exactly the host it may reach. :meth:`RestOrdersSource.for_conformance` swaps in
an in-memory fake serving the conformance kit's poisoned tables through the same parsing
code, so what the kit tests is what ships.

WHAT IS NOT HERE, ON PURPOSE
----------------------------
No ``print``, no :mod:`logging`, no value in an exception message, no ``Tainted``, no
budget arithmetic, no sketching, no retry loop that swallows errors into a log. The base
class does all of that, and does it the same way for every source.
"""

from __future__ import annotations

import datetime as _dt
import http.client
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from http import HTTPStatus
from typing import Final, Self
from urllib.parse import quote, unquote, urlencode

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

__all__ = ["API_HOST", "RestOrdersSource", "Transport", "UrlTransport"]

type Transport = Callable[[str], bytes]
"""``GET`` one path (with query string) and return the response body."""

API_HOST: Final[str] = "orders.api.example.com"

_ARROW: Final[Mapping[LogicalType, pa.DataType]] = {
    LogicalType.STRING: pa.string(),
    LogicalType.INT: pa.int64(),
    LogicalType.FLOAT: pa.float64(),
    LogicalType.BOOL: pa.bool_(),
}


class UrlTransport:
    """The production transport: HTTPS GET with the standard library. Network only."""

    def __init__(self, host: str = API_HOST, *, timeout: float = 30.0) -> None:
        self._host = host
        self._timeout = timeout

    def __call__(self, path: str) -> bytes:
        connection = http.client.HTTPSConnection(self._host, timeout=self._timeout)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            if response.status != HTTPStatus.OK:
                # The status code only: a response body can quote the row it choked on.
                raise ConnectionError(f"orders API answered {response.status}")
            return response.read()
        finally:
            connection.close()


@source(
    name="rest-orders",
    namespace="examples",
    version="1.0.0",
    summary="Orders from a paginated REST API.",
    capabilities=Capabilities(network=(API_HOST,)),
)
class RestOrdersSource(SourceBase):
    """Reads tables from the orders API through a :data:`Transport`."""

    def __init__(self, transport: Transport | None = None) -> None:
        self._get = transport if transport is not None else UrlTransport()

    def _json(self, path: str) -> dict[str, object]:
        loaded = json.loads(self._get(path))
        if not isinstance(loaded, dict):
            raise TypeError("the orders API returned something other than an object")
        return loaded

    @staticmethod
    def _path(table: TableName, leaf: str) -> str:
        return f"/tables/{quote(table.name, safe='')}/{leaf}"

    # -- metadata ------------------------------------------------------------------------

    def snapshot(self, table: TableName, *, at: _dt.datetime | None) -> Snapshot:
        del at  # this API only serves its current version
        found = self._json(self._path(table, "version"))
        return Snapshot(
            snapshot_id=str(found["version"]),
            sequence_number=int(str(found["sequence"])),
            committed_at=_dt.datetime.fromisoformat(str(found["updated_at"])),
        )

    def columns(self, table: TableName, snapshot: Snapshot) -> Mapping[str, LogicalType]:
        del snapshot  # the API serves the current schema only
        return self._schema(table)

    def _schema(self, table: TableName) -> Mapping[str, LogicalType]:
        found = self._json(self._path(table, "schema"))["columns"]
        if not isinstance(found, dict):
            raise TypeError("schema.columns is not an object")
        return {str(name): LogicalType(str(kind)) for name, kind in found.items()}

    def partitions(self, table: TableName, snapshot: Snapshot) -> Sequence[Partition]:
        del snapshot
        pages = self._json(self._path(table, "pages"))["pages"]
        if not isinstance(pages, list):
            raise TypeError("pages is not a list")
        return [
            Partition(
                key=str(page["page"]),
                estimated_bytes=int(page["bytes"]),
                row_count=int(page["rows"]),
            )
            for page in pages
        ]

    def column_stats(self, table: TableName, snapshot: Snapshot) -> Mapping[str, ColumnStats]:
        del table, snapshot
        return {}  # the API publishes no statistics; the base copes with none

    # -- data ----------------------------------------------------------------------------

    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        types = self._schema(table)
        query = urlencode({"page": partition.key, "fields": ",".join(columns)})
        rows = self._json(f"{self._path(table, 'rows')}?{query}")["rows"]
        if not isinstance(rows, list):
            raise TypeError("rows is not a list")
        schema = pa.schema([(name, _ARROW[types[name]]) for name in columns])
        yield pa.Table.from_pylist(rows, schema=schema)

    # -- conformance ---------------------------------------------------------------------

    @classmethod
    def for_conformance(cls, tables: Mapping[str, pa.Table]) -> Self:
        return cls(transport=_FakeOrdersApi(tables))


_PAGE_ROWS: Final[int] = 500
_LOGICAL: Final[Mapping[str, LogicalType]] = {
    "string": LogicalType.STRING,
    "int64": LogicalType.INT,
    "double": LogicalType.FLOAT,
    "bool": LogicalType.BOOL,
}


class _FakeOrdersApi:
    """The orders API, in memory, serving given Arrow tables. For the conformance kit."""

    def __init__(self, tables: Mapping[str, pa.Table]) -> None:
        self._tables = dict(tables)

    def __call__(self, path: str) -> bytes:
        route, _, query = path.partition("?")
        _, _, name, leaf = route.split("/", 3)
        table = self._tables[name]
        if leaf == "version":
            body: object = {"version": "v1", "sequence": 1, "updated_at": "2024-01-01T00:00:00Z"}
        elif leaf == "schema":
            body = {"columns": {f.name: _LOGICAL[str(f.type)] for f in table.schema}}
        elif leaf == "pages":
            body = {
                "pages": [
                    {
                        "page": index,
                        "rows": min(_PAGE_ROWS, table.num_rows - start),
                        "bytes": table.slice(start, _PAGE_ROWS).nbytes,
                    }
                    for index, start in enumerate(range(0, table.num_rows, _PAGE_ROWS))
                ]
            }
        else:
            params = dict(part.split("=", 1) for part in query.split("&") if part)
            fields = unquote(params["fields"]).split(",")
            start = int(params["page"]) * _PAGE_ROWS
            body = {"rows": table.select(fields).slice(start, _PAGE_ROWS).to_pylist()}
        return json.dumps(body).encode("utf-8")
