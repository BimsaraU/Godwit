"""Talking to a SQL database without depending on a driver. Data plane.

Both SQL adapters take a live DB-API 2.0 connection rather than a DSN, for three
reasons. It keeps ``psycopg``, ``snowflake-connector`` and ``google-cloud-bigquery``
out of this package's dependency tree, which matters inside a bank that reviews every
transitive package it runs. It lets the caller own connection pooling, TLS and
credentials, none of which belong here. And it makes the zero-scan test possible: a
recording connection is a dozen lines and proves what a live database never could.

Statements are built with SQLAlchemy Core, never with string formatting. That is not
style. Customer table and column names go into every one of these queries, and a
customer table can be called ``"; drop table x --``. SQLAlchemy quotes identifiers and
binds values; a formatted string would make this module the injection point for the
whole product.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal, Protocol, runtime_checkable

import sqlalchemy as sa
from godwit_contracts.common import ScalarValue
from godwit_contracts.segment import Operator, Segment
from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.sql.elements import ColumnElement

from godwit_source.errors import UnsupportedProbeError, sanitise_driver_error

type ParamStyle = Literal["qmark", "numeric", "named", "format", "pyformat", "numeric_dollar"]
"""The DB-API parameter styles PEP 249 defines. A driver accepts exactly one."""

__all__ = [
    "Connection",
    "Cursor",
    "ParamStyle",
    "fetch",
    "parse_pg_array",
    "segment_clause",
    "sql_dialect",
    "table_ref",
    "to_float",
]


def sql_dialect(*, paramstyle: ParamStyle = "pyformat") -> Dialect:
    """A compile-only dialect.

    SQLAlchemy dialects normally carry driver behaviour as well as SQL rendering. This
    package never opens a connection -- the caller hands one in -- so all that is wanted
    is a compiler, and ``DefaultDialect`` is exactly that: ANSI rendering plus a
    parameter style. ``pyformat`` matches psycopg and most warehouse drivers; pass
    ``qmark`` or ``named`` for one that does not.

    Using the vendor dialect instead would pull in that vendor's driver assumptions for
    no gain: every statement this package emits is ANSI plus a CAST.
    """
    return DefaultDialect(paramstyle=paramstyle)


def to_float(value: object) -> float | None:
    """Coerce a catalog value to a float, or ``None`` when it is not a number.

    Catalog columns come back as whatever the driver decided -- ``Decimal`` from one,
    ``str`` from another, ``None`` when the statistic was never collected. ``None`` is
    a real answer here and means "no estimate", which callers must not turn into zero.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


@runtime_checkable
class Cursor(Protocol):
    """The slice of PEP 249's cursor this package uses."""

    def execute(
        self, operation: str, parameters: Mapping[str, object] | Sequence[object] = ...
    ) -> object:
        """Run one statement."""
        ...

    def fetchall(self) -> Sequence[Sequence[object]]:
        """Every row of the result."""
        ...

    def close(self) -> None:
        """Release the cursor."""
        ...


@runtime_checkable
class Connection(Protocol):
    """The slice of PEP 249's connection this package uses."""

    def cursor(self) -> Cursor:
        """A new cursor."""
        ...


def fetch(
    connection: Connection,
    statement: sa.Select[Any],
    *,
    dialect: Dialect,
    source_id: str | None = None,
) -> tuple[tuple[object, ...], ...]:
    """Compile, execute and drain one SELECT.

    Driver exceptions are caught here and nowhere else. A driver message routinely
    quotes the offending row -- ``Key (customer_ssn)=(100-40-1000) already exists`` --
    so the original never propagates; :func:`~godwit_source.errors.sanitise_driver_error`
    keeps it as a tainted value and raises a message that says only what class of
    failure it was.
    """
    compiled = statement.compile(dialect=dialect)
    cursor = connection.cursor()
    try:
        cursor.execute(str(compiled), compiled.params)
        return tuple(tuple(row) for row in cursor.fetchall())
    except Exception as exc:
        raise sanitise_driver_error(exc, source_id=source_id) from None
    finally:
        cursor.close()


def table_ref(namespace: str, name: str, columns: Sequence[str]) -> sa.TableClause:
    """A SQLAlchemy table handle for a customer table.

    ``sa.table`` quotes whatever it is given, so a namespace or column containing a
    quote, a semicolon or a comment marker is rendered as an identifier rather than as
    syntax.
    """
    return sa.table(name, *(sa.column(item) for item in dict.fromkeys(columns)), schema=namespace)


def segment_clause(handle: sa.TableClause, segment: Segment) -> ColumnElement[bool] | None:
    """Translate a ``Segment`` into a WHERE clause, with every value bound.

    Predicate values are revealed here, which is legitimate: this is the data plane and
    selecting rows is what a predicate is for. They become bound parameters, never
    literals, so the revealed value reaches the driver as data and never as SQL text.
    """
    if segment.is_universe:
        return None
    clauses: list[ColumnElement[bool]] = []
    for predicate in segment.predicates:
        column = handle.c[predicate.column.reveal()]
        values: list[ScalarValue] = [value.reveal() for value in predicate.values]
        clauses.append(_predicate_clause(column, predicate.op, values))
    return sa.and_(*clauses)


def _predicate_clause(
    column: ColumnElement[Any], operator: Operator, values: Sequence[ScalarValue]
) -> ColumnElement[bool]:
    match operator:
        case Operator.EQ:
            return column == values[0]
        case Operator.NE:
            return column != values[0]
        case Operator.LT:
            return column < values[0]
        case Operator.LE:
            return column <= values[0]
        case Operator.GT:
            return column > values[0]
        case Operator.GE:
            return column >= values[0]
        case Operator.IN:
            return column.in_(list(values))
        case Operator.NOT_IN:
            return column.notin_(list(values))
        case Operator.IS_NULL:
            return column.is_(None)
        case Operator.NOT_NULL:
            return column.isnot(None)
        case Operator.BETWEEN:
            return column.between(values[0], values[1])
        case Operator.PREFIX:
            if not isinstance(values[0], str):
                raise UnsupportedProbeError("a prefix predicate needs a string value")
            return column.startswith(values[0])


def parse_pg_array(literal: str | None) -> tuple[str, ...]:
    """Parse a Postgres array literal that was cast to ``text``.

    ``pg_stats.most_common_vals`` and ``histogram_bounds`` are ``anyarray``. No driver
    can type an ``anyarray``, so the query casts them to ``text`` and gets back a string
    like ``{a,b,"c,d"}``. This unpicks it: braces, comma separators, double-quoted
    members with backslash escapes, and the bare token ``NULL``.

    The result is row values, every one of them. The caller taints them.
    """
    if literal is None:
        return ()
    text = literal.strip()
    if not text.startswith("{") or not text.endswith("}"):
        return ()
    body = text[1:-1]
    if not body:
        return ()

    members: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            members.append("".join(current))
            current = []
        else:
            current.append(char)
    members.append("".join(current))
    return tuple(members)
