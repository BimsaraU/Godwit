"""Column types: UTC instants, JSON that becomes JSONB, and the pgvector embedding.

Three dialect-specific things are wrapped here so that the schema is written once.
Postgres 16 with pgvector is the deployment target; SQLite is what the test suite runs
against, because ``make test`` must work on a clean checkout with no Docker, and a
schema that can only be exercised with a container is a schema nobody exercises.

The differences that matter are exactly three, and each is handled by a
``TypeDecorator`` rather than by a branch at every call site:

``UtcInstant``
    SQLite has no timezone-aware type and hands back naive datetimes. Universal rule 5
    says time is injected and always tz-aware; a naive datetime coming *out* of the
    store would silently reintroduce local time. Every read is re-stamped UTC.

``Json``
    JSONB on Postgres for the operator support and the GIN indexes; plain JSON
    elsewhere.

``Embedding``
    ``vector(256)`` on Postgres, so the ivfflat index and the distance operators work;
    a JSON array elsewhere, where similarity is computed in Python by
    :func:`godwit_store.signature.cosine`.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence
from typing import Any, Final

from sqlalchemy import JSON, DateTime, Dialect, types
from sqlalchemy.dialects.postgresql import JSONB

from godwit_store.signature import EMBEDDING_DIM

__all__ = ["Embedding", "Json", "UtcInstant", "is_postgres"]

_POSTGRES: Final[str] = "postgresql"


def is_postgres(dialect: Dialect) -> bool:
    """True when we are talking to the real target rather than the test dialect."""
    return dialect.name == _POSTGRES


class UtcInstant(types.TypeDecorator[_dt.datetime]):
    """A tz-aware instant, stored UTC and returned UTC on every dialect.

    Refuses a naive datetime on the way in for the same reason
    ``godwit_contracts.require_utc`` does: two agents in two timezones would otherwise
    produce two different lineages for the same run.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(
        self, value: _dt.datetime | None, _dialect: Dialect
    ) -> _dt.datetime | None:
        """Normalise to UTC before storing, refusing naive input."""
        if value is None:
            return None
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError("naive datetime is not allowed; supply a tz-aware instant")
        return value.astimezone(_dt.UTC)

    def process_result_value(
        self, value: _dt.datetime | None, _dialect: Dialect
    ) -> _dt.datetime | None:
        """Re-stamp UTC on the way out, because SQLite drops the offset."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=_dt.UTC)
        return value.astimezone(_dt.UTC)


class Json(types.TypeDecorator[Any]):
    """JSONB on Postgres, JSON elsewhere.

    Used for every tainted ``_value`` column. The value inside is customer data; the
    column name ends in ``_value`` by convention and the ``_safe`` views omit every one
    of them, so a query written against a view cannot reach one by accident.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> types.TypeEngine[Any]:
        """JSONB where it exists."""
        if is_postgres(dialect):
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class Embedding(types.TypeDecorator[tuple[float, ...]]):
    """``vector(256)`` on Postgres, a JSON array elsewhere.

    The vector is computed over the *redacted* structural rendering -- see
    :mod:`godwit_store.signature`. It still carries customer column names, so it is
    ``SCHEMA_NAME``-class and sits outside the ``_safe`` views alongside the tainted
    columns.
    """

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> types.TypeEngine[Any]:
        """Hand Postgres a real vector column so pgvector can index it."""
        if is_postgres(dialect):
            from pgvector.sqlalchemy import Vector  # noqa: PLC0415

            return dialect.type_descriptor(Vector(EMBEDDING_DIM))
        return dialect.type_descriptor(JSON())

    def process_bind_param(
        self, value: Sequence[float] | None, _dialect: Dialect
    ) -> list[float] | None:
        """Normalise tuples to lists; both dialects want a sequence."""
        if value is None:
            return None
        return [float(component) for component in value]

    def process_result_value(
        self, value: Sequence[float] | None, _dialect: Dialect
    ) -> tuple[float, ...] | None:
        """Return an immutable vector, so a caller cannot mutate a cached row."""
        if value is None:
            return None
        return tuple(float(component) for component in value)
