"""Turning a ``ProbeSpec`` into pushdown SQL, and its result into Arrow. Data plane.

Shared by the Postgres and warehouse adapters, because the two differ in exactly two
places -- whether an approximate aggregate is available, and what it is called -- and
nowhere else worth duplicating.

**Never ``SELECT *``. Never a row.** Every statement here is an aggregate over named
columns. The shapes the database is asked for are counts, extremes, quantiles and
grouped tallies. A grouped tally does return values, which is the point of a heavy
hitter and is why those results are tainted ``COUNT_MIN_HEAVY_HITTER`` or
``CATEGORY_HISTOGRAM`` by the adapter that asked for them.

THE RESULT CONVENTION
---------------------
Every probe result becomes the same shape: a population, plus either ``None`` or an
Arrow table with a ``value`` column and a ``count`` column. One rule, so the sketch
seam does not need a branch per probe kind:

===================  ==========================================================
``row_count``        ``None``; the population is the answer.
``distinct_count``   ``None``; the population is the answer. Exact, not a sketch.
``null_rate``        two rows: ``(True, nulls)`` and ``(False, non-nulls)``.
``column_bounds``    two rows: the minimum and the maximum, count 1 each.
``freshness``        one row: the maximum, count 1.
``quantiles``        one row per requested quantile, count 1 each.
``category_histogram``, ``heavy_hitters``
                     one row per group: the value and how many rows carried it.
===================  ==========================================================
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import pyarrow as pa
import sqlalchemy as sa
from godwit_contracts.probe import ProbeKind
from godwit_contracts.taint import Acquisition
from sqlalchemy.sql.elements import ColumnElement

from godwit_source.errors import UnsupportedProbeError

__all__ = [
    "APPROXIMATE_TIER",
    "DEFAULT_TOP_K",
    "EXACT_TIER",
    "SqlProfile",
    "aggregate_statement",
    "probe_acquisition",
    "result_to_values",
]


def probe_acquisition(kind: ProbeKind) -> Acquisition:
    """How a probe's output was obtained, for the provenance on its sketch.

    The three kinds that return observed values say so. Labelling a heavy-hitter probe
    as a computed statistic would let an identifier column's top values through the
    gate as though they were numbers -- and on an identifier column the heavy hitters
    ARE the PII.
    """
    match kind:
        case ProbeKind.HEAVY_HITTERS:
            return Acquisition.COUNT_MIN_HEAVY_HITTER
        case ProbeKind.CATEGORY_HISTOGRAM:
            return Acquisition.CATEGORY_HISTOGRAM
        case ProbeKind.QUANTILES:
            return Acquisition.QUANTILE
        case ProbeKind.COLUMN_BOUNDS | ProbeKind.FRESHNESS:
            return Acquisition.SEGMENT_PREDICATE
        case _:
            return Acquisition.COMPUTED_STATISTIC


DEFAULT_TOP_K: Final[int] = 50
"""Groups returned by a histogram or heavy-hitter probe when the spec does not say.

Deliberately small. On an identifier column the groups *are* the identifiers, so the
number of rows this returns is the number of customer values the probe pulls back into
the data plane, and a default of "all of them" would be a scan wearing a GROUP BY.
"""

DEFAULT_QUANTILES: Final[tuple[float, ...]] = (0.01, 0.25, 0.5, 0.75, 0.99)


@dataclass(frozen=True, slots=True)
class SqlProfile:
    """What a backend can do, in the two places backends differ.

    ``None`` means "no approximate version; use the exact one". That is a correctness
    choice, not a performance one: an adapter that silently substituted a different
    aggregate would make two snapshots of the same table incomparable.
    """

    approx_distinct: str | None = None
    approx_quantile: str | None = None


EXACT_TIER: Final[SqlProfile] = SqlProfile()
"""Postgres: exact ``count(DISTINCT ...)`` and ``percentile_cont``."""

APPROXIMATE_TIER: Final[SqlProfile] = SqlProfile(
    approx_distinct="approx_count_distinct", approx_quantile="approx_percentile"
)
"""Snowflake-style names. BigQuery's differ; see ``WarehouseSqlAdapter``."""


def aggregate_statement(
    *,
    handle: sa.TableClause,
    kind: ProbeKind,
    columns: Sequence[str],
    params: Mapping[str, int | float | str | bool],
    where: ColumnElement[bool] | None,
    profile: SqlProfile,
) -> sa.Select[Any]:
    """Build the one statement that answers ``kind``.

    Raises :class:`~godwit_source.errors.UnsupportedProbeError` for a kind no SQL
    backend can answer in one pushdown -- graph degree and join cardinality need a join
    plan this adapter does not build. Refusing is better than issuing something that
    looks like an answer.
    """
    total = sa.func.count().label("population")
    if kind is ProbeKind.ROW_COUNT:
        return _maybe_where(sa.select(total).select_from(handle), where)

    column = _single_column(handle, columns, kind)

    match kind:
        case ProbeKind.NULL_RATE:
            return _maybe_where(
                sa.select(total, sa.func.count(column).label("non_null")).select_from(handle),
                where,
            )
        case ProbeKind.DISTINCT_COUNT:
            distinct = (
                sa.func.count(sa.distinct(column))
                if profile.approx_distinct is None
                else getattr(sa.func, profile.approx_distinct)(column)
            )
            return _maybe_where(sa.select(distinct.label("population")).select_from(handle), where)
        case ProbeKind.COLUMN_BOUNDS:
            return _maybe_where(
                sa.select(
                    sa.func.min(column).label("lower"),
                    sa.func.max(column).label("upper"),
                    total,
                ).select_from(handle),
                where,
            )
        case ProbeKind.FRESHNESS:
            return _maybe_where(
                sa.select(sa.func.max(column).label("upper"), total).select_from(handle), where
            )
        case ProbeKind.QUANTILES:
            return _maybe_where(
                sa.select(*_quantile_columns(column, params, profile), total).select_from(handle),
                where,
            )
        case ProbeKind.CATEGORY_HISTOGRAM | ProbeKind.HEAVY_HITTERS:
            tally = sa.func.count().label("count")
            statement = (
                sa.select(column.label("value"), tally)
                .select_from(handle)
                .group_by(column)
                .order_by(sa.desc(tally), column)
                .limit(_top_k(params))
            )
            return _maybe_where(statement, where)
        case _:
            raise UnsupportedProbeError(f"no single-statement pushdown for a {kind} probe")


def _maybe_where(statement: sa.Select[Any], where: ColumnElement[bool] | None) -> sa.Select[Any]:
    return statement if where is None else statement.where(where)


def _single_column(
    handle: sa.TableClause, columns: Sequence[str], kind: ProbeKind
) -> ColumnElement[Any]:
    if len(columns) != 1:
        raise UnsupportedProbeError(f"a {kind} probe measures exactly one column")
    return handle.c[columns[0]]


def _top_k(params: Mapping[str, int | float | str | bool]) -> int:
    raw = params.get("top_k", DEFAULT_TOP_K)
    if not isinstance(raw, int) or isinstance(raw, bool) or raw <= 0:
        raise UnsupportedProbeError("top_k must be a positive integer")
    return raw


def _quantiles(params: Mapping[str, int | float | str | bool]) -> tuple[float, ...]:
    raw = params.get("quantiles")
    if raw is None:
        return DEFAULT_QUANTILES
    if not isinstance(raw, str):
        raise UnsupportedProbeError("quantiles must be a comma-separated string of fractions")
    try:
        parsed = tuple(float(part) for part in raw.split(",") if part.strip())
    except ValueError:
        raise UnsupportedProbeError(
            "quantiles must be a comma-separated string of fractions"
        ) from None
    if not parsed or any(not 0.0 <= value <= 1.0 for value in parsed):
        raise UnsupportedProbeError("every quantile must lie in [0, 1]")
    return parsed


def _quantile_columns(
    column: ColumnElement[Any],
    params: Mapping[str, int | float | str | bool],
    profile: SqlProfile,
) -> list[ColumnElement[Any]]:
    """One labelled expression per requested quantile.

    Labels are positional (``q0``, ``q1``) rather than named after the fraction, so a
    quantile of 0.5 and one of 0.50 cannot produce two columns with the same name.
    """
    fractions = _quantiles(params)
    if profile.approx_quantile is not None:
        return [
            getattr(sa.func, profile.approx_quantile)(column, fraction).label(f"q{index}")
            for index, fraction in enumerate(fractions)
        ]
    return [
        sa.func.percentile_cont(fraction).within_group(column.asc()).label(f"q{index}")
        for index, fraction in enumerate(fractions)
    ]


def result_to_values(kind: ProbeKind, rows: Sequence[Sequence[Any]]) -> tuple[int, pa.Table | None]:
    """Reshape a probe's result set into ``(population, value/count table)``.

    See the convention table in the module docstring. An empty result -- a segment that
    matched nothing -- is a population of zero and no values, which is a real answer and
    not an error.
    """
    if not rows:
        return 0, None
    first = list(rows[0])

    match kind:
        case ProbeKind.ROW_COUNT | ProbeKind.DISTINCT_COUNT:
            return _as_int(first[0]), None
        case ProbeKind.NULL_RATE:
            population = _as_int(first[0])
            non_null = _as_int(first[1])
            return population, _value_table([True, False], [population - non_null, non_null])
        case ProbeKind.COLUMN_BOUNDS:
            return _as_int(first[2]), _value_table([first[0], first[1]], [1, 1])
        case ProbeKind.FRESHNESS:
            return _as_int(first[1]), _value_table([first[0]], [1])
        case ProbeKind.QUANTILES:
            quantiles = first[:-1]
            return _as_int(first[-1]), _value_table(list(quantiles), [1] * len(quantiles))
        case ProbeKind.CATEGORY_HISTOGRAM | ProbeKind.HEAVY_HITTERS:
            pairs = [tuple(row) for row in rows]
            values = [pair[0] for pair in pairs]
            counts = [_as_int(pair[1]) for pair in pairs]
            return sum(counts), _value_table(values, counts)
        case _:
            raise UnsupportedProbeError(f"no result convention for a {kind} probe")


def _value_table(values: Sequence[object], counts: Sequence[int]) -> pa.Table:
    return pa.table({"value": pa.array(list(values)), "count": pa.array(list(counts))})


def _as_int(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float):
        return int(value)
    return int(float(str(value)))
