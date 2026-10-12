"""``@feature``: a custom feature transform for the feature factory (A11). **DATA PLANE.**

The rule this module exists to make impossible to skip: **a feature may only read rows
from before the event it describes.** A feature computed over rows that arrived after
the event knows the future, and a model trained on it looks excellent in evaluation and
fails on the first day it is deployed.

So a feature plugin does not write a query. It writes one *aggregate* --
``avg({amount})``, ``count(*)``, ``count(DISTINCT {device})`` -- and declares its window:
``LOOKBACK`` (how far back it reads, mandatory and positive) and ``EMBARGO`` (the gap
before the event it must not read, for late-arriving data). The SDK builds the
point-in-time window around the aggregate, for each entity at that entity's own event
time, in :meth:`FeatureBase.evaluate`, and records the same window in the contract's
:class:`~godwit_contracts.PointInTimeRule` on the :class:`~godwit_contracts.FeatureSpec`
it produces. There is no way to declare a feature without one.

The aggregate is checked at registration: it must be valid DuckDB over the window's rows,
deterministic, and contain no string literal (a literal drawn from data belongs in a
segment, where it is tainted) and no subquery (a subquery can read outside the window).
The conformance kit then checks the property directly: it changes every row on or after
each event's cut-off and asserts that no feature value moves.

``INPUTS`` names the *roles* the aggregate reads (``amount``), not customer columns. The
customer's column names are bound when a spec is built, so a plugin never embeds one.
"""

from __future__ import annotations

import abc
import datetime as _dt
import re
from collections.abc import Callable, Mapping
from typing import Any, ClassVar, Final

import duckdb
import pyarrow as pa
from godwit_contracts.common import SourceId, Version
from godwit_contracts.features import FeatureKind, FeatureSpec, FillPolicy, PointInTimeRule
from godwit_contracts.source import LogicalType
from godwit_contracts.taint import schema_name

from godwit_sdk.capabilities import Capabilities, ResourceLimits
from godwit_sdk.plugin import (
    DEFAULT_REQUIREMENT,
    PluginBase,
    PluginInfo,
    PluginKind,
    decorator_for,
    require_class_vars,
)

__all__ = ["EVENT_TIME", "FEATURE_VALUE", "FeatureBase", "feature"]

EVENT_TIME: Final[str] = "event_time"
"""The column of the events table :meth:`FeatureBase.evaluate` reads each event's time from."""

FEATURE_VALUE: Final[str] = "value"
"""The column :meth:`FeatureBase.evaluate` writes the feature into."""

_DECLARATIONS: Final[tuple[str, ...]] = ("DTYPE", "INPUTS", "LOOKBACK")
_ROLE: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]{0,31}\Z")
_FORBIDDEN: Final[re.Pattern[str]] = re.compile(
    r"'|;|--|/\*|\b(select|from|join|with|union|attach|copy|pragma|install|load)\b",
    re.IGNORECASE,
)
_ROW_ORDER: Final[str] = "__godwit_event_row"


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


class FeatureBase(PluginBase, abc.ABC):
    """Base class for ``@feature`` plugins.

    Declare ``DTYPE`` (``LogicalType``), ``INPUTS`` (roles, e.g. ``("amount",)``) and
    ``LOOKBACK`` (a positive ``timedelta``); optionally ``EMBARGO``, ``LABEL_LAG``,
    ``FILL`` and ``KIND``. Implement :meth:`aggregate`.
    """

    SDK_METHODS = ("rule", "spec", "evaluate")

    KIND: ClassVar[FeatureKind] = FeatureKind.TIME_WINDOW
    DTYPE: ClassVar[LogicalType]
    INPUTS: ClassVar[tuple[str, ...]]
    LOOKBACK: ClassVar[_dt.timedelta]
    EMBARGO: ClassVar[_dt.timedelta] = _dt.timedelta(0)
    LABEL_LAG: ClassVar[_dt.timedelta] = _dt.timedelta(0)
    FILL: ClassVar[FillPolicy] = FillPolicy.NULL

    @abc.abstractmethod
    def aggregate(self, columns: Mapping[str, str]) -> str:
        """One DuckDB aggregate over the window's rows.

        ``columns`` maps each role in ``INPUTS`` to an already-quoted column identifier;
        use them and nothing else: ``f"avg({columns['amount']})"``.
        """

    def rule(self, timestamp_column: str) -> PointInTimeRule:
        """The contract's point-in-time rule for this feature over ``timestamp_column``."""
        return PointInTimeRule(
            timestamp_column=schema_name(timestamp_column),
            max_lookback=self.LOOKBACK,
            embargo=self.EMBARGO,
            label_lag_allowance=self.LABEL_LAG,
        )

    def spec(
        self,
        *,
        feature_id: str,
        source_id: str,
        entity_key: str,
        timestamp_column: str,
        columns: Mapping[str, str],
        spec_version: Version = 1,
    ) -> FeatureSpec:
        """Bind the roles to customer columns and produce the contract ``FeatureSpec``."""
        info = self.plugin_info()
        quoted = {role: _quote(columns[role]) for role in self.INPUTS}
        expression = self.runner.call("aggregate", lambda: self.aggregate(quoted))
        bound = ",".join(columns[role] for role in self.INPUTS)
        return FeatureSpec(
            feature_id=feature_id,
            name=schema_name(f"{info.qualified_name}({bound})", source_id=source_id),
            kind=self.KIND,
            spec_version=spec_version,
            source_id=SourceId(source_id),
            entity_key=schema_name(entity_key, source_id=source_id),
            inputs=tuple(schema_name(columns[role], source_id=source_id) for role in self.INPUTS),
            expression=expression,
            dtype=self.DTYPE,
            fill_policy=self.FILL,
            point_in_time=self.rule(timestamp_column),
        )

    def evaluate(self, spec: FeatureSpec, *, events: pa.Table, history: pa.Table) -> pa.Table:
        """Compute ``spec`` for each event, point-in-time correct. Data plane.

        ``events`` has the entity key column and ``event_time``; ``history`` has the
        entity key, the timestamp column and the inputs. Each event gets the aggregate of
        its own entity's rows in ``[event_time - LOOKBACK, event_time - EMBARGO)`` -- the
        end inclusive only if the rule says so -- in a new ``value`` column. Rows come
        back in the order of ``events``.
        """
        rule = spec.point_in_time
        entity = _quote(spec.entity_key.reveal())
        stamp = _quote(rule.timestamp_column.reveal())
        upper = "<=" if rule.inclusive_end else "<"
        lookback = int(rule.max_lookback / _dt.timedelta(microseconds=1))
        embargo = int(rule.embargo / _dt.timedelta(microseconds=1))
        value = f"({spec.expression})"
        if spec.fill_policy is FillPolicy.ZERO:
            value = f"coalesce({value}, 0)"
        numbered = events.append_column(_ROW_ORDER, pa.array(range(events.num_rows), pa.int64()))
        at = f"e.{_quote(EVENT_TIME)}"
        window = [
            f"h.{entity} = e.{entity}",
            f"h.{stamp} >= {at} - to_microseconds({lookback})",
            f"h.{stamp} {upper} {at} - to_microseconds({embargo})",
        ]
        parts = [
            "SELECT e.*, (SELECT",
            value,
            "FROM godwit_history AS h WHERE",
            " AND ".join(window),
            ") AS",
            _quote(FEATURE_VALUE),
            "FROM godwit_events AS e ORDER BY",
            f"e.{_quote(_ROW_ORDER)}",
        ]
        sql = " ".join(parts)
        with duckdb.connect(":memory:") as connection:
            connection.register("godwit_events", numbered)
            connection.register("godwit_history", history)
            result = connection.execute(sql).to_arrow_table()
        return result.drop_columns([_ROW_ORDER])


def _probe_tables(cls: type[FeatureBase]) -> tuple[pa.Table, pa.Table]:
    epoch = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
    step = cls.LOOKBACK / 4 if _dt.timedelta(0) < cls.LOOKBACK else _dt.timedelta(hours=1)
    history: dict[str, list[Any]] = {
        "entity": ["e1", "e1", "e2", "e1"],
        "ts": [epoch - step * 3, epoch - step, epoch - step * 2, epoch + step],
    }
    for role in cls.INPUTS:
        history[role] = [1.0, 2.0, 3.0, 4.0]
    events = pa.table({"entity": ["e1", "e2"], EVENT_TIME: [epoch, epoch]})
    return events, pa.table(history)


def _feature_problems(cls: type[FeatureBase]) -> list[str]:
    problems: list[str] = []
    declared: dict[str, object] = {
        name: getattr(cls, name) for name in ("KIND", "DTYPE", "FILL", "INPUTS")
    }
    if not isinstance(declared["KIND"], FeatureKind):
        problems.append("KIND must be a godwit_contracts.FeatureKind")
    if not isinstance(declared["DTYPE"], LogicalType):
        problems.append("DTYPE must be a godwit_contracts.LogicalType")
    if not isinstance(declared["FILL"], FillPolicy):
        problems.append("FILL must be a godwit_contracts.FillPolicy")
    inputs = declared["INPUTS"]
    if (
        not isinstance(inputs, tuple)
        or not inputs
        or not all(isinstance(r, str) and _ROLE.match(r) for r in inputs)
    ):
        problems.append("INPUTS must be a non-empty tuple of lowercase role names")
    for label in ("LOOKBACK", "EMBARGO", "LABEL_LAG"):
        if not isinstance(getattr(cls, label), _dt.timedelta):
            problems.append(f"{label} must be a datetime.timedelta")
    if problems:
        return problems
    if _dt.timedelta(0) >= cls.LOOKBACK:
        problems.append(
            "LOOKBACK must be positive: a feature with no lookback bound is not reproducible"
        )
    if _dt.timedelta(0) > cls.EMBARGO or _dt.timedelta(0) > cls.LABEL_LAG:
        problems.append("EMBARGO and LABEL_LAG cannot be negative")
    elif cls.EMBARGO >= cls.LOOKBACK:
        problems.append("EMBARGO is at least LOOKBACK: the window would contain no rows")
    return problems


def _aggregate_problems(cls: type[FeatureBase]) -> list[str]:
    plugin = cls()
    bindings = {role: _quote(role) for role in cls.INPUTS}
    try:
        first = plugin.runner.call("aggregate", lambda: plugin.aggregate(bindings))
        second = plugin.runner.call("aggregate", lambda: plugin.aggregate(bindings))
    except Exception as exc:  # report the type only: the message is the plugin's text
        return [f"aggregate() raised {type(exc).__name__}"]
    if not isinstance(first, str) or not first.strip():
        return ["aggregate() must return a non-empty string"]
    if first != second:
        return ["aggregate() is not deterministic: two calls returned different SQL"]
    if _FORBIDDEN.search(first):
        return [
            (
                "aggregate() must be one aggregate expression with no string literal, "
                "comment, statement separator or subquery: a literal belongs in a segment, "
                "and a subquery can read outside the point-in-time window"
            )
        ]
    events, history = _probe_tables(cls)
    spec = plugin.spec(
        feature_id="sdk_registration_check",
        source_id="src_sdk_registration",
        entity_key="entity",
        timestamp_column="ts",
        columns={role: role for role in cls.INPUTS},
    )
    try:
        plugin.evaluate(spec, events=events, history=history)
    except duckdb.Error as exc:
        return [f"aggregate() is not valid DuckDB over the window ({type(exc).__name__})"]
    return []


def _registration_problems(cls: type[FeatureBase], info: PluginInfo) -> list[str]:
    problems = require_class_vars(cls, _DECLARATIONS)
    if problems:
        return problems
    problems = _feature_problems(cls)
    if problems:
        return problems
    # The aggregate check calls the plugin through its runner, which needs its identity:
    # stamp it for the check, and take the stamp back off if the check fails.
    cls.__godwit_plugin__ = info
    problems = _aggregate_problems(cls)
    if problems:
        type.__delattr__(cls, "__godwit_plugin__")
    return problems


def feature[F: FeatureBase](
    *,
    name: str,
    namespace: str,
    version: str,
    summary: str = "",
    requires_sdk: str = DEFAULT_REQUIREMENT,
    capabilities: Capabilities | None = None,
    limits: ResourceLimits | None = None,
) -> Callable[[type[F]], type[F]]:
    """Register a :class:`FeatureBase` subclass. The point-in-time window is mandatory."""

    return decorator_for(
        PluginKind.FEATURE,
        FeatureBase,
        _registration_problems,
        name=name,
        namespace=namespace,
        version=version,
        summary=summary,
        requires_sdk=requires_sdk,
        capabilities=capabilities,
        limits=limits,
    )
