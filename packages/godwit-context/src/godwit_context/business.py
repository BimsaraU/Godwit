"""Business calendars: month end, quarter end, fiscal year end, payroll, settlement.

These explain RECURRING changes. A corporate client's quarterly transfer, a payroll run on
the last business day, a weekly card-scheme settlement -- each produces a spike that
looks anomalous to a detector with a short memory and is completely normal.

Every date here is a business day in the source's own jurisdiction: a month end that
falls on a Saturday is the Friday before, and a month end that falls on Good Friday in
London is the Thursday before. That is why a business calendar is built on top of a
``HolidayCalendar`` rather than on weekdays alone.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final
from zoneinfo import ZoneInfo

from godwit_contracts import SourceId

from godwit_context.events import ContextEvent, ContextScope, ContextType, event_id_for
from godwit_context.holidays import HolidayCalendar

__all__ = [
    "BusinessCalendarSource",
    "BusinessCalendarSpec",
    "Payroll",
    "PayrollRule",
    "SettlementCycle",
]


_SATURDAY: Final = 5


class PayrollRule(StrEnum):
    """When salaries land."""

    LAST_BUSINESS_DAY = "last_business_day"
    SEMI_MONTHLY = "semi_monthly"
    """The 15th and the last day of the month, each rolled back to a business day."""
    BIWEEKLY = "biweekly"
    """Every fourteen days from ``anchor``, rolled back to a business day."""


@dataclass(frozen=True)
class Payroll:
    name: str
    rule: PayrollRule
    anchor: _dt.date | None = None

    def __post_init__(self) -> None:
        if self.rule is PayrollRule.BIWEEKLY and self.anchor is None:
            raise ValueError("a biweekly payroll needs an anchor date")


@dataclass(frozen=True)
class SettlementCycle:
    """A recurring settlement: on given weekdays, or on the n-th business day of a month.

    Weekday settlements that fall on a holiday move to the next business day.
    """

    name: str
    weekdays: tuple[int, ...] = ()
    nth_business_day: int | None = None

    def __post_init__(self) -> None:
        if not self.weekdays and self.nth_business_day is None:
            raise ValueError("a settlement cycle needs weekdays or nth_business_day")


@dataclass(frozen=True)
class BusinessCalendarSpec:
    """One business's calendar, applying to the sources listed."""

    source_ids: tuple[SourceId, ...]
    calendar: HolidayCalendar
    month_end: bool = True
    quarter_end: bool = True
    fiscal_year_end_month: int = 12
    payroll: tuple[Payroll, ...] = ()
    settlements: tuple[SettlementCycle, ...] = ()


class _Days:
    """Business-day arithmetic for one calendar, with the holiday sets computed once."""

    def __init__(self, calendar: HolidayCalendar, years: range) -> None:
        self._closed = {h.day for y in years for h in calendar.holidays(y)}

    def is_open(self, day: _dt.date) -> bool:
        return day.weekday() < _SATURDAY and day not in self._closed

    def on_or_before(self, day: _dt.date) -> _dt.date:
        while not self.is_open(day):
            day -= _dt.timedelta(days=1)
        return day

    def on_or_after(self, day: _dt.date) -> _dt.date:
        while not self.is_open(day):
            day += _dt.timedelta(days=1)
        return day

    def nth_in_month(self, year: int, month: int, n: int) -> _dt.date:
        day = self.on_or_after(_dt.date(year, month, 1))
        for _ in range(n - 1):
            day = self.on_or_after(day + _dt.timedelta(days=1))
        return day


def _last_of_month(year: int, month: int) -> _dt.date:
    return _dt.date(year + month // 12, month % 12 + 1, 1) - _dt.timedelta(days=1)


class BusinessCalendarSource:
    """Context events for month, quarter and fiscal-year ends, payroll and settlement."""

    name: Final = "business_calendar"

    def __init__(self, specs: Sequence[BusinessCalendarSpec]) -> None:
        self._specs = tuple(specs)

    def events(self, *, start: _dt.datetime, end: _dt.datetime) -> tuple[ContextEvent, ...]:
        out: list[ContextEvent] = []
        for spec in self._specs:
            days = _Days(spec.calendar, range(start.year - 1, end.year + 2))
            zone = ZoneInfo(spec.calendar.timezone)
            for day, kind in self._occurrences(spec, days, start.date(), end.date()):
                begin = _dt.datetime.combine(day, _dt.time.min, tzinfo=zone)
                finish = begin + _dt.timedelta(days=1)
                if finish < start or begin > end:
                    continue
                scope = ContextScope(source_ids=tuple(sorted(spec.source_ids)))
                key = ",".join(scope.source_ids)
                out.append(
                    ContextEvent(
                        event_id=event_id_for(self.name, kind, day.isoformat(), key),
                        context_type=ContextType.BUSINESS_CALENDAR,
                        kind=kind,
                        origin=self.name,
                        start=begin,
                        end=finish,
                        scope=scope,
                    )
                )
        return tuple(sorted(out, key=lambda e: (e.start, e.event_id)))

    @staticmethod
    def _occurrences(
        spec: BusinessCalendarSpec, days: _Days, first: _dt.date, last: _dt.date
    ) -> list[tuple[_dt.date, str]]:
        out: list[tuple[_dt.date, str]] = []
        fy = spec.fiscal_year_end_month
        quarter_months = {(fy - 1 - 3 * q) % 12 + 1 for q in range(4)}
        month = _dt.date(first.year, first.month, 1) - _dt.timedelta(days=1)
        month = _dt.date(month.year, month.month, 1)
        while month <= last + _dt.timedelta(days=31):
            y, m = month.year, month.month
            month_end = days.on_or_before(_last_of_month(y, m))
            if spec.month_end:
                out.append((month_end, "business.month_end"))
            if spec.quarter_end and m in quarter_months:
                out.append((month_end, "business.quarter_end"))
            if m == fy:
                out.append((month_end, "business.fiscal_year_end"))
            for payroll in spec.payroll:
                kind = f"business.payroll.{payroll.name}"
                if payroll.rule is PayrollRule.LAST_BUSINESS_DAY:
                    out.append((month_end, kind))
                elif payroll.rule is PayrollRule.SEMI_MONTHLY:
                    out.append((days.on_or_before(_dt.date(y, m, 15)), kind))
                    out.append((month_end, kind))
            for cycle in spec.settlements:
                if cycle.nth_business_day is not None:
                    day = days.nth_in_month(y, m, cycle.nth_business_day)
                    out.append((day, f"business.settlement.{cycle.name}"))
            month = _dt.date(y + m // 12, m % 12 + 1, 1)
        day = first - _dt.timedelta(days=1)
        while day <= last + _dt.timedelta(days=1):
            for cycle in spec.settlements:
                if day.weekday() in cycle.weekdays:
                    out.append((days.on_or_after(day), f"business.settlement.{cycle.name}"))
            for payroll in spec.payroll:
                anchor = payroll.anchor
                if (
                    payroll.rule is PayrollRule.BIWEEKLY
                    and anchor
                    and (day - anchor).days % 14 == 0
                ):
                    out.append((days.on_or_before(day), f"business.payroll.{payroll.name}"))
            day += _dt.timedelta(days=1)
        return sorted(set(out))
