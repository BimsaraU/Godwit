"""Business calendars roll to business days in the source's own jurisdiction."""

from __future__ import annotations

import datetime as _dt
from typing import Any

import pytest
from godwit_context import (
    CALENDARS,
    BusinessCalendarSource,
    BusinessCalendarSpec,
    Payroll,
    PayrollRule,
    SettlementCycle,
)
from godwit_contracts import SourceId

D = _dt.date


def _kinds(spec: BusinessCalendarSpec, first: _dt.date, last: _dt.date) -> dict[str, set[_dt.date]]:
    source = BusinessCalendarSource([spec])
    zone_start = _dt.datetime.combine(first, _dt.time(), tzinfo=_dt.UTC)
    zone_end = _dt.datetime.combine(last, _dt.time(23), tzinfo=_dt.UTC)
    out: dict[str, set[_dt.date]] = {}
    for e in source.events(start=zone_start, end=zone_end):
        local = e.start.astimezone(_dt.timezone(_dt.timedelta(hours=1))).date()
        out.setdefault(e.kind, set()).add(local)
    return out


def _spec(**kwargs: Any) -> BusinessCalendarSpec:
    return BusinessCalendarSpec(
        source_ids=(SourceId("src_fin"),),
        calendar=CALENDARS["GB-ENG"],
        **kwargs,
    )


def test_month_end_rolls_back_over_weekends_and_holidays() -> None:
    kinds = _kinds(_spec(), D(2024, 3, 1), D(2024, 6, 30))
    # 31 Mar 2024 is Easter Sunday, 29 Mar is Good Friday: month end is Thursday 28th.
    assert D(2024, 3, 28) in kinds["business.month_end"]
    assert D(2024, 3, 28) in kinds["business.quarter_end"]
    # 30 Jun 2024 is a Sunday.
    assert D(2024, 6, 28) in kinds["business.month_end"]


def test_fiscal_year_and_quarters_follow_the_fiscal_month() -> None:
    kinds = _kinds(_spec(fiscal_year_end_month=3), D(2024, 1, 1), D(2024, 12, 31))
    assert kinds["business.fiscal_year_end"] == {D(2024, 3, 28)}
    quarter_months = {d.month for d in kinds["business.quarter_end"]}
    assert quarter_months == {3, 6, 9, 12}


def test_semi_monthly_payroll_and_settlement() -> None:
    spec = _spec(
        month_end=False,
        quarter_end=False,
        payroll=(Payroll("staff", PayrollRule.SEMI_MONTHLY),),
        settlements=(
            SettlementCycle("scheme", weekdays=(0,)),
            SettlementCycle("monthly", nth_business_day=2),
        ),
    )
    kinds = _kinds(spec, D(2024, 6, 1), D(2024, 6, 30))
    assert kinds["business.payroll.staff"] >= {D(2024, 6, 14), D(2024, 6, 28)}  # 15th is Sat
    assert D(2024, 6, 4) in kinds["business.settlement.monthly"]
    assert {D(2024, 6, 3), D(2024, 6, 10)} <= kinds["business.settlement.scheme"]


def test_settlement_on_a_holiday_moves_to_the_next_business_day() -> None:
    spec = _spec(month_end=False, quarter_end=False, settlements=(SettlementCycle("s", (0,)),))
    kinds = _kinds(spec, D(2024, 5, 20), D(2024, 5, 31))
    assert D(2024, 5, 28) in kinds["business.settlement.s"]  # 27 May: spring bank holiday
    assert D(2024, 5, 27) not in kinds["business.settlement.s"]


def test_biweekly_payroll_needs_an_anchor() -> None:
    with pytest.raises(ValueError, match="anchor"):
        Payroll("p", PayrollRule.BIWEEKLY)
    kinds = _kinds(
        _spec(
            month_end=False,
            quarter_end=False,
            payroll=(Payroll("p", PayrollRule.BIWEEKLY, anchor=D(2024, 1, 5)),),
        ),
        D(2024, 1, 1),
        D(2024, 2, 10),
    )
    assert kinds["business.payroll.p"] == {D(2024, 1, 5), D(2024, 1, 19), D(2024, 2, 2)}
