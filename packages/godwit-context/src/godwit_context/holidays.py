"""Public holiday calendars, as rules rather than as a downloaded list.

Holidays are a classic source of embarrassing false positives: a volume drop on Easter
Monday in Frankfurt is not fraud, and neither is a spike on the Friday before a US
Independence Day that fell on a Saturday. Getting this wrong for one jurisdiction trains
that jurisdiction's analysts to ignore the product.

Every holiday is a ``HolidayRule``: a date rule (fixed, n-th weekday, Easter-relative in
either the Western or the Orthodox computus) plus an observance rule (what happens when
it falls on a weekend). A calendar may inherit from a parent, so a region is its country
plus its own extras. One-off holidays (a jubilee, a state funeral) and one-off moves (the
UK's early-May bank holiday moved to VE Day in 2020) are data, not code.

When an observance moves a holiday, BOTH days are emitted: the actual day (shops closed,
behaviour changes) and the observed day (banks closed, settlement shifts). Either can
explain a change, and they are different explanations.

Built-in jurisdictions, each tested against published dates in ``tests/test_holidays.py``:

    US        US federal holidays (OPM rules: Saturday -> Friday, Sunday -> Monday)
    GB-ENG    England and Wales bank holidays (substitute days roll to the next free
              weekday). GB-WLS is an alias.
    GB-SCT    Scotland
    DE        Germany, nationwide
    DE-BY     Bavaria (DE plus Epiphany, Corpus Christi, Assumption, All Saints)
    DE-BE     Berlin (DE plus International Women's Day from 2019)
    FR        France, metropolitan
    FR-57/67/68  Alsace-Moselle (FR plus Good Friday and St Stephen's Day)
    GR        Greece (Orthodox Easter)

Lunar and observation-based calendars (Eid, Diwali, Lunar New Year) are not computable
from rules a regulator would accept; supply them as explicit dates through
``HolidayCalendar.one_off`` or a ``StaticSource``.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final
from zoneinfo import ZoneInfo

from godwit_contracts import SourceId

from godwit_context.events import ContextEvent, ContextScope, ContextType, event_id_for

__all__ = [
    "CALENDARS",
    "EasterOffset",
    "Fixed",
    "Holiday",
    "HolidayCalendar",
    "HolidayRule",
    "HolidaySource",
    "NthWeekday",
    "Observance",
    "easter",
    "orthodox_easter",
]

MON, TUE, WED, THU, FRI, SAT, SUN = range(7)


def easter(year: int) -> _dt.date:
    """Western (Gregorian) Easter Sunday. Anonymous Gregorian algorithm (Meeus)."""
    a, b, c = year % 19, year // 100, year % 100
    d, e = b // 4, b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = c // 4, c % 4
    el = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * el) // 451
    month, day = divmod(h + el - 7 * m + 114, 31)
    return _dt.date(year, month, day + 1)


def orthodox_easter(year: int) -> _dt.date:
    """Orthodox Easter Sunday, as a Gregorian date. Meeus' Julian algorithm."""
    a, b, c = year % 4, year % 7, year % 19
    d = (19 * c + 15) % 30
    e = (2 * a + 4 * b - d + 34) % 7
    month, day = divmod(d + e + 114, 31)
    julian_offset = year // 100 - year // 400 - 2
    return _dt.date(year, month, day + 1) + _dt.timedelta(days=julian_offset)


@dataclass(frozen=True)
class Fixed:
    """The same calendar date every year."""

    month: int
    day: int

    def on(self, year: int) -> _dt.date:
        return _dt.date(year, self.month, self.day)


@dataclass(frozen=True)
class NthWeekday:
    """The n-th given weekday of a month; ``n = -1`` is the last one."""

    month: int
    weekday: int
    n: int

    def on(self, year: int) -> _dt.date:
        if self.n > 0:
            first = _dt.date(year, self.month, 1)
            shift = (self.weekday - first.weekday()) % 7
            return first + _dt.timedelta(days=shift + 7 * (self.n - 1))
        following = _dt.date(year + self.month // 12, self.month % 12 + 1, 1)
        last = following - _dt.timedelta(days=1)
        return last - _dt.timedelta(days=(last.weekday() - self.weekday) % 7)


@dataclass(frozen=True)
class EasterOffset:
    """Days relative to Easter Sunday, Western or Orthodox."""

    days: int
    orthodox: bool = False

    def on(self, year: int) -> _dt.date:
        base = orthodox_easter(year) if self.orthodox else easter(year)
        return base + _dt.timedelta(days=self.days)


type DateRule = Fixed | NthWeekday | EasterOffset


class Observance(StrEnum):
    """What happens when a holiday falls on a weekend."""

    ACTUAL = "actual"
    """Nothing. Germany and France do not move holidays."""

    NEAREST_WEEKDAY = "nearest_weekday"
    """Saturday is observed on Friday, Sunday on Monday. US federal."""

    SUNDAY_TO_MONDAY = "sunday_to_monday"

    NEXT_FREE_WEEKDAY = "next_free_weekday"
    """A substitute day on the next weekday that is not already a holiday. The UK rule:
    Christmas on Saturday and Boxing Day on Sunday give Monday 27th and Tuesday 28th."""


@dataclass(frozen=True)
class HolidayRule:
    """One recurring holiday."""

    name: str
    rule: DateRule
    observance: Observance = Observance.ACTUAL
    since: int | None = None
    until: int | None = None
    moved: Mapping[int, _dt.date] = field(default_factory=dict)
    """One-off moves by year. The moved date replaces the rule's date that year."""

    def actual(self, year: int) -> _dt.date | None:
        if (self.since is not None and year < self.since) or (
            self.until is not None and year > self.until
        ):
            return None
        return self.moved.get(year, self.rule.on(year))


@dataclass(frozen=True)
class Holiday:
    """One holiday day. ``substitute`` is True for an observed-on-another-day entry."""

    day: _dt.date
    name: str
    substitute: bool = False


@dataclass(frozen=True)
class HolidayCalendar:
    """A jurisdiction's rules, optionally on top of a parent's."""

    code: str
    timezone: str
    rules: tuple[HolidayRule, ...] = ()
    one_off: Mapping[_dt.date, str] = field(default_factory=dict)
    parent: HolidayCalendar | None = None

    def all_rules(self) -> tuple[HolidayRule, ...]:
        inherited = self.parent.all_rules() if self.parent is not None else ()
        return inherited + self.rules

    def all_one_offs(self) -> dict[_dt.date, str]:
        inherited = self.parent.all_one_offs() if self.parent is not None else {}
        return {**inherited, **self.one_off}

    def holidays(self, year: int) -> tuple[Holiday, ...]:
        """Every holiday day falling in ``year``, actual and substitute, sorted.

        Rules for the neighbouring years are evaluated too: a US New Year's Day on a
        Saturday is observed on 31 December of the year before.
        """
        actual: list[tuple[_dt.date, HolidayRule]] = []
        for y in (year - 1, year, year + 1):
            for rule in self.all_rules():
                day = rule.actual(y)
                if day is not None:
                    actual.append((day, rule))
        one_offs = self.all_one_offs()
        out = [Holiday(day=day, name=rule.name) for day, rule in actual]
        out += [Holiday(day=day, name=name) for day, name in one_offs.items()]
        occupied = {day for day, _ in actual if day.weekday() < SAT} | {
            day for day in one_offs if day.weekday() < SAT
        }
        for day, rule in sorted(actual, key=lambda item: (item[0], item[1].name)):
            observed = _observe(day, rule.observance, occupied)
            if observed != day:
                occupied.add(observed)
                out.append(Holiday(day=observed, name=rule.name, substitute=True))
        unique = {(h.day, h.name, h.substitute): h for h in out if h.day.year == year}
        return tuple(sorted(unique.values(), key=lambda h: (h.day, h.name, h.substitute)))

    def is_holiday(self, day: _dt.date) -> bool:
        """True if ``day`` is a holiday, actual or substitute."""
        return any(h.day == day for h in self.holidays(day.year))

    def is_business_day(self, day: _dt.date) -> bool:
        """A weekday that is not a holiday. Weekend holidays do not close a weekday;
        their substitute days do, and those are in :meth:`holidays`."""
        return day.weekday() < SAT and not self.is_holiday(day)


def _observe(day: _dt.date, observance: Observance, occupied: set[_dt.date]) -> _dt.date:
    weekday = day.weekday()
    if observance is Observance.ACTUAL or weekday < SAT:
        return day
    if observance is Observance.NEAREST_WEEKDAY:
        return day + _dt.timedelta(days=-1 if weekday == SAT else 1)
    if observance is Observance.SUNDAY_TO_MONDAY:
        return day + _dt.timedelta(days=1) if weekday == SUN else day
    candidate = day + _dt.timedelta(days=1)
    while candidate.weekday() >= SAT or candidate in occupied:
        candidate += _dt.timedelta(days=1)
    return candidate


# --------------------------------------------------------------------------------------
# Built-in jurisdictions
# --------------------------------------------------------------------------------------

_NEAREST = Observance.NEAREST_WEEKDAY
_SUBST = Observance.NEXT_FREE_WEEKDAY

US: Final = HolidayCalendar(
    code="US",
    timezone="America/New_York",
    rules=(
        HolidayRule("new_years_day", Fixed(1, 1), _NEAREST),
        HolidayRule("martin_luther_king_jr_day", NthWeekday(1, MON, 3), since=1986),
        HolidayRule("washingtons_birthday", NthWeekday(2, MON, 3)),
        HolidayRule("memorial_day", NthWeekday(5, MON, -1)),
        HolidayRule("juneteenth", Fixed(6, 19), _NEAREST, since=2021),
        HolidayRule("independence_day", Fixed(7, 4), _NEAREST),
        HolidayRule("labor_day", NthWeekday(9, MON, 1)),
        HolidayRule("columbus_day", NthWeekday(10, MON, 2), since=1971),
        HolidayRule("veterans_day", Fixed(11, 11), _NEAREST),
        HolidayRule("thanksgiving_day", NthWeekday(11, THU, 4)),
        HolidayRule("christmas_day", Fixed(12, 25), _NEAREST),
    ),
)

_UK_ONE_OFFS: Final[dict[_dt.date, str]] = {
    _dt.date(1999, 12, 31): "millennium_celebrations",
    _dt.date(2002, 6, 3): "golden_jubilee",
    _dt.date(2011, 4, 29): "royal_wedding",
    _dt.date(2012, 6, 5): "diamond_jubilee",
    _dt.date(2022, 6, 3): "platinum_jubilee",
    _dt.date(2022, 9, 19): "state_funeral_of_queen_elizabeth_ii",
    _dt.date(2023, 5, 8): "coronation_of_king_charles_iii",
}

GB_ENG: Final = HolidayCalendar(
    code="GB-ENG",
    timezone="Europe/London",
    rules=(
        HolidayRule("new_years_day", Fixed(1, 1), _SUBST),
        HolidayRule("good_friday", EasterOffset(-2)),
        HolidayRule("easter_monday", EasterOffset(1)),
        HolidayRule(
            "early_may_bank_holiday",
            NthWeekday(5, MON, 1),
            since=1978,
            moved={1995: _dt.date(1995, 5, 8), 2020: _dt.date(2020, 5, 8)},
        ),
        HolidayRule(
            "spring_bank_holiday",
            NthWeekday(5, MON, -1),
            moved={
                2002: _dt.date(2002, 6, 4),
                2012: _dt.date(2012, 6, 4),
                2022: _dt.date(2022, 6, 2),
            },
        ),
        HolidayRule("summer_bank_holiday", NthWeekday(8, MON, -1)),
        HolidayRule("christmas_day", Fixed(12, 25), _SUBST),
        HolidayRule("boxing_day", Fixed(12, 26), _SUBST),
    ),
    one_off=_UK_ONE_OFFS,
)

GB_SCT: Final = HolidayCalendar(
    code="GB-SCT",
    timezone="Europe/London",
    rules=(
        HolidayRule("new_years_day", Fixed(1, 1), _SUBST),
        HolidayRule("second_january", Fixed(1, 2), _SUBST),
        HolidayRule("good_friday", EasterOffset(-2)),
        HolidayRule(
            "early_may_bank_holiday",
            NthWeekday(5, MON, 1),
            since=1978,
            moved={2020: _dt.date(2020, 5, 8)},
        ),
        HolidayRule(
            "spring_bank_holiday",
            NthWeekday(5, MON, -1),
            moved={2022: _dt.date(2022, 6, 2)},
        ),
        HolidayRule("summer_bank_holiday", NthWeekday(8, MON, 1)),
        HolidayRule("st_andrews_day", Fixed(11, 30), _SUBST, since=2007),
        HolidayRule("christmas_day", Fixed(12, 25), _SUBST),
        HolidayRule("boxing_day", Fixed(12, 26), _SUBST),
    ),
    one_off=_UK_ONE_OFFS,
)

DE: Final = HolidayCalendar(
    code="DE",
    timezone="Europe/Berlin",
    rules=(
        HolidayRule("neujahr", Fixed(1, 1)),
        HolidayRule("karfreitag", EasterOffset(-2)),
        HolidayRule("ostermontag", EasterOffset(1)),
        HolidayRule("tag_der_arbeit", Fixed(5, 1)),
        HolidayRule("christi_himmelfahrt", EasterOffset(39)),
        HolidayRule("pfingstmontag", EasterOffset(50)),
        HolidayRule("tag_der_deutschen_einheit", Fixed(10, 3), since=1990),
        HolidayRule("erster_weihnachtstag", Fixed(12, 25)),
        HolidayRule("zweiter_weihnachtstag", Fixed(12, 26)),
    ),
    one_off={_dt.date(2017, 10, 31): "reformationstag_500"},
)

DE_BY: Final = HolidayCalendar(
    code="DE-BY",
    timezone="Europe/Berlin",
    parent=DE,
    rules=(
        HolidayRule("heilige_drei_koenige", Fixed(1, 6)),
        HolidayRule("fronleichnam", EasterOffset(60)),
        HolidayRule("mariae_himmelfahrt", Fixed(8, 15)),
        HolidayRule("allerheiligen", Fixed(11, 1)),
    ),
)

DE_BE: Final = HolidayCalendar(
    code="DE-BE",
    timezone="Europe/Berlin",
    parent=DE,
    rules=(HolidayRule("internationaler_frauentag", Fixed(3, 8), since=2019),),
    one_off={
        _dt.date(2020, 5, 8): "tag_der_befreiung",
        _dt.date(2025, 5, 8): "tag_der_befreiung",
    },
)

FR: Final = HolidayCalendar(
    code="FR",
    timezone="Europe/Paris",
    rules=(
        HolidayRule("jour_de_l_an", Fixed(1, 1)),
        HolidayRule("lundi_de_paques", EasterOffset(1)),
        HolidayRule("fete_du_travail", Fixed(5, 1)),
        HolidayRule("victoire_1945", Fixed(5, 8)),
        HolidayRule("ascension", EasterOffset(39)),
        HolidayRule("lundi_de_pentecote", EasterOffset(50)),
        HolidayRule("fete_nationale", Fixed(7, 14)),
        HolidayRule("assomption", Fixed(8, 15)),
        HolidayRule("toussaint", Fixed(11, 1)),
        HolidayRule("armistice", Fixed(11, 11)),
        HolidayRule("noel", Fixed(12, 25)),
    ),
)

FR_ALSACE_MOSELLE: Final = HolidayCalendar(
    code="FR-ALSACE-MOSELLE",
    timezone="Europe/Paris",
    parent=FR,
    rules=(
        HolidayRule("vendredi_saint", EasterOffset(-2)),
        HolidayRule("saint_etienne", Fixed(12, 26)),
    ),
)

GR: Final = HolidayCalendar(
    code="GR",
    timezone="Europe/Athens",
    rules=(
        HolidayRule("protochronia", Fixed(1, 1)),
        HolidayRule("theofania", Fixed(1, 6)),
        HolidayRule("kathara_deftera", EasterOffset(-48, orthodox=True)),
        HolidayRule("independence_day", Fixed(3, 25)),
        HolidayRule("megali_paraskevi", EasterOffset(-2, orthodox=True)),
        HolidayRule("deftera_tou_pascha", EasterOffset(1, orthodox=True)),
        HolidayRule("protomagia", Fixed(5, 1)),
        HolidayRule("agiou_pnevmatos", EasterOffset(50, orthodox=True)),
        HolidayRule("koimisi_theotokou", Fixed(8, 15)),
        HolidayRule("ochi_day", Fixed(10, 28)),
        HolidayRule("christougenna", Fixed(12, 25)),
        HolidayRule("synaxis_theotokou", Fixed(12, 26)),
    ),
)

CALENDARS: Final[Mapping[str, HolidayCalendar]] = {
    "US": US,
    "GB-ENG": GB_ENG,
    "GB-WLS": GB_ENG,
    "GB-SCT": GB_SCT,
    "DE": DE,
    "DE-BY": DE_BY,
    "DE-BE": DE_BE,
    "FR": FR,
    "FR-57": FR_ALSACE_MOSELLE,
    "FR-67": FR_ALSACE_MOSELLE,
    "FR-68": FR_ALSACE_MOSELLE,
    "GR": GR,
}


class HolidaySource:
    """Turns calendars into context events for the sources each jurisdiction covers.

    ``assignments`` maps a jurisdiction code to the sources whose data lives under it.
    A holiday only touches its own sources: that is what lets the counterfactual check
    compare a German source on Easter Monday against a US source that worked that day.
    """

    name: Final = "holidays"

    def __init__(
        self,
        assignments: Mapping[str, Sequence[SourceId]],
        *,
        calendars: Mapping[str, HolidayCalendar] = CALENDARS,
    ) -> None:
        unknown = sorted(set(assignments) - set(calendars))
        if unknown:
            raise ValueError(f"no holiday calendar for {unknown}")
        self._assignments = {code: tuple(sorted(ids)) for code, ids in assignments.items()}
        self._calendars = calendars

    def events(self, *, start: _dt.datetime, end: _dt.datetime) -> tuple[ContextEvent, ...]:
        out: list[ContextEvent] = []
        for code in sorted(self._assignments):
            calendar = self._calendars[code]
            zone = ZoneInfo(calendar.timezone)
            for year in range(start.year - 1, end.year + 2):
                for holiday in calendar.holidays(year):
                    begin = _dt.datetime.combine(holiday.day, _dt.time.min, tzinfo=zone)
                    finish = begin + _dt.timedelta(days=1)
                    if finish < start or begin > end:
                        continue
                    suffix = "_observed" if holiday.substitute else ""
                    kind = f"holiday.{code.lower()}.{holiday.name}{suffix}"
                    out.append(
                        ContextEvent(
                            event_id=event_id_for(self.name, kind, holiday.day.isoformat()),
                            context_type=ContextType.HOLIDAY,
                            kind=kind,
                            origin=self.name,
                            start=begin,
                            end=finish,
                            scope=ContextScope(source_ids=self._assignments[code]),
                        )
                    )
        return tuple(sorted(out, key=lambda e: (e.start, e.event_id)))
