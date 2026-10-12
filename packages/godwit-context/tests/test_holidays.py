"""Holiday calendars against published dates. Every date here is checked against the
issuing government's own list (OPM, gov.uk, the German and French official calendars)."""

from __future__ import annotations

import datetime as _dt

import pytest
from godwit_context import CALENDARS, HolidaySource, easter, orthodox_easter
from godwit_contracts import SourceId

D = _dt.date


@pytest.mark.parametrize(
    ("year", "expected"),
    [
        (1818, D(1818, 3, 22)),
        (1943, D(1943, 4, 25)),
        (2000, D(2000, 4, 23)),
        (2019, D(2019, 4, 21)),
        (2024, D(2024, 3, 31)),
        (2025, D(2025, 4, 20)),
        (2038, D(2038, 4, 25)),
    ],
)
def test_western_easter(year: int, expected: _dt.date) -> None:
    assert easter(year) == expected


@pytest.mark.parametrize(
    ("year", "expected"),
    [
        (2021, D(2021, 5, 2)),
        (2022, D(2022, 4, 24)),
        (2023, D(2023, 4, 16)),
        (2024, D(2024, 5, 5)),
        (2025, D(2025, 4, 20)),
    ],
)
def test_orthodox_easter(year: int, expected: _dt.date) -> None:
    assert orthodox_easter(year) == expected


def _days(code: str, year: int) -> dict[_dt.date, set[str]]:
    out: dict[_dt.date, set[str]] = {}
    for h in CALENDARS[code].holidays(year):
        out.setdefault(h.day, set()).add(h.name + ("*" if h.substitute else ""))
    return out


def test_us_federal_2024() -> None:
    assert sorted(_days("US", 2024)) == [
        D(2024, 1, 1),
        D(2024, 1, 15),
        D(2024, 2, 19),
        D(2024, 5, 27),
        D(2024, 6, 19),
        D(2024, 7, 4),
        D(2024, 9, 2),
        D(2024, 10, 14),
        D(2024, 11, 11),
        D(2024, 11, 28),
        D(2024, 12, 25),
    ]


def test_us_saturday_new_year_is_observed_in_the_previous_year() -> None:
    # 1 Jan 2022 was a Saturday: federal offices closed Friday 31 Dec 2021.
    assert "new_years_day*" in _days("US", 2021)[D(2021, 12, 31)]
    assert "new_years_day" in _days("US", 2022)[D(2022, 1, 1)]


def test_us_observance_both_directions() -> None:
    assert "independence_day*" in _days("US", 2020)[D(2020, 7, 3)]  # Saturday -> Friday
    assert "juneteenth*" in _days("US", 2022)[D(2022, 6, 20)]  # Sunday -> Monday
    assert "christmas_day*" in _days("US", 2022)[D(2022, 12, 26)]
    assert D(2020, 6, 19) not in _days("US", 2020)  # Juneteenth starts in 2021


def test_england_2022_moves_and_one_offs() -> None:
    days = _days("GB-ENG", 2022)
    assert "spring_bank_holiday" in days[D(2022, 6, 2)]
    assert D(2022, 5, 30) not in days
    assert "platinum_jubilee" in days[D(2022, 6, 3)]
    assert "state_funeral_of_queen_elizabeth_ii" in days[D(2022, 9, 19)]
    # Christmas on Sunday: Boxing Day Monday 26th, Christmas substitute Tuesday 27th.
    assert days[D(2022, 12, 26)] == {"boxing_day"}
    assert days[D(2022, 12, 27)] == {"christmas_day*"}


def test_england_substitutes_roll_past_each_other() -> None:
    # 2021: Christmas Saturday, Boxing Day Sunday -> Monday 27th and Tuesday 28th.
    days = _days("GB-ENG", 2021)
    assert days[D(2021, 12, 27)] == {"christmas_day*"}
    assert days[D(2021, 12, 28)] == {"boxing_day*"}


def test_england_2020_early_may_moved_to_ve_day() -> None:
    days = _days("GB-ENG", 2020)
    assert "early_may_bank_holiday" in days[D(2020, 5, 8)]
    assert D(2020, 5, 4) not in days


def test_scotland_differs_from_england() -> None:
    sct = _days("GB-SCT", 2022)
    eng = _days("GB-ENG", 2022)
    assert D(2022, 4, 18) in eng and D(2022, 4, 18) not in sct  # no Easter Monday
    assert "summer_bank_holiday" in sct[D(2022, 8, 1)]  # first Monday, not last
    assert sct[D(2022, 1, 3)] == {"new_years_day*"}
    assert sct[D(2022, 1, 4)] == {"second_january*"}
    assert "st_andrews_day*" in _days("GB-SCT", 2025)[D(2025, 12, 1)]


def test_germany_national_and_bavaria() -> None:
    de = _days("DE", 2024)
    assert "karfreitag" in de[D(2024, 3, 29)]
    assert "christi_himmelfahrt" in de[D(2024, 5, 9)]
    assert "pfingstmontag" in de[D(2024, 5, 20)]
    assert D(2024, 5, 30) not in de
    by = _days("DE-BY", 2024)
    assert "fronleichnam" in by[D(2024, 5, 30)]
    assert "heilige_drei_koenige" in by[D(2024, 1, 6)]
    # Germany does not move holidays: Christmas on a Sunday stays on Sunday.
    assert not any(name.endswith("*") for names in _days("DE", 2022).values() for name in names)


def test_berlin_womens_day_from_2019() -> None:
    assert D(2019, 3, 8) in _days("DE-BE", 2019)
    assert D(2018, 3, 8) not in _days("DE-BE", 2018)


def test_france_and_alsace_moselle() -> None:
    fr = _days("FR", 2024)
    assert "lundi_de_pentecote" in fr[D(2024, 5, 20)]
    assert "victoire_1945" in fr[D(2024, 5, 8)]
    assert D(2024, 3, 29) not in fr
    assert "vendredi_saint" in _days("FR-67", 2024)[D(2024, 3, 29)]


def test_greece_follows_orthodox_easter() -> None:
    gr = _days("GR", 2024)
    assert "kathara_deftera" in gr[D(2024, 3, 18)]
    assert "megali_paraskevi" in gr[D(2024, 5, 3)]
    assert "deftera_tou_pascha" in gr[D(2024, 5, 6)]
    assert "agiou_pnevmatos" in gr[D(2024, 6, 24)]


def test_holiday_events_are_local_days_in_utc() -> None:
    source = HolidaySource({"GB-ENG": [SourceId("src_uk")], "US": [SourceId("src_us")]})
    events = source.events(
        start=_dt.datetime(2024, 7, 1, tzinfo=_dt.UTC),
        end=_dt.datetime(2024, 7, 10, tzinfo=_dt.UTC),
    )
    (july4,) = [e for e in events if e.kind == "holiday.us.independence_day"]
    assert july4.start == _dt.datetime(2024, 7, 4, 4, tzinfo=_dt.UTC)  # EDT midnight
    assert july4.scope.source_ids == (SourceId("src_us"),)
    assert all(e.scope.source_ids != (SourceId("src_uk"),) for e in events)


def test_unknown_jurisdiction_is_refused() -> None:
    with pytest.raises(ValueError, match="no holiday calendar"):
        HolidaySource({"XX": [SourceId("s")]})
