"""The virtual clock, and proof that the guard catches a real wall-clock read.

The last test in this file is the one that matters: it asserts the guard actually fires on a
Godwit package, not merely that it fires on a toy module written to be caught.
"""

from __future__ import annotations

import datetime as _dt
import random
import sys
import time
from types import ModuleType

import pytest
from godwit_replay.clock import VirtualClock, forbid_wall_clock
from godwit_replay.errors import WallClockAccessError

UTC = _dt.UTC


def _instants(count: int) -> list[_dt.datetime]:
    base = _dt.datetime(2024, 1, 1, tzinfo=UTC)
    return [base + _dt.timedelta(days=index) for index in range(count)]


def test_clock_starts_at_the_first_instant() -> None:
    clock = VirtualClock(_instants(3))
    assert clock.now() == _dt.datetime(2024, 1, 1, tzinfo=UTC)
    assert clock.index == 0


def test_clock_advances_forward_only() -> None:
    clock = VirtualClock(_instants(3))
    clock.advance_to(2)
    assert clock.now() == _dt.datetime(2024, 1, 3, tzinfo=UTC)
    with pytest.raises(ValueError, match="cannot move back"):
        clock.advance_to(1)


def test_clock_refuses_an_out_of_range_index() -> None:
    clock = VirtualClock(_instants(2))
    with pytest.raises(IndexError, match="no instant at 5"):
        clock.advance_to(5)


def test_clock_refuses_empty_or_unordered_instants() -> None:
    with pytest.raises(ValueError, match="at least one instant"):
        VirtualClock([])
    backwards = list(reversed(_instants(2)))
    with pytest.raises(ValueError, match="non-decreasing"):
        VirtualClock(backwards)


def test_clock_refuses_naive_instants() -> None:
    with pytest.raises(ValueError, match="naive datetime"):
        VirtualClock([_dt.datetime(2024, 1, 1)])


def test_two_clocks_from_the_same_instants_agree() -> None:
    left, right = VirtualClock(_instants(4)), VirtualClock(_instants(4))
    for index in range(4):
        assert left.advance_to(index) == right.advance_to(index)


# -- the guard ---------------------------------------------------------------------------


def _victim() -> ModuleType:
    """A module inside the watched namespace that reads a clock four different ways."""
    module = ModuleType("godwit_replay_test_victim")
    module.__dict__.update(
        {
            "_dt": _dt,
            "datetime_class": _dt.datetime,
            "date_class": _dt.date,
            "time_module": time,
            "time_func": time.time,
            "random_module": random,
            "random_func": random.random,
        }
    )
    sys.modules[module.__name__] = module
    return module


def test_guard_blocks_every_route_to_the_wall_clock() -> None:
    module = _victim()
    try:
        with forbid_wall_clock() as patched:
            assert any(name == module.__name__ for name, _ in patched)
            with pytest.raises(WallClockAccessError, match="wall-clock read"):
                module.__dict__["_dt"].datetime.now()
            with pytest.raises(WallClockAccessError, match="wall-clock read"):
                module.__dict__["datetime_class"].utcnow()
            with pytest.raises(WallClockAccessError, match="wall-clock read"):
                module.__dict__["date_class"].today()
            with pytest.raises(WallClockAccessError, match="wall clock"):
                module.__dict__["time_module"].time()
            with pytest.raises(WallClockAccessError, match="wall clock"):
                module.__dict__["time_func"]()
            with pytest.raises(WallClockAccessError, match="unseeded global RNG"):
                module.__dict__["random_module"].random()
            with pytest.raises(WallClockAccessError, match="unseeded global RNG"):
                module.__dict__["random_func"]()
    finally:
        del sys.modules[module.__name__]


def test_guard_leaves_arithmetic_and_isinstance_working() -> None:
    module = _victim()
    try:
        with forbid_wall_clock():
            guarded = module.__dict__["_dt"]
            moment = guarded.datetime(2024, 1, 1, tzinfo=UTC)
            assert isinstance(moment, guarded.datetime)
            assert isinstance(moment, _dt.datetime)
            assert issubclass(_dt.datetime, guarded.datetime)
            assert guarded.datetime.fromisoformat("2024-01-01T00:00:00+00:00") == moment
            assert guarded.timedelta(days=1) == _dt.timedelta(days=1)
            # The seeded generator is still reachable: only the module-level convenience
            # functions, which draw on the shared unseeded instance, are blocked.
            assert module.__dict__["random_module"].Random is random.Random
    finally:
        del sys.modules[module.__name__]


def test_guard_restores_everything_even_when_the_body_raises() -> None:
    module = _victim()
    try:
        with pytest.raises(RuntimeError, match="deliberate"), forbid_wall_clock():
            raise RuntimeError("deliberate")
        assert module.__dict__["_dt"] is _dt
        assert module.__dict__["time_func"] is time.time
        assert module.__dict__["random_func"] is random.random
    finally:
        del sys.modules[module.__name__]


def test_guard_does_not_touch_modules_outside_the_watched_prefixes() -> None:
    with forbid_wall_clock():
        # json is not a godwit module, so its own imports are untouched and stdlib keeps
        # working. A guard with global side effects would break pytest itself.
        assert time.time() > 0.0


def test_guard_fires_on_a_real_godwit_package() -> None:
    """The load-bearing assertion: the guard reaches into a package we did not write.

    ``godwit_contracts.common`` does ``import datetime as _dt``. If the guard could only
    catch a module built for the purpose, it would prove nothing about the nineteen packages
    it is supposed to police.
    """
    from godwit_contracts import common

    assert common.__dict__["_dt"] is _dt
    with forbid_wall_clock():
        with pytest.raises(WallClockAccessError):
            common.__dict__["_dt"].datetime.now()
        # And the module's real work still functions: nothing here reads a clock.
        assert common.require_utc(_dt.datetime(2024, 1, 1, tzinfo=UTC))
    assert common.__dict__["_dt"] is _dt
