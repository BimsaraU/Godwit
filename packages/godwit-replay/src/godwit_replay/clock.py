"""The virtual clock, and the guard that proves nothing read the real one.

Universal rule 5: no wall-clock reads anywhere in a path that can produce a pattern or a
prediction. Time is injected. This module supplies the injectable clock and, more
importantly, the thing that catches the packages which forgot.

HOW THE GUARD WORKS, AND WHAT IT CANNOT SEE
-------------------------------------------
``datetime.datetime.now`` lives on a C type and cannot be patched in place. What *can* be
patched is the name each module reached for. So :func:`forbid_wall_clock` walks
``sys.modules``, and in every module whose name starts with one of the watched prefixes it
replaces:

* an attribute that **is** the ``datetime`` module -- covers ``import datetime as _dt``
  followed by ``_dt.datetime.now()``;
* an attribute that **is** ``datetime.datetime`` or ``datetime.date`` -- covers
  ``from datetime import datetime`` followed by ``datetime.now()``;
* an attribute that **is** the ``time`` module, or one of its clock functions;
* an attribute that **is** the ``random`` module, or one of its module-level convenience
  functions, which draw on the shared unseeded generator.

The replacement for ``datetime`` is a class with a metaclass that forwards
``isinstance``, ``issubclass``, construction and every attribute except the forbidden
ones, so ``isinstance(value, _dt.datetime)`` in ``godwit_contracts.segment`` keeps working
while ``_dt.datetime.now()`` raises.

Known limits, stated rather than hidden:

* A module imported *after* the guard is entered is not patched. The driver imports its
  handler before entering, and the guard re-scans on entry, so this only bites code that
  imports lazily inside a hot path.
* A direct ``from datetime import datetime as _dt_now_holder`` bound to a name the scan
  does not recognise is still caught, because the scan matches on identity of the object,
  not on the name it was bound to.
* C extensions that read a clock internally (LightGBM's own timers, for instance) are
  invisible to this and always will be. Those do not influence output, and the
  determinism tests are what actually prove that.
* Nothing outside the watched prefixes is touched, so pytest's own timing, hypothesis and
  the standard library at large are unaffected. The guard has no global side effects.
"""

from __future__ import annotations

import datetime as _dt
import random as _random
import sys
import time as _time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import ModuleType
from typing import Final, Protocol, cast, runtime_checkable

from godwit_contracts.common import Instant, require_utc

from godwit_replay.errors import WallClockAccessError

__all__ = [
    "WATCHED_PREFIXES",
    "Clock",
    "VirtualClock",
    "forbid_wall_clock",
]

WATCHED_PREFIXES: Final[tuple[str, ...]] = ("godwit_",)
"""Module prefixes the guard patches. Everything else is left exactly as it was."""

_FORBIDDEN_DATETIME: Final[frozenset[str]] = frozenset({"now", "utcnow", "today", "fromtimestamp"})
"""``fromtimestamp`` is here because ``fromtimestamp(time.time())`` is a clock read with
an extra step. Replay converts recorded epoch values with ``datetime.fromtimestamp`` in
its own code, outside the watched prefixes, which is why that is not a contradiction."""

_FORBIDDEN_TIME: Final[frozenset[str]] = frozenset(
    {
        "time",
        "time_ns",
        "monotonic",
        "monotonic_ns",
        "perf_counter",
        "perf_counter_ns",
        "process_time",
        "localtime",
        "gmtime",
        "ctime",
        "asctime",
        "mktime",
    }
)

_FORBIDDEN_RANDOM: Final[frozenset[str]] = frozenset(
    {
        "random",
        "randint",
        "randrange",
        "choice",
        "choices",
        "shuffle",
        "sample",
        "uniform",
        "gauss",
        "normalvariate",
        "seed",
        "getrandbits",
    }
)


@runtime_checkable
class Clock(Protocol):
    """The one way any Godwit component may learn the time.

    LAWS
    ----
    1. ``now()`` is a pure function of the clock's own state. It never consults the
       operating system.
    2. ``now()`` is monotone non-decreasing across calls.
    3. Two clocks constructed from the same instants return the same sequence.
    """

    def now(self) -> Instant:
        """The current instant according to this clock."""
        ...


@dataclass(eq=False)
class VirtualClock:
    """A clock that only moves when replay tells it to.

    Constructed from the instants replay will visit, in order. ``advance_to`` refuses to
    go backwards: a handler that could see time run backwards could see a future label
    twice, and the whole point of the harness is that it cannot.
    """

    instants: Sequence[Instant]
    _index: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if not self.instants:
            raise ValueError("a VirtualClock needs at least one instant")
        previous: Instant | None = None
        for instant in self.instants:
            require_utc(instant)
            if previous is not None and instant < previous:
                raise ValueError("VirtualClock instants must be non-decreasing")
            previous = instant

    def now(self) -> Instant:
        """The instant this clock is parked at."""
        return self.instants[self._index]

    @property
    def index(self) -> int:
        """Which instant the clock is parked at, for the driver's own bookkeeping."""
        return self._index

    def advance_to(self, index: int) -> Instant:
        """Move the clock to ``instants[index]``. Refuses to move backwards."""
        if index < self._index:
            raise ValueError(f"clock cannot move back from {self._index} to {index}")
        if index >= len(self.instants):
            raise IndexError(f"no instant at {index}; this clock has {len(self.instants)}")
        self._index = index
        return self.now()


class _DatetimeGuardMeta(type):
    """Metaclass that makes a guard class behave like ``datetime.datetime`` minus the clock."""

    _target: type[_dt.date]

    def __instancecheck__(cls, instance: object) -> bool:
        return isinstance(instance, cls._target)

    def __subclasscheck__(cls, subclass: type) -> bool:
        return issubclass(subclass, cls._target)

    def __call__(cls, *args: object, **kwargs: object) -> object:
        """Forward construction to the real class, so ``_dt.datetime(...)`` still works."""
        return cast("Callable[..., object]", cls._target)(*args, **kwargs)

    def __getattr__(cls, name: str) -> object:
        if name in _FORBIDDEN_DATETIME:
            raise WallClockAccessError(
                f"{cls._target.__qualname__}.{name}() is a wall-clock read; replay injects "
                "time (universal rule 5)"
            )
        return getattr(cls._target, name)


class _GuardedDatetime(metaclass=_DatetimeGuardMeta):
    """Stands in for ``datetime.datetime`` while replay is running."""

    _target = _dt.datetime


class _GuardedDate(metaclass=_DatetimeGuardMeta):
    """Stands in for ``datetime.date``: ``date.today()`` is a clock read too."""

    _target = _dt.date


class _ModuleGuard:
    """Forwards to a real module, raising on the names that read a clock or a global RNG."""

    def __init__(self, target: ModuleType, forbidden: frozenset[str], why: str) -> None:
        self._target = target
        self._forbidden = forbidden
        self._why = why

    def __getattr__(self, name: str) -> object:
        if name in self._forbidden:
            raise WallClockAccessError(
                f"{self._target.__name__}.{name}() {self._why} (universal rule 5)"
            )
        value = getattr(self._target, name)
        if value is _dt.datetime:
            return _GuardedDatetime
        if value is _dt.date:
            return _GuardedDate
        return value


def _forbidden_callable(qualified: str, why: str) -> Callable[..., object]:
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise WallClockAccessError(f"{qualified}() {why} (universal rule 5)")

    return _raise


def _replacement(value: object) -> object | None:
    """What to substitute for one module attribute, or None to leave it alone."""
    if value is _dt:
        return _ModuleGuard(_dt, frozenset(), "reads the wall clock")
    if value is _dt.datetime:
        return _GuardedDatetime
    if value is _dt.date:
        return _GuardedDate
    if value is _time:
        return _ModuleGuard(_time, _FORBIDDEN_TIME, "reads the wall clock")
    if value is _random:
        return _ModuleGuard(_random, _FORBIDDEN_RANDOM, "draws on the unseeded global RNG")
    for name in _FORBIDDEN_TIME:
        if value is getattr(_time, name, None):
            return _forbidden_callable(f"time.{name}", "reads the wall clock")
    for name in _FORBIDDEN_RANDOM:
        if value is getattr(_random, name, None):
            return _forbidden_callable(f"random.{name}", "draws on the unseeded global RNG")
    return None


def _watched_modules(prefixes: Sequence[str]) -> Iterator[ModuleType]:
    """Watched modules, excluding this one.

    This module is exempt and must be: it holds the real ``datetime``, ``time`` and
    ``random`` references the guards forward to. Patching its own ``_dt`` would make
    ``_ModuleGuard.__getattr__`` consult a guard to decide what to guard, which recurses
    until the stack runs out. The exemption is safe because nothing here reads a clock --
    every reference is used for identity comparison and forwarding.
    """
    for name, module in list(sys.modules.items()):
        if name == __name__:
            continue
        if any(name.startswith(prefix) for prefix in prefixes):
            yield module


@contextmanager
def forbid_wall_clock(
    *, prefixes: Sequence[str] = WATCHED_PREFIXES
) -> Iterator[tuple[tuple[str, str], ...]]:
    """Make every watched module's clock and global-RNG access raise.

    Yields the (module, attribute) pairs that were patched, so a test can assert the
    guard actually found something rather than passing because it found nothing. Restores
    every attribute on the way out, including when the body raises.
    """
    saved: list[tuple[ModuleType, str, object]] = []
    patched: list[tuple[str, str]] = []
    try:
        for module in _watched_modules(prefixes):
            for attribute, value in list(vars(module).items()):
                if attribute.startswith("__"):
                    continue
                substitute = _replacement(value)
                if substitute is None:
                    continue
                saved.append((module, attribute, value))
                setattr(module, attribute, substitute)
                patched.append((module.__name__, attribute))
        yield tuple(patched)
    finally:
        for module, attribute, value in reversed(saved):
            setattr(module, attribute, value)
