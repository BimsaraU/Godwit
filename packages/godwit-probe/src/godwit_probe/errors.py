"""The only exceptions that leave this package, and the boundary that makes that true.

DATA PLANE. A database driver puts the offending row in its message. DuckDB does it:
``Conversion Error: Could not convert string 'dev-0000-a4f7723b' to INT32``. pyarrow
does it on a failed cast. A source adapter's ``OSError`` carries a path with a table
name in it. None of that may reach a log line, a trace, a metric label, a job row or a
caller.

So every call into something we do not own goes through :func:`guarded` or
:func:`guarded_iter`. Whatever it raises is swallowed *whole* -- the message, the
arguments, the traceback, the chain -- and replaced by a :class:`ProbeError` built from
two closed vocabularies, :class:`Stage` and :class:`ErrorCode`. The replacement is
raised *outside* the ``except`` block, so Python does not attach the original as
``__context__``: there is nothing left to walk.

That is a blunter instrument than :func:`godwit_source.sanitise_driver_error`, which
keeps the original as a tainted value for code inside the perimeter. Nothing inside this
package needs the original, and a value that is not kept cannot be leaked.
"""

from __future__ import annotations

from collections.abc import Callable, Generator, Iterable
from enum import StrEnum
from typing import Final, cast

__all__ = ["ErrorCode", "ProbeError", "Stage", "guarded", "guarded_iter"]


class Stage(StrEnum):
    """Where in a probe run a failure happened. Our vocabulary; never a value."""

    RESOLVE = "resolve"
    LIST = "list"
    SCHEMA = "schema"
    PLAN = "plan"
    READ = "read"
    QUERY = "query"
    SKETCH = "sketch"
    SERIALISE = "serialise"
    STORE = "store"


class ErrorCode(StrEnum):
    """What kind of failure it was. A closed set, so a dashboard can count them."""

    SOURCE_UNAVAILABLE = "source_unavailable"
    """The catalog or source adapter could not answer a metadata question."""

    SCAN_FAILED = "scan_failed"
    """Reading a data file failed."""

    QUERY_FAILED = "query_failed"
    """The in-perimeter query engine rejected or failed the planned query."""

    SKETCH_FAILED = "sketch_failed"
    """A sketch could not be built or serialised from the rows it was given."""

    PLAN_VIOLATION = "plan_violation"
    """A read or a result did not match the plan's access modes. A defect, not a refusal."""

    STORE_FAILED = "store_failed"
    """The job queue or bundle store failed."""


_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.SOURCE_UNAVAILABLE: "the source could not answer a metadata request",
    ErrorCode.SCAN_FAILED: "reading a data file failed",
    ErrorCode.QUERY_FAILED: "the planned query failed",
    ErrorCode.SKETCH_FAILED: "building a sketch failed",
    ErrorCode.PLAN_VIOLATION: "a read did not match its access-mode plan",
    ErrorCode.STORE_FAILED: "the probe store failed",
}


class ProbeError(Exception):
    """A probe failed. Carries a stage and a code and nothing else.

    ``str()``, ``repr()`` and ``args`` are built from the two enums. There is no field in
    which driver text, a path, a column name or a value could be carried, and adding one
    would be the bug.
    """

    def __init__(self, code: ErrorCode, *, stage: Stage) -> None:
        self.code = code
        self.stage = stage
        super().__init__(f"probe failed at {stage.value}: {code.value} ({_MESSAGES[code]})")


def guarded[T](stage: Stage, code: ErrorCode, call: Callable[[], T]) -> T:
    """Run ``call``; turn anything it raises into a bare :class:`ProbeError`.

    A :class:`ProbeError` passes through untouched: it was built here and is already
    safe. Must not be called from inside an ``except`` block, or Python would attach
    that block's exception as context; nothing in this package does.
    """
    try:
        return call()
    except ProbeError:
        raise
    except Exception:
        # Deliberately broad and deliberately unbound: nothing specific survives.
        failure = ProbeError(code, stage=stage)
    raise failure


_END: Final[object] = object()


def guarded_iter[T](stage: Stage, code: ErrorCode, items: Iterable[T]) -> Generator[T]:
    """Iterate ``items`` under the same rule as :func:`guarded`, one ``next`` at a time.

    Generators raise from ``next``, which is where a Parquet reader or a query cursor
    fails half-way through a file.
    """
    iterator = guarded(stage, code, lambda: iter(items))
    try:
        while True:
            failure: ProbeError | None = None
            item: object = _END
            try:
                item = next(iterator, _END)
            except ProbeError:
                raise
            except Exception:
                failure = ProbeError(code, stage=stage)
            if failure is not None:
                raise failure
            if item is _END:
                return
            yield cast("T", item)
    finally:
        # Close the wrapped generator now, not whenever the garbage collector gets to
        # it: a query cursor's cleanup needs its connection, and the executor closes
        # the connection as soon as a probe stops. Left to the collector, the cleanup
        # ran after the close on Linux and raised into nowhere.
        close = getattr(iterator, "close", None)
        if close is not None:
            close()
