"""Every failure mode the harness has of its own.

Replay is the adversary of every other package, so its errors are deliberately blunt:
each one names a rule that was broken, not a thing that went wrong. None of them carries
a customer value -- an error message is an egress like any other, and a driver exception
is on the leak-path list.
"""

from __future__ import annotations

__all__ = [
    "BaselineNotReproducibleError",
    "DatasetNotAvailableError",
    "FutureKnowledgeError",
    "LeakDetectedError",
    "ReplayError",
    "WallClockAccessError",
]


class ReplayError(Exception):
    """Base for every harness failure."""


class WallClockAccessError(ReplayError):
    """Something read wall time, a local timezone or unseeded randomness during replay.

    Universal rule 5. A run that reads a clock cannot be reproduced tomorrow, so it is
    not evidence of anything. The guard names the module that did it.
    """


class FutureKnowledgeError(ReplayError):
    """A handler emitted something that names a snapshot or label it could not have seen.

    This is the bug replay exists to catch. Every impressive-and-useless backtest in the
    industry is this bug with better presentation.
    """


class LeakDetectedError(ReplayError):
    """The harness's own output carried a value that must not leave the perimeter.

    Raised after the audit, never instead of it: the findings are recorded on the run
    first so a failing run can still be read.
    """


class DatasetNotAvailableError(ReplayError):
    """A dataset's raw files are not present.

    Public datasets are not redistributed in this repo. The message names the files and
    where they come from, and never guesses at a substitute -- a fabricated dataset that
    looks real is worse than no dataset.
    """


class BaselineNotReproducibleError(ReplayError):
    """A recorded expert baseline did not rebuild to the same numbers.

    Either the data changed, the library changed, or the baseline was never deterministic
    in the first place. All three invalidate the comparison A13 is graded against.
    """
