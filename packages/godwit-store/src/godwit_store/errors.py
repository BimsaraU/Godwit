"""Every error this package raises.

Nothing here wraps a driver exception. A psycopg error message routinely contains the
offending row (leak path 10), so every database failure is caught, classified and
re-raised with a message we wrote. :func:`classify_driver_error` is the one funnel.
"""

from __future__ import annotations

from typing import Final

_APPEND_ONLY_SENTINEL: Final[str] = "GODWIT_APPEND_ONLY"
"""Mirrors :data:`godwit_store.appendonly.APPEND_ONLY_SENTINEL`.

Duplicated as a literal rather than imported, because ``appendonly`` imports SQLAlchemy
and this module must stay importable by anything, including a failure path that is
already unwinding.
"""

__all__ = [
    "AppendOnlyViolationError",
    "ChainBrokenError",
    "LifecycleTransitionError",
    "PatternNotFoundError",
    "RevealRefusedError",
    "StoreError",
    "StoreIntegrityError",
    "StoreUnavailableError",
    "SuppressedError",
    "UnboundedHypothesisFamilyError",
    "UncoveredRegionError",
    "classify_driver_error",
]


class StoreError(Exception):
    """Base for every failure in godwit-store."""


class StoreUnavailableError(StoreError):
    """The database could not be reached, or refused the connection."""


class StoreIntegrityError(StoreError):
    """A write violated a constraint the schema enforces."""


class AppendOnlyViolationError(StoreIntegrityError):
    """An UPDATE or DELETE was attempted against an append-only ledger.

    Raised when the database refused it. The database refusing is the control; this
    exception is how the refusal reaches Python without a driver message attached.
    """


class ChainBrokenError(StoreError):
    """A hash-chained ledger did not verify. Treat as a tamper indication."""


class PatternNotFoundError(StoreError):
    """No pattern with that id."""


class LifecycleTransitionError(StoreError):
    """A lifecycle transition is not allowed, or lacks the evidence it requires."""


class UnboundedHypothesisFamilyError(StoreError):
    """A detector run reported fewer tests than it produced candidates, or none.

    Benjamini-Hochberg needs the size of the family that was tested, not the size of
    the family that survived. A run that cannot say how many hypotheses it examined has
    a bug, and absorbing it silently would understate every q-value in the batch.
    """


class UncoveredRegionError(StoreError):
    """A metric was requested over a region the label ledger does not cover.

    Precision and AUC over an uncovered region are not conservative estimates; they are
    numbers about a population whose labels nobody promised to have collected.
    """


class SuppressedError(StoreError):
    """The signature is under an active suppression. Reversible; see ``unsuppress``."""


class RevealRefusedError(StoreError):
    """Something tried to unwrap a tainted value this package may not unwrap.

    godwit-store is control plane. It legitimately reads derived statistics and schema
    names in order to key, rank and deduplicate. It never reads a DATA_VALUE, because
    there is nothing it could correctly do with one.
    """


def classify_driver_error(exc: Exception) -> StoreError:
    """Turn a driver or ORM exception into one of ours, discarding its message.

    The message is dropped on purpose. ``IntegrityError`` from psycopg renders the
    conflicting row in ``DETAIL``, which means logging it is an egress nobody gated.
    The exception *type* is enough to act on; the row is not ours to keep.
    """
    name = type(exc).__name__
    if _APPEND_ONLY_SENTINEL in str(exc):
        # The sentinel is text we wrote into the refusing trigger, not driver output.
        # It is the only part of the message inspected, and none of it is kept.
        return AppendOnlyViolationError(
            "the database refused a mutation of an append-only ledger; correct a "
            "mistaken entry by appending a correcting one"
        )
    if name in {"OperationalError", "InterfaceError", "DBAPIError"}:
        return StoreUnavailableError(f"database unavailable ({name}); message withheld")
    if name in {"IntegrityError", "DataError"}:
        return StoreIntegrityError(f"write rejected by a constraint ({name}); message withheld")
    return StoreError(f"store operation failed ({name}); message withheld")
