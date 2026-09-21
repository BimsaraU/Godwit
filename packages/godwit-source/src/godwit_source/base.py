"""The ``SourceAdapter`` surface and the plan-time checks every adapter shares.

DATA PLANE. An adapter reads rows in place and emits gated artifacts. No adapter method
returns rows, ever, under any flag, including in an exception message -- see
:func:`safe_backend_error`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ._contracts import CostBudget, ProbeSpec, SketchBundle, Tainted
from .access import AccessPolicy, BlindColumnError
from .stats import SnapshotMetadata

__all__ = [
    "BlindColumnLeak",
    "ProbeResult",
    "SnapshotRef",
    "SourceAdapter",
    "assert_plan_is_blind_safe",
    "readable_columns",
    "require_readable",
    "safe_backend_error",
]


class BlindColumnLeak(AssertionError):
    """A generated plan mentions a BLIND column. Fail the query; do not sanitise it."""


@dataclass(frozen=True, slots=True)
class SnapshotRef:
    """A point in a table's history. ``commit_ms`` comes from the catalog, not a clock."""

    snapshot_id: str
    sequence_number: int
    commit_ms: int
    parent_id: str | None = None


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Aggregates and sketches. Never rows.

    ``sql`` is retained so a test can assert on the text that was actually sent, which is
    the only honest way to prove a BLIND column was never projected.
    """

    spec: ProbeSpec
    sql: str | None
    schema_names: tuple[str, ...]
    aggregates: Mapping[str, Tainted[float]] = field(default_factory=dict)
    sketches: Mapping[str, SketchBundle] = field(default_factory=dict)
    bytes_read: int = 0
    files_read: int = 0


@runtime_checkable
class SourceAdapter(Protocol):
    """What every backend provides. Three implementations live in this package."""

    name: str

    def list_snapshots(self, table: str) -> Sequence[SnapshotRef]:
        """Snapshots ordered oldest first by commit time."""
        ...

    def read_metadata_stats(
        self,
        table: str,
        *,
        policy: AccessPolicy,
        since: str | None = None,
        until: str | None = None,
    ) -> Sequence[SnapshotMetadata]:
        """Free metadata for each snapshot in ``(since, until]``. Reads no table data."""
        ...

    def execute_probe(
        self,
        spec: ProbeSpec,
        *,
        policy: AccessPolicy,
        budget: CostBudget,
    ) -> ProbeResult:
        """Run a probe against the data. Refuses rather than exceeding ``budget``."""
        ...


def assert_plan_is_blind_safe(
    sql: str | None,
    schema_names: Sequence[str],
    policy: AccessPolicy,
    candidate_columns: Sequence[str],
) -> None:
    """Verify structurally that no BLIND column reached the plan.

    Checks the generated SQL text *and* the result schema, because those are the two places
    a column can appear. A check on the returned data would be worthless: by then the value
    has been read.
    """
    blind = [c for c in candidate_columns if policy.is_blind(c)]
    for col in blind:
        if col in schema_names:
            raise BlindColumnLeak(f"BLIND column {col!r} present in result schema")
        if sql and re.search(rf"(?<![\w]){re.escape(col)}(?![\w])", sql):
            raise BlindColumnLeak(f"BLIND column {col!r} present in generated SQL")


def safe_backend_error(exc: BaseException, *, backend: str, context: str) -> RuntimeError:
    """Replace a driver exception with one that cannot carry a row.

    Driver messages routinely quote the offending row ("duplicate key value violates ...
    (email)=(ada@example.com)"). The original is dropped entirely rather than scrubbed: a
    regex over a driver message is a guess, and a guess is not a control.
    """
    return RuntimeError(
        f"{backend} failed during {context}: {type(exc).__name__} (detail withheld)"
    )


def readable_columns(policy: AccessPolicy, columns: Sequence[str]) -> tuple[str, ...]:
    """Columns that survive plan-time access resolution, in input order."""
    return tuple(p.column for p in policy.plan(columns))


def require_readable(policy: AccessPolicy, columns: Sequence[str]) -> tuple[str, ...]:
    """Like :func:`readable_columns`, but a BLIND column is an error rather than a silent drop.

    Used where the caller named the columns explicitly: silently dropping one would make a
    probe quietly measure something other than what was asked for.
    """
    for col in columns:
        if policy.is_blind(col):
            raise BlindColumnError(f"column {col!r} is BLIND and must never be read")
    return tuple(columns)
