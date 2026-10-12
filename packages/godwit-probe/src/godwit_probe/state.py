"""Where "since the last probed snapshot" comes from.

Incremental is the default mode: a probe measures the rows committed after the snapshot
it last measured, and nothing else. This module remembers that snapshot per probe key.
The in-memory store serves the simulator, the poller and tests; the worker runtime keeps
the same record in Postgres (``godwit_probe.worker``) and advances it in the same
transaction that writes the bundle, so the two can never disagree.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from godwit_contracts import ProbeKey, SnapshotId

__all__ = ["MemoryProbeState", "ProbeState"]


@runtime_checkable
class ProbeState(Protocol):
    """The last snapshot each probe key has been measured up to."""

    def last_snapshot(self, probe_key: ProbeKey) -> SnapshotId | None:
        """The snapshot a probe last covered, or None if it never ran."""
        ...

    def advance(self, probe_key: ProbeKey, snapshot_id: SnapshotId) -> None:
        """Record that ``probe_key`` has now been measured up to ``snapshot_id``."""
        ...


class MemoryProbeState:
    """A dict. For one process: the simulator, the poller, tests."""

    def __init__(self) -> None:
        self._last: dict[ProbeKey, SnapshotId] = {}

    def last_snapshot(self, probe_key: ProbeKey) -> SnapshotId | None:
        """See :class:`ProbeState`."""
        return self._last.get(probe_key)

    def advance(self, probe_key: ProbeKey, snapshot_id: SnapshotId) -> None:
        """See :class:`ProbeState`."""
        self._last[probe_key] = snapshot_id
