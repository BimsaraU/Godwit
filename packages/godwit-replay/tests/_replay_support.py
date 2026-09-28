"""Handlers the tests drive replay with, including the ones that misbehave on purpose.

The metadata-only handler in the package emits segments with nullary operators only, which
is A1's deliberate design: an L-1 candidate carries no predicate value at all. That is good
for privacy and useless for testing the egress audit, because there is nothing to leak. So
the handlers here replay ``tests/golden/candidates.json``, whose segments quote real column
values -- ``country = 'PT'`` -- and are therefore the right input for proving the audit fires.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from godwit_contracts.common import Instant, SnapshotId
from godwit_contracts.discovery import Candidate
from godwit_replay.driver import ReplayView


def load_golden_candidates(golden_dir: Path) -> tuple[Candidate, ...]:
    """The two golden candidates, which correspond to the fixture's documented drift."""
    payload = json.loads((golden_dir / "candidates.json").read_text(encoding="utf-8"))
    return tuple(Candidate.model_validate(item) for item in payload["candidates"])


def relineage(candidate: Candidate, *, snapshot_id: SnapshotId, created_at: Instant) -> Candidate:
    """Re-point a fixture candidate at a snapshot a replay step could actually have seen.

    The fixture's candidates name ``snap_2``, which is the manifest's own snapshot label, not
    the Iceberg snapshot id a materialised table mints. A handler that emitted them unchanged
    would be rejected by the driver as future knowledge -- correctly, which is why this
    function exists rather than the driver being relaxed.
    """
    evidence = tuple(
        item.model_copy(update={"snapshot_id": snapshot_id, "baseline_snapshot_id": None})
        for item in candidate.evidence
    )
    return candidate.model_copy(
        update={
            "evidence": evidence,
            "lineage": candidate.lineage.model_copy(
                update={"snapshot_id": snapshot_id, "baseline_snapshot_id": None}
            ),
            "created_at": created_at,
        }
    )


@dataclass(frozen=True, slots=True)
class GoldenCandidateHandler:
    """Emits the golden candidates at the final step, correctly lineaged.

    Stands in for the L1/L2 layers that do not exist yet. It is not a detector and makes no
    claim to be one: it replays a fixture so that the harness's own machinery -- ranking,
    scoring, the egress audit -- can be tested against candidates that carry values.
    """

    candidates: Sequence[Candidate]
    emit_from_step: int = 2
    name: str = "golden-candidates"

    def observe(self, view: ReplayView) -> tuple[Candidate, ...]:
        if view.step_index < self.emit_from_step:
            return ()
        return tuple(
            relineage(candidate, snapshot_id=view.snapshot.snapshot_id, created_at=view.now)
            for candidate in self.candidates
        )


@dataclass(frozen=True, slots=True)
class FutureSnapshotHandler:
    """Emits a candidate naming a snapshot that does not exist yet. Must be rejected.

    This is the bug the harness exists to catch: a backtest that quietly used information
    from after the moment it claims to be standing at.
    """

    candidates: Sequence[Candidate]
    name: str = "future-snapshot"

    def observe(self, view: ReplayView) -> tuple[Candidate, ...]:
        return tuple(
            relineage(
                candidate,
                snapshot_id=SnapshotId("a-snapshot-from-next-month"),
                created_at=view.now,
            )
            for candidate in self.candidates
        )


@dataclass(frozen=True, slots=True)
class FutureDateHandler:
    """Emits a candidate dated after the step instant. Also future knowledge."""

    candidates: Sequence[Candidate]
    skew_days: int = 30
    name: str = "future-date"

    def observe(self, view: ReplayView) -> tuple[Candidate, ...]:
        import datetime as _dt

        return tuple(
            relineage(
                candidate,
                snapshot_id=view.snapshot.snapshot_id,
                created_at=view.now + _dt.timedelta(days=self.skew_days),
            )
            for candidate in self.candidates
        )


@dataclass(frozen=True, slots=True)
class ClockReadingHandler:
    """Reads the wall clock while replaying. The guard must stop it.

    A handler cannot reach the guarded names through its own module -- this file is not in
    the watched namespace -- so it goes through ``godwit_contracts.common``, which is. That
    is exactly the route a real detector would take: it would use the contracts' own
    ``datetime`` import.
    """

    name: str = "clock-reader"

    def observe(self, _view: ReplayView) -> tuple[Candidate, ...]:
        from godwit_contracts import common

        common.__dict__["_dt"].datetime.now()
        return ()


@dataclass(frozen=True, slots=True)
class LabelPeekingHandler:
    """Records how many labels it was shown, so a test can prove the future was withheld."""

    seen: list[int]
    name: str = "label-counter"

    def observe(self, view: ReplayView) -> tuple[Candidate, ...]:
        self.seen.append(len(view.labels))
        return ()
