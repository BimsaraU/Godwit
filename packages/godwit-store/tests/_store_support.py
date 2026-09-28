"""Shared builders for the godwit-store suite.

Contract objects are fiddly to construct correctly -- a segment predicate whose value is
not tainted ``DATA_VALUE`` with the ``segment_predicate`` acquisition simply will not
validate, and that is deliberate. Building them in one place means a contract change
breaks one file rather than a dozen, and it means every test in this suite exercises
*correctly tainted* objects rather than ones that happen to pass.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from godwit_contracts import (
    Acquisition,
    Candidate,
    CandidateId,
    Evidence,
    EvidenceKind,
    Instant,
    Lineage,
    Operator,
    Predicate,
    ProbeKey,
    Segment,
    SnapshotId,
    SourceId,
    data_value,
    derived_statistic,
    schema_name,
)


def make_segment(pairs: Sequence[tuple[str, str]], *, population: int | None = 500) -> Segment:
    """A conjunction of equality predicates, correctly tainted.

    Column names are SCHEMA_NAME, values are DATA_VALUE with the ``segment_predicate``
    acquisition -- leak path 4. Anything else fails contract validation, which is the
    point of building them here.
    """
    return Segment(
        predicates=tuple(
            Predicate(
                column=schema_name(column),
                op=Operator.EQ,
                values=(
                    data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE, column=column),
                ),
            )
            for column, value in pairs
        ),
        population=population,
    )


def make_evidence(
    *,
    snapshot_id: str,
    probe_key: str,
    columns: Sequence[str],
    segment: Segment,
    statistic: float,
    baseline: float | None,
    p_value: float | None,
    kind: EvidenceKind = EvidenceKind.SEGMENT_DIVERGENCE,
    population: int | None = 500,
) -> Evidence:
    """One measured claim. Statistics are DERIVED_STATISTIC; columns are SCHEMA_NAME."""
    return Evidence(
        kind=kind,
        probe_key=ProbeKey(probe_key),
        snapshot_id=SnapshotId(snapshot_id),
        baseline_snapshot_id=SnapshotId("snap_1"),
        segment=segment,
        columns=tuple(schema_name(column) for column in columns),
        statistic=derived_statistic(statistic, population=population),
        baseline=None if baseline is None else derived_statistic(baseline, population=population),
        p_value=None if p_value is None else derived_statistic(p_value, population=population),
        population=population,
    )


@dataclass(frozen=True, slots=True)
class CandidateSpec:
    """Everything a test might vary about a candidate, with defaults for the rest.

    A dataclass rather than a fourteen-argument function: the builder is used from a
    dozen tests and a positional mistake in one of them would be silent.
    """

    candidate_id: str
    created_at: Instant
    pairs: Sequence[tuple[str, str]] = (("country", "PT"),)
    columns: Sequence[str] = ("amount",)
    statistic: float = 10.0
    baseline: float | None = 1.0
    p_value: float | None = 0.001
    score: float = 0.9
    detector: str = "segment_divergence"
    detector_version: int = 1
    snapshot_id: str = "snap_2"
    probe_key: str = "prb_test"
    source_id: str = "src_test"
    population: int | None = 500
    kind: EvidenceKind = EvidenceKind.SEGMENT_DIVERGENCE

    def build(self) -> Candidate:
        """A complete, contract-valid candidate."""
        segment = make_segment(self.pairs, population=self.population)
        return Candidate(
            candidate_id=CandidateId(self.candidate_id),
            source_id=SourceId(self.source_id),
            segment=segment,
            evidence=(
                make_evidence(
                    snapshot_id=self.snapshot_id,
                    probe_key=self.probe_key,
                    columns=self.columns,
                    segment=segment,
                    statistic=self.statistic,
                    baseline=self.baseline,
                    p_value=self.p_value,
                    kind=self.kind,
                    population=self.population,
                ),
            ),
            score=self.score,
            lineage=Lineage(
                probe_key=ProbeKey(self.probe_key),
                snapshot_id=SnapshotId(self.snapshot_id),
                baseline_snapshot_id=SnapshotId("snap_1"),
                detector=self.detector,
                detector_version=self.detector_version,
                code_version="test-build",
                seed=20240117,
            ),
            created_at=self.created_at,
        )
