"""Builders shared by the godwit-context tests. Package-unique name on purpose."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Mapping, Sequence

from godwit_context import (
    ContextEvent,
    ContextScope,
    ContextType,
    PeerObservation,
    event_id_for,
)
from godwit_contracts import (
    Acquisition,
    Candidate,
    CandidateId,
    Evidence,
    EvidenceKind,
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

T0 = _dt.datetime(2024, 3, 1, tzinfo=_dt.UTC)
HOUR = _dt.timedelta(hours=1)
DAY = _dt.timedelta(days=1)


def segment(pairs: Mapping[str, str] | None = None, population: int | None = 500) -> Segment:
    return Segment(
        predicates=tuple(
            Predicate(
                column=schema_name(column),
                op=Operator.EQ,
                values=(data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE),),
            )
            for column, value in sorted((pairs or {}).items())
        ),
        population=population,
    )


def candidate(
    cid: str,
    *,
    source: str = "src_a",
    at: _dt.datetime = T0,
    pairs: Mapping[str, str] | None = None,
    columns: Sequence[str] = ("amount",),
    effect: float | None = 2.0,
    kind: EvidenceKind = EvidenceKind.DISTRIBUTION_SHIFT,
    detector: str = "psi_drift",
) -> Candidate:
    seg = segment(pairs)
    snap = SnapshotId(f"snap_{cid}")
    return Candidate(
        candidate_id=CandidateId(cid),
        source_id=SourceId(source),
        segment=seg,
        evidence=(
            Evidence(
                kind=kind,
                probe_key=ProbeKey(f"prb_{source}"),
                snapshot_id=snap,
                segment=seg,
                columns=tuple(schema_name(c) for c in columns),
                statistic=derived_statistic(abs(effect or 1.0) * 10),
                effect_size=None if effect is None else derived_statistic(effect),
                p_value=derived_statistic(1e-6),
                population=500,
            ),
        ),
        score=1.0,
        lineage=Lineage(
            probe_key=ProbeKey(f"prb_{source}"),
            snapshot_id=snap,
            detector=detector,
            detector_version=1,
            code_version="test",
            seed=7,
        ),
        created_at=at,
    )


def event(
    name: str,
    context_type: ContextType = ContextType.DEPLOY,
    *,
    start: _dt.datetime = T0 - 2 * HOUR,
    duration: _dt.timedelta = _dt.timedelta(0),
    sources: Sequence[str] = ("src_a",),
    columns: Sequence[str] = (),
    pairs: Mapping[str, str] | None = None,
    derived_from: str | None = None,
) -> ContextEvent:
    return ContextEvent(
        event_id=event_id_for("test", name),
        context_type=context_type,
        kind=f"{context_type.value}.{name}",
        origin="test",
        start=start,
        end=start + duration,
        scope=ContextScope(
            source_ids=tuple(SourceId(s) for s in sources),
            columns=tuple(schema_name(c) for c in columns),
            segments=(segment(pairs),) if pairs else (),
        ),
        derived_from=None if derived_from is None else CandidateId(derived_from),
    )


def peer(
    source: str,
    effect: float,
    *,
    at: _dt.datetime = T0,
    pairs: Mapping[str, str] | None = None,
    family: str = "distribution_shift",
) -> PeerObservation:
    return PeerObservation(
        source_id=SourceId(source),
        segment=segment(pairs),
        family=family,
        observed_at=at,
        effect=derived_statistic(effect),
    )
