"""L-1 metadata detectors: the tier that costs nothing to run.

Iceberg manifests already carry per-file, per-column bounds, null counts, value counts
and row counts. Puffin already carries an NDV. ``pg_stats`` already carries
most-common-values and histogram boundaries. All of it is written by somebody else's
pipeline, for somebody else's reasons, and all of it is free to read. These six
detectors turn that free metadata into a first-pass signal, so that invariant 5 --
metadata first -- has something concrete to mean: a paid scan is spent only where the
free tier already flagged something.

WHAT THESE ARE NOT
------------------
They are not the L2 ``Detector`` protocol. L2 scores *sketches* against a baseline and
runs in the control plane. These run in the data plane, over metadata this package read
itself, and they exist one layer earlier. They obey the same laws all the same: pure,
seeded, no clock, no LLM, one complete ``Lineage`` per candidate, raw p-values with FDR
control left to L5.

VALUE-FREE BY CONSTRUCTION
--------------------------
The brief asks for a preference: a detector that reports *how far* a bound moved emits
a derived statistic, while one that reports *which* bound it moved to is handling a row
value. Every detector here is in the first camp, and none of them needs to be in the
second:

* Numeric bounds are measured on an axis -- the log of the column's range, and the
  movement of its midpoint in units of the previous range. Both are pure numbers.
* String bounds are measured by :func:`~godwit_source.scalars.prefix_similarity`, which
  survives Iceberg's 16-character bound truncation and returns a ratio.
* A schema change is reported as a count of columns added, removed and retyped.

So no ``Candidate`` produced here carries a bound, and the only tainted things in one
are column names (``SCHEMA_NAME``) and the statistics themselves
(``DERIVED_STATISTIC``). The segment predicates are ``IS NULL`` and ``NOT NULL``, which
take no value at all. That is deliberate: it makes L-1 output the cheapest thing in the
system for the gate to clear.

RELATIVE, NOT ABSOLUTE
----------------------
Every detector measures the *latest transition against the previous transitions*, never
the latest value against a threshold. A table whose ``order_id`` prefix advances every
week is not drifting; a table whose amount range triples once, having been stable, is.
Measuring the second difference is what tells those apart, and it is why
:func:`evaluate_deltas` takes a series of changes rather than a series of values.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Final

from godwit_contracts.common import (
    CandidateId,
    GodwitModel,
    Instant,
    NonNegInt,
    ProbeId,
    ProbeKey,
    SnapshotId,
    Version,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget
from godwit_contracts.discovery import Candidate, Evidence, EvidenceKind, Lineage
from godwit_contracts.probe import ProbeKind, ProbeSpec
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.source import SourceRef
from godwit_contracts.taint import Tainted, derived_statistic
from pydantic import Field

from godwit_source.metadata import ColumnMetadata, SnapshotMetadata
from godwit_source.scalars import as_axis, prefix_similarity
from godwit_source.stats import log_ratio, robust_z, two_proportion_z, two_sided_p

__all__ = [
    "DEFAULT_CONFIG",
    "DETECTOR_VERSION",
    "METADATA_PROBE_BUDGET",
    "DeltaVerdict",
    "DetectorConfig",
    "bounds_drift",
    "evaluate_deltas",
    "file_layout_anomaly",
    "ndv_ratio_shift",
    "null_rate_shift",
    "row_volume_anomaly",
    "run_metadata_detectors",
    "schema_change",
]

DETECTOR_VERSION: Final[Version] = 1
"""Bumped whenever any detector here could produce different output for identical input."""

METADATA_PROBE_BUDGET: Final[CostBudget] = CostBudget(
    bytes_scanned=0,
    wall_seconds=0.0,
    usd=Decimal("0"),
    llm_tokens=0,
    train_seconds=0.0,
)
"""The budget an L-1 probe spec declares: nothing, in every currency.

``ProbeSpec.budget`` is excluded from ``probe_key``, so this value does not affect
identity. It is all zeros because that is the true cost of the measurement, and a probe
spec that claimed otherwise would misreport the free tier to the orchestrator.
"""

_BOUNDS_DRIFT: Final[str] = "metadata.bounds_drift"
_NULL_RATE_SHIFT: Final[str] = "metadata.null_rate_shift"
_NDV_RATIO_SHIFT: Final[str] = "metadata.ndv_ratio_shift"
_ROW_VOLUME_ANOMALY: Final[str] = "metadata.row_volume_anomaly"
_SCHEMA_CHANGE: Final[str] = "metadata.schema_change"
_FILE_LAYOUT_ANOMALY: Final[str] = "metadata.file_layout_anomaly"

_MIN_SNAPSHOTS: Final[int] = 3
"""Three snapshots give two transitions: one to measure and one to judge it against."""

_RELATIVE_FLOOR: Final[float] = 2.0
"""How many times the largest previous change the latest one must be, when there is not
enough history for a robust z. Two is chosen to be obviously conservative rather than
tuned: with three snapshots the honest answer is "we barely know", and the threshold
should say so."""


class DetectorConfig(GodwitModel):
    """Thresholds shared by the six detectors.

    Every field is a decision about how loud to be, and every one of them belongs in
    lineage-adjacent configuration rather than in code, because changing one changes
    what the system reports. Defaults are deliberately quiet: the discovery queue is
    five items a week and precision is the objective.
    """

    max_p_value: float = Field(default=0.01, gt=0.0, lt=1.0)
    """Raw p-value below which a test with enough history fires. L5 applies FDR."""

    min_abs_log_ratio: float = Field(default=0.5, gt=0.0)
    """Absolute change required when there is too little history for a robust z.

    0.5 in log units is roughly a 65% increase or a 40% decrease."""

    min_divergence: float = Field(default=0.5, ge=0.0, le=1.0)
    """Prefix divergence required of a string bound, on the same fallback path."""

    min_population: NonNegInt = 100
    """Row count a table must have reached, at some point in its history, to be tested.

    Below it the statistics are noise and every segment is a small cell. Measured
    against the largest snapshot rather than the latest, so that a table collapsing to
    nothing is still reported -- see :func:`_usable`."""

    min_history: NonNegInt = 3
    """Snapshots required before any detector will speak.

    Three, not two, and the reason is the golden fixture. A table whose ``order_id``
    prefix advances with every load shows a large change at every snapshot. With two
    snapshots there is one transition and nothing to compare it against, so that
    perfectly normal advance looks exactly like drift. The third snapshot is what makes
    "this changed" separable from "this always changes"."""


DEFAULT_CONFIG: Final[DetectorConfig] = DetectorConfig()


@dataclass(frozen=True, slots=True)
class DeltaVerdict:
    """The outcome of testing one series of changes.

    ``p_value`` is ``None`` when the history was too short for a robust z. That is not
    the same as a large p-value and callers must not substitute one: a detector that
    reported 1.0 where it meant "cannot say" would be handing L5 a hypothesis it never
    actually tested.
    """

    latest: float
    baseline: float
    z_score: float | None
    p_value: float | None
    fired: bool

    @property
    def score(self) -> float:
        """Detector-local ranking score. Not comparable across detectors until L5."""
        if self.p_value is not None:
            return -math.log10(max(self.p_value, 1e-300))
        return abs(self.latest)


def evaluate_deltas(
    deltas: Sequence[float], *, threshold: float, config: DetectorConfig
) -> DeltaVerdict | None:
    """Test the last change in ``deltas`` against the ones before it.

    Two regimes, and which one applies is decided by how much history there is, never by
    which one gives a more interesting answer:

    * **Enough history** -- a robust z of the latest change against the previous ones,
      converted to a two-sided p-value. Median and MAD, so one previous spike does not
      hide the next one.
    * **Too little history** -- the latest change must clear ``threshold`` in absolute
      terms *and* be at least :data:`_RELATIVE_FLOOR` times the largest previous change.
      The second condition is what stops a steadily advancing identifier prefix from
      being reported every week.

    Returns ``None`` when there is not even one change to test.
    """
    if not deltas:
        return None
    latest = deltas[-1]
    prior = list(deltas[:-1])
    if not math.isfinite(latest):
        return None

    if not prior:
        # One transition and nothing to compare it against. Reporting it would flag
        # every table that changes on a schedule, which is most of them.
        return DeltaVerdict(latest=latest, baseline=0.0, z_score=None, p_value=None, fired=False)

    z_score = robust_z(value=latest, baseline=prior)
    if z_score is not None:
        p_value = two_sided_p(z_score)
        return DeltaVerdict(
            latest=latest,
            baseline=_median_or_zero(prior),
            z_score=z_score,
            p_value=p_value,
            fired=p_value <= config.max_p_value,
        )

    largest_prior = max((abs(item) for item in prior), default=0.0)
    fired = abs(latest) >= threshold and abs(latest) >= _RELATIVE_FLOOR * largest_prior
    return DeltaVerdict(
        latest=latest, baseline=largest_prior, z_score=None, p_value=None, fired=fired
    )


def _median_or_zero(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


# --------------------------------------------------------------------------------------
# Candidate assembly
# --------------------------------------------------------------------------------------


def _probe_spec(
    *,
    source: SourceRef,
    kind: ProbeKind,
    columns: tuple[Tainted[str], ...],
    segment: Segment,
    as_of: Instant,
    seed: int,
) -> ProbeSpec:
    """The probe spec an L-1 measurement corresponds to.

    A metadata read is still a measurement, and invariant 7 wants every pattern to name
    the measurement that produced it. Building a real ``ProbeSpec`` -- rather than
    inventing a probe key -- means a replay can take this spec, hand it to an adapter
    and get the same numbers back.

    ``probe_id`` is a hash rather than a readable string, because the readable version
    would be ``bounds_drift:customer_email`` and that is a customer column name in an
    untainted field.
    """
    identity = canonical_json(
        {
            "detector_layer": "l-1",
            "kind": kind.value,
            "source_id": str(source.source_id),
            "columns": sorted(column.reveal() for column in columns),
            "segment": str(segment.key),
        }
    )
    return ProbeSpec(
        probe_id=ProbeId(content_hash(identity, prefix="l1")),
        kind=kind,
        spec_version=DETECTOR_VERSION,
        source=source,
        columns=columns,
        segment=segment,
        budget=METADATA_PROBE_BUDGET,
        seed=seed,
        as_of=as_of,
    )


def _candidate_id(
    *, detector: str, probe_key: ProbeKey, snapshot_id: SnapshotId, segment: Segment
) -> CandidateId:
    """A deterministic id, so that ingesting the same finding twice yields one pattern.

    ``PatternStore`` law 1 requires exactly this. Nothing readable goes in: the segment
    contributes its key, which is already a hash.
    """
    return CandidateId(
        content_hash(
            canonical_json(
                {
                    "detector": detector,
                    "detector_version": int(DETECTOR_VERSION),
                    "probe_key": str(probe_key),
                    "snapshot_id": str(snapshot_id),
                    "segment": str(segment.key),
                }
            ),
            prefix="cnd",
        )
    )


def _build_candidate(
    *,
    detector: str,
    history: Sequence[SnapshotMetadata],
    segment: Segment,
    columns: tuple[Tainted[str], ...],
    probe_kind: ProbeKind,
    evidence: Sequence[Evidence],
    score: float,
    code_version: str,
    seed: int,
) -> Candidate:
    current, baseline = history[-1], history[-2]
    source = current.source
    spec = _probe_spec(
        source=source,
        kind=probe_kind,
        columns=columns,
        segment=segment,
        as_of=current.observed_at,
        seed=seed,
    )
    return Candidate(
        candidate_id=_candidate_id(
            detector=detector,
            probe_key=spec.key,
            snapshot_id=current.snapshot.snapshot_id,
            segment=segment,
        ),
        source_id=source.source_id,
        segment=segment,
        evidence=tuple(evidence),
        score=score,
        lineage=Lineage(
            probe_key=spec.key,
            snapshot_id=current.snapshot.snapshot_id,
            baseline_snapshot_id=baseline.snapshot.snapshot_id,
            detector=detector,
            detector_version=DETECTOR_VERSION,
            code_version=code_version,
            seed=seed,
        ),
        created_at=current.observed_at,
    )


def _evidence(
    *,
    kind: EvidenceKind,
    probe_key: ProbeKey,
    current: SnapshotMetadata,
    baseline: SnapshotMetadata,
    segment: Segment,
    columns: tuple[Tainted[str], ...],
    verdict: DeltaVerdict,
    metadata_fields: tuple[str, ...],
    population: int | None,
) -> Evidence:
    """One measured claim. Every number in it is a ``DERIVED_STATISTIC`` by construction.

    ``sketch_names`` carries the *catalog* fields the claim was computed from --
    ``manifest.lower_bound``, ``pg_stats.n_distinct`` -- which is what the brief means by
    naming exactly which metadata fields were used. They are our names for somebody
    else's schema, not customer column names, so they are plain strings.
    """
    return Evidence(
        kind=kind,
        probe_key=probe_key,
        snapshot_id=current.snapshot.snapshot_id,
        baseline_snapshot_id=baseline.snapshot.snapshot_id,
        segment=segment,
        columns=columns,
        statistic=derived_statistic(
            verdict.latest,
            source_id=current.source.source_id,
            snapshot_id=current.snapshot.snapshot_id,
            population=population,
        ),
        baseline=derived_statistic(
            verdict.baseline,
            source_id=current.source.source_id,
            snapshot_id=baseline.snapshot.snapshot_id,
            population=population,
        ),
        effect_size=derived_statistic(
            verdict.latest - verdict.baseline,
            source_id=current.source.source_id,
            snapshot_id=current.snapshot.snapshot_id,
            population=population,
        ),
        p_value=(
            None
            if verdict.p_value is None
            else derived_statistic(
                verdict.p_value,
                source_id=current.source.source_id,
                snapshot_id=current.snapshot.snapshot_id,
                population=population,
            )
        ),
        population=population,
        sketch_names=metadata_fields,
    )


def _column_segment(column: ColumnMetadata, operator: Operator) -> Segment:
    """A segment that names a column without quoting one of its values.

    ``NOT NULL`` is the exact population an Iceberg bound or an NDV describes; ``IS
    NULL`` is the exact population a null-rate shift is about. Both operators are
    nullary, so the segment carries no row value at all -- which is also what keeps two
    columns' candidates from colliding on the universe segment during dedup.
    """
    return Segment(predicates=(Predicate(column=column.ref.column, op=operator),))


def _usable(history: Sequence[SnapshotMetadata], config: DetectorConfig) -> bool:
    """Is this table worth testing at all?

    The population test looks at the *largest* row count in the history, not the
    current one. A table that has collapsed from a million rows to forty is the most
    interesting thing L-1 will see all week, and gating on the current count would
    silence exactly that case. The statistics that come out of the collapsed snapshot
    are a small cell -- and they are reported as one, in ``Evidence.population``, for
    the gate to suppress. Suppression is the gate's job; staying quiet is not this
    layer's way of doing it.
    """
    if len(history) < max(_MIN_SNAPSHOTS, config.min_history):
        return False
    counts = [snapshot.row_count.reveal() for snapshot in history if snapshot.row_count is not None]
    return not counts or max(counts) >= config.min_population


# --------------------------------------------------------------------------------------
# The six detectors
# --------------------------------------------------------------------------------------


def bounds_drift(
    history: Sequence[SnapshotMetadata],
    *,
    code_version: str,
    seed: int,
    config: DetectorConfig = DEFAULT_CONFIG,
) -> tuple[Candidate, ...]:
    """Column bounds moved more than their own history says they should.

    Metadata fields used: ``manifest.lower_bound``, ``manifest.upper_bound``.

    Numeric and temporal columns are measured twice -- the log of the range, and the
    movement of the midpoint in units of the previous range -- because a distribution
    can spread without moving and move without spreading. String columns are measured by
    prefix divergence on each bound separately.
    """
    if not _usable(history, config):
        return ()
    current, baseline = history[-1], history[-2]
    candidates: list[Candidate] = []
    for column in current.columns:
        series = [snapshot.column(column.ref.column.reveal()) for snapshot in history]
        if any(item is None for item in series):
            continue
        present = [item for item in series if item is not None]
        verdicts = _bounds_verdicts(present, config=config)
        fired = [
            (name, kind, fields, verdict)
            for name, kind, fields, verdict in verdicts
            if verdict.fired
        ]
        if not fired:
            continue
        segment = _column_segment(column, Operator.NOT_NULL)
        columns = (column.ref.column,)
        spec = _probe_spec(
            source=current.source,
            kind=ProbeKind.COLUMN_BOUNDS,
            columns=columns,
            segment=segment,
            as_of=current.observed_at,
            seed=seed,
        )
        population = column.value_count.reveal() if column.value_count is not None else None
        evidence = [
            _evidence(
                kind=kind,
                probe_key=spec.key,
                current=current,
                baseline=baseline,
                segment=segment,
                columns=columns,
                verdict=verdict,
                metadata_fields=fields,
                population=population,
            )
            for _, kind, fields, verdict in fired
        ]
        candidates.append(
            _build_candidate(
                detector=_BOUNDS_DRIFT,
                history=history,
                segment=segment,
                columns=columns,
                probe_kind=ProbeKind.COLUMN_BOUNDS,
                evidence=evidence,
                score=max(verdict.score for _, _, _, verdict in fired),
                code_version=code_version,
                seed=seed,
            )
        )
    return tuple(candidates)


def _bounds_verdicts(
    series: Sequence[ColumnMetadata], *, config: DetectorConfig
) -> tuple[tuple[str, EvidenceKind, tuple[str, ...], DeltaVerdict], ...]:
    """Build every delta series a column's bounds support, and test each one."""
    lows = [item.lower_bound.reveal() if item.lower_bound is not None else None for item in series]
    highs = [item.upper_bound.reveal() if item.upper_bound is not None else None for item in series]
    if any(value is None for value in lows) or any(value is None for value in highs):
        return ()

    numeric_lows = [as_axis(value) for value in lows]
    numeric_highs = [as_axis(value) for value in highs]
    results: list[tuple[str, EvidenceKind, tuple[str, ...], DeltaVerdict]] = []
    both_fields = ("manifest.lower_bound", "manifest.upper_bound")

    if all(value is not None for value in numeric_lows + numeric_highs):
        low_axis = [value for value in numeric_lows if value is not None]
        high_axis = [value for value in numeric_highs if value is not None]
        ranges = [high - low for low, high in zip(low_axis, high_axis, strict=True)]
        midpoints = [(high + low) / 2.0 for low, high in zip(low_axis, high_axis, strict=True)]

        range_deltas = [
            ratio
            for ratio in (
                log_ratio(value=ranges[index], baseline=ranges[index - 1])
                for index in range(1, len(ranges))
            )
            if ratio is not None
        ]
        if len(range_deltas) == len(ranges) - 1:
            verdict = evaluate_deltas(
                range_deltas, threshold=config.min_abs_log_ratio, config=config
            )
            if verdict is not None:
                results.append(("range", EvidenceKind.DISTRIBUTION_SHIFT, both_fields, verdict))

        moves = [
            (midpoints[index] - midpoints[index - 1]) / ranges[index - 1]
            for index in range(1, len(midpoints))
            if ranges[index - 1] > 0.0
        ]
        if len(moves) == len(midpoints) - 1:
            verdict = evaluate_deltas(moves, threshold=config.min_abs_log_ratio, config=config)
            if verdict is not None:
                results.append(("location", EvidenceKind.DISTRIBUTION_SHIFT, both_fields, verdict))
        return tuple(results)

    for name, values, field_name in (
        ("lower", lows, "manifest.lower_bound"),
        ("upper", highs, "manifest.upper_bound"),
    ):
        texts = [value for value in values if isinstance(value, str)]
        if len(texts) != len(values):
            continue
        divergences = [
            1.0 - prefix_similarity(texts[index - 1], texts[index])
            for index in range(1, len(texts))
        ]
        verdict = evaluate_deltas(divergences, threshold=config.min_divergence, config=config)
        if verdict is not None:
            results.append((name, EvidenceKind.DISTRIBUTION_SHIFT, (field_name,), verdict))
    return tuple(results)


def null_rate_shift(
    history: Sequence[SnapshotMetadata],
    *,
    code_version: str,
    seed: int,
    config: DetectorConfig = DEFAULT_CONFIG,
) -> tuple[Candidate, ...]:
    """A column started, or stopped, being null.

    Metadata fields used: ``manifest.null_value_counts``, ``manifest.record_count``
    (or ``pg_stats.null_frac`` and ``pg_class.reltuples``).

    A two-proportion z rather than a delta series, because both sides are exact counts
    and a real test is available. Silent data-quality collapse usually shows here first:
    an upstream join starts missing and a column quietly fills with nulls.
    """
    return _proportion_detector(
        history,
        detector=_NULL_RATE_SHIFT,
        kind=EvidenceKind.NULL_RATE_SHIFT,
        probe_kind=ProbeKind.NULL_RATE,
        operator=Operator.IS_NULL,
        metadata_fields=("manifest.null_value_counts", "manifest.record_count"),
        counts_of=lambda column: (column.null_count, column.row_count),
        code_version=code_version,
        seed=seed,
        config=config,
    )


def ndv_ratio_shift(
    history: Sequence[SnapshotMetadata],
    *,
    code_version: str,
    seed: int,
    config: DetectorConfig = DEFAULT_CONFIG,
) -> tuple[Candidate, ...]:
    """The distinct-to-row ratio of a column moved.

    Metadata fields used: ``puffin.apache-datasketches-theta-v1.ndv`` (or
    ``pg_stats.n_distinct``) and ``manifest.record_count``.

    Cardinality is where novel abuse shows up cheaply: a fraud ring reusing one device
    across many accounts collapses the ratio, and a bot minting identifiers inflates it.
    """
    return _proportion_detector(
        history,
        detector=_NDV_RATIO_SHIFT,
        kind=EvidenceKind.CARDINALITY_SHIFT,
        probe_kind=ProbeKind.DISTINCT_COUNT,
        operator=Operator.NOT_NULL,
        metadata_fields=("puffin.ndv", "manifest.record_count"),
        counts_of=lambda column: (column.distinct_estimate, column.row_count),
        code_version=code_version,
        seed=seed,
        config=config,
    )


def _proportion_detector(
    history: Sequence[SnapshotMetadata],
    *,
    detector: str,
    kind: EvidenceKind,
    probe_kind: ProbeKind,
    operator: Operator,
    metadata_fields: tuple[str, ...],
    counts_of: Callable[[ColumnMetadata], tuple[Tainted[int] | None, Tainted[int] | None]],
    code_version: str,
    seed: int,
    config: DetectorConfig,
) -> tuple[Candidate, ...]:
    """Shared body for the two detectors that compare a count against a denominator."""
    if not _usable(history, config):
        return ()
    current, baseline = history[-1], history[-2]
    candidates: list[Candidate] = []
    for column in current.columns:
        previous = baseline.column(column.ref.column.reveal())
        if previous is None:
            continue
        counts = _proportion_counts(column, previous, counts_of)
        if counts is None:
            continue
        successes_a, total_a, successes_b, total_b = counts
        z_score = two_proportion_z(
            successes_a=successes_a,
            total_a=total_a,
            successes_b=successes_b,
            total_b=total_b,
        )
        if z_score is None:
            continue
        p_value = two_sided_p(z_score)
        if p_value > config.max_p_value:
            continue
        verdict = DeltaVerdict(
            latest=successes_a / total_a,
            baseline=successes_b / total_b,
            z_score=z_score,
            p_value=p_value,
            fired=True,
        )
        segment = _column_segment(column, operator)
        columns = (column.ref.column,)
        spec = _probe_spec(
            source=current.source,
            kind=probe_kind,
            columns=columns,
            segment=segment,
            as_of=current.observed_at,
            seed=seed,
        )
        candidates.append(
            _build_candidate(
                detector=detector,
                history=history,
                segment=segment,
                columns=columns,
                probe_kind=probe_kind,
                evidence=[
                    _evidence(
                        kind=kind,
                        probe_key=spec.key,
                        current=current,
                        baseline=baseline,
                        segment=segment,
                        columns=columns,
                        verdict=verdict,
                        metadata_fields=metadata_fields,
                        population=total_a,
                    )
                ],
                score=verdict.score,
                code_version=code_version,
                seed=seed,
            )
        )
    return tuple(candidates)


def _proportion_counts(
    column: ColumnMetadata,
    previous: ColumnMetadata,
    counts_of: Callable[[ColumnMetadata], tuple[Tainted[int] | None, Tainted[int] | None]],
) -> tuple[int, int, int, int] | None:
    parts = (*counts_of(column), *counts_of(previous))
    if any(part is None for part in parts):
        return None
    successes_a, total_a, successes_b, total_b = (
        part.reveal() for part in parts if part is not None
    )
    if total_a <= 0 or total_b <= 0:
        return None
    if not (0 <= successes_a <= total_a and 0 <= successes_b <= total_b):
        return None
    return successes_a, total_a, successes_b, total_b


def row_volume_anomaly(
    history: Sequence[SnapshotMetadata],
    *,
    code_version: str,
    seed: int,
    config: DetectorConfig = DEFAULT_CONFIG,
) -> tuple[Candidate, ...]:
    """The table's row count moved unlike it has moved before.

    Metadata fields used: ``manifest.record_count`` (or ``pg_class.reltuples``).

    Measured in log space, so a doubling and a halving are the same size of surprise,
    and on the second difference, so a table that grows steadily is not reported every
    snapshot for growing steadily.
    """
    if not _usable(history, config):
        return ()
    counts = [snapshot.row_count for snapshot in history]
    if any(count is None for count in counts):
        return ()
    values = [float(count.reveal()) for count in counts if count is not None]
    deltas = [
        ratio
        for ratio in (
            log_ratio(value=values[index], baseline=values[index - 1])
            for index in range(1, len(values))
        )
        if ratio is not None
    ]
    if len(deltas) != len(values) - 1:
        return ()
    verdict = evaluate_deltas(deltas, threshold=config.min_abs_log_ratio, config=config)
    if verdict is None or not verdict.fired:
        return ()
    return (
        _table_candidate(
            history=history,
            detector=_ROW_VOLUME_ANOMALY,
            probe_kind=ProbeKind.ROW_COUNT,
            verdicts=(("rows", EvidenceKind.RATE_CHANGE, ("manifest.record_count",), verdict),),
            code_version=code_version,
            seed=seed,
        ),
    )


def file_layout_anomaly(
    history: Sequence[SnapshotMetadata],
    *,
    code_version: str,
    seed: int,
    config: DetectorConfig = DEFAULT_CONFIG,
) -> tuple[Candidate, ...]:
    """The shape of the table's files changed.

    Metadata fields used: ``manifest.file_count``, ``manifest.file_size_in_bytes``.

    A sudden change in file count or mean file size almost always means an upstream
    pipeline changed -- a new writer, a different batch size, a backfill replaying
    history. It is the cheapest early warning in the system, and it is the one that most
    often *explains away* a drift another detector found, which is why L3 wants it.
    """
    if not _usable(history, config):
        return ()
    layouts = [snapshot.layout for snapshot in history]
    if any(layout is None for layout in layouts):
        return ()
    present = [layout for layout in layouts if layout is not None]

    verdicts: list[tuple[str, EvidenceKind, tuple[str, ...], DeltaVerdict]] = []
    for name, kind, fields, values in (
        (
            "file_count",
            EvidenceKind.RATE_CHANGE,
            ("manifest.file_count",),
            [float(layout.file_count.reveal()) for layout in present],
        ),
        (
            "mean_file_bytes",
            EvidenceKind.DISTRIBUTION_SHIFT,
            ("manifest.file_size_in_bytes",),
            [layout.mean_file_bytes.reveal() for layout in present],
        ),
    ):
        deltas = [
            ratio
            for ratio in (
                log_ratio(value=values[index], baseline=values[index - 1])
                for index in range(1, len(values))
            )
            if ratio is not None
        ]
        if len(deltas) != len(values) - 1:
            continue
        verdict = evaluate_deltas(deltas, threshold=config.min_abs_log_ratio, config=config)
        if verdict is not None and verdict.fired:
            verdicts.append((name, kind, fields, verdict))

    if not verdicts:
        return ()
    return (
        _table_candidate(
            history=history,
            detector=_FILE_LAYOUT_ANOMALY,
            probe_kind=ProbeKind.ROW_COUNT,
            verdicts=tuple(verdicts),
            code_version=code_version,
            seed=seed,
        ),
    )


def schema_change(
    history: Sequence[SnapshotMetadata],
    *,
    code_version: str,
    seed: int,
    config: DetectorConfig = DEFAULT_CONFIG,
) -> tuple[Candidate, ...]:
    """Columns were added, removed or retyped between the last two snapshots.

    Metadata fields used: ``schema.columns``, ``schema.logical_type``.

    Not a statistical claim -- it either happened or it did not -- so it reports a
    p-value of 0.0 and an effect size that counts the columns involved. It is here
    because a schema change explains away most of what the other five detectors will
    say about the same snapshot, and L3 needs to see it first.

    The names of added or removed columns are *not* reported. A column name is a
    disclosure on its own (``patient_hiv_status``), and a count of changed columns is
    enough for a human to go and look.
    """
    if len(history) < max(_MIN_SNAPSHOTS, config.min_history):
        return ()
    current, baseline = history[-1], history[-2]
    now = {column.ref.column.reveal(): column.logical_type for column in current.columns}
    before = {column.ref.column.reveal(): column.logical_type for column in baseline.columns}
    added = len(now.keys() - before.keys())
    removed = len(before.keys() - now.keys())
    retyped = sum(1 for name in now.keys() & before.keys() if now[name] != before[name])
    changed = added + removed + retyped
    if changed == 0:
        return ()
    verdict = DeltaVerdict(
        latest=float(changed), baseline=0.0, z_score=None, p_value=0.0, fired=True
    )
    return (
        _table_candidate(
            history=history,
            detector=_SCHEMA_CHANGE,
            probe_kind=ProbeKind.COLUMN_BOUNDS,
            verdicts=(
                (
                    "columns_changed",
                    EvidenceKind.RATE_CHANGE,
                    ("schema.columns", "schema.logical_type"),
                    verdict,
                ),
            ),
            code_version=code_version,
            seed=seed,
        ),
    )


def _table_candidate(
    *,
    history: Sequence[SnapshotMetadata],
    detector: str,
    probe_kind: ProbeKind,
    verdicts: tuple[tuple[str, EvidenceKind, tuple[str, ...], DeltaVerdict], ...],
    code_version: str,
    seed: int,
) -> Candidate:
    """Assemble a candidate about the table as a whole.

    The segment is the universe, which is correct and not a collision risk: only one
    candidate per detector per snapshot comes out of a table-level detector.
    """
    current, baseline = history[-1], history[-2]
    segment = Segment(
        population=current.row_count.reveal() if current.row_count is not None else None
    )
    spec = _probe_spec(
        source=current.source,
        kind=probe_kind,
        columns=(),
        segment=segment,
        as_of=current.observed_at,
        seed=seed,
    )
    population = current.row_count.reveal() if current.row_count is not None else None
    evidence = [
        _evidence(
            kind=evidence_kind,
            probe_key=spec.key,
            current=current,
            baseline=baseline,
            segment=segment,
            columns=(),
            verdict=verdict,
            metadata_fields=fields,
            population=population,
        )
        for _, evidence_kind, fields, verdict in verdicts
    ]
    return _build_candidate(
        detector=detector,
        history=history,
        segment=segment,
        columns=(),
        probe_kind=probe_kind,
        evidence=evidence,
        score=max(verdict.score for _, _, _, verdict in verdicts),
        code_version=code_version,
        seed=seed,
    )


DETECTORS: Final[tuple[Callable[..., tuple[Candidate, ...]], ...]] = (
    bounds_drift,
    null_rate_shift,
    ndv_ratio_shift,
    row_volume_anomaly,
    file_layout_anomaly,
    schema_change,
)
"""Every L-1 detector, in a fixed order. Order does not affect output -- the result is
sorted -- but a fixed tuple makes "run them all" reproducible as the code changes."""


def run_metadata_detectors(
    history: Sequence[SnapshotMetadata],
    *,
    code_version: str,
    seed: int,
    config: DetectorConfig = DEFAULT_CONFIG,
) -> tuple[Candidate, ...]:
    """Run all six over one metadata time-series.

    Deterministic in every sense invariant 7 asks for: same history, same seed, same
    config gives the same candidates in the same order. The ordering is by candidate id,
    which is a hash, so it does not depend on which detector happened to run first.
    """
    found: list[Candidate] = []
    for detector in DETECTORS:
        found.extend(detector(history, code_version=code_version, seed=seed, config=config))
    return tuple(sorted(found, key=lambda candidate: candidate.candidate_id))
