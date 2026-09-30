"""Discovery scoring: precision@k, time-to-detection, novelty, cost and stability.

WHAT "PRECISION@K" MEANS HERE, EXACTLY
-------------------------------------
Only over label-covered segments. A discovery system's ranked list contains three kinds of
item: things a reviewer confirmed, things a reviewer rejected, and things nobody has looked
at. Scoring the third kind as wrong makes the number meaningless, and scoring it as right
makes it a lie. So the ranking is restricted to segments the dataset's own ground truth has
an opinion about, and the share of the list that was scoreable is reported alongside the
precision. A precision@50 of 0.40 computed over four covered items is not a precision@50,
and the ``coverage`` fields are what stop it being presented as one.

THE HEADLINE NUMBER IS TIME-TO-DETECTION
----------------------------------------
Precision is the number a demo shows. Time-to-detection is the number that decides whether
this product exists: did the system surface a known event *before* the organisation
actually caught it. It is reported in seconds, signed, and negative is good -- the system
was ahead. Where the dataset's label delay is fabricated (see
:mod:`godwit_replay.datasets`), the caveat travels with the number rather than living in a
methods section.

STABILITY IS A SCORE, NOT A TEST
--------------------------------
"Two identical runs agree exactly" is in the objective function, so it is measured here and
recorded in the score, not only asserted in a test. A run that is not reproducible has no
precision, because the number would be different tomorrow.
"""

from __future__ import annotations

import math
import statistics
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Final, cast

from godwit_contracts.common import (
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    ScalarValue,
)
from godwit_contracts.cost import CostSpend
from godwit_contracts.segment import Operator, Predicate, Segment, segment_key
from godwit_contracts.taint import Acquisition, data_value, schema_name
from godwit_source.metadata import SnapshotMetadata
from pydantic import Field

from godwit_replay.driver import ReplayRun

__all__ = [
    "K_VALUES",
    "DiscoveryScore",
    "SegmentTruth",
    "StabilityCheck",
    "TruthSet",
    "naive_threshold_keys",
    "score_discovery",
    "truth_from_golden_manifest",
]

K_VALUES: Final[tuple[int, ...]] = (10, 25, 50, 100)
"""The review capacities from the objective function. k is a human's day, not a knob."""

_GOLDEN_TIMING_CAVEAT: Final[str] = (
    "the golden fixture has no label_time, so time-to-detection is measured against the "
    "snapshot the drift was introduced at, not against a real investigation date"
)

_TRIPLE_LENGTH: Final[int] = 3

_USD_PLACES: Final[Decimal] = Decimal("0.0001")
"""Four decimal places. Cost per pattern at the metadata tier is fractions of a cent."""

_NULL_RATE_ALARM: Final[float] = 0.5
"""Null fraction at which the naive rule shouts. Half a column missing is not subtle, which
is the point: the naive rule is supposed to be something anyone would have written."""


class SegmentTruth(GodwitModel):
    """What is actually true about one segment, and when the world found out.

    ``segment_key`` is a hash, so a truth set carries no row value and can be committed to a
    repository. Building one requires the values, which is why
    :func:`truth_from_golden_manifest` runs in the data plane and returns only keys.
    """

    segment_key: str
    is_real: bool
    is_novel: bool = Field(
        default=False,
        description="True when a naive rule would not have found this. Measured against "
        "naive_threshold_keys rather than asserted.",
    )
    known_at: Instant | None = Field(
        default=None,
        description="When the organisation actually caught this, from the dataset's own "
        "label_time. None means time-to-detection is not measurable for this segment.",
    )
    note: str = ""


class TruthSet(GodwitModel):
    """The ground truth for one dataset, plus how honest its timing is."""

    dataset: str
    segments: tuple[SegmentTruth, ...]
    columns_of_interest: tuple[str, ...] = Field(
        default=(),
        description="Columns the documented drift lives in. Used for column-level credit, "
        "which is reported separately from precision and never folded into it.",
    )
    label_time_is_fabricated: bool = False
    caveats: tuple[str, ...] = ()

    @property
    def by_key(self) -> Mapping[str, SegmentTruth]:
        """Index by segment key."""
        return {item.segment_key: item for item in self.segments}

    @property
    def real_keys(self) -> frozenset[str]:
        """Segments that are genuinely there."""
        return frozenset(item.segment_key for item in self.segments if item.is_real)


class StabilityCheck(GodwitModel):
    """Whether two runs of the same configuration produced the same thing.

    Two digests, because they answer different questions. ``strict_agree`` is bit-identity
    within one materialisation of the data. ``content_agree`` survives a reload, which
    renumbers every Iceberg snapshot id; it is the one a CI job on freshly loaded data can
    assert.
    """

    strict_digests: tuple[ContentHash, ...]
    content_digests: tuple[ContentHash, ...]

    @property
    def strict_agree(self) -> bool:
        """True when every run produced byte-identical output."""
        return len(set(self.strict_digests)) <= 1

    @property
    def content_agree(self) -> bool:
        """True when every run produced the same findings, ignoring minted identifiers."""
        return len(set(self.content_digests)) <= 1

    @property
    def agree(self) -> bool:
        """The objective-function question: do two identical runs agree exactly."""
        return self.strict_agree and self.content_agree


class DiscoveryScore(GodwitModel):
    """Everything the objective function asks of discovery, in one record."""

    dataset: str
    handler: str
    config_name: str
    run_digest: ContentHash
    content_digest: ContentHash

    surfaced_total: NonNegInt = Field(description="Distinct candidates the run emitted.")
    surfaced_covered: NonNegInt = Field(
        description="Of those, how many fall on a segment the truth set has an opinion "
        "about. Every precision below is computed over these and only these."
    )
    precision_at_k: Mapping[str, float] = Field(
        description="Keyed by k as a string. NaN where fewer than one covered item exists."
    )
    considered_at_k: Mapping[str, int] = Field(
        description="How many covered items each precision was actually computed over. A "
        "precision@100 over 4 items is reported as such rather than dressed up."
    )

    real_surfaced: NonNegInt = 0
    real_total: NonNegInt = 0
    surfaced_on_truth_columns: tuple[str, ...] = Field(
        default=(),
        description="Columns named in the truth set that the run surfaced *something* about, "
        "on a segment the truth set does not list.\n\n"
        "This is the cross-layer case and it is reported separately for a reason. A metadata "
        "detector watching Iceberg bounds can see the shadow of a segment-level divergence -- "
        "the amount column's range tripling because one segment's amounts moved -- without "
        "ever naming that segment. Segment-key matching scores that as a miss, which "
        "understates the system; folding it into precision would overstate it. So it is a "
        "third number, and a reader decides.",
    )
    false_positives_on_controls: tuple[str, ...] = Field(
        default=(),
        description="Segment keys the truth set marks NOT real that the run surfaced. On "
        "the golden fixture this is the documented false-positive control.",
    )

    time_to_detection_seconds: Mapping[str, float] = Field(
        default_factory=dict,
        description="Per real segment, signed seconds from when the world knew to when we "
        "surfaced it. Negative means we were ahead, which is the point of the product.",
    )
    headline_time_to_detection_seconds: float | None = Field(
        default=None, description="Median of the above. THE headline number."
    )
    time_to_detection_is_fabricated: bool = Field(
        default=False,
        description="True when the dataset's label delay was invented by us. The number "
        "above is then a measurement of our own assumption.",
    )

    novelty_rate: float | None = Field(
        default=None,
        description="Share of real segments we surfaced that a naive threshold rule did "
        "not. None when there was nothing real to compare.",
    )
    naive_surfaced_real: NonNegInt = 0

    cost: CostSpend = Field(default_factory=CostSpend.zero)
    usd_per_confirmed: Decimal | None = None
    bytes_per_confirmed: float | None = Field(
        default=None,
        description="The metadata tier costs no money, so dollars-per-pattern is zero and "
        "uninformative. Bytes scanned per confirmed pattern is the honest cost figure at "
        "L-1, and it should be very small: the whole tier reads manifests.",
    )

    stability: StabilityCheck
    caveats: tuple[str, ...] = ()

    @property
    def is_reproducible(self) -> bool:
        """No reproducibility, no score."""
        return self.stability.agree


def _universe_key() -> str:
    return str(segment_key(Segment()))


def naive_threshold_keys(
    history: Sequence[SnapshotMetadata],
    *,
    log_ratio_threshold: float = 0.5,
) -> frozenset[str]:
    """The naive rule novelty is measured against: "row count moved a lot".

    Deliberately stupid, and deliberately the rule a competent engineer would write in an
    afternoon: if the row count changed by more than ``log_ratio_threshold`` in log units
    against the previous snapshot, flag the whole table. Anything Godwit finds that this
    also finds is not novel, whatever the marketing says.

    Returns segment keys so the result can sit in a record with no row value in it.
    """
    flagged: set[str] = set()
    previous: float | None = None
    for item in history:
        count = None if item.row_count is None else float(item.row_count.reveal())
        if count is not None and count > 0.0:
            if (
                previous is not None
                and previous > 0.0
                and (abs(math.log(count / previous)) > log_ratio_threshold)
            ):
                flagged.add(_universe_key())
            previous = count
        for column in item.columns:
            fraction = column.null_fraction
            if fraction is not None and fraction.reveal() > _NULL_RATE_ALARM:
                flagged.add(
                    str(
                        Segment(
                            predicates=(
                                Predicate(
                                    column=schema_name(column.ref.column.reveal()),
                                    op=Operator.IS_NULL,
                                ),
                            )
                        ).key
                    )
                )
    return frozenset(flagged)


def truth_from_golden_manifest(
    manifest: Mapping[str, object],
    *,
    dataset: str = "golden-drift",
    known_at: Instant | None = None,
) -> TruthSet:
    """Build a truth set from ``tests/golden/drift_table/manifest.json``. Data plane.

    The manifest states the drift and the false-positive control in predicate form, so the
    truth set is the fixture's own claim rather than the harness's opinion. Predicate values
    are revealed here in order to compute keys and are not retained: what comes back is
    hashes.
    """
    drift = manifest.get("documented_drift")
    if not isinstance(drift, Mapping):
        raise TypeError("manifest has no documented_drift mapping")
    segments: list[SegmentTruth] = []
    columns: set[str] = set()
    for entry in _entries(drift.get("segments")):
        segment = _segment_from_triples(entry.get("predicates"))
        columns.update(predicate.column.reveal() for predicate in segment.predicates)
        segments.append(
            SegmentTruth(
                segment_key=str(segment.key),
                is_real=True,
                known_at=known_at,
                note=str(entry.get("what_changed", "")),
            )
        )
    for entry in _entries(drift.get("unchanged_controls")):
        segments.append(
            SegmentTruth(
                segment_key=str(_segment_from_triples(entry.get("predicates")).key),
                is_real=False,
                note=str(entry.get("note", "")),
            )
        )
    return TruthSet(
        dataset=dataset,
        segments=tuple(segments),
        columns_of_interest=tuple(sorted(columns)),
        label_time_is_fabricated=False,
        caveats=(_GOLDEN_TIMING_CAVEAT,),
    )


def _entries(value: object) -> tuple[Mapping[str, object], ...]:
    """The mappings in a manifest list, refusing anything else rather than guessing."""
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise TypeError("expected a list of manifest entries")
    found: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError("a manifest entry is not a mapping")
        found.append(item)
    return tuple(found)


def _segment_from_triples(triples: object) -> Segment:
    """``[[column, op, value], ...]`` from a manifest into a Segment. Data plane."""
    if not isinstance(triples, Sequence) or isinstance(triples, str | bytes):
        raise TypeError("expected a list of [column, operator, value] triples")
    predicates: list[Predicate] = []
    for triple in triples:
        if (
            not isinstance(triple, Sequence)
            or isinstance(triple, str | bytes)
            or len(triple) != _TRIPLE_LENGTH
        ):
            raise TypeError("a predicate triple must be [column, operator, value]")
        column, operator = str(triple[0]), str(triple[1])
        # The cast is the one narrowing this function needs: a manifest is JSON, so the
        # value arrives as object. Pydantic validates it inside Predicate a line later, and
        # rejects anything canonical_scalar cannot render.
        value = cast("ScalarValue", triple[2])
        predicates.append(
            Predicate(
                column=schema_name(column),
                op=Operator(operator),
                values=(
                    data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE, column=column),
                ),
            )
        )
    return Segment(predicates=tuple(predicates))


def score_discovery(
    run: ReplayRun,
    *,
    truth: TruthSet,
    naive_keys: frozenset[str] = frozenset(),
    repeat_runs: Sequence[ReplayRun] = (),
    detection_reference: Mapping[str, Instant] | None = None,
) -> DiscoveryScore:
    """Score one run against a truth set.

    ``repeat_runs`` are further runs of the same configuration, used for the stability
    check. Passing none means the score records a single-run stability, which trivially
    agrees and is reported as such rather than as a pass.

    ``detection_reference`` overrides ``SegmentTruth.known_at`` per segment, for datasets
    whose reference instant is computed rather than declared.
    """
    ranked = run.ranked()
    index = truth.by_key
    covered = [item for item in ranked if str(item.segment.key) in index]

    precision: dict[str, float] = {}
    considered: dict[str, int] = {}
    for k in K_VALUES:
        window = covered[:k]
        considered[str(k)] = len(window)
        precision[str(k)] = (
            float("nan")
            if not window
            else sum(1 for item in window if index[str(item.segment.key)].is_real) / len(window)
        )

    surfaced_keys = {str(item.segment.key) for item in ranked}
    real_keys = truth.real_keys
    real_surfaced = sorted(real_keys & surfaced_keys)
    controls = sorted(key for key in surfaced_keys if key in index and not index[key].is_real)

    first = run.first_surfaced()
    deltas: dict[str, float] = {}
    for key in real_surfaced:
        reference = (
            detection_reference.get(key) if detection_reference is not None else index[key].known_at
        )
        if reference is None:
            continue
        deltas[key] = (first[key] - reference).total_seconds()
    headline = statistics.median(deltas.values()) if deltas else None

    wanted_columns = frozenset(truth.columns_of_interest)
    touched = sorted(
        {
            column.reveal()
            for item in ranked
            for evidence in item.evidence
            for column in evidence.columns
            if column.reveal() in wanted_columns
        }
    )

    naive_real = sorted(real_keys & naive_keys)
    novelty = (
        None
        if not real_surfaced
        else sum(1 for key in real_surfaced if key not in naive_keys) / len(real_surfaced)
    )

    confirmed = len(real_surfaced)
    usd_per = (
        None if confirmed == 0 else (run.total_cost.usd / Decimal(confirmed)).quantize(_USD_PLACES)
    )
    bytes_per = None if confirmed == 0 else run.total_cost.bytes_scanned / confirmed

    runs = (run, *repeat_runs)
    stability = StabilityCheck(
        strict_digests=tuple(item.digest for item in runs),
        content_digests=tuple(item.content_digest for item in runs),
    )

    return DiscoveryScore(
        dataset=run.dataset,
        handler=run.handler,
        config_name=run.config.name,
        run_digest=run.digest,
        content_digest=run.content_digest,
        surfaced_total=len(ranked),
        surfaced_covered=len(covered),
        precision_at_k=precision,
        considered_at_k=considered,
        real_surfaced=confirmed,
        real_total=len(real_keys),
        surfaced_on_truth_columns=tuple(touched),
        false_positives_on_controls=tuple(controls),
        time_to_detection_seconds=deltas,
        headline_time_to_detection_seconds=headline,
        time_to_detection_is_fabricated=truth.label_time_is_fabricated,
        novelty_rate=novelty,
        naive_surfaced_real=len(naive_real),
        cost=run.total_cost,
        usd_per_confirmed=usd_per,
        bytes_per_confirmed=bytes_per,
        stability=stability,
        caveats=truth.caveats,
    )
