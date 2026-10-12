"""What a detector says: typed findings, refusals, and the conversion to contract candidates.

A :class:`Finding` is richer than the contract's ``Evidence`` on purpose. Two readers
shaped it:

* **A11, the feature factory**, turns findings into feature definitions mechanically.
  So segment, columns, window, direction and method are structured fields, never prose.
  ``(segment, columns, method, window.baseline_policy, direction)`` is enough to write
  the feature "share of rows in this segment, this week versus the same week of the
  last four cycles, flagged when it rises".
* **A reviewer with the identities suppressed.** Every value that came out of a row --
  a heavy-hitter key, a category label, a fan-in entity -- lives in exactly two places:
  ``identities`` and ``Attribution.identity``. :meth:`Finding.without_identities` strips
  both, and every detector is tested to still produce a usable finding afterwards: the
  effect size, the direction, the p-value and the ``shape`` measures are derived
  statistics that say *how far* something moved without saying *which* value moved.

The segment still quotes values in its predicates (leak path 4) and the columns are
schema names (leak path 9). Neither is removed by suppression; both are the gate's job.

``Evidence`` has no field for any of the extra structure, and ``Candidate`` none for the
number of tests a run performed. See
``docs/change-requests/CR-A7-evidence-has-no-structured-detail.md``.
"""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Self

from godwit_contracts.common import (
    CandidateId,
    GodwitModel,
    Instant,
    NonNegInt,
    ProbeKey,
    SnapshotId,
    SourceId,
    canonical_json,
    content_hash,
)
from godwit_contracts.discovery import Candidate, Evidence, EvidenceKind, Lineage
from godwit_contracts.segment import Segment
from godwit_contracts.taint import Sensitivity, Tainted, derived_statistic
from pydantic import model_validator

_PART_LIMIT = 1000

__all__ = [
    "Attribution",
    "DetectionResult",
    "Direction",
    "Finding",
    "Measure",
    "Refusal",
    "RefusalReason",
    "Window",
    "lineage_version",
    "measure",
    "to_candidate",
]


class Direction(StrEnum):
    """Which way the finding points. A11 turns this into the sign of a feature."""

    UP = "up"
    DOWN = "down"
    CHANGED = "changed"
    """Two-sided: the shape moved, with no single direction (a categorical mix)."""
    APPEARED = "appeared"
    """Something is present now that was absent from the reference."""
    VANISHED = "vanished"
    """Something present in the reference is absent now."""


class Measure(GodwitModel):
    """A named derived statistic with its unit. Never a row value."""

    name: str
    unit: str
    value: Tainted[float]

    @model_validator(mode="after")
    def _is_a_statistic(self) -> Self:
        if self.value.sensitivity is not Sensitivity.DERIVED_STATISTIC:
            raise ValueError(f"measure {self.name!r} must be a DERIVED_STATISTIC")
        return self


def measure(name: str, value: float, unit: str, *, population: int | None = None) -> Measure:
    """Build a :class:`Measure`. ``name`` and ``unit`` are our vocabulary, never data."""
    return Measure(
        name=name, unit=unit, value=derived_statistic(float(value), population=population)
    )


class Window(GodwitModel):
    """When the finding was measured, and against what."""

    snapshot_id: SnapshotId
    at: Instant
    baseline_policy: str
    """``fixed(<snapshot>)``, ``trailing(points=n)``, ``seasonal(period=p,cycles=c)`` or
    ``cross_section`` for detectors that compare peers at one instant."""
    baseline_snapshot_ids: tuple[SnapshotId, ...] = ()
    baseline_from: Instant | None = None
    baseline_to: Instant | None = None


class Attribution(GodwitModel):
    """How much one named component contributed to the finding.

    ``feature`` is our own label: a ``godwit_sketch`` feature-slot name, ``bin:3``,
    ``rank:2``, ``edge:0-2``. ``identity`` is the row value behind it when there is one,
    and is the thing suppression removes.
    """

    feature: str
    contribution: Tainted[float]
    identity: Tainted[str] | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.contribution.sensitivity is not Sensitivity.DERIVED_STATISTIC:
            raise ValueError("Attribution.contribution must be a DERIVED_STATISTIC")
        if self.identity is not None and self.identity.sensitivity is Sensitivity.DERIVED_STATISTIC:
            raise ValueError("Attribution.identity is a row value, never a statistic")
        return self


class Finding(GodwitModel):
    """One emitted claim, with everything needed to judge it without querying the source."""

    detector: str
    detector_version: str
    method: str
    """Which statistic inside the detector: ``psi``, ``hhi``, ``entrant``, ``welch``..."""
    settings_digest: str
    """Hash of the detector's settings. Replay needs the same settings as well as the
    same version; ``Lineage`` has no field for them."""
    kind: EvidenceKind

    probe_key: ProbeKey
    source_id: SourceId
    sketch_names: tuple[str, ...]
    segment: Segment
    columns: tuple[Tainted[str], ...] = ()
    window: Window
    direction: Direction

    statistic: Measure
    """The test statistic itself (chi-square, z, t...)."""
    baseline: Measure | None = None
    """The same quantity measured on the reference, when it has one."""
    effect: Measure
    """How far it moved, in interpretable units. The number to read first."""
    p_value: Tainted[float] | None
    p_value_note: str = ""
    """Why ``p_value`` is None, or a caveat on how it was computed. Our words, no values."""

    population: NonNegInt | None = None
    baseline_population: NonNegInt | None = None
    shape: tuple[Measure, ...] = ()
    """Identity-free statistics that keep the finding usable once identities are gone."""
    attribution: tuple[Attribution, ...] = ()
    identities: tuple[Tainted[str], ...] = ()
    score: float
    """Detector-local ranking score. Larger is more interesting. Not comparable across
    detectors until L5 calibrates it."""

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.p_value is None and not self.p_value_note:
            raise ValueError("a finding without a p-value must say why in p_value_note")
        if self.p_value is not None:
            if self.p_value.sensitivity is not Sensitivity.DERIVED_STATISTIC:
                raise ValueError("Finding.p_value must be a DERIVED_STATISTIC")
            if not 0.0 <= self.p_value.reveal() <= 1.0:
                raise ValueError("Finding.p_value must lie in [0, 1]")
        for identity in self.identities:
            if identity.sensitivity is Sensitivity.DERIVED_STATISTIC:
                raise ValueError("Finding.identities are row values, never statistics")
        if not math.isfinite(self.score):
            raise ValueError("Finding.score must be finite")
        return self

    @property
    def carries_identities(self) -> bool:
        """True if any row value other than the segment's predicates rides along."""
        return bool(self.identities) or any(a.identity is not None for a in self.attribution)

    def without_identities(self) -> Finding:
        """The same finding with every heavy-hitter key, label and entity removed."""
        return self.model_copy(
            update={
                "identities": (),
                "attribution": tuple(
                    item.model_copy(update={"identity": None}) for item in self.attribution
                ),
            }
        )


class RefusalReason(StrEnum):
    """Why a detector declined to test something. Refusing is a normal outcome."""

    THIN_SKETCH = "thin_sketch"
    """Population below the minimum support: where spurious findings are manufactured."""
    THIN_BASELINE = "thin_baseline"
    """Too few reference windows, or too few rows in them."""
    NO_BASELINE = "no_baseline"
    INCOMPARABLE = "incomparable"
    """Different codecs, or item keys hashed under different keys."""
    UNSUPPORTED_SKETCH = "unsupported_sketch"
    IRREGULAR_SERIES = "irregular_series"
    GAP = "gap"
    """The window under test received no data. A pipeline problem, not a drift."""
    TOO_FEW_PEERS = "too_few_peers"


class Refusal(GodwitModel):
    """A test the detector declined to run, and why. Carries no values."""

    detector: str
    reason: RefusalReason
    sketch_names: tuple[str, ...] = ()
    subject: str = ""
    """Which part was refused, in our labels: ``segment:3``, ``metric:mean_in_degree``."""


class DetectionResult(GodwitModel):
    """One detector run.

    ``tests`` is every hypothesis examined, including the ones that did not reach the
    emission threshold. L5 needs the full count to control the false-discovery rate
    honestly; counting only the emitted findings would understate it.
    """

    detector: str
    detector_version: str
    findings: tuple[Finding, ...] = ()
    tests: NonNegInt = 0
    refusals: tuple[Refusal, ...] = ()


def lineage_version(semver: str) -> int:
    """Encode ``MAJOR.MINOR.PATCH`` as the integer ``Lineage.detector_version`` holds.

    ``major * 1_000_000 + minor * 1_000 + patch``: lossless while minor and patch stay
    below 1000, and monotone, so a bump always produces a larger integer.
    """
    major, minor, patch = (int(part) for part in semver.split("."))
    if min(major, minor, patch) < 0 or max(minor, patch) >= _PART_LIMIT:
        raise ValueError(f"version {semver!r} does not fit the lineage encoding")
    return (major * _PART_LIMIT + minor) * _PART_LIMIT + patch


def _candidate_id(finding: Finding) -> CandidateId:
    identity = canonical_json(
        [
            finding.detector,
            finding.detector_version,
            finding.settings_digest,
            finding.method,
            str(finding.probe_key),
            str(finding.window.snapshot_id),
            list(finding.window.baseline_snapshot_ids),
            str(finding.segment.key),
            list(finding.sketch_names),
            [item.feature for item in finding.attribution],
        ]
    )
    return CandidateId(content_hash(identity, prefix="cand"))


def to_candidate(finding: Finding, *, code_version: str, seed: int) -> Candidate:
    """Project a finding onto the contract ``Candidate``.

    Lossy, and the losses are listed in the CR: direction, window range, method, shape
    and attribution have no home in ``Evidence``. ``baseline_snapshot_id`` gets the most
    recent reference window. ``created_at`` is the window's own instant -- nothing here
    reads a clock -- and the id is a hash of the finding's identity, so re-running a
    detector re-creates the same candidate rather than a near-duplicate.
    """
    baseline_id = (
        finding.window.baseline_snapshot_ids[-1] if finding.window.baseline_snapshot_ids else None
    )
    evidence = Evidence(
        kind=finding.kind,
        probe_key=finding.probe_key,
        snapshot_id=finding.window.snapshot_id,
        baseline_snapshot_id=baseline_id,
        segment=finding.segment,
        columns=finding.columns,
        statistic=finding.statistic.value,
        baseline=finding.baseline.value if finding.baseline is not None else None,
        effect_size=finding.effect.value,
        p_value=finding.p_value,
        population=finding.population,
        sketch_names=finding.sketch_names,
    )
    return Candidate(
        candidate_id=_candidate_id(finding),
        source_id=finding.source_id,
        segment=finding.segment,
        evidence=(evidence,),
        score=finding.score,
        lineage=Lineage(
            probe_key=finding.probe_key,
            snapshot_id=finding.window.snapshot_id,
            baseline_snapshot_id=baseline_id,
            detector=finding.detector,
            detector_version=lineage_version(finding.detector_version),
            code_version=code_version,
            seed=seed,
        ),
        created_at=finding.window.at,
    )
