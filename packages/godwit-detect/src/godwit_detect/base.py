"""The detector base classes and the few helpers every detector shares.

A detector here is a pure function wearing a class: settings in, sketches in, a
:class:`~godwit_detect.evidence.DetectionResult` out. No I/O, no clock, no randomness.
The class exists to carry three things a bare function cannot: a stable ``NAME``, a
semantic ``VERSION`` that A3 lineage and A4 replay key on, and a frozen ``Settings``
model whose digest travels on every finding.
"""

from __future__ import annotations

import abc
import functools
import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar, Final

from godwit_contracts.common import GodwitModel, Probability, canonical_json, content_hash
from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.segment import Segment
from godwit_contracts.sketch import SketchEnvelope
from godwit_contracts.taint import Tainted, derived_statistic
from godwit_sketch import BaseSketch, GodwitSketchError, decode_envelope
from pydantic import Field

from godwit_detect.evidence import (
    Attribution,
    DetectionResult,
    Direction,
    Finding,
    Measure,
    Refusal,
    RefusalReason,
    Window,
)
from godwit_detect.series import (
    BaselinePolicy,
    IrregularSeriesError,
    ProbeContext,
    SeriesPoint,
    SketchSeries,
    select_baseline,
)

__all__ = [
    "Claim",
    "DetectorBase",
    "SeriesDetector",
    "Settings",
    "item_key",
    "merge_all",
    "same_keying",
]

_KEYING_PARAMS: Final[tuple[str, ...]] = ("key_mode", "key_id")


class Settings(GodwitModel):
    """Settings every detector has. Subclasses add their own.

    ``alpha`` is the emission threshold on the raw p-value, not a significance claim:
    FDR control belongs to L5, which sees every hypothesis. A detector still counts the
    tests it ran below the threshold, in ``DetectionResult.tests``.
    """

    alpha: Probability = 0.05
    min_support: int = Field(default=100, ge=1)
    """Rows a sketch needs before this detector will draw a conclusion from it."""

    def digest(self) -> str:
        """Stable hash of every setting. Floats are rendered with ``repr`` first,
        because JSON float formatting is not something two builds agree on."""
        rendered = {
            key: repr(value) if isinstance(value, float) else value
            for key, value in self.model_dump(mode="json").items()
        }
        return content_hash(canonical_json(rendered), prefix="set")


def item_key(value: Tainted[str]) -> str:
    """Unwrap a heavy-hitter key or category label, to use as a dictionary key. Nothing else.

    Comparing two snapshots' category mixes means knowing that the ``PT`` in one is the
    ``PT`` in the other, and that needs the value. This is the only ``reveal()`` of an
    item in the package, the result is only ever used to align counts, and it never
    reaches a finding: findings carry the original ``Tainted`` object instead. Grep for
    ``item_key(`` when reviewing a diff.
    """
    return value.reveal()


def same_keying(first: SketchEnvelope, second: SketchEnvelope) -> bool:
    """True when two item-bearing envelopes key their items the same way.

    Keys hashed under two different data-plane keys are unrelated strings, and comparing
    them would report every item as having appeared and vanished at once.
    """
    return all(first.params.get(name) == second.params.get(name) for name in _KEYING_PARAMS)


def merge_all(sketches: Sequence[BaseSketch]) -> BaseSketch:
    """Fold sketches oldest first. The fold order is fixed, so the result is deterministic
    even for kinds whose merge is only associative within its error bound."""
    return functools.reduce(lambda left, right: left.merge(right), sketches[1:], sketches[0])


@dataclass(frozen=True, slots=True)
class Claim:
    """A tested statistic on its way to becoming a finding. See :meth:`DetectorBase._emit`."""

    method: str
    statistic: Measure
    effect: Measure
    p_value: float
    direction: Direction
    note: str
    baseline: Measure | None = None
    shape: tuple[Measure, ...] = ()
    attribution: tuple[Attribution, ...] = ()
    identities: tuple[Tainted[str], ...] | None = None
    """None means: whatever identities the attribution carries."""
    population: int | None = None
    baseline_population: int | None = None
    segment: Segment | None = None
    """None means: the probe's own segment."""


class DetectorBase[S: Settings](abc.ABC):
    """Name, version, settings. Everything else is the subclass's."""

    NAME: ClassVar[str]
    VERSION: ClassVar[str]
    """Semantic version. Any change that could alter output for identical input is a
    bump: ``tests/test_registry.py`` hashes behaviour over golden fixtures and fails when
    the hash moves without one."""
    KIND: ClassVar[EvidenceKind]
    SUMMARY: ClassVar[str]

    def __init__(self, settings: S | None = None) -> None:
        self.settings: S = settings if settings is not None else self.default_settings()

    @classmethod
    @abc.abstractmethod
    def default_settings(cls) -> S:
        """The settings the version number describes."""

    def _result(
        self,
        findings: Sequence[Finding] = (),
        *,
        tests: int = 0,
        refusals: Sequence[Refusal] = (),
    ) -> DetectionResult:
        ordered = sorted(
            findings, key=lambda item: (-item.score, item.method, _attribution_key(item))
        )
        return DetectionResult(
            detector=self.NAME,
            detector_version=self.VERSION,
            findings=tuple(ordered),
            tests=tests,
            refusals=tuple(refusals),
        )

    def _refusal(
        self, reason: RefusalReason, sketch_names: Sequence[str] = (), subject: str = ""
    ) -> Refusal:
        return Refusal(
            detector=self.NAME, reason=reason, sketch_names=tuple(sketch_names), subject=subject
        )

    def _emit(self, context: ProbeContext, window: Window, claim: Claim) -> Finding | None:
        """A finding for ``claim``, or None when its p-value misses the threshold."""
        if claim.p_value > self.settings.alpha:
            return None
        identities = claim.identities
        if identities is None:
            identities = tuple(a.identity for a in claim.attribution if a.identity is not None)
        return Finding(
            detector=self.NAME,
            detector_version=self.VERSION,
            settings_digest=self.settings.digest(),
            method=claim.method,
            kind=self.KIND,
            probe_key=context.probe_key,
            source_id=context.source_id,
            sketch_names=(context.sketch_name,),
            segment=claim.segment if claim.segment is not None else context.segment,
            columns=context.columns,
            window=window,
            direction=claim.direction,
            statistic=claim.statistic,
            baseline=claim.baseline,
            effect=claim.effect,
            p_value=derived_statistic(claim.p_value),
            p_value_note=claim.note,
            population=claim.population,
            baseline_population=claim.baseline_population,
            shape=claim.shape,
            attribution=claim.attribution,
            identities=identities,
            score=-math.log10(max(claim.p_value, 1e-300)),
        )


def _attribution_key(finding: Finding) -> str:
    return ",".join(item.feature for item in finding.attribution) + "|" + str(finding.segment.key)


class SeriesDetector[S: Settings](DetectorBase[S]):
    """A detector over one :class:`~godwit_detect.series.SketchSeries`.

    :meth:`run` does the checks every series detector needs -- a gap in the current
    window, an unsupported codec, a baseline that is empty or incomparable -- and hands
    the rest to :meth:`_detect`.
    """

    CODECS: ClassVar[frozenset[str]]

    def accepts(self, envelope: SketchEnvelope) -> bool:
        """True when this detector can read ``envelope``."""
        return envelope.codec in self.CODECS

    def run(self, series: SketchSeries, *, policy: BaselinePolicy) -> DetectionResult:
        """Test the current window of ``series`` against the windows ``policy`` selects."""
        name = (series.context.sketch_name,)
        current = series.current.envelope
        if current is None:
            return self._result(refusals=[self._refusal(RefusalReason.GAP, name)])
        if not self.accepts(current):
            return self._result(refusals=[self._refusal(RefusalReason.UNSUPPORTED_SKETCH, name)])
        try:
            reference = select_baseline(series, policy)
        except IrregularSeriesError:
            return self._result(refusals=[self._refusal(RefusalReason.IRREGULAR_SERIES, name)])
        if not reference:
            return self._result(refusals=[self._refusal(RefusalReason.NO_BASELINE, name)])
        for point in reference:
            envelope = _present(point)
            if envelope.codec != current.codec or not same_keying(envelope, current):
                return self._result(refusals=[self._refusal(RefusalReason.INCOMPARABLE, name)])
        window = Window(
            snapshot_id=series.current.snapshot_id,
            at=series.current.at,
            baseline_policy=policy.describe(),
            baseline_snapshot_ids=tuple(point.snapshot_id for point in reference),
            baseline_from=reference[0].at,
            baseline_to=reference[-1].at,
        )
        try:
            return self._detect(series, reference, window)
        except GodwitSketchError:
            return self._result(refusals=[self._refusal(RefusalReason.INCOMPARABLE, name)])

    @abc.abstractmethod
    def _detect(
        self, series: SketchSeries, reference: Sequence[SeriesPoint], window: Window
    ) -> DetectionResult:
        """Everything after the common checks. ``reference`` is non-empty and gap-free."""


def _present(point: SeriesPoint) -> SketchEnvelope:
    if point.envelope is None:
        raise ValueError("select_baseline returned a gap; that is a bug in select_baseline")
    return point.envelope


def decoded(point: SeriesPoint) -> BaseSketch:
    """Decode a non-gap point's sketch."""
    return decode_envelope(_present(point))
