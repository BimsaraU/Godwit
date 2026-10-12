"""The contract's ``Detector`` protocol, over any series detector here.

``godwit_contracts.protocols.Detector.detect`` hands a detector one current bundle and
at most one baseline bundle. That shape cannot express a trailing or seasonal baseline,
and a bundle does not say which segment or columns it measured. This adapter therefore
needs the ``ProbeSpec`` at construction, compares against the single baseline bundle as
a fixed reference, and is honest about what that costs: a detector that needs history
(graph anomaly, rank churn) refuses rather than inventing a variance, and the adapter
returns no candidate for it. See
``docs/change-requests/CR-A7-detector-cannot-see-history-or-spec.md``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from godwit_contracts.common import Version
from godwit_contracts.discovery import Candidate
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.sketch import SketchBundle
from godwit_contracts.source import ColumnProfile

from godwit_detect.base import SeriesDetector
from godwit_detect.evidence import DetectionResult, lineage_version, to_candidate
from godwit_detect.series import FixedReference, ProbeContext, SeriesPoint, SketchSeries

__all__ = ["BundleDetector"]


class BundleDetector:
    """Satisfies ``godwit_contracts.protocols.Detector`` for one probe spec."""

    def __init__(
        self, detector: SeriesDetector[Any], *, spec: ProbeSpec, code_version: str
    ) -> None:
        self._detector = detector
        self._spec = spec
        self._code_version = code_version
        self.last_results: tuple[DetectionResult, ...] = ()
        """Every result of the latest ``detect`` call, refusals and test counts included --
        the parts a ``Candidate`` cannot carry."""

    @property
    def name(self) -> str:
        """The wrapped detector's registry name."""
        return self._detector.NAME

    @property
    def version(self) -> Version:
        """The wrapped detector's semantic version, in lineage encoding."""
        return lineage_version(self._detector.VERSION)

    def detect(
        self,
        *,
        current: SketchBundle,
        baseline: SketchBundle | None,
        profiles: Sequence[ColumnProfile],
        seed: int,
    ) -> tuple[Candidate, ...]:
        """Compare every sketch the detector can read against the same sketch in ``baseline``.

        ``profiles`` is accepted for the protocol and not read: nothing in a column
        profile is needed that the sketches do not already say, and a profile's bounds
        and most-common values are row values this package has no reason to touch.
        """
        del profiles
        self.last_results = ()
        if baseline is None or baseline.produced_at >= current.produced_at:
            return ()
        results: list[DetectionResult] = []
        candidates: list[Candidate] = []
        for sketch_name in sorted(current.sketches):
            now = current.sketches[sketch_name]
            before = baseline.sketches.get(sketch_name)
            if before is None or not self._detector.accepts(now):
                continue
            series = SketchSeries(
                context=ProbeContext.from_spec(self._spec, sketch_name),
                points=(
                    SeriesPoint(
                        at=baseline.produced_at, snapshot_id=baseline.snapshot_id, envelope=before
                    ),
                    SeriesPoint(
                        at=current.produced_at, snapshot_id=current.snapshot_id, envelope=now
                    ),
                ),
            )
            result = self._detector.run(
                series, policy=FixedReference(snapshot_id=baseline.snapshot_id)
            )
            results.append(result)
            candidates.extend(
                to_candidate(finding, code_version=self._code_version, seed=seed)
                for finding in result.findings
            )
        self.last_results = tuple(results)
        return tuple(candidates)
