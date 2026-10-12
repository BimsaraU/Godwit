"""Correlation-structure change, from Moments sketches, across windows and across segments.

A Moments sketch is univariate, so a correlation needs one more sketch per pair: the
Moments of the row-wise sum ``x_i + x_j``. Then

    Cov(x_i, x_j) = (Var(x_i + x_j) - Var(x_i) - Var(x_j)) / 2

and the correlation follows. Everything stays a mergeable monoid, so the same slice can
be merged across segments to form the "all other segments" reference. The probe must
compute the pair sums over rows where both columns are present; godwit-probe does not
schedule that today (see HANDOFF, known limits).

Each pair is compared with Fisher's z: ``atanh(r1) - atanh(r0)`` over
``sqrt(1/(n1-3) + 1/(n0-3))``, two-sided. A pair is *reported* only when it crosses
``edge_threshold`` in absolute correlation -- an edge that appeared, vanished or flipped
sign -- and is significant; every pair compared counts as a test. Fisher's z assumes
roughly bivariate-normal data; heavy tails make it liberal, which is one more reason
L5 applies FDR control over the whole run.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import ClassVar, Final, Self

from godwit_contracts.common import GodwitModel, Instant, SnapshotId
from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.sketch import SketchEnvelope
from godwit_contracts.taint import derived_statistic
from godwit_sketch import GodwitSketchError, Moments, decode_envelope
from pydantic import Field, model_validator

from godwit_detect.base import DetectorBase, Settings, merge_all
from godwit_detect.evidence import (
    Attribution,
    DetectionResult,
    Direction,
    Finding,
    Refusal,
    RefusalReason,
    Window,
    measure,
)
from godwit_detect.series import ProbeContext
from godwit_detect.stats import two_sided_normal_p

__all__ = [
    "CorrelationPanel",
    "CorrelationSettings",
    "CorrelationShift",
    "CorrelationSlice",
    "pair_key",
]

_R_CLIP: Final[float] = 0.999999
_MIN_ROWS_FOR_FISHER: Final[int] = 4


def pair_key(i: int, j: int) -> str:
    """Key of the pair-sum sketch for columns ``i`` and ``j``: ``"0+2"``."""
    low, high = sorted((i, j))
    return f"{low}+{high}"


class CorrelationSlice(GodwitModel):
    """One segment's Moments: one per column, and one per column pair's row-wise sum."""

    context: ProbeContext
    columns: tuple[SketchEnvelope, ...] = Field(min_length=2)
    pair_sums: Mapping[str, SketchEnvelope]

    @model_validator(mode="after")
    def _complete(self) -> Self:
        count = len(self.columns)
        for i in range(count):
            for j in range(i + 1, count):
                if pair_key(i, j) not in self.pair_sums:
                    raise ValueError(f"missing pair-sum sketch {pair_key(i, j)}")
        return self


class CorrelationPanel(GodwitModel):
    """Correlation slices for comparable segments at one snapshot."""

    snapshot_id: SnapshotId
    at: Instant
    slices: tuple[CorrelationSlice, ...] = Field(min_length=1)


class CorrelationSettings(Settings):
    """Settings for :class:`CorrelationShift`."""

    min_support: int = Field(default=50, ge=_MIN_ROWS_FOR_FISHER)
    edge_threshold: float = Field(default=0.3, gt=0.0, lt=1.0)
    """Absolute correlation at which a pair counts as an edge."""


@dataclass(frozen=True, slots=True)
class _Matrix:
    n: int
    r: dict[tuple[int, int], float]


def _matrix(columns: Sequence[Moments], pairs: Mapping[str, Moments]) -> _Matrix:
    n = min([c.population for c in columns] + [p.population for p in pairs.values()])
    r: dict[tuple[int, int], float] = {}
    for i in range(len(columns)):
        for j in range(i + 1, len(columns)):
            vi, vj = columns[i].variance(), columns[j].variance()
            if vi <= 0 or vj <= 0:
                continue
            cov = (pairs[pair_key(i, j)].variance() - vi - vj) / 2.0
            r[(i, j)] = max(-_R_CLIP, min(_R_CLIP, cov / math.sqrt(vi * vj)))
    return _Matrix(n=n, r=r)


@dataclass(frozen=True, slots=True)
class _Decoded:
    item: CorrelationSlice
    columns: tuple[Moments, ...]
    pairs: dict[str, Moments]


def _decode(item: CorrelationSlice) -> _Decoded | None:
    columns = [decode_envelope(env) for env in item.columns]
    pairs = {key: decode_envelope(env) for key, env in item.pair_sums.items()}
    if not all(isinstance(c, Moments) for c in columns) or not all(
        isinstance(p, Moments) for p in pairs.values()
    ):
        return None
    return _Decoded(
        item=item,
        columns=tuple(c for c in columns if isinstance(c, Moments)),
        pairs={k: p for k, p in pairs.items() if isinstance(p, Moments)},
    )


class CorrelationShift(DetectorBase[CorrelationSettings]):
    """Edges that appeared, vanished or flipped between windows or against peer segments."""

    NAME: ClassVar[str] = "correlation_shift"
    VERSION: ClassVar[str] = "1.0.0"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.DISTRIBUTION_SHIFT
    SUMMARY: ClassVar[str] = "Fisher-z test of pairwise correlations from pair-sum Moments"

    @classmethod
    def default_settings(cls) -> CorrelationSettings:
        """Alpha 0.05, 50 rows, edges at |r| >= 0.3."""
        return CorrelationSettings()

    def run(
        self, current: CorrelationPanel, *, baseline: CorrelationPanel | None = None
    ) -> DetectionResult:
        """Compare each slice with its own baseline window, and with its peer segments."""
        decoded_now = [_decode(item) for item in current.slices]
        if any(d is None for d in decoded_now):
            return self._result(refusals=[self._refusal(RefusalReason.UNSUPPORTED_SKETCH)])
        now = [d for d in decoded_now if d is not None]
        before: dict[str, _Decoded] = {}
        if baseline is not None:
            for item in baseline.slices:
                d = _decode(item)
                if d is not None:
                    before[str(item.context.segment.key)] = d
        findings: list[Finding] = []
        refusals: list[Refusal] = []
        tests = 0
        for index, slice_now in enumerate(now):
            key = str(slice_now.item.context.segment.key)
            matrix_now = _matrix(slice_now.columns, slice_now.pairs)
            if matrix_now.n < self.settings.min_support:
                refusals.append(self._refusal(RefusalReason.THIN_SKETCH, (), f"segment:{key}"))
                continue
            if key in before and baseline is not None:
                reference = _matrix(before[key].columns, before[key].pairs)
                window = self._window(
                    current,
                    baseline_ids=(baseline.snapshot_id,),
                    policy=f"fixed({baseline.snapshot_id})",
                    baseline_at=baseline.at,
                )
                t, f = self._compare(slice_now.item, matrix_now, reference, window, "window")
                tests += t
                findings.extend(f)
            peers = [d for j, d in enumerate(now) if j != index]
            if peers:
                try:
                    rest_columns = [
                        _as_moments(merge_all([p.columns[c] for p in peers]))
                        for c in range(len(slice_now.columns))
                    ]
                    rest_pairs = {
                        k: _as_moments(merge_all([p.pairs[k] for p in peers]))
                        for k in slice_now.pairs
                    }
                except (GodwitSketchError, KeyError, IndexError):
                    refusals.append(self._refusal(RefusalReason.INCOMPARABLE, (), f"segment:{key}"))
                    continue
                window = self._window(current, baseline_ids=(), policy="peers", baseline_at=None)
                t, f = self._compare(
                    slice_now.item, matrix_now, _matrix(rest_columns, rest_pairs), window, "peers"
                )
                tests += t
                findings.extend(f)
        return self._result(findings, tests=tests, refusals=refusals)

    @staticmethod
    def _window(
        panel: CorrelationPanel,
        *,
        baseline_ids: tuple[SnapshotId, ...],
        policy: str,
        baseline_at: Instant | None,
    ) -> Window:
        return Window(
            snapshot_id=panel.snapshot_id,
            at=panel.at,
            baseline_policy=policy,
            baseline_snapshot_ids=baseline_ids,
            baseline_from=baseline_at,
            baseline_to=baseline_at,
        )

    def _compare(
        self, item: CorrelationSlice, now: _Matrix, reference: _Matrix, window: Window, method: str
    ) -> tuple[int, list[Finding]]:
        if reference.n < self.settings.min_support:
            return 0, []
        tau = self.settings.edge_threshold
        findings: list[Finding] = []
        tests = 0
        for pair in sorted(now.r):
            if pair not in reference.r:
                continue
            tests += 1
            r1, r0 = now.r[pair], reference.r[pair]
            z = (math.atanh(r1) - math.atanh(r0)) / math.sqrt(
                1.0 / (now.n - 3) + 1.0 / (reference.n - 3)
            )
            p_value = two_sided_normal_p(z)
            if abs(r0) < tau <= abs(r1):
                direction = Direction.APPEARED
            elif abs(r1) < tau <= abs(r0):
                direction = Direction.VANISHED
            elif abs(r0) >= tau and abs(r1) >= tau and (r0 > 0) != (r1 > 0):
                direction = Direction.CHANGED
            else:
                continue
            if p_value > self.settings.alpha:
                continue
            i, j = pair
            columns = tuple(item.context.columns[c] for c in pair if c < len(item.context.columns))
            findings.append(
                Finding(
                    detector=self.NAME,
                    detector_version=self.VERSION,
                    settings_digest=self.settings.digest(),
                    method=f"fisher_z_{method}",
                    kind=self.KIND,
                    probe_key=item.context.probe_key,
                    source_id=item.context.source_id,
                    sketch_names=(item.context.sketch_name,),
                    segment=item.context.segment,
                    columns=columns,
                    window=window,
                    direction=direction,
                    statistic=measure("fisher_z", z, "z"),
                    baseline=measure("correlation", r0, "r"),
                    effect=measure("correlation_change", r1 - r0, "r"),
                    p_value=derived_statistic(p_value),
                    p_value_note="Fisher z; assumes roughly bivariate-normal columns",
                    population=now.n,
                    baseline_population=reference.n,
                    shape=(measure("correlation", r1, "r"), measure("edge_threshold", tau, "r")),
                    attribution=(
                        Attribution(
                            feature=f"edge:{i}-{j}", contribution=derived_statistic(r1 - r0)
                        ),
                    ),
                    score=-math.log10(max(p_value, 1e-300)),
                )
            )
        return tests, findings


def _as_moments(sketch: object) -> Moments:
    if not isinstance(sketch, Moments):
        raise GodwitSketchError("correlation slices must hold Moments sketches")
    return sketch
