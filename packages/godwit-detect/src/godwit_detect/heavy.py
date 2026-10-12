"""Heavy-hitter dynamics: who entered the top set, how much it churned, how concentrated it is.

Reads a series of Count-Min heavy-hitter sketches or category histograms. Three families:

``entrant`` / ``exit`` / ``share_shift``
    Every key in the union of the current and the reference top-k gets a two-sided
    two-proportion z test of its share. A significant rise by a key that is new to the
    top set is an ``entrant`` (APPEARED), a significant fall by one that left it an
    ``exit`` (VANISHED), anything else a ``share_shift`` (UP/DOWN). The family is the
    whole union, not just the keys that crossed the boundary: testing only the crossers
    selects on the outcome -- a key is an entrant *because* its count happened to rise --
    and in a measured null run that alone tripled the false-positive rate. When a key is
    absent from the reference counters its reference count is not known, only bounded
    (a Misra-Gries summary guarantees a missing key's count is at most what the counters
    shed), and the bound is used.
``concentration``
    Change in the Herfindahl-Hirschman index of the itemised shares. Its sampling
    variance under a multinomial has a closed form (delta method):
    ``Var(HHI) = 4/n * (sum p^3 - (sum p^2)^2)``, so this test works against a single
    reference window.
``rank_churn``
    Turnover of the top-k set: ``1 - |now & ref| / k``. It has no closed-form null, so it
    is tested against the churn between consecutive reference windows with a t
    prediction interval, and only when there are at least ``min_history`` of them.
    Below that, churn is still reported, as a shape measure, without a p-value.

THE IDENTITIES ARE TAINTED; THE SHAPE IS NOT
--------------------------------------------
The keys that entered are row values -- on an identifier column they are the PII. They
ride in ``identities`` and ``Attribution.identity`` only. Every finding also carries
``entrant_count``, ``entrant_share``, ``churn``, ``hhi`` and ``gini`` as shape measures,
so a reviewer who sees none of the keys still reads "two new keys took 19% of the
volume and concentration doubled" -- which is most of what the finding is worth.

An entrant finding's segment gets an equality predicate on the key when the key is
plain and the probe measured a single column; that predicate quotes the value, as every
segment does, and is the gate's to redact.
"""

from __future__ import annotations

import datetime as _dt
import math
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import ClassVar, Final

from godwit_contracts.common import ScalarValue
from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.taint import Acquisition, data_value, derived_statistic
from godwit_sketch import CategoryHistogram, CountMinHeavy
from pydantic import Field

from godwit_detect.base import Claim, SeriesDetector, Settings, decoded, merge_all
from godwit_detect.evidence import (
    Attribution,
    DetectionResult,
    Direction,
    Measure,
    RefusalReason,
    Window,
    measure,
)
from godwit_detect.histograms import OTHER, CategoryCounts, category_counts, effective_n
from godwit_detect.series import SeriesPoint, SketchSeries
from godwit_detect.stats import prediction_test, two_sided_normal_p

__all__ = ["HeavyHitterSettings", "HeavyHitterShift", "parse_canonical_key"]

_HASHED: Final[str] = "hashed"
_KEY_METHODS: Final[dict[Direction, str]] = {
    Direction.APPEARED: "entrant",
    Direction.VANISHED: "exit",
    Direction.UP: "share_shift",
    Direction.DOWN: "share_shift",
}


class HeavyHitterSettings(Settings):
    """Settings for :class:`HeavyHitterShift`."""

    top_k: int = Field(default=10, ge=1)
    min_history: int = Field(default=5, ge=3)
    """Reference windows needed before rank churn gets a p-value."""


def parse_canonical_key(key: str) -> ScalarValue:
    """Invert ``godwit_contracts.segment.canonical_scalar`` for the tags a sketch emits.

    Heavy-hitter keys come back in canonical tagged form (``"s:PT"``), and a segment
    predicate wants the value (``"PT"``). Raises ``ValueError`` on anything else.
    """
    tag, _, body = key.partition(":")
    if tag == "n":
        return None
    if tag == "s":
        return body
    if tag == "i":
        return int(body)
    if tag == "b":
        return body == "true"
    if tag == "f":
        return float(body)
    if tag == "d":
        return Decimal(body)
    if tag == "y":
        return bytes.fromhex(body)
    if tag == "t":
        return _dt.date.fromisoformat(body)
    if tag == "T":
        return _dt.datetime.fromisoformat(body.replace("Z", "+00:00"))
    raise ValueError("not a canonical sketch key")


@dataclass(frozen=True, slots=True)
class _Ranked:
    counts: CategoryCounts
    order: tuple[str, ...]
    absent_bound: float

    def top(self, k: int) -> tuple[str, ...]:
        return self.order[:k]

    def count(self, key: str) -> float:
        return self.counts.counts.get(key, self.absent_bound)


def _ranked(sketch: CategoryHistogram | CountMinHeavy) -> _Ranked:
    counts = category_counts(sketch)
    order = tuple(
        key
        for key, _ in sorted(
            ((k, v) for k, v in counts.counts.items() if k != OTHER), key=lambda kv: (-kv[1], kv[0])
        )
    )
    other = counts.counts.get(OTHER, 0.0)
    bound = (
        min(float(sketch.underestimate()), other) if isinstance(sketch, CountMinHeavy) else other
    )
    return _Ranked(counts=counts, order=order, absent_bound=bound)


def _hhi(ranked: _Ranked) -> tuple[float, float]:
    """Herfindahl index of itemised shares and its delta-method variance."""
    total = ranked.counts.total
    if total <= 0:
        return 0.0, 0.0
    shares = [ranked.counts.counts[key] / total for key in ranked.order]
    s2 = sum(s * s for s in shares)
    s3 = sum(s * s * s for s in shares)
    n = effective_n(total, ranked.counts.epsilon)
    return s2, max(0.0, 4.0 / n * (s3 - s2 * s2))


def _gini(ranked: _Ranked) -> float:
    values = sorted(ranked.counts.counts[key] for key in ranked.order)
    total = sum(values)
    count = len(values)
    if count == 0 or total <= 0:
        return 0.0
    weighted = sum((2 * (i + 1) - count - 1) * v for i, v in enumerate(values))
    return weighted / (count * total)


def _churn(now: Sequence[str], ref: Sequence[str]) -> float:
    k = min(len(now), len(ref))
    if k == 0:
        return 0.0
    return 1.0 - len(set(now[:k]) & set(ref[:k])) / k


def _proportion_z(c1: float, n1: float, c0: float, n0: float) -> float:
    p1, p0 = c1 / n1, c0 / n0
    pooled = (c1 + c0) / (n1 + n0)
    se = math.sqrt(max(pooled * (1.0 - pooled) * (1.0 / n1 + 1.0 / n0), 1e-18))
    return (p1 - p0) / se


class HeavyHitterShift(SeriesDetector[HeavyHitterSettings]):
    """New entrants, exits, concentration and churn in a heavy-hitter series."""

    NAME: ClassVar[str] = "heavy_hitter_shift"
    VERSION: ClassVar[str] = "1.0.0"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.HEAVY_HITTER_SHIFT
    SUMMARY: ClassVar[str] = "Top-k entrants and exits, HHI concentration change, rank churn"
    CODECS: ClassVar[frozenset[str]] = frozenset({CountMinHeavy.CODEC, CategoryHistogram.CODEC})

    @classmethod
    def default_settings(cls) -> HeavyHitterSettings:
        """Top ten, alpha 0.05, 100 rows, five reference windows for churn."""
        return HeavyHitterSettings()

    def _detect(
        self, series: SketchSeries, reference: Sequence[SeriesPoint], window: Window
    ) -> DetectionResult:
        name = (series.context.sketch_name,)
        current = decoded(series.current)
        windows = [decoded(point) for point in reference]
        pooled = merge_all(windows)
        if not isinstance(current, CategoryHistogram | CountMinHeavy) or not isinstance(
            pooled, CategoryHistogram | CountMinHeavy
        ):
            return self._result(refusals=[self._refusal(RefusalReason.UNSUPPORTED_SKETCH, name)])
        if current.population < self.settings.min_support:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_SKETCH, name)])
        if pooled.population < self.settings.min_support:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_BASELINE, name)])

        k = self.settings.top_k
        now, ref = _ranked(current), _ranked(pooled)
        entrants = [key for key in now.top(k) if key not in set(ref.top(k))]
        exits = [key for key in ref.top(k) if key not in set(now.top(k))]
        n1 = effective_n(now.counts.total, now.counts.epsilon)
        n0 = effective_n(ref.counts.total, ref.counts.epsilon)
        churn = _churn(now.top(k), ref.top(k))
        hhi_now, var_now = _hhi(now)
        hhi_ref, var_ref = _hhi(ref)
        entrant_share = sum(now.count(key) for key in entrants) / now.counts.total
        shape = (
            measure("entrant_count", len(entrants), "keys"),
            measure("exit_count", len(exits), "keys"),
            measure("entrant_share", entrant_share, "share"),
            measure("churn", churn, "share"),
            measure("hhi", hhi_now, "index"),
            measure("hhi_reference", hhi_ref, "index"),
            measure("gini", _gini(now), "index"),
            measure("gini_reference", _gini(ref), "index"),
            measure(
                "top1_share",
                now.count(now.order[0]) / now.counts.total if now.order else 0.0,
                "share",
            ),
        )
        context = series.context
        entrant_ids = tuple(
            identity for key in entrants if (identity := now.counts.identities.get(key)) is not None
        )
        claims: list[Claim] = []
        top_now, top_ref = set(now.top(k)), set(ref.top(k))
        for key in sorted(top_now | top_ref):
            z = _proportion_z(now.count(key), n1, ref.count(key), n0)
            if key not in top_ref and z > 0:
                direction = Direction.APPEARED
            elif key not in top_now and z < 0:
                direction = Direction.VANISHED
            else:
                direction = Direction.UP if z > 0 else Direction.DOWN
            claims.append(
                self._key_claim(series, key, now, ref, z, two_sided_normal_p(z), direction, shape)
            )

        if len(windows) >= self.settings.min_history:
            hhi_test = prediction_test(hhi_now, [_hhi(_ranked_of(w))[0] for w in windows])
            z, p_hhi = hhi_test.statistic, hhi_test.p_two_sided
            note = "t prediction interval against each reference window's Herfindahl index"
        else:
            se = math.sqrt(var_now + var_ref)
            z = (hhi_now - hhi_ref) / se if se > 0 else 0.0
            p_hhi = two_sided_normal_p(z) if se > 0 else 1.0
            note = "delta-method variance of the Herfindahl index over itemised shares"
        claims.append(
            Claim(
                method="concentration",
                statistic=measure("z", z, "z"),
                baseline=measure("hhi", hhi_ref, "index"),
                effect=measure("hhi_change", hhi_now - hhi_ref, "index"),
                p_value=p_hhi,
                direction=Direction.UP if hhi_now > hhi_ref else Direction.DOWN,
                note=note,
                shape=shape,
                identities=entrant_ids,
                population=int(now.counts.total),
                baseline_population=int(ref.counts.total),
            )
        )

        if len(windows) >= self.settings.min_history:
            history = [
                _churn(_ranked_of(windows[i]).top(k), _ranked_of(windows[i - 1]).top(k))
                for i in range(1, len(windows))
            ]
            test = prediction_test(_churn(now.top(k), _ranked_of(windows[-1]).top(k)), history)
            claims.append(
                Claim(
                    method="rank_churn",
                    statistic=measure("t", test.statistic, "t"),
                    baseline=measure("churn", test.reference_mean, "share"),
                    effect=measure("churn_change", churn - test.reference_mean, "share"),
                    p_value=test.p_upper,
                    direction=Direction.UP,
                    note="t prediction interval against churn between consecutive references",
                    shape=shape,
                    identities=entrant_ids,
                    population=int(now.counts.total),
                    baseline_population=int(ref.counts.total),
                )
            )
        findings = [f for c in claims if (f := self._emit(context, window, c)) is not None]
        return self._result(findings, tests=len(claims))

    def _key_claim(
        self,
        series: SketchSeries,
        key: str,
        now: _Ranked,
        ref: _Ranked,
        z: float,
        p_value: float,
        direction: Direction,
        shape: tuple[Measure, ...],
    ) -> Claim:
        identity = now.counts.identities.get(key) or ref.counts.identities.get(key)
        share_now = now.count(key) / now.counts.total
        share_ref = ref.count(key) / ref.counts.total
        rank = now.order.index(key) if key in now.order else len(now.order)
        return Claim(
            method=_KEY_METHODS[direction],
            statistic=measure("z", z, "z"),
            baseline=measure("share", share_ref, "share"),
            effect=measure("share_change", share_now - share_ref, "share"),
            p_value=p_value,
            direction=direction,
            note="two-sided two-proportion z over the union of both top sets; an absent "
            "reference count is its Misra-Gries upper bound",
            shape=(measure("share", share_now, "share"), measure("rank", rank + 1, "rank"), *shape),
            attribution=(
                Attribution(
                    feature=f"rank:{rank + 1}",
                    contribution=derived_statistic(share_now - share_ref),
                    identity=identity,
                ),
            ),
            population=int(now.count(key)) if key in now.counts.counts else None,
            baseline_population=int(ref.counts.total),
            segment=self._key_segment(series, key, int(now.count(key))),
        )

    def _key_segment(self, series: SketchSeries, key: str, count: int) -> Segment:
        """The probe's segment, narrowed to this key when the key is a plain value."""
        context = series.context
        envelope = series.current.envelope
        hashed = envelope is not None and envelope.params.get("key_mode") == _HASHED
        if hashed or len(context.columns) != 1:
            return context.segment
        try:
            value = parse_canonical_key(key)
        except ValueError:
            return context.segment
        predicate = Predicate(
            column=context.columns[0],
            op=Operator.EQ,
            values=(
                data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE, population=count),
            ),
        )
        return Segment(predicates=(*context.segment.predicates, predicate), population=count)


def _ranked_of(sketch: object) -> _Ranked:
    if not isinstance(sketch, CategoryHistogram | CountMinHeavy):
        raise TypeError("heavy-hitter series must hold categorical sketches")
    return _ranked(sketch)
