"""Champion/challenger: two configurations over the same replay, and what changed.

Three questions, in the order they matter:

1. **What did the challenger stop finding?** A lost pattern is the expensive kind of
   regression, because nobody notices an alert that never arrives. Losses are listed first.
2. **What did it start finding, and did the ranking move?** A reordering that pushes a
   confirmed pattern below the review capacity is a regression even though nothing was lost.
3. **What did it cost?** A configuration that finds one more pattern for ten times the bytes
   is not an improvement, and the diff states the ratio rather than leaving it to be inferred.

The diff works on ``content_digest``-level identity, not on candidate ids, so two arms may be
replayed over separately materialised copies of the data. Segment keys are hashes, so the
whole diff can be committed to a repository.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from enum import StrEnum

from godwit_contracts.common import ContentHash, GodwitModel, NonNegInt
from godwit_contracts.cost import CostSpend
from pydantic import Field

from godwit_replay.verdict import ReplayReport

__all__ = [
    "ArmSummary",
    "ChampionChallenger",
    "CostDelta",
    "MetricDelta",
    "PatternDelta",
    "PatternStatus",
    "diff_reports",
    "render_markdown",
]


class PatternStatus(StrEnum):
    """What happened to one segment between the two arms."""

    GAINED = "gained"
    LOST = "lost"
    REORDERED = "reordered"
    UNCHANGED = "unchanged"


class PatternDelta(GodwitModel):
    """One segment's fate. Carries a key, never a value."""

    segment_key: str
    status: PatternStatus
    detector: str
    champion_rank: int | None = None
    challenger_rank: int | None = None
    score_delta: float | None = None

    @property
    def rank_delta(self) -> int | None:
        """Positive means the challenger ranked it worse."""
        if self.champion_rank is None or self.challenger_rank is None:
            return None
        return self.challenger_rank - self.champion_rank


class MetricDelta(GodwitModel):
    """One scalar, both ways, and the difference."""

    metric: str
    champion: float | None = None
    challenger: float | None = None

    @property
    def delta(self) -> float | None:
        """Challenger minus champion, when both exist."""
        if self.champion is None or self.challenger is None:
            return None
        return self.challenger - self.champion


class CostDelta(GodwitModel):
    """What the challenger spent, relative to the champion.

    ``CostSpend`` adds and does not subtract, deliberately -- a negative spend is not a
    thing. So the difference lives here, in a type that is a *comparison* rather than a
    budget, and cannot be handed back to anything that spends.
    """

    bytes_scanned: int
    wall_seconds: float
    usd: Decimal
    llm_tokens: int
    train_seconds: float

    @classmethod
    def between(cls, champion: CostSpend, challenger: CostSpend) -> CostDelta:
        """Challenger minus champion, field by field."""
        return cls(
            bytes_scanned=challenger.bytes_scanned - champion.bytes_scanned,
            wall_seconds=challenger.wall_seconds - champion.wall_seconds,
            usd=challenger.usd - champion.usd,
            llm_tokens=challenger.llm_tokens - champion.llm_tokens,
            train_seconds=challenger.train_seconds - champion.train_seconds,
        )

    def bytes_ratio(self, champion: CostSpend) -> float | None:
        """Challenger bytes over champion bytes. None when the champion scanned nothing."""
        if champion.bytes_scanned == 0:
            return None
        return (champion.bytes_scanned + self.bytes_scanned) / champion.bytes_scanned


class ArmSummary(GodwitModel):
    """One side of the comparison, in the fields a reader checks first."""

    config_name: str
    config_digest: ContentHash
    run_digest: ContentHash
    content_digest: ContentHash
    handler: str
    snapshots: NonNegInt
    surfaced: NonNegInt
    verdict: str
    cost: CostSpend = Field(default_factory=CostSpend.zero)


class ChampionChallenger(GodwitModel):
    """The full comparison. JSON by construction; markdown by :func:`render_markdown`."""

    dataset: str
    champion: ArmSummary
    challenger: ArmSummary
    identical: bool = Field(
        description="True when both arms produced the same findings. Two arms that were "
        "supposed to differ and did not is a result worth seeing, usually a config that "
        "never took effect."
    )
    patterns: tuple[PatternDelta, ...] = ()
    gained: NonNegInt = 0
    lost: NonNegInt = 0
    reordered: NonNegInt = 0
    unchanged: NonNegInt = 0
    metrics: tuple[MetricDelta, ...] = ()
    cost_delta: CostDelta
    caveats: tuple[str, ...] = ()

    @property
    def regressed(self) -> bool:
        """True when the challenger lost a pattern or dropped one out of the top list."""
        return self.lost > 0


def _ranks(report: ReplayReport) -> Mapping[str, tuple[int, str, float]]:
    return {str(row.segment_key): (int(row.rank), row.detector, row.score) for row in report.top}


def _metric_pairs(champion: ReplayReport, challenger: ReplayReport) -> tuple[MetricDelta, ...]:
    pairs: list[MetricDelta] = []
    left = champion.discovery
    right = challenger.discovery
    if left is None and right is None:
        return ()
    names = sorted(
        set(left.precision_at_k if left else {}) | set(right.precision_at_k if right else {}),
        key=int,
    )
    for name in names:
        pairs.append(
            MetricDelta(
                metric=f"precision_at_{name}",
                champion=left.precision_at_k.get(name) if left else None,
                challenger=right.precision_at_k.get(name) if right else None,
            )
        )
    pairs.append(
        MetricDelta(
            metric="time_to_detection_seconds",
            champion=left.headline_time_to_detection_seconds if left else None,
            challenger=right.headline_time_to_detection_seconds if right else None,
        )
    )
    pairs.append(
        MetricDelta(
            metric="novelty_rate",
            champion=left.novelty_rate if left else None,
            challenger=right.novelty_rate if right else None,
        )
    )
    return tuple(pairs)


def diff_reports(
    champion: ReplayReport,
    challenger: ReplayReport,
    *,
    caveats: Sequence[str] = (),
) -> ChampionChallenger:
    """Diff two reports over the same dataset.

    Refuses to compare two different datasets: a diff across datasets is not a comparison,
    it is two unrelated numbers next to each other.
    """
    if champion.dataset != challenger.dataset:
        raise ValueError(
            f"cannot diff {champion.dataset} against {challenger.dataset}: "
            "a champion/challenger comparison is one dataset, two configurations"
        )
    left, right = _ranks(champion), _ranks(challenger)
    deltas: list[PatternDelta] = []
    for key in sorted(set(left) | set(right)):
        in_left, in_right = left.get(key), right.get(key)
        if in_left is not None and in_right is None:
            deltas.append(
                PatternDelta(
                    segment_key=key,
                    status=PatternStatus.LOST,
                    detector=in_left[1],
                    champion_rank=in_left[0],
                    challenger_rank=None,
                )
            )
        elif in_left is None and in_right is not None:
            deltas.append(
                PatternDelta(
                    segment_key=key,
                    status=PatternStatus.GAINED,
                    detector=in_right[1],
                    champion_rank=None,
                    challenger_rank=in_right[0],
                )
            )
        elif in_left is not None and in_right is not None:
            status = (
                PatternStatus.UNCHANGED if in_left[0] == in_right[0] else PatternStatus.REORDERED
            )
            deltas.append(
                PatternDelta(
                    segment_key=key,
                    status=status,
                    detector=in_right[1],
                    champion_rank=in_left[0],
                    challenger_rank=in_right[0],
                    score_delta=in_right[2] - in_left[2],
                )
            )
    ordered = sorted(
        deltas,
        key=lambda item: (
            {"lost": 0, "gained": 1, "reordered": 2, "unchanged": 3}[item.status.value],
            item.segment_key,
        ),
    )
    counts = {
        status: sum(1 for item in ordered if item.status is status) for status in PatternStatus
    }

    def arm(report: ReplayReport) -> ArmSummary:
        return ArmSummary(
            config_name=report.config.name,
            config_digest=report.config.digest(),
            run_digest=report.run_digest,
            content_digest=report.content_digest,
            handler=report.handler,
            snapshots=report.snapshots_replayed,
            surfaced=report.surfaced_total,
            verdict=report.verdict.value,
            cost=report.discovery.cost if report.discovery is not None else CostSpend.zero(),
        )

    champion_arm, challenger_arm = arm(champion), arm(challenger)
    return ChampionChallenger(
        dataset=champion.dataset,
        champion=champion_arm,
        challenger=challenger_arm,
        identical=champion.content_digest == challenger.content_digest,
        patterns=tuple(ordered),
        gained=counts[PatternStatus.GAINED],
        lost=counts[PatternStatus.LOST],
        reordered=counts[PatternStatus.REORDERED],
        unchanged=counts[PatternStatus.UNCHANGED],
        metrics=_metric_pairs(champion, challenger),
        cost_delta=CostDelta.between(champion_arm.cost, challenger_arm.cost),
        caveats=tuple(caveats),
    )


def _render_arms(diff: ChampionChallenger) -> list[str]:
    """The two arms side by side, in the fields a reader checks first."""
    lines = [
        f"# Champion vs challenger -- {diff.dataset}",
        "",
        "| | champion | challenger |",
        "|---|---|---|",
        f"| configuration | `{diff.champion.config_name}` | `{diff.challenger.config_name}` |",
        (
            f"| config digest | `{diff.champion.config_digest}` "
            f"| `{diff.challenger.config_digest}` |"
        ),
        f"| handler | {diff.champion.handler} | {diff.challenger.handler} |",
        f"| snapshots | {diff.champion.snapshots} | {diff.challenger.snapshots} |",
        f"| surfaced | {diff.champion.surfaced} | {diff.challenger.surfaced} |",
        f"| verdict | {diff.champion.verdict} | {diff.challenger.verdict} |",
        "",
    ]
    if diff.identical:
        lines.append(
            "**The two arms produced identical findings.** If they were meant to differ, the "
            "configuration difference did not reach the code path you thought it did."
        )
        lines.append("")
    lines.append(
        f"Patterns: **{diff.lost} lost**, {diff.gained} gained, {diff.reordered} reordered, "
        f"{diff.unchanged} unchanged."
    )
    lines.append("")
    return lines


def _render_patterns(diff: ChampionChallenger) -> list[str]:
    """Losses first, then gains, then reorderings. A loss is the expensive kind."""
    lines: list[str] = []
    if diff.lost:
        lines.append("## Lost -- read this part first")
        lines.append("")
        lines.extend(
            f"- `{item.segment_key}` ({item.detector}) was at rank {item.champion_rank}"
            for item in diff.patterns
            if item.status is PatternStatus.LOST
        )
        lines.append("")
    if diff.gained:
        lines.append("## Gained")
        lines.append("")
        lines.extend(
            f"- `{item.segment_key}` ({item.detector}) entered at rank {item.challenger_rank}"
            for item in diff.patterns
            if item.status is PatternStatus.GAINED
        )
        lines.append("")
    moved = [item for item in diff.patterns if item.status is PatternStatus.REORDERED]
    if moved:
        lines.append("## Reordered")
        lines.append("")
        lines.extend(
            f"- `{item.segment_key}` moved {item.champion_rank} -> {item.challenger_rank}"
            for item in moved
        )
        lines.append("")
    return lines


def _render_cost(diff: ChampionChallenger) -> list[str]:
    """What the challenger spent, as a ratio rather than as two numbers to compare by eye."""
    ratio = diff.cost_delta.bytes_ratio(diff.champion.cost)
    return [
        "## Cost",
        "",
        f"- bytes scanned: {diff.cost_delta.bytes_scanned:+,} "
        + (f"({ratio:.2f}x the champion)" if ratio is not None else "(champion scanned nothing)"),
        f"- USD: {diff.cost_delta.usd:+}",
        f"- LLM tokens: {diff.cost_delta.llm_tokens:+,}",
        f"- train seconds: {diff.cost_delta.train_seconds:+.3f}",
        "",
    ]


def render_markdown(diff: ChampionChallenger) -> str:
    """The readable form. Losses first, then gains, then the cost."""
    lines = _render_arms(diff)
    lines.extend(_render_patterns(diff))
    if diff.metrics:
        lines.append("## Metrics")
        lines.append("")
        lines.append("| metric | champion | challenger | delta |")
        lines.append("|---|---|---|---|")
        lines.extend(
            f"| {item.metric} | {_number(item.champion)} | {_number(item.challenger)} "
            f"| {_number(item.delta)} |"
            for item in diff.metrics
        )
        lines.append("")
    lines.extend(_render_cost(diff))
    if diff.caveats:
        lines.append("## Caveats")
        lines.append("")
        lines.extend(f"- {item}" for item in diff.caveats)
        lines.append("")
    return "\n".join(lines)


def _number(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.6g}"
