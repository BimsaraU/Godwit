"""The kill criterion, and the report a domain expert marks up in under an hour.

THE CRITERION
-------------
``godwit-replay verdict --dataset nyc-tlc --months 12`` prints the top twenty patterns with
enough evidence to judge, plus a template for marking each one *obvious*, *known*,
*non-obvious-and-real* or *wrong*. Fewer than three non-obvious-and-real means the thesis is
not supported, and the tool says so in its own output. That sentence is not softened, is not
qualified and is not moved to a footnote. It is in :data:`KILL_SENTENCE` and it is printed
whether the run looks good or not.

WHY THE REPORT IS AN EGRESS
---------------------------
A report is a document a human reads, which makes it an egress and makes it subject to
invariant 2. Everything in a ``PatternRow`` is therefore either a derived statistic, a
SCHEMA_NAME column reference, or a redacted label -- never a predicate value. The one path
that puts a value in is ``ReplayConfig.reveal_values_in_output``, which exists so the harness
can demonstrate that its own audit catches a leak. When that flag is set the revealed values
land in ``PatternRow.disclosed`` typed honestly as DATA_VALUE, the audit fires on the type
before anything is rendered, and the run's verdict becomes ``FAILED_LEAK``.

WHAT A REVIEWER LOSES BY THAT
-----------------------------
A reviewer sees "the ``country`` column's category mix moved, p = 0.0004, over 2,000 rows" and
not "``country = 'PT'`` went from 3% to 18%". The second is more useful and it is a row value.
Getting it requires the gate, a redaction policy and a destination, which is A5's job. The
harness prints the segment key, which is stable, so a reviewer inside the perimeter can look
the segment up and a reviewer outside it cannot.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Final

from godwit_contracts.common import (
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    ScalarValue,
    SegmentKey,
    Version,
)
from godwit_contracts.discovery import Candidate
from godwit_contracts.taint import Sensitivity, Tainted
from pydantic import Field

from godwit_replay.driver import ReplayConfig, ReplayRun, ReplayVerdict
from godwit_replay.errors import FutureKnowledgeError, LeakDetectedError
from godwit_replay.leak import LeakFinding, audit_egress, render_tainted
from godwit_replay.scoring import DiscoveryScore

__all__ = [
    "KILL_SENTENCE",
    "KILL_THRESHOLD",
    "TOP_N",
    "EvidenceRow",
    "KillCriterion",
    "PatternRow",
    "ReplayReport",
    "ReviewMark",
    "assert_passed",
    "build_report",
    "group_candidates",
    "render_markdown",
    "render_review_template",
]

_SECONDS_PER_DAY: Final[float] = 86400.0
_FINGERPRINT_PLACES: Final[int] = 9
_LOCKSTEP_MIN: Final[int] = 2
_PERSISTENT_PERIODS: Final[int] = 3
_EXTREME_LOG_RATIO: Final[float] = math.log(10.0)
_MAX_EXP: Final[float] = 700.0

TOP_N: Final[int] = 20
"""How many patterns a reviewer sees. Twenty, because an hour is the budget."""

KILL_THRESHOLD: Final[int] = 3
"""How many must come back non-obvious-and-real for the thesis to stand."""

KILL_SENTENCE: Final[str] = (
    "If fewer than 3 of these come back non-obvious-and-real, the thesis is not supported."
)
"""Printed by the tool, every time, in its own output. Do not soften it."""


class ReviewMark(StrEnum):
    """What a domain expert concluded about one pattern."""

    UNMARKED = "unmarked"
    OBVIOUS = "obvious"
    """True, and anyone who knows the domain would have said so without being told."""

    KNOWN = "known"
    """True, and the organisation already has a rule, a dashboard or a team on it."""

    NON_OBVIOUS_AND_REAL = "non-obvious-and-real"
    """True, and nobody was looking for it. The only mark that counts."""

    WRONG = "wrong"
    """Not true, or an artefact of the measurement."""


class EvidenceRow(GodwitModel):
    """One measured claim, rendered for a human. Statistics only."""

    kind: str
    statistic: Tainted[float]
    baseline: Tainted[float] | None = None
    effect_size: Tainted[float] | None = None
    p_value: Tainted[float] | None = None
    population: NonNegInt | None = None
    measured_from: tuple[str, ...] = Field(
        default=(),
        description="Which metadata fields or sketches the claim was computed from.",
    )

    def line(self) -> str:
        """One line a reviewer can read without a legend."""
        parts = [f"{self.kind}: statistic={self.statistic.reveal():.6g}"]
        if self.baseline is not None:
            parts.append(f"baseline={self.baseline.reveal():.6g}")
        if self.p_value is not None:
            parts.append(f"p={self.p_value.reveal():.3g}")
        parts.append(f"n={self.population if self.population is not None else 'unknown'}")
        if self.measured_from:
            parts.append("from " + ", ".join(self.measured_from))
        return "  ".join(parts)


class PatternRow(GodwitModel):
    """One pattern as a reviewer sees it."""

    rank: NonNegInt
    segment_key: SegmentKey
    segment_population: NonNegInt | None = None
    detector: str
    detector_version: Version
    score: float
    first_seen_period: str
    first_seen_at: Instant
    columns: tuple[Tainted[str], ...] = Field(
        default=(),
        description="SCHEMA_NAME. A column name is a disclosure in its own right and is "
        "gated as one; on a public benchmark it is also the only way a reviewer can judge.",
    )
    predicate_summary: tuple[str, ...] = Field(
        default=(),
        description="Redacted renderings of the segment predicates: operator and column, "
        "never the value.",
    )
    disclosed: tuple[Tainted[ScalarValue], ...] = Field(
        default=(),
        description="ONLY populated by the leaky configuration. Typed DATA_VALUE so the "
        "audit catches it on type, before anything is rendered.",
    )
    evidence: tuple[EvidenceRow, ...] = ()
    label: str = Field(
        default="",
        description="What the pattern is, in one sentence, generated from its statistics and "
        "column names. Deterministic; no LLM.",
    )
    triage: tuple[str, ...] = Field(
        default=(),
        description="The system's own reading of the pattern -- co-missing block, extreme "
        "value, persistent, one-off. A hypothesis for the reviewer, never a mark.",
    )
    recurrences: NonNegInt = Field(
        default=1, description="How many replay periods surfaced this segment."
    )
    merged: NonNegInt = Field(
        default=1,
        description="Candidates folded into this row because they measured the same rows "
        "moving in lockstep (identical statistics, same snapshot, same detector).",
    )
    mark: ReviewMark = ReviewMark.UNMARKED


class KillCriterion(GodwitModel):
    """The verdict on the thesis, and the sentence that states it."""

    required: NonNegInt = KILL_THRESHOLD
    reviewed: NonNegInt = 0
    non_obvious_and_real: NonNegInt = 0
    sentence: str = KILL_SENTENCE

    @property
    def supported(self) -> bool | None:
        """True, False, or None when nobody has marked anything yet."""
        if self.reviewed == 0:
            return None
        return self.non_obvious_and_real >= self.required

    def statement(self) -> str:
        """What to print, in every case."""
        if self.supported is None:
            return (
                f"UNREVIEWED: {self.sentence} Nothing has been marked yet, so the thesis is "
                "neither supported nor refuted -- it is untested."
            )
        if self.supported:
            return (
                f"SUPPORTED: {self.non_obvious_and_real} of {self.reviewed} marked patterns came "
                f"back non-obvious-and-real, against a threshold of {self.required}."
            )
        return (
            f"NOT SUPPORTED: {self.non_obvious_and_real} of {self.reviewed} marked patterns came "
            f"back non-obvious-and-real, against a threshold of {self.required}. {self.sentence}"
        )


class ReplayReport(GodwitModel):
    """The artifact replay actually publishes. Audited before it is rendered."""

    dataset: str
    handler: str
    config: ReplayConfig
    run_digest: ContentHash
    content_digest: ContentHash
    steps: NonNegInt
    snapshots_replayed: NonNegInt
    generated_as_of: Instant = Field(description="Injected. Never a clock read.")

    top: tuple[PatternRow, ...] = ()
    surfaced_total: NonNegInt = 0
    discovery: DiscoveryScore | None = None
    kill: KillCriterion = Field(default_factory=KillCriterion)

    leaks: tuple[LeakFinding, ...] = ()
    verdict: ReplayVerdict = ReplayVerdict.PASSED
    refusal: str | None = None
    caveats: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        """True when nothing leaked, nothing saw the future and the budget held."""
        return self.verdict is ReplayVerdict.PASSED


def _fingerprint(candidate: Candidate) -> tuple[object, ...]:
    """What a candidate measured, without which column it measured it on."""
    return tuple(
        (
            item.kind.value,
            round(item.statistic.reveal(), _FINGERPRINT_PLACES),
            None if item.baseline is None else round(item.baseline.reveal(), _FINGERPRINT_PLACES),
            item.population,
        )
        for item in candidate.evidence
    )


def group_candidates(ranked: Sequence[Candidate]) -> tuple[tuple[Candidate, ...], ...]:
    """Fold one phenomenon into one row, and drop repeats. Order follows ``ranked``.

    * Candidates from the same detector at the same snapshot with identical statistics
      measured the same rows moving together -- five columns that go null on the same
      trips are one finding, not five.
    * A segment already shown in a stronger group is not shown again. A column that
      re-fires every month is one pattern with a recurrence count, not twelve rows.
    """
    buckets: dict[tuple[object, ...], list[Candidate]] = {}
    for candidate in ranked:
        key = (
            candidate.lineage.detector,
            str(candidate.lineage.snapshot_id),
            _fingerprint(candidate),
        )
        buckets.setdefault(key, []).append(candidate)
    seen: set[str] = set()
    groups: list[tuple[Candidate, ...]] = []
    for members in buckets.values():
        fresh: list[Candidate] = []
        for candidate in members:
            segment = str(candidate.segment.key)
            if segment not in seen:
                seen.add(segment)
                fresh.append(candidate)
        if fresh:
            groups.append(tuple(fresh))
    return tuple(groups)


def _column_names(group: Sequence[Candidate]) -> tuple[str, ...]:
    names: list[str] = []
    for candidate in group:
        for item in candidate.evidence:
            for column in item.columns:
                if column.reveal() not in names:
                    names.append(column.reveal())
    return tuple(names)


def _label(group: Sequence[Candidate]) -> str:
    """One sentence, from the statistics. Column names only; never a predicate value."""
    lead = group[0]
    names = ", ".join(f"`{name}`" for name in _column_names(group)) or "the table"
    detector = lead.lineage.detector
    if not lead.evidence:
        return f"{detector} fired on {names}"
    first = lead.evidence[0]
    now = first.statistic.reveal()
    before = None if first.baseline is None else first.baseline.reveal()
    if detector.endswith("null_rate_shift") and before is not None:
        return f"null rate of new rows in {names} moved from {before:.1%} to {now:.1%}"
    if detector.endswith("ndv_ratio_shift") and before is not None:
        return f"distinct-to-row ratio of {names} moved from {before:.3g} to {now:.3g}"
    if detector.endswith("bounds_drift"):
        # The evidence does not say whether the range or the midpoint moved, so the
        # label does not claim which: it reports the size against the column's norm.
        largest = max(abs(item.statistic.reveal()) for item in lead.evidence)
        typical = before if before is not None else 0.0
        return (
            f"min/max of {names} jumped out of line with its history "
            f"(log-scale change {largest:.3g} against a typical {abs(typical):.3g})"
        )
    if detector.endswith("row_volume_anomaly"):
        return f"row volume changed by a factor of {math.exp(min(now, _MAX_EXP)):.3g} in one period"
    if detector.endswith("file_layout_anomaly"):
        return "the table's file layout (file count or size) changed unlike before"
    if detector.endswith("schema_change"):
        return "the table's schema changed (columns added, removed or retyped)"
    return f"{detector} fired on {names}"


def _triage(group: Sequence[Candidate], recurrences: int) -> tuple[str, ...]:
    """The system's own reading. Stated as hypotheses; the reviewer decides."""
    lead = group[0]
    detector = lead.lineage.detector
    tags: list[str] = []
    if len(group) >= _LOCKSTEP_MIN and detector.endswith("null_rate_shift"):
        tags.append(
            f"co-missing block: {len(group)} columns go null on the same rows -- one upstream "
            "source, vendor or record type stopped sending them"
        )
    if detector.endswith("bounds_drift") and any(
        abs(item.statistic.reveal()) >= _EXTREME_LOG_RATIO for item in lead.evidence
    ):
        tags.append(
            "extreme value: a bound moved over tenfold (log scale) in one period -- most often a "
            "single outlier or a unit/entry error; confirm before treating it as behaviour"
        )
    if recurrences >= _PERSISTENT_PERIODS:
        tags.append(
            f"persistent: re-surfaced in {recurrences} periods -- a regime change, not a blip"
        )
    elif recurrences == 1:
        tags.append("one-off: surfaced in a single period")
    return tuple(tags)


def _pattern_row(
    group: Sequence[Candidate],
    *,
    rank: int,
    first_seen: Mapping[str, Instant],
    period_of: Mapping[str, str],
    recurrences: int,
    reveal: bool,
) -> PatternRow:
    candidate = group[0]
    key = str(candidate.segment.key)
    return PatternRow(
        rank=rank,
        segment_key=candidate.segment.key,
        segment_population=candidate.segment.population,
        detector=candidate.lineage.detector,
        detector_version=candidate.lineage.detector_version,
        score=candidate.score,
        first_seen_period=period_of.get(key, "?"),
        first_seen_at=first_seen.get(key, candidate.created_at),
        columns=tuple(
            column for member in group for item in member.evidence for column in item.columns
        )[:8],
        label=_label(group),
        triage=_triage(group, recurrences),
        recurrences=recurrences,
        merged=len(group),
        predicate_summary=tuple(
            f"{predicate.column.redacted()} {predicate.op.value} "
            + (
                "()"
                if not predicate.values
                else "("
                + ", ".join(render_tainted(value, reveal=reveal) for value in predicate.values)
                + ")"
            )
            for predicate in candidate.segment.predicates
        ),
        disclosed=(
            tuple(value for predicate in candidate.segment.predicates for value in predicate.values)
            if reveal
            else ()
        ),
        evidence=tuple(
            EvidenceRow(
                kind=item.kind.value,
                statistic=item.statistic,
                baseline=item.baseline,
                effect_size=item.effect_size,
                p_value=item.p_value,
                population=item.population,
                measured_from=item.sketch_names,
            )
            for item in candidate.evidence
        ),
    )


def build_report(
    run: ReplayRun,
    *,
    as_of: Instant,
    score: DiscoveryScore | None = None,
    top_n: int = TOP_N,
    forbidden: frozenset[str] = frozenset(),
    caveats: Sequence[str] = (),
    marks: Mapping[str, ReviewMark] | None = None,
) -> ReplayReport:
    """Build the publishable report and audit it. Never raises on a leak: records it.

    The audit runs on the structured report, by type, before :func:`render_markdown` turns
    anything into characters. The string backstop then runs over the rendered form, and the
    findings say which arm fired -- because if only the backstop fired, the taint typing
    upstream is wrong and that is a bug in somebody's package rather than a near miss.
    """
    first_seen = run.first_surfaced()
    period_of: dict[str, str] = {}
    by_id = {candidate.candidate_id: candidate for candidate in run.candidates}
    for outcome in run.steps:
        for candidate_id in outcome.candidate_ids:
            candidate = by_id.get(candidate_id)
            if candidate is None:
                continue
            period_of.setdefault(str(candidate.segment.key), outcome.period_key)

    periods_of: dict[str, set[int]] = {}
    for outcome in run.steps:
        for candidate_id in outcome.candidate_ids:
            found = by_id.get(candidate_id)
            if found is not None:
                periods_of.setdefault(str(found.segment.key), set()).add(outcome.step_index)

    reveal = run.config.reveal_values_in_output
    marked = marks or {}
    rows = tuple(
        _pattern_row(
            group,
            rank=index + 1,
            first_seen=first_seen,
            period_of=period_of,
            recurrences=len(periods_of.get(str(group[0].segment.key), ())) or 1,
            reveal=reveal,
        ).model_copy(update={"mark": marked.get(str(group[0].segment.key), ReviewMark.UNMARKED)})
        for index, group in enumerate(group_candidates(run.ranked())[:top_n])
    )

    reviewed = tuple(row for row in rows if row.mark is not ReviewMark.UNMARKED)
    kill = KillCriterion(
        reviewed=len(reviewed),
        non_obvious_and_real=sum(
            1 for row in reviewed if row.mark is ReviewMark.NON_OBVIOUS_AND_REAL
        ),
    )

    report = ReplayReport(
        dataset=run.dataset,
        handler=run.handler,
        config=run.config,
        run_digest=run.digest,
        content_digest=run.content_digest,
        steps=len(run.steps),
        snapshots_replayed=len(run.steps),
        generated_as_of=as_of,
        top=rows,
        surfaced_total=len(run.candidates),
        discovery=score,
        kill=kill,
        verdict=run.verdict,
        refusal=run.refusal,
        caveats=tuple(caveats),
    )

    leaks = audit_egress(
        report,
        rendered=render_markdown(report, audit_pass=True),
        small_cell_threshold=int(run.config.small_cell_threshold),
        forbidden=forbidden,
        max_sensitivity=run.config.max_sensitivity,
    )
    if leaks:
        return report.model_copy(update={"leaks": leaks, "verdict": ReplayVerdict.FAILED_LEAK})
    return report


def _render_summary(report: ReplayReport) -> list[str]:
    """The header: what ran, against what, and whether it stood up."""
    lines = [
        f"# Replay verdict -- {report.dataset}",
        "",
        f"- handler: `{report.handler}`",
        f"- configuration: `{report.config.name}` (`{report.config.digest()}`)",
        f"- snapshots replayed: {report.snapshots_replayed}",
        f"- candidates surfaced: {report.surfaced_total}",
        f"- run digest: `{report.run_digest}`",
        f"- content digest: `{report.content_digest}`",
        f"- generated as of: {report.generated_as_of.isoformat()}",
        f"- verdict: **{report.verdict.value}**",
    ]
    if report.refusal:
        lines.append(f"- refusal: {report.refusal}")
    lines.append("")
    if report.caveats:
        lines.append("## Read these before you read a number")
        lines.append("")
        lines.extend(f"- {item}" for item in report.caveats)
        lines.append("")
    lines.append("## The kill criterion")
    lines.append("")
    lines.append(report.kill.statement())
    lines.append("")
    return lines


def _render_detection(score: DiscoveryScore) -> list[str]:
    """The headline number, with its caveat attached rather than filed elsewhere."""
    if score.headline_time_to_detection_seconds is None:
        return ["- time to detection: not measurable (no reference instant)"]
    days = score.headline_time_to_detection_seconds / _SECONDS_PER_DAY
    ahead = "ahead of" if days < 0 else "behind"
    warning = (
        "  <-- the reference instant is FABRICATED for this dataset"
        if score.time_to_detection_is_fabricated
        else ""
    )
    return [
        f"- **time to detection (headline): {abs(days):.2f} days {ahead} the reference**{warning}"
    ]


def _render_score(score: DiscoveryScore) -> list[str]:
    """The discovery score, with the coverage each precision was computed over."""
    lines = [
        "## Discovery score",
        "",
        (
            f"- surfaced {score.surfaced_total}, of which {score.surfaced_covered} fall on "
            "segments the truth set has an opinion about"
        ),
    ]
    lines.extend(
        f"- precision@{k} = {score.precision_at_k[k]:.4f} "
        f"over {score.considered_at_k[k]} covered items"
        for k in sorted(score.precision_at_k, key=int)
    )
    lines.extend(_render_detection(score))
    if score.surfaced_on_truth_columns:
        lines.append(
            "- surfaced something about these truth-set columns without naming the truth "
            "segment: " + ", ".join(f"`{name}`" for name in score.surfaced_on_truth_columns)
        )
    if score.novelty_rate is not None:
        lines.append(
            f"- novelty rate against a naive threshold rule: {score.novelty_rate:.4f} "
            f"({score.naive_surfaced_real} of the real segments were also found naively)"
        )
    if score.bytes_per_confirmed is not None:
        lines.append(
            f"- cost: {score.usd_per_confirmed} USD and "
            f"{score.bytes_per_confirmed:,.0f} bytes scanned per confirmed pattern"
        )
    if score.false_positives_on_controls:
        lines.append(
            f"- **{len(score.false_positives_on_controls)} false positive(s) on documented "
            "controls**: " + ", ".join(f"`{key}`" for key in score.false_positives_on_controls)
        )
    lines.append(
        f"- reproducible: {'yes' if score.is_reproducible else '**NO**'} "
        f"(strict digests agree: {score.stability.strict_agree}, "
        f"content digests agree: {score.stability.content_agree})"
    )
    lines.append("")
    return lines


def _render_row(row: PatternRow) -> list[str]:
    """One pattern, with enough evidence for a domain expert to judge it."""
    lines = [
        f"### {row.rank}. `{row.segment_key}` -- {row.detector} v{int(row.detector_version)}",
        "",
        f"- first surfaced: {row.first_seen_period} ({row.first_seen_at.isoformat()})",
        f"- score: {row.score:.6g}",
        "- segment population: "
        + (str(row.segment_population) if row.segment_population is not None else "unknown"),
    ]
    if row.columns:
        lines.append("- columns: " + ", ".join(f"`{column.reveal()}`" for column in row.columns))
    if row.label:
        lines.append(f"- **what**: {row.label}")
    lines.extend(f"- auto-triage: {tag}" for tag in row.triage)
    if row.merged > 1:
        lines.append(f"- merged: {row.merged} lockstep candidates folded into this row")
    if row.predicate_summary:
        lines.append("- predicates: " + "; ".join(row.predicate_summary))
    lines.extend(f"- {item.line()}" for item in row.evidence)
    lines.append(f"- mark: `{row.mark.value}`")
    lines.append("")
    return lines


def render_markdown(report: ReplayReport, *, audit_pass: bool = False) -> str:
    """Render the report for a human. Readable, and short enough to read.

    ``audit_pass`` is set when the renderer is being called by the audit itself, to avoid
    recursing through the findings list that does not exist yet.
    """
    lines = _render_summary(report)
    if report.discovery is not None:
        lines.extend(_render_score(report.discovery))

    lines.append(f"## Top {len(report.top)} patterns")
    lines.append("")
    if not report.top:
        lines.append("Nothing was surfaced. That is a result, not an error.")
        lines.append("")
    for row in report.top:
        lines.extend(_render_row(row))

    if not audit_pass:
        lines.append("## Review template")
        lines.append("")
        lines.append(render_review_template(report))
        lines.append("")
        if report.leaks:
            lines.append("## Egress findings -- THIS RUN FAILED")
            lines.append("")
            lines.extend(f"- {finding.line()}" for finding in report.leaks)
            lines.append("")

    return "\n".join(lines)


def render_review_template(report: ReplayReport) -> str:
    """The markable template. One line per pattern, four marks, and the sentence."""
    lines = [
        "Mark each pattern with exactly one of: obvious | known | non-obvious-and-real | wrong.",
        "",
        f"    {KILL_SENTENCE}",
        "",
        "| # | segment key | detector | first surfaced | mark |",
        "|---|---|---|---|---|",
    ]
    for row in report.top:
        lines.append(
            f"| {row.rank} | `{row.segment_key}` | {row.detector} | {row.first_seen_period} |   |"
        )
    lines.append("")
    lines.append(
        f"Count the non-obvious-and-real rows. Fewer than {KILL_THRESHOLD} means the thesis is "
        "not supported, and the honest thing to do with that result is publish it."
    )
    return "\n".join(lines)


def assert_passed(report: ReplayReport) -> ReplayReport:
    """Return the report, or raise naming what broke. What a test or a CI gate calls."""
    if report.verdict is ReplayVerdict.FAILED_LEAK:
        typed = [finding for finding in report.leaks if finding.kind.value != "forbidden_string"]
        arm = "typed taint" if typed else "STRING BACKSTOP ONLY -- the taint typing is wrong"
        raise LeakDetectedError(
            f"{len(report.leaks)} egress finding(s), caught by {arm}: "
            + "; ".join(finding.line() for finding in report.leaks)
        )
    if report.verdict is ReplayVerdict.FAILED_FUTURE:
        raise FutureKnowledgeError(report.refusal or "a handler saw the future")
    return report


def sensitivity_of(value: Tainted[object]) -> Sensitivity:
    """The sensitivity of one value. A named helper so call sites read as intent."""
    return value.sensitivity
