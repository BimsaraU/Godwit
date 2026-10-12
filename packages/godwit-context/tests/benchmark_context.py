"""Synthetic explained-away benchmark.

Run: ``uv run python packages/godwit-context/tests/benchmark_context.py``.

A world of twelve sources in three jurisdictions (US, GB-ENG, DE) over the first half of
2024, with daily probe windows. Injected:

BENIGN -- each one caused by a context event the router is given:
  deploy      a deploy on one source, scoped to one or two columns, shifts a distribution
              on one of those columns within hours (40% of deploys cause anything)
  campaign    a campaign aimed at one channel on one to three sources raises that
              channel's rate six to forty-eight hours after launch
  holiday     a public holiday drops volume on most sources in its own jurisdiction
  month_end   the last business day of the month spikes volume on finance sources
  schema      an A1 schema migration shifts a distribution on that source next window

GENUINE -- nothing mundane caused these:
  isolated    one source, one random day, a random segment and column
  wave        an attack hitting five to eight sources across jurisdictions on one day,
              half of them deliberately placed on a public holiday

Unrelated context is everywhere: 60% of deploys cause nothing, and every day has deploys
somewhere. Isolated anomalies therefore sometimes coincide with a deploy on the same
source and on the same column. That case is genuinely ambiguous from statistics alone,
and it is where the false-explanation rate comes from.

Peers: for every (family, segment) that any source flagged on a day, every source reports
an observation -- the flagged effect where it flagged, noise elsewhere. This is what a
detector's full list of examined hypotheses gives the counterfactual check.

Nothing here was tuned against this benchmark: the policy is the package default, and
the seed is fixed so the numbers are reproducible, not chosen.
"""

from __future__ import annotations

import datetime as _dt
import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from godwit_context import (
    CALENDARS,
    BusinessCalendarSource,
    BusinessCalendarSpec,
    ContextEvent,
    ContextRouter,
    ContextScope,
    ContextType,
    HolidaySource,
    MemoryAuditSink,
    PeerObservation,
    PriorBook,
    Route,
    RoutingPolicy,
    data_quality_from_candidates,
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

START = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
DAYS = 182
DAY = _dt.timedelta(days=1)
HOUR = _dt.timedelta(hours=1)
JURISDICTIONS = {"US": "us", "GB-ENG": "uk", "DE": "de"}
COLUMNS = ("amount", "merchant", "channel", "status", "device")
CHANNELS = ("web", "app", "store")
STATUSES = ("paid", "refund", "chargeback", "pending")

BENIGN = ("deploy", "campaign", "holiday", "month_end", "schema")
GENUINE = ("isolated", "wave")


class Rng:
    """SplitMix64. A seeded generator small enough to read, so the benchmark depends on
    nothing whose output could change under a library upgrade."""

    def __init__(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFFFFFFFFFF

    def _next(self) -> int:
        self._state = (self._state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self._state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return z ^ (z >> 31)

    def random(self) -> float:
        return (self._next() >> 11) / float(1 << 53)

    def randrange(self, lo: int, hi: int) -> int:
        return lo + int(self.random() * (hi - lo))

    def uniform(self, lo: float, hi: float) -> float:
        return lo + (hi - lo) * self.random()

    def choice[T](self, items: Sequence[T]) -> T:
        return items[self.randrange(0, len(items))]

    def sample[T](self, items: Sequence[T], k: int) -> list[T]:
        pool = list(items)
        return [pool.pop(self.randrange(0, len(pool))) for _ in range(k)]

    def gauss(self, mu: float, sigma: float) -> float:
        u1, u2 = 1.0 - self.random(), self.random()
        return mu + sigma * math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)


@dataclass
class _Injected:
    source: str
    day: int
    family: EvidenceKind
    pairs: tuple[tuple[str, str], ...]
    column: str
    effect: float
    label: str


@dataclass
class World:
    sources: list[str]
    injected: list[_Injected] = field(default_factory=list)
    events: list[ContextEvent] = field(default_factory=list)
    schema_candidates: list[Candidate] = field(default_factory=list)


def _segment(pairs: Sequence[tuple[str, str]]) -> Segment:
    return Segment(
        predicates=tuple(
            Predicate(
                column=schema_name(c),
                op=Operator.EQ,
                values=(data_value(v, acquisition=Acquisition.SEGMENT_PREDICATE),),
            )
            for c, v in pairs
        ),
        population=1000,
    )


def _window_end(day: int) -> _dt.datetime:
    return START + (day + 1) * DAY


def _candidate(item: _Injected, index: int, detector: str = "drift") -> Candidate:
    seg = _segment(item.pairs)
    snap = SnapshotId(f"{item.source}_d{item.day}")
    return Candidate(
        candidate_id=CandidateId(f"cand_{index:05d}"),
        source_id=SourceId(item.source),
        segment=seg,
        evidence=(
            Evidence(
                kind=item.family,
                probe_key=ProbeKey(f"prb_{item.source}"),
                snapshot_id=snap,
                segment=seg,
                columns=(schema_name(item.column),),
                statistic=derived_statistic(abs(item.effect) * 5),
                effect_size=derived_statistic(item.effect),
                p_value=derived_statistic(1e-5),
                population=1000,
            ),
        ),
        score=abs(item.effect),
        lineage=Lineage(
            probe_key=ProbeKey(f"prb_{item.source}"),
            snapshot_id=snap,
            detector=detector,
            detector_version=1,
            code_version="benchmark",
            seed=0,
        ),
        created_at=_window_end(item.day),
    )


def _context(
    name: str,
    context_type: ContextType,
    start: _dt.datetime,
    end: _dt.datetime,
    sources: Sequence[str],
    *,
    columns: Sequence[str] = (),
    pairs: Sequence[tuple[str, str]] = (),
) -> ContextEvent:
    return ContextEvent(
        event_id=event_id_for("bench", name),
        context_type=context_type,
        kind=f"{context_type.value}.bench",
        origin="bench",
        start=start,
        end=end,
        scope=ContextScope(
            source_ids=tuple(SourceId(s) for s in sorted(sources)),
            columns=tuple(schema_name(c) for c in columns),
            segments=(_segment(pairs),) if pairs else (),
        ),
    )


def build_world(seed: int) -> World:
    rng = Rng(seed)
    world = World(sources=[f"{tag}_{i}" for tag in JURISDICTIONS.values() for i in range(4)])
    _inject_changes(world, rng)
    _inject_calendars(world, rng)
    _inject_genuine(world, rng)
    return world


def _inject_changes(world: World, rng: Rng) -> None:
    sources, add = world.sources, world.injected.append

    # Deploys: about one per source per ten days, 40% of them causing a shift.
    for source in sources:
        for day in range(DAYS):
            if rng.random() >= 0.1:
                continue
            at = START + day * DAY + rng.randrange(0, 24) * HOUR
            columns = rng.sample(COLUMNS, rng.choice((1, 2)))
            world.events.append(
                _context(
                    f"deploy_{source}_{day}", ContextType.DEPLOY, at, at, [source], columns=columns
                )
            )
            if rng.random() < 0.4:
                lag_day = ((at + rng.randrange(0, 7) * HOUR) - START) // DAY
                status = rng.choice(STATUSES)
                add(
                    _Injected(
                        source,
                        lag_day,
                        EvidenceKind.DISTRIBUTION_SHIFT,
                        (("status", status),),
                        columns[0],
                        rng.choice((-1, 1)) * rng.uniform(2, 5),
                        "deploy",
                    )
                )

    # Campaigns: fifteen, each on one to three sources and one channel.
    for n in range(15):
        day = rng.randrange(0, DAYS - 20)
        targets = rng.sample(sources, rng.choice((1, 2, 3)))
        channel = rng.choice(CHANNELS)
        start = START + day * DAY + rng.randrange(0, 24) * HOUR
        end = start + rng.randrange(3, 15) * DAY
        world.events.append(
            _context(
                f"campaign_{n}",
                ContextType.CAMPAIGN,
                start,
                end,
                targets,
                pairs=[("channel", channel)],
            )
        )
        for source in targets:
            effect_day = ((start + rng.randrange(6, 49) * HOUR) - START) // DAY
            add(
                _Injected(
                    source,
                    effect_day,
                    EvidenceKind.RATE_CHANGE,
                    (("channel", channel),),
                    "channel",
                    rng.uniform(2, 5),
                    "campaign",
                )
            )


def _inject_calendars(world: World, rng: Rng) -> None:
    sources, add = world.sources, world.injected.append

    # Holidays: actual and observed weekday holidays drop volume on 80% of local sources.
    by_code = {
        code: [s for s in sources if s.startswith(tag)] for code, tag in JURISDICTIONS.items()
    }
    holidays = HolidaySource({code: [SourceId(s) for s in ids] for code, ids in by_code.items()})
    world.events.extend(holidays.events(start=START, end=START + DAYS * DAY))
    for code, ids in by_code.items():
        for h in CALENDARS[code].holidays(2024):
            day = (h.day - START.date()).days
            if not 0 <= day < DAYS or h.day.weekday() >= 5:
                continue
            for source in ids:
                if rng.random() < 0.8:
                    add(
                        _Injected(
                            source,
                            day,
                            EvidenceKind.RATE_CHANGE,
                            (),
                            "amount",
                            -rng.uniform(2, 5),
                            "holiday",
                        )
                    )

    # Month end on two finance sources per jurisdiction.
    specs = []
    for code, ids in by_code.items():
        finance = ids[:2]
        specs.append(
            BusinessCalendarSpec(
                source_ids=tuple(SourceId(s) for s in finance),
                calendar=CALENDARS[code],
                quarter_end=False,
            )
        )
    business = BusinessCalendarSource(specs)
    for e in business.events(start=START, end=START + DAYS * DAY):
        world.events.append(e)
        day = (e.start + 12 * HOUR - START) // DAY
        if 0 <= day < DAYS:
            for source in e.scope.source_ids:
                add(
                    _Injected(
                        source,
                        day,
                        EvidenceKind.RATE_CHANGE,
                        (),
                        "amount",
                        rng.uniform(2, 5),
                        "month_end",
                    )
                )

    # Schema migrations from A1, each shifting a distribution in the next window.
    for n in range(8):
        source, day = rng.choice(sources), rng.randrange(1, DAYS - 2)
        marker = _Injected(source, day, EvidenceKind.RATE_CHANGE, (), "amount", 1.0, "a1")
        world.schema_candidates.append(_candidate(marker, 90_000 + n, "metadata.schema_change"))
        add(
            _Injected(
                source,
                day + 1,
                EvidenceKind.DISTRIBUTION_SHIFT,
                (("status", rng.choice(STATUSES)),),
                rng.choice(COLUMNS),
                rng.uniform(2, 5),
                "schema",
            )
        )
    world.events.extend(data_quality_from_candidates(world.schema_candidates))


def _inject_genuine(world: World, rng: Rng) -> None:
    sources, add = world.sources, world.injected.append

    # Genuine: isolated anomalies anywhere.
    for _ in range(80):
        family = rng.choice((EvidenceKind.DISTRIBUTION_SHIFT, EvidenceKind.RATE_CHANGE))
        pairs: tuple[tuple[str, str], ...] = rng.choice(
            ((("status", rng.choice(STATUSES)),), (("channel", rng.choice(CHANNELS)),), ())
        )
        add(
            _Injected(
                rng.choice(sources),
                rng.randrange(0, DAYS),
                family,
                pairs,
                rng.choice(COLUMNS),
                rng.choice((-1, 1)) * rng.uniform(2, 5),
                "isolated",
            )
        )

    # Genuine: coordinated waves, half of them on a public holiday somewhere.
    holiday_days = sorted(
        {
            (h.day - START.date()).days
            for code in JURISDICTIONS
            for h in CALENDARS[code].holidays(2024)
            if 0 <= (h.day - START.date()).days < DAYS and h.day.weekday() < 5
        }
    )
    for n in range(10):
        day = rng.choice(holiday_days) if n % 2 == 0 else rng.randrange(0, DAYS)
        for source in rng.sample(sources, rng.randrange(5, 9)):
            add(
                _Injected(
                    source, day, EvidenceKind.RATE_CHANGE, (), "amount", -rng.uniform(2, 5), "wave"
                )
            )


@dataclass(frozen=True)
class Report:
    explained: Mapping[str, int]
    total: Mapping[str, int]

    def rate(self, label: str) -> float:
        return self.explained[label] / self.total[label] if self.total[label] else 0.0

    def benign_rate(self) -> float:
        return sum(self.explained[k] for k in BENIGN) / sum(self.total[k] for k in BENIGN)

    def genuine_rate(self) -> float:
        return sum(self.explained[k] for k in GENUINE) / sum(self.total[k] for k in GENUINE)

    def table(self) -> str:
        rows = [f"{'class':<10} {'n':>4} {'explained':>9} {'rate':>6}"]
        for label in (*BENIGN, *GENUINE):
            rows.append(
                f"{label:<10} {self.total[label]:>4} {self.explained[label]:>9} "
                f"{self.rate(label):>6.1%}"
            )
        rows.append(f"{'BENIGN':<10} {'':>4} {'':>9} {self.benign_rate():>6.1%}")
        rows.append(f"{'GENUINE':<10} {'':>4} {'':>9} {self.genuine_rate():>6.1%}")
        return "\n".join(rows)


def run(seed: int = 20240101, *, peers: bool = True, threshold: float = 0.5) -> Report:
    world = build_world(seed)
    # One candidate per (source, day, family, segment): first cause wins the label.
    merged: dict[tuple[str, int, str, tuple[tuple[str, str], ...]], _Injected] = {}
    for item in world.injected:
        if 0 <= item.day < DAYS:
            merged.setdefault((item.source, item.day, item.family.value, item.pairs), item)
    by_day: dict[int, list[_Injected]] = defaultdict(list)
    for item in merged.values():
        by_day[item.day].append(item)

    rng = Rng(seed + 1)
    router = ContextRouter(
        audit=MemoryAuditSink(), priors=PriorBook(), routing=RoutingPolicy(threshold=threshold)
    )
    explained: dict[str, int] = defaultdict(int)
    total: dict[str, int] = defaultdict(int)
    index = 0
    for day in sorted(by_day):
        items = by_day[day]
        candidates = []
        for item in items:
            candidates.append(_candidate(item, index))
            index += 1
        observations: list[PeerObservation] = []
        if peers:
            flagged = {(i.source, i.family, i.pairs): i.effect for i in items}
            for family, pairs in sorted({(i.family, i.pairs) for i in items}):
                for source in world.sources:
                    effect = flagged.get((source, family, pairs), rng.gauss(0.0, 0.3))
                    observations.append(
                        PeerObservation(
                            source_id=SourceId(source),
                            segment=_segment(pairs),
                            family=family.value,
                            observed_at=_window_end(day),
                            effect=derived_statistic(effect),
                        )
                    )
        lo, hi = START + (day - 10) * DAY, START + (day + 3) * DAY
        events = [e for e in world.events if e.end >= lo and e.start <= hi]
        decisions = router.route(candidates, events=events, peers=observations, at=_window_end(day))
        for item, decision in zip(items, decisions, strict=True):
            total[item.label] += 1
            explained[item.label] += int(decision.route is Route.EXPLAINED)
    return Report(explained=dict(explained), total=dict(total))


if __name__ == "__main__":
    print("with peer observations (the detector's full test list):")
    print(run().table())
    print()
    print("without peer observations (batch candidates only):")
    print(run(peers=False).table())
    print()
    print("threshold sweep, with peers:  threshold  benign  genuine")
    for value in (0.4, 0.5, 0.6, 0.7, 0.8):
        report = run(threshold=value)
        print(f"{value:>36.1f}  {report.benign_rate():>6.1%}  {report.genuine_rate():>7.1%}")
