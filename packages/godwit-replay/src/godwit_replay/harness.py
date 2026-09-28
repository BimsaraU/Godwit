"""End to end: load a dataset, replay it, score it, report it.

**This module runs in the DATA PLANE** on the loading side and the control plane on the
scoring side. The boundary is ``SnapshotMetadata``: everything before it reads files,
everything after it reads statistics.

WHY THE HISTORY IS RE-TIMED
---------------------------
An Iceberg snapshot's ``committed_at`` is the wall-clock moment the loader ran. It is
different on every machine, it has nothing to do with the data, and feeding it to detectors
would make ``Candidate.created_at`` a clock reading -- which the replay driver rejects as
future knowledge the moment it lands after the step instant, and rightly.

So :func:`retime` rewrites each snapshot's ``committed_at`` and ``observed_at`` to the instant
the *data* says that period closed, taken from ``LoadedDataset.clock_instants``. That is what
replaying history as if it were arriving live actually means. Nothing else in the metadata is
touched.

WHAT IT COSTS TO RUN
--------------------
Nothing but manifest bytes. The whole pipeline below uses the L-1 tier: A1's
``read_metadata_stats`` reads Iceberg manifests through the object store and touches zero bytes
of table data, and the six detectors are pure functions over the result. That is why the kill
criterion can run on a real public dataset before Wave 2 exists.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Final

from godwit_contracts.common import GodwitModel, Instant, NonNegInt
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_source.iceberg import IcebergAdapter
from godwit_source.metadata import SnapshotMetadata

from godwit_replay.datasets import (
    DatasetSpec,
    LoadedDataset,
    materialise,
    open_catalog,
    periods_for_months,
    resolve,
)
from godwit_replay.driver import (
    MetadataOnlyHandler,
    ReplayConfig,
    ReplayHandler,
    ReplayRun,
    replay,
)
from godwit_replay.scoring import (
    DiscoveryScore,
    TruthSet,
    naive_threshold_keys,
    score_discovery,
    truth_from_golden_manifest,
)
from godwit_replay.verdict import ReplayReport, ReviewMark, build_report

__all__ = [
    "METADATA_BUDGET",
    "HarnessResult",
    "MeterReading",
    "RunOptions",
    "empty_truth",
    "read_history",
    "retime",
    "run_dataset",
]

METADATA_BUDGET: CostBudget = CostBudget(
    bytes_scanned=512 * 1024 * 1024,
    wall_seconds=600.0,
    usd=Decimal("0"),
    llm_tokens=0,
    train_seconds=0.0,
)
"""The ceiling one metadata pass may spend.

``usd`` and ``llm_tokens`` are zero, not large: the metadata tier costs no money and speaks
to no model, and a budget that permitted either would hide the day somebody changed that.
"""


_NO_TRUTH_CAVEAT: Final[str] = (
    "{dataset} has no segment-level ground truth, so precision@k is not computable and is "
    "reported as NaN over zero covered items. Judge this run by the kill criterion, not by a "
    "precision number."
)


class MeterReading(GodwitModel):
    """What one metadata pass read, split by tier.

    ``data_bytes == 0`` is the L-1 claim made measurable. It is a field rather than an
    assertion so that a report can state it and a test can fail on it.
    """

    metadata_bytes: NonNegInt
    data_bytes: NonNegInt
    metadata_reads: NonNegInt
    data_reads: NonNegInt

    @property
    def total_bytes(self) -> int:
        """Every byte read, both tiers."""
        return int(self.metadata_bytes) + int(self.data_bytes)

    @property
    def touched_table_data(self) -> bool:
        """True when something scanned rows. On the metadata tier this must be False."""
        return self.data_bytes > 0


def retime(
    history: Sequence[SnapshotMetadata], instants: Sequence[Instant]
) -> tuple[SnapshotMetadata, ...]:
    """Replace Iceberg commit times with the instants the data's own periods closed."""
    if len(history) != len(instants):
        raise ValueError(
            f"{len(history)} snapshots but {len(instants)} clock instants; they must correspond"
        )
    retimed: list[SnapshotMetadata] = []
    for index, (item, instant) in enumerate(zip(history, instants, strict=True)):
        retimed.append(
            item.model_copy(
                update={
                    "snapshot": item.snapshot.model_copy(
                        update={"committed_at": instant, "sequence_number": index}
                    ),
                    "observed_at": instant,
                }
            )
        )
    return tuple(retimed)


def read_history(
    loaded: LoadedDataset, *, budget: CostBudget = METADATA_BUDGET
) -> tuple[tuple[SnapshotMetadata, ...], MeterReading]:
    """Read one ``SnapshotMetadata`` per commit, oldest first, and report what it cost.

    The budget is charged with what the meter actually saw, snapshot by snapshot, rather than
    with the adapter's own pre-read estimate: an estimate that is charged and never
    reconciled is how a bill surprises somebody. ``MeterReading.data_bytes`` must be zero on
    this path -- a non-zero value means something started scanning table data, and the tests
    assert on it rather than trusting the claim.
    """
    catalog = open_catalog(loaded)
    adapter = IcebergAdapter(catalog)
    refs = adapter.list_snapshots(loaded.source)
    remaining = budget
    history: list[SnapshotMetadata] = []
    seen = 0
    for ref in refs:
        item = adapter.read_metadata_stats(loaded.source, ref, budget=remaining)
        actual = adapter.meter.total_bytes - seen
        seen = adapter.meter.total_bytes
        remaining = remaining.spend(CostSpend(bytes_scanned=actual))
        history.append(item)
    _dispose(catalog)
    reading = MeterReading(
        metadata_bytes=adapter.meter.metadata_bytes,
        data_bytes=adapter.meter.data_bytes,
        metadata_reads=adapter.meter.metadata_reads,
        data_reads=adapter.meter.data_reads,
    )
    return retime(history, loaded.clock_instants[: len(history)]), reading


def _dispose(catalog: object) -> None:
    """Release the SQLite handle a local catalog holds.

    Windows refuses to delete an open file, so a temporary workspace cannot be cleaned up
    while SQLAlchemy still has the catalog connected. Nothing downstream needs the catalog
    once the metadata is read.
    """
    engine = getattr(catalog, "engine", None)
    disposer = getattr(engine, "dispose", None)
    if callable(disposer):
        disposer()


def _meter_caveat(meter: MeterReading) -> str:
    """What the run actually read, as one sentence fit to print next to a number."""
    return (
        f"metadata-only run: {meter.metadata_bytes:,} manifest bytes read from object storage "
        f"and {meter.data_bytes:,} bytes of table data"
    )


def empty_truth(spec: DatasetSpec) -> TruthSet:
    """A truth set for a dataset that has no segment-level ground truth.

    Which is most of them. Every precision@k then comes back NaN over zero covered items,
    which is the honest answer: nobody has told us which of these segments are real. The
    kill criterion exists precisely because this is the normal case.
    """
    return TruthSet(
        dataset=spec.name,
        segments=(),
        label_time_is_fabricated=(spec.label_delay is not None and spec.label_delay.is_fabricated),
        caveats=(_NO_TRUTH_CAVEAT.format(dataset=spec.name), *spec.caveats),
    )


@dataclass(frozen=True, slots=True)
class RunOptions:
    """The optional half of an end-to-end run, bundled.

    ``repeats`` is the stability check: the same configuration is replayed this many extra
    times and the digests compared. One extra run catches every nondeterminism bug the
    harness has needed to catch so far, and it doubles the cost of a verdict run, which is
    why it is a setting rather than a constant.

    ``golden_manifest`` supplies segment-level ground truth for the golden drift fixture.
    Every other dataset gets :func:`empty_truth` and says so in the report's caveats.
    """

    months: int | None = None
    root: Path | None = None
    handler: ReplayHandler | None = None
    budget: CostBudget = METADATA_BUDGET
    repeats: int = 1
    golden_manifest: Mapping[str, object] | None = None
    forbidden: frozenset[str] = frozenset()
    marks: Mapping[str, ReviewMark] | None = None


@dataclass(frozen=True, slots=True)
class HarnessResult:
    """Everything one end-to-end run produced."""

    loaded: LoadedDataset
    history: tuple[SnapshotMetadata, ...]
    meter: MeterReading
    run: ReplayRun
    repeats: tuple[ReplayRun, ...]
    score: DiscoveryScore
    report: ReplayReport


def run_dataset(
    dataset: str,
    *,
    workspace: Path,
    config: ReplayConfig,
    as_of: Instant,
    options: RunOptions | None = None,
) -> HarnessResult:
    """Load, replay, score and report one dataset. See :class:`RunOptions` for the rest."""
    settings = options if options is not None else RunOptions()
    spec = resolve(dataset)
    limit = config.max_periods
    if limit is None and settings.months is not None:
        limit = periods_for_months(spec, settings.months)
    effective = config.model_copy(update={"max_periods": limit})

    loaded = materialise(spec, workspace=workspace, root=settings.root, max_periods=limit)
    history, meter = read_history(loaded, budget=settings.budget)
    used = (
        settings.handler
        if settings.handler is not None
        else MetadataOnlyHandler(code_version=config.code_version)
    )

    def once() -> ReplayRun:
        return replay(
            dataset=spec.name,
            history=history,
            clock_instants=loaded.clock_instants[: len(history)],
            period_keys=loaded.period_keys[: len(history)],
            handler=used,
            config=effective,
            budget=settings.budget,
            labels=loaded.labels,
        )

    run = once()
    extra = tuple(once() for _ in range(max(0, settings.repeats)))

    manifest = settings.golden_manifest
    truth = (
        truth_from_golden_manifest(manifest, dataset=spec.name)
        if manifest is not None
        else empty_truth(spec)
    )
    reference = (
        {item.segment_key: loaded.clock_instants[0] for item in truth.segments if item.is_real}
        if manifest is not None
        else None
    )
    score = score_discovery(
        run,
        truth=truth,
        naive_keys=naive_threshold_keys(history),
        repeat_runs=extra,
        detection_reference=reference,
    )
    report = build_report(
        run,
        as_of=as_of,
        score=score,
        forbidden=settings.forbidden,
        caveats=(*truth.caveats, _meter_caveat(meter)),
        marks=settings.marks,
    )
    return HarnessResult(
        loaded=loaded,
        history=history,
        meter=meter,
        run=run,
        repeats=extra,
        score=score,
        report=report,
    )
