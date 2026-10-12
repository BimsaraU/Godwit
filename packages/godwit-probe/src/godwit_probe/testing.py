"""The probe simulator: a synthetic, in-memory source with known statistics.

A PUBLIC TESTING UTILITY. A7 (detectors), A10 (orchestrator), A11 (features) and A19
need probes that behave exactly like production probes -- same planner, same access
modes, same query engine, same sketches, same bundles -- over data whose true
statistics are known in advance, so that a detector's output can be scored against the
truth rather than against another detector.

Nothing here is a mock of the executor. :class:`SyntheticSource` implements
:class:`~godwit_probe.source.ProbeSource`, and :class:`ProbeSimulator` wires it to a real
:class:`~godwit_probe.executor.ProbeExecutor`.

WHAT IS KNOWN
-------------
A :class:`SyntheticTable` is a list of commits. Each commit appends ``rows`` rows (or
overwrites the table, or rewrites files without changing data) and may override any
column's generator from that commit on, which is how drift is injected. Every value is a
pure function of ``(table seed, commit, file, block, column)``: the same rows come back
whatever batch size is asked for, whichever other columns are read with them, and in
whatever order files are visited. That is what lets the batch-versus-streaming test
compare bytes.

:meth:`SyntheticTable.rows_between` gives the exact row count of any delta, and each
column's generator states its own distribution, so null rates, category shares and
distinct counts are known in closed form.

INSTRUMENTED
------------
``bytes_read`` counts the bytes a real columnar read of the requested columns would
move, computed from the same per-column widths the manifest-style estimate uses, so an
estimate and its actual agree exactly. ``reads`` records every (file, columns) pair
opened, so a test can assert that a BLIND column was never read and that a refused
probe opened nothing.

``inject`` makes any metadata or read call raise an exception of the caller's choosing,
which is how the leak tests push poisoned messages through every error path.

Determinism note: values come from ``numpy.random.Generator`` seeded per block. They are
identical run to run on one machine; floating-point columns are not promised to be
bit-identical across CPU architectures.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import math
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Final

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
from godwit_contracts import (
    ColumnRef,
    CostBudget,
    Instant,
    LogicalType,
    PiiClass,
    ProbeId,
    ProbeKind,
    ProbeSpec,
    Segment,
    SketchKind,
    SnapshotId,
    SnapshotRef,
    SourceId,
    SourceKind,
    SourceRef,
    schema_name,
)
from godwit_guard import AccessMode, AccessModeMap, EntropyAssessment, ModeDecision

from godwit_probe.executor import CancelToken, ExecutionMode, ProbeExecutor, ProbeOutcome
from godwit_probe.keyring import ProbeKeyring
from godwit_probe.source import DataFileRef, Delta, DeltaKind
from godwit_probe.state import MemoryProbeState
from godwit_probe.telemetry import ProbeTelemetry

__all__ = [
    "Distribution",
    "FailurePoint",
    "ProbeSimulator",
    "SyntheticColumn",
    "SyntheticCommit",
    "SyntheticSource",
    "SyntheticTable",
    "access_map",
    "generous_budget",
    "simulator_keyring",
]

_FILE_OVERHEAD_BYTES: Final[int] = 1024
_DEFAULT_EPOCH: Final[_dt.datetime] = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
_ID_DIGITS: Final[int] = 12
_SYNTHETIC_SOURCE: Final[SourceId] = SourceId("synthetic")


class Distribution(StrEnum):
    """How a synthetic column's values are drawn."""

    CATEGORICAL = "categorical"
    """One of ``categories`` with probability proportional to ``weights``."""

    NORMAL = "normal"
    LOGNORMAL = "lognormal"
    UNIFORM = "uniform"

    IDENTIFIER = "identifier"
    """``prefix`` + the row's global position, zero-padded: unique across the table."""

    SEQUENCE = "sequence"
    """The row's global position as an integer."""


@dataclass(frozen=True, slots=True)
class SyntheticColumn:
    """One column's generator. Its parameters are the ground truth."""

    name: str
    distribution: Distribution
    categories: tuple[str, ...] = ()
    weights: tuple[float, ...] = ()
    mean: float = 0.0
    sigma: float = 1.0
    low: float = 0.0
    high: float = 1.0
    null_fraction: float = 0.0
    prefix: str = "id-"

    @property
    def logical_type(self) -> LogicalType:
        """The type a source reports for this column."""
        if self.distribution in (Distribution.CATEGORICAL, Distribution.IDENTIFIER):
            return LogicalType.STRING
        if self.distribution is Distribution.SEQUENCE:
            return LogicalType.INT
        return LogicalType.FLOAT

    @property
    def value_bytes(self) -> int:
        """Bytes one value occupies in the simulated columnar file."""
        if self.distribution is Distribution.CATEGORICAL:
            return max(1, math.ceil(sum(len(c) for c in self.categories) / len(self.categories)))
        if self.distribution is Distribution.IDENTIFIER:
            return len(self.prefix) + _ID_DIGITS
        return 8

    def probabilities(self) -> tuple[float, ...]:
        """Category probabilities, normalised. The truth a histogram should recover."""
        weights = self.weights or tuple(1.0 for _ in self.categories)
        total = sum(weights)
        return tuple(weight / total for weight in weights)


@dataclass(frozen=True, slots=True)
class SyntheticCommit:
    """One commit: ``rows`` new rows, optional drift, and what kind of commit it is."""

    rows: int
    overrides: Mapping[str, SyntheticColumn] = field(default_factory=dict)
    operation: DeltaKind = DeltaKind.ADDITIVE
    """``ADDITIVE`` appends; ``NON_ADDITIVE`` overwrites every earlier row;
    ``NO_LOGICAL_CHANGE`` is a compaction that rewrites files and adds nothing."""


@dataclass(frozen=True, slots=True)
class SyntheticTable:
    """A table as a sequence of commits, with its ground truth attached."""

    namespace: str
    name: str
    columns: tuple[SyntheticColumn, ...]
    commits: tuple[SyntheticCommit, ...]
    seed: int
    source_id: SourceId = _SYNTHETIC_SOURCE
    rows_per_file: int = 250_000
    block_rows: int = 65_536
    epoch: Instant = _DEFAULT_EPOCH
    commit_interval: _dt.timedelta = _dt.timedelta(minutes=5)

    def source_ref(self) -> SourceRef:
        """A ``SourceRef`` addressing this table."""
        return SourceRef(
            source_id=self.source_id,
            kind=SourceKind.ICEBERG,
            catalog="synthetic",
            namespace=schema_name(self.namespace, source_id=self.source_id),
            table=schema_name(self.name, source_id=self.source_id),
        )

    def snapshot_id(self, commit: int) -> SnapshotId:
        """The snapshot id minted for a commit index."""
        return SnapshotId(f"s{commit:06d}")

    def commit_index(self, snapshot_id: SnapshotId) -> int:
        """The commit index behind a snapshot id minted by :meth:`snapshot_id`."""
        return int(str(snapshot_id)[1:])

    def snapshot(self, commit: int) -> SnapshotRef:
        """The ``SnapshotRef`` of a commit."""
        return SnapshotRef(
            source_id=self.source_id,
            snapshot_id=self.snapshot_id(commit),
            sequence_number=commit,
            committed_at=self.epoch + self.commit_interval * (commit + 1),
            parent_snapshot_id=self.snapshot_id(commit - 1) if commit > 0 else None,
        )

    def column(self, name: str, commit: int) -> SyntheticColumn:
        """The generator in force for ``name`` at ``commit``, drift included."""
        found = next(column for column in self.columns if column.name == name)
        for index in range(commit + 1):
            found = self.commits[index].overrides.get(name, found)
        return found

    def live_commits(self, until: int) -> tuple[int, ...]:
        """Commits whose rows are in the table at ``until``: since the last overwrite."""
        start = 0
        for index in range(until + 1):
            if self.commits[index].operation is DeltaKind.NON_ADDITIVE:
                start = index
        return tuple(
            index
            for index in range(start, until + 1)
            if self.commits[index].operation is not DeltaKind.NO_LOGICAL_CHANGE
        )

    def rows_between(self, since: int | None, until: int) -> int:
        """Exact row count of the delta ``(since, until]``, or of the table if ``since`` is None."""
        if since is None:
            return sum(self.commits[index].rows for index in self.live_commits(until))
        return sum(
            self.commits[index].rows
            for index in range(since + 1, until + 1)
            if self.commits[index].operation is DeltaKind.ADDITIVE
        )


class FailurePoint(StrEnum):
    """Where :meth:`SyntheticSource.inject` can make a call fail."""

    RESOLVE = "resolve"
    CHAIN = "chain"
    DELTA = "delta"
    SCHEMA = "schema"
    READ_OPEN = "read_open"
    READ_MID = "read_mid"


@dataclass(frozen=True, slots=True)
class _FileId:
    commit: int
    index: int
    rows: int
    first_row: int


class SyntheticSource:
    """:class:`~godwit_probe.source.ProbeSource` over synthetic tables."""

    def __init__(
        self, tables: Sequence[SyntheticTable], *, visible_commits: int | None = None
    ) -> None:
        self._tables = {(table.namespace, table.name): table for table in tables}
        self._visible = visible_commits
        self._bytes = 0
        self._failures: dict[FailurePoint, Callable[[], Exception]] = {}
        self.reads: list[tuple[str, tuple[str, ...]]] = []
        self.metadata_calls = 0

    # -- simulation controls -------------------------------------------------------------

    def publish(self, count: int = 1) -> None:
        """Make ``count`` more commits visible: a writer committing, as a stream would."""
        self._visible = (self._visible or 0) + count

    def inject(self, point: FailurePoint, failure: Callable[[], Exception] | None) -> None:
        """Make calls at ``point`` raise ``failure()``; pass None to stop."""
        if failure is None:
            self._failures.pop(point, None)
        else:
            self._failures[point] = failure

    def _maybe_fail(self, point: FailurePoint) -> None:
        make = self._failures.get(point)
        if make is not None:
            raise make()

    # -- ProbeSource ---------------------------------------------------------------------

    @property
    def bytes_read(self) -> int:
        """Bytes a columnar read of the requested columns would have moved."""
        return self._bytes

    def _table(self, source: SourceRef) -> SyntheticTable:
        return self._tables[(source.namespace.reveal(), source.table.reveal())]

    def _last_visible(self, table: SyntheticTable) -> int:
        count = len(table.commits) if self._visible is None else self._visible
        return min(count, len(table.commits)) - 1

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        """The newest visible commit at or before ``at``."""
        self.metadata_calls += 1
        self._maybe_fail(FailurePoint.RESOLVE)
        table = self._table(source)
        last = self._last_visible(table)
        if last < 0:
            raise LookupError("no commit is visible yet")
        if at is not None:
            eligible = [i for i in range(last + 1) if table.snapshot(i).committed_at <= at]
            if not eligible:
                raise LookupError("no commit had been made by that instant")
            last = eligible[-1]
        return table.snapshot(last)

    def snapshot_chain(
        self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotId
    ) -> tuple[SnapshotRef, ...]:
        """Commits in ``(since, until]``."""
        self.metadata_calls += 1
        self._maybe_fail(FailurePoint.CHAIN)
        table = self._table(source)
        start = 0 if since is None else table.commit_index(since) + 1
        return tuple(table.snapshot(i) for i in range(start, table.commit_index(until) + 1))

    def delta(self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotRef) -> Delta:
        """Classified from the commit operations, exactly as the Iceberg source does."""
        self.metadata_calls += 1
        self._maybe_fail(FailurePoint.DELTA)
        table = self._table(source)
        end = table.commit_index(until.snapshot_id)
        if since is None:
            commits = table.live_commits(end)
            return Delta(
                since=None, until=until, kind=DeltaKind.ADDITIVE, files=self._files(table, commits)
            )
        start = table.commit_index(since)
        operations = {table.commits[i].operation for i in range(start + 1, end + 1)}
        if start == end or operations == {DeltaKind.NO_LOGICAL_CHANGE}:
            return Delta(since=since, until=until, kind=DeltaKind.NO_LOGICAL_CHANGE, files=())
        if DeltaKind.NON_ADDITIVE in operations:
            return Delta(since=since, until=until, kind=DeltaKind.NON_ADDITIVE, files=())
        commits = tuple(
            i for i in range(start + 1, end + 1) if table.commits[i].operation is DeltaKind.ADDITIVE
        )
        return Delta(
            since=since, until=until, kind=DeltaKind.ADDITIVE, files=self._files(table, commits)
        )

    def column_types(self, source: SourceRef, snapshot: SnapshotRef) -> Mapping[str, LogicalType]:
        """Every column's logical type."""
        del snapshot
        self.metadata_calls += 1
        self._maybe_fail(FailurePoint.SCHEMA)
        return {column.name: column.logical_type for column in self._table(source).columns}

    def read(
        self, source: SourceRef, data_file: DataFileRef, *, columns: Sequence[str], batch_rows: int
    ) -> Iterator[pa.RecordBatch]:
        """Generate the requested columns of one file, block by block."""
        self._maybe_fail(FailurePoint.READ_OPEN)
        table = self._table(source)
        file_id = _parse_location(data_file.location)
        requested = tuple(columns)
        self.reads.append((data_file.location, requested))
        self._bytes += _FILE_OVERHEAD_BYTES
        offset = 0
        block = 0
        while offset < file_id.rows:
            if block > 0:
                self._maybe_fail(FailurePoint.READ_MID)
            size = min(table.block_rows, file_id.rows - offset)
            arrays = [
                _generate(
                    table,
                    table.column(name, file_id.commit),
                    file_id,
                    block,
                    first_row=file_id.first_row + offset,
                    rows=size,
                    column_index=_column_index(table, name),
                )
                for name in requested
            ]
            self._bytes += (
                sum(table.column(n, file_id.commit).value_bytes for n in requested) * size
            )
            generated = pa.RecordBatch.from_arrays(arrays, names=list(requested))
            for start in range(0, size, batch_rows):
                yield generated.slice(start, batch_rows)
            offset += size
            block += 1

    def _files(self, table: SyntheticTable, commits: Sequence[int]) -> tuple[DataFileRef, ...]:
        files: list[DataFileRef] = []
        for commit in commits:
            rows = table.commits[commit].rows
            first_row = sum(table.commits[i].rows for i in range(commit))
            for index in range(math.ceil(rows / table.rows_per_file)):
                count = min(table.rows_per_file, rows - index * table.rows_per_file)
                widths = {c.name: table.column(c.name, commit).value_bytes for c in table.columns}
                column_bytes = {name: width * count for name, width in widths.items()}
                files.append(
                    DataFileRef(
                        location=(
                            f"synthetic://c{commit}/f{index}/r{count}"
                            f"/o{first_row + index * table.rows_per_file}"
                        ),
                        size_bytes=sum(column_bytes.values()) + _FILE_OVERHEAD_BYTES,
                        record_count=count,
                        column_bytes=column_bytes,
                    )
                )
        return tuple(files)


def _parse_location(location: str) -> _FileId:
    parts = location.removeprefix("synthetic://").split("/")
    return _FileId(
        commit=int(parts[0][1:]),
        index=int(parts[1][1:]),
        rows=int(parts[2][1:]),
        first_row=int(parts[3][1:]),
    )


def _column_index(table: SyntheticTable, name: str) -> int:
    return next(i for i, column in enumerate(table.columns) if column.name == name)


def _generate(
    table: SyntheticTable,
    column: SyntheticColumn,
    file_id: _FileId,
    block: int,
    *,
    first_row: int,
    rows: int,
    column_index: int,
) -> pa.Array:
    rng = np.random.default_rng([table.seed, file_id.commit, file_id.index, block, column_index])
    nulls = rng.random(rows) < column.null_fraction if column.null_fraction > 0 else None
    positions = np.arange(first_row, first_row + rows, dtype=np.int64)
    match column.distribution:
        case Distribution.CATEGORICAL:
            indices = rng.choice(len(column.categories), size=rows, p=column.probabilities())
            codes = pa.array(indices.astype(np.int32), mask=nulls)
            dictionary = pa.array(column.categories, type=pa.string())
            return pa.DictionaryArray.from_arrays(codes, dictionary).cast(pa.string())
        case Distribution.IDENTIFIER:
            digits = pc.utf8_lpad(pc.cast(pa.array(positions), pa.string()), _ID_DIGITS, "0")
            joined = pc.binary_join_element_wise(pa.scalar(column.prefix), digits, "")
            return joined if nulls is None else pc.if_else(pa.array(nulls), None, joined)
        case Distribution.SEQUENCE:
            return pa.array(positions, mask=nulls)
        case Distribution.NORMAL:
            return pa.array(rng.normal(column.mean, column.sigma, rows), mask=nulls)
        case Distribution.LOGNORMAL:
            return pa.array(rng.lognormal(column.mean, column.sigma, rows), mask=nulls)
        case Distribution.UNIFORM:
            return pa.array(rng.uniform(column.low, column.high, rows), mask=nulls)


# --------------------------------------------------------------------------------------
# Access modes, keys and budgets for simulated runs
# --------------------------------------------------------------------------------------


def access_map(
    table: SyntheticTable | SourceRef,
    modes: Mapping[str, AccessMode],
    *,
    at: Instant,
    pii: Mapping[str, PiiClass] | None = None,
    entropy_bits: Mapping[str, float] | None = None,
) -> AccessModeMap:
    """A resolved access-mode map for a synthetic table, or for any table by its ref.

    Columns missing from ``modes`` get no decision at all, which the planner treats as
    unclassified -- the fail-closed case. OPAQUE columns default to 64 bits of declared
    input entropy and ``DIRECT_IDENTIFIER``; OPEN columns to ``NONE``. In production this
    map comes from ``godwit_guard.AccessControl.mode_map``; building it by hand is only
    for simulations.
    """
    pii = pii or {}
    entropy_bits = entropy_bits or {}
    if isinstance(table, SourceRef):
        source_id, table_name = table.source_id, table.table.reveal()
    else:
        source_id, table_name = table.source_id, table.name
    defaults = {
        AccessMode.OPEN: PiiClass.NONE,
        AccessMode.OPAQUE: PiiClass.DIRECT_IDENTIFIER,
        AccessMode.BLIND: PiiClass.CREDENTIAL,
    }
    decisions = []
    for name, mode in modes.items():
        bits = entropy_bits.get(name, 64.0 if mode is AccessMode.OPAQUE else None)
        decisions.append(
            ModeDecision(
                column=ColumnRef(
                    source_id=source_id,
                    table=schema_name(table_name, source_id=source_id),
                    column=schema_name(name, source_id=source_id, table=table_name),
                ),
                mode=mode,
                pii_class=pii.get(name, defaults[mode]),
                confirmed=True,
                reasons=("simulator",),
                entropy=(
                    None
                    if bits is None
                    else EntropyAssessment(bits=bits, min_bits=24.0, basis=("simulator",))
                ),
            )
        )
    return AccessModeMap(resolved_at=at, decisions=tuple(decisions))


def simulator_keyring(label: str = "godwit-probe-simulator") -> ProbeKeyring:
    """A deterministic keyring for simulations. **Never use outside a test.**"""
    column = hashlib.blake2b(f"{label}/column".encode(), digest_size=32).digest()
    sketch = hashlib.blake2b(f"{label}/sketch".encode(), digest_size=32).digest()
    return ProbeKeyring(column_key=column, sketch_key=sketch)


def generous_budget(*, bytes_scanned: int = 10**15) -> CostBudget:
    """A budget nothing in a simulation will hit, unless you lower ``bytes_scanned``."""
    return CostBudget(
        bytes_scanned=bytes_scanned,
        wall_seconds=3600.0,
        usd=Decimal(1000),
        llm_tokens=0,
        train_seconds=0.0,
    )


class ProbeSimulator:
    """A real executor over a synthetic source, with an in-memory incremental state."""

    def __init__(
        self,
        table: SyntheticTable,
        *,
        modes: Mapping[str, AccessMode],
        at: Instant = _DEFAULT_EPOCH,
        pii: Mapping[str, PiiClass] | None = None,
        entropy_bits: Mapping[str, float] | None = None,
        keyring: ProbeKeyring | None = None,
        visible_commits: int | None = None,
        telemetry: ProbeTelemetry | None = None,
        batch_rows: int = 65_536,
    ) -> None:
        self.table = table
        self.source = SyntheticSource([table], visible_commits=visible_commits)
        self.state = MemoryProbeState()
        self.access = access_map(table, modes, at=at, pii=pii, entropy_bits=entropy_bits)
        self.executor = ProbeExecutor(
            self.source,
            access=self.access,
            state=self.state,
            keyring=keyring if keyring is not None else simulator_keyring(),
            telemetry=telemetry,
            batch_rows=batch_rows,
        )
        self._at = at

    def spec(
        self,
        kind: ProbeKind,
        columns: Sequence[str] = (),
        *,
        sketches: Sequence[SketchKind] = (),
        segment: Segment | None = None,
        params: Mapping[str, int | float | str | bool] | None = None,
        seed: int = 0,
        budget: CostBudget | None = None,
        probe_id: str = "sim-probe",
    ) -> ProbeSpec:
        """A spec over this simulation's table."""
        return ProbeSpec(
            probe_id=ProbeId(probe_id),
            kind=kind,
            spec_version=1,
            source=self.table.source_ref(),
            columns=tuple(
                schema_name(name, source_id=self.table.source_id, table=self.table.name)
                for name in columns
            ),
            segment=segment if segment is not None else Segment(),
            sketches=tuple(sketches),
            params=dict(params or {}),
            budget=budget if budget is not None else generous_budget(),
            seed=seed,
            as_of=self._at,
        )

    def run(
        self,
        spec: ProbeSpec,
        *,
        budget: CostBudget | None = None,
        mode: ExecutionMode = ExecutionMode.INCREMENTAL,
        cancel: CancelToken | None = None,
    ) -> ProbeOutcome:
        """Execute, and advance the incremental state when the outcome covers a snapshot."""
        outcome = self.executor.execute(
            spec,
            budget=budget if budget is not None else generous_budget(),
            mode=mode,
            cancel=cancel,
        )
        if outcome.covers_snapshot:
            self.state.advance(outcome.probe_key, outcome.snapshot_id)
        return outcome
