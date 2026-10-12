"""The adapter from a :class:`~godwit_sdk.SourceBase` plugin onto ``godwit-probe``. DATA PLANE.

Imported lazily, on the first probe, because ``godwit_probe`` imports ``godwit_guard``
and importing ``godwit_guard`` claims the process's single ``SafePayloadIssuer``. A
plugin package that merely imports the SDK -- to be discovered, to be type-checked, to
be scaffolded -- must not have that side effect.

The executor trusts nothing here that it does not check itself: it plans against the
access modes, compares the columns a batch carries with the plan, verifies the query's
output schema, and counts bytes through :attr:`_PluginProbeSource.bytes_read`, which is
measured from the Arrow batches the plugin actually handed over (``RecordBatch.nbytes``),
not from anything the plugin reports.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from decimal import Decimal
from typing import TYPE_CHECKING, Final

import pyarrow as pa
from godwit_contracts.common import Instant, SnapshotId
from godwit_contracts.cost import CostBudget
from godwit_contracts.errors import BudgetExceededError
from godwit_contracts.governance import Guardrail
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.sketch import SketchBundle
from godwit_contracts.source import LogicalType, SnapshotRef, SourceRef
from godwit_guard import AccessModeMap
from godwit_probe import (
    CancelReason,
    CancelToken,
    CostModel,
    DataFileRef,
    Delta,
    DeltaKind,
    ExecutionMode,
    MemoryProbeState,
    ProbeError,
    ProbeExecutor,
    ProbeKeyring,
    ProbeOutcome,
    ProbeStatus,
    RefusalReason,
)

from godwit_sdk._version import __version__
from godwit_sdk.errors import (
    PluginFailedError,
    ProbeRefusedError,
    ResourceLimitError,
    SdkError,
)

if TYPE_CHECKING:
    from godwit_sdk.source import Partition, SourceBase

__all__ = ["bundle_or_raise", "run_probe"]

_LOCATION_PREFIX: Final[str] = "godwit-sdk-partition:"


class _PluginProbeSource:
    """``godwit_probe.ProbeSource`` over one plugin, for one probe run."""

    def __init__(self, plugin: SourceBase, *, deadline: float | None) -> None:
        self._plugin = plugin
        self._runner = plugin.runner
        self._deadline = deadline
        self._bytes = 0
        self._partitions: dict[str, Partition] = {}
        self.failure: SdkError | None = None

    @property
    def bytes_read(self) -> int:
        """Arrow bytes the plugin has handed over so far."""
        return self._bytes

    def _remember(self, error: SdkError) -> SdkError:
        if self.failure is None:
            self.failure = error
        return error

    def resolve_snapshot(self, source: SourceRef, *, at: Instant | None = None) -> SnapshotRef:
        try:
            return self._plugin.resolve_snapshot(source, at=at)
        except SdkError as error:
            raise self._remember(error) from None

    def snapshot_chain(
        self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotId
    ) -> tuple[SnapshotRef, ...]:
        del source, since, until
        return ()

    def delta(self, source: SourceRef, *, since: SnapshotId | None, until: SnapshotRef) -> Delta:
        del since
        table = self._plugin._table(source)
        plain = self._plugin._plain_snapshot(until)
        try:
            parts = tuple(
                self._runner.call(
                    "partitions",
                    lambda: self._plugin.partitions(table, plain),
                    deadline=self._deadline,
                )
            )
        except SdkError as error:
            raise self._remember(error) from None
        files: list[DataFileRef] = []
        for index, part in enumerate(parts):
            location = f"{_LOCATION_PREFIX}{index}"
            self._partitions[location] = part
            files.append(
                DataFileRef(
                    location=location,
                    size_bytes=max(0, int(part.estimated_bytes)),
                    record_count=max(0, int(part.row_count)),
                )
            )
        return Delta(since=None, until=until, kind=DeltaKind.ADDITIVE, files=tuple(files))

    def column_types(self, source: SourceRef, snapshot: SnapshotRef) -> Mapping[str, LogicalType]:
        table = self._plugin._table(source)
        plain = self._plugin._plain_snapshot(snapshot)
        try:
            found = self._runner.call(
                "columns", lambda: self._plugin.columns(table, plain), deadline=self._deadline
            )
        except SdkError as error:
            raise self._remember(error) from None
        return {str(name): LogicalType(kind) for name, kind in found.items()}

    def read(
        self, source: SourceRef, data_file: DataFileRef, *, columns: Sequence[str], batch_rows: int
    ) -> Iterator[pa.RecordBatch]:
        table = self._plugin._table(source)
        part = self._partitions[data_file.location]
        wanted = tuple(columns)
        ceiling = self._runner.limits.max_bytes_read
        items = self._runner.iterate(
            "read", lambda: self._plugin.read(table, part, wanted), deadline=self._deadline
        )
        try:
            for item in items:
                batches = (
                    item.to_batches(max_chunksize=batch_rows)
                    if isinstance(item, pa.Table)
                    else [item]
                )
                for batch in batches:
                    self._bytes += batch.nbytes
                    if ceiling is not None and self._bytes > ceiling:
                        raise ResourceLimitError(
                            f"plugin {self._runner.plugin} exceeded max_bytes_read={ceiling}"
                        )
                    yield batch
        except SdkError as error:
            raise self._remember(error) from None


def run_probe(
    plugin: SourceBase,
    spec: ProbeSpec,
    *,
    budget: CostBudget,
    snapshot: SnapshotRef | None,
    cancel: CancelToken | None,
    access: AccessModeMap | None,
    keyring: ProbeKeyring | None,
    guardrails: Sequence[Guardrail],
    usd_per_gib: Decimal,
) -> ProbeOutcome:
    """Execute ``spec`` against ``plugin`` with godwit-probe's executor."""
    info = plugin.plugin_info()
    bridge = _PluginProbeSource(plugin, deadline=plugin.runner.deadline())
    executor = ProbeExecutor(
        bridge,
        access=access or AccessModeMap(resolved_at=spec.as_of, decisions=()),
        state=MemoryProbeState(),
        keyring=keyring,
        guardrails=guardrails,
        cost_model=CostModel(usd_per_gib=usd_per_gib),
        worker_version=f"godwit-sdk/{__version__}+{info.qualified_name}/{info.version}",
    )
    effective = budget
    if info.limits.max_bytes_read is not None:
        effective = CostBudget.compose(
            budget, budget.model_copy(update={"bytes_scanned": info.limits.max_bytes_read})
        )
    try:
        return executor.execute(
            spec, budget=effective, mode=ExecutionMode.FULL, until=snapshot, cancel=cancel
        )
    except ProbeError as error:
        if bridge.failure is not None:
            raise bridge.failure from None
        raise PluginFailedError(
            info.qualified_name,
            stage=error.stage.value,
            error_type="ProbeError",
            classification=error.code.value,
            original=None,
        ) from None


def bundle_or_raise(outcome: ProbeOutcome) -> SketchBundle:
    """The bundle of a completed outcome; the refusal of any other, raised.

    Budget refusals raise ``BudgetExceededError`` (``SourceAdapter`` law 4), whether the
    estimate was refused up front or the reads overran mid-probe.
    """
    if outcome.bundle is not None:
        return outcome.bundle
    if outcome.status is ProbeStatus.REFUSED and outcome.refusal is not None:
        if outcome.refusal.reason is RefusalReason.BUDGET:
            raise BudgetExceededError(
                f"probe estimated {outcome.estimated_cost.bytes_scanned} bytes, more than "
                "its budget allows"
            )
        raise ProbeRefusedError(outcome.refusal.reason.value)
    if outcome.cancel_reason is CancelReason.BUDGET_EXHAUSTED:
        raise BudgetExceededError("probe stopped when its reads exceeded the budget")
    reason = outcome.cancel_reason.value if outcome.cancel_reason else outcome.status.value
    raise ProbeRefusedError(reason)
