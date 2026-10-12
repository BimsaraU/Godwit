"""``@source``: a custom data source in about fifty lines. **DATA PLANE.**

A source plugin reads customer rows. Everything it touches is customer data, so the
base class does every part of the job that is easy to get subtly wrong, and leaves the
plugin only the part that is genuinely about the backend:

=====================================  ===============================================
The plugin writes                      The base does
=====================================  ===============================================
``snapshot`` -- what version is it     access modes (BLIND / OPAQUE / OPEN) at plan time
``columns`` -- name and logical type   budget: refuse before reading, stop mid-read
``partitions`` -- units of reading     cancellation between batches
``read`` -- Arrow batches, named       sketching, envelopes, the ``SketchBundle``
columns only                           tainting bounds, value lists, names
``column_stats`` (optional)            exception sanitising, cost accounting
``for_conformance`` -- a fake backend  capability and resource enforcement
=====================================  ===============================================

The probe itself is ``godwit-probe``'s :class:`~godwit_probe.ProbeExecutor` -- the same
code that probes Iceberg -- run over an adapter onto these five methods. A plugin source
therefore gets the identical plan-time access-mode enforcement, keyed hashing of OPAQUE
columns and refusal semantics as a core one. Nothing about a plugin is a second-class
path.

THE RULES A SOURCE PLUGIN MUST KEEP
-----------------------------------
1. ``read`` returns only the columns it was asked for. If the backend returns more (a
   REST API that always sends every field), drop the rest *inside* ``read`` with
   ``batch.select(columns)``. Handing over an extra column fails the probe: a BLIND
   column in a batch means it was read.
2. ``partitions`` estimates honestly, from metadata. The estimate is what the budget is
   checked against before any read; the bytes actually handed over are counted and the
   probe stops when they exceed the budget.
3. ``column_stats`` returns plain values from the backend's own catalog. Do not wrap them
   in ``Tainted`` and do not compute them by scanning: the base taints them correctly,
   and a scan belongs in a probe, where the budget can see it.
4. Never print, never import :mod:`logging`, never put a value in an exception message.
   Use ``self.log``. The conformance kit checks all three.

Without :meth:`SourceBase.govern`, every column is BLIND and every probe that reads a
column is refused. That is the fail-closed default, not a bug.
"""

from __future__ import annotations

import abc
import datetime as _dt
import importlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from types import ModuleType
from typing import TYPE_CHECKING, Final, Self

import pyarrow as pa
from godwit_contracts.common import (
    ScalarValue,
    SnapshotId,
    SourceId,
    is_safe_identifier,
    require_utc,
)
from godwit_contracts.cost import CostBudget
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.sketch import SketchBundle
from godwit_contracts.source import (
    ColumnProfile,
    ColumnRef,
    LogicalType,
    SnapshotRef,
    SourceKind,
    SourceRef,
    TableProfile,
)
from godwit_contracts.taint import Acquisition, data_value, derived_statistic, schema_name

from godwit_sdk.capabilities import Capabilities, ResourceLimits
from godwit_sdk.errors import PluginFailedError, ProbeRefusedError
from godwit_sdk.plugin import (
    DEFAULT_REQUIREMENT,
    PluginBase,
    PluginKind,
    decorator_for,
)

if TYPE_CHECKING:
    from godwit_contracts.governance import Guardrail
    from godwit_guard import AccessModeMap
    from godwit_probe import CancelToken, ProbeKeyring, ProbeOutcome

__all__ = [
    "BOUNDS_ACQUISITION",
    "PLUGIN_SOURCE_KIND",
    "VALUE_LIST_ACQUISITION",
    "ColumnStats",
    "Partition",
    "Snapshot",
    "SourceBase",
    "TableName",
    "logical_type",
    "source",
]

PLUGIN_SOURCE_KIND: Final[SourceKind] = SourceKind.PARQUET
"""The ``SourceKind`` a plugin's ``SourceRef`` carries. The vocabulary is closed and has
no member for a plugin, so this is a stand-in; the plugin is identified by the ref's
``catalog`` handle (``plugin:<namespace>.<name>``). See
``docs/change-requests/CR-A9-source-kind-is-closed-to-plugins.md``."""

BOUNDS_ACQUISITION: Final[Acquisition] = Acquisition.ICEBERG_MANIFEST_BOUNDS
"""How a plugin's catalog min/max are tainted. The contract has no generic "catalog
bounds" route; this is the nearest, and its floor is DATA_VALUE, which is what matters.
See ``docs/change-requests/CR-A9-acquisition-has-no-generic-catalog-route.md``."""

VALUE_LIST_ACQUISITION: Final[Acquisition] = Acquisition.PG_STATS_MCV
"""How a plugin's catalog most-common-values are tainted. Same CR as above."""

_PROFILE_VERSION: Final[int] = 1


@dataclass(frozen=True, slots=True)
class TableName:
    """A table, by the backend's own names. **Data plane**: these are customer names."""

    namespace: str
    name: str


@dataclass(frozen=True, slots=True)
class Snapshot:
    """A version of a table, as the backend identifies it.

    ``snapshot_id`` must be a plain identifier (letters, digits, ``_.-``) that changes
    whenever the data does -- a commit id, an etag, a high-water mark. ``committed_at``
    is when that version came to exist, tz-aware. Never a clock read: if the backend has
    no notion of time, use a fixed epoch and say so in your docs.
    """

    snapshot_id: str
    sequence_number: int
    committed_at: _dt.datetime


@dataclass(frozen=True, slots=True)
class Partition:
    """One unit of reading: a file, a page range, a shard.

    ``key`` is your handle for it and goes nowhere but back into your ``read``.
    ``estimated_bytes`` is your honest upper estimate of what reading it moves, from
    metadata; ``row_count`` likewise. Both feed the budget check before any read.
    """

    key: str
    estimated_bytes: int
    row_count: int


@dataclass(frozen=True, slots=True)
class ColumnStats:
    """Catalog statistics for one column, as plain values. The base taints them.

    ``minimum``, ``maximum`` and ``common_values`` are ROW VALUES -- the minimum of a
    name column is a name -- and come back from :meth:`SourceBase.profile_table` as
    ``Tainted`` DATA_VALUE. ``null_fraction`` and ``distinct`` are statistics.
    """

    null_fraction: float | None = None
    distinct: int | None = None
    minimum: ScalarValue = None
    maximum: ScalarValue = None
    common_values: tuple[ScalarValue, ...] = ()


@dataclass(frozen=True, slots=True)
class _Governance:
    access: AccessModeMap
    keyring: ProbeKeyring | None
    guardrails: tuple[Guardrail, ...]
    usd_per_gib: Decimal


def _bridge() -> ModuleType:
    """``godwit_sdk._bridge``, imported on first use. See that module for why it is lazy."""
    return importlib.import_module("godwit_sdk._bridge")


_ARROW_TYPES: Final[tuple[tuple[Callable[[pa.DataType], bool], LogicalType], ...]] = (
    (pa.types.is_boolean, LogicalType.BOOL),
    (pa.types.is_integer, LogicalType.INT),
    (pa.types.is_floating, LogicalType.FLOAT),
    (pa.types.is_decimal, LogicalType.DECIMAL),
    (pa.types.is_date, LogicalType.DATE),
    (pa.types.is_timestamp, LogicalType.TIMESTAMP),
    (pa.types.is_string, LogicalType.STRING),
    (pa.types.is_large_string, LogicalType.STRING),
    (pa.types.is_binary, LogicalType.BINARY),
    (pa.types.is_large_binary, LogicalType.BINARY),
)


def logical_type(arrow_type: pa.DataType) -> LogicalType:
    """The contracts' logical type for an Arrow type; ``UNKNOWN`` when there is none."""
    return next((kind for test, kind in _ARROW_TYPES if test(arrow_type)), LogicalType.UNKNOWN)


class SourceBase(PluginBase, abc.ABC):
    """Base class for ``@source`` plugins. Implements ``godwit_contracts.SourceAdapter``.

    Implement the five abstract methods. Do not override the others; registration
    rejects a plugin that does (see ``SDK_METHODS``).
    """

    SDK_METHODS = (
        "resolve_snapshot",
        "profile_table",
        "execute_probe",
        "run_probe",
        "govern",
        "source_ref",
    )

    # -- what the plugin writes ----------------------------------------------------------

    @abc.abstractmethod
    def snapshot(self, table: TableName, *, at: _dt.datetime | None) -> Snapshot:
        """The version current at ``at``, or the newest when ``at`` is None. Metadata."""

    @abc.abstractmethod
    def columns(self, table: TableName, snapshot: Snapshot) -> Mapping[str, LogicalType]:
        """Every column's name and logical type at ``snapshot``. Metadata."""

    @abc.abstractmethod
    def partitions(self, table: TableName, snapshot: Snapshot) -> Sequence[Partition]:
        """The units a full read of ``snapshot`` consists of, with estimates. Metadata."""

    @abc.abstractmethod
    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        """Read ``columns`` of one partition, and no other column. The only data read."""

    @classmethod
    @abc.abstractmethod
    def for_conformance(cls, tables: Mapping[str, pa.Table]) -> Self:
        """An instance serving ``tables`` (keyed by table name) from a fake backend.

        The conformance kit calls this with poisoned data. Build the same code path your
        real backend uses -- a fake transport, a temporary database -- so that what is
        tested is what ships.
        """

    def column_stats(self, table: TableName, snapshot: Snapshot) -> Mapping[str, ColumnStats]:
        """Catalog statistics, keyed by column name. Optional; the default has none."""
        del table, snapshot
        return {}

    # -- what the SDK provides -----------------------------------------------------------

    @classmethod
    def source_ref(cls, *, source_id: str, namespace: str, table: str) -> SourceRef:
        """A correctly tainted ``SourceRef`` addressing one of this plugin's tables."""
        return SourceRef(
            source_id=SourceId(source_id),
            kind=PLUGIN_SOURCE_KIND,
            catalog=f"plugin:{cls.plugin_info().qualified_name}",
            namespace=schema_name(namespace, source_id=source_id),
            table=schema_name(table, source_id=source_id),
        )

    def govern(
        self,
        *,
        access: AccessModeMap,
        keyring: ProbeKeyring | None = None,
        guardrails: Sequence[Guardrail] = (),
        usd_per_gib: Decimal = Decimal(0),
    ) -> Self:
        """Attach the access-mode map (from ``godwit_guard.AccessControl.mode_map``).

        ``keyring`` holds the data-plane keys OPAQUE columns are hashed with; without one,
        probes over OPAQUE columns are refused. Returns ``self``.
        """
        self.__dict__["_godwit_governance"] = _Governance(
            access=access,
            keyring=keyring,
            guardrails=tuple(guardrails),
            usd_per_gib=usd_per_gib,
        )
        return self

    def resolve_snapshot(self, source: SourceRef, *, at: _dt.datetime | None = None) -> SnapshotRef:
        """``SourceAdapter.resolve_snapshot``: the plugin's snapshot, as a contract ref."""
        table = self._table(source)
        found = self.runner.call("snapshot", lambda: self.snapshot(table, at=at))
        return self._snapshot_ref(source, found)

    def profile_table(
        self, source: SourceRef, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> TableProfile:
        """``SourceAdapter.profile_table``: metadata only, charged nothing, tainted here.

        Nothing is scanned, so ``budget`` is never drawn on.
        """
        del budget
        table = self._table(source)
        plain = self._plain_snapshot(snapshot)
        runner = self.runner
        types = dict(runner.call("columns", lambda: self.columns(table, plain)))
        stats = dict(runner.call("column_stats", lambda: self.column_stats(table, plain)))
        parts = tuple(runner.call("partitions", lambda: self.partitions(table, plain)))
        rows = sum(part.row_count for part in parts)
        sid = str(source.source_id)
        table_name = table.name
        snap = str(snapshot.snapshot_id)

        def taint_value(value: ScalarValue, acquisition: Acquisition, column: str) -> object:
            return data_value(
                value,
                acquisition=acquisition,
                source_id=sid,
                table=table_name,
                column=column,
                snapshot_id=snap,
            )

        columns: list[ColumnProfile] = []
        for name in sorted(types):
            found = stats.get(name, ColumnStats())
            stat: Callable[..., object] = derived_statistic
            columns.append(
                ColumnProfile.model_validate(
                    {
                        "ref": ColumnRef(
                            source_id=source.source_id,
                            table=schema_name(table_name, source_id=sid),
                            column=schema_name(name, source_id=sid, table=table_name),
                        ),
                        "logical_type": types[name],
                        "native_type": LogicalType(types[name]).value,
                        "nullable": True,
                        "null_fraction": None
                        if found.null_fraction is None
                        else stat(float(found.null_fraction), population=rows, column=name),
                        "distinct_estimate": None
                        if found.distinct is None
                        else stat(int(found.distinct), population=rows, column=name),
                        "row_count": stat(rows, population=rows, column=name),
                        "min_bound": None
                        if found.minimum is None
                        else taint_value(found.minimum, BOUNDS_ACQUISITION, name),
                        "max_bound": None
                        if found.maximum is None
                        else taint_value(found.maximum, BOUNDS_ACQUISITION, name),
                        "most_common_values": tuple(
                            taint_value(value, VALUE_LIST_ACQUISITION, name)
                            for value in found.common_values
                        ),
                        "observed_at": snapshot.committed_at,
                        "profile_version": _PROFILE_VERSION,
                    }
                )
            )
        return TableProfile(
            source=source,
            snapshot=snapshot,
            columns=tuple(columns),
            row_count_estimate=derived_statistic(rows, population=rows, source_id=sid),
            observed_at=snapshot.committed_at,
            profile_version=_PROFILE_VERSION,
        )

    def execute_probe(
        self, spec: ProbeSpec, snapshot: SnapshotRef, *, budget: CostBudget
    ) -> SketchBundle:
        """``SourceAdapter.execute_probe``: a bundle, or a refusal raised as an error.

        Budget refusals raise ``BudgetExceededError`` (contract law 4); any other refusal
        raises :class:`~godwit_sdk.errors.ProbeRefusedError`. :meth:`run_probe` returns
        the same outcomes as values instead.
        """
        outcome = self.run_probe(spec, budget=budget, snapshot=snapshot)
        settle: Callable[[ProbeOutcome], SketchBundle] = _bridge().bundle_or_raise
        return settle(outcome)

    def run_probe(
        self,
        spec: ProbeSpec,
        *,
        budget: CostBudget,
        snapshot: SnapshotRef | None = None,
        cancel: CancelToken | None = None,
    ) -> ProbeOutcome:
        """Run one probe and return every outcome -- completed, refused, cancelled -- as a value.

        Always a full measurement of ``snapshot`` (or of the newest snapshot): a plugin
        source has no file-level history, so there is nothing to measure incrementally.
        """
        run_probe: Callable[..., ProbeOutcome] = _bridge().run_probe
        if spec.source.catalog != f"plugin:{self.plugin_info().qualified_name}":
            raise ProbeRefusedError("wrong_source")
        governance = self.__dict__.get("_godwit_governance")
        return run_probe(
            self,
            spec,
            budget=budget,
            snapshot=snapshot,
            cancel=cancel,
            access=governance.access if governance else None,
            keyring=governance.keyring if governance else None,
            guardrails=governance.guardrails if governance else (),
            usd_per_gib=governance.usd_per_gib if governance else Decimal(0),
        )

    # -- internals -----------------------------------------------------------------------

    def _table(self, source: SourceRef) -> TableName:
        # Data plane: the plugin needs the backend's own names to address the table.
        return TableName(namespace=source.namespace.reveal(), name=source.table.reveal())

    def _snapshot_ref(self, source: SourceRef, found: Snapshot) -> SnapshotRef:
        qualified = self.plugin_info().qualified_name
        if not isinstance(found, Snapshot) or not is_safe_identifier(str(found.snapshot_id)):
            raise PluginFailedError(
                qualified,
                stage="snapshot",
                error_type="Snapshot",
                classification="snapshot_id_not_a_plain_identifier",
                original=None,
            )
        try:
            committed = require_utc(found.committed_at)
        except ValueError:
            raise PluginFailedError(
                qualified,
                stage="snapshot",
                error_type="Snapshot",
                classification="committed_at_is_naive",
                original=None,
            ) from None
        return SnapshotRef(
            source_id=source.source_id,
            snapshot_id=SnapshotId(found.snapshot_id),
            sequence_number=max(0, int(found.sequence_number)),
            committed_at=committed,
        )

    @staticmethod
    def _plain_snapshot(snapshot: SnapshotRef) -> Snapshot:
        return Snapshot(
            snapshot_id=str(snapshot.snapshot_id),
            sequence_number=snapshot.sequence_number,
            committed_at=snapshot.committed_at,
        )


def source[S: SourceBase](
    *,
    name: str,
    namespace: str,
    version: str,
    summary: str = "",
    requires_sdk: str = DEFAULT_REQUIREMENT,
    capabilities: Capabilities | None = None,
    limits: ResourceLimits | None = None,
) -> Callable[[type[S]], type[S]]:
    """Register a :class:`SourceBase` subclass as a source plugin.

    Rejects, listing every problem: a class that is not a ``SourceBase``, leaves an
    abstract method unimplemented, overrides an SDK method, or declares a bad name,
    version or capability.
    """

    return decorator_for(
        PluginKind.SOURCE,
        SourceBase,
        None,
        name=name,
        namespace=namespace,
        version=version,
        summary=summary,
        requires_sdk=requires_sdk,
        capabilities=capabilities,
        limits=limits,
    )
