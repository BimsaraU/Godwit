"""Probe workers executing a ProbeSpec into a SketchBundle (L1).

Owner: A6. **Plane: DATA.** This package reads customer rows in place and emits sketch
bundles, costs and refusal reasons -- never a row, and never a value in a log line, an
exception, a metric label or a trace attribute. Read ``docs/packages/godwit-probe.md``
before changing anything here; the short version:

* :class:`ProbeExecutor` -- plan against access modes, estimate from metadata, refuse
  before reading, stream batches into sketches, record the actual cost.
* :mod:`godwit_probe.plan` -- BLIND never enters a query; OPAQUE enters only hashed.
* :mod:`godwit_probe.stream` -- streaming is catalog polling; batch is the same loop.
* :mod:`godwit_probe.worker` -- the Postgres jobs table, leases, cancellation, limits.
* :mod:`godwit_probe.testing` -- the simulator other agents test against.
* :mod:`godwit_probe.errors` and :mod:`godwit_probe.telemetry` -- the leak boundary.
"""

from godwit_probe.errors import ErrorCode, ProbeError, Stage
from godwit_probe.executor import (
    DEFAULT_BATCH_ROWS,
    WORKER_VERSION,
    CancelFlag,
    CancelReason,
    CancelToken,
    CostModel,
    ExecutionMode,
    ProbeExecutor,
    ProbeOutcome,
    ProbeStatus,
    bundle_id,
)
from godwit_probe.keyring import ProbeKeyring
from godwit_probe.plan import (
    PLAIN_KEYS_PURPOSE,
    ColumnRole,
    KeyPermission,
    ProbePlan,
    Refusal,
    RefusalReason,
    plan_probe,
)
from godwit_probe.source import DataFileRef, Delta, DeltaKind, IcebergProbeSource, ProbeSource
from godwit_probe.state import MemoryProbeState, ProbeState
from godwit_probe.stream import CatalogPoller, SketchSeries, advance, backfill
from godwit_probe.telemetry import ProbeTelemetry
from godwit_probe.worker import JobQueue, ProbeWorker, SqlProbeState, WorkerPool, make_engine

__all__ = [
    "DEFAULT_BATCH_ROWS",
    "PLAIN_KEYS_PURPOSE",
    "WORKER_VERSION",
    "CancelFlag",
    "CancelReason",
    "CancelToken",
    "CatalogPoller",
    "ColumnRole",
    "CostModel",
    "DataFileRef",
    "Delta",
    "DeltaKind",
    "ErrorCode",
    "ExecutionMode",
    "IcebergProbeSource",
    "JobQueue",
    "KeyPermission",
    "MemoryProbeState",
    "ProbeError",
    "ProbeExecutor",
    "ProbeKeyring",
    "ProbeOutcome",
    "ProbePlan",
    "ProbeSource",
    "ProbeState",
    "ProbeStatus",
    "ProbeTelemetry",
    "ProbeWorker",
    "Refusal",
    "RefusalReason",
    "SketchSeries",
    "SqlProbeState",
    "Stage",
    "WorkerPool",
    "__version__",
    "advance",
    "backfill",
    "bundle_id",
    "make_engine",
    "plan_probe",
]

__version__ = "0.1.0"
