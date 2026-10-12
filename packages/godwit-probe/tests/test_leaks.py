"""ACCEPTANCE: poisoned sentinels through every error path we can construct.

Every value in the poison table -- category labels, identifiers, the column names
themselves -- is a sentinel or a real string from the golden PII torture fixture. Each
test drives one failure (or success) path and then renders *everything* the package
emitted to text: the exception's ``str``, ``repr``, ``args`` and full formatted
traceback chain; every log record; every OpenTelemetry span name, attribute, status
description and event; every metric data point's labels; the outcome; and, for OPAQUE
probes, the bundle's JSON and raw payload bytes. No sentinel may appear in any of it.

This is a BACKSTOP. The controls are the closed error vocabulary in
:mod:`godwit_probe.errors`, the typed field set in :mod:`godwit_probe.telemetry` and the
plan-time access modes. The string search proves those controls held for these inputs;
the mypy case at the bottom proves the logger refuses the wrong types at all.

Four golden strings -- ``general``, ``negative``, ``positive``, ``unknown`` -- are
excluded from the search: they are real row values in the fixture and ordinary English
that legitimately appears in our own vocabulary. godwit-sketch documents the same
collision; it is the demonstration that scanning is not the control.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import subprocess
import sys
import traceback
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pyarrow as pa
import pytest
from _probe_support import predicate, segment
from godwit_contracts import Operator, ProbeKind, SketchKind, schema_name
from godwit_guard import AccessMode, KeyedHasher
from godwit_probe import (
    CancelFlag,
    ErrorCode,
    JobQueue,
    ProbeError,
    ProbeOutcome,
    ProbeStatus,
    ProbeTelemetry,
    ProbeWorker,
    WorkerPool,
    make_engine,
)
from godwit_probe.accumulate import Accumulator
from godwit_probe.telemetry import REFUSED_MARKER, Event, Field
from godwit_probe.testing import (
    Distribution,
    FailurePoint,
    ProbeSimulator,
    SyntheticColumn,
    SyntheticCommit,
    SyntheticTable,
    generous_budget,
)
from godwit_sketch import NullRate
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
_COMMON_WORDS = frozenset({"general", "negative", "positive", "unknown"})

POISON = tuple(f"PZN{index:02d}-{tag}" for index, tag in enumerate(("7f3a", "c0de", "beef")))
POISON_PREFIX = "PZNID-9e1f-"
POISON_COLUMNS = ("patient_hiv_status", "customer_ssn", "salary_2024", "device_id")


def _golden_leaks() -> tuple[str, ...]:
    path = ROOT / "tests" / "golden" / "pii_torture" / "expected_leaks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return tuple(s for s in data["must_never_appear_in_any_egress"] if s not in _COMMON_WORDS)


GOLDEN = _golden_leaks()
FORBIDDEN = (*POISON, POISON_PREFIX, *POISON_COLUMNS, *GOLDEN)


def poison_table() -> SyntheticTable:
    names = [n for n in GOLDEN if " " in n and "@" not in n and "called" not in n][:6]
    return SyntheticTable(
        namespace="pii",
        name="customers",
        columns=(
            SyntheticColumn(
                "patient_hiv_status", Distribution.CATEGORICAL, categories=(*POISON, *names)
            ),
            SyntheticColumn("customer_ssn", Distribution.IDENTIFIER, prefix=POISON_PREFIX),
            SyntheticColumn("salary_2024", Distribution.NORMAL, mean=58050.0, sigma=9000.0),
            SyntheticColumn("device_id", Distribution.IDENTIFIER, prefix="dev-0000-a4f7723b-"),
        ),
        commits=(SyntheticCommit(rows=6_000), SyntheticCommit(rows=6_000)),
        seed=99,
        rows_per_file=3_000,
        block_rows=1_000,
    )


MODES = {
    "patient_hiv_status": AccessMode.OPEN,
    "customer_ssn": AccessMode.OPAQUE,
    "salary_2024": AccessMode.OPEN,
    "device_id": AccessMode.OPAQUE,
}


def _scrub_ids(text: str) -> str:
    return re.sub(r"\b[a-z][a-z0-9]{1,7}_[0-9a-f]{16,64}\b", "<id>", text)


class Emitted:
    """Everything the package emitted during one test, rendered to text."""

    def __init__(self, caplog: pytest.LogCaptureFixture) -> None:
        self._caplog = caplog
        self.spans = InMemorySpanExporter()
        tracer_provider = TracerProvider()
        tracer_provider.add_span_processor(SimpleSpanProcessor(self.spans))
        self.metrics = InMemoryMetricReader()
        meter_provider = MeterProvider(metric_readers=[self.metrics])
        self.telemetry = ProbeTelemetry(
            tracer_provider=tracer_provider, meter_provider=meter_provider
        )
        self.extra: list[str] = []
        self.bundles: list[str] = []
        """Bundle JSON. Checked for values only: provenance names columns by design."""

    def simulator(self, *, visible_commits: int | None = None) -> ProbeSimulator:
        return ProbeSimulator(
            poison_table(),
            modes=MODES,
            telemetry=self.telemetry,
            visible_commits=visible_commits,
            batch_rows=500,
        )

    def add_error(self, error: BaseException) -> None:
        assert error.__cause__ is None
        assert error.__context__ is None
        self.extra += [str(error), repr(error), repr(error.args)]
        self.extra.append("".join(traceback.format_exception(error)))

    def add_outcome(self, outcome: ProbeOutcome) -> None:
        self.extra.append(outcome.model_dump_json(exclude={"bundle"}))

    def texts(self) -> Iterator[str]:
        yield self._caplog.text
        for record in self._caplog.records:
            yield record.getMessage()
            yield repr(record.args)
        for span in self.spans.get_finished_spans():
            yield span.name
            yield json.dumps(dict(span.attributes or {}), default=str)
            yield str(span.status.description)
            yield json.dumps([event.name for event in span.events])
            yield json.dumps([dict(event.attributes or {}) for event in span.events], default=str)
        data = self.metrics.get_metrics_data()
        if data is not None:
            for resource in data.resource_metrics:
                for scope in resource.scope_metrics:
                    for metric in scope.metrics:
                        yield metric.name
                        for point in metric.data.data_points:
                            yield json.dumps(dict(point.attributes or {}), default=str)
        yield from self.extra

    def assert_clean(self) -> None:
        blob = "\n".join(self.texts())
        leaked = sorted(s for s in FORBIDDEN if s in blob)
        assert not leaked, f"leaked {len(leaked)} forbidden strings"
        assert REFUSED_MARKER not in blob
        assert self.telemetry.refused_values == 0


@pytest.fixture
def emitted(caplog: pytest.LogCaptureFixture) -> Emitted:
    caplog.set_level(logging.DEBUG)
    return Emitted(caplog)


def _raises(call: Callable[[], object]) -> ProbeError:
    with pytest.raises(ProbeError) as info:
        call()
    return info.value


def _poisoned(kind: type[Exception]) -> Callable[[], Exception]:
    message = f"row ({POISON[0]}, {POISON_PREFIX}000000000001) {GOLDEN[0]} in patient_hiv_status"
    return lambda: kind(message)


# -- metadata and read failures ------------------------------------------------------------


@pytest.mark.parametrize(
    ("point", "code"),
    [
        (FailurePoint.RESOLVE, ErrorCode.SOURCE_UNAVAILABLE),
        (FailurePoint.DELTA, ErrorCode.SOURCE_UNAVAILABLE),
        (FailurePoint.SCHEMA, ErrorCode.SOURCE_UNAVAILABLE),
        (FailurePoint.READ_OPEN, ErrorCode.QUERY_FAILED),
        (FailurePoint.READ_MID, ErrorCode.QUERY_FAILED),
    ],
)
@pytest.mark.parametrize("kind", [RuntimeError, OSError, pa.ArrowInvalid, sqlite3.IntegrityError])
def test_source_failures_never_carry_the_driver_message(
    emitted: Emitted, point: FailurePoint, code: ErrorCode, kind: type[Exception]
) -> None:
    sim = emitted.simulator()
    sim.source.inject(point, _poisoned(kind))
    spec = sim.spec(ProbeKind.HEAVY_HITTERS, ["customer_ssn", "patient_hiv_status"])
    error = _raises(lambda: sim.run(spec))
    if point is FailurePoint.READ_OPEN:
        # The first read happens before the query engine; either code is a safe answer.
        assert error.code in (ErrorCode.SCAN_FAILED, ErrorCode.QUERY_FAILED)
    else:
        assert error.code is code
    emitted.add_error(error)
    emitted.assert_clean()


def test_a_real_duckdb_conversion_error_does_not_leak_the_predicate_value(
    emitted: Emitted,
) -> None:
    """DuckDB really does quote the value: 'Could not convert string ... to DOUBLE'."""
    sim = emitted.simulator()
    where = segment(predicate("salary_2024", Operator.EQ, POISON[1]))
    spec = sim.spec(ProbeKind.NULL_RATE, ["patient_hiv_status"], segment=where)
    error = _raises(lambda: sim.run(spec))
    assert error.code is ErrorCode.QUERY_FAILED
    emitted.add_error(error)
    emitted.assert_clean()


def test_a_failing_keyed_hash_inside_the_engine_does_not_leak_the_row(
    emitted: Emitted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(self: KeyedHasher, value: object) -> str:
        raise ValueError(f"cannot hash {value!r}")

    monkeypatch.setattr(KeyedHasher, "digest", explode)
    sim = emitted.simulator()
    spec = sim.spec(ProbeKind.DISTINCT_COUNT, ["customer_ssn"])
    error = _raises(lambda: sim.run(spec))
    emitted.add_error(error)
    emitted.assert_clean()


def test_a_failing_sketch_update_does_not_leak_the_value(
    emitted: Emitted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(self: Accumulator, batch: pa.RecordBatch) -> None:
        raise ValueError(f"bad batch {batch.to_pylist()[:3]}")

    monkeypatch.setattr(Accumulator, "feed", explode)
    sim = emitted.simulator()
    spec = sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["patient_hiv_status"])
    error = _raises(lambda: sim.run(spec))
    assert error.code is ErrorCode.SKETCH_FAILED
    emitted.add_error(error)
    emitted.assert_clean()


def test_a_failing_serialisation_does_not_leak(
    emitted: Emitted, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(self: NullRate, context: object = None) -> object:
        raise TypeError(f"{POISON[2]} could not be encoded for patient_hiv_status")

    monkeypatch.setattr(NullRate, "serialise", explode)
    sim = emitted.simulator()
    spec = sim.spec(ProbeKind.NULL_RATE, ["patient_hiv_status"])
    error = _raises(lambda: sim.run(spec))
    assert error.code is ErrorCode.SKETCH_FAILED
    emitted.add_error(error)
    emitted.assert_clean()


# -- normal outcomes -----------------------------------------------------------------------


def test_refusals_no_change_cancellation_and_success_emit_nothing_forbidden(
    emitted: Emitted,
) -> None:
    sim = emitted.simulator()
    blind = sim.spec(ProbeKind.QUANTILES, ["patient_hiv_status"], sketches=[SketchKind.KLL])
    emitted.add_outcome(sim.run(blind))
    budget = sim.spec(ProbeKind.DISTINCT_COUNT, ["customer_ssn"])
    emitted.add_outcome(sim.run(budget, budget=generous_budget(bytes_scanned=1)))

    opaque = sim.spec(
        ProbeKind.HEAVY_HITTERS,
        ["customer_ssn", "device_id"],
        sketches=[SketchKind.COUNT_MIN, SketchKind.THETA, SketchKind.HLL],
    )
    done = sim.run(opaque)
    assert done.status is ProbeStatus.COMPLETED
    assert done.bundle is not None
    emitted.add_outcome(done)
    emitted.bundles.append(done.bundle.model_dump_json())
    for envelope in done.bundle.sketches.values():
        for text in (POISON_PREFIX, "dev-0000-a4f7723b"):
            assert text.encode() not in envelope.payload
        assert re.search(rb"h_[0-9a-f]{32}", envelope.payload) is None

    emitted.add_outcome(sim.run(opaque))  # no change

    stop = CancelFlag()
    stop.cancel()
    fresh = sim.spec(ProbeKind.NULL_RATE, ["salary_2024"], probe_id="another")
    emitted.add_outcome(sim.run(fresh, cancel=stop))
    emitted.assert_clean()


# -- the worker runtime ------------------------------------------------------------------


def test_worker_failures_record_a_code_and_nothing_else(emitted: Emitted, tmp_path: Path) -> None:
    sim = emitted.simulator()
    sim.source.inject(FailurePoint.READ_MID, _poisoned(RuntimeError))
    queue = JobQueue(make_engine(f"sqlite:///{(tmp_path / 'q.db').as_posix()}"), max_attempts=2)
    queue.create_schema()
    spec = sim.spec(ProbeKind.HEAVY_HITTERS, ["customer_ssn"])
    job_id = queue.enqueue(spec, budget=generous_budget())
    worker = ProbeWorker(
        queue, lambda _source: sim.executor, worker_id="w-1", telemetry=emitted.telemetry
    )
    WorkerPool([worker]).run_until_idle(queue)
    record = queue.job(job_id)
    assert record is not None
    assert record.error_code is ErrorCode.QUERY_FAILED
    assert record.attempts == 2
    emitted.extra.append(repr(record))
    emitted.assert_clean()


def test_a_store_failure_does_not_render_bound_parameters(emitted: Emitted, tmp_path: Path) -> None:
    """SQLAlchemy renders bound parameters into its errors -- here, the bundle's JSON."""
    sim = emitted.simulator()
    engine = make_engine(f"sqlite:///{(tmp_path / 'q.db').as_posix()}")
    queue = JobQueue(engine)
    queue.create_schema()
    spec = sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["patient_hiv_status"])
    job_id = queue.enqueue(spec, budget=generous_budget())
    claimed = queue.claim("w-1")
    assert claimed is not None
    outcome = sim.executor.execute(claimed.spec, budget=claimed.budget)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE godwit_probe_bundles")
        conn.exec_driver_sql(
            "CREATE TABLE godwit_probe_bundles (probe_key TEXT NOT NULL CHECK (0))"
        )
    error = _raises(lambda: queue.complete(job_id, "w-1", outcome))
    assert error.code is ErrorCode.STORE_FAILED
    emitted.add_error(error)
    emitted.assert_clean()


# -- the type-level half -------------------------------------------------------------------


def test_the_logger_rejects_customer_values_at_runtime_too(emitted: Emitted) -> None:
    """Type hints are not enforced at runtime; the renderer checks again."""
    smuggled: dict[Field, Any] = {
        Field.SOURCE: schema_name("customer_ssn"),
        Field.REASON: POISON[0],
    }
    emitted.telemetry.event(Event.PROBE, smuggled)
    assert emitted.telemetry.refused_values == 2
    blob = "\n".join(emitted.texts())
    assert "customer_ssn" not in blob
    assert POISON[0] not in blob
    assert blob.count(REFUSED_MARKER) >= 2


CASES = HERE / "typing_cases" / "must_fail.py"
_ERROR_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+): error: .*\[(?P<code>[a-z-]+)\]$")


def test_the_logger_rejects_customer_values_in_the_type_checker() -> None:
    expected: dict[int, str] = {}
    for number, text in enumerate(CASES.read_text(encoding="utf-8").splitlines(), start=1):
        marker = re.search(r"#\s*EXPECT:\s*([a-z-]+)\s*$", text)
        if marker:
            expected[number] = marker.group(1)
    assert len(expected) >= 7
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--no-incremental",
            "--hide-error-context",
            "--no-color-output",
            "--no-error-summary",
            str(CASES),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=False,
    )
    found: dict[int, list[str]] = {}
    for line in result.stdout.splitlines():
        match = _ERROR_RE.match(line.strip())
        if match and Path(match.group("file")).name == CASES.name:
            found.setdefault(int(match.group("line")), []).append(match.group("code"))
    missing = {line: code for line, code in expected.items() if code not in found.get(line, [])}
    unexpected = {line: codes for line, codes in found.items() if line not in expected}
    assert not missing, (missing, result.stdout)
    assert not unexpected, (unexpected, result.stdout)
