"""Small units: the error boundary, the keyring, the telemetry emitter, the cost model."""

from __future__ import annotations

import copy
import json
import logging
import pickle
from collections.abc import Iterator
from decimal import Decimal

import pytest
from _probe_support import simulator
from godwit_contracts import ProbeKind
from godwit_probe import CostModel, ErrorCode, ProbeError, ProbeKeyring, Stage
from godwit_probe.errors import guarded, guarded_iter
from godwit_probe.source import DataFileRef
from godwit_probe.telemetry import Event, Field, ProbeTelemetry, SafeId
from godwit_probe.testing import simulator_keyring
from hypothesis import given
from hypothesis import strategies as st
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


def _boom() -> int:
    raise KeyError("secret-value")


def test_guarded_replaces_the_exception_and_drops_the_chain() -> None:
    with pytest.raises(ProbeError) as info:
        guarded(Stage.READ, ErrorCode.SCAN_FAILED, _boom)
    error = info.value
    assert error.code is ErrorCode.SCAN_FAILED
    assert error.stage is Stage.READ
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "secret-value" not in str(error) + repr(error)


def test_guarded_passes_its_own_errors_through_untouched() -> None:
    original = ProbeError(ErrorCode.QUERY_FAILED, stage=Stage.QUERY)

    def raise_it() -> None:
        raise original

    with pytest.raises(ProbeError) as info:
        guarded(Stage.READ, ErrorCode.SCAN_FAILED, raise_it)
    assert info.value is original


def test_guarded_iter_fails_mid_stream_without_the_chain() -> None:
    def items() -> Iterator[int]:
        yield 1
        yield 2
        raise ValueError("row 100-40-1000")

    seen: list[int] = []
    with pytest.raises(ProbeError) as info:
        seen.extend(guarded_iter(Stage.READ, ErrorCode.SCAN_FAILED, items()))
    assert seen == [1, 2]
    assert info.value.__context__ is None


def test_keyring_never_renders_or_serialises_its_keys() -> None:
    keyring = simulator_keyring()
    assert "column" not in repr(keyring)
    with pytest.raises(TypeError):
        pickle.dumps(keyring)
    with pytest.raises(TypeError):
        copy.deepcopy(keyring)
    with pytest.raises(ValueError, match="differ"):
        ProbeKeyring(column_key=b"k" * 32, sketch_key=b"k" * 32)
    with pytest.raises(ValueError, match="32 bytes"):
        ProbeKeyring(column_key=b"k" * 32, sketch_key=b"s" * 8)


def test_safe_ids_hash_free_form_identifiers() -> None:
    handle = SafeId.of("snp", "41000")
    assert "41000" not in str(handle)
    assert handle == SafeId.of("snp", "41000")
    with pytest.raises(ValueError, match="prefix_hexdigits"):
        SafeId("customer_ssn")


def test_a_completed_probe_emits_a_span_a_log_line_and_labelled_metrics(
    caplog: pytest.LogCaptureFixture,
) -> None:
    spans = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(spans))
    reader = InMemoryMetricReader()
    telemetry = ProbeTelemetry(
        tracer_provider=tracer_provider, meter_provider=MeterProvider(metric_readers=[reader])
    )
    caplog.set_level(logging.INFO, logger="godwit_probe")
    sim = simulator(telemetry=telemetry)
    sim.run(sim.spec(ProbeKind.NULL_RATE, ["amount"]))
    (span,) = spans.get_finished_spans()
    assert span.name == Event.PROBE.value
    assert (span.attributes or {})[Field.STATUS.value] == "completed"
    assert span.events == ()
    lines = [json.loads(record.getMessage()) for record in caplog.records]
    assert lines[-1]["event"] == Event.PROBE_COMPLETED.value
    assert lines[-1]["bytes_read"] > 0
    data = reader.get_metrics_data()
    assert data is not None
    labels = [
        dict(point.attributes or {})
        for resource in data.resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
        if metric.name == "godwit.probe.outcomes"
        for point in metric.data.data_points
    ]
    assert labels == [{"status": "completed", "kind": "null_rate"}]


@given(st.integers(min_value=0, max_value=10**12))
def test_cost_is_monotone_in_bytes(extra: int) -> None:
    model = CostModel(usd_per_gib=Decimal("5"))
    base = model.spend(10**9)
    more = model.spend(10**9 + extra)
    assert more.usd >= base.usd
    assert more.bytes_scanned >= base.bytes_scanned


@given(
    st.dictionaries(
        st.sampled_from(["a", "b", "c", "d"]), st.integers(min_value=0, max_value=10**6)
    ),
    st.lists(st.sampled_from(["a", "b", "c", "d", "e"]), max_size=5),
    st.integers(min_value=0, max_value=10**5),
)
def test_a_projected_estimate_never_exceeds_the_file_nor_undercounts_its_columns(
    sizes: dict[str, int], columns: list[str], overhead: int
) -> None:
    data_file = DataFileRef(
        location="x",
        size_bytes=sum(sizes.values()) + overhead,
        record_count=1,
        column_bytes=sizes,
    )
    estimate = data_file.estimated_bytes(columns)
    assert estimate <= data_file.size_bytes
    known = sum(sizes[c] for c in set(columns) if c in sizes)
    assert estimate >= min(data_file.size_bytes, known + overhead)
