"""Detector, feature, context and panel bases: the parts each enforces at run time."""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import ClassVar, Self

import pyarrow as pa
import pytest
from _sdk_support import EPOCH, kll_series
from godwit_contracts import Destination, Sensitivity, SnapshotId, derived_statistic
from godwit_detect import FixedReference, SketchSeries
from godwit_guard import DEFAULT_POLICY, Backstop, ClassificationRegistry, Gate, MemoryLedger
from godwit_sdk import (
    EVENT_TIME,
    FEATURE_VALUE,
    BaseSketch,
    ContextBase,
    ContextRecord,
    ContextType,
    DetectorBase,
    Direction,
    EvidenceKind,
    FeatureBase,
    HypothesisTest,
    LogicalType,
    PanelBase,
    PanelSeries,
    PanelView,
    PluginFailedError,
    SafePayload,
    context,
    detector,
    feature,
    panel,
)
from godwit_sdk.examples.benford import BenfordDetector
from godwit_sdk.testing import run_conformance
from godwit_sketch.deterministic import uniforms

# -- detector ---------------------------------------------------------------------------


@detector(name="greedy", namespace="test", version="0.1.0")
class GreedyDetector(DetectorBase):
    """Declares one test and runs three."""

    EVIDENCE: ClassVar[EvidenceKind] = EvidenceKind.RATE_CHANGE
    CODECS: ClassVar[frozenset[str]] = frozenset({"godwit-kll-v1"})
    TESTS_PER_SKETCH: ClassVar[int] = 1

    def examine(
        self, current: BaseSketch, reference: Sequence[BaseSketch]
    ) -> Sequence[HypothesisTest]:
        del current, reference
        return tuple(HypothesisTest(f"t{i}", 1.0, 0.1, 0.5, Direction.UP) for i in range(3))


def _benford_series(first: list[float], second: list[float]) -> SketchSeries:
    return kll_series([first, second])


def test_a_detector_that_tests_more_than_it_declared_fails() -> None:
    series = _benford_series([float(i) for i in range(1, 1000)], [float(i) for i in range(1, 1000)])
    with pytest.raises(PluginFailedError, match="tested_3_declared_1"):
        GreedyDetector().run(series, policy=FixedReference(snapshot_id=SnapshotId("s0")))


def test_benford_abstains_when_the_reference_never_followed_benford() -> None:
    prices = [5.0 + 4.99 * u for u in uniforms(5000, salt="prices")]
    series = _benford_series(prices, prices)
    result = BenfordDetector().run(series, policy=FixedReference(snapshot_id=SnapshotId("s0")))
    assert result.tests == 0
    assert result.findings == ()


def test_a_version_pin_catches_changed_output_without_a_bump(tmp_path: Path) -> None:
    pins = tmp_path / "pins.json"
    assert run_conformance(BenfordDetector, pins=pins).passed
    recorded = json.loads(pins.read_text("utf-8"))
    recorded["examples.benford@1.0.0"] = "beh_something_else"
    pins.write_text(json.dumps(recorded), "utf-8")
    report = run_conformance(BenfordDetector, pins=pins)
    detail = next(r.detail for r in report.results if r.name == "version_pin")
    assert "Bump the version" in detail


# -- feature ----------------------------------------------------------------------------


@feature(name="spend-7d", namespace="test", version="0.1.0")
class SevenDaySpend(FeatureBase):
    """sum(amount) over [event - 7 days, event - 1 day)."""

    DTYPE: ClassVar[LogicalType] = LogicalType.FLOAT
    INPUTS: ClassVar[tuple[str, ...]] = ("amount",)
    LOOKBACK: ClassVar[_dt.timedelta] = _dt.timedelta(days=7)
    EMBARGO: ClassVar[_dt.timedelta] = _dt.timedelta(days=1)

    def aggregate(self, columns: Mapping[str, str]) -> str:
        return f"sum({columns['amount']})"


def test_a_feature_reads_only_its_own_window_for_each_entity() -> None:
    plugin = SevenDaySpend()
    built = plugin.spec(
        feature_id="spend",
        source_id="src_f",
        entity_key="card",
        timestamp_column="ts",
        columns={"amount": "amt"},
    )
    day = _dt.timedelta(days=1)
    history = pa.table(
        {
            "card": ["a", "a", "a", "a", "b"],
            "ts": [EPOCH - 8 * day, EPOCH - 3 * day, EPOCH - day / 2, EPOCH + day, EPOCH - 2 * day],
            "amt": [1000.0, 10.0, 500.0, 900.0, 7.0],
        }
    )
    events = pa.table({"card": ["a", "b", "c"], EVENT_TIME: [EPOCH, EPOCH, EPOCH]})
    values = plugin.evaluate(built, events=events, history=history).column(FEATURE_VALUE)
    # a: only the row 3 days back (8 days is past the lookback, half a day is inside the
    # embargo, tomorrow is the future). b: its own row. c: no rows at all.
    assert values.to_pylist() == [10.0, 7.0, None]
    assert built.point_in_time.embargo == day
    assert built.name.sensitivity is Sensitivity.SCHEMA_NAME


# -- context ----------------------------------------------------------------------------


@context(name="calendar", namespace="test", version="0.1.0")
class Calendar(ContextBase):
    def __init__(self, records: Sequence[ContextRecord]) -> None:
        self._records = tuple(records)

    def fetch(self, *, start: _dt.datetime, end: _dt.datetime) -> Iterable[ContextRecord]:
        del start, end
        return self._records

    @classmethod
    def for_conformance(cls, records: Sequence[ContextRecord]) -> Self:
        return cls(records)


def test_context_records_become_tainted_events_inside_the_window() -> None:
    hour = _dt.timedelta(hours=1)
    source = Calendar(
        [
            ContextRecord(
                "2",
                ContextType.CAMPAIGN,
                "campaign.spring",
                EPOCH + hour,
                label="Spring sale for Aoife Brennan",
                columns=("amount",),
            ),
            ContextRecord("1", ContextType.DEPLOY, "deploy.payments", EPOCH),
            ContextRecord("0", ContextType.DEPLOY, "deploy.old", EPOCH - 48 * hour),
        ]
    )
    events = source.events(start=EPOCH, end=EPOCH + 24 * hour)
    assert [e.kind for e in events] == ["deploy.payments", "campaign.spring"]
    campaign = events[1]
    assert campaign.label is not None
    assert campaign.label.sensitivity is Sensitivity.DATA_VALUE
    assert campaign.scope.columns[0].sensitivity is Sensitivity.SCHEMA_NAME
    assert campaign.origin == "test.calendar"
    assert "Aoife" not in repr(events)


def test_a_context_record_with_a_free_text_kind_is_refused() -> None:
    source = Calendar([ContextRecord("1", ContextType.DEPLOY, "Deploy by Aoife Brennan", EPOCH)])
    with pytest.raises(PluginFailedError, match="kind_is_not_a_plain_identifier") as error:
        source.events(start=EPOCH, end=EPOCH)
    assert "Aoife" not in str(error.value)


# -- panel ------------------------------------------------------------------------------


@panel(name="tile", namespace="test", version="0.1.0")
class Tile(PanelBase):
    TITLE: ClassVar[str] = "Alerts"
    FIELDS: ClassVar[tuple[str, ...]] = ("alerts",)
    LABELS: ClassVar[tuple[str, ...]] = ("today",)

    def render(self, payload: SafePayload) -> PanelView:
        return PanelView(
            title=self.TITLE,
            chart="stat",
            series=(PanelSeries(label="today", values=(payload.fields["alerts"],)),),
        )


@panel(name="chatty", namespace="test", version="0.1.0")
class Chatty(Tile):
    """Adds a label nobody cleared."""

    def render(self, payload: SafePayload) -> PanelView:
        del payload
        return PanelView(title="Alerts for Aoife Brennan", chart="stat")


@panel(name="inventive", namespace="test", version="0.1.0")
class Inventive(Tile):
    """Shows a number that was not in the payload."""

    def render(self, payload: SafePayload) -> PanelView:
        del payload
        return PanelView(
            title=self.TITLE, chart="stat", series=(PanelSeries(label="today", values=(41000,)),)
        )


def _payload(**fields: float) -> SafePayload:
    gate = Gate(
        ledger=MemoryLedger(),
        registry=ClassificationRegistry(),
        backstop=Backstop(use_presidio=False),
    )
    payload, _ = gate.clear(
        fields={k: derived_statistic(v, population=10_000) for k, v in fields.items()},
        destination=Destination.UI,
        purpose="panel.test",
        policy=DEFAULT_POLICY,
        guardrails=(),
        actor="test",
        occurred_at=EPOCH,
    )
    return payload


def test_a_panel_renders_a_gated_payload() -> None:
    view = Tile().view(_payload(alerts=12.0))
    assert view.series[0].values == (12.0,)


@pytest.mark.parametrize(
    ("plugin", "why"),
    [
        (Chatty, "text_that_did_not_come_through_the_gate"),
        (Inventive, "value_that_is_not_in_the_payload"),
    ],
)
def test_a_panel_cannot_add_what_the_gate_did_not_clear(plugin: type[Tile], why: str) -> None:
    with pytest.raises(PluginFailedError, match=why):
        plugin().view(_payload(alerts=12.0))


def test_a_payload_missing_a_declared_field_is_refused() -> None:
    with pytest.raises(PluginFailedError, match="payload_lacks_declared_fields"):
        Tile().view(_payload(other=1.0))
