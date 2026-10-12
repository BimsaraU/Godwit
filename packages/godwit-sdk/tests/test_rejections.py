"""Acceptance: a deliberately non-conformant plugin of each kind is rejected at registration,
with an error saying exactly what is wrong."""

from __future__ import annotations

import datetime as _dt
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, ClassVar, Self

import pytest
from _sdk_support import MemorySource
from godwit_contracts import CostBudget, ProbeSpec, SketchBundle, SnapshotRef
from godwit_sdk import (
    Acquisition,
    BaseSketch,
    ContextBase,
    ContextRecord,
    DetectorBase,
    Direction,
    ErrorBound,
    EvidenceKind,
    FeatureBase,
    HypothesisTest,
    IncompatiblePluginError,
    ItemFlavour,
    LogicalType,
    MergeExactness,
    PanelBase,
    PanelView,
    PluginRejectedError,
    Sensitivity,
    SketchBase,
    SketchKind,
    context,
    detector,
    feature,
    panel,
    sketch,
    source,
)


def _problems(error: pytest.ExceptionInfo[PluginRejectedError]) -> str:
    return "\n".join(error.value.problems)


# -- common ----------------------------------------------------------------------------


def test_every_problem_is_listed_not_just_the_first() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @source(name="Bad Name", namespace="godwit", version="1.0")
        class Bad(MemorySource):
            pass

    text = _problems(error)
    assert "name 'Bad Name'" in text
    assert "namespace 'godwit' is reserved" in text
    assert "version '1.0' must be MAJOR.MINOR.PATCH" in text
    assert len(error.value.problems) >= 3


def test_a_plugin_for_another_sdk_is_refused_with_both_versions_named() -> None:
    with pytest.raises(IncompatiblePluginError) as error:

        @source(name="future", namespace="acme", version="1.0.0", requires_sdk=">=2.0,<3")
        class Future(MemorySource):
            pass

    assert "requires godwit-sdk >=2.0,<3" in str(error.value)
    assert "this core runs godwit-sdk 0.1.0" in str(error.value)


def test_a_class_of_the_wrong_kind_is_refused() -> None:
    with pytest.raises(PluginRejectedError, match=r"must subclass godwit_sdk\.DetectorBase"):
        detector(name="wrong", namespace="acme", version="1.0.0")(MemorySource)


# -- source ----------------------------------------------------------------------------


def test_a_source_that_overrides_the_sdk_and_skips_conformance_is_refused() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @source(name="overreach", namespace="acme", version="1.0.0")
        class Overreach(MemorySource):
            def execute_probe(
                self, spec: ProbeSpec, snapshot: SnapshotRef, *, budget: CostBudget
            ) -> SketchBundle:
                raise NotImplementedError

    assert "overrides execute_probe(), which the SDK implements for every source" in _problems(
        error
    )


def test_a_source_missing_an_abstract_method_is_refused() -> None:
    from godwit_sdk import SourceBase

    with pytest.raises(PluginRejectedError, match=r"does not implement .*for_conformance"):

        @source(name="partial", namespace="acme", version="1.0.0")
        class Partial(SourceBase):
            def snapshot(self, *args: Any, **kwargs: Any) -> Any:
                raise NotImplementedError

            def columns(self, *args: Any) -> Any:
                raise NotImplementedError

            def partitions(self, *args: Any) -> Any:
                raise NotImplementedError

            def read(self, *args: Any) -> Any:
                raise NotImplementedError


# -- sketch ----------------------------------------------------------------------------


class _Counter(SketchBase):
    """A correct exact counter; subclasses break it one way at a time."""

    KIND: ClassVar[SketchKind] = SketchKind.EXACT_COUNT
    CODEC: ClassVar[str] = "acme-counter-v1"
    SCHEMA_VERSION: ClassVar[int] = 1
    VALUE_BEARING: ClassVar[bool] = False
    SENSITIVITY: ClassVar[Sensitivity | None] = Sensitivity.DERIVED_STATISTIC
    MERGE_EXACTNESS: ClassVar[MergeExactness] = MergeExactness.EXACT
    ITEM_FLAVOUR: ClassVar[ItemFlavour] = ItemFlavour.CATEGORICAL
    ACQUISITION: ClassVar[Acquisition] = Acquisition.COMPUTED_STATISTIC
    DEFAULT_PARAMS: ClassVar[Mapping[str, int | float | str | bool]] = {}

    def __init__(self, count: int = 0, last: str = "") -> None:
        self.count = count
        self.last = last

    @classmethod
    def identity(cls, params: Mapping[str, Any]) -> Self:
        del params
        return cls()

    @classmethod
    def from_items(cls, items: Sequence[Any], params: Mapping[str, Any]) -> Self:
        del params
        return cls(len([i for i in items if i is not None]))

    @property
    def params(self) -> Mapping[str, Any]:
        return {}

    @property
    def population(self) -> int:
        return self.count

    def merge(self, other: Self) -> Self:
        return type(self)(self.count + other.count)

    def error_bound(self) -> ErrorBound:
        return ErrorBound(kind="exact")

    def estimate(self) -> float:
        return float(self.count)

    def encode(self) -> bytes:
        return self.count.to_bytes(8, "big") + self.last.encode()

    @classmethod
    def _decode_body(cls, payload: bytes) -> Self:
        return cls(int.from_bytes(payload[:8], "big"), payload[8:].decode())


def test_a_sketch_whose_merge_is_not_commutative_is_refused_before_it_ships() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @sketch(name="lefty", namespace="acme", version="1.0.0")
        class Lefty(_Counter):
            CODEC: ClassVar[str] = "acme-lefty-v1"

            def merge(self, other: Self) -> Self:
                return type(self)(self.count + other.count, self.last or "left")

            @classmethod
            def from_items(cls, items: Sequence[Any], params: Mapping[str, Any]) -> Self:
                del params
                return cls(len(items), str(len(items)))

    assert "commutativity fails" in _problems(error)


def test_a_sketch_that_hides_its_items_while_claiming_not_to_hold_any_is_refused() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @sketch(name="liar", namespace="acme", version="1.0.0")
        class Liar(_Counter):
            CODEC: ClassVar[str] = "acme-liar-v1"

            @classmethod
            def from_items(cls, items: Sequence[Any], params: Mapping[str, Any]) -> Self:
                del params
                strings = [i for i in items if isinstance(i, str)]
                return cls(len(items), max(strings) if strings else "")

            def merge(self, other: Self) -> Self:
                return type(self)(self.count + other.count, max(self.last, other.last))

    assert "declares VALUE_BEARING = False but its payload contains an item" in _problems(error)


def test_a_sketch_codec_outside_its_namespace_or_value_bearing_without_data_value() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @sketch(name="squatter", namespace="acme", version="1.0.0")
        class Squatter(_Counter):
            CODEC: ClassVar[str] = "godwit-kll-v1"
            VALUE_BEARING: ClassVar[bool] = True

    text = _problems(error)
    assert "must start with the namespace: 'acme-'" in text
    assert "already registered" in text
    assert "must declare SENSITIVITY = DATA_VALUE" in text


def test_merge_across_different_parameters_raises_even_if_the_author_forgot() -> None:
    from godwit_sdk.examples.bloom import BloomMembership
    from godwit_sketch import IncompatibleMergeError

    small = BloomMembership.identity({"bits": 64, "hashes": 2, "seed": 1})
    large = BloomMembership.identity({"bits": 128, "hashes": 2, "seed": 1})
    with pytest.raises(IncompatibleMergeError):
        small.merge(large)


# -- detector --------------------------------------------------------------------------


def test_a_detector_that_declares_nothing_is_refused_with_each_missing_declaration() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @detector(name="vague", namespace="acme", version="1.0.0")
        class Vague(DetectorBase):
            def examine(
                self, current: BaseSketch, reference: Sequence[BaseSketch]
            ) -> Sequence[HypothesisTest]:
                del current, reference
                return ()

    text = _problems(error)
    for declaration in ("EVIDENCE", "CODECS", "TESTS_PER_SKETCH"):
        assert f"must declare {declaration}" in text


def test_a_detector_reading_an_unknown_codec_or_with_a_bad_alpha_is_refused() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @detector(name="lost", namespace="acme", version="1.0.0")
        class Lost(DetectorBase):
            EVIDENCE: ClassVar[EvidenceKind] = EvidenceKind.RATE_CHANGE
            CODECS: ClassVar[frozenset[str]] = frozenset({"acme-nonexistent-v9"})
            TESTS_PER_SKETCH: ClassVar[int] = 0
            ALPHA: ClassVar[float] = 1.5

            def examine(
                self, current: BaseSketch, reference: Sequence[BaseSketch]
            ) -> Sequence[HypothesisTest]:
                del current, reference
                return (HypothesisTest("m", 0.0, 0.0, 1.0, Direction.UP),)

    text = _problems(error)
    assert "which no registered sketch writes" in text
    assert "TESTS_PER_SKETCH must be a positive integer" in text
    assert "ALPHA must be a float strictly between 0 and 1" in text


# -- feature ---------------------------------------------------------------------------


def test_a_feature_without_a_point_in_time_window_is_refused() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @feature(name="timeless", namespace="acme", version="1.0.0")
        class Timeless(FeatureBase):
            DTYPE: ClassVar[LogicalType] = LogicalType.INT
            INPUTS: ClassVar[tuple[str, ...]] = ("amount",)

            def aggregate(self, columns: Mapping[str, str]) -> str:
                return f"count({columns['amount']})"

    assert "must declare LOOKBACK" in _problems(error)


def test_a_feature_whose_embargo_swallows_its_window_is_refused() -> None:
    with pytest.raises(PluginRejectedError, match="EMBARGO is at least LOOKBACK"):

        @feature(name="empty", namespace="acme", version="1.0.0")
        class Empty(FeatureBase):
            DTYPE: ClassVar[LogicalType] = LogicalType.INT
            INPUTS: ClassVar[tuple[str, ...]] = ("amount",)
            LOOKBACK: ClassVar[_dt.timedelta] = _dt.timedelta(days=1)
            EMBARGO: ClassVar[_dt.timedelta] = _dt.timedelta(days=2)

            def aggregate(self, columns: Mapping[str, str]) -> str:
                return f"count({columns['amount']})"


@pytest.mark.parametrize(
    "expression",
    [
        "count(*) FILTER (WHERE merchant = 'ACME_CORP')",
        "(SELECT max(amount) FROM godwit_history)",
        "count(*); DROP TABLE x",
    ],
)
def test_a_feature_aggregate_with_a_literal_or_a_subquery_is_refused(expression: str) -> None:
    with pytest.raises(PluginRejectedError, match="no string literal"):

        @feature(name="peeking", namespace="acme", version="1.0.0")
        class Peeking(FeatureBase):
            DTYPE: ClassVar[LogicalType] = LogicalType.FLOAT
            INPUTS: ClassVar[tuple[str, ...]] = ("amount",)
            LOOKBACK: ClassVar[_dt.timedelta] = _dt.timedelta(days=7)

            def aggregate(self, columns: Mapping[str, str]) -> str:
                del columns
                return expression


def test_a_feature_aggregate_that_is_not_valid_duckdb_is_refused() -> None:
    with pytest.raises(PluginRejectedError, match="not valid DuckDB"):

        @feature(name="garbled", namespace="acme", version="1.0.0")
        class Garbled(FeatureBase):
            DTYPE: ClassVar[LogicalType] = LogicalType.FLOAT
            INPUTS: ClassVar[tuple[str, ...]] = ("amount",)
            LOOKBACK: ClassVar[_dt.timedelta] = _dt.timedelta(days=7)

            def aggregate(self, columns: Mapping[str, str]) -> str:
                return f"avgg({columns['amount']}"


# -- context ---------------------------------------------------------------------------


def test_a_context_source_that_overrides_events_is_refused() -> None:
    with pytest.raises(PluginRejectedError, match=r"overrides events\(\)"):

        @context(name="raw", namespace="acme", version="1.0.0")
        class Raw(ContextBase):
            def fetch(self, *, start: _dt.datetime, end: _dt.datetime) -> Iterable[ContextRecord]:
                del start, end
                return ()

            @classmethod
            def for_conformance(cls, records: Sequence[ContextRecord]) -> Self:
                del records
                return cls()

            def events(self, *, start: _dt.datetime, end: _dt.datetime) -> tuple[Any, ...]:
                del start, end
                return ()


# -- panel -----------------------------------------------------------------------------


def test_a_panel_that_takes_anything_but_a_safe_payload_is_refused() -> None:
    with pytest.raises(PluginRejectedError) as error:

        @panel(name="raw", namespace="acme", version="1.0.0")
        class RawPanel(PanelBase):
            TITLE: ClassVar[str] = "Raw"
            FIELDS: ClassVar[tuple[str, ...]] = ("Customer Name",)

            def render(self, payload: dict[str, str]) -> PanelView:
                del payload
                return PanelView(title="Raw", chart="stat")

    text = _problems(error)
    assert "render() must take exactly one parameter, annotated SafePayload" in text
    assert "FIELDS must be a non-empty tuple of gate field keys" in text
