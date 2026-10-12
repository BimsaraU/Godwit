"""The conformance checks, one function per check, grouped by plugin kind.

Every check takes the plugin class and either returns (it passed) or raises
``AssertionError`` with a message saying exactly what is wrong and what to do about it.
Messages name the plugin's own identifiers and our labels -- never a value the check
fed in, because a conformance report is itself something people paste into tickets.
"""

from __future__ import annotations

import ast
import datetime as _dt
import inspect
import json
import sys
import textwrap
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

import pyarrow as pa
from godwit_context import ContextSource, ContextType
from godwit_contracts.common import (
    ProbeId,
    ProbeKey,
    SnapshotId,
    SourceId,
    canonical_json,
    content_hash,
)
from godwit_contracts.cost import CostBudget, CostSpend
from godwit_contracts.errors import BudgetExceededError
from godwit_contracts.features import FeatureSpec
from godwit_contracts.governance import Destination
from godwit_contracts.probe import ProbeKind, ProbeSpec
from godwit_contracts.protocols import Detector, Sketch, SourceAdapter
from godwit_contracts.sketch import SketchBundle, SketchEnvelope
from godwit_contracts.source import (
    ColumnProfile,
    ColumnRef,
    ColumnRole,
    LogicalType,
    SourceKind,
    SourceRef,
)
from godwit_contracts.taint import Sensitivity, derived_statistic, schema_name
from godwit_detect import (
    DetectionResult,
    FixedReference,
    ProbeContext,
    RefusalReason,
    SeriesPoint,
    SketchSeries,
)
from godwit_guard import (
    DEFAULT_POLICY,
    AccessMode,
    Backstop,
    ClassificationRegistry,
    Gate,
    MemoryLedger,
)
from godwit_probe import CancelFlag, ProbeKeyring, ProbeStatus
from godwit_probe.testing import access_map
from godwit_sketch import SKETCH_REGISTRY, BaseSketch, ItemFlavour, SketchContext, decode_envelope
from godwit_sketch.base import SketchItem
from godwit_sketch.deterministic import uniforms, zipf_indices
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from godwit_sdk.context import ContextBase, ContextRecord
from godwit_sdk.detector import DetectorBase, HypothesisTest
from godwit_sdk.errors import PluginFailedError, SdkError
from godwit_sdk.feature import EVENT_TIME, FEATURE_VALUE, FeatureBase
from godwit_sdk.panel import PanelBase, PanelView
from godwit_sdk.plugin import PluginBase, PluginKind
from godwit_sdk.registry import PluginRegistry
from godwit_sdk.sketch import SketchBase, law_problems
from godwit_sdk.source import Partition, SourceBase, TableName
from godwit_sdk.testing._capture import Capture, capture_egress
from godwit_sdk.testing._torture import torture

__all__ = ["CHECKS", "Check"]

type Check = Callable[[type[PluginBase]], None]

AT: Final[_dt.datetime] = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
"""The kit's one instant. Nothing here reads a clock."""

_GENEROUS: Final[CostBudget] = CostBudget(
    bytes_scanned=10**12, wall_seconds=3600.0, usd=Decimal(1000), llm_tokens=0, train_seconds=0.0
)
_NOTHING: Final[CostBudget] = CostBudget(
    bytes_scanned=0, wall_seconds=3600.0, usd=Decimal(1000), llm_tokens=0, train_seconds=0.0
)


def _fail(message: str) -> AssertionError:
    return AssertionError(textwrap.fill(message, width=100))


def _assert_no_leak(capture: Capture, what: str) -> None:
    leaked = capture.leaked(torture().sentinels)
    if leaked:
        raise _fail(
            f"{len(leaked)} poisoned value(s) from the PII torture fixture appeared in "
            f"{what}. A plugin must never print, log or raise with a value: use self.log, "
            "whose fields cannot hold a plain string, and let the SDK sanitise exceptions."
        )


# --------------------------------------------------------------------------------------
# Common: static hygiene and registration
# --------------------------------------------------------------------------------------

_RAW_OUTPUT_MODULES: Final[frozenset[str]] = frozenset(
    {"logging", "loguru", "structlog", "traceback", "warnings", "pprint"}
)
_RAW_OUTPUT_ATTRS: Final[frozenset[tuple[str, str]]] = frozenset(
    {("sys", "stdout"), ("sys", "stderr"), ("os", "write"), ("sys", "__stdout__")}
)
_CONTROL_PLANE: Final[frozenset[PluginKind]] = frozenset(
    {PluginKind.PANEL, PluginKind.CONTEXT, PluginKind.FEATURE}
)


def _module_source(cls: type) -> str:
    module = sys.modules.get(cls.__module__)
    if module is None:
        raise _fail(f"the module of {cls.__name__} is not importable by name")
    return inspect.getsource(module)


def check_static_hygiene(cls: type[PluginBase]) -> None:
    """No raw output channel in the plugin's module: logging, print, stdout, os.write."""
    tree = ast.parse(_module_source(cls))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if a.name in _RAW_OUTPUT_MODULES]
        elif isinstance(node, ast.ImportFrom) and node.module in _RAW_OUTPUT_MODULES:
            found.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"print", "breakpoint", "input"}:
                found.append(f"{node.func.id}() on line {node.lineno}")
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and (node.value.id, node.attr) in _RAW_OUTPUT_ATTRS
        ):
            found.append(f"{node.value.id}.{node.attr} on line {node.lineno}")
        elif (
            cls.plugin_info().kind in _CONTROL_PLANE
            and isinstance(node, ast.Attribute)
            and node.attr == "reveal"
        ):
            found.append(f".reveal() on line {node.lineno} in a control-plane plugin")
    if found:
        raise _fail(
            f"{cls.__name__}'s module writes output the SDK cannot control: "
            f"{'; '.join(sorted(set(found)))}. Use self.log (godwit_sdk.PluginLogger); a "
            "plugin that prints or logs directly can copy a customer value into a log."
        )


def check_registration(cls: type[PluginBase]) -> None:
    """The plugin registers into a fresh registry and states its trust category."""
    info = PluginRegistry().register(cls)
    if info.qualified_name.count(".") != 1:
        raise _fail("qualified name must be exactly <namespace>.<name>")
    if not info.trust_category:
        raise _fail("trust category is not stated")


# --------------------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------------------

_OPAQUE_CLASSES: Final[frozenset[str]] = frozenset({"direct_identifier"})
_UNCLASSIFIED: Final[str] = "patient_hiv_status"
"""Left out of the access map on purpose: a column nobody classified must fail closed."""
_BLIND: Final[str] = "notes"
_KEY: Final[bytes] = b"godwit-sdk-conformance-key-0001!"


class _Recording:
    """Wraps a source instance's ``read`` to record which columns it was asked for."""

    def __init__(self, plugin: SourceBase) -> None:
        self.requested: list[tuple[str, ...]] = []
        self.calls = 0
        original = plugin.read

        def read(
            table: TableName, partition: Partition, columns: Sequence[str]
        ) -> Iterable[pa.RecordBatch | pa.Table]:
            self.calls += 1
            self.requested.append(tuple(columns))
            return original(table, partition, columns)

        plugin.__dict__["read"] = read


def _source(cls: type[PluginBase]) -> tuple[SourceBase, SourceRef]:
    if not issubclass(cls, SourceBase):
        raise TypeError("not a source")

    data = torture()
    plugin = cls.for_conformance({data.table_name: data.table})
    if not isinstance(plugin, cls):
        raise _fail("for_conformance() must return an instance of the plugin class")
    ref = cls.source_ref(
        source_id="src_conformance", namespace="conformance", table=data.table_name
    )
    modes = {
        name: (
            AccessMode.BLIND
            if name == _BLIND
            else AccessMode.OPAQUE
            if pii in _OPAQUE_CLASSES
            else AccessMode.OPEN
        )
        for name, pii in data.pii_classes.items()
        if name != _UNCLASSIFIED
    }
    plugin.govern(
        access=access_map(ref, modes, at=AT),
        keyring=ProbeKeyring(column_key=_KEY, sketch_key=_KEY[::-1]),
    )
    return plugin, ref


def _spec(ref: SourceRef, kind: ProbeKind, *columns: str) -> ProbeSpec:
    return ProbeSpec(
        probe_id=ProbeId(f"conformance-{kind.value}"),
        kind=kind,
        spec_version=1,
        source=ref,
        columns=tuple(schema_name(c) for c in columns),
        budget=_GENEROUS,
        seed=20240101,
        as_of=AT,
    )


_PROBES: Final[tuple[tuple[ProbeKind, tuple[str, ...]], ...]] = (
    (ProbeKind.ROW_COUNT, ()),
    (ProbeKind.QUANTILES, ("salary_2024",)),
    (ProbeKind.HEAVY_HITTERS, ("merchant_name",)),
    (ProbeKind.DISTINCT_COUNT, ("email",)),
    (ProbeKind.HEAVY_HITTERS, ("device_id",)),
    (ProbeKind.NULL_RATE, ("cohort",)),
)


def _run_all(plugin: SourceBase, ref: SourceRef) -> list[SketchBundle]:
    snapshot = plugin.resolve_snapshot(ref)
    return [
        plugin.execute_probe(_spec(ref, kind, *columns), snapshot, budget=_GENEROUS)
        for kind, columns in _PROBES
    ]


def check_source_protocol(cls: type[PluginBase]) -> None:
    """The instance satisfies ``SourceAdapter`` and profiles the table from metadata."""
    plugin, ref = _source(cls)
    if not isinstance(plugin, SourceAdapter):
        raise _fail("the instance does not satisfy godwit_contracts.SourceAdapter")
    recording = _Recording(plugin)
    snapshot = plugin.resolve_snapshot(ref)
    profile = plugin.profile_table(ref, snapshot, budget=_NOTHING)
    names = {column.ref.column.reveal() for column in profile.columns}
    if names != set(torture().table.column_names):
        raise _fail("profile_table() does not list exactly the table's columns")
    if recording.calls:
        raise _fail("profile_table() read data; it must use metadata only (invariant 5)")


def check_source_probes(cls: type[PluginBase]) -> None:
    """Every planned probe completes; BLIND and unclassified columns are refused unread."""

    plugin, ref = _source(cls)
    recording = _Recording(plugin)
    bundles = _run_all(plugin, ref)
    if len(bundles) != len(_PROBES):
        raise _fail("not every conformance probe produced a bundle")
    for column in (_BLIND, _UNCLASSIFIED):
        outcome = plugin.run_probe(_spec(ref, ProbeKind.QUANTILES, column), budget=_GENEROUS)
        if outcome.status is not ProbeStatus.REFUSED:
            raise _fail(f"a probe over the {column!r} column was not refused")
    if any(_BLIND in columns or _UNCLASSIFIED in columns for columns in recording.requested):
        raise _fail("read() was asked for a BLIND or unclassified column")


def check_source_budget(cls: type[PluginBase]) -> None:
    """A probe that cannot afford its reads is refused before ``read`` is called."""

    plugin, ref = _source(cls)
    recording = _Recording(plugin)
    spec = _spec(ref, ProbeKind.QUANTILES, "salary_2024")
    snapshot = plugin.resolve_snapshot(ref)
    try:
        plugin.execute_probe(spec, snapshot, budget=_NOTHING)
    except BudgetExceededError:
        pass
    else:
        raise _fail("a probe with a zero-byte budget was not refused")
    if recording.calls:
        raise _fail("read() was called for a probe the budget could not afford")
    flag = CancelFlag()
    flag.cancel()
    outcome = plugin.run_probe(spec, budget=_GENEROUS, cancel=flag)
    if outcome.status is not ProbeStatus.CANCELLED:
        raise _fail("a cancelled probe did not report CANCELLED")
    done = plugin.run_probe(spec, budget=_GENEROUS)
    if done.cost_spent.bytes_scanned <= 0:
        raise _fail("a completed probe reported no bytes read; cost accounting is broken")


def check_source_determinism(cls: type[PluginBase]) -> None:
    """Two fresh instances give byte-identical bundles for the same probes."""
    first = [b.model_dump_json() for b in _run_all(*_source(cls))]
    second = [b.model_dump_json() for b in _run_all(*_source(cls))]
    if first != second:
        raise _fail("the same probes over the same data gave different bundles (invariant 7)")


def check_source_serialisation(cls: type[PluginBase]) -> None:
    """Bundles survive a JSON round trip, and every envelope decodes and re-encodes."""
    for bundle in _run_all(*_source(cls)):
        if SketchBundle.model_validate_json(bundle.model_dump_json()) != bundle:
            raise _fail("a SketchBundle did not survive a JSON round trip")
        for envelope in bundle.sketches.values():
            _envelope_round_trip(envelope)


def _envelope_round_trip(envelope: SketchEnvelope) -> None:
    decoded = decode_envelope(envelope)
    if decoded.encode() != envelope.payload:
        raise _fail(f"a {envelope.codec} envelope did not decode back to the same bytes")


def check_source_leaks(cls: type[PluginBase]) -> None:
    """Poisoned rows, and a poisoned driver error, reach no log, stream or error text."""
    data = torture()
    with capture_egress() as capture:
        plugin, ref = _source(cls)
        snapshot = plugin.resolve_snapshot(ref)
        capture.add(repr(plugin.profile_table(ref, snapshot, budget=_NOTHING)))
        for bundle in _run_all(plugin, ref):
            capture.add(_render_bundle(bundle))
        failing, failing_ref = _source(cls)

        def explode(*_: object) -> Iterator[pa.RecordBatch]:
            raise RuntimeError(data.driver_exception)

        failing.__dict__["read"] = explode
        try:
            failing.execute_probe(
                _spec(failing_ref, ProbeKind.QUANTILES, "salary_2024"),
                failing.resolve_snapshot(failing_ref),
                budget=_GENEROUS,
            )
        except SdkError as error:
            capture.add(str(error))
            capture.add(repr(error))
        else:
            raise _fail("a read() that raised did not fail the probe")
    _assert_no_leak(capture, "the output of a source run over the PII torture table")


def _render_bundle(bundle: SketchBundle) -> str:
    """The bundle as text, minus the payloads that are DATA_VALUE by declaration."""
    parts = [bundle.model_dump_json(exclude={"sketches"})]
    for name, envelope in sorted(bundle.sketches.items()):
        exclude = {"payload"} if envelope.sensitivity is Sensitivity.DATA_VALUE else set()
        parts.append(name + envelope.model_dump_json(exclude=exclude))
        if not exclude:
            parts.append(envelope.payload.decode("latin-1"))
    return "\n".join(parts)


# --------------------------------------------------------------------------------------
# Sketches
# --------------------------------------------------------------------------------------


def _sketch(cls: type[PluginBase]) -> type[SketchBase]:
    if not issubclass(cls, SketchBase):
        raise TypeError("not a sketch")
    return cls


def check_sketch_laws(cls: type[PluginBase]) -> None:
    """The monoid laws hold over hypothesis-generated inputs, not only the fixed sample."""

    target = _sketch(cls)
    flavour = target.ITEM_FLAVOUR
    pool = [f"item-{i}" for i in range(40)]
    item: st.SearchStrategy[SketchItem]
    if flavour is ItemFlavour.NUMERIC:
        item = st.floats(min_value=-1e9, max_value=1e9, allow_nan=False, width=64)
    elif flavour is ItemFlavour.EDGE:
        item = st.tuples(st.sampled_from(pool), st.sampled_from(pool))
    else:
        item = st.sampled_from(pool) | st.text(min_size=1, max_size=12)
    batch = st.lists(item, max_size=300)
    problems: list[str] = []

    @settings(
        max_examples=60,
        deadline=None,
        derandomize=True,
        suppress_health_check=list(HealthCheck),
        database=None,
    )
    @given(batch, batch, batch)
    def laws(a: list[SketchItem], b: list[SketchItem], c: list[SketchItem]) -> None:
        found = law_problems(target, [(a, b, c)])
        if found:
            problems.extend(found)
            raise AssertionError(found[0])

    try:
        laws()
    except AssertionError:
        raise _fail(
            f"{cls.__name__} breaks a monoid law on generated input: "
            f"{'; '.join(dict.fromkeys(problems))}"
        ) from None


def check_sketch_protocol(cls: type[PluginBase]) -> None:
    """An instance satisfies ``godwit_contracts.Sketch``."""
    target = _sketch(cls)
    if not isinstance(target.identity(target.DEFAULT_PARAMS), Sketch):
        raise _fail("an instance does not satisfy godwit_contracts.Sketch")


def check_sketch_leaks(cls: type[PluginBase]) -> None:
    """Fed the torture table's strings, a sketch renders and logs none of them."""
    target = _sketch(cls)
    data = torture()
    with capture_egress() as capture:
        items: list[SketchItem]
        if target.ITEM_FLAVOUR is ItemFlavour.NUMERIC:
            items = [float(v) for v in data.table.column("salary_2024").to_pylist()]
        elif target.ITEM_FLAVOUR is ItemFlavour.EDGE:
            items = [(v, v) for v in data.strings()]
        else:
            items = list(data.strings())
        built = target.from_items(items, target.DEFAULT_PARAMS)
        envelope = built.serialise(
            SketchContext(
                source_id=SourceId("src_conformance"),
                snapshot_id=SnapshotId("snap_conformance"),
                produced_for=ProbeKey("prb_conformance"),
                produced_at=AT,
            )
        )
        capture.add(repr(built))
        capture.add(str(built))
        if envelope.sensitivity is not Sensitivity.DATA_VALUE:
            capture.add(envelope.payload.decode("latin-1"))
    _assert_no_leak(capture, "the rendering or payload of a sketch declared not value-bearing")


# --------------------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------------------


def _detector(cls: type[PluginBase]) -> type[DetectorBase]:
    if not issubclass(cls, DetectorBase):
        raise TypeError("not a detector")
    return cls


def _scenario_items(
    flavour: ItemFlavour, shape: str, count: int, salt: str = ""
) -> list[SketchItem]:
    if flavour is ItemFlavour.NUMERIC:
        u = uniforms(count, salt=f"kit-{shape}-{salt}")
        if shape == "shifted":
            return [400.0 + 500.0 * x for x in u]
        return [10.0 ** (1.0 + 4.0 * x) for x in u]
    pool = list(torture().strings())
    exponent = 1.1 if shape != "shifted" else 2.0
    indices = zipf_indices(count, distinct=len(pool), salt=f"kit-{shape}-{salt}", exponent=exponent)
    if flavour is ItemFlavour.EDGE:
        return [(pool[i], pool[(i * 5 + 1) % len(pool)]) for i in indices]
    return [pool[i] for i in indices]


def _build(codec: str, items: Sequence[SketchItem]) -> BaseSketch:
    sketch_cls = SKETCH_REGISTRY[codec]
    params = dict(getattr(sketch_cls, "DEFAULT_PARAMS", {}))
    return sketch_cls.from_items(items, params)


_WINDOWS: Final[tuple[str, ...]] = ("w0", "w1", "w2")


def _context(spec_key: ProbeKey, index: int) -> SketchContext:
    return SketchContext(
        source_id=SourceId("src_conformance"),
        snapshot_id=SnapshotId(f"snap_{_WINDOWS[index]}"),
        produced_for=spec_key,
        produced_at=AT + _dt.timedelta(days=index),
        column="amount",
    )


def _detector_spec() -> ProbeSpec:
    ref = SourceRef(
        source_id=SourceId("src_conformance"),
        kind=SourceKind.PARQUET,
        catalog="conformance",
        namespace=schema_name("conformance"),
        table=schema_name("payments"),
    )
    return ProbeSpec(
        probe_id=ProbeId("conformance-detector"),
        kind=ProbeKind.QUANTILES,
        spec_version=1,
        source=ref,
        columns=(schema_name("amount"),),
        budget=_GENEROUS,
        seed=1,
        as_of=AT,
    )


def _envelopes(codec: str, shapes: tuple[str, str, str], count: int) -> list[SketchEnvelope]:
    flavour = SKETCH_REGISTRY[codec].ITEM_FLAVOUR
    spec = _detector_spec()
    return [
        _build(codec, _scenario_items(flavour, shape, count, str(index))).serialise(
            _context(spec.key, index)
        )
        for index, shape in enumerate(shapes)
    ]


def _series(codec: str, envelopes: Sequence[SketchEnvelope]) -> SketchSeries:
    spec = _detector_spec()
    return SketchSeries(
        context=ProbeContext.from_spec(spec, f"{codec}:0"),
        points=tuple(
            SeriesPoint(at=e.produced_at, snapshot_id=e.snapshot_id, envelope=e) for e in envelopes
        ),
    )


def _results(cls: type[DetectorBase]) -> list[str]:
    policy = FixedReference(snapshot_id=SnapshotId("snap_w1"))
    rendered: list[str] = []
    for codec in sorted(cls.CODECS):
        for shapes in (("stable", "stable", "stable"), ("stable", "stable", "shifted")):
            result = cls().run(_series(codec, _envelopes(codec, shapes, 5000)), policy=policy)
            rendered.append(result.model_dump_json())
    return rendered


def check_detector_min_support(cls: type[PluginBase]) -> None:
    """A thin sketch is refused before ``examine`` runs."""
    target = _detector(cls)
    plugin = target()
    calls: list[int] = []
    original = plugin.examine

    def counted(current: BaseSketch, reference: Sequence[BaseSketch]) -> Sequence[HypothesisTest]:
        calls.append(1)
        return original(current, reference)

    plugin.__dict__["examine"] = counted
    policy = FixedReference(snapshot_id=SnapshotId("snap_w1"))
    for codec in sorted(target.CODECS):
        envelopes = _envelopes(codec, ("stable", "stable", "stable"), 5000)
        thin = _build(codec, _scenario_items(SKETCH_REGISTRY[codec].ITEM_FLAVOUR, "thin", 3))
        envelopes[2] = thin.serialise(_context(_detector_spec().key, 2))
        result = plugin.run(_series(codec, envelopes), policy=policy)
        if result.findings or not any(
            r.reason is RefusalReason.THIN_SKETCH for r in result.refusals
        ):
            raise _fail("a sketch below MIN_SUPPORT was not refused as thin_sketch")
    if calls:
        raise _fail("examine() ran on a sketch below MIN_SUPPORT")


def check_detector_tests_declared(cls: type[PluginBase]) -> None:
    """Every result reports a test count within ``TESTS_PER_SKETCH``."""
    target = _detector(cls)
    for rendered in _results(target):
        tests = json.loads(rendered)["tests"]
        if tests > target.TESTS_PER_SKETCH:
            raise _fail("a result reported more tests than TESTS_PER_SKETCH declares")


def check_detector_determinism(cls: type[PluginBase]) -> None:
    """The same series gives the same result, and it survives a JSON round trip."""

    target = _detector(cls)
    first, second = _results(target), _results(target)
    if first != second:
        raise _fail("the same series gave different results (detector law 1)")
    for rendered in first:
        if DetectionResult.model_validate_json(rendered).model_dump_json() != rendered:
            raise _fail("a DetectionResult did not survive a JSON round trip")


def check_detector_contract(cls: type[PluginBase]) -> None:
    """``as_contract`` satisfies ``Detector`` and honours ``ROLES`` from the profiles."""
    target = _detector(cls)
    spec = _detector_spec()
    adapter = target().as_contract(spec=spec, code_version="conformance")
    if not isinstance(adapter, Detector):
        raise _fail("as_contract() does not satisfy godwit_contracts.Detector")
    roles = sorted(target.ROLES) or [ColumnRole.UNKNOWN]
    for codec in sorted(target.CODECS):
        before, _, after = _envelopes(codec, ("stable", "stable", "shifted"), 5000)

        def bundle(envelope: SketchEnvelope, name: str = f"{codec}:0") -> SketchBundle:
            return _bundle(spec, name, envelope)

        for role in roles:
            profile = _profile(role)
            candidates = adapter.detect(
                current=bundle(after), baseline=bundle(before), profiles=(profile,), seed=1
            )
            for candidate in candidates:
                if candidate.model_validate_json(candidate.model_dump_json()) != candidate:
                    raise _fail("a Candidate did not survive a JSON round trip")
        if target.ROLES:
            other = next(r for r in ColumnRole if r not in target.ROLES)
            if adapter.detect(
                current=bundle(after), baseline=bundle(before), profiles=(_profile(other),), seed=1
            ):
                raise _fail("candidates were produced for a column whose role is not in ROLES")


def _bundle(spec: ProbeSpec, name: str, envelope: SketchEnvelope) -> SketchBundle:
    return SketchBundle(
        bundle_id=f"bnd_{envelope.snapshot_id}",
        probe_key=spec.key,
        source_id=spec.source.source_id,
        snapshot_id=envelope.snapshot_id,
        sketches={name: envelope},
        cost_spent=CostSpend.zero(),
        produced_at=envelope.produced_at,
        worker_version="conformance",
        seed=1,
    )


def _profile(role: ColumnRole) -> ColumnProfile:
    return ColumnProfile(
        ref=ColumnRef(
            source_id=SourceId("src_conformance"),
            table=schema_name("payments"),
            column=schema_name("amount"),
        ),
        logical_type=LogicalType.FLOAT,
        native_type="double",
        nullable=True,
        role=role,
        observed_at=AT,
        profile_version=1,
    )


def check_detector_leaks(cls: type[PluginBase]) -> None:
    """Over poisoned categorical sketches, findings, notes and logs quote no value."""
    target = _detector(cls)
    policy = FixedReference(snapshot_id=SnapshotId("snap_w1"))
    with capture_egress() as capture:
        for codec in sorted(target.CODECS):
            envelopes = _envelopes(codec, ("stable", "stable", "shifted"), 5000)
            result = target().run(_series(codec, envelopes), policy=policy)
            capture.add(repr(result))
            for finding in result.findings:
                capture.add(finding.method + finding.p_value_note + finding.statistic.name)
    _assert_no_leak(capture, "a detector's findings or logs")


def behaviour_digest(cls: type[DetectorBase]) -> str:
    """A hash of the detector's output over the kit's scenarios, for version pinning."""
    return content_hash(canonical_json(_results(cls)), prefix="beh")


def check_version_pin(cls: type[PluginBase], pins: Path) -> None:
    """Output may change only with a version bump. The first run of a version records it."""
    target = _detector(cls)
    info = target.plugin_info()
    recorded: dict[str, str] = json.loads(pins.read_text("utf-8")) if pins.exists() else {}
    key = f"{info.qualified_name}@{info.version}"
    digest = behaviour_digest(target)
    if key not in recorded:
        recorded[key] = digest
        pins.write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n", "utf-8")
    elif recorded[key] != digest:
        raise _fail(
            f"{info.qualified_name}'s output changed but its version is still {info.version}. "
            "Bump the version (lineage and replay key on it), then rerun to record the new pin."
        )


# --------------------------------------------------------------------------------------
# Features
# --------------------------------------------------------------------------------------


def _feature(cls: type[PluginBase]) -> FeatureBase:
    if not issubclass(cls, FeatureBase):
        raise TypeError("not a feature")
    return cls()


def _feature_tables(plugin: FeatureBase) -> tuple[pa.Table, pa.Table]:
    lookback = plugin.LOOKBACK
    events = pa.table({"entity": ["a", "b", "a"], EVENT_TIME: [AT, AT, AT + lookback / 2]})
    offsets = [-1.5, -0.9, -0.5, -0.1, 0.0, 0.4, 0.6, 1.2]
    stamps = [AT + lookback * f for f in offsets] * 2
    entities = ["a"] * len(offsets) + ["b"] * len(offsets)
    history: dict[str, list[Any]] = {"entity": entities, "ts": stamps}
    for index, role in enumerate(plugin.INPUTS):
        history[role] = [float(i + 1 + index) for i in range(len(stamps))]
    return events, pa.table(history)


def _feature_spec(plugin: FeatureBase) -> FeatureSpec:
    return plugin.spec(
        feature_id="conformance",
        source_id="src_conformance",
        entity_key="entity",
        timestamp_column="ts",
        columns={role: role for role in plugin.INPUTS},
    )


def check_feature_point_in_time(cls: type[PluginBase]) -> None:
    """Changing rows at or after each event's cut-off, or before its lookback, moves nothing."""
    plugin = _feature(cls)
    spec = _feature_spec(plugin)
    events, history = _feature_tables(plugin)
    baseline = plugin.evaluate(spec, events=events, history=history).column(FEATURE_VALUE)
    stamps = history.column("ts").to_pylist()
    entities = history.column("entity").to_pylist()
    rule = spec.point_in_time
    windows = {
        (e, t)
        for e, t in zip(
            events.column("entity").to_pylist(), events.column(EVENT_TIME).to_pylist(), strict=True
        )
    }

    def inside(entity: str, stamp: _dt.datetime) -> bool:
        for owner, at in windows:
            end = at - rule.embargo
            if (
                owner == entity
                and at - rule.max_lookback <= stamp
                and (stamp <= end if rule.inclusive_end else stamp < end)
            ):
                return True
        return False

    poisoned = history
    for role in plugin.INPUTS:
        values = history.column(role).to_pylist()
        changed = [
            v if inside(e, t) else v * 1000.0 + 7.0
            for v, e, t in zip(values, entities, stamps, strict=True)
        ]
        index = poisoned.schema.get_field_index(role)
        poisoned = poisoned.set_column(index, role, pa.array(changed, pa.float64()))
    moved = plugin.evaluate(spec, events=events, history=poisoned).column(FEATURE_VALUE)
    if moved.to_pylist() != baseline.to_pylist():
        raise _fail(
            "a feature value changed when only rows outside its point-in-time window "
            "changed: the feature reads the future (or past its lookback)"
        )


def check_feature_determinism(cls: type[PluginBase]) -> None:
    """Same spec, same tables, same values; the spec survives a JSON round trip."""
    plugin = _feature(cls)
    spec = _feature_spec(plugin)
    events, history = _feature_tables(plugin)
    first = plugin.evaluate(spec, events=events, history=history)
    second = _feature(cls).evaluate(_feature_spec(_feature(cls)), events=events, history=history)
    if not first.equals(second):
        raise _fail("the same feature over the same rows gave different values")
    if type(spec).model_validate_json(spec.model_dump_json()) != spec:
        raise _fail("the FeatureSpec did not survive a JSON round trip")


def check_feature_leaks(cls: type[PluginBase]) -> None:
    """Building and evaluating the feature logs nothing from the data."""
    plugin = _feature(cls)
    with capture_egress() as capture:
        spec = _feature_spec(plugin)
        events, history = _feature_tables(plugin)
        plugin.evaluate(spec, events=events, history=history)
        capture.add(repr(spec))
    _assert_no_leak(capture, "a feature's spec or logs")


# --------------------------------------------------------------------------------------
# Context sources
# --------------------------------------------------------------------------------------


def _records() -> list[ContextRecord]:
    data = torture()
    names = data.table.column("full_name").to_pylist()
    return [
        ContextRecord(
            key=f"evt-{index}",
            context_type=ContextType.CAMPAIGN if index % 2 else ContextType.DEPLOY,
            kind="conformance.campaign" if index % 2 else "conformance.deploy",
            start=AT + _dt.timedelta(hours=index),
            end=AT + _dt.timedelta(hours=index + 1),
            label=f"{data.driver_exception} {name}",
            columns=("customer_ssn",),
        )
        for index, name in enumerate(names)
    ] + [
        ContextRecord(
            key="evt-outside",
            context_type=ContextType.DEPLOY,
            kind="conformance.deploy",
            start=AT - _dt.timedelta(days=30),
        )
    ]


def _context_events(cls: type[PluginBase]) -> tuple[Any, ...]:
    if not issubclass(cls, ContextBase):
        raise TypeError("not a context source")
    plugin = cls.for_conformance(_records())
    if not isinstance(plugin, ContextSource):
        raise _fail("the instance does not satisfy godwit_context.ContextSource")
    return plugin.events(start=AT, end=AT + _dt.timedelta(days=1))


def check_context_events(cls: type[PluginBase]) -> None:
    """Window filtering, tainted labels and schema-tainted columns, deterministically."""
    events = _context_events(cls)
    if len(events) != len(_records()) - 1:
        raise _fail("events() did not return exactly the records overlapping the window")
    for event in events:
        if event.label is not None and event.label.sensitivity is not Sensitivity.DATA_VALUE:
            raise _fail("a label is not tainted DATA_VALUE")
    if [e.model_dump_json() for e in events] != [e.model_dump_json() for e in _context_events(cls)]:
        raise _fail("the same records gave different events")
    for event in events:
        if type(event).model_validate_json(event.model_dump_json()) != event:
            raise _fail("a ContextEvent did not survive a JSON round trip")


def check_context_leaks(cls: type[PluginBase]) -> None:
    """Poisoned labels never reach a rendering, an id or a log."""
    with capture_egress() as capture:
        for event in _context_events(cls):
            capture.add(repr(event))
            capture.add(event.event_id + event.kind + event.origin)
    _assert_no_leak(capture, "a context source's events or logs")


# --------------------------------------------------------------------------------------
# Panels
# --------------------------------------------------------------------------------------


@contextmanager
def _payload(fields: Sequence[str]) -> Iterator[Any]:

    gate = Gate(
        ledger=MemoryLedger(),
        registry=ClassificationRegistry(),
        backstop=Backstop(use_presidio=False),
    )
    payload, _ = gate.clear(
        fields={
            name: derived_statistic(float(index + 1), population=10_000)
            for index, name in enumerate(fields)
        },
        destination=Destination.UI,
        purpose="panel.conformance",
        policy=DEFAULT_POLICY,
        guardrails=(),
        actor="godwit-sdk.conformance",
        occurred_at=AT,
    )
    yield payload


def _panel(cls: type[PluginBase]) -> PanelBase:
    if not issubclass(cls, PanelBase):
        raise TypeError("not a panel")
    return cls()


def check_panel_view(cls: type[PluginBase]) -> None:
    """A gated payload renders to a valid view, deterministically, with nothing added."""
    plugin = _panel(cls)
    with _payload(plugin.FIELDS) as payload:
        try:
            first = plugin.view(payload)
            second = _panel(cls).view(payload)
        except PluginFailedError as error:
            raise _fail(f"view() refused the render: {error.classification}") from None
    if first != second:
        raise _fail("the same payload rendered two different views")
    if PanelView.model_validate_json(first.model_dump_json()) != first:
        raise _fail("the PanelView did not survive a JSON round trip")


def check_panel_leaks(cls: type[PluginBase]) -> None:
    """Rendering logs nothing; the view is checked against the payload by ``view``."""
    plugin = _panel(cls)
    with capture_egress() as capture, _payload(plugin.FIELDS) as payload:
        capture.add(plugin.view(payload).model_dump_json())
    _assert_no_leak(capture, "a panel's view or logs")


# --------------------------------------------------------------------------------------

_COMMON: Final[tuple[tuple[str, Check], ...]] = (
    ("registration", check_registration),
    ("static_hygiene", check_static_hygiene),
)

CHECKS: Final[Mapping[PluginKind, tuple[tuple[str, Check], ...]]] = {
    PluginKind.SOURCE: (
        *_COMMON,
        ("protocol", check_source_protocol),
        ("probes_and_access_modes", check_source_probes),
        ("budget_and_cancellation", check_source_budget),
        ("determinism", check_source_determinism),
        ("serialisation", check_source_serialisation),
        ("leaks", check_source_leaks),
    ),
    PluginKind.SKETCH: (
        *_COMMON,
        ("protocol", check_sketch_protocol),
        ("monoid_laws", check_sketch_laws),
        ("leaks", check_sketch_leaks),
    ),
    PluginKind.DETECTOR: (
        *_COMMON,
        ("protocol", check_detector_contract),
        ("min_support", check_detector_min_support),
        ("tests_declared", check_detector_tests_declared),
        ("determinism_and_serialisation", check_detector_determinism),
        ("leaks", check_detector_leaks),
    ),
    PluginKind.FEATURE: (
        *_COMMON,
        ("point_in_time", check_feature_point_in_time),
        ("determinism_and_serialisation", check_feature_determinism),
        ("leaks", check_feature_leaks),
    ),
    PluginKind.CONTEXT: (
        *_COMMON,
        ("events", check_context_events),
        ("leaks", check_context_leaks),
    ),
    PluginKind.PANEL: (
        *_COMMON,
        ("view", check_panel_view),
        ("leaks", check_panel_leaks),
    ),
}
"""Every check, per kind, in the order they run."""
