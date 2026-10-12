"""``@detector``: a custom detector over sketches. Control plane, no data access. L2.

A detector plugin answers one question: *given this sketch and its reference, what did
you test, and what did you find?* It returns :class:`HypothesisTest` values -- plain
numbers and our own labels -- and the base does the rest, all of which is easy to get
wrong and none of which is specific to the detector:

* **versioning** -- the plugin's semantic version becomes ``Lineage.detector_version``;
  bump it whenever output could change for identical input. The conformance kit can pin
  output per version so a forgotten bump fails a test.
* **minimum support** -- a sketch below ``MIN_SUPPORT`` rows, or a reference window
  below it, is refused (``thin_sketch`` / ``thin_baseline``) before ``examine`` runs.
  Small populations are where spurious findings are manufactured.
* **test-count declaration** -- ``TESTS_PER_SKETCH`` is the most hypotheses ``examine``
  may test per sketch. L5 controls the false-discovery rate over every hypothesis
  tested, so the count is reported on every result, emitted or not, and a plugin that
  tests more than it declared fails.
* **emission** -- raw p-values only; a test is emitted as a finding when its p-value is
  at most ``ALPHA``. No FDR here: that belongs to L5.
* **lineage, candidates, refusals, the contract** -- through ``godwit-detect``'s own
  machinery, so a plugin's findings are indistinguishable in shape from a core one's.

A detector never sees a row. Value-bearing sketches expose stored items only as
``Tainted``; if you need to align heavy-hitter keys between two windows, do it with the
tainted objects and never copy one into a label, a note or a method name.
"""

from __future__ import annotations

import abc
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Final

from godwit_contracts.common import Version
from godwit_contracts.discovery import Candidate, EvidenceKind
from godwit_contracts.probe import ProbeSpec
from godwit_contracts.protocols import Detector
from godwit_contracts.segment import canonical_column
from godwit_contracts.sketch import SketchBundle
from godwit_contracts.source import ColumnProfile, ColumnRole
from godwit_detect import (
    BaselinePolicy,
    BundleDetector,
    DetectionResult,
    Direction,
    ProbeContext,
    RefusalReason,
    SeriesDetector,
    SeriesPoint,
    Settings,
    SketchSeries,
    Window,
)
from godwit_detect.base import Claim
from godwit_detect.evidence import measure
from godwit_sketch import SKETCH_REGISTRY, BaseSketch, decode_envelope

from godwit_sdk.capabilities import Capabilities, ResourceLimits
from godwit_sdk.errors import PluginFailedError
from godwit_sdk.plugin import (
    DEFAULT_REQUIREMENT,
    PluginBase,
    PluginInfo,
    PluginKind,
    decorator_for,
    require_class_vars,
)

__all__ = ["DetectorBase", "HypothesisTest", "detector"]

_DECLARATIONS: Final[tuple[str, ...]] = ("EVIDENCE", "CODECS", "TESTS_PER_SKETCH")


@dataclass(frozen=True, slots=True)
class HypothesisTest:
    """One hypothesis a detector tested. Every field is a number or our own label.

    ``method`` names the test (``chi2_vs_benford``); ``statistic`` is the test statistic
    and ``effect`` how far things moved, in interpretable units -- the number a reviewer
    reads first. ``p_value`` is raw; ``None`` means "no valid test" and must say why in
    ``note``. A test with no p-value is neither counted nor emitted.
    """

    method: str
    statistic: float
    effect: float
    p_value: float | None
    direction: Direction
    note: str = ""
    baseline: float | None = None
    statistic_unit: str = ""
    effect_unit: str = ""


class DetectorBase(PluginBase, abc.ABC):
    """Base class for ``@detector`` plugins.

    Declare ``EVIDENCE`` (an ``EvidenceKind``), ``CODECS`` (the sketch codecs you read)
    and ``TESTS_PER_SKETCH``; optionally ``ROLES`` (column roles you apply to, e.g.
    ``{ColumnRole.AMOUNT}``; empty means any), ``MIN_SUPPORT`` and ``ALPHA``. Implement
    :meth:`examine`.
    """

    SDK_METHODS = ("run", "as_contract", "settings")

    EVIDENCE: ClassVar[EvidenceKind]
    CODECS: ClassVar[frozenset[str]]
    TESTS_PER_SKETCH: ClassVar[int]
    ROLES: ClassVar[frozenset[ColumnRole]] = frozenset()
    MIN_SUPPORT: ClassVar[int] = 100
    ALPHA: ClassVar[float] = 0.05

    @abc.abstractmethod
    def examine(
        self, current: BaseSketch, reference: Sequence[BaseSketch]
    ) -> Sequence[HypothesisTest]:
        """Test ``current`` against ``reference`` (oldest first, never empty).

        Both already passed the minimum-support check and share ``current``'s codec and
        key mode. Pure: no I/O, no clock, no randomness.
        """

    def settings(self) -> Settings:
        """The settings ``godwit-detect`` sees: ``ALPHA`` and ``MIN_SUPPORT``."""
        return Settings(alpha=self.ALPHA, min_support=self.MIN_SUPPORT)

    def run(self, series: SketchSeries, *, policy: BaselinePolicy) -> DetectionResult:
        """Test the current window of ``series`` against the windows ``policy`` selects."""
        return _series_detector(self).run(series, policy=policy)

    def as_contract(self, *, spec: ProbeSpec, code_version: str) -> Detector:
        """This detector as ``godwit_contracts.protocols.Detector``, for one probe spec.

        ``ROLES`` is applied here, from the column profiles the protocol passes in: a
        Benford detector declared for ``AMOUNT`` never tests an identifier column.
        """
        return _ContractDetector(self, spec=spec, code_version=code_version)


class _SeriesShim(SeriesDetector[Settings]):
    """``godwit-detect``'s series machinery around one plugin instance."""

    CODECS: ClassVar[frozenset[str]] = frozenset()
    plugin: DetectorBase

    @classmethod
    def default_settings(cls) -> Settings:
        return Settings()

    def _detect(
        self, series: SketchSeries, reference: Sequence[SeriesPoint], window: Window
    ) -> DetectionResult:
        plugin = self.plugin
        name = (series.context.sketch_name,)
        current_envelope = series.current.envelope
        if current_envelope is None:
            return self._result(refusals=[self._refusal(RefusalReason.GAP, name)])
        current = decode_envelope(current_envelope)
        past = [decode_envelope(point.envelope) for point in reference if point.envelope]
        if current.population < plugin.MIN_SUPPORT:
            return self._result(refusals=[self._refusal(RefusalReason.THIN_SKETCH, name)])
        if any(sketch.population < plugin.MIN_SUPPORT for sketch in past):
            return self._result(refusals=[self._refusal(RefusalReason.THIN_BASELINE, name)])
        tests = plugin.runner.call("examine", lambda: tuple(plugin.examine(current, tuple(past))))
        _check_tests(plugin, tests)
        findings = []
        counted = 0
        reference_rows = sum(sketch.population for sketch in past)
        for test in tests:
            if test.p_value is None:
                continue
            counted += 1
            claim = Claim(
                method=test.method,
                statistic=measure(test.method, test.statistic, test.statistic_unit),
                effect=measure("effect", test.effect, test.effect_unit),
                p_value=float(test.p_value),
                direction=test.direction,
                note=test.note,
                baseline=None
                if test.baseline is None
                else measure(test.method, test.baseline, test.statistic_unit),
                population=current.population,
                baseline_population=reference_rows,
            )
            finding = self._emit(series.context, window, claim)
            if finding is not None:
                findings.append(finding)
        return self._result(findings, tests=counted)


def _check_tests(plugin: DetectorBase, tests: Sequence[object]) -> None:
    info = plugin.plugin_info()

    def fail(classification: str) -> PluginFailedError:
        return PluginFailedError(
            info.qualified_name,
            stage="examine",
            error_type="HypothesisTest",
            classification=classification,
            original=None,
        )

    if len(tests) > plugin.TESTS_PER_SKETCH:
        raise fail(f"tested_{len(tests)}_declared_{plugin.TESTS_PER_SKETCH}")
    for test in tests:
        if not isinstance(test, HypothesisTest):
            raise fail("not_a_hypothesis_test")
        if not (math.isfinite(test.statistic) and math.isfinite(test.effect)):
            raise fail("statistic_or_effect_not_finite")
        if test.p_value is None:
            if not test.note:
                raise fail("p_value_none_without_note")
        elif not (math.isfinite(test.p_value) and 0.0 <= test.p_value <= 1.0):
            raise fail("p_value_outside_0_1")


_SHIMS: Final[dict[type[DetectorBase], type[_SeriesShim]]] = {}


def _series_detector(plugin: DetectorBase) -> _SeriesShim:
    cls = type(plugin)
    shim_cls = _SHIMS.get(cls)
    if shim_cls is None:
        info = cls.plugin_info()
        attributes: dict[str, Any] = {
            "NAME": info.qualified_name,
            "VERSION": info.version,
            "KIND": cls.EVIDENCE,
            "SUMMARY": info.summary,
            "CODECS": frozenset(cls.CODECS),
        }
        shim_cls = type(f"{cls.__name__}Series", (_SeriesShim,), attributes)
        _SHIMS[cls] = shim_cls
    shim = shim_cls(plugin.settings())
    shim.plugin = plugin
    return shim


class _ContractDetector:
    """``godwit_contracts.protocols.Detector`` over a plugin, with ``ROLES`` applied."""

    def __init__(self, plugin: DetectorBase, *, spec: ProbeSpec, code_version: str) -> None:
        self._plugin = plugin
        self._spec = spec
        self._inner = BundleDetector(_series_detector(plugin), spec=spec, code_version=code_version)

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def version(self) -> Version:
        return self._inner.version

    def detect(
        self,
        *,
        current: SketchBundle,
        baseline: SketchBundle | None,
        profiles: Sequence[ColumnProfile],
        seed: int,
    ) -> tuple[Candidate, ...]:
        roles = self._plugin.ROLES
        if roles:
            current = self._only(current, profiles, roles)
            if baseline is not None:
                baseline = self._only(baseline, profiles, roles)
        return self._inner.detect(current=current, baseline=baseline, profiles=(), seed=seed)

    def _only(
        self,
        bundle: SketchBundle,
        profiles: Sequence[ColumnProfile],
        roles: frozenset[ColumnRole],
    ) -> SketchBundle:
        # Column names are SCHEMA_NAME; comparing two of them for equality discloses
        # nothing and copies nothing out.
        wanted = {canonical_column(p.ref.column.reveal()) for p in profiles if p.role in roles}
        kept: Mapping[str, Any] = {
            name: envelope
            for name, envelope in bundle.sketches.items()
            if _columns_of(self._spec, name)
            and all(column in wanted for column in _columns_of(self._spec, name))
        }
        return bundle.model_copy(update={"sketches": dict(kept)})


def _columns_of(spec: ProbeSpec, sketch_name: str) -> tuple[str, ...]:
    context = ProbeContext.from_spec(spec, sketch_name)
    return tuple(canonical_column(column.reveal()) for column in context.columns)


def _detector_problems(cls: type[DetectorBase], info: PluginInfo) -> list[str]:
    del info
    problems = require_class_vars(cls, _DECLARATIONS)
    if problems:
        return problems
    declared: dict[str, object] = dict(vars(cls))
    for klass in cls.__mro__:
        for key, value in vars(klass).items():
            declared.setdefault(key, value)
    if not isinstance(declared["EVIDENCE"], EvidenceKind):
        problems.append("EVIDENCE must be a godwit_contracts.EvidenceKind")
    codecs = declared["CODECS"]
    if not isinstance(codecs, frozenset) or not codecs:
        problems.append("CODECS must be a non-empty frozenset of codec names")
    else:
        unknown = sorted(str(codec) for codec in codecs if codec not in SKETCH_REGISTRY)
        if unknown:
            problems.append(
                f"CODECS names {unknown}, which no registered sketch writes; "
                "register the sketch plugin first"
            )
    tests = declared["TESTS_PER_SKETCH"]
    if not isinstance(tests, int) or isinstance(tests, bool) or tests < 1:
        problems.append("TESTS_PER_SKETCH must be a positive integer")
    support = declared["MIN_SUPPORT"]
    if not isinstance(support, int) or isinstance(support, bool) or support < 1:
        problems.append("MIN_SUPPORT must be a positive integer")
    alpha = declared["ALPHA"]
    if not isinstance(alpha, float) or not 0.0 < alpha < 1.0:
        problems.append("ALPHA must be a float strictly between 0 and 1")
    roles = declared["ROLES"]
    if not isinstance(roles, frozenset) or not all(isinstance(r, ColumnRole) for r in roles):
        problems.append("ROLES must be a frozenset of godwit_contracts.ColumnRole members")
    return problems


def detector[D: DetectorBase](
    *,
    name: str,
    namespace: str,
    version: str,
    summary: str = "",
    requires_sdk: str = DEFAULT_REQUIREMENT,
    capabilities: Capabilities | None = None,
    limits: ResourceLimits | None = None,
) -> Callable[[type[D]], type[D]]:
    """Register a :class:`DetectorBase` subclass as a detector plugin."""

    return decorator_for(
        PluginKind.DETECTOR,
        DetectorBase,
        _detector_problems,
        name=name,
        namespace=namespace,
        version=version,
        summary=summary,
        requires_sdk=requires_sdk,
        capabilities=capabilities,
        limits=limits,
    )
