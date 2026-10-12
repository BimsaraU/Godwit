"""What every plugin has in common: an identity, a declaration, and judgement at registration.

A plugin is a class, decorated by one of ``@source``, ``@sketch``, ``@detector``,
``@feature``, ``@context`` or ``@panel``. The decorator *is* registration: it checks the
class against everything this module and the kind's own module require, collects every
problem it finds, and raises :class:`~godwit_sdk.errors.PluginRejectedError` listing all
of them -- so a non-conformant plugin fails on its author's machine the moment it is
imported, not in production. A class that passes is stamped with a :class:`PluginInfo`
and can be added to a :class:`~godwit_sdk.registry.PluginRegistry`.

NAMES
-----
A plugin is ``<namespace>.<name>``: lowercase letters, digits, ``-`` and ``_``. The
namespace is the publisher (``acme``), the name is the plugin (``mongodb``). The
namespaces ``godwit`` and ``core`` are reserved for the project itself. A sketch's codec
must start with ``<namespace>-`` so that two publishers can never write payloads that
claim the same codec.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar, Final

from godwit_detect import lineage_version
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from godwit_sdk._version import __version__
from godwit_sdk.capabilities import Capabilities, PluginRunner, ResourceLimits
from godwit_sdk.errors import IncompatiblePluginError, PluginRejectedError
from godwit_sdk.log import PluginLogger

__all__ = [
    "DEFAULT_REQUIREMENT",
    "RESERVED_NAMESPACES",
    "PluginBase",
    "PluginInfo",
    "PluginKind",
    "TrustCategory",
    "check_compatible",
]

DEFAULT_REQUIREMENT: Final[str] = f"~={__version__}"
"""What a plugin targets when it does not say: this SDK's minor series."""

RESERVED_NAMESPACES: Final[frozenset[str]] = frozenset({"godwit", "core"})

_NAME: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*\Z")
_NAME_MAX: Final[int] = 48
_SEMVER: Final[re.Pattern[str]] = re.compile(r"\A(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
_SUMMARY_MAX: Final[int] = 200


class PluginKind(StrEnum):
    """The six extension points."""

    SOURCE = "source"
    SKETCH = "sketch"
    DETECTOR = "detector"
    FEATURE = "feature"
    CONTEXT = "context"
    PANEL = "panel"


class TrustCategory(StrEnum):
    """Where a plugin should run. See :mod:`godwit_sdk.capabilities` for the reasoning."""

    IN_PROCESS = "in_process"
    """Pure computation, no declared capability. Reviewed code may run in-process."""

    ISOLATE = "isolate"
    """Reads customer rows or declares a capability. Unreviewed code needs its own process."""


@dataclass(frozen=True, slots=True)
class PluginInfo:
    """A plugin's declaration, as its decorator recorded it. Contains no customer data."""

    kind: PluginKind
    namespace: str
    name: str
    version: str
    requires_sdk: str
    summary: str
    capabilities: Capabilities
    limits: ResourceLimits

    @property
    def qualified_name(self) -> str:
        """``<namespace>.<name>``: the registry key, the entry-point name, the log name."""
        return f"{self.namespace}.{self.name}"

    @property
    def lineage_version(self) -> int:
        """The plugin version encoded as ``Lineage.detector_version`` holds it."""
        return lineage_version(self.version)

    @property
    def trust_category(self) -> TrustCategory:
        """Which of the two categories this plugin falls into, stated plainly."""
        if self.kind is PluginKind.SOURCE or self.capabilities.declared:
            return TrustCategory.ISOLATE
        return TrustCategory.IN_PROCESS


def check_compatible(info: PluginInfo, *, sdk_version: str = __version__) -> None:
    """Raise :class:`IncompatiblePluginError` unless ``info`` accepts ``sdk_version``."""
    try:
        wanted = SpecifierSet(info.requires_sdk)
    except InvalidSpecifier:
        raise IncompatiblePluginError(
            f"plugin {info.qualified_name} {info.version} declares requires_sdk="
            f"{info.requires_sdk!r}, which is not a version specifier"
        ) from None
    if not wanted.contains(Version(sdk_version), prereleases=True):
        raise IncompatiblePluginError(
            f"plugin {info.qualified_name} {info.version} requires godwit-sdk "
            f"{info.requires_sdk}; this core runs godwit-sdk {sdk_version}. Install a "
            f"release of the plugin built for {sdk_version}, or a core it supports."
        )


class PluginBase:
    """The part every plugin base class shares: identity, logger, runner.

    ``SDK_METHODS`` names the methods the SDK implements on the plugin's behalf --
    budget enforcement, tainting, sanitising. A plugin that overrides one is rejected at
    registration, because overriding it is exactly how a plugin gets subtly wrong.
    """

    __godwit_plugin__: ClassVar[PluginInfo]
    SDK_METHODS: ClassVar[tuple[str, ...]] = ()

    @classmethod
    def plugin_info(cls) -> PluginInfo:
        """This plugin's declaration. Raises if the class was never decorated."""
        info = cls.__dict__.get("__godwit_plugin__")
        if not isinstance(info, PluginInfo):
            raise TypeError(
                f"{cls.__name__} is not a registered plugin; decorate it with the "
                "decorator for its kind (@source, @sketch, @detector, ...)"
            )
        return info

    @property
    def log(self) -> PluginLogger:
        """The only logger a plugin gets. See :mod:`godwit_sdk.log`."""
        return PluginLogger(self.plugin_info().qualified_name)

    @property
    def runner(self) -> PluginRunner:
        """Runs this plugin's code under its declared capabilities."""
        info = self.plugin_info()
        return PluginRunner(info.qualified_name, info.capabilities, info.limits)


def _overridden(cls: type, base: type, method: str) -> bool:
    for klass in cls.__mro__:
        if klass is base:
            return False
        if method in klass.__dict__:
            return True
    return False


def _common_problems(
    cls: object,
    base: type[PluginBase],
    kind: PluginKind,
    *,
    name: object,
    namespace: object,
    version: object,
    summary: object,
    capabilities: object,
    limits: object,
) -> list[str]:
    problems: list[str] = []
    is_plugin_class = isinstance(cls, type) and issubclass(cls, base)
    if not is_plugin_class:
        problems.append(f"must subclass godwit_sdk.{base.__name__}")
    elif "__godwit_plugin__" in cls.__dict__:
        problems.append("is decorated twice")
    for label, value in (("name", name), ("namespace", namespace)):
        if not isinstance(value, str) or len(value) > _NAME_MAX or not _NAME.match(value):
            problems.append(
                f"{label} {value!r} must be lowercase letters and digits joined by '-' or "
                f"'_', at most {_NAME_MAX} characters"
            )
    if namespace in RESERVED_NAMESPACES:
        problems.append(f"namespace {namespace!r} is reserved for the Godwit project")
    if not isinstance(version, str) or not _SEMVER.match(version):
        problems.append(f"version {version!r} must be MAJOR.MINOR.PATCH")
    else:
        try:
            lineage_version(version)
        except ValueError:
            problems.append(f"version {version!r} must keep MINOR and PATCH below 1000")
    if not isinstance(summary, str) or len(summary) > _SUMMARY_MAX:
        problems.append(f"summary must be a string of at most {_SUMMARY_MAX} characters")
    if not isinstance(capabilities, Capabilities):
        problems.append("capabilities must be a godwit_sdk.Capabilities")
    if not isinstance(limits, ResourceLimits):
        problems.append("limits must be a godwit_sdk.ResourceLimits")
    if isinstance(cls, type) and is_plugin_class:
        for method in base.SDK_METHODS:
            if _overridden(cls, base, method):
                problems.append(
                    f"overrides {method}(), which the SDK implements for every "
                    f"{kind.value}; implement the abstract methods instead"
                )
        if inspect.isabstract(cls):
            missing = ", ".join(sorted(getattr(cls, "__abstractmethods__", ())))
            problems.append(f"does not implement {missing}")
    return problems


def require_class_vars(cls: type, names: tuple[str, ...]) -> list[str]:
    """A problem for every class attribute in ``names`` the plugin left undeclared."""
    return [f"must declare {name}" for name in names if getattr(cls, name, None) is None]


type KindChecks = Callable[[type[Any], PluginInfo], list[str]]
"""A kind's own registration checks. Runs only once the common checks have passed."""


def decorator_for[P: PluginBase](
    kind: PluginKind,
    base: type[PluginBase],
    checks: KindChecks | None,
    *,
    name: str,
    namespace: str,
    version: str,
    summary: str,
    requires_sdk: str,
    capabilities: Capabilities | None,
    limits: ResourceLimits | None,
) -> Callable[[type[P]], type[P]]:
    """Build a kind's decorator: common checks, then the kind's, then the stamp.

    Every problem found is collected and raised together in one
    :class:`~godwit_sdk.errors.PluginRejectedError`. An incompatible ``requires_sdk``
    raises :class:`~godwit_sdk.errors.IncompatiblePluginError` instead, and is checked
    before the kind's checks run any plugin code.
    """
    declared_capabilities = capabilities if capabilities is not None else Capabilities()
    declared_limits = limits if limits is not None else ResourceLimits()

    def decorate(cls: type[P]) -> type[P]:
        info = PluginInfo(
            kind=kind,
            namespace=namespace,
            name=name,
            version=version,
            requires_sdk=requires_sdk,
            summary=summary,
            capabilities=declared_capabilities,
            limits=declared_limits,
        )
        problems = _common_problems(
            cls,
            base,
            kind,
            name=name,
            namespace=namespace,
            version=version,
            summary=summary,
            capabilities=declared_capabilities,
            limits=declared_limits,
        )
        if problems:
            raise PluginRejectedError(info.qualified_name, problems)
        check_compatible(info)
        problems = checks(cls, info) if checks is not None else []
        if problems:
            raise PluginRejectedError(info.qualified_name, problems)
        cls.__godwit_plugin__ = info
        return cls

    return decorate
