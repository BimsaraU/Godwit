"""Discovery and registration: ``pip install godwit-source-mongodb`` and the adapter exists.

A plugin package advertises its plugins as entry points in the group
:data:`ENTRY_POINT_GROUP`, one per plugin, named by the plugin's qualified name::

    [project.entry-points."godwit.plugins"]
    "acme.mongodb" = "godwit_source_mongodb:MongoSource"

:func:`discover` loads every such entry point, checks that what it found is a decorated
plugin whose qualified name matches the entry point's name, checks its ``requires_sdk``
against this core, and registers it. A plugin that fails any of those is reported in the
:class:`DiscoveryReport` with the reason, and the rest still load -- one broken plugin
must not take a deployment down. Pass ``strict=True`` to turn the first failure into an
exception instead, which is what CI should do.

Nothing here runs plugin code beyond importing its module. Importing it runs its
decorators, which is where a non-conformant plugin is rejected.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib.metadata import EntryPoint, entry_points
from typing import Final

from godwit_sdk.errors import PluginRejectedError, SdkError
from godwit_sdk.plugin import PluginBase, PluginInfo, PluginKind, check_compatible

__all__ = ["ENTRY_POINT_GROUP", "DiscoveryReport", "PluginRegistry", "discover"]

ENTRY_POINT_GROUP: Final[str] = "godwit.plugins"


class PluginRegistry:
    """Registered plugins, by kind and qualified name. Not thread-safe; build it at startup."""

    def __init__(self) -> None:
        self._plugins: dict[tuple[PluginKind, str], type[PluginBase]] = {}

    def register(self, plugin: type[PluginBase]) -> PluginInfo:
        """Add a decorated plugin class. Raises on an undecorated class, a name clash or
        an incompatible ``requires_sdk``."""
        if not isinstance(plugin, type) or not issubclass(plugin, PluginBase):
            raise PluginRejectedError(repr(plugin), ["is not a godwit_sdk plugin class"])
        info = plugin.plugin_info()
        check_compatible(info)
        key = (info.kind, info.qualified_name)
        existing = self._plugins.get(key)
        if existing is not None and existing is not plugin:
            raise PluginRejectedError(
                info.qualified_name,
                [f"another {info.kind.value} plugin is already registered under this name"],
            )
        self._plugins[key] = plugin
        return info

    def get(self, kind: PluginKind, qualified_name: str) -> type[PluginBase]:
        """The plugin registered under ``qualified_name``, or ``KeyError`` naming what exists."""
        try:
            return self._plugins[(kind, qualified_name)]
        except KeyError:
            known = sorted(name for k, name in self._plugins if k is kind)
            raise KeyError(
                f"no {kind.value} plugin named {qualified_name!r}; registered: {known}"
            ) from None

    def of_kind(self, kind: PluginKind) -> tuple[type[PluginBase], ...]:
        """Every plugin of one kind, sorted by qualified name."""
        return tuple(self._plugins[key] for key in sorted(self._plugins) if key[0] is kind)

    def infos(self) -> tuple[PluginInfo, ...]:
        """Every registered plugin's declaration, sorted."""
        return tuple(self._plugins[key].plugin_info() for key in sorted(self._plugins))


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    """What :func:`discover` loaded, and what it refused with the reason."""

    loaded: tuple[PluginInfo, ...] = ()
    failed: tuple[tuple[str, str], ...] = field(default=())
    """``(entry point name, reason)``. The reason is ours: no plugin text is quoted."""


def _load(entry: EntryPoint) -> type[PluginBase]:
    try:
        loaded = entry.load()
    except SdkError:
        raise
    except Exception as exc:
        raise PluginRejectedError(
            entry.name, [f"importing it raised {type(exc).__name__}"]
        ) from None
    if not isinstance(loaded, type) or not issubclass(loaded, PluginBase):
        raise PluginRejectedError(
            entry.name, ["the entry point does not name a godwit_sdk plugin class"]
        )
    info = loaded.plugin_info()
    if info.qualified_name != entry.name:
        raise PluginRejectedError(
            entry.name,
            [
                (
                    f"the entry point is named {entry.name!r} but the plugin declares "
                    f"{info.qualified_name!r}; they must match"
                )
            ],
        )
    return loaded


def discover(
    registry: PluginRegistry,
    *,
    entries: Iterable[EntryPoint] | None = None,
    strict: bool = False,
) -> DiscoveryReport:
    """Load and register every installed plugin. ``entries`` overrides the installed set."""
    found = entries if entries is not None else entry_points(group=ENTRY_POINT_GROUP)
    loaded: list[PluginInfo] = []
    failed: list[tuple[str, str]] = []
    for entry in sorted(found, key=lambda item: item.name):
        try:
            loaded.append(registry.register(_load(entry)))
        except (SdkError, TypeError) as error:
            if strict:
                raise
            failed.append((entry.name, str(error)))
    return DiscoveryReport(loaded=tuple(loaded), failed=tuple(failed))
