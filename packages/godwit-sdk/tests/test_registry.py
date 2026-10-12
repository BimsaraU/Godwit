"""Discovery and registration: entry points, namespacing, version compatibility."""

from __future__ import annotations

from importlib.metadata import EntryPoint

import pytest
from _sdk_registry_plugins import AcmeMemory, GlobexMemory
from _sdk_support import MemorySource
from godwit_sdk import (
    ENTRY_POINT_GROUP,
    IncompatiblePluginError,
    PluginKind,
    PluginRegistry,
    PluginRejectedError,
    check_compatible,
    discover,
    source,
)


def _entry(name: str, target: str) -> EntryPoint:
    return EntryPoint(name=name, value=target, group=ENTRY_POINT_GROUP)


def test_the_reference_plugins_are_discovered_from_installed_entry_points() -> None:
    registry = PluginRegistry()
    report = discover(registry)
    names = {info.qualified_name for info in report.loaded}
    assert {"examples.rest-orders", "examples.bloom", "examples.benford"} <= names
    assert registry.get(PluginKind.DETECTOR, "examples.benford").__name__ == "BenfordDetector"


def test_namespaces_keep_two_publishers_plugins_apart() -> None:
    registry = PluginRegistry()
    registry.register(AcmeMemory)
    registry.register(GlobexMemory)
    assert [p.plugin_info().qualified_name for p in registry.of_kind(PluginKind.SOURCE)] == [
        "acme.memory",
        "globex.memory",
    ]


def test_a_second_plugin_under_a_taken_name_is_refused() -> None:
    @source(name="memory", namespace="acme", version="9.9.9")
    class Impostor(MemorySource):
        pass

    registry = PluginRegistry()
    registry.register(AcmeMemory)
    with pytest.raises(PluginRejectedError, match="already registered under this name"):
        registry.register(Impostor)


def test_an_unknown_name_lists_what_is_registered() -> None:
    registry = PluginRegistry()
    registry.register(AcmeMemory)
    with pytest.raises(KeyError, match=r"acme\.memory"):
        registry.get(PluginKind.SOURCE, "acme.mongodb")


def test_discovery_reports_a_bad_entry_point_and_loads_the_rest() -> None:
    registry = PluginRegistry()
    report = discover(
        registry,
        entries=[
            _entry("acme.memory", "_sdk_registry_plugins:AcmeMemory"),
            _entry("acme.wrong-name", "_sdk_registry_plugins:GlobexMemory"),
            _entry("acme.missing", "no_such_module_anywhere:Thing"),
            _entry("acme.not-a-plugin", "pathlib:Path"),
        ],
    )
    assert [info.qualified_name for info in report.loaded] == ["acme.memory"]
    failures = dict(report.failed)
    assert "they must match" in failures["acme.wrong-name"]
    assert "importing it raised ModuleNotFoundError" in failures["acme.missing"]
    assert "does not name a godwit_sdk plugin class" in failures["acme.not-a-plugin"]


def test_strict_discovery_raises_the_first_failure() -> None:
    with pytest.raises(PluginRejectedError, match="they must match"):
        discover(
            PluginRegistry(),
            entries=[_entry("acme.wrong-name", "_sdk_registry_plugins:GlobexMemory")],
            strict=True,
        )


def test_a_plugin_targeting_an_incompatible_core_fails_clearly() -> None:
    info = AcmeMemory.plugin_info()
    with pytest.raises(IncompatiblePluginError) as error:
        check_compatible(info, sdk_version="1.0.0")
    message = str(error.value)
    assert "acme.memory 1.2.3 requires godwit-sdk ~=0.1.0" in message
    assert "this core runs godwit-sdk 1.0.0" in message


def test_the_plugin_info_says_what_an_installer_needs_to_know() -> None:
    from godwit_sdk.examples.rest_source import RestOrdersSource

    info = RestOrdersSource.plugin_info()
    assert info.capabilities.describe() == ("network: orders.api.example.com",)
    assert info.lineage_version == 1_000_000


def test_an_undecorated_class_is_not_a_plugin() -> None:
    with pytest.raises(TypeError, match="not a registered plugin"):
        MemorySource.plugin_info()
