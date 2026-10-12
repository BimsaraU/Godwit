"""Every error the SDK raises, and the one place a plugin's own exception is defused.

A plugin's exception is the easiest leak a plugin author can write without noticing:
``raise ValueError(f"bad row {row}")`` puts a customer row into whatever logs the
traceback. So nothing a plugin raises crosses the SDK boundary as itself. The base
classes catch it and raise :class:`PluginFailedError`, whose message carries the
plugin's name, the exception's *type* name and a fixed classification -- never its text.
The text survives as ``Tainted[str]`` (``DRIVER_EXCEPTION``, so ``DATA_VALUE``) on
:attr:`PluginFailedError.original`, for code inside the perimeter with a reason to look.

Messages here name plugins, capabilities, class attributes and methods. Those are the
plugin author's identifiers, never values read from customer data.
"""

from __future__ import annotations

from collections.abc import Sequence

from godwit_contracts.taint import Tainted

__all__ = [
    "CapabilityViolationError",
    "IncompatiblePluginError",
    "PluginFailedError",
    "PluginRejectedError",
    "ProbeRefusedError",
    "ResourceLimitError",
    "SdkError",
]


class SdkError(Exception):
    """Base for every error the SDK raises."""


class PluginRejectedError(SdkError):
    """A plugin failed registration. ``problems`` lists every reason, not just the first.

    Registration is where a plugin is judged: a non-conformant plugin must fail when it
    is loaded, on the author's machine, rather than in production inside a bank.
    """

    def __init__(self, plugin: str, problems: Sequence[str]) -> None:
        self.plugin = plugin
        self.problems = tuple(problems)
        listing = "\n".join(f"  - {problem}" for problem in self.problems)
        super().__init__(f"plugin {plugin} was rejected at registration:\n{listing}")


class IncompatiblePluginError(SdkError):
    """A plugin targets a version of the SDK this core is not."""


class CapabilityViolationError(SdkError):
    """A plugin did something it did not declare: network, filesystem, subprocess, threads.

    Raised even if the plugin caught the first refusal and carried on: a violation is
    recorded when it happens and re-raised when the plugin call returns.
    """


class ResourceLimitError(SdkError):
    """A plugin exceeded a declared resource ceiling (bytes handed over, seconds, memory)."""


class ProbeRefusedError(SdkError):
    """A source probe was refused for a reason other than budget.

    ``reason`` is the probe planner's refusal code (``blind_column``, ``unclassified``,
    ``unsupported_probe``...). Budget refusals raise the contract's
    ``BudgetExceededError`` instead, as ``SourceAdapter`` law 4 requires.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"probe refused: {reason}")


class PluginFailedError(SdkError):
    """A plugin raised. Its message is withheld; see the module docstring."""

    def __init__(
        self,
        plugin: str,
        *,
        stage: str,
        error_type: str,
        classification: str,
        original: Tainted[str] | None,
    ) -> None:
        self.plugin = plugin
        self.stage = stage
        self.error_type = error_type
        self.classification = classification
        self.original = original
        super().__init__(
            f"plugin {plugin} failed in {stage}: {error_type} classified as "
            f"{classification}; message withheld"
        )
