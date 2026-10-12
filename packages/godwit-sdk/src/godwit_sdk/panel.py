"""``@panel``: a custom Vision Board panel. Control plane. Receives only gated data.

A panel renders something a person will look at, which makes everything it shows an
egress. So a panel's input is a :class:`~godwit_contracts.SafePayload` and nothing else:
a bag of scalars the gate (``godwit-guard``) has already cleared for
``Destination.UI``, with the egress record written before the payload existed. A panel
cannot be handed a ``Tainted`` value, a pattern, a row or a store handle, because its
one method does not accept them -- registration checks the signature.

The base checks the other direction too. :meth:`PanelBase.view` validates what
``render`` returns: every string in the :class:`PanelView` must be the panel's own
``TITLE``, one of its declared ``LABELS``, or a value that was in the payload. A panel
therefore cannot add text that did not come through the gate -- not a value it read
from a file, not one it remembered from an earlier payload.

The Vision Board server (A16) reads registered panels from the registry
(``PluginRegistry.of_kind(PluginKind.PANEL)``), clears a payload naming ``FIELDS``, and
calls :meth:`PanelBase.view`.
"""

from __future__ import annotations

import abc
import inspect
import re
from collections.abc import Callable
from typing import ClassVar, Final, Literal

from godwit_contracts.common import GodwitModel
from godwit_contracts.safe import SafePayload, SafeScalar

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

__all__ = ["PanelBase", "PanelSeries", "PanelView", "panel"]

_FIELD: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]*(\.[a-z0-9_]+)*\Z")
"""The gate's own field-key rule; a panel cannot ask for a field the gate would refuse."""


class PanelSeries(GodwitModel):
    """One labelled series of cleared scalars."""

    label: str
    values: tuple[SafeScalar, ...]


class PanelView(GodwitModel):
    """What a panel renders: a title, a chart kind and its series. The UI draws it."""

    title: str
    chart: Literal["stat", "bar", "line", "table"]
    series: tuple[PanelSeries, ...] = ()


class PanelBase(PluginBase, abc.ABC):
    """Base class for ``@panel`` plugins.

    Declare ``TITLE``, ``FIELDS`` (the payload fields it reads) and optionally ``LABELS``
    (series labels it may use). Implement :meth:`render`.
    """

    SDK_METHODS = ("view",)

    TITLE: ClassVar[str]
    FIELDS: ClassVar[tuple[str, ...]]
    LABELS: ClassVar[tuple[str, ...]] = ()

    @abc.abstractmethod
    def render(self, payload: SafePayload) -> PanelView:
        """Turn one cleared payload into a view. ``payload.fields`` holds ``FIELDS``."""

    def view(self, payload: SafePayload) -> PanelView:
        """Render ``payload`` and check that the view carries nothing it did not."""
        qualified = self.plugin_info().qualified_name

        def bad(classification: str) -> PluginFailedError:
            return PluginFailedError(
                qualified,
                stage="render",
                error_type="PanelView",
                classification=classification,
                original=None,
            )

        fields = payload.fields
        if any(name not in fields for name in self.FIELDS):
            raise bad("payload_lacks_declared_fields")
        result = self.runner.call("render", lambda: self.render(payload))
        if not isinstance(result, PanelView):
            raise bad("render_did_not_return_a_panel_view")
        allowed = {self.TITLE, *self.LABELS}
        allowed |= {value for value in fields.values() if isinstance(value, str)}
        texts = [result.title, *(s.label for s in result.series)]
        texts += [v for s in result.series for v in s.values if isinstance(v, str)]
        if any(text not in allowed for text in texts):
            raise bad("view_contains_text_that_did_not_come_through_the_gate")
        payload_values = set(fields.values())
        if any(v not in payload_values for s in result.series for v in s.values):
            raise bad("view_contains_a_value_that_is_not_in_the_payload")
        return result


def _render_problems(cls: type[PanelBase]) -> list[str]:
    problems: list[str] = []
    try:
        signature = inspect.signature(cls.render, eval_str=True)
    except (NameError, TypeError, ValueError):
        return ["render() annotations must be resolvable"]
    params = [p for p in signature.parameters.values() if p.name != "self"]
    if len(params) != 1 or params[0].annotation is not SafePayload:
        problems.append(
            "render() must take exactly one parameter, annotated SafePayload: a panel "
            "receives only what the gate cleared"
        )
    return problems


def _panel_problems(cls: type[PanelBase], info: PluginInfo) -> list[str]:
    del info
    problems = require_class_vars(cls, ("TITLE", "FIELDS"))
    if problems:
        return problems
    title: object = cls.TITLE
    fields: object = cls.FIELDS
    labels: object = cls.LABELS
    if not isinstance(title, str) or not title:
        problems.append("TITLE must be a non-empty string")
    if (
        not isinstance(fields, tuple)
        or not fields
        or not all(isinstance(f, str) and _FIELD.match(f) for f in fields)
    ):
        problems.append(
            "FIELDS must be a non-empty tuple of gate field keys (lowercase, digits, '_', dotted)"
        )
    if not isinstance(labels, tuple) or not all(isinstance(x, str) for x in labels):
        problems.append("LABELS must be a tuple of strings")
    problems.extend(_render_problems(cls))
    return problems


def panel[P: PanelBase](
    *,
    name: str,
    namespace: str,
    version: str,
    summary: str = "",
    requires_sdk: str = DEFAULT_REQUIREMENT,
    capabilities: Capabilities | None = None,
    limits: ResourceLimits | None = None,
) -> Callable[[type[P]], type[P]]:
    """Register a :class:`PanelBase` subclass as a Vision Board panel."""

    return decorator_for(
        PluginKind.PANEL,
        PanelBase,
        _panel_problems,
        name=name,
        namespace=namespace,
        version=version,
        summary=summary,
        requires_sdk=requires_sdk,
        capabilities=capabilities,
        limits=limits,
    )
