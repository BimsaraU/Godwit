"""The egress audit the harness runs on its own output.

Replay is the adversary of every other package, including itself. Everything this package
writes to a file, prints to a terminal or hands to a reviewer is an egress: a verdict
report is a document a human reads, which is exactly what invariant 2 is about.

THE CONTROL, AND THE BACKSTOP
-----------------------------
The control is the typed taint. :func:`audit_object` walks the object graph of whatever is
about to be written and finds every ``Tainted`` in it, by type, before anything is
rendered. It does not look at the characters; it looks at the declarations. That is what
catches an Iceberg manifest bound, a Count-Min heavy hitter and a segment predicate --
none of which a scanner would recognise.

:func:`scan_text` is the backstop, and it is only ever a backstop. It searches rendered
output for the strings ``tests/golden/pii_torture/expected_leaks.json`` says must never
appear. **If the string scan is the only thing that caught a value, that is a bug in the
taint typing and must be reported as one**, per ``EgressGate`` law 6 -- so
:func:`audit_egress` records which arm fired.

A note on what is *not* a finding: a ``Candidate`` legitimately carries DATA_VALUE segment
predicates while it travels inside the perimeter. The audit is not run over candidates in
flight. It is run over the artifacts replay writes out, which is a different surface with
a different rule.

THE NEEDLE LIST BELONGS TO ITS OWN DATASET
------------------------------------------
``forbidden_strings`` returns the values from *one* fixture, and those values include the
words ``unknown``, ``general``, ``positive`` and ``negative`` -- because in that fixture they
are column values. Searching an unrelated dataset's report for them flags the sentence
"segment population: unknown" as a leak, which is a false positive and a demonstration of
exactly why a scanner is not the control. So the backstop is applied only to output derived
from the dataset whose values the list came from. Passing one dataset's needles at another
dataset's report is a category error, not extra safety.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from godwit_contracts.common import GodwitModel, NonNegInt
from godwit_contracts.segment import Segment
from godwit_contracts.taint import Sensitivity, Tainted, egress_risk_rank
from pydantic import BaseModel, Field

__all__ = [
    "DEFAULT_MAX_SENSITIVITY",
    "LeakFinding",
    "LeakKind",
    "audit_egress",
    "audit_object",
    "forbidden_strings",
    "render_tainted",
    "scan_text",
    "tainted_fields",
]

DEFAULT_MAX_SENSITIVITY: Final[Sensitivity] = Sensitivity.SCHEMA_NAME
"""The most disclosive class replay output may carry.

SCHEMA_NAME rather than DERIVED_STATISTIC, because a report that cannot say which column
moved is not reviewable by a human, and every dataset the harness loads is a published
benchmark whose column names are public. On a customer dataset this must be tightened,
and the CLI exposes it: see ``--max-sensitivity``.
"""

_POPULATION_REQUIRED: Final[frozenset[Sensitivity]] = frozenset(
    {Sensitivity.DATA_VALUE, Sensitivity.TOKEN}
)
"""Classes for which an unknown population is itself a finding.

``Tainted.is_small_cell`` already treats unknown as small; this makes the unknown case
visible in an audit rather than only in a threshold comparison that never runs.
SCHEMA_NAME and DERIVED_STATISTIC are exempt: a column name has no population, and a count
whose population is unknown is still a count. Flagging those would bury the real findings
under noise, which is its own kind of failure.
"""

_ICEBERG_BOUND_TRUNCATION: Final[int] = 16
"""Iceberg truncates string bounds to sixteen characters.

Which makes a bound a *prefix* of a real value and not one byte less sensitive: sixteen
characters of an email address is still that person. The backstop therefore searches for
prefixes of this length as well as for whole values.
"""


class LeakKind(StrEnum):
    """What kind of rule the output broke."""

    DATA_VALUE_EGRESS = "data_value_egress"
    """A value more disclosive than the configured ceiling reached an output artifact."""

    SMALL_CELL = "small_cell"
    """A statistic whose population is below the small-cell threshold. "Segment X (n=3)
    is anomalous" re-identifies without quoting a value."""

    UNKNOWN_POPULATION = "unknown_population"
    """A reported segment with no population. Unknown must mean unsafe, not large."""

    FORBIDDEN_STRING = "forbidden_string"
    """The backstop fired: a known-sensitive string appeared in rendered output. If this
    fires and DATA_VALUE_EGRESS did not, the taint typing is wrong somewhere."""


class LeakFinding(GodwitModel):
    """One rule broken, named without quoting the offending value.

    ``detail`` is our own description. It never contains the value: that is the thing we
    are trying to stop leaving, and a finding that quotes it has leaked it into the
    findings file.
    """

    kind: LeakKind
    path: str = Field(description="Where in the artifact, as a dotted field path.")
    sensitivity: Sensitivity | None = None
    acquisition: str | None = None
    population: NonNegInt | None = None
    detail: str = ""

    def line(self) -> str:
        """One line, for a terminal."""
        parts = [f"{self.kind.value}", f"at {self.path}"]
        if self.sensitivity is not None:
            parts.append(f"sensitivity={self.sensitivity.value}")
        if self.acquisition is not None:
            parts.append(f"via={self.acquisition}")
        if self.detail:
            parts.append(self.detail)
        return " | ".join(parts)


def tainted_fields(obj: object, *, path: str = "") -> Iterator[tuple[str, Tainted[Any]]]:
    """Every ``Tainted`` reachable from ``obj``, with its dotted path.

    Walks pydantic models, mappings and sequences. ``Tainted`` is itself a model, so it is
    checked first and not descended into -- its ``value`` field is the thing we are
    keeping out of reach.
    """
    if isinstance(obj, Tainted):
        yield (path or "<root>", obj)
        return
    if isinstance(obj, BaseModel):
        for name in type(obj).model_fields:
            yield from tainted_fields(getattr(obj, name), path=f"{path}.{name}" if path else name)
        return
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            yield from tainted_fields(value, path=f"{path}[{key}]")
        return
    if isinstance(obj, str | bytes):
        return
    if isinstance(obj, Sequence):
        for index, value in enumerate(obj):
            yield from tainted_fields(value, path=f"{path}[{index}]")


def _segments(obj: object, *, path: str = "") -> Iterator[tuple[str, Segment]]:
    if isinstance(obj, Segment):
        yield (path or "<root>", obj)
        return
    if isinstance(obj, Tainted):
        return
    if isinstance(obj, BaseModel):
        for name in type(obj).model_fields:
            yield from _segments(getattr(obj, name), path=f"{path}.{name}" if path else name)
        return
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            yield from _segments(value, path=f"{path}[{key}]")
        return
    if isinstance(obj, str | bytes):
        return
    if isinstance(obj, Sequence):
        for index, value in enumerate(obj):
            yield from _segments(value, path=f"{path}[{index}]")


def audit_object(
    artifact: object,
    *,
    small_cell_threshold: int,
    max_sensitivity: Sensitivity = DEFAULT_MAX_SENSITIVITY,
) -> tuple[LeakFinding, ...]:
    """The typed arm. Findings from declarations, before anything is rendered."""
    ceiling = egress_risk_rank(max_sensitivity)
    findings: list[LeakFinding] = []
    for path, value in tainted_fields(artifact):
        if egress_risk_rank(value.sensitivity) > ceiling:
            findings.append(
                LeakFinding(
                    kind=LeakKind.DATA_VALUE_EGRESS,
                    path=path,
                    sensitivity=value.sensitivity,
                    acquisition=value.provenance.acquisition.value,
                    population=value.population,
                    detail=f"ceiling is {max_sensitivity.value}",
                )
            )
        if value.population is None and value.sensitivity in _POPULATION_REQUIRED:
            findings.append(
                LeakFinding(
                    kind=LeakKind.UNKNOWN_POPULATION,
                    path=path,
                    sensitivity=value.sensitivity,
                    acquisition=value.provenance.acquisition.value,
                    detail="a row-derived value with no population; unknown means unsafe",
                )
            )
        if value.population is not None and value.population < small_cell_threshold:
            findings.append(
                LeakFinding(
                    kind=LeakKind.SMALL_CELL,
                    path=path,
                    sensitivity=value.sensitivity,
                    acquisition=value.provenance.acquisition.value,
                    population=value.population,
                    detail=f"population below threshold {small_cell_threshold}",
                )
            )
    for path, segment in _segments(artifact):
        if segment.is_universe:
            continue
        if segment.population is None:
            findings.append(
                LeakFinding(
                    kind=LeakKind.UNKNOWN_POPULATION,
                    path=path,
                    detail="a reported segment with no population; unknown means unsafe",
                )
            )
        elif segment.population < small_cell_threshold:
            findings.append(
                LeakFinding(
                    kind=LeakKind.SMALL_CELL,
                    path=path,
                    population=segment.population,
                    detail=f"segment population below threshold {small_cell_threshold}",
                )
            )
    return tuple(findings)


def scan_text(text: str, forbidden: frozenset[str]) -> tuple[LeakFinding, ...]:
    """The backstop arm. A substring search over rendered output.

    Matches are reported by length and position only. Quoting the match in the finding
    would put the leaked value in the findings file, which is the same leak with an audit
    trail attached.
    """
    findings: list[LeakFinding] = []
    for needle in sorted(forbidden):
        if not needle:
            continue
        index = text.find(needle)
        if index >= 0:
            findings.append(
                LeakFinding(
                    kind=LeakKind.FORBIDDEN_STRING,
                    path=f"rendered[{index}:{index + len(needle)}]",
                    detail=(
                        f"a known-sensitive string of {len(needle)} characters appeared in "
                        "rendered output; if the typed arm did not also fire, the taint "
                        "typing upstream is wrong (EgressGate law 6)"
                    ),
                )
            )
    return tuple(findings)


def audit_egress(
    artifact: object,
    *,
    rendered: str | None = None,
    small_cell_threshold: int,
    forbidden: frozenset[str] = frozenset(),
    max_sensitivity: Sensitivity = DEFAULT_MAX_SENSITIVITY,
) -> tuple[LeakFinding, ...]:
    """Both arms, in order: typed first, string scan second.

    Returns findings sorted by kind then path, so two runs produce identical findings in
    identical order and a diff of two audits is readable.
    """
    findings = list(
        audit_object(
            artifact, small_cell_threshold=small_cell_threshold, max_sensitivity=max_sensitivity
        )
    )
    if rendered is not None and forbidden:
        findings.extend(scan_text(rendered, forbidden))
    return tuple(sorted(findings, key=lambda finding: (finding.kind.value, finding.path)))


def forbidden_strings(golden_dir: Path) -> frozenset[str]:
    """Load the strings ``pii_torture`` says must never appear in any egress artifact.

    Iceberg truncates string bounds to sixteen characters, so a sixteen-character prefix
    of an email address is still that person. Prefixes of length sixteen and above are
    therefore included alongside whole values.
    """
    path = golden_dir / "pii_torture" / "expected_leaks.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    values = [str(item) for item in payload["must_never_appear_in_any_egress"]]
    with_prefixes = set(values)
    with_prefixes.update(
        value[:_ICEBERG_BOUND_TRUNCATION]
        for value in values
        if len(value) > _ICEBERG_BOUND_TRUNCATION
    )
    return frozenset(with_prefixes)


def render_tainted(value: Tainted[Any], *, reveal: bool) -> str:
    """The one place a tainted value is turned into output text.

    ``reveal=True`` is what a deliberately leaky configuration sets. It exists so that the
    harness can prove its own audit catches a leak rather than asserting that it would;
    the audit runs regardless of this flag and fails the run either way.
    """
    return str(value.reveal()) if reveal else value.redacted()
