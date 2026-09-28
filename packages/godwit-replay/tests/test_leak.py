"""The egress audit: the typed arm, the backstop, and why the two are not equals.

The most important test here is the last one. It renders an artifact built from the PII
torture fixture and shows that the typed arm catches every leak path in it -- including the
ones a scanner would never recognise -- while the string scan is only confirmation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from godwit_contracts.common import GodwitModel
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.taint import (
    Acquisition,
    Sensitivity,
    Tainted,
    data_value,
    derived_statistic,
    schema_name,
    token,
)
from godwit_replay.leak import (
    DEFAULT_MAX_SENSITIVITY,
    LeakKind,
    audit_egress,
    audit_object,
    forbidden_strings,
    render_tainted,
    scan_text,
    tainted_fields,
)


class _Artifact(GodwitModel):
    """A stand-in for something replay might publish."""

    title: str = "a report"
    statistic: Tainted[float] | None = None
    column: Tainted[str] | None = None
    disclosed: tuple[Tainted[object], ...] = ()
    segment: Segment | None = None


def _bound(value: str) -> Tainted[object]:
    """An Iceberg manifest bound: advertised as metadata, actually a row value."""
    return data_value(
        value, acquisition=Acquisition.ICEBERG_MANIFEST_BOUNDS, column="customer_email"
    )


def test_the_walk_finds_tainted_values_at_every_depth() -> None:
    artifact = _Artifact(
        statistic=derived_statistic(1.5, population=1000),
        column=schema_name("amount"),
        disclosed=(_bound("someone@example.test"),),
    )
    found = dict(tainted_fields(artifact))
    assert "statistic" in found
    assert "column" in found
    assert "disclosed[0]" in found


def test_a_statistic_and_a_column_name_pass_the_default_ceiling() -> None:
    artifact = _Artifact(
        statistic=derived_statistic(1.5, population=1000), column=schema_name("amount")
    )
    assert audit_object(artifact, small_cell_threshold=20) == ()


def test_a_manifest_bound_is_caught_by_type_not_by_its_contents() -> None:
    """The bound here is a plausible-looking email. No scanner knows it is sensitive.

    The taint does. That is the difference between the control and the backstop.
    """
    artifact = _Artifact(disclosed=(_bound("t.mueller-schmidt@corporate-holdings.example"),))
    findings = audit_object(artifact, small_cell_threshold=20)
    kinds = {finding.kind for finding in findings}
    assert LeakKind.DATA_VALUE_EGRESS in kinds
    assert LeakKind.UNKNOWN_POPULATION in kinds
    assert all("corporate-holdings" not in finding.detail for finding in findings), (
        "a finding that quotes the value has leaked it into the findings file"
    )


def test_a_token_still_needs_a_population() -> None:
    """A stable token is a stable pseudonym; with no population behind it, it is unsafe."""
    artifact = _Artifact(disclosed=(token("tok_abc123"),))
    kinds = {finding.kind for finding in audit_object(artifact, small_cell_threshold=20)}
    assert LeakKind.UNKNOWN_POPULATION in kinds
    assert LeakKind.DATA_VALUE_EGRESS not in kinds, "a token is below the default ceiling"


def test_a_small_cell_is_caught_even_when_no_value_is_quoted() -> None:
    """ "Segment X (n=3) is anomalous" re-identifies without quoting anything."""
    artifact = _Artifact(statistic=derived_statistic(9.9, population=3))
    findings = audit_object(artifact, small_cell_threshold=20)
    assert [finding.kind for finding in findings] == [LeakKind.SMALL_CELL]


def test_a_reported_segment_with_no_population_is_unsafe() -> None:
    segment = Segment(
        predicates=(
            Predicate(
                column=schema_name("country"),
                op=Operator.EQ,
                values=(data_value("PT", acquisition=Acquisition.SEGMENT_PREDICATE),),
            ),
        )
    )
    kinds = {
        finding.kind
        for finding in audit_object(_Artifact(segment=segment), small_cell_threshold=20)
    }
    assert LeakKind.UNKNOWN_POPULATION in kinds
    assert LeakKind.DATA_VALUE_EGRESS in kinds


def test_the_universe_segment_needs_no_population() -> None:
    """ "The whole table" discloses nothing about anybody, so it is not a finding."""
    assert audit_object(_Artifact(segment=Segment()), small_cell_threshold=20) == ()


def test_tightening_the_ceiling_catches_a_column_name() -> None:
    """A column name is a disclosure on its own: ``patient_hiv_status`` says something."""
    artifact = _Artifact(column=schema_name("patient_hiv_status"))
    assert audit_object(artifact, small_cell_threshold=20) == ()
    strict = audit_object(
        artifact, small_cell_threshold=20, max_sensitivity=Sensitivity.DERIVED_STATISTIC
    )
    assert [finding.kind for finding in strict] == [LeakKind.DATA_VALUE_EGRESS]
    assert DEFAULT_MAX_SENSITIVITY is Sensitivity.SCHEMA_NAME


def test_findings_are_ordered_so_two_audits_can_be_diffed() -> None:
    artifact = _Artifact(
        statistic=derived_statistic(1.0, population=2),
        disclosed=(_bound("a@b.test"), _bound("c@d.test")),
    )
    left = audit_egress(artifact, small_cell_threshold=20)
    right = audit_egress(artifact, small_cell_threshold=20)
    assert left == right
    assert [finding.kind.value for finding in left] == sorted(
        finding.kind.value for finding in left
    )


def test_render_tainted_is_the_only_door_and_it_is_shut_by_default() -> None:
    value = _bound("someone@example.test")
    assert render_tainted(value, reveal=False) == value.redacted()
    assert "someone@example.test" not in render_tainted(value, reveal=False)
    assert render_tainted(value, reveal=True) == "someone@example.test"


# -- the backstop, where it actually means something ---------------------------------------


def test_the_needle_list_includes_truncated_prefixes(golden_dir: Path) -> None:
    """Iceberg truncates string bounds to sixteen characters; a prefix is still a person."""
    needles = forbidden_strings(golden_dir)
    raw = json.loads(
        (golden_dir / "pii_torture" / "expected_leaks.json").read_text(encoding="utf-8")
    )["must_never_appear_in_any_egress"]
    long_values = [str(value) for value in raw if len(str(value)) > 16]
    assert long_values
    for value in long_values:
        assert value in needles
        assert value[:16] in needles


def test_the_backstop_reports_a_position_and_a_length_never_the_match(golden_dir: Path) -> None:
    needles = forbidden_strings(golden_dir)
    victim = sorted((needle for needle in needles if len(needle) > 10), key=len)[-1]
    findings = scan_text(f"the model card says {victim} which it should not", needles)
    assert findings
    assert findings[0].kind is LeakKind.FORBIDDEN_STRING
    for finding in findings:
        assert victim not in finding.detail
        assert victim not in finding.path


def test_both_arms_fire_on_a_pii_artifact_and_the_typed_one_is_first(golden_dir: Path) -> None:
    """The whole point, in one test.

    The artifact carries a manifest bound from the PII fixture. The typed arm catches it
    because of how it is declared; the string scan catches it because the value happens to be
    in a list. If only the second had fired, that would be a taint-typing bug -- and this test
    is what distinguishes the two cases rather than treating them as equivalent.
    """
    needles = forbidden_strings(golden_dir)
    victim = sorted((needle for needle in needles if len(needle) > 10), key=len)[-1]
    artifact = _Artifact(disclosed=(_bound(victim),))
    rendered = f"# report\n\n- bound: {render_tainted(artifact.disclosed[0], reveal=True)}\n"
    findings = audit_egress(artifact, rendered=rendered, small_cell_threshold=20, forbidden=needles)
    kinds = {finding.kind for finding in findings}
    assert LeakKind.DATA_VALUE_EGRESS in kinds, "the control must fire"
    assert LeakKind.FORBIDDEN_STRING in kinds, "the backstop confirms it"

    # And with the value redacted, neither arm has anything to say.
    safe = f"# report\n\n- bound: {render_tainted(artifact.disclosed[0], reveal=False)}\n"
    assert scan_text(safe, needles) == ()


def test_the_backstop_alone_would_have_missed_a_leak_no_list_knows_about() -> None:
    """A bound that is not on anybody's list. The typed arm still catches it.

    This is the case that makes "scanning is a backstop" a design statement rather than a
    disclaimer: no needle list can contain a value nobody has seen yet.
    """
    artifact = _Artifact(disclosed=(_bound("a.person.nobody.listed@example.test"),))
    assert scan_text("a.person.nobody.listed@example.test", frozenset()) == ()
    kinds = {finding.kind for finding in audit_object(artifact, small_cell_threshold=20)}
    assert LeakKind.DATA_VALUE_EGRESS in kinds


def test_the_needle_list_refuses_to_load_from_the_wrong_place(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        forbidden_strings(tmp_path)
