"""Schema-name modes, and a measurement of what OPAQUE and DESCRIBED cost."""

from __future__ import annotations

import datetime as _dt
import re
from collections.abc import Callable
from typing import Any

from _guard_support import SCOPE, classify, make_gate, make_vault
from godwit_contracts import ColumnRole, Destination, LogicalType, PiiClass, schema_name
from godwit_guard import (
    DEFAULT_POLICY,
    ClassificationRegistry,
    EgressOptions,
    SchemaNameMode,
    describe,
)

_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    [
        "which",
        "column",
        "holds",
        "the",
        "is",
        "a",
        "an",
        "of",
        "in",
        "on",
        "for",
        "was",
        "were",
        "where",
        "what",
        "did",
        "does",
        "used",
        "someone",
        "says",
        "has",
        "have",
        "happen",
        "person",
        "s",
    ]
)


def test_the_three_modes(at: _dt.datetime) -> None:
    registry = ClassificationRegistry()
    ref = classify(
        registry, "patient_hiv_status", at=at, confirm=PiiClass.HEALTH, role=ColumnRole.CATEGORY
    )
    entry = registry.entry(ref)
    assert entry is not None
    assert describe(entry, SchemaNameMode.FULL, alias=None) == "patient_hiv_status"
    described = describe(entry, SchemaNameMode.DESCRIBED, alias="COLUMN_1")
    assert described == "COLUMN_1: health attribute (categorical attribute, string)"
    assert describe(entry, SchemaNameMode.OPAQUE, alias="COLUMN_1") == (
        "COLUMN_1: categorical attribute, string"
    )
    for word in ("patient", "hiv"):
        assert word not in described


def test_described_is_the_default_and_aliases_restore_in_the_ui(at: _dt.datetime) -> None:
    registry = ClassificationRegistry()
    classify(
        registry,
        "customer_ssn",
        at=at,
        confirm=PiiClass.DIRECT_IDENTIFIER,
        role=ColumnRole.ENTITY_ID,
    )
    registry.register_table("src_pii", "customers")
    vault = make_vault(at)
    gate, _, _ = make_gate(registry, at=at, vault=vault)
    payload, _ = gate.clear(
        fields={
            "col": schema_name("customer_ssn", source_id="src_pii", table="customers"),
            "tbl": schema_name("customers", source_id="src_pii"),
        },
        destination=Destination.LLM_PROVIDER,
        purpose="explain",
        policy=DEFAULT_POLICY,
        guardrails=(),
        actor="llm",
        occurred_at=at,
        options=EgressOptions(token_scope=SCOPE),
    )
    assert payload.fields["col"] == "COLUMN_1: government identifier (entity identifier, string)"
    assert payload.fields["tbl"] == "TABLE_1"
    restored = vault.restore(
        str(payload.fields["col"]), scope_id=SCOPE, roles=frozenset({"investigator"}), at=at
    )
    assert restored.reveal().startswith("customer_ssn:")

    opaque, _, _ = make_gate(registry, at=at, schema_mode=SchemaNameMode.OPAQUE)
    payload, _ = opaque.clear(
        fields={"col": schema_name("customer_ssn", source_id="src_pii", table="customers")},
        destination=Destination.LLM_PROVIDER,
        purpose="explain",
        policy=DEFAULT_POLICY,
        guardrails=(),
        actor="llm",
        occurred_at=at,
        options=EgressOptions(token_scope=SCOPE),
    )
    assert payload.fields["col"] == "COLUMN_1: entity identifier, string"


def test_full_names_need_a_destination_that_permits_them(at: _dt.datetime) -> None:
    registry = ClassificationRegistry()
    classify(registry, "customer_ssn", at=at, confirm=PiiClass.DIRECT_IDENTIFIER)
    gate, _, _ = make_gate(registry, at=at, schema_mode=SchemaNameMode.FULL)
    payload, _ = gate.clear(
        fields={"col": schema_name("customer_ssn", source_id="src_pii", table="customers")},
        destination=Destination.LLM_PROVIDER,
        purpose="explain",
        policy=DEFAULT_POLICY,
        guardrails=(),
        actor="llm",
        occurred_at=at,
        options=EgressOptions(token_scope=SCOPE),
    )
    assert "customer_ssn" not in str(payload.fields["col"])


# --------------------------------------------------------------------------------------
# Capability loss, measured on a real task
# --------------------------------------------------------------------------------------


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall(text.casefold().replace("_", " "))) - _STOP


def _grounding_accuracy(bench: dict[str, Any], render: Callable[[str, str, str], str]) -> float:
    knowledge: dict[str, list[str]] = bench["knowledge"]
    correct = 0
    for q in bench["questions"]:
        # The table is given, so words naming it are context, not a pointer to a column.
        asked = _tokens(q["question"]) - _tokens(q["table"]) - {q["table"].rstrip("s")}
        expanded = asked | {w for t in asked for w in knowledge.get(t, [])}
        columns = bench["tables"][q["table"]]
        scores = {
            c["name"]: len(expanded & _tokens(render(c["name"], c["role"], c["logical_type"])))
            for c in columns
        }
        best = max(scores.values())
        winners = [name for name, score in scores.items() if score == best]
        correct += best > 0 and winners == [q["answer"]]
    return correct / len(bench["questions"])


def _renderer(mode: SchemaNameMode, at: _dt.datetime) -> Callable[[str, str, str], str]:
    def render(name: str, role: str, logical: str) -> str:
        registry = ClassificationRegistry()
        ref = classify(
            registry,
            name,
            LogicalType(logical),
            at=at,
            confirm=PiiClass.NONE,
            role=ColumnRole(role),
        )
        entry = registry.entry(ref)
        assert entry is not None
        if mode is SchemaNameMode.FULL:
            # The literal name in place of the alias. A reader of the name infers the
            # concept for itself, so FULL carries everything DESCRIBED does and more.
            return describe(entry, SchemaNameMode.DESCRIBED, alias=name)
        return describe(entry, mode, alias="COLUMN_1")

    return render


def test_capability_loss_is_measured(golden_json: Callable[[str], Any], at: _dt.datetime) -> None:
    """Column grounding accuracy under each mode. Pinned, so the docs cannot drift.

    These numbers are reported in docs/packages/godwit-guard.md. If a change moves them,
    update the table there in the same commit -- the point is to report the loss, not to
    assert there is none.
    """
    bench = golden_json("schema_grounding/questions.json")
    accuracy = {mode: _grounding_accuracy(bench, _renderer(mode, at)) for mode in SchemaNameMode}
    chance = sum(1 / len(bench["tables"][q["table"]]) for q in bench["questions"]) / len(
        bench["questions"]
    )
    assert accuracy[SchemaNameMode.FULL] >= accuracy[SchemaNameMode.DESCRIBED]
    assert accuracy[SchemaNameMode.DESCRIBED] >= accuracy[SchemaNameMode.OPAQUE]
    assert accuracy[SchemaNameMode.OPAQUE] > chance, "OPAQUE must still do something useful"
    measured = {mode.value: round(value, 3) for mode, value in accuracy.items()}
    assert measured == {"full": 0.952, "described": 0.857, "opaque": 0.286}, measured
