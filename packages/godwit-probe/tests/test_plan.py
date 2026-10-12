"""Access modes are a planning constraint: asserted on the SQL and the read list.

A plan that reads a BLIND column and drops it later has already failed, so every test
here looks at what the plan *would read* -- ``sql``, ``read_columns`` -- and never at a
filtered result.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

import pytest
from _probe_support import orders, plain_keys_guardrail, predicate, segment, simulator
from godwit_contracts import (
    Guardrail,
    GuardrailAction,
    Operator,
    ProbeKind,
    Segment,
    SketchKind,
)
from godwit_guard import OPAQUE_SUFFIX
from godwit_probe.plan import (
    ROW_COUNT_FIELD,
    ColumnRole,
    ProbePlan,
    Refusal,
    RefusalReason,
    plan_probe,
)
from godwit_probe.testing import simulator_keyring

TABLE = orders()
TYPES = {column.name: column.logical_type for column in TABLE.columns}


def plan(
    kind: ProbeKind,
    columns: Sequence[str],
    *,
    sketches: Sequence[SketchKind] = (),
    where: Segment | None = None,
    keyring: bool = True,
    guardrails: Sequence[Guardrail] = (),
    params: dict[str, int | float | str | bool] | None = None,
) -> ProbePlan | Refusal:
    sim = simulator()
    spec = sim.spec(kind, columns, sketches=sketches, segment=where, params=params)
    return plan_probe(
        spec,
        access=sim.access,
        column_types=TYPES,
        keyring=simulator_keyring() if keyring else None,
        guardrails=guardrails,
    )


def planned(result: ProbePlan | Refusal) -> ProbePlan:
    assert isinstance(result, ProbePlan), result
    return result


def refused(result: ProbePlan | Refusal) -> Refusal:
    assert isinstance(result, Refusal), result
    return result


def identifiers(sql: str) -> set[str]:
    """Every identifier in the SQL, quoted or bare, with string literals removed."""
    stripped = re.sub(r"'(?:[^']|'')*'", "''", sql)
    return {
        (quoted.replace('""', '"') if quoted else bare)
        for quoted, bare in re.findall(r'"((?:[^"]|"")+)"|([A-Za-z_][A-Za-z0-9_]*)', stripped)
    }


# -- BLIND ------------------------------------------------------------------------------


def test_blind_column_never_appears_in_sql_or_reads_of_an_unrelated_probe() -> None:
    result = planned(plan(ProbeKind.CATEGORY_HISTOGRAM, ["country", "status"]))
    assert "notes" not in identifiers(result.sql)
    assert "notes" not in result.read_columns
    assert "customer_email_v2" not in identifiers(result.sql)
    assert set(result.read_columns) == {"country", "status"}
    assert "notes" in result.blind_columns
    assert "customer_email_v2" in result.blind_columns


def test_measuring_a_blind_column_is_refused_by_position() -> None:
    refusal = refused(plan(ProbeKind.NULL_RATE, ["country", "notes"]))
    assert refusal.reason is RefusalReason.BLIND_COLUMN
    assert refusal.column_role is ColumnRole.MEASURE
    assert refusal.column_index == 1


def test_filtering_on_a_blind_column_is_refused() -> None:
    where = segment(predicate("notes", Operator.EQ, "anything"))
    refusal = refused(plan(ProbeKind.NULL_RATE, ["country"], where=where))
    assert refusal.reason is RefusalReason.BLIND_COLUMN
    assert refusal.column_role is ColumnRole.PREDICATE
    assert refusal.column_index == 0


def test_an_unclassified_column_fails_closed() -> None:
    refusal = refused(plan(ProbeKind.DISTINCT_COUNT, ["customer_email_v2"]))
    assert refusal.reason is RefusalReason.UNCLASSIFIED_COLUMN


def test_a_column_the_table_does_not_have_is_refused() -> None:
    refusal = refused(plan(ProbeKind.NULL_RATE, ["no_such_column"]))
    assert refusal.reason is RefusalReason.UNKNOWN_COLUMN


def test_refusal_explanations_are_fixed_sentences() -> None:
    refusal = refused(plan(ProbeKind.NULL_RATE, ["notes"]))
    assert "notes" not in refusal.explanation
    assert "notes" not in refusal.model_dump_json()


# -- OPAQUE -----------------------------------------------------------------------------


def test_opaque_column_enters_only_as_a_keyed_hash_expression() -> None:
    result = planned(plan(ProbeKind.DISTINCT_COUNT, ["email"], sketches=[SketchKind.THETA]))
    assert result.sql == ('SELECT godwit_opaque_string("email") AS "email__opaque" FROM godwit_src')
    assert result.output_fields == ("email" + OPAQUE_SUFFIX,)
    assert result.read_columns == ("email",)


def test_opaque_predicate_compares_hash_to_hash_with_bound_parameters() -> None:
    where = segment(predicate("device_id", Operator.IN, "dev-000000000001", "dev-000000000002"))
    result = planned(plan(ProbeKind.NULL_RATE, ["country"], where=where))
    assert 'godwit_opaque_string("device_id") IN ($1, $2)' in result.sql
    assert "dev-000000000001" not in result.sql
    keyring = simulator_keyring()
    assert all(str(value).startswith("h_") for value in result.parameters)
    assert keyring.column_hasher.digest("dev-000000000001") in result.parameters


@pytest.mark.parametrize("op", [Operator.LT, Operator.GE, Operator.PREFIX])
def test_ranges_over_an_opaque_column_are_refused(op: Operator) -> None:
    where = segment(predicate("email", op, "user-"))
    refusal = refused(plan(ProbeKind.NULL_RATE, ["country"], where=where))
    assert refusal.reason is RefusalReason.OPAQUE_OPERATOR


def test_opaque_without_a_keyring_is_refused() -> None:
    refusal = refused(plan(ProbeKind.DISTINCT_COUNT, ["email"], keyring=False))
    assert refusal.reason is RefusalReason.NO_KEYRING


@pytest.mark.parametrize("kind", [SketchKind.KLL, SketchKind.FREQUENT_ITEMS])
def test_value_exposing_sketches_over_opaque_columns_are_refused(kind: SketchKind) -> None:
    refusal = refused(plan(ProbeKind.QUANTILES, ["email"], sketches=[kind]))
    assert refusal.reason in (
        RefusalReason.SKETCH_FORBIDDEN_FOR_MODE,
        RefusalReason.SKETCH_TYPE_MISMATCH,
    )


# -- OPEN -------------------------------------------------------------------------------


def test_open_predicate_values_are_parameters_never_sql_text() -> None:
    where = segment(
        predicate("country", Operator.EQ, "PT"),
        predicate("amount", Operator.BETWEEN, 400.0, 900.0),
    )
    result = planned(plan(ProbeKind.QUANTILES, ["amount"], where=where))
    assert result.sql == (
        'SELECT "amount" AS "amount" FROM godwit_src '
        'WHERE "country" = $1 AND "amount" BETWEEN $2 AND $3'
    )
    assert result.parameters == ("PT", 400.0, 900.0)
    assert "PT" not in result.sql


def test_row_count_over_the_universe_is_metadata_only() -> None:
    result = planned(plan(ProbeKind.ROW_COUNT, []))
    assert result.metadata_only
    assert result.read_columns == ()
    assert result.output_fields == (ROW_COUNT_FIELD,)


def test_row_count_over_a_segment_reads_only_the_predicate_column() -> None:
    result = planned(
        plan(ProbeKind.ROW_COUNT, [], where=segment(predicate("country", Operator.EQ, "PT")))
    )
    assert not result.metadata_only
    assert result.read_columns == ("country",)
    assert result.sql.startswith(f'SELECT count(*) AS "{ROW_COUNT_FIELD}"')


def test_numeric_sketch_on_a_string_column_is_a_type_mismatch() -> None:
    refusal = refused(plan(ProbeKind.QUANTILES, ["country"]))
    assert refusal.reason is RefusalReason.SKETCH_TYPE_MISMATCH


def test_unsupported_probe_kinds_are_refused() -> None:
    for kind in (ProbeKind.SEGMENT_AGGREGATE, ProbeKind.JOIN_CARDINALITY, ProbeKind.FRESHNESS):
        assert refused(plan(kind, ["country"])).reason is RefusalReason.UNSUPPORTED_PROBE


def test_params_outside_a_sketch_allowlist_stay_out_of_it() -> None:
    result = planned(
        plan(ProbeKind.QUANTILES, ["amount"], params={"k": 400, "unrelated": "x", "lg_k": 14})
    )
    (sketch,) = result.sketches
    assert dict(sketch.params) == {"k": 400}


# -- heavy hitters on identifiers ----------------------------------------------------------


def test_heavy_hitters_on_opaque_columns_store_hashed_keys() -> None:
    result = planned(plan(ProbeKind.HEAVY_HITTERS, ["device_id"]))
    (sketch,) = result.sketches
    assert sketch.hashed_entropy_bits == 64.0
    assert sketch.permission is None


def test_open_direct_identifier_is_hashed_without_a_guardrail() -> None:
    from godwit_contracts import PiiClass
    from godwit_guard import AccessMode
    from godwit_probe.testing import ProbeSimulator

    sim = ProbeSimulator(
        orders(),
        modes={"email": AccessMode.OPEN},
        pii={"email": PiiClass.DIRECT_IDENTIFIER},
        entropy_bits={"email": 48.0},
    )
    spec = sim.spec(ProbeKind.HEAVY_HITTERS, ["email"])
    result = planned(
        plan_probe(spec, access=sim.access, column_types=TYPES, keyring=simulator_keyring())
    )
    assert result.sketches[0].hashed_entropy_bits == 48.0
    allowed = planned(
        plan_probe(
            spec,
            access=sim.access,
            column_types=TYPES,
            keyring=simulator_keyring(),
            guardrails=[plain_keys_guardrail("email")],
        )
    )
    (sketch,) = allowed.sketches
    assert sketch.hashed_entropy_bits is None
    assert sketch.permission is not None
    assert sketch.permission.guardrail_id == "g-email-allow"
    assert allowed.permissions == (sketch.permission,)


def test_a_generic_allow_is_not_explicit_permission() -> None:
    from godwit_contracts import PiiClass
    from godwit_guard import AccessMode
    from godwit_probe.testing import ProbeSimulator

    sim = ProbeSimulator(
        orders(),
        modes={"email": AccessMode.OPEN},
        pii={"email": PiiClass.DIRECT_IDENTIFIER},
        entropy_bits={"email": 48.0},
    )
    spec = sim.spec(ProbeKind.HEAVY_HITTERS, ["email"])
    generic = plain_keys_guardrail("email", purpose=False)
    denied = plain_keys_guardrail("email", action=GuardrailAction.DENY)
    for guardrails in ([generic], [plain_keys_guardrail("email"), denied]):
        result = planned(
            plan_probe(
                spec,
                access=sim.access,
                column_types=TYPES,
                keyring=simulator_keyring(),
                guardrails=guardrails,
            )
        )
        assert result.sketches[0].hashed_entropy_bits == 48.0
        assert result.sketches[0].permission is None


def test_category_histogram_on_an_unpermitted_identifier_is_refused() -> None:
    from godwit_contracts import PiiClass
    from godwit_guard import AccessMode
    from godwit_probe.testing import ProbeSimulator

    sim = ProbeSimulator(
        orders(), modes={"email": AccessMode.OPEN}, pii={"email": PiiClass.DIRECT_IDENTIFIER}
    )
    spec = sim.spec(ProbeKind.CATEGORY_HISTOGRAM, ["email"])
    refusal = refused(
        plan_probe(spec, access=sim.access, column_types=TYPES, keyring=simulator_keyring())
    )
    assert refusal.reason is RefusalReason.PLAIN_KEYS_NOT_PERMITTED


def test_entropy_between_the_guard_and_sketch_floors_refuses_heavy_hitters() -> None:
    from godwit_guard import AccessMode
    from godwit_probe.testing import ProbeSimulator

    sim = ProbeSimulator(
        orders(), modes={"device_id": AccessMode.OPAQUE}, entropy_bits={"device_id": 28.0}
    )
    spec = sim.spec(ProbeKind.HEAVY_HITTERS, ["device_id"])
    refusal = refused(
        plan_probe(spec, access=sim.access, column_types=TYPES, keyring=simulator_keyring())
    )
    assert refusal.reason is RefusalReason.ENTROPY_BELOW_SKETCH_FLOOR
    theta = sim.spec(ProbeKind.DISTINCT_COUNT, ["device_id"])
    assert isinstance(
        plan_probe(theta, access=sim.access, column_types=TYPES, keyring=simulator_keyring()),
        ProbePlan,
    )


def test_graph_degree_over_two_opaque_identifiers() -> None:
    result = planned(plan(ProbeKind.GRAPH_DEGREE, ["email", "device_id"]))
    (sketch,) = result.sketches
    assert sketch.name == "count_min:graph"
    assert sketch.fields == ("email__opaque", "device_id__opaque")
    assert sketch.hashed_entropy_bits == 64.0
    assert refused(plan(ProbeKind.GRAPH_DEGREE, ["email"])).reason is (
        RefusalReason.UNSUPPORTED_PROBE
    )
