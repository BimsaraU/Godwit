"""k-anonymity (property-tested, through the gate too), complementary releases, DP."""

from __future__ import annotations

import datetime as _dt
import statistics

import pytest
from _guard_support import SCOPE, classify, make_gate, value
from godwit_contracts import (
    Acquisition,
    Destination,
    Evidence,
    EvidenceKind,
    Operator,
    PiiClass,
    Predicate,
    ProbeKey,
    Segment,
    SnapshotId,
    derived_statistic,
    schema_name,
)
from godwit_guard import (
    DEFAULT_POLICY,
    ClassificationRegistry,
    EgressOptions,
    EgressRefusedError,
    RefusalReason,
    ReleaseLedger,
    dp_quantile,
    enforce_evidence_k,
    enforce_segment_k,
    laplace_count,
)
from hypothesis import given, settings
from hypothesis import strategies as st

AT = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
COLUMNS = ("country", "status", "cohort")


def _pred(column: str, raw: str) -> Predicate:
    return Predicate(
        column=schema_name(column, source_id="src_pii", table="customers"),
        op=Operator.EQ,
        values=(value(raw, column, acquisition=Acquisition.SEGMENT_PREDICATE, population=None),),
    )


def _segment(*pairs: tuple[str, str], population: int | None) -> Segment:
    return Segment(predicates=tuple(_pred(c, v) for c, v in pairs), population=population)


segments = st.builds(
    lambda chosen, population: _segment(
        *[(c, f"{c}_value") for c in chosen], population=population
    ),
    st.lists(st.sampled_from(COLUMNS), unique=True, max_size=3),
    st.one_of(st.none(), st.integers(min_value=0, max_value=200)),
)


@given(
    segment=segments,
    k=st.integers(min_value=2, max_value=50),
    coarser=st.dictionaries(st.integers(0, 3), st.integers(0, 500)),
)
def test_no_segment_below_k_survives(segment: Segment, k: int, coarser: dict[int, int]) -> None:
    def population_of(candidate: Segment) -> int | None:
        return coarser.get(len(candidate.predicates))

    result = enforce_segment_k(segment, k=k, population_of=population_of)
    assert result is None or (result.population is not None and result.population >= k)
    if result is not None and result is not segment:
        kept = {p.canonical_form()[0] for p in result.predicates}
        assert kept < {p.canonical_form()[0] for p in segment.predicates}


def test_k_is_never_below_two() -> None:
    for k in (0, 1):
        with pytest.raises(ValueError, match="at least 2"):
            enforce_segment_k(_segment(population=100), k=k)
        with pytest.raises(ValueError, match="at least 2"):
            ReleaseLedger(k=k)


def _world() -> ClassificationRegistry:
    registry = ClassificationRegistry()
    for column in COLUMNS:
        classify(registry, column, at=AT, confirm=PiiClass.QUASI_IDENTIFIER)
    return registry


@settings(max_examples=60, deadline=None)
@given(segment=segments)
def test_the_gate_never_emits_a_segment_below_k(segment: Segment) -> None:
    gate, _, _ = make_gate(_world(), at=AT)
    payload, _ = gate.clear(
        fields={},
        destination=Destination.LLM_PROVIDER,
        purpose="explain_pattern",
        policy=DEFAULT_POLICY,
        guardrails=(),
        actor="godwit-llm",
        occurred_at=AT,
        options=EgressOptions(segments={"seg": segment}, token_scope=SCOPE),
    )
    population = payload.fields.get("seg.population")
    if population is None:
        assert not any(key.startswith("seg.") for key in payload.fields)
    else:
        assert isinstance(population, int) and population >= DEFAULT_POLICY.min_cell_size


def test_evidence_needs_both_populations() -> None:
    def evidence(population: int | None, segment_population: int | None) -> Evidence:
        return Evidence(
            kind=EvidenceKind.RATE_CHANGE,
            probe_key=ProbeKey("pk"),
            snapshot_id=SnapshotId("s"),
            segment=_segment(("country", "PT"), population=segment_population),
            statistic=derived_statistic(0.4, population=population),
            population=population,
        )

    assert enforce_evidence_k(evidence(50, 50), k=20) is not None
    assert enforce_evidence_k(evidence(50, 3), k=20) is None
    assert enforce_evidence_k(evidence(None, 50), k=20) is None


# --------------------------------------------------------------------------------------
# Complementary releases
# --------------------------------------------------------------------------------------


def test_nested_releases_that_isolate_fewer_than_k_are_refused() -> None:
    ledger = ReleaseLedger(k=10)
    country = _segment(("country", "PT"), population=100)
    ledger.record(country, scope="t")
    narrower = _segment(("country", "PT"), ("status", "refund"), population=97)
    decision = ledger.check(narrower, scope="t")
    assert not decision.allowed and decision.conflicts == 1
    assert ledger.check(
        _segment(("country", "PT"), ("status", "refund"), population=80), scope="t"
    ).allowed
    assert ledger.check(narrower, scope="another_table").allowed
    assert not ledger.check(_segment(("country", "PT"), population=None), scope="t").allowed


def test_non_nested_overlaps_are_the_documented_residual_risk() -> None:
    """A and B vs A and C is NOT caught. This test pins the limit so nobody oversells it."""
    ledger = ReleaseLedger(k=10)
    ledger.record(_segment(("country", "PT"), ("status", "refund"), population=50), scope="t")
    sibling = _segment(("country", "PT"), ("cohort", "pilot"), population=48)
    assert ledger.check(sibling, scope="t").allowed


def test_the_gate_refuses_a_release_that_narrows_in_combination() -> None:
    gate, _, _ = make_gate(_world(), at=AT, releases=ReleaseLedger(k=20))

    def release(segment: Segment) -> None:
        gate.clear(
            fields={},
            destination=Destination.LLM_PROVIDER,
            purpose="explain",
            policy=DEFAULT_POLICY,
            guardrails=(),
            actor="llm",
            occurred_at=AT,
            options=EgressOptions(segments={"seg": segment}, token_scope=SCOPE),
        )

    release(_segment(("country", "PT"), population=100))
    with pytest.raises(EgressRefusedError) as caught:
        release(_segment(("country", "PT"), ("status", "refund"), population=95))
    assert caught.value.refusal.reason is RefusalReason.RELEASE_NARROWS_POPULATION


# --------------------------------------------------------------------------------------
# Differential privacy: off by default, honest about what it costs
# --------------------------------------------------------------------------------------


def test_laplace_noise_is_seeded_and_has_the_right_scale() -> None:
    assert laplace_count(100, epsilon=1.0, seed=7) == laplace_count(100, epsilon=1.0, seed=7)
    draws = [laplace_count(0, epsilon=1.0, seed=7, draw=i) for i in range(4000)]
    spread = statistics.pstdev(draws)
    assert 1.2 < spread < 1.6, "Laplace(1/eps) has stdev sqrt(2)/eps ~ 1.41"
    with pytest.raises(ValueError, match="positive"):
        laplace_count(1, epsilon=0, seed=1)


def test_dp_noise_swamps_a_small_segment_rate_change() -> None:
    """The trade-off, measured: a 3-row rise in a 40-row segment, one noisy comparison each.

    At epsilon=1 about 6% of comparisons see the change go the wrong way; at epsilon=0.1,
    the kind of budget that survives repeated measurement, it is close to a coin toss.
    """

    def wrong_direction_rate(epsilon: float) -> float:
        wrong = sum(
            1
            for i in range(2000)
            if laplace_count(43, epsilon=epsilon, seed=12, draw=i)
            <= laplace_count(40, epsilon=epsilon, seed=11, draw=i)
        )
        return wrong / 2000

    assert 0.03 < wrong_direction_rate(1.0) < 0.10
    assert wrong_direction_rate(0.1) > 0.35


def test_dp_quantile_is_bounded_and_deterministic() -> None:
    values = [float(v) for v in range(1, 101)]
    first = dp_quantile(values, q=0.5, epsilon=2.0, lower=0.0, upper=200.0, seed=3)
    assert first == dp_quantile(values, q=0.5, epsilon=2.0, lower=0.0, upper=200.0, seed=3)
    assert 0.0 <= first <= 200.0
    estimates = [
        dp_quantile(values, q=0.5, epsilon=2.0, lower=0.0, upper=200.0, seed=s) for s in range(200)
    ]
    assert 40 < statistics.median(estimates) < 60
