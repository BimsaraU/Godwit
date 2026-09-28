"""The three keys: exact signature, structural key, embedding.

The properties asserted here are the ones the rest of the store rests on. If the
signature is not stable across processes, dedup silently stops working and the queue
fills with the same finding; if it is *too* stable, two different findings merge and one
of them is never seen.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from _store_support import CandidateSpec
from godwit_contracts import EvidenceKind, Instant
from godwit_store.signature import (
    _FLAT_EPSILON,
    EMBEDDING_DIM,
    EffectDirection,
    column_set,
    cosine,
    detector_family,
    effect_direction,
    embed_candidate,
    embed_rendering,
    signature_of,
    structural_rendering,
    structure_key,
)
from hypothesis import given
from hypothesis import strategies as st


def test_the_same_finding_produces_the_same_signature(at: Instant) -> None:
    left = CandidateSpec(candidate_id="c1", created_at=at).build()
    right = CandidateSpec(candidate_id="c2", created_at=at).build()
    assert signature_of(left).key == signature_of(right).key


def test_a_different_segment_value_is_a_different_finding(at: Instant) -> None:
    """``country = PT`` and ``country = US`` are two findings, not one.

    The golden drift fixture makes this concrete: ``PT`` is the real drift and ``US``
    is the false-positive control. A store that merged them would report the control.
    """
    portugal = CandidateSpec(candidate_id="c1", created_at=at, pairs=(("country", "PT"),)).build()
    states = CandidateSpec(candidate_id="c2", created_at=at, pairs=(("country", "US"),)).build()
    assert signature_of(portugal).key != signature_of(states).key


def test_a_direction_change_opens_a_new_signature(at: Instant) -> None:
    """ "Refunds went up" and "refunds went down" must not deduplicate together."""
    rising = CandidateSpec(candidate_id="c1", created_at=at, statistic=10.0, baseline=1.0).build()
    falling = CandidateSpec(candidate_id="c2", created_at=at, statistic=1.0, baseline=10.0).build()
    assert effect_direction(rising) is EffectDirection.UP
    assert effect_direction(falling) is EffectDirection.DOWN
    assert signature_of(rising).key != signature_of(falling).key


def test_a_detector_version_bump_does_not_fork_a_pattern(at: Instant) -> None:
    """Family is the claim, not the code. Protocol law 2."""
    version_one = CandidateSpec(candidate_id="c1", created_at=at, detector_version=1).build()
    version_two = CandidateSpec(
        candidate_id="c2", created_at=at, detector_version=2, detector="other_detector"
    ).build()
    assert signature_of(version_one).key == signature_of(version_two).key


def test_a_different_evidence_kind_is_a_different_family(at: Instant) -> None:
    divergence = CandidateSpec(candidate_id="c1", created_at=at).build()
    graph = CandidateSpec(candidate_id="c2", created_at=at, kind=EvidenceKind.GRAPH_ANOMALY).build()
    assert detector_family(divergence) != detector_family(graph)
    assert signature_of(divergence).key != signature_of(graph).key


def test_column_names_are_casefolded_like_the_contract_does(at: Instant) -> None:
    lower = CandidateSpec(candidate_id="c1", created_at=at, columns=("amount",)).build()
    upper = CandidateSpec(candidate_id="c2", created_at=at, columns=("AMOUNT",)).build()
    assert column_set(lower) == column_set(upper) == ("amount",)
    assert signature_of(lower).key == signature_of(upper).key


def test_no_baseline_means_flat_not_up(at: Instant) -> None:
    """A first observation has no direction. Guessing one would fork it later."""
    first = CandidateSpec(candidate_id="c1", created_at=at, baseline=None).build()
    assert effect_direction(first) is EffectDirection.FLAT


def test_structure_key_ignores_values_but_signature_does_not(at: Instant) -> None:
    portugal = CandidateSpec(candidate_id="c1", created_at=at, pairs=(("country", "PT"),)).build()
    spain = CandidateSpec(candidate_id="c2", created_at=at, pairs=(("country", "ES"),)).build()
    assert structure_key(portugal) == structure_key(spain)
    assert signature_of(portugal).key != signature_of(spain).key


def test_structure_key_separates_different_shapes(at: Instant) -> None:
    one_predicate = CandidateSpec(candidate_id="c1", created_at=at).build()
    two_predicates = CandidateSpec(
        candidate_id="c2", created_at=at, pairs=(("country", "PT"), ("status", "refund"))
    ).build()
    assert structure_key(one_predicate) != structure_key(two_predicates)


def test_the_rendering_is_stable_under_predicate_order(at: Instant) -> None:
    """Segment canonicalisation sorts predicates; the rendering must inherit that."""
    forward = CandidateSpec(
        candidate_id="c1", created_at=at, pairs=(("country", "PT"), ("status", "refund"))
    ).build()
    reversed_order = CandidateSpec(
        candidate_id="c2", created_at=at, pairs=(("status", "refund"), ("country", "PT"))
    ).build()
    assert structural_rendering(forward) == structural_rendering(reversed_order)


def test_embeddings_are_unit_length(at: Instant) -> None:
    vector = embed_candidate(CandidateSpec(candidate_id="c1", created_at=at).build())
    assert len(vector) == EMBEDDING_DIM
    assert abs(sum(component * component for component in vector) - 1.0) < 1e-9


def test_embedding_of_an_empty_rendering_is_zero_not_an_error() -> None:
    assert embed_rendering("") == (0.0,) * EMBEDDING_DIM
    assert cosine(embed_rendering(""), embed_rendering("")) == 0.0


def test_related_shapes_are_nearer_than_unrelated_ones(at: Instant) -> None:
    """The embedding earns its place only if nearness means something."""
    base = CandidateSpec(candidate_id="c1", created_at=at).build()
    same_shape = CandidateSpec(candidate_id="c2", created_at=at, pairs=(("country", "ES"),)).build()
    other_shape = CandidateSpec(
        candidate_id="c3",
        created_at=at,
        pairs=(("device_id", "d1"), ("merchant", "m2")),
        columns=("device_id", "merchant", "amount"),
        kind=EvidenceKind.GRAPH_ANOMALY,
        probe_key="prb_graph",
    ).build()
    near = cosine(embed_candidate(base), embed_candidate(same_shape))
    far = cosine(embed_candidate(base), embed_candidate(other_shape))
    assert near > far


@given(seed=st.integers(min_value=0, max_value=10_000))
def test_the_signature_is_a_pure_function_of_the_candidate(seed: int) -> None:
    """Determinism (universal rule 5): no clock, no salt, no process state.

    Property-tested rather than example-tested because the failure mode is a signature
    that happens to agree within one process and disagrees across two, which a single
    example would never find.
    """
    moment = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC) + _dt.timedelta(seconds=seed)
    candidate = CandidateSpec(candidate_id=f"c{seed}", created_at=moment).build()
    first = signature_of(candidate).key
    second = signature_of(candidate.model_copy(deep=True)).key
    assert first == second


@given(
    statistic=st.floats(min_value=-1e6, max_value=1e6, allow_nan=False),
    baseline=st.floats(min_value=-1e6, max_value=1e6, allow_nan=False),
)
def test_direction_is_the_sign_of_the_change(statistic: float, baseline: float) -> None:
    candidate = CandidateSpec(
        candidate_id="c1",
        created_at=_dt.datetime(2024, 1, 1, tzinfo=_dt.UTC),
        statistic=statistic,
        baseline=baseline,
    ).build()
    direction = effect_direction(candidate)
    delta = statistic - baseline
    if abs(delta) <= _FLAT_EPSILON:
        # Below the epsilon a difference is not a direction. Two values that differ in
        # the 120th decimal place are the same measurement, and calling that a rise
        # would fork a pattern on floating-point noise.
        assert direction is EffectDirection.FLAT
    elif delta > 0.0:
        assert direction is EffectDirection.UP
    elif delta < 0.0:
        assert direction is EffectDirection.DOWN
    else:
        assert direction is EffectDirection.FLAT


def test_embed_rendering_refuses_a_zero_width_vector() -> None:
    with pytest.raises(ValueError, match="positive"):
        embed_rendering("src:x", dim=0)


def test_cosine_refuses_mismatched_widths() -> None:
    with pytest.raises(ValueError, match="different width"):
        cosine((1.0, 0.0), (1.0, 0.0, 0.0))
