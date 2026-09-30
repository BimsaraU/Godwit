"""False-discovery control: the algebra, the guarantee, and the holdout.

The acceptance criterion is *"pure noise in, adjusted candidate rate matches target q"*.
That phrase needs stating precisely before it can be tested, because two different
things are called "the rate":

* Under the **complete null** -- every hypothesis is noise -- the false-discovery rate
  and the family-wise error rate coincide, because every rejection is false. The
  guarantee is then ``P(at least one rejection) <= q``, and that is what
  :func:`test_pure_noise_rejects_at_most_the_target_rate` measures.
* Under a **mixture** of nulls and real effects, the guarantee is on the *expected
  proportion of false discoveries among the rejections*, which is strictly weaker and
  is what :func:`test_a_mixture_controls_the_realised_false_discovery_rate` measures.

Both are tested, with a seeded generator, because a store that controls one and claims
the other would be overstating what it does to the person who has to sign off on it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import math
from collections.abc import Iterator, Sequence
from itertools import pairwise

import pytest
from godwit_contracts import ContentHash, Instant, RunId, SnapshotId
from godwit_store.errors import UnboundedHypothesisFamilyError
from godwit_store.fdr import (
    DEFAULT_Q,
    HoldoutKind,
    HoldoutPolicy,
    HypothesisFamily,
    ValidationStatus,
    benjamini_hochberg,
    conservative_test_count,
    reconcile_holdout,
)
from hypothesis import given, settings
from hypothesis import strategies as st

_TRIALS = 2000
_FAMILY_SIZE = 200
_SEED = 20240117


def _uniforms(stream: Iterator[int], count: int) -> list[float]:
    """``count`` p-values from the null: uniform on [0, 1], by definition.

    Drawn from a BLAKE2b counter rather than from ``random``, for two reasons. It is
    reproducible on every machine and every Python version -- Mersenne Twister's stream
    is stable in practice but is not a documented guarantee -- and it keeps a
    cryptographically-unsuitable generator out of a codebase where the next person to
    reach for one might be hashing an identifier.
    """
    values: list[float] = []
    for _ in range(count):
        digest = hashlib.blake2b(str(next(stream)).encode("ascii"), digest_size=8).digest()
        values.append(int.from_bytes(digest, "big") / 2**64)
    return values


def _stream(seed: int) -> Iterator[int]:
    """A counter, so every draw in a test comes from a distinct hash input."""
    counter = seed
    while True:
        counter += 1
        yield counter


# ------------------------------------------------------------------------------------
# The algebra
# ------------------------------------------------------------------------------------


@given(
    p_values=st.lists(st.floats(min_value=0.0, max_value=1.0), min_size=1, max_size=60),
    q_target=st.floats(min_value=0.01, max_value=0.5),
)
@settings(max_examples=200)
def test_adjustment_never_makes_a_finding_more_significant(
    p_values: list[float], q_target: float
) -> None:
    """``q_i >= p_i``, always. Correcting for multiplicity can only cost significance."""
    for test in benjamini_hochberg(p_values, q_target=q_target):
        assert test.q_value >= test.p_value - 1e-12


@given(p_values=st.lists(st.floats(min_value=0.0, max_value=1.0), min_size=2, max_size=60))
@settings(max_examples=200)
def test_q_is_monotone_in_p(p_values: list[float]) -> None:
    """Sorting by p and sorting by q give the same order.

    The property that makes "the rejected set is a prefix" true, and the one a naive
    per-test adjustment (``p * m / rank`` with no running minimum) silently breaks.
    """
    tests = benjamini_hochberg(p_values)
    ordered = sorted(tests, key=lambda test: (test.p_value, test.index))
    for earlier, later in pairwise(ordered):
        assert earlier.q_value <= later.q_value + 1e-12


@given(p_values=st.lists(st.floats(min_value=0.0, max_value=1.0), min_size=1, max_size=60))
@settings(max_examples=200)
def test_the_rejected_set_is_a_prefix_in_p_order(p_values: list[float]) -> None:
    tests = sorted(benjamini_hochberg(p_values), key=lambda test: (test.p_value, test.index))
    seen_acceptance = False
    for test in tests:
        if not test.rejected:
            seen_acceptance = True
        elif seen_acceptance:
            pytest.fail("a rejected test follows an accepted one with a smaller p-value")


@given(p_values=st.lists(st.floats(min_value=0.0, max_value=1.0), min_size=1, max_size=40))
@settings(max_examples=100)
def test_input_order_does_not_change_any_verdict(p_values: list[float]) -> None:
    """Results come back in input order, and the input order is not a signal."""
    forward = {test.p_value: test.q_value for test in benjamini_hochberg(p_values)}
    backward = {test.p_value: test.q_value for test in benjamini_hochberg(list(reversed(p_values)))}
    assert forward == backward


def test_one_test_is_unadjusted() -> None:
    (only,) = benjamini_hochberg([0.03], q_target=0.05, test_count=1)
    assert only.q_value == pytest.approx(0.03)
    assert only.rejected


def test_a_larger_declared_family_makes_findings_less_significant() -> None:
    """The reason ``test_count`` is mandatory rather than inferred.

    A detector that examined ten thousand segments and emitted its best five has tested
    ten thousand hypotheses, not five. Reporting only the survivors makes each of them
    look two thousand times more significant than it is.
    """
    survivors = [0.0001, 0.0002, 0.0003, 0.0004, 0.0005]
    honest = benjamini_hochberg(survivors, test_count=10_000)
    flattering = benjamini_hochberg(survivors, test_count=5)
    assert all(
        honest_test.q_value > flattering_test.q_value
        for honest_test, flattering_test in zip(honest, flattering, strict=True)
    )
    assert not any(test.rejected for test in honest)
    assert all(test.rejected for test in flattering)


def test_a_family_smaller_than_its_candidates_is_a_detector_bug() -> None:
    with pytest.raises(UnboundedHypothesisFamilyError, match="every hypothesis it examined"):
        benjamini_hochberg([0.01, 0.02, 0.03], test_count=2)


def test_an_empty_batch_adjusts_to_nothing() -> None:
    assert benjamini_hochberg([]) == ()


def test_a_p_value_outside_zero_to_one_is_refused() -> None:
    with pytest.raises(ValueError, match="not a probability"):
        benjamini_hochberg([0.5, 1.5])


def test_q_target_must_be_a_rate() -> None:
    with pytest.raises(ValueError, match=r"q_target must be in \(0, 1\]"):
        benjamini_hochberg([0.5], q_target=0.0)


# ------------------------------------------------------------------------------------
# The guarantee
# ------------------------------------------------------------------------------------


def test_pure_noise_rejects_at_most_the_target_rate() -> None:
    """**Acceptance criterion.** Pure noise in, adjusted rate at or below target q.

    Under the complete null every rejection is false, so the false-discovery rate equals
    the probability of making any rejection at all. Over ``_TRIALS`` independent families
    of ``_FAMILY_SIZE`` uniform p-values, that probability must not exceed ``q``.

    The bound is on an **expectation**, and what is measured here is an estimate of it,
    so the assertion carries three Monte Carlo standard errors of slack. Asserting the
    bare inequality would be wrong in both directions: it fails on a run that is merely
    unlucky, and it passes an implementation whose true rate is 12% whenever the sample
    happens to land low. Stating the tolerance is the honest version.

    Seeded, so this is a regression test and not a coin toss: the same numbers every run,
    on every machine (universal rule 5).
    """
    rng = _stream(_SEED)
    families_with_a_rejection = 0
    for _ in range(_TRIALS):
        tests = benjamini_hochberg(
            _uniforms(rng, _FAMILY_SIZE), q_target=DEFAULT_Q, test_count=_FAMILY_SIZE
        )
        if any(test.rejected for test in tests):
            families_with_a_rejection += 1
    rate = families_with_a_rejection / _TRIALS
    standard_error = math.sqrt(DEFAULT_Q * (1.0 - DEFAULT_Q) / _TRIALS)
    assert rate <= DEFAULT_Q + 3 * standard_error, (
        f"noise produced a rejection in {rate:.1%} of families, against a target of "
        f"{DEFAULT_Q:.0%} +/- {3 * standard_error:.1%}"
    )


def test_without_adjustment_the_same_noise_floods_the_queue() -> None:
    """What the adjustment is for, measured rather than asserted.

    At a raw threshold of 0.05 over two hundred noise hypotheses, ten of them clear the
    bar in every single run -- for ever. That is the alert queue the objective function
    caps at fifty a day, filled entirely with nothing.
    """
    rng = _stream(_SEED)
    raw_hits = 0
    adjusted_hits = 0
    for _ in range(50):
        p_values = _uniforms(rng, _FAMILY_SIZE)
        raw_hits += sum(1 for p in p_values if p < 0.05)
        adjusted_hits += sum(
            1
            for test in benjamini_hochberg(p_values, q_target=DEFAULT_Q, test_count=_FAMILY_SIZE)
            if test.rejected
        )
    assert raw_hits > 300
    # Two orders of magnitude fewer. The exact count is a property of the seed; the
    # ratio is the property of the adjustment, so the ratio is what is asserted.
    assert adjusted_hits * 20 < raw_hits


def test_a_mixture_controls_the_realised_false_discovery_rate() -> None:
    """With real effects present, the *proportion of rejections that are false* is bounded.

    A weaker claim than the complete-null one and the one that actually applies in
    production, where some of the hypotheses are true. Twenty real effects hidden among
    a hundred and eighty nulls.
    """
    rng = _stream(_SEED)
    real_count = 20
    null_count = _FAMILY_SIZE - real_count
    false_discoveries = 0
    total_discoveries = 0
    for _ in range(_TRIALS):
        reals = [_uniforms(rng, 1)[0] * 0.0005 for _ in range(real_count)]
        nulls = _uniforms(rng, null_count)
        tests = benjamini_hochberg(reals + nulls, q_target=DEFAULT_Q, test_count=_FAMILY_SIZE)
        for index, test in enumerate(tests):
            if test.rejected:
                total_discoveries += 1
                if index >= real_count:
                    false_discoveries += 1
    assert total_discoveries > 0, "the real effects should have been found"
    realised = false_discoveries / total_discoveries
    assert realised <= DEFAULT_Q


def test_the_real_effects_are_still_found() -> None:
    """A control that rejects everything is not a control, it is a mute button."""
    rng = _stream(_SEED)
    reals = [_uniforms(rng, 1)[0] * 0.0005 for _ in range(20)]
    nulls = _uniforms(rng, 180)
    tests = benjamini_hochberg(reals + nulls, q_target=DEFAULT_Q, test_count=_FAMILY_SIZE)
    found = sum(1 for test in tests[:20] if test.rejected)
    assert found == 20


# ------------------------------------------------------------------------------------
# The declared family
# ------------------------------------------------------------------------------------


def test_a_family_of_zero_tests_is_refused(at: Instant) -> None:
    with pytest.raises(ValueError, match="cannot be adjusted"):
        HypothesisFamily(
            run_id=RunId("run_1"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=0,
            declared_at=at,
        )


def test_the_family_key_is_stable_and_covers_the_test_count(at: Instant) -> None:
    def family(test_count: int) -> HypothesisFamily:
        return HypothesisFamily(
            run_id=RunId("run_1"),
            snapshot_id=SnapshotId("snap_2"),
            detector="segment_divergence",
            detector_version=1,
            test_count=test_count,
            declared_at=at,
        )

    assert family(100).key == family(100).key
    assert family(100).key != family(101).key


def test_conservative_test_count_prefers_the_declared_ceiling() -> None:
    """The fallback for an adaptively scheduled probe space.

    A bandit changes how many hypotheses exist as it runs, so there is no honest fixed
    count. The conservative answer is to adjust against a ceiling declared for the
    snapshot; the emitted count is the floor, never a way to shrink the family. See
    ``docs/change-requests/CR-A3-fdr-hypothesis-space.md``.
    """
    assert conservative_test_count(emitted=10, declared_ceiling=5000) == 5000
    assert conservative_test_count(emitted=6000, declared_ceiling=5000) == 6000
    assert conservative_test_count(emitted=10, declared_ceiling=None) == 10


# ------------------------------------------------------------------------------------
# The holdout
# ------------------------------------------------------------------------------------


def _keys(*names: str) -> Sequence[ContentHash]:
    return [ContentHash(name) for name in names]


def test_a_candidate_that_reproduces_on_the_holdout_is_validated(at: Instant) -> None:
    policy = HoldoutPolicy(
        kind=HoldoutKind.TIME_SLICE,
        time_from=at,
        time_to=at + _dt.timedelta(days=1),
    )
    verdicts = reconcile_holdout(
        generated=_keys("sig_a", "sig_b"), reproduced=_keys("sig_a"), policy=policy
    )
    assert verdicts[ContentHash("sig_a")] is ValidationStatus.VALIDATED
    assert verdicts[ContentHash("sig_b")] is ValidationStatus.UNVALIDATED


def test_no_holdout_means_not_tested_not_passed(at: Instant) -> None:
    """ "We did not look" must not read the same as "we looked and it was there".

    Treating an absent holdout as a pass would make the weakest run in the system look
    like the strongest, which is the exact shape of every accidentally-impressive result
    in machine learning.
    """
    verdicts = reconcile_holdout(
        generated=_keys("sig_a"),
        reproduced=_keys("sig_a"),
        policy=HoldoutPolicy(kind=HoldoutKind.NONE),
    )
    assert verdicts[ContentHash("sig_a")] is ValidationStatus.NOT_TESTED


def test_a_time_slice_holdout_needs_its_window(at: Instant) -> None:
    with pytest.raises(ValueError, match="time_from and time_to"):
        HoldoutPolicy(kind=HoldoutKind.TIME_SLICE)


def test_a_segment_slice_holdout_needs_an_explicit_seed() -> None:
    """An unseeded partition is not reproducible, so it is not a holdout."""
    with pytest.raises(ValueError, match="partition_seed"):
        HoldoutPolicy(kind=HoldoutKind.SEGMENT_SLICE, partition_modulus=10)


def test_holding_out_everything_is_not_a_holdout(at: Instant) -> None:
    with pytest.raises(ValueError, match=r"fraction must be in \(0, 1\)"):
        HoldoutPolicy(
            kind=HoldoutKind.TIME_SLICE,
            fraction=1.0,
            time_from=at,
            time_to=at + _dt.timedelta(days=1),
        )


def test_the_holdout_key_pins_the_slice(at: Instant) -> None:
    """Replay has to be able to rebuild the exact slice that was reserved."""
    first = HoldoutPolicy(
        kind=HoldoutKind.TIME_SLICE, time_from=at, time_to=at + _dt.timedelta(days=1)
    )
    second = HoldoutPolicy(
        kind=HoldoutKind.TIME_SLICE, time_from=at, time_to=at + _dt.timedelta(days=2)
    )
    assert first.key == first.model_copy().key
    assert first.key != second.key
