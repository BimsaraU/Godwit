"""False-discovery control: Benjamini-Hochberg, the test family, and the holdout.

THE FAILURE THIS PREVENTS
-------------------------
A system testing thousands of hypotheses an hour produces findings that are
statistically significant and meaningless. At p < 0.05 over ten thousand probes, five
hundred pure-noise segments clear the bar every run, for ever, and the operational
queue fills with them. Alert fatigue kills this product faster than poor accuracy does.

Two independent controls are applied, because neither is sufficient alone:

1. **Benjamini-Hochberg**, over an explicitly declared test family. Controls the
   expected proportion of false discoveries among the candidates that survive.
2. **A holdout slice**, reserved before generation and never used to generate. A
   candidate that does not reproduce there is ``UNVALIDATED`` and never reaches the
   operational queue, whatever its q-value says.

BH is a statement about a family of tests. A candidate that reproduces on data the
detector never saw is a statement about the world. The second catches the failure mode
the first cannot: a detector whose p-values are simply wrong.

THE TEST COUNT IS THE DETECTOR'S JOB TO REPORT
----------------------------------------------
BH needs the size of the family that was *tested*, not the size of the family that
*survived*. A detector that reports only its survivors makes every q-value in the batch
too small -- the more aggressively it prefilters, the more significant its findings look.
``benjamini_hochberg`` therefore takes ``test_count`` explicitly and refuses a count
smaller than the number of p-values it was handed. That refusal surfaces a detector bug
instead of absorbing it (deliverable 3).

An adaptively scheduled probe space does not have a fixed test count -- a bandit changes
how many hypotheses exist as it goes. See ``docs/change-requests/CR-A3-fdr-hypothesis-
space.md``; the implemented fallback is the conservative one, a declared ceiling per
snapshot, and :func:`conservative_test_count` is where it lives.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Final, Self

from godwit_contracts import (
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    Probability,
    RunId,
    SnapshotId,
    Version,
    canonical_json,
    content_hash,
)
from pydantic import Field, model_validator

from godwit_store.errors import UnboundedHypothesisFamilyError

__all__ = [
    "DEFAULT_Q",
    "AdjustedTest",
    "HoldoutKind",
    "HoldoutPolicy",
    "HypothesisFamily",
    "ValidationStatus",
    "benjamini_hochberg",
    "conservative_test_count",
    "reconcile_holdout",
]

DEFAULT_Q: Final[float] = 0.10
"""Target false-discovery rate when a run does not state one.

Ten percent, not five: the operational queue is reviewed by humans who reject things,
and a review capacity of fifty a day is the real bound on how much noise costs. A run
may state its own; this is the value used when it does not.
"""


class HypothesisFamily(GodwitModel):
    """The set of hypotheses one adjustment is made over. Declared, never inferred.

    A family is per detector run and per snapshot. Pooling two detectors into one
    family makes a weak detector's noise dilute a strong detector's findings; splitting
    one detector's snapshot across two families does the opposite. Both are wrong in
    ways that are invisible in the output, which is why this is a stored object with an
    id rather than an argument someone passes.
    """

    run_id: RunId
    snapshot_id: SnapshotId
    detector: str
    detector_version: Version
    test_count: NonNegInt = Field(
        description="How many hypotheses the detector examined, including the ones it "
        "discarded. Not how many candidates it emitted."
    )
    q_target: Probability = DEFAULT_Q
    declared_at: Instant

    @model_validator(mode="after")
    def _family_is_bounded(self) -> Self:
        if self.test_count == 0:
            raise ValueError(
                "a test family of size zero cannot be adjusted; a detector that cannot "
                "say how many hypotheses it examined has a bug worth surfacing"
            )
        if not 0.0 < self.q_target <= 1.0:
            raise ValueError("q_target must be in (0, 1]")
        return self

    def canonical_form(self) -> str:
        """The exact string hashed into :attr:`key`."""
        return canonical_json(
            {
                "run_id": str(self.run_id),
                "snapshot_id": str(self.snapshot_id),
                "detector": self.detector,
                "detector_version": int(self.detector_version),
                "test_count": int(self.test_count),
                "q_target": self.q_target,
            }
        )

    @property
    def key(self) -> ContentHash:
        """Stable identity of this family, recorded on every candidate it adjusted."""
        return content_hash(self.canonical_form(), prefix="fam")


class AdjustedTest(GodwitModel):
    """One hypothesis after adjustment: what went in, what came out, and the verdict."""

    index: NonNegInt = Field(description="Position in the input sequence. Order is kept.")
    p_value: Probability
    q_value: Probability
    rejected: bool = Field(
        description="True when the null is rejected at the family's q target, i.e. "
        "when this candidate survives FDR control."
    )


def conservative_test_count(*, emitted: int, declared_ceiling: int | None) -> int:
    """Pick the test count to adjust against, erring towards fewer discoveries.

    An adaptive orchestrator does not know its own hypothesis count in advance. The
    conservative answer is to adjust against a ceiling declared for the snapshot, and
    to fall back to the number emitted only when no ceiling exists -- which is the
    least conservative case and therefore the one that must be explicit in the data
    rather than implicit in a default.
    """
    if declared_ceiling is None:
        return emitted
    return max(declared_ceiling, emitted)


def benjamini_hochberg(
    p_values: Sequence[float],
    *,
    q_target: float = DEFAULT_Q,
    test_count: int | None = None,
) -> tuple[AdjustedTest, ...]:
    """Benjamini-Hochberg step-up, returning adjusted q-values in input order.

    ``test_count`` is the size of the family that was tested. It defaults to
    ``len(p_values)``, which is correct only when the detector emitted a candidate for
    every hypothesis it examined. A count smaller than the number of p-values supplied
    is a detector bug and raises :class:`UnboundedHypothesisFamilyError` rather than being
    quietly clamped -- see the module docstring.

    The unobserved tests (``test_count - len(p_values)`` of them) are treated as
    ``p = 1``, which is the conservative reading: they can only ever have failed.

    Properties, all property-tested in ``tests/test_fdr.py``:

    * ``q_i >= p_i`` for every test -- adjustment never makes a finding *more*
      significant.
    * ``q`` is monotone non-decreasing in ``p``: sorting by either gives the same order.
    * The rejected set is a prefix in p-order -- if a test is rejected, every test with
      a smaller p-value is too.
    * With ``test_count == 1`` and one p-value, ``q == p``.
    """
    if not 0.0 < q_target <= 1.0:
        raise ValueError("q_target must be in (0, 1]")
    count = len(p_values)
    if count == 0:
        return ()
    family_size = count if test_count is None else test_count
    if family_size < count:
        raise UnboundedHypothesisFamilyError(
            f"the family was declared as {family_size} tests but {count} p-values were "
            "supplied; a detector must report every hypothesis it examined, not only "
            "the ones that survived its own filter"
        )
    for index, value in enumerate(p_values):
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"p_values[{index}] = {value} is not a probability")

    order = sorted(range(count), key=lambda i: (p_values[i], i))
    adjusted = [0.0] * count
    running_min = 1.0
    # Step up from the largest p-value: the BH adjusted value is the running minimum of
    # m * p_(k) / k taken downwards, which is what makes it monotone.
    for rank_from_end, position in enumerate(reversed(order)):
        rank = count - rank_from_end
        raw = p_values[position] * family_size / rank
        running_min = min(running_min, raw, 1.0)
        adjusted[position] = running_min

    return tuple(
        AdjustedTest(
            index=index,
            p_value=p_values[index],
            q_value=adjusted[index],
            rejected=adjusted[index] <= q_target,
        )
        for index in range(count)
    )


class HoldoutKind(StrEnum):
    """How a run reserves the slice it will not generate from."""

    TIME_SLICE = "time_slice"
    """The most recent window of the snapshot, held back entirely."""
    SEGMENT_SLICE = "segment_slice"
    """A deterministic hash partition of the entity space."""
    NONE = "none"
    """No holdout was reserved. Candidates from such a run are ``NOT_TESTED`` and are
    barred from the operational queue. Recorded rather than forbidden, because a
    backfill or a one-off investigation legitimately has no holdout."""


class HoldoutPolicy(GodwitModel):
    """The slice a run reserved, stated precisely enough to reproduce.

    The policy is declared *before* generation and stored with the run. A holdout
    chosen after the fact is not a holdout; it is a second look at the same data.
    """

    kind: HoldoutKind
    fraction: Probability = Field(
        default=0.2,
        description="Share of the population reserved. Ignored when kind is NONE.",
    )
    time_from: Instant | None = None
    time_to: Instant | None = None
    partition_seed: int | None = Field(
        default=None,
        description="Seed for the SEGMENT_SLICE hash partition. Explicit, never "
        "defaulted: an unseeded partition is not reproducible.",
    )
    partition_modulus: int | None = Field(default=None, ge=2)
    partition_residues: tuple[int, ...] = ()

    @model_validator(mode="after")
    def _policy_is_complete(self) -> Self:
        if self.kind is HoldoutKind.TIME_SLICE and (self.time_from is None or self.time_to is None):
            raise ValueError("a time-slice holdout needs time_from and time_to")
        if (
            self.kind is HoldoutKind.TIME_SLICE
            and self.time_from is not None
            and self.time_to is not None
            and self.time_to <= self.time_from
        ):
            raise ValueError("holdout time_to must follow time_from")
        if self.kind is HoldoutKind.SEGMENT_SLICE:
            missing = [
                name
                for name, value in (
                    ("partition_seed", self.partition_seed),
                    ("partition_modulus", self.partition_modulus),
                )
                if value is None
            ]
            if missing or not self.partition_residues:
                needed = [*missing, *([] if self.partition_residues else ["partition_residues"])]
                raise ValueError(f"a segment-slice holdout needs {', '.join(needed)}")
        if self.kind is not HoldoutKind.NONE and not 0.0 < self.fraction < 1.0:
            raise ValueError("holdout fraction must be in (0, 1): all or nothing is not a holdout")
        return self

    def canonical_form(self) -> str:
        """The exact string hashed into :attr:`key`, so a replay can rebuild the slice."""
        return canonical_json(
            {
                "kind": self.kind.value,
                "fraction": self.fraction,
                "time_from": None if self.time_from is None else self.time_from.isoformat(),
                "time_to": None if self.time_to is None else self.time_to.isoformat(),
                "partition_seed": self.partition_seed,
                "partition_modulus": self.partition_modulus,
                "partition_residues": sorted(self.partition_residues),
            }
        )

    @property
    def key(self) -> ContentHash:
        """Stable identity of this holdout, stored with the run that reserved it."""
        return content_hash(self.canonical_form(), prefix="hld")


class ValidationStatus(StrEnum):
    """Whether a candidate reproduced on the slice it was not generated from.

    ``UNVALIDATED`` and ``NOT_TESTED`` are different facts and are kept apart.
    "We looked and it was not there" and "we did not look" call for different
    responses, and collapsing them would let a run with no holdout look as trustworthy
    as one that passed.
    """

    VALIDATED = "validated"
    UNVALIDATED = "unvalidated"
    NOT_TESTED = "not_tested"


#: The only status that may reach the operational queue. Referenced by
#: :mod:`godwit_store.ranking` and enforced again in SQL by the queue view.
OPERATIONAL_ELIGIBLE: Final[frozenset[ValidationStatus]] = frozenset({ValidationStatus.VALIDATED})


def reconcile_holdout(
    *,
    generated: Iterable[ContentHash],
    reproduced: Iterable[ContentHash],
    policy: HoldoutPolicy,
) -> Mapping[ContentHash, ValidationStatus]:
    """Decide each generated signature's validation status against the holdout run.

    ``generated`` are the signatures the detector produced on the generation slice;
    ``reproduced`` are the signatures it produced when re-run on the reserved slice.
    Matching is by signature, not by score: reproducing the same finding weakly is
    still reproducing it, and a store that demanded a similar effect size would be
    re-testing on the holdout, which is the thing a holdout exists to avoid.

    When the policy reserved nothing, everything is ``NOT_TESTED``. The alternative --
    treating an absent holdout as a pass -- makes the weakest run look like the
    strongest.
    """
    generated_keys = list(dict.fromkeys(generated))
    if policy.kind is HoldoutKind.NONE:
        return dict.fromkeys(generated_keys, ValidationStatus.NOT_TESTED)
    reproduced_keys = set(reproduced)
    return {
        key: (
            ValidationStatus.VALIDATED if key in reproduced_keys else ValidationStatus.UNVALIDATED
        )
        for key in generated_keys
    }
