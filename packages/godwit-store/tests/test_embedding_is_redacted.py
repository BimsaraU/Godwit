"""The dedup embedding is built from the redacted rendering. Proved three ways.

An embedding computed over raw values is an egress channel. It is a lossy but real
encoding of its input, it lives in a control-plane table, it gets served to a UI to draw
a similarity map, and nobody thinks of it as data because it is a list of floats. This
is the acceptance test for that: *the embedding for dedup is computed over redacted
renderings; prove it with the PII torture fixture.*

Three proofs, in increasing order of strength:

1. **String search.** No value from ``expected_leaks.json`` appears in the rendering.
   This is a **backstop**, and it proves very little on its own -- most of the leak paths
   in that fixture are things a regex would never recognise as sensitive.
2. **Invariance.** Two candidates that differ *only* in their predicate values produce a
   byte-identical rendering and an identical vector. A rendering that had read a value
   could not possibly satisfy this.
3. **No unwrap.** ``Tainted.reveal`` is replaced with one that raises on ``DATA_VALUE``
   for the duration of the call. Building a rendering does not touch a row value at all,
   so it does not even reach the point where a redaction rule would have to be correct.

Proof 3 is the one that matters. It is a statement about the code path rather than about
this particular data, which is the difference between a control and a coincidence.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from _store_support import CandidateSpec
from godwit_contracts import EvidenceKind, Instant, Sensitivity, Tainted
from godwit_store.signature import (
    embed_candidate,
    signature_of,
    structural_rendering,
    structure_key,
)

# Column names from the torture fixture. Every one of these is a SCHEMA_NAME disclosure
# in its own right (leak path 9) -- `patient_hiv_status` discloses before a row is read.
_TORTURE_COLUMNS = ("merchant_name", "device_id", "patient_hiv_status", "salary_2024")

# Values from the torture fixture. Manifest bounds, most-common-values and Count-Min
# heavy hitters: leak paths 1, 2 and 3. Each of these is a real identifier.
_TORTURE_VALUES = (
    ("merchant_name", "ACME_CORP"),
    ("device_id", "dev-0000-a4f7723b"),
    ("patient_hiv_status", "positive"),
)
_OTHER_VALUES = (
    ("merchant_name", "vendor_11"),
    ("device_id", "dev-0011-0837e2ae"),
    ("patient_hiv_status", "negative"),
)


@pytest.fixture
def expected_leaks(golden_dir: Path) -> tuple[str, ...]:
    """Every string that must never appear in any egress artifact."""
    import json

    payload = json.loads(
        (golden_dir / "pii_torture" / "expected_leaks.json").read_text(encoding="utf-8")
    )
    return tuple(payload["must_never_appear_in_any_egress"])


def _torture_candidate(at: Instant, *, values: tuple[tuple[str, str], ...]) -> Any:
    return CandidateSpec(
        candidate_id="cand_torture",
        created_at=at,
        pairs=values,
        columns=_TORTURE_COLUMNS,
        kind=EvidenceKind.HEAVY_HITTER_SHIFT,
        probe_key="prb_torture",
        population=12,
    ).build()


def test_the_rendering_quotes_no_value_from_the_torture_fixture(
    at: Instant, expected_leaks: tuple[str, ...]
) -> None:
    """Proof 1: the backstop. Necessary, and nowhere near sufficient."""
    rendering = structural_rendering(_torture_candidate(at, values=_TORTURE_VALUES))
    found = [leak for leak in expected_leaks if leak in rendering]
    assert found == [], f"the redacted rendering quotes {found}"


def test_two_candidates_differing_only_in_values_render_identically(at: Instant) -> None:
    """Proof 2: invariance. A rendering that read a value could not do this."""
    left = _torture_candidate(at, values=_TORTURE_VALUES)
    right = _torture_candidate(at, values=_OTHER_VALUES)
    assert structural_rendering(left) == structural_rendering(right)
    assert embed_candidate(left) == embed_candidate(right)
    assert structure_key(left) == structure_key(right)


def test_the_signature_still_separates_them(at: Instant) -> None:
    """The complement of proof 2, and the reason the store still works.

    If the embedding cannot tell ``ACME_CORP`` from ``vendor_11``, something has to, or
    two different findings would merge. The **signature** does, through the segment key
    -- a one-way hash of the canonical form, which is how dedup stays exact without the
    vector ever seeing a value.
    """
    left = _torture_candidate(at, values=_TORTURE_VALUES)
    right = _torture_candidate(at, values=_OTHER_VALUES)
    assert signature_of(left).key != signature_of(right).key


def test_building_a_rendering_never_unwraps_a_row_value(
    at: Instant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proof 3: the code path. The one that is a control rather than an observation.

    ``reveal()`` is replaced with one that raises on ``DATA_VALUE`` and passes everything
    else through -- godwit-store legitimately reads derived statistics and schema names
    in order to key and rank. If rendering ever starts reading predicate values, this
    fails immediately and loudly, whatever the values happen to be.
    """
    original: Callable[[Tainted[Any]], Any] = Tainted.reveal

    def guarded(self: Tainted[Any]) -> Any:
        if self.sensitivity is Sensitivity.DATA_VALUE:
            raise AssertionError(
                f"structural_rendering unwrapped a DATA_VALUE ({self.redacted()}); "
                "the embedding would then be computed over customer data"
            )
        return original(self)

    candidate = _torture_candidate(at, values=_TORTURE_VALUES)
    monkeypatch.setattr(Tainted, "reveal", guarded)
    rendering = structural_rendering(candidate)
    embed_candidate(candidate)
    assert rendering


def test_the_guard_itself_works(at: Instant, monkeypatch: pytest.MonkeyPatch) -> None:
    """A test that proves the previous test can fail.

    A monkeypatched guard that silently failed to install would make
    ``test_building_a_rendering_never_unwraps_a_row_value`` pass for the wrong reason,
    and a proof that cannot fail is not a proof. ``Segment.key`` *does* unwrap predicate
    values -- inside ``godwit_contracts``, which is where canonicalisation belongs -- so
    it is the honest thing to point the guard at.
    """
    original: Callable[[Tainted[Any]], Any] = Tainted.reveal

    def guarded(self: Tainted[Any]) -> Any:
        if self.sensitivity is Sensitivity.DATA_VALUE:
            raise AssertionError("unwrapped a DATA_VALUE")
        return original(self)

    candidate = _torture_candidate(at, values=_TORTURE_VALUES)
    monkeypatch.setattr(Tainted, "reveal", guarded)
    with pytest.raises(AssertionError, match="unwrapped a DATA_VALUE"):
        _ = candidate.segment.key


def test_column_names_do_reach_the_rendering_and_that_is_recorded(at: Instant) -> None:
    """The embedding is SCHEMA_NAME-class, not safe. Stated, not implied.

    ``patient_hiv_status`` in a rendering is a disclosure even with no value attached
    (leak path 9). The vector is therefore recorded as ``SCHEMA_NAME`` in
    ``patterns.embedding_sensitivity``, is excluded from ``patterns_safe``, and is
    constrained by ``ck_patterns_embedding_is_not_built_from_values`` so it can never be
    labelled ``DATA_VALUE`` either.
    """
    rendering = structural_rendering(_torture_candidate(at, values=_TORTURE_VALUES))
    assert "col:patient_hiv_status" in rendering
    assert "pred:merchant_name:eq:1" in rendering
