"""Dedup keys, the redacted structural rendering, and the embedding built from it.

Three keys are derived from a candidate, and they do different jobs. Confusing them is
how a pattern store either reports the same finding forever or silently merges two
different ones.

``signature``
    Exact identity. ``(source, normalised segment key, column set, detector family,
    effect direction)``. Two candidates with the same signature are the same finding,
    and the second one extends the first pattern's evidence rather than opening a new
    one. A change in direction or in segment changes the signature, which is what makes
    "a material shift opens a new pattern" fall out of the key rather than out of a
    heuristic.

``structure_key``
    Shape identity, with every value **and the effect direction** removed.
    ``country = <something>`` rising and ``country = <something else>`` falling share a
    structure key and do **not** share a signature. It is what finds a new pattern's
    ancestor -- and since a material shift is precisely a change of segment or of
    direction, the shape has to ignore both of those or it could never find one.

``embedding``
    A vector over the same redacted rendering the structure key hashes, for
    nearest-neighbour recall in pgvector: "what else looks like this". It is never the
    thing that decides a merge.

WHY THE EMBEDDING IS BUILT FROM THE REDACTED RENDERING
------------------------------------------------------
An embedding computed over raw values is an egress channel. It is a lossy but real
encoding of its input, it sits in a control-plane table, it is served to a UI to draw a
similarity map, and nobody thinks of it as data because it is a list of floats. Two
candidates that differ only in their predicate *values* produce byte-identical
renderings here, and therefore identical vectors --
``tests/test_embedding_is_redacted.py`` proves exactly that against the PII torture
fixture, and additionally proves that building a rendering never calls ``reveal()`` on
a row value.

The rendering does contain customer **column** names, which are ``SCHEMA_NAME`` (leak
path 9). The embedding is therefore recorded as ``SCHEMA_NAME``-class in
``patterns.embedding_sensitivity``, and it is not in the ``_safe`` view.

A note on ``segment_key``: computing it reveals predicate values, inside
``godwit_contracts.segment``. That is the contract's own canonicalisation and every
agent performs it; this package only ever holds the resulting hash. That hash is a
pseudonym, not an anonymisation -- see the ``SegmentKey`` warning in the contracts --
which is why it keys the signature but never enters the embedding.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterator, Sequence
from enum import StrEnum
from typing import Final

from godwit_contracts import (
    Candidate,
    ContentHash,
    Evidence,
    GodwitModel,
    SegmentKey,
    SourceId,
    canonical_column,
    canonical_json,
    content_hash,
)

from godwit_store.taint import reveal_schema_name, reveal_statistic

__all__ = [
    "EMBEDDING_DIM",
    "CandidateSignature",
    "EffectDirection",
    "column_set",
    "cosine",
    "detector_family",
    "effect_direction",
    "embed_candidate",
    "embed_rendering",
    "rendering_tokens",
    "signature_of",
    "structural_rendering",
    "structure_key",
]

EMBEDDING_DIM: Final[int] = 256
"""Vector width. Large enough that the hashing trick collides rarely over the few dozen
structural tokens a candidate produces, small enough that an ivfflat index over a
million patterns is cheap. Changing it is a migration: every stored vector has this
width, and pgvector enforces it."""

_FLAT_EPSILON: Final[float] = 1e-12
"""Below this, a change in a statistic is not a direction. Not a sensitivity knob --
detectors decide what is significant; this only decides a sign."""


class EffectDirection(StrEnum):
    """Which way the statistic moved against its baseline.

    Part of the signature, because "refunds in PT went up" and "refunds in PT went
    down" are two findings, and an alert that merges them is worse than either.
    """

    UP = "up"
    DOWN = "down"
    MIXED = "mixed"
    """Different pieces of evidence disagree. Kept distinct rather than collapsed: a
    candidate whose evidence disagrees with itself deserves its own pattern."""
    FLAT = "flat"
    """No baseline to compare against, or no movement. A first observation is FLAT."""


def detector_family(candidate: Candidate) -> tuple[str, ...]:
    """The kinds of claim this candidate makes, sorted and deduplicated.

    Family is the *claim*, not the code that made it. Two detectors that both find a
    segment divergence in the same segment are one finding, and a detector version bump
    does not fork every pattern in the store. Protocol law 2 -- "dedup by segment key
    plus detector family, never by rendered text" -- is this plus the segment key.
    """
    return tuple(sorted({item.kind.value for item in candidate.evidence}))


def column_set(candidate: Candidate) -> tuple[str, ...]:
    """Canonicalised customer column names named by the evidence, sorted.

    Uses the contracts' own column normalisation, so this package and every detector
    agree about ``Country`` and ``country``.
    """
    names = {
        canonical_column(reveal_schema_name(column))
        for item in candidate.evidence
        for column in item.columns
    }
    return tuple(sorted(names))


def _evidence_direction(item: Evidence) -> EffectDirection:
    if item.effect_size is not None:
        delta = reveal_statistic(item.effect_size)
    elif item.baseline is not None:
        delta = reveal_statistic(item.statistic) - reveal_statistic(item.baseline)
    else:
        return EffectDirection.FLAT
    if abs(delta) <= _FLAT_EPSILON:
        return EffectDirection.FLAT
    return EffectDirection.UP if delta > 0.0 else EffectDirection.DOWN


def effect_direction(candidate: Candidate) -> EffectDirection:
    """Aggregate direction over the candidate's evidence.

    ``FLAT`` pieces abstain rather than vote: a rate change with no baseline should not
    turn a clear rise into ``MIXED``. If the non-flat pieces disagree, the result is
    ``MIXED`` and the candidate gets a pattern of its own.
    """
    directions = {_evidence_direction(item) for item in candidate.evidence}
    directions.discard(EffectDirection.FLAT)
    if not directions:
        return EffectDirection.FLAT
    if len(directions) == 1:
        return directions.pop()
    return EffectDirection.MIXED


class CandidateSignature(GodwitModel):
    """The exact-identity key of a finding, and the fields it is built from.

    Stored decomposed as well as hashed, so that "why did these two merge" is a query
    rather than an archaeology exercise. ``segment_key`` is a pseudonym; the rest are
    our own identifiers or customer column names.
    """

    source_id: SourceId
    segment_key: SegmentKey
    columns: tuple[str, ...]
    family: tuple[str, ...]
    direction: EffectDirection

    def canonical_form(self) -> str:
        """The exact string hashed into :attr:`key`."""
        return canonical_json(
            {
                "source_id": str(self.source_id),
                "segment_key": str(self.segment_key),
                "columns": list(self.columns),
                "family": list(self.family),
                "direction": self.direction.value,
            }
        )

    @property
    def key(self) -> ContentHash:
        """Stable dedup key. Equal keys mean one pattern."""
        return content_hash(self.canonical_form(), prefix="sig")


def signature_of(candidate: Candidate) -> CandidateSignature:
    """Derive the exact-identity signature of one candidate."""
    return CandidateSignature(
        source_id=candidate.source_id,
        segment_key=candidate.segment.key,
        columns=column_set(candidate),
        family=detector_family(candidate),
        direction=effect_direction(candidate),
    )


def _population_bucket(population: int | None) -> str:
    """Order-of-magnitude bucket of a row count.

    A count is not a row value, but an exact one over a tiny segment re-identifies
    (leak path 6), and an exact one would also make every pattern's vector unique for
    no analytic gain. Buckets are powers of two. Unknown is its own bucket, because
    unknown means unsafe, not small.
    """
    if population is None:
        return "unknown"
    if population <= 0:
        return "0"
    return f"b{population.bit_length() - 1}"


def structural_rendering(candidate: Candidate) -> str:
    """The redacted rendering: shape only, no value, in a stable order.

    Every token is one of: our own identifier, a customer column name
    (``SCHEMA_NAME``), an operator, an arity, an evidence kind or a population bucket.
    **No predicate value is read**, not even its type -- arity is used instead, so that
    this function never touches a ``DATA_VALUE`` at all.

    Effect **direction** is deliberately absent, although the signature includes it.
    The structure key's job is to find the pattern a new one shifted away from, and a
    direction reversal is exactly such a shift: a rendering that encoded the direction
    would give the reversal a different shape and the ancestry link would never be
    made. Shape is "what kind of finding, where", not "which way it went".
    """
    tokens: list[str] = [
        f"src:{candidate.source_id}",
        f"pop:{_population_bucket(candidate.segment.population)}",
    ]
    tokens.extend(f"fam:{kind}" for kind in detector_family(candidate))
    tokens.extend(f"col:{name}" for name in column_set(candidate))
    predicates = {
        f"pred:{canonical_column(reveal_schema_name(predicate.column))}"
        f":{predicate.op.value}:{len(predicate.values)}"
        for predicate in candidate.segment.predicates
    }
    tokens.extend(sorted(predicates))
    probes = {f"probe:{item.probe_key}" for item in candidate.evidence}
    tokens.extend(sorted(probes))
    return "\n".join(tokens)


def structure_key(candidate: Candidate) -> ContentHash:
    """Shape identity. Equal keys mean "the same kind of finding, somewhere else"."""
    return content_hash(structural_rendering(candidate), prefix="shp")


def _token_hash(token: str) -> tuple[int, float]:
    digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
    index = int.from_bytes(digest[:4], "big")
    sign = 1.0 if digest[4] & 1 else -1.0
    return index, sign


def embed_rendering(rendering: str, *, dim: int = EMBEDDING_DIM) -> tuple[float, ...]:
    """Feature-hash a redacted rendering into a unit vector.

    Deterministic by construction: BLAKE2b with no salt, no learned model, no network
    and no seed to forget to set. Two processes on two machines produce identical
    vectors for identical renderings, which is what lets a pattern written last year
    sit in the same neighbourhood as one written today (universal rule 5).

    The *signed* hashing trick keeps collisions unbiased in expectation rather than
    systematically additive. An empty rendering returns the zero vector rather than
    dividing by zero.
    """
    if dim <= 0:
        raise ValueError("embedding dimension must be positive")
    vector = [0.0] * dim
    for token in rendering.split("\n"):
        if not token:
            continue
        index, sign = _token_hash(token)
        vector[index % dim] += sign
    norm = math.sqrt(sum(component * component for component in vector))
    if norm == 0.0:
        return tuple(vector)
    return tuple(component / norm for component in vector)


def embed_candidate(candidate: Candidate) -> tuple[float, ...]:
    """Rendering then embedding, for the common call site."""
    return embed_rendering(structural_rendering(candidate))


def cosine(left: Sequence[float], right: Sequence[float]) -> float:
    """Cosine similarity of two vectors. Used in tests and in offline analysis.

    Similarity search in production is pgvector's job -- it has the index. This exists
    so the same arithmetic can be asserted without a database.
    """
    if len(left) != len(right):
        raise ValueError("vectors of different width are not comparable")
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def rendering_tokens(rendering: str) -> Iterator[str]:
    """Split a rendering back into its tokens. For diagnostics and tests."""
    return (token for token in rendering.split("\n") if token)
