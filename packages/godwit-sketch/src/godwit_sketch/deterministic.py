"""A hash-derived pseudo-random generator, for tests, benchmarks and synthetic data.

This package's whole claim is that the same data gives the same bytes, so seeding it
from :mod:`random` would be a slightly absurd way to test it: ``random.Random`` is
reproducible only for a fixed Python version and a fixed call sequence, and the ruff
configuration flags it (``S311``) wherever it appears outside ``scripts/``.

Everything here is a pure function of ``(salt, index)``. There is no state to seed
wrongly, no call-order dependence, and no way for two processes to disagree -- which
makes it usable for generating fixture data that has to stay stable across machines and
Python releases.

Not for anything that needs unpredictability. BLAKE2b is a fine hash but this is a
*deterministic* stream and is public by construction; it is for synthetic data, not for
keys, tokens or sampling decisions that an adversary should not be able to replay.
"""

from __future__ import annotations

import bisect
import hashlib
import math
from collections.abc import Sequence

__all__ = ["lognormals", "normals", "scramble", "uniforms", "zipf_indices"]

_U64 = float(1 << 64)


def _digest(salt: str, index: int) -> int:
    """A 64-bit value from ``(salt, index)``. The only source of entropy in this module."""
    return int.from_bytes(
        hashlib.blake2b(f"{salt}:{index}".encode(), digest_size=8).digest(), "big"
    )


def uniforms(count: int, *, salt: str) -> list[float]:
    """``count`` values in ``[0, 1)``."""
    return [_digest(salt, index) / _U64 for index in range(count)]


def normals(count: int, *, salt: str, mu: float = 0.0, sigma: float = 1.0) -> list[float]:
    """``count`` normal variates, by Box-Muller over two independent hash streams."""
    first = uniforms(count, salt=f"{salt}/bm0")
    second = uniforms(count, salt=f"{salt}/bm1")
    out: list[float] = []
    for a, b in zip(first, second, strict=True):
        radius = math.sqrt(-2.0 * math.log(max(a, 1e-18)))
        out.append(mu + sigma * radius * math.cos(2.0 * math.pi * b))
    return out


def lognormals(count: int, *, salt: str, mu: float = 3.2, sigma: float = 0.7) -> list[float]:
    """``count`` lognormal variates. The stand-in for a payments ``amount`` column."""
    return [math.exp(value) for value in normals(count, salt=salt, mu=mu, sigma=sigma)]


def zipf_indices(count: int, *, distinct: int, salt: str, exponent: float = 1.1) -> list[int]:
    """``count`` indices into ``distinct`` categories, Zipf-distributed.

    Uniform categories would make a heavy-hitter benchmark meaningless: there would be
    no heavy hitters to find and Count-Min would look flawless.
    """
    weights = [1.0 / (index + 1) ** exponent for index in range(distinct)]
    total = sum(weights)
    cumulative: list[float] = []
    running = 0.0
    for weight in weights:
        running += weight / total
        cumulative.append(running)
    return [
        min(bisect.bisect_left(cumulative, draw), distinct - 1)
        for draw in uniforms(count, salt=salt)
    ]


def scramble[T](items: Sequence[T], *, salt: str) -> list[T]:
    """A deterministic permutation of ``items``.

    Used to simulate out-of-order arrival. Ordering by a hash of the position gives a
    thorough shuffle that is identical on every machine and every run, so a failing
    batch-versus-streaming test can be reproduced exactly rather than approximately.
    """
    order = sorted(range(len(items)), key=lambda index: _digest(salt, index))
    return [items[index] for index in order]
