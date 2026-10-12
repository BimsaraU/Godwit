"""A hash-derived pseudo-random generator, for tests, benchmarks and synthetic data.

This package's whole claim is that the same data gives the same bytes, so seeding it
from :mod:`random` would be a slightly absurd way to test it: ``random.Random`` is
reproducible only for a fixed Python version and a fixed call sequence, and the ruff
configuration flags it (``S311``) wherever it appears outside ``scripts/``.

Everything here is a pure function of ``(salt, index)``. There is no state to seed
wrongly, no call-order dependence, and no way for two processes to disagree -- which
makes it usable for generating fixture data that has to stay stable across machines and
Python releases. That includes operating systems: the transcendental functions are
computed here rather than by the C library, whose last bit differs between Windows and
Linux (see ``portable_log``).

Not for anything that needs unpredictability. BLAKE2b is a fine hash but this is a
*deterministic* stream and is public by construction; it is for synthetic data, not for
keys, tokens or sampling decisions that an adversary should not be able to replay.
"""

from __future__ import annotations

import bisect
import hashlib
import math
from collections.abc import Sequence
from typing import Final

__all__ = [
    "lognormals",
    "normals",
    "portable_exp",
    "portable_log",
    "scramble",
    "uniforms",
    "zipf_indices",
]

_U64 = float(1 << 64)


def _digest(salt: str, index: int) -> int:
    """A 64-bit value from ``(salt, index)``. The only source of entropy in this module."""
    return int.from_bytes(
        hashlib.blake2b(f"{salt}:{index}".encode(), digest_size=8).digest(), "big"
    )


# --------------------------------------------------------------------------------------
# Portable transcendental functions
#
# ``math.log``, ``math.exp``, ``math.cos`` and ``**`` call the platform's C library, and
# Windows (UCRT) and Linux (glibc) disagree in the last bit for some inputs. One bit is
# enough: a KLL compaction compares values, so a last-bit difference in a synthetic
# input can change which items a sketch retains, and a detector's output on "the same"
# data then differs between a developer's laptop and CI. The functions below use only
# +, -, *, /, ``math.sqrt``, ``math.frexp`` and ``math.ldexp``, which IEEE 754 requires to
# be correctly rounded or exact, so they give the same bits everywhere. They are
# accurate to a few units in the last place: plenty for synthetic data, and not meant
# for anything else.
# --------------------------------------------------------------------------------------

_LN2: Final[float] = 0.6931471805599453
_SQRT_HALF: Final[float] = 0.7071067811865476
_TWO_PI: Final[float] = 6.283185307179586
_SERIES_TERMS: Final[int] = 40


def portable_log(x: float) -> float:
    """Natural logarithm of ``x > 0``, identical on every platform."""
    if not x > 0.0:
        raise ValueError("portable_log needs a positive argument")
    mantissa, exponent = math.frexp(x)
    if mantissa < _SQRT_HALF:
        mantissa *= 2.0
        exponent -= 1
    s = (mantissa - 1.0) / (mantissa + 1.0)
    s2 = s * s
    total = 0.0
    for k in range(_SERIES_TERMS - 1, -1, -1):
        total = total * s2 + 1.0 / (2 * k + 1)
    return 2.0 * s * total + exponent * _LN2


def portable_exp(x: float) -> float:
    """``e ** x``, identical on every platform."""
    k = math.floor(x / _LN2 + 0.5)
    r = x - k * _LN2
    total = 1.0
    for n in range(_SERIES_TERMS, 0, -1):
        total = 1.0 + r * total / n
    return math.ldexp(total, k)


def _portable_cos_turns(turns: float) -> float:
    """``cos(2 * pi * turns)``, identical on every platform."""
    angle = _TWO_PI * (turns - math.floor(turns + 0.5))
    a2 = angle * angle
    total = 1.0
    for n in range(_SERIES_TERMS, 0, -1):
        total = 1.0 - a2 * total / ((2 * n - 1) * (2 * n))
    return total


def uniforms(count: int, *, salt: str) -> list[float]:
    """``count`` values in ``[0, 1)``."""
    return [_digest(salt, index) / _U64 for index in range(count)]


def normals(count: int, *, salt: str, mu: float = 0.0, sigma: float = 1.0) -> list[float]:
    """``count`` normal variates, by Box-Muller over two independent hash streams."""
    first = uniforms(count, salt=f"{salt}/bm0")
    second = uniforms(count, salt=f"{salt}/bm1")
    out: list[float] = []
    for a, b in zip(first, second, strict=True):
        radius = math.sqrt(-2.0 * portable_log(max(a, 1e-18)))
        out.append(mu + sigma * radius * _portable_cos_turns(b))
    return out


def lognormals(count: int, *, salt: str, mu: float = 3.2, sigma: float = 0.7) -> list[float]:
    """``count`` lognormal variates. The stand-in for a payments ``amount`` column."""
    return [portable_exp(value) for value in normals(count, salt=salt, mu=mu, sigma=sigma)]


def zipf_indices(count: int, *, distinct: int, salt: str, exponent: float = 1.1) -> list[int]:
    """``count`` indices into ``distinct`` categories, Zipf-distributed.

    Uniform categories would make a heavy-hitter benchmark meaningless: there would be
    no heavy hitters to find and Count-Min would look flawless.
    """
    weights = [portable_exp(-exponent * portable_log(index + 1.0)) for index in range(distinct)]
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
