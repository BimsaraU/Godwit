"""Turning an observation into a stable key, and the OPAQUE (hashed-key) mode.

Two separate jobs live here, and they are here together because every value-bearing
sketch needs both.

CANONICAL KEYS
--------------
``1``, ``1.0``, ``"1"`` and ``True`` are four different observations and must never
collide in a sketch, exactly as they must never collide in a
:class:`~godwit_contracts.segment.Segment`. So an item is rendered through
``godwit_contracts.segment.canonical_scalar``, which tags the type and formats floats
portably. Reusing that function rather than writing a second renderer is deliberate: if
a sketch and a segment disagreed about what ``1`` means, a detector would compare two
populations that were never the same population.

OPAQUE MODE -- and the trap inside it
-------------------------------------
An identifier column defaults to OPAQUE, not BLIND: it is read only through a keyed
hash, with the key held in the data plane. That preserves cardinality, velocity, fan-in
and fan-out, join behaviour and collision structure -- which is where the organised
fraud signal lives -- while the values themselves never appear.

**Keyed hashing is not anonymisation when the input space is small.** A hashed
four-digit PIN, ISO country code or date of birth has at most a few thousand to a few
million possible inputs; anyone who obtains the key enumerates the lot in seconds, and a
rainbow table over the domain turns every stored digest back into its value. So
:class:`KeyHasher` refuses to be constructed in hashed mode without a declared
plausible-input-space entropy, and refuses outright below
:data:`MIN_OPAQUE_ENTROPY_BITS`. A column that fails the check must be bucketed or
blinded. It must never be hashed and called safe.

**Hashing does not lower the taint class.** A hashed identifier is a stable pseudonym,
and a stable pseudonym re-identifies across alerts and across time. Only the gate, in
``godwit-guard``, can issue a ``TOKEN``; nothing in this package downgrades anything.
Heavy hitters come back ``DATA_VALUE`` in both modes. What OPAQUE buys is blast radius:
a leaked payload is useless without a key held on the other side of the perimeter.

**The key is never serialised.** :meth:`KeyHasher.params` publishes the mode, the
declared entropy and a *key id* -- a digest of the key -- so that two sketches hashed
under different keys refuse to merge instead of quietly producing nonsense. The key
itself stays in the data plane and never enters an envelope, which travels to the
control plane.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from godwit_contracts.segment import canonical_scalar

from godwit_sketch.errors import InsufficientEntropyError

__all__ = [
    "MIN_OPAQUE_ENTROPY_BITS",
    "KeyHasher",
    "KeyMode",
    "canonical_item_key",
    "edge_key",
]

MIN_OPAQUE_ENTROPY_BITS: Final[float] = 32.0
"""Minimum plausible-input-space entropy for OPAQUE mode, in bits.

32 bits is roughly four billion candidates. That is not a cryptographic threshold and
is not meant to be: it is the point below which offline enumeration by anyone holding
the key is trivial on a laptop. Columns that fail it -- PIN, country, postcode, date of
birth, sex, boolean flags, small enumerations -- have to be bucketed or blinded.

The check is a floor, not a clearance. Passing it does not make a column safe to
disclose; it makes hashing a meaningful control rather than a decorative one.
"""

_NULL_KEY: Final[None] = None


class KeyMode(StrEnum):
    """How a value-bearing sketch stores the keys it observes."""

    PLAIN = "plain"
    """Keys stored as canonical strings. The payload contains real row values."""

    HASHED = "hashed"
    """Keys stored as keyed digests. OPAQUE columns. The key stays in the data plane."""


def canonical_item_key(item: float | str | tuple[str, str] | None) -> str | None:
    """Render one observation into its canonical, type-tagged key.

    Returns ``None`` for a null, which is not a key: nulls are counted by
    :class:`~godwit_sketch.moments.NullRate` and ignored by everything else.
    """
    if item is None:
        return _NULL_KEY
    if isinstance(item, tuple):
        return edge_key(item[0], item[1])
    return canonical_scalar(item)


def edge_key(source: str, target: str) -> str:
    """Canonical key for a directed edge.

    The separator is escaped so that ``("a|b", "c")`` and ``("a", "b|c")`` cannot
    collide into one edge, which would understate fan-out on exactly the accounts a
    structuring detector cares about.
    """
    return f"e:{_escape_separator(source)}|{_escape_separator(target)}"


def _escape_separator(value: str) -> str:
    """Escape the edge separator, and the escape character itself."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


@dataclass(frozen=True, slots=True)
class KeyHasher:
    """Maps a canonical key to the form a sketch stores.

    Construct with :meth:`plain` or :meth:`opaque`. The dataclass is frozen so that a
    sketch cannot have its hashing mode changed after it has observed anything.
    """

    mode: KeyMode
    _key: bytes = b""
    input_entropy_bits: float = 0.0
    _key_id: str = ""

    @classmethod
    def plain(cls) -> KeyHasher:
        """Store canonical keys as-is. For OPEN columns, and only for those."""
        return cls(mode=KeyMode.PLAIN)

    @classmethod
    def opaque(cls, *, key: bytes, input_entropy_bits: float) -> KeyHasher:
        """Store keyed digests. For OPAQUE columns: the default for identifiers.

        ``input_entropy_bits`` is the caller's honest estimate of the log2 size of the
        plausible input space for this column -- not the observed cardinality, which is
        a lower bound and would let a sampled column look safer than it is.

        Raises :class:`InsufficientEntropyError` below :data:`MIN_OPAQUE_ENTROPY_BITS`.
        """
        if not key:
            raise ValueError("OPAQUE mode needs a hashing key; an empty key hashes nothing")
        if input_entropy_bits < MIN_OPAQUE_ENTROPY_BITS:
            raise InsufficientEntropyError(
                f"a column with about {input_entropy_bits:.1f} bits of input entropy is "
                f"enumerable by anyone holding the key; OPAQUE requires at least "
                f"{MIN_OPAQUE_ENTROPY_BITS:.0f}. Bucket or blind this column instead -- "
                "do not hash it and call it safe"
            )
        return cls(
            mode=KeyMode.HASHED,
            _key=key,
            input_entropy_bits=input_entropy_bits,
            _key_id=hashlib.blake2b(key, digest_size=8).hexdigest(),
        )

    def apply(self, key: str) -> str:
        """Map a canonical key to its stored form."""
        if self.mode is KeyMode.PLAIN:
            return key
        return hashlib.blake2b(key.encode("utf-8"), key=self._key, digest_size=16).hexdigest()

    def params(self) -> dict[str, str | float]:
        """Merge-identity parameters. Publishes the key *id*, never the key."""
        if self.mode is KeyMode.PLAIN:
            return {"key_mode": KeyMode.PLAIN.value}
        return {
            "key_mode": KeyMode.HASHED.value,
            "key_id": self._key_id,
            "input_entropy_bits": self.input_entropy_bits,
        }

    @classmethod
    def from_params(cls, params: dict[str, object]) -> KeyHasher:
        """Rebuild the *identity* of a hasher from params, without its key.

        A decoded sketch can report how it was keyed and refuse an incompatible merge,
        but it cannot hash anything new: the key never crossed. Feeding items into a
        sketch decoded from an envelope is therefore a data-plane operation that must
        re-supply the key.
        """
        mode = KeyMode(str(params.get("key_mode", KeyMode.PLAIN.value)))
        if mode is KeyMode.PLAIN:
            return cls.plain()
        declared = params.get("input_entropy_bits", 0.0)
        entropy = float(declared) if isinstance(declared, int | float) else 0.0
        return cls(
            mode=KeyMode.HASHED,
            _key=b"",
            input_entropy_bits=entropy,
            _key_id=str(params.get("key_id", "")),
        )

    def __repr__(self) -> str:
        """Never renders the key."""
        return f"<KeyHasher {self.mode.value} key_id={self._key_id or 'n/a'}>"
