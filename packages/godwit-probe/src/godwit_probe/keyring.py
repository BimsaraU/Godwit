"""The data-plane keys behind OPAQUE columns.

DATA PLANE ONLY. Two keys, two jobs:

* The **column key** drives ``godwit_guard.KeyedHasher`` (HMAC-SHA256). An OPAQUE
  column enters the query only as that hash, computed inside the query engine, so the
  result set the probe consumes never holds the value.
* The **sketch key** drives ``godwit_sketch.KeyHasher`` in its OPAQUE mode. A
  heavy-hitter sketch over an already-hashed column hashes again under its own key, so
  its envelope declares ``key_mode = hashed`` truthfully, carries a ``key_id`` that
  refuses a merge with a sketch keyed differently, and publishes nothing a holder of
  the column key alone could reverse.

Neither key is rendered, copied into an envelope, logged or pickled. A worker gets them
from its secret store (KMS envelope or an external manager -- never the database) and
hands them to :class:`ProbeKeyring` at start-up.
"""

from __future__ import annotations

import hashlib
from typing import Final, NoReturn

from godwit_guard import KeyedHasher
from godwit_sketch import KeyHasher

__all__ = ["ProbeKeyring"]

_MIN_KEY_BYTES: Final[int] = 32


class ProbeKeyring:
    """Holds the two OPAQUE-mode keys for one worker process."""

    __slots__ = ("_column", "_sketch_key", "key_id")

    def __init__(self, *, column_key: bytes, sketch_key: bytes) -> None:
        if column_key == sketch_key:
            raise ValueError("the column key and the sketch key must differ")
        if len(sketch_key) < _MIN_KEY_BYTES:
            raise ValueError(f"the sketch key must be at least {_MIN_KEY_BYTES} bytes")
        self.key_id = hashlib.blake2b(column_key + sketch_key, digest_size=8).hexdigest()
        self._column = KeyedHasher(column_key, key_id=f"col-{self.key_id}")
        self._sketch_key = sketch_key

    @property
    def column_hasher(self) -> KeyedHasher:
        """The HMAC used for OPAQUE columns in queries and predicates."""
        return self._column

    def sketch_hasher(self, *, input_entropy_bits: float) -> KeyHasher:
        """A sketch-side hasher. Refuses below godwit-sketch's entropy floor."""
        return KeyHasher.opaque(key=self._sketch_key, input_entropy_bits=input_entropy_bits)

    def __repr__(self) -> str:
        return f"<ProbeKeyring key_id={self.key_id}>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("a ProbeKeyring holds data-plane keys and cannot be serialised")
