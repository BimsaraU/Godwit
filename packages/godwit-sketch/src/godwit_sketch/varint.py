"""LEB128 varints, for the sparse integer matrices Count-Min serialises.

A Count-Min matrix at the golden fixture's parameters is ``5 x 2718`` counters. At eight
bytes each that is a 108 KB envelope payload, nearly all of it leading zero bytes,
copied into the pattern store for every probe of every column of every snapshot. Nearly
every counter is small, so a variable-length encoding takes the same payload to a few
kilobytes.

Unsigned only: every count in this package is non-negative, and a signed varint would
buy nothing but a sign-extension bug waiting to happen.
"""

from __future__ import annotations

from godwit_sketch.errors import SketchDecodeError

__all__ = ["decode_varints", "encode_varints"]

_CONTINUATION = 0x80
_PAYLOAD = 0x7F
_MAX_VARINT_BYTES = 10
"""Ten groups of seven bits covers any 64-bit count. More than that is a corrupt stream."""


def encode_varints(values: list[int]) -> bytes:
    """Encode non-negative integers as concatenated LEB128."""
    out = bytearray()
    for value in values:
        if value < 0:
            raise ValueError(f"varint encoding is unsigned; got {value}")
        remaining = value
        while True:
            chunk = remaining & _PAYLOAD
            remaining >>= 7
            if remaining:
                out.append(chunk | _CONTINUATION)
            else:
                out.append(chunk)
                break
    return bytes(out)


def decode_varints(payload: bytes, offset: int, count: int) -> tuple[list[int], int]:
    """Decode exactly ``count`` varints starting at ``offset``. Returns them and the new offset."""
    values: list[int] = []
    position = offset
    for _ in range(count):
        result = 0
        shift = 0
        consumed = 0
        while True:
            if position >= len(payload):
                raise SketchDecodeError("varint stream is truncated")
            byte = payload[position]
            position += 1
            consumed += 1
            if consumed > _MAX_VARINT_BYTES:
                raise SketchDecodeError("varint is longer than any 64-bit value")
            result |= (byte & _PAYLOAD) << shift
            if not byte & _CONTINUATION:
                break
            shift += 7
        values.append(result)
    return values, position
