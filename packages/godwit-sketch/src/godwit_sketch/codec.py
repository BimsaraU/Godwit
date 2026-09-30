"""The versioned binary container every sketch payload lives inside.

Layout, big-endian throughout::

    magic        4 bytes   b"GWSK"
    container    1 byte    container format version (currently 1)
    codec_len    1 byte    length of the codec identifier in bytes
    codec        N bytes   ASCII codec identifier, e.g. b"godwit-kll-v1"
    schema_ver   2 bytes   unsigned, the codec's own body version
    body         rest      codec-specific, opaque to this module

Why a container at all, when :class:`~godwit_contracts.sketch.SketchEnvelope` already
carries ``codec`` and ``schema_version``: the envelope is a Pydantic model that can be
rewritten by anything that can construct one. The payload is the thing that actually
gets stored, copied between object stores and handed to a future build. It has to be
self-describing on its own, so that a reader holding only bytes can refuse correctly
rather than misread. :func:`decode_header` cross-checks the two on the way in, and a
disagreement is a decode error rather than a warning.

**Refusing forward.** A reader that meets a ``schema_ver`` higher than it knows raises
:class:`~godwit_sketch.errors.UnsupportedVersionError`. It never attempts a best-effort
parse. A sketch that silently misreads a newer layout produces a plausible number, and a
plausible wrong number is undetectable anywhere above L1.
"""

from __future__ import annotations

import struct
from typing import Final, NamedTuple

from godwit_contracts.common import ContentHash, canonical_json, content_hash
from godwit_contracts.segment import canonical_scalar

from godwit_sketch.errors import SketchDecodeError, UnsupportedVersionError

__all__ = [
    "CONTAINER_VERSION",
    "MAGIC",
    "SketchHeader",
    "decode_header",
    "encode_container",
    "payload_digest",
    "producer_fingerprint",
    "read_exact",
]

MAGIC: Final[bytes] = b"GWSK"
"""Container magic. Four bytes, so a truncated or foreign blob fails immediately."""

CONTAINER_VERSION: Final[int] = 1
"""Version of the framing above, not of any codec body."""

_HEADER_PREFIX: Final[struct.Struct] = struct.Struct(">4sBB")
_SCHEMA_VERSION: Final[struct.Struct] = struct.Struct(">H")

_MAX_CODEC_LEN: Final[int] = 255
_MAX_SCHEMA_VERSION: Final[int] = 0xFFFF
"""The header stores the body version in two bytes."""


class SketchHeader(NamedTuple):
    """A decoded container header and the offset at which the body starts."""

    codec: str
    schema_version: int
    body_offset: int


def encode_container(*, codec: str, schema_version: int, body: bytes) -> bytes:
    """Frame ``body`` with the self-describing header documented above.

    ``codec`` must be ASCII: it is an identifier we mint, never anything read from a
    customer system, and restricting it keeps the header byte-stable across platforms.
    """
    try:
        raw_codec = codec.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"codec identifier must be ASCII, got {codec!r}; codec names are minted by "
            "us and are never read from a customer system"
        ) from exc
    if not raw_codec or len(raw_codec) > _MAX_CODEC_LEN:
        raise ValueError(f"codec identifier must be 1..{_MAX_CODEC_LEN} ASCII bytes, got {codec!r}")
    if not 0 <= schema_version <= _MAX_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be 0..{_MAX_SCHEMA_VERSION}, got {schema_version}")
    return b"".join(
        (
            _HEADER_PREFIX.pack(MAGIC, CONTAINER_VERSION, len(raw_codec)),
            raw_codec,
            _SCHEMA_VERSION.pack(schema_version),
            body,
        )
    )


def decode_header(payload: bytes, *, expect_codec: str, max_schema_version: int) -> SketchHeader:
    """Validate the framing and return the header.

    Raises :class:`UnsupportedVersionError` when the payload is newer than this build,
    and :class:`SketchDecodeError` for every other malformation, including a codec that
    does not match the class being asked to decode it.
    """
    if len(payload) < _HEADER_PREFIX.size:
        raise SketchDecodeError("payload is shorter than a sketch container header")
    magic, container, codec_len = _HEADER_PREFIX.unpack_from(payload, 0)
    if magic != MAGIC:
        raise SketchDecodeError("payload is not a Godwit sketch container (bad magic)")
    if container > CONTAINER_VERSION:
        raise UnsupportedVersionError(
            f"sketch container version {container} was written by a newer build; "
            f"this build reads up to {CONTAINER_VERSION}"
        )
    offset = _HEADER_PREFIX.size
    end_codec = offset + codec_len
    if len(payload) < end_codec + _SCHEMA_VERSION.size:
        raise SketchDecodeError("sketch container header is truncated")
    try:
        codec = payload[offset:end_codec].decode("ascii")
    except UnicodeDecodeError as exc:
        raise SketchDecodeError("codec identifier is not ASCII") from exc
    if codec != expect_codec:
        raise SketchDecodeError(f"payload codec is {codec!r}, expected {expect_codec!r}")
    (schema_version,) = _SCHEMA_VERSION.unpack_from(payload, end_codec)
    if schema_version > max_schema_version:
        raise UnsupportedVersionError(
            f"{codec} body version {schema_version} was written by a newer build; "
            f"this build reads up to {max_schema_version}. Refusing rather than misreading."
        )
    return SketchHeader(codec, schema_version, end_codec + _SCHEMA_VERSION.size)


def read_exact(payload: bytes, offset: int, size: int) -> tuple[bytes, int]:
    """Slice ``size`` bytes at ``offset``, or raise. Returns the slice and the new offset."""
    end = offset + size
    if size < 0 or end > len(payload):
        raise SketchDecodeError("sketch payload is truncated")
    return payload[offset:end], end


def payload_digest(payload: bytes) -> ContentHash:
    """Digest of a serialised payload, for :attr:`SketchEnvelope.payload_digest`."""
    return content_hash(payload, prefix="sk")


def producer_fingerprint(
    *,
    codec: str,
    schema_version: int,
    params: dict[str, int | float | str | bool],
) -> ContentHash:
    """Identity of *what produced* a payload, independent of the data it saw.

    Two sketches merge only if their construction parameters match, so the fingerprint
    is exactly the merge-compatibility key: equal fingerprints mean mergeable. It is
    deterministic across processes and platforms because every value is rendered by
    ``canonical_scalar`` first -- raw float formatting is not portable and would give
    two agents two different fingerprints for the same sketch.

    It contains no row value. Construction parameters are ours (``k``, ``lg_k``,
    ``width``, ``depth``, ``seed``); a threshold that came out of the data belongs in a
    ``Segment``, not here.
    """
    rendered = {key: canonical_scalar(params[key]) for key in sorted(params)}
    identity = canonical_json(
        {"codec": codec, "schema_version": int(schema_version), "params": rendered}
    )
    return content_hash(identity, prefix="skp")
