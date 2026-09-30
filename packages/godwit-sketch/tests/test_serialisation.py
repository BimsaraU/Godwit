"""Serialisation: versioning, refusal, fingerprints and the varint encoder.

The pattern store holds envelopes written by older builds, and object storage holds them
for as long as the retention policy says. So the codecs here outlive the code that wrote
them, and the interesting cases are not the happy round-trip -- covered by the law suite
-- but what happens when a reader meets something it does not understand.

The rule throughout: **refuse loudly, never guess.** A sketch that misreads a newer
layout returns a plausible number, and a plausible wrong number is undetectable anywhere
above L1.
"""

from __future__ import annotations

import pytest
from _support import SMALL_PARAMS, context
from godwit_sketch.base import BaseSketch, registered_sketches
from godwit_sketch.codec import (
    CONTAINER_VERSION,
    MAGIC,
    decode_header,
    encode_container,
    payload_digest,
    producer_fingerprint,
)
from godwit_sketch.errors import (
    SketchDecodeError,
    UnsupportedCodecError,
    UnsupportedVersionError,
)
from godwit_sketch.moments import Moments
from godwit_sketch.quantile import KllQuantile
from godwit_sketch.varint import decode_varints, encode_varints

ALL_SKETCHES = registered_sketches()
IDS = [c.__name__ for c in ALL_SKETCHES]


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=IDS)
def test_payload_is_self_describing(cls: type[BaseSketch]) -> None:
    """The bytes identify themselves, independently of the envelope wrapped around them.

    An envelope is a Pydantic model anything can construct; the payload is the thing
    that actually gets stored and copied. A reader holding only bytes has to be able to
    tell what it has.
    """
    payload = cls.from_items([], SMALL_PARAMS).encode()
    assert payload.startswith(MAGIC)
    header = decode_header(payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION)
    assert header.codec == cls.CODEC
    assert header.schema_version == cls.SCHEMA_VERSION


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=IDS)
def test_an_older_reader_refuses_a_newer_payload(cls: type[BaseSketch]) -> None:
    """Meeting a body version from the future raises rather than parsing optimistically."""
    payload = cls.from_items([], SMALL_PARAMS).encode()
    with pytest.raises(UnsupportedVersionError, match="newer build"):
        decode_header(payload, expect_codec=cls.CODEC, max_schema_version=cls.SCHEMA_VERSION - 1)


def test_an_older_reader_refuses_a_newer_container() -> None:
    """The same applies one level up, to the framing itself."""
    payload = bytearray(Moments.from_items([1.0], SMALL_PARAMS).encode())
    payload[4] = CONTAINER_VERSION + 1
    with pytest.raises(UnsupportedVersionError, match="container version"):
        decode_header(
            bytes(payload),
            expect_codec=Moments.CODEC,
            max_schema_version=Moments.SCHEMA_VERSION,
        )


def test_foreign_bytes_are_rejected_on_the_magic() -> None:
    """Something that is not one of ours fails immediately, not halfway through a parse."""
    with pytest.raises(SketchDecodeError, match="not a Godwit sketch container"):
        decode_header(b"NOPE\x01\x05abcde\x00\x01", expect_codec="x", max_schema_version=1)


def test_a_truncated_payload_is_rejected() -> None:
    """Short reads raise instead of returning a half-built sketch."""
    payload = Moments.from_items([1.0, 2.0], SMALL_PARAMS).encode()
    with pytest.raises(SketchDecodeError):
        Moments._decode_body(payload[:-4])
    with pytest.raises(SketchDecodeError):
        decode_header(payload[:3], expect_codec=Moments.CODEC, max_schema_version=1)


@pytest.mark.parametrize("cls", ALL_SKETCHES, ids=IDS)
def test_a_class_refuses_another_classes_codec(cls: type[BaseSketch]) -> None:
    """Handing Moments a KLL envelope is a mistake worth an exception."""
    other = KllQuantile if cls is not KllQuantile else Moments
    envelope = other.from_items([], SMALL_PARAMS).serialise(context())
    with pytest.raises(UnsupportedCodecError):
        cls.decode(envelope)


def test_decode_rejects_an_envelope_whose_digest_does_not_match() -> None:
    """The envelope's digest is checked before the payload is trusted.

    An envelope whose payload has been swapped -- by a bad migration, a partial write,
    or anything else -- must not decode into a sketch that then gets merged into a
    series and quietly moves every statistic in it.
    """
    good = Moments.from_items([1.0, 2.0, 3.0], SMALL_PARAMS).serialise(context())
    tampered = good.model_copy(
        update={"payload": Moments.from_items([99.0], SMALL_PARAMS).encode()}
    )
    with pytest.raises(ValueError, match="payload digest mismatch"):
        Moments.decode(tampered)


def test_decode_by_registry_dispatches_on_codec() -> None:
    """``decode_envelope`` finds the right class without the caller naming it."""
    from godwit_sketch.base import decode_envelope

    original = KllQuantile.from_items([1.0, 2.0, 3.0], SMALL_PARAMS)
    rebuilt = decode_envelope(original.serialise(context()))
    assert isinstance(rebuilt, KllQuantile)
    assert rebuilt == original


def test_an_unknown_codec_is_refused_by_name() -> None:
    """A payload from a build that knew a kind this one does not is a refusal, not a guess."""
    from godwit_sketch.base import decode_envelope

    envelope = Moments.from_items([1.0], SMALL_PARAMS).serialise(context())
    foreign = envelope.model_copy(update={"codec": "godwit-something-v9"})
    with pytest.raises(UnsupportedCodecError, match="godwit-something-v9"):
        decode_envelope(foreign)


# --------------------------------------------------------------------------------------
# Producer fingerprints
# --------------------------------------------------------------------------------------


def test_fingerprint_is_merge_compatibility() -> None:
    """Equal fingerprints mean mergeable; different ones mean refuse."""
    a = KllQuantile.from_items([1.0], {"k": 32, "seed": 4})
    b = KllQuantile.from_items([9.0, 9.0], {"k": 32, "seed": 4})
    c = KllQuantile.from_items([1.0], {"k": 64, "seed": 4})
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint


def test_fingerprint_ignores_the_data() -> None:
    """A fingerprint identifies what produced a payload, never what it saw."""
    empty = KllQuantile.from_items([], {"k": 32, "seed": 4})
    full = KllQuantile.from_items([float(v) for v in range(500)], {"k": 32, "seed": 4})
    assert empty.fingerprint == full.fingerprint


def test_fingerprint_is_stable_across_parameter_ordering() -> None:
    """Parameters are a set, not a sequence: insertion order must not change identity."""
    left = producer_fingerprint(
        codec="x-v1", schema_version=1, params={"k": 8, "seed": 1, "width": 64}
    )
    right = producer_fingerprint(
        codec="x-v1", schema_version=1, params={"width": 64, "seed": 1, "k": 8}
    )
    assert left == right


def test_fingerprint_renders_floats_portably() -> None:
    """Float formatting is not portable, so parameters go through canonical_scalar.

    Two agents on two platforms must agree on the identity of the same sketch, or the
    pattern store ends up holding two series that should have been one.
    """
    assert producer_fingerprint(
        codec="x-v1", schema_version=1, params={"ratio": 0.1}
    ) == producer_fingerprint(codec="x-v1", schema_version=1, params={"ratio": 0.1})
    assert producer_fingerprint(
        codec="x-v1", schema_version=1, params={"ratio": 0.1}
    ) != producer_fingerprint(codec="x-v1", schema_version=1, params={"ratio": 0.2})


def test_payload_digest_is_stable() -> None:
    """The digest is a plain content hash, prefixed as the golden fixtures expect."""
    digest = payload_digest(b"some bytes")
    assert digest.startswith("sk_")
    assert digest == payload_digest(b"some bytes")


def test_encode_container_rejects_a_non_ascii_codec() -> None:
    """Codec identifiers are ours. A non-ASCII one means something has gone badly wrong."""
    with pytest.raises(ValueError, match="ASCII"):
        encode_container(codec="godwit-é-v1", schema_version=1, body=b"")


# --------------------------------------------------------------------------------------
# Varints
# --------------------------------------------------------------------------------------


def test_varints_round_trip() -> None:
    """Every value comes back exactly, including the boundaries between byte widths."""
    values = [0, 1, 127, 128, 255, 256, 16383, 16384, 2**31, 2**63 - 1]
    encoded = encode_varints(values)
    decoded, offset = decode_varints(encoded, 0, len(values))
    assert decoded == values
    assert offset == len(encoded)


def test_varints_shrink_a_sparse_matrix() -> None:
    """The reason this encoder exists: Count-Min matrices are mostly small numbers."""
    sparse = [0] * 5000 + [3, 7, 11]
    assert len(encode_varints(sparse)) < len(sparse) * 2


def test_varints_reject_a_negative() -> None:
    """Unsigned only. A negative count means a bug upstream, not a number to encode."""
    with pytest.raises(ValueError, match="unsigned"):
        encode_varints([-1])


def test_a_truncated_varint_stream_raises() -> None:
    """Asking for more values than the stream holds is a decode error, not a short list."""
    with pytest.raises(SketchDecodeError, match="truncated"):
        decode_varints(encode_varints([1, 2]), 0, 5)


def test_a_runaway_varint_raises() -> None:
    """A continuation bit that never terminates must not spin or allocate without bound."""
    with pytest.raises(SketchDecodeError):
        decode_varints(b"\x80" * 12, 0, 1)
