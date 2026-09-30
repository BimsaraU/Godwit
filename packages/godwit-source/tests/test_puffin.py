"""Puffin: our blobs round-trip, and other engines step over them.

The claim the format buys us is interoperability. A Puffin file written here must be
readable by any Iceberg engine, which must use the blobs it recognises and ignore the
``godwit-`` ones. The strongest available proof is to write with our codec and read back
with pyiceberg's own reader -- a different implementation, written by somebody else,
which we do not control.

The property tests generate arbitrary payloads and properties, because a codec that
only round-trips the examples its author thought of is a codec with a bug waiting in
the offsets.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from godwit_contracts.sketch import SketchEnvelope
from godwit_source.puffin import (
    ENVELOPE_PROPERTY,
    GODWIT_BLOB_PREFIX,
    SKETCH_ENVELOPE_BLOB,
    PuffinBlob,
    blob_to_sketch_envelope,
    godwit_blobs,
    read_puffin,
    sketch_envelope_blob,
    write_puffin,
)
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pyiceberg.table.puffin import MAGIC_BYTES, PuffinFile

_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=0, max_size=40)

blobs = st.builds(
    PuffinBlob,
    blob_type=st.sampled_from(
        [SKETCH_ENVELOPE_BLOB, "godwit-column-profile-v1", "apache-datasketches-theta-v1"]
    ),
    fields=st.lists(st.integers(min_value=1, max_value=999), max_size=4).map(tuple),
    snapshot_id=st.integers(min_value=0, max_value=2**62),
    sequence_number=st.integers(min_value=0, max_value=2**31),
    payload=st.binary(min_size=0, max_size=512),
    properties=st.dictionaries(_TEXT, _TEXT, max_size=4),
)


@given(
    written=st.lists(blobs, min_size=1, max_size=5),
    properties=st.dictionaries(_TEXT, _TEXT, max_size=3),
)
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_write_then_read_is_the_identity(
    written: list[PuffinBlob], properties: Mapping[str, str]
) -> None:
    """Every blob comes back with its payload, its fields and its properties intact."""
    recovered = read_puffin(write_puffin(written, properties=properties))
    assert len(recovered) == len(written)
    for original, found in zip(written, recovered, strict=True):
        assert found.blob_type == original.blob_type
        assert found.fields == original.fields
        assert found.snapshot_id == original.snapshot_id
        assert found.sequence_number == original.sequence_number
        assert found.payload == original.payload
        assert dict(found.properties) == dict(original.properties)


@given(written=st.lists(blobs, min_size=1, max_size=4))
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_writing_is_deterministic(written: list[PuffinBlob]) -> None:
    """Same blobs, same bytes. A Puffin file can therefore be content-addressed."""
    assert write_puffin(written) == write_puffin(written)


def test_pyiceberg_reads_what_we_wrote() -> None:
    """A different implementation parses our file and skips our blob types.

    ``PuffinBlobMetadata.type`` is a plain string in pyiceberg's reader, so a
    ``godwit-`` blob is carried through rather than rejected: it appears in the footer,
    its payload is retrievable, and an engine that filters on the types it knows simply
    passes over it. That is exactly the spec's "unknown blobs are ignored".
    """
    ours = PuffinBlob(
        blob_type="godwit-column-profile-v1",
        fields=(3,),
        snapshot_id=42,
        sequence_number=7,
        payload=b"godwit-only-payload",
        properties={"godwit.kind": "profile"},
    )
    theirs = PuffinBlob(
        blob_type="apache-datasketches-theta-v1",
        fields=(1,),
        snapshot_id=42,
        sequence_number=7,
        payload=b"theta-bytes",
        properties={"ndv": "1234"},
    )
    raw = write_puffin([theirs, ours], properties={"created-by": "godwit-test"})

    assert raw[:4] == MAGIC_BYTES
    assert raw[-4:] == MAGIC_BYTES

    puffin = PuffinFile(raw)
    assert [blob.type for blob in puffin.footer.blobs] == [
        "apache-datasketches-theta-v1",
        "godwit-column-profile-v1",
    ]
    assert puffin.footer.properties["created-by"] == "godwit-test"
    assert puffin.get_blob_payload(puffin.footer.blobs[0]) == b"theta-bytes"
    assert puffin.get_blob_payload(puffin.footer.blobs[1]) == b"godwit-only-payload"

    known = [blob for blob in puffin.footer.blobs if not blob.type.startswith(GODWIT_BLOB_PREFIX)]
    assert [blob.type for blob in known] == ["apache-datasketches-theta-v1"]
    assert known[0].properties["ndv"] == "1234"


def test_godwit_blobs_filters_by_namespace() -> None:
    raw = write_puffin(
        [
            PuffinBlob(
                blob_type="apache-datasketches-theta-v1",
                snapshot_id=1,
                sequence_number=1,
                payload=b"a",
            ),
            PuffinBlob(
                blob_type="godwit-sketch-envelope-v1",
                snapshot_id=1,
                sequence_number=1,
                payload=b"b",
            ),
        ]
    )
    assert [blob.blob_type for blob in godwit_blobs(read_puffin(raw))] == [
        "godwit-sketch-envelope-v1"
    ]


def _envelopes(golden_dir: Path) -> list[Mapping[str, Any]]:
    document = json.loads((golden_dir / "sketch_envelopes.json").read_text(encoding="utf-8"))
    return list(document["envelopes"])


def test_sketch_envelopes_round_trip_through_a_blob(golden_dir: Path) -> None:
    """GOLDEN: A0's three envelope shapes survive a trip through a Puffin blob.

    The item-bearing one matters most. Its payload contains row values and it declares
    ``DATA_VALUE``; the codec must carry that declaration through, because a Puffin file
    outlives the process that wrote it and its sensitivity has to travel with it.
    """
    for document in _envelopes(golden_dir):
        envelope = SketchEnvelope.model_validate(document)
        blob = sketch_envelope_blob(envelope, fields=(1,))

        assert blob.blob_type == SKETCH_ENVELOPE_BLOB
        assert ENVELOPE_PROPERTY in blob.properties

        recovered = blob_to_sketch_envelope(read_puffin(write_puffin([blob]))[0])
        assert recovered == envelope
        assert recovered.sensitivity is envelope.sensitivity
        assert recovered.payload == envelope.payload


def test_an_item_bearing_envelope_cannot_claim_to_be_a_statistic(golden_dir: Path) -> None:
    """Contracts refuse it on construction; the codec refuses it again on the way out."""
    count_min = next(
        document for document in _envelopes(golden_dir) if document["kind"] == "count_min"
    )
    lying = {**count_min, "sensitivity": "derived_statistic"}
    with pytest.raises(ValueError, match="stores observed items"):
        SketchEnvelope.model_validate(lying)


def test_a_non_puffin_file_is_refused() -> None:
    with pytest.raises(ValueError, match="magic"):
        read_puffin(b"")
    with pytest.raises(ValueError, match="magic bytes"):
        read_puffin(b"NOTPUFFINATALL")


def test_blob_to_sketch_envelope_refuses_a_foreign_blob() -> None:
    foreign = PuffinBlob(
        blob_type="apache-datasketches-theta-v1", snapshot_id=1, sequence_number=1, payload=b"x"
    )
    with pytest.raises(ValueError, match="is not godwit-sketch-envelope-v1"):
        blob_to_sketch_envelope(foreign)
