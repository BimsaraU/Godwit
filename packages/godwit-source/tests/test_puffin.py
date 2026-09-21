"""Custom Puffin blobs: round-trip, namespace discipline, and graceful coexistence."""

from __future__ import annotations

import importlib.util
import json
import struct

import pytest

from godwit_source.puffin import (
    GODWIT_METADATA_STATS_V1,
    MAGIC,
    Blob,
    PuffinError,
    decode_json_blob,
    encode_json_blob,
    godwit_blobs,
    read_puffin,
    write_puffin,
)


def sample_blob() -> Blob:
    return encode_json_blob(
        GODWIT_METADATA_STATS_V1,
        {"null_rate": 0.0012, "ndv_ratio": 0.94, "probe_version": "1"},
        fields=[5],
        snapshot_id=1234567890123456789,
        sequence_number=7,
    )


def test_round_trip_single_blob() -> None:
    original = sample_blob()
    blobs, props = read_puffin(write_puffin([original], file_properties={"created-by": "godwit"}))
    assert props == {"created-by": "godwit"}
    assert len(blobs) == 1
    got = blobs[0]
    assert got.type == original.type
    assert got.fields == (5,)
    assert got.snapshot_id == original.snapshot_id
    assert got.sequence_number == 7
    assert got.data == original.data
    assert got.properties["godwit.taint"] == "derived_statistic"
    assert decode_json_blob(got)["ndv_ratio"] == 0.94


def test_round_trip_many_blobs_preserves_order_and_extents() -> None:
    blobs = [
        encode_json_blob(GODWIT_METADATA_STATS_V1, {"i": i}, fields=[i], snapshot_id=i)
        for i in range(1, 6)
    ]
    got, _ = read_puffin(write_puffin(blobs))
    assert [decode_json_blob(b)["i"] for b in got] == [1, 2, 3, 4, 5]


def test_foreign_blobs_survive_a_read() -> None:
    """Another engine's statistics must come back untouched, so a rewrite can put them back.

    Dropping what we do not understand is how shared tables get quietly corrupted.
    """
    theirs = Blob(
        type="apache-datasketches-theta-v1",
        fields=(2,),
        snapshot_id=9,
        sequence_number=1,
        data=b"\x01\x02\x03\x04",
        properties={"ndv": "4242"},
    )
    blobs, _ = read_puffin(write_puffin([theirs, sample_blob()]))
    assert len(blobs) == 2
    assert blobs[0].data == b"\x01\x02\x03\x04"
    assert blobs[0].properties["ndv"] == "4242"
    assert [b.type for b in godwit_blobs(blobs)] == [GODWIT_METADATA_STATS_V1]


def test_our_file_is_structurally_a_puffin_file() -> None:
    """A standard reader keys off the magic and the footer JSON. Assert the bytes it would
    look at, so a change to our writer cannot quietly produce something only we can read."""
    raw = write_puffin([sample_blob()])
    assert raw.startswith(MAGIC)
    assert raw.endswith(MAGIC)
    (payload_size,) = struct.unpack("<i", raw[-12:-8])
    footer = json.loads(raw[-12 - payload_size : -12].decode("utf-8"))
    assert set(footer) == {"blobs", "properties"}
    entry = footer["blobs"][0]
    assert set(entry) >= {"type", "fields", "snapshot-id", "sequence-number", "offset", "length"}
    assert entry["type"].startswith("godwit-")


@pytest.mark.skipif(
    importlib.util.find_spec("pyiceberg") is None, reason="pyiceberg not installed"
)
def test_pyiceberg_rejects_unknown_blob_types_in_table_metadata() -> None:
    """The reason GODWIT Puffin files are sidecars and are never registered in the table.

    The Puffin spec says a reader should ignore blob types it does not know. pyiceberg 0.12
    does not: ``BlobMetadata.type`` is a ``Literal`` of the two types it knows, so a
    ``statistics-files`` entry naming a ``godwit-`` blob fails validation and takes the
    whole table load down with it -- for every pyiceberg reader of that table, not just
    ours. Writing into ``statistics-files`` would therefore break the customer's other
    tooling, so we do not. If this assertion ever starts failing because pyiceberg relaxed
    the type, that is the signal to revisit the decision, not a broken test.
    """
    from pyiceberg.table.statistics import StatisticsFile

    document = {
        "snapshot-id": 1,
        "statistics-path": "s3://warehouse/prod/payments/metadata/1.puffin",
        "file-size-in-bytes": 10,
        "file-footer-size-in-bytes": 4,
        "blob-metadata": [
            {
                "type": GODWIT_METADATA_STATS_V1,
                "snapshot-id": 1,
                "sequence-number": 1,
                "fields": [5],
            }
        ],
    }
    with pytest.raises(Exception, match="godwit-metadata-stats-v1"):
        StatisticsFile.model_validate(document)


@pytest.mark.skipif(
    importlib.util.find_spec("pyiceberg") is None, reason="pyiceberg not installed"
)
def test_standard_blob_metadata_still_validates() -> None:
    """Control for the test above: the rejection is about the type, not our document shape."""
    from pyiceberg.table.statistics import StatisticsFile

    document = {
        "snapshot-id": 1,
        "statistics-path": "s3://warehouse/prod/payments/metadata/1.puffin",
        "file-size-in-bytes": 10,
        "file-footer-size-in-bytes": 4,
        "blob-metadata": [
            {
                "type": "apache-datasketches-theta-v1",
                "snapshot-id": 1,
                "sequence-number": 1,
                "fields": [2],
                "properties": {"ndv": "42"},
            }
        ],
    }
    assert StatisticsFile.model_validate(document).blob_metadata[0].properties == {"ndv": "42"}


def test_blob_type_outside_namespace_is_refused() -> None:
    with pytest.raises(PuffinError):
        encode_json_blob("someone-elses-v1", {"a": 1})


@pytest.mark.parametrize(
    "raw",
    [b"", b"nope", MAGIC + b"body", MAGIC + b"body" + MAGIC],
)
def test_malformed_files_raise_without_echoing_content(raw: bytes) -> None:
    with pytest.raises(PuffinError) as excinfo:
        read_puffin(raw)
    assert "body" not in str(excinfo.value)
