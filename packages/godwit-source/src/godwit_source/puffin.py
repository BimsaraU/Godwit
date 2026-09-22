"""Reading and writing Puffin files, including Godwit's own blob types.

Puffin is Iceberg's sidecar format for statistics. The spec allows arbitrary blob types
carried alongside the standard ones, and requires a reader to skip any type it does not
recognise. That is the whole reason this module exists: Godwit can cache a probe result
next to the table it measured, and Spark, Trino and pyiceberg will read the same file,
use the blobs they know and step over ours.

Reading is delegated to :class:`pyiceberg.table.puffin.PuffinFile`, which already parses
the footer and handles zstd blob payloads. pyiceberg ships no writer, so the writer here
implements the format directly. The layout, from the spec::

    Magic Blob* Footer
    Footer := Magic FooterPayload FooterPayloadSize Flags Magic

``Magic`` is ``PFA1``. ``FooterPayloadSize`` is a signed 32-bit little-endian integer
giving the length of ``FooterPayload``. ``Flags`` is four bytes; bit 0 of byte 0 means
the footer payload is zstd-compressed, and we always write it uncompressed so that any
reader can parse the footer without a codec.

The format is pinned by ``docs/specs/puffin-blobs.md`` and by round-trip tests that read
what this module writes back through pyiceberg's own reader.

DATA PLANE. A blob payload is a serialised sketch, and a Count-Min or frequent-items
payload contains row values. Blob *properties* carry the envelope's metadata, which
includes customer column names. Puffin files live inside the customer's own object
store, beside the table they describe, so nothing here crosses the perimeter -- but a
Puffin file is not a safe artifact to copy out, and :func:`sketch_envelope_blob` refuses
to write a payload whose envelope does not declare its sensitivity honestly.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Mapping, Sequence
from typing import Final

from godwit_contracts.common import GodwitModel, canonical_json
from godwit_contracts.sketch import ITEM_BEARING_KINDS, SketchEnvelope
from godwit_contracts.taint import Sensitivity, egress_risk_rank
from pydantic import Field
from pyiceberg.table.puffin import MAGIC_BYTES, PuffinFile

__all__ = [
    "ENVELOPE_PROPERTY",
    "GODWIT_BLOB_PREFIX",
    "SKETCH_ENVELOPE_BLOB",
    "PuffinBlob",
    "blob_to_sketch_envelope",
    "godwit_blobs",
    "read_puffin",
    "sketch_envelope_blob",
    "write_puffin",
]

GODWIT_BLOB_PREFIX: Final[str] = "godwit-"
"""Namespace for every blob type Godwit writes. Other engines skip these."""

SKETCH_ENVELOPE_BLOB: Final[str] = "godwit-sketch-envelope-v1"
"""A serialised ``SketchEnvelope``: the sketch bytes as payload, the rest as properties.

Versioned in the type name, not in a property, because a reader decides whether it
understands a blob from its type alone -- that is how the spec keeps unknown blobs
skippable.
"""

ENVELOPE_PROPERTY: Final[str] = "godwit.envelope"
"""Blob property holding the envelope's non-payload fields as canonical JSON."""

_FLAGS_UNCOMPRESSED: Final[bytes] = b"\x00\x00\x00\x00"
_FOOTER_SIZE_STRUCT: Final[struct.Struct] = struct.Struct("<i")
_MAGIC_LEN: Final[int] = len(MAGIC_BYTES)


class PuffinBlob(GodwitModel):
    """One blob, before it is placed in a file.

    ``payload`` is opaque. ``fields`` names the Iceberg schema field ids the blob
    describes, which the spec requires even for custom types; an empty tuple means the
    blob is about the table as a whole.
    """

    blob_type: str
    fields: tuple[int, ...] = ()
    snapshot_id: int
    sequence_number: int
    payload: bytes
    properties: Mapping[str, str] = Field(default_factory=dict)


def write_puffin(
    blobs: Sequence[PuffinBlob], *, properties: Mapping[str, str] | None = None
) -> bytes:
    """Serialise ``blobs`` into a Puffin file.

    Deterministic: the same blobs in the same order always produce the same bytes. The
    footer is rendered with :func:`godwit_contracts.common.canonical_json` so that two
    independently built writers agree, and so a Puffin file can be content-addressed.
    """
    body = bytearray(MAGIC_BYTES)
    metadata: list[dict[str, object]] = []
    for blob in blobs:
        offset = len(body)
        body.extend(blob.payload)
        entry: dict[str, object] = {
            "type": blob.blob_type,
            "fields": list(blob.fields),
            "snapshot-id": blob.snapshot_id,
            "sequence-number": blob.sequence_number,
            "offset": offset,
            "length": len(blob.payload),
        }
        if blob.properties:
            entry["properties"] = dict(blob.properties)
        metadata.append(entry)

    footer_payload = canonical_json(
        {"blobs": metadata, "properties": dict(properties or {})}
    ).encode("utf-8")
    body.extend(MAGIC_BYTES)
    body.extend(footer_payload)
    body.extend(_FOOTER_SIZE_STRUCT.pack(len(footer_payload)))
    body.extend(_FLAGS_UNCOMPRESSED)
    body.extend(MAGIC_BYTES)
    return bytes(body)


def read_puffin(data: bytes) -> tuple[PuffinBlob, ...]:
    """Parse a Puffin file into blobs, payloads included.

    Every blob in the file comes back, ours and other engines'. Filter with
    :func:`godwit_blobs` when you only want Godwit's.
    """
    if len(data) < 2 * _MAGIC_LEN:
        raise ValueError("not a Puffin file: too short to hold its magic bytes")
    puffin = PuffinFile(data)
    return tuple(
        PuffinBlob(
            blob_type=blob.type,
            fields=tuple(blob.fields),
            snapshot_id=blob.snapshot_id,
            sequence_number=blob.sequence_number,
            payload=puffin.get_blob_payload(blob),
            properties=dict(blob.properties),
        )
        for blob in puffin.footer.blobs
    )


def godwit_blobs(blobs: Sequence[PuffinBlob]) -> tuple[PuffinBlob, ...]:
    """Keep only blobs in the ``godwit-`` namespace."""
    return tuple(blob for blob in blobs if blob.blob_type.startswith(GODWIT_BLOB_PREFIX))


def sketch_envelope_blob(envelope: SketchEnvelope, *, fields: Sequence[int] = ()) -> PuffinBlob:
    """Pack a ``SketchEnvelope`` into a ``godwit-sketch-envelope-v1`` blob.

    Refuses an item-bearing sketch that declares itself a derived statistic. Contracts
    validate that on construction; this repeats the check because a Puffin file outlives
    the process that wrote it and is the one artifact here that a human might copy.
    """
    if envelope.kind in ITEM_BEARING_KINDS and egress_risk_rank(envelope.sensitivity) < (
        egress_risk_rank(Sensitivity.TOKEN)
    ):
        raise ValueError(f"{envelope.kind} stores observed items and cannot be a statistic")
    header = envelope.model_dump(mode="json", exclude={"payload"})
    return PuffinBlob(
        blob_type=SKETCH_ENVELOPE_BLOB,
        fields=tuple(fields),
        snapshot_id=_snapshot_id_as_long(envelope.snapshot_id),
        sequence_number=0,
        payload=envelope.payload,
        properties={ENVELOPE_PROPERTY: canonical_json(header)},
    )


def blob_to_sketch_envelope(blob: PuffinBlob) -> SketchEnvelope:
    """Rebuild the ``SketchEnvelope`` a ``godwit-sketch-envelope-v1`` blob carries."""
    if blob.blob_type != SKETCH_ENVELOPE_BLOB:
        raise ValueError(f"{blob.blob_type} is not {SKETCH_ENVELOPE_BLOB}")
    header_json = blob.properties.get(ENVELOPE_PROPERTY)
    if header_json is None:
        raise ValueError(f"blob is missing its {ENVELOPE_PROPERTY} property")
    header = json.loads(header_json)
    if not isinstance(header, dict):
        raise TypeError(f"{ENVELOPE_PROPERTY} is not a JSON object")
    return SketchEnvelope.model_validate({**header, "payload": blob.payload})


def _snapshot_id_as_long(snapshot_id: str) -> int:
    """Puffin stores a snapshot id as a long; ours is a string.

    Iceberg snapshot ids are longs rendered as strings by ``SnapshotRef``, so the common
    case parses. Anything else -- a Postgres pseudo-snapshot, for instance -- gets 0,
    the spec's "not attributable to a snapshot" value, rather than a made-up number.
    """
    try:
        return int(snapshot_id)
    except ValueError:
        return 0
