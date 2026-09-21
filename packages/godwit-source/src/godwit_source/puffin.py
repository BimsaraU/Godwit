"""Minimal Puffin reader/writer for GODWIT's own blob types.

DATA PLANE. A Puffin file lives beside the table in the customer's own object storage, so
it is *inside* the perimeter and may legally hold DATA_VALUE payloads. That is exactly why
every blob we write carries a ``godwit.taint`` property: a file inside the perimeter still
must not be copied out of it by a later reader who assumed "it's only statistics".

The Puffin spec allows arbitrary blob types and requires readers to ignore ones they do not
know, which is what lets us persist our own statistics in a table another engine also reads.
The wire format is specified in ``docs/specs/puffin-blobs.md``; treat that document, not
this module, as the contract.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

__all__ = [
    "GODWIT_COLUMN_PROFILE_V1",
    "GODWIT_METADATA_STATS_V1",
    "GODWIT_NAMESPACE",
    "MAGIC",
    "Blob",
    "PuffinError",
    "decode_json_blob",
    "encode_json_blob",
    "godwit_blobs",
    "read_puffin",
    "write_puffin",
]

MAGIC = b"PFA1"
GODWIT_NAMESPACE = "godwit-"
GODWIT_METADATA_STATS_V1 = "godwit-metadata-stats-v1"
GODWIT_COLUMN_PROFILE_V1 = "godwit-column-profile-v1"

_FOOTER_TAIL = 4 + 4 + 4  # payload size, flags, trailing magic


class PuffinError(ValueError):
    """The bytes are not a Puffin file we can read. Never carries file content."""


@dataclass(frozen=True, slots=True)
class Blob:
    """One blob plus the footer metadata that describes how to read it.

    ``fields`` are Iceberg field ids the blob describes. ``properties`` must be flat
    string-to-string, per the spec; GODWIT always sets ``godwit.taint`` to ``data_value`` or
    ``derived_statistic`` so a reader knows what it is holding before it parses anything.
    """

    type: str
    fields: tuple[int, ...]
    snapshot_id: int
    sequence_number: int
    data: bytes
    properties: Mapping[str, str] = field(default_factory=dict)


def write_puffin(
    blobs: Sequence[Blob], *, file_properties: Mapping[str, str] | None = None
) -> bytes:
    """Serialise blobs into a Puffin file.

    Uncompressed blobs and an uncompressed footer only: compression would buy little on
    payloads this size and would add a codec negotiation that another engine could get
    wrong while reading a table it shares with us.
    """
    out = bytearray(MAGIC)
    entries: list[dict[str, object]] = []
    for blob in blobs:
        offset = len(out)
        out += blob.data
        entries.append(
            {
                "type": blob.type,
                "fields": list(blob.fields),
                "snapshot-id": blob.snapshot_id,
                "sequence-number": blob.sequence_number,
                "offset": offset,
                "length": len(blob.data),
                "properties": dict(blob.properties),
            }
        )
    payload = json.dumps(
        {"blobs": entries, "properties": dict(file_properties or {})},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    out += MAGIC
    out += payload
    out += struct.pack("<i", len(payload))
    out += struct.pack("<4B", 0, 0, 0, 0)
    out += MAGIC
    return bytes(out)


def read_puffin(raw: bytes) -> tuple[list[Blob], dict[str, str]]:
    """Parse a Puffin file. Returns ``(blobs, file_properties)``.

    Blob types we do not know are returned as-is rather than dropped, because a caller
    rewriting a file must be able to put them back untouched -- silently discarding another
    engine's statistics is how shared tables get corrupted.
    """
    if len(raw) < len(MAGIC) * 3 + _FOOTER_TAIL or not raw.startswith(MAGIC):
        raise PuffinError("not a puffin file")
    if not raw.endswith(MAGIC):
        raise PuffinError("missing trailing magic")
    flags_start = len(raw) - 4 - 4 - 4
    (payload_size,) = struct.unpack("<i", raw[flags_start : flags_start + 4])
    if payload_size < 0 or payload_size > flags_start:
        raise PuffinError("footer payload size out of range")
    payload_start = flags_start - payload_size
    if raw[payload_start - len(MAGIC) : payload_start] != MAGIC:
        raise PuffinError("missing footer magic")
    try:
        footer = json.loads(raw[payload_start:flags_start].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PuffinError(f"unreadable footer: {type(exc).__name__}") from exc

    blobs: list[Blob] = []
    for entry in footer.get("blobs", []):
        offset = int(entry["offset"])
        length = int(entry["length"])
        if offset < len(MAGIC) or offset + length > payload_start - len(MAGIC):
            raise PuffinError("blob extent outside file body")
        blobs.append(
            Blob(
                type=str(entry["type"]),
                fields=tuple(int(f) for f in entry.get("fields", [])),
                snapshot_id=int(entry.get("snapshot-id", 0)),
                sequence_number=int(entry.get("sequence-number", 0)),
                data=raw[offset : offset + length],
                properties={str(k): str(v) for k, v in (entry.get("properties") or {}).items()},
            )
        )
    props = {str(k): str(v) for k, v in (footer.get("properties") or {}).items()}
    return blobs, props


def godwit_blobs(blobs: Sequence[Blob]) -> list[Blob]:
    """The blobs this system wrote. Everything else belongs to another engine."""
    return [b for b in blobs if b.type.startswith(GODWIT_NAMESPACE)]


def encode_json_blob(
    blob_type: str,
    payload: Mapping[str, object],
    *,
    fields: Sequence[int] = (),
    snapshot_id: int = 0,
    sequence_number: int = 0,
    taint: str = "derived_statistic",
) -> Blob:
    """Pack a JSON payload as a GODWIT blob with its taint declared up front."""
    if not blob_type.startswith(GODWIT_NAMESPACE):
        raise PuffinError(f"blob type {blob_type!r} is outside the {GODWIT_NAMESPACE!r} namespace")
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return Blob(
        type=blob_type,
        fields=tuple(fields),
        snapshot_id=snapshot_id,
        sequence_number=sequence_number,
        data=data,
        properties={"godwit.taint": taint, "godwit.encoding": "json-utf8"},
    )


def decode_json_blob(blob: Blob) -> dict[str, object]:
    """Unpack a GODWIT JSON blob."""
    try:
        decoded = json.loads(blob.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PuffinError(f"unreadable {blob.type} blob: {type(exc).__name__}") from exc
    if not isinstance(decoded, dict):
        raise PuffinError(f"{blob.type} blob is not a JSON object")
    return decoded
