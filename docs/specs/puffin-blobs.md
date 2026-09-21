# GODWIT Puffin blob types

**Owner:** A1 (`packages/godwit-source`)
**Status:** v1, stable
**Audience:** anyone implementing a reader or writer for these blobs, in any language.

This document is the contract. `godwit_source/puffin.py` is one implementation of it; where
the two disagree, this document wins.

## Why we write Puffin at all

Iceberg manifests give per-file, per-column statistics for free, but they give only what the
format defines: counts and bounds. GODWIT computes statistics the format has no slot for —
sketch digests, per-column derived rates, profiling outcomes — and those have to live
somewhere durable, versioned and readable by something other than the process that wrote
them. Puffin is the Iceberg-native answer: a self-describing blob container with a JSON
footer, already in the ecosystem, already understood by tooling.

## Where these files live, and where they do not

**GODWIT Puffin files are sidecars. They are never registered in the Iceberg table's
`statistics-files` metadata.**

The Puffin spec says a reader should ignore blob types it does not recognise. pyiceberg
0.12 does not: `BlobMetadata.type` is a `Literal` of the two types it knows, so a
`statistics-files` entry naming a `godwit-` blob fails Pydantic validation and takes down
the *entire table load* — for every pyiceberg reader of that table, not only ours. Writing
into `statistics-files` would therefore break the customer's other tooling with a change
they did not ask for.

So: write the file into GODWIT's own prefix, record the path in the pattern store (A3), and
leave the customer's table metadata untouched. The file is still a valid Puffin file, still
readable by anything that understands the format, and still inside the customer's storage
perimeter.

`packages/godwit-source/tests/test_puffin.py::test_pyiceberg_rejects_unknown_blob_types_in_table_metadata`
pins this behaviour. If it ever starts failing because pyiceberg relaxed the type, that is
the signal to revisit the decision — not a broken test.

## Data protection

A Puffin file written by GODWIT sits in the customer's own object storage, which is *inside*
the perimeter. It may therefore legally hold `DATA_VALUE` payloads — a bounds digest, a
heavy-hitter list. That is exactly why every blob declares its taint:

| Property | Values | Meaning |
| --- | --- | --- |
| `godwit.taint` | `data_value`, `derived_statistic` | What the payload contains, before anyone parses it |
| `godwit.encoding` | `json-utf8` | How to decode the payload |

A reader that intends to move a blob's contents anywhere outside the perimeter must route it
through `godwit-guard` (A5). `godwit.taint: data_value` means that is mandatory. A file being
inside the perimeter is not permission to copy it out of one.

## Wire format

Standard Puffin, no extensions. Stated here so an independent implementation does not have
to read ours:

```
Magic Blob₁ Blob₂ … Blobₙ Magic FooterPayload FooterPayloadSize Flags Magic
```

- `Magic` is the four bytes `PFA1`.
- Blobs are written back to back, uncompressed, starting at offset 4.
- `FooterPayload` is UTF-8 JSON, uncompressed.
- `FooterPayloadSize` is a 4-byte little-endian signed integer.
- `Flags` is 4 zero bytes. GODWIT sets no flag bits; in particular bit 0 of byte 0 (footer
  compressed with LZ4) is always 0.

We write blobs and footer uncompressed deliberately. Payloads are small, and a compression
codec is one more thing another engine can get wrong while reading a file it shares with us.

Footer JSON:

```json
{
  "blobs": [
    {
      "type": "godwit-metadata-stats-v1",
      "fields": [5],
      "snapshot-id": 1234567890123456789,
      "sequence-number": 7,
      "offset": 4,
      "length": 91,
      "properties": {"godwit.taint": "derived_statistic", "godwit.encoding": "json-utf8"}
    }
  ],
  "properties": {}
}
```

Keys are emitted sorted and without whitespace, so a file is byte-identical for identical
input — replay (A4) depends on that.

## Blob types

All GODWIT types are namespaced `godwit-` and carry an explicit version suffix. A version is
never reinterpreted: a change to a payload's meaning is a new `-v2`, and a reader that does
not know `-v2` skips it rather than guessing.

### `godwit-metadata-stats-v1`

Per-column derived statistics for one snapshot, as computed by the L-1 metadata tier.
Payload is a JSON object. Taint is `derived_statistic`; a writer must not put a bound, a
common value or any other row value in this blob — that is what `-column-profile-v1` and its
own taint declaration are for.

| Key | Type | Meaning |
| --- | --- | --- |
| `null_rate` | number | nulls ÷ rows for the snapshot delta |
| `ndv_ratio` | number | distinct ÷ rows |
| `row_count` | integer | rows in the snapshot delta |
| `probe_version` | string | the version of the code that produced it |

### `godwit-column-profile-v1`

The first-pass semantic profile of one column: role, PII class, value format label,
cardinality ratio, and the reasons behind each. Taint depends on content — a profile that
names a value format is `derived_statistic`; one that retains an example value is
`data_value` and must say so.

## Reading rules

1. A reader must return blob types it does not recognise, unchanged, rather than dropping
   them. Silently discarding another engine's statistics is how shared tables get corrupted.
2. A reader must reject a file whose blob extents fall outside the file body, rather than
   reading whatever is at that offset.
3. A reader must not include file content in an error message. A malformed Puffin file may
   be malformed *because* it is full of row data.

## Round-tripping

`read_puffin(write_puffin(blobs))` returns the blobs unchanged — type, fields, snapshot id
and payload bytes — for arbitrary payloads, including payloads that contain the magic bytes.
This is property-tested in `tests/test_properties.py`; file-level properties round-trip too,
but they are returned separately from the blobs, so a byte-identical rewrite has to pass
them back in explicitly.
