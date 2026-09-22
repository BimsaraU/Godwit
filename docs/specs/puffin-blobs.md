# Godwit Puffin blobs

**Owner:** A1 (`godwit-source`) · **Status:** v1, implemented
**Implementation:** `packages/godwit-source/src/godwit_source/puffin.py`

This document specifies the Puffin blob types Godwit writes, precisely enough that
somebody who has never seen our code can implement a reader or a writer against it.

---

## Background: the format

[Puffin](https://iceberg.apache.org/puffin-spec/) is Iceberg's sidecar format for
statistics and indexes. Its relevant property is that **blob types are open**: a file may
carry arbitrary types alongside the standard ones, and a reader is required to skip any
type it does not recognise. That is what lets Godwit cache a probe result next to the
table it measured while Spark, Trino and pyiceberg keep reading the same file.

The physical layout, which `write_puffin` implements directly because pyiceberg ships a
reader and no writer:

```
Magic  Blob₁ Blob₂ … Blobₙ  Footer

Footer := Magic  FooterPayload  FooterPayloadSize  Flags  Magic
```

* `Magic` is the four bytes `PFA1`.
* Each blob's payload is written contiguously in order; its byte offset and length go in
  the footer.
* `FooterPayload` is UTF-8 JSON.
* `FooterPayloadSize` is a **signed 32-bit little-endian** integer: the length of
  `FooterPayload` in bytes.
* `Flags` is four bytes. Bit 0 of byte 0 means the footer payload is zstd-compressed.
  **Godwit always writes it uncompressed (all four bytes zero)** so that any reader can
  parse the footer without a codec.

`FooterPayload` is an object with `blobs` (an array) and `properties` (an object of
strings). Each blob entry:

| Key | Type | Notes |
|---|---|---|
| `type` | string | The blob type. Godwit's all begin `godwit-`. |
| `fields` | array of int | Iceberg schema field ids the blob describes. Empty means the table as a whole. |
| `snapshot-id` | long | The snapshot the blob was computed from. `0` when not attributable to one. |
| `sequence-number` | long | The snapshot's sequence number, or `0`. |
| `offset` | long | Byte offset of the payload from the start of the file. |
| `length` | long | Payload length in bytes. |
| `compression-codec` | string | Omitted by Godwit's writer. The reader accepts `zstd`. |
| `properties` | object | String-to-string. Omitted when empty. |

The footer JSON is rendered with `godwit_contracts.common.canonical_json`: separators
`,` and `:` with no whitespace, keys sorted by Unicode code point, `ensure_ascii` false.
That makes the writer **deterministic** -- the same blobs in the same order always produce
the same bytes -- so a Puffin file can be content-addressed and diffed.

---

## Namespace

Every blob type Godwit writes begins with `godwit-` and carries its version **in the type
name**, not in a property. That is deliberate: a reader decides whether it understands a
blob from its type alone, which is how the spec keeps unknown blobs skippable. A `v2`
blob is a new type, never a property change on `v1`.

`godwit_source.puffin.godwit_blobs()` filters a parsed file to this namespace.

---

## `godwit-sketch-envelope-v1`

**Purpose.** Carry one serialised `godwit_contracts.sketch.SketchEnvelope` -- a probe
result -- beside the table it was computed from, so that repeating the same probe at the
same snapshot costs nothing.

**Payload.** The envelope's `payload` field verbatim: opaque bytes in the codec named by
the envelope's `codec` field. This spec does not define sketch payload encodings; those
belong to `godwit-sketch` and are versioned by `codec` and `schema_version` inside the
envelope header.

**Blob properties.**

| Key | Value |
|---|---|
| `godwit.envelope` | The envelope's non-payload fields, as canonical JSON. |

`godwit.envelope` is the result of `envelope.model_dump(mode="json", exclude={"payload"})`
rendered through `canonical_json`. It contains `kind`, `codec`, `schema_version`,
`payload_digest`, `sensitivity`, `provenance`, `population`, `error_bound`, `params`,
`source_id`, `snapshot_id`, `produced_for` and `produced_at`.

Reconstructing the envelope is `{**json.loads(properties["godwit.envelope"]),
"payload": blob.payload}` passed to `SketchEnvelope.model_validate`, which is what
`blob_to_sketch_envelope` does. Validation is not skipped: the envelope's own invariants,
including the one that refuses an item-bearing sketch declaring itself a derived
statistic, run again on the way back in.

**`fields`.** The Iceberg field id of the column the sketch summarises, or empty for a
table-level measurement.

**Sensitivity.** `godwit.envelope` restates the sensitivity the envelope declared.
`count_min` and `frequent_items` payloads **contain row values** and must declare
`data_value` (or `token`, once the gate has substituted the items).
`sketch_envelope_blob` refuses to write one that claims to be a derived statistic --
contracts check this on construction, and the codec checks it again because a Puffin file
outlives the process that wrote it and is the one artifact here a human might copy out.

---

## Where these files live, and why they are not registered

Iceberg lets a table's metadata list its statistics files, and an engine then finds them
without being told where to look. **Godwit does not register its Puffin files that way.**

pyiceberg 0.12 types the registered blob type as a two-member `Literal`:

```python
class BlobMetadata(IcebergBaseModel):
    type: Literal["apache-datasketches-theta-v1", "deletion-vector-v1"]
```

Registering a `godwit-` blob in `StatisticsFile.blob_metadata` therefore makes the whole
table's metadata fail to parse -- for pyiceberg, and so for us. The Iceberg spec itself
says the field is a string, so this is a pyiceberg limitation rather than a format one,
and it may lift.

Until it does, `IcebergAdapter.write_statistics` writes the file to a caller-chosen
location beside the table and returns that location. The caller addresses it by path.
This loses discovery and keeps the property that actually matters -- every other engine
ignores our blobs, because it never sees them at all.

**If you are implementing against this spec:** read Godwit blobs from a location you were
given, not from `table.metadata.statistics`.

---

## Reading other people's blobs

`godwit-source` reads one standard type:

**`apache-datasketches-theta-v1`** -- the distinct count lives in the blob's
`properties["ndv"]` as a decimal string. `IcebergAdapter` reads it from the registered
statistics file for a snapshot and maps it to `fields[0]`, giving
`ColumnMetadata.distinct_estimate` and feeding `ndv_ratio_shift`. The payload is never
parsed; the property is a `DERIVED_STATISTIC` and that is all that is wanted.

A missing statistics file is normal and not an error -- most tables have never had
`ANALYZE` run on them. The NDV stays `None` and `ndv_ratio_shift` stays quiet, which is
the honest outcome rather than a guess.

---

## Conformance

`packages/godwit-source/tests/test_puffin.py`:

* **Round-trip under hypothesis.** Arbitrary payloads, field lists, snapshot ids and
  properties survive write-then-read intact.
* **Determinism.** The same blobs produce the same bytes.
* **Foreign reader.** A file written by `write_puffin` is parsed by pyiceberg's own
  `PuffinFile`: the footer reads, the properties read, both payloads retrieve by offset,
  and an engine filtering on the types it knows steps over the `godwit-` one.
* **Golden envelopes.** A0's three `tests/golden/sketch_envelopes.json` shapes -- a pure
  statistic, an opaque summary, and an item-bearing sketch -- survive a trip through a
  blob with their sensitivity intact.

---

## Version history

| Version | Change |
|---|---|
| v1 | Initial. `godwit-sketch-envelope-v1`. |
