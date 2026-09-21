"""``ManifestReader`` backed by pyiceberg against a REST catalog.

DATA PLANE. Imports pyiceberg lazily so the rest of the package -- detectors, profiling,
access policy, Puffin -- stays importable and testable without a catalog. Manifests and
Puffin metadata are read through the table's own ``FileIO``, straight from object storage;
no query engine is involved and nothing is billed by a warehouse.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import only for type checking
    from pyiceberg.catalog import Catalog
    from pyiceberg.schema import Schema
    from pyiceberg.table import Table
    from pyiceberg.types import IcebergType

from .base import SnapshotRef
from .iceberg import DataFileStats, SchemaField

__all__ = ["PyIcebergManifestReader"]

_ADDED = 1


def _decode_bounds(
    raw: Mapping[int, bytes] | None, types: Mapping[int, IcebergType]
) -> dict[int, object]:
    """Decode Iceberg's binary single-value bounds using each field's own type.

    A bound that fails to decode is dropped rather than guessed at: a mis-decoded bound is a
    wrong row value, which is worse than a missing one in both directions -- it can trigger
    a false pattern and it can be shown to a reviewer as if it were real.
    """
    if not raw:
        return {}
    from pyiceberg.conversions import from_bytes
    from pyiceberg.types import PrimitiveType

    out: dict[int, object] = {}
    for field_id, payload in raw.items():
        field_type = types.get(field_id)
        if not isinstance(field_type, PrimitiveType):
            # Only primitives carry single-value bounds; a struct, map or list has none.
            continue
        try:
            out[field_id] = from_bytes(field_type, payload)
        except Exception:
            continue
    return out


class PyIcebergManifestReader:
    """Reads snapshots, schema, manifest statistics and Puffin NDV for one catalog."""

    def __init__(self, catalog: Catalog) -> None:
        self._catalog = catalog

    def _table(self, table: str) -> Table:
        return self._catalog.load_table(table)

    def snapshots(self, table: str) -> Sequence[SnapshotRef]:
        tbl = self._table(table)
        return [
            SnapshotRef(
                snapshot_id=str(s.snapshot_id),
                sequence_number=int(getattr(s, "sequence_number", 0) or 0),
                commit_ms=int(s.timestamp_ms),
                parent_id=None if s.parent_snapshot_id is None else str(s.parent_snapshot_id),
            )
            for s in tbl.snapshots()
        ]

    def _schema_at(self, table: str, snapshot_id: str) -> Schema:
        """The schema as of one snapshot, falling back to the table's current schema.

        ``Snapshot.schema_id`` is optional in the Iceberg spec and is absent on tables
        written before per-snapshot schema tracking. Falling back keeps an older table
        readable instead of failing the whole metadata pass on a missing field.
        """
        tbl = self._table(table)
        snapshot = tbl.snapshot_by_id(int(snapshot_id))
        schema_id = None if snapshot is None else snapshot.schema_id
        if schema_id is None:
            return tbl.schema()
        return tbl.schemas()[schema_id]

    def schema(self, table: str, snapshot_id: str) -> Sequence[SchemaField]:
        return [
            SchemaField(field_id=f.field_id, name=f.name, data_type=str(f.field_type))
            for f in self._schema_at(table, snapshot_id).fields
        ]

    def _field_types(self, table: str, snapshot_id: str) -> dict[int, IcebergType]:
        return {f.field_id: f.field_type for f in self._schema_at(table, snapshot_id).fields}

    def data_files(
        self, table: str, snapshot_id: str, *, delta_only: bool = True
    ) -> Sequence[DataFileStats]:
        """Manifest entries for a snapshot.

        ``delta_only`` keeps only the files this snapshot added, which is what turns a
        sequence of snapshots into a time-series of new data rather than a sequence of
        slowly-moving full-table aggregates.
        """
        tbl = self._table(table)
        snapshot = tbl.snapshot_by_id(int(snapshot_id))
        if snapshot is None:
            raise KeyError(f"snapshot {snapshot_id!r} not found")
        types = self._field_types(table, snapshot_id)
        io = tbl.io
        out: list[DataFileStats] = []
        for manifest in snapshot.manifests(io):
            for entry in manifest.fetch_manifest_entry(io, discard_deleted=True):
                if delta_only and int(getattr(entry, "status", _ADDED)) != _ADDED:
                    continue
                df = entry.data_file
                out.append(
                    DataFileStats(
                        path=str(df.file_path),
                        file_size_in_bytes=int(df.file_size_in_bytes or 0),
                        record_count=int(df.record_count or 0),
                        value_counts=dict(df.value_counts or {}),
                        null_value_counts=dict(df.null_value_counts or {}),
                        lower_bounds=_decode_bounds(df.lower_bounds, types),
                        upper_bounds=_decode_bounds(df.upper_bounds, types),
                    )
                )
        return out

    def puffin_ndv(self, table: str, snapshot_id: str) -> Mapping[int, int]:
        """NDV per field from the Theta sketch blob's ``ndv`` property.

        Read from the statistics-file metadata in the table metadata, not by downloading
        and deserialising the sketch: the property is there precisely so a reader can get
        the number without paying for the blob.
        """
        tbl = self._table(table)
        wanted = int(snapshot_id)
        out: dict[int, int] = {}
        for stats_file in getattr(tbl.metadata, "statistics", []) or []:
            if int(stats_file.snapshot_id) != wanted:
                continue
            for blob in stats_file.blob_metadata:
                ndv = (blob.properties or {}).get("ndv")
                if ndv is None:
                    continue
                for field_id in blob.fields:
                    try:
                        out[int(field_id)] = int(ndv)
                    except (TypeError, ValueError):
                        continue
        return out
