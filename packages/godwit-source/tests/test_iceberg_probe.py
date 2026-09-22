"""The paid tier on Iceberg: budgets, segments, projection, and Puffin write-back.

Everything here reads table data, which is the point: it is the path the metadata tier
exists to avoid, and the one that has to refuse rather than overspend.

The sketch builder is a stub. This package owns no sketch code -- a stated non-goal --
so what is checked is what the adapter is responsible for: that the budget was charged
from the manifest *before* anything opened, that only the named columns crossed, that
the segment filtered, and that nothing but envelopes came back.
"""

from __future__ import annotations

import datetime as _dt
from decimal import Decimal
from pathlib import Path

import pytest
from godwit_contracts.common import SourceId
from godwit_contracts.cost import CostBudget
from godwit_contracts.errors import BudgetExceededError
from godwit_contracts.probe import ProbeId, ProbeKind, ProbeSpec
from godwit_contracts.segment import Operator, Predicate, Segment
from godwit_contracts.sketch import SketchKind
from godwit_contracts.source import SourceKind, SourceRef
from godwit_contracts.taint import Acquisition, data_value, schema_name
from godwit_source.errors import UnsupportedProbeError, UnsupportedSourceError
from godwit_source.iceberg import IcebergAdapter
from godwit_source.objectstore import ByteMeter, ReadClass, classify_location
from godwit_source.puffin import read_puffin, sketch_envelope_blob
from pyiceberg.catalog import Catalog

from .conftest import StubSketchBuilder

AS_OF = _dt.datetime(2024, 1, 15, tzinfo=_dt.UTC)

TIGHT = CostBudget(
    bytes_scanned=1024,
    wall_seconds=60.0,
    usd=Decimal("1"),
    llm_tokens=0,
    train_seconds=0.0,
)


def spec(
    source: SourceRef,
    *,
    kind: ProbeKind = ProbeKind.CATEGORY_HISTOGRAM,
    columns: tuple[str, ...] = ("country",),
    segment: Segment | None = None,
    budget: CostBudget,
) -> ProbeSpec:
    return ProbeSpec(
        probe_id=ProbeId("probe"),
        kind=kind,
        spec_version=1,
        source=source,
        columns=tuple(
            schema_name(name, source_id=source.source_id, table="orders") for name in columns
        ),
        segment=segment if segment is not None else Segment(),
        sketches=(SketchKind.FREQUENT_ITEMS,),
        params={"top_k": 10},
        budget=budget,
        seed=5,
        as_of=AS_OF,
    )


def test_a_probe_reads_only_the_named_columns(
    golden_catalog: Catalog,
    golden_source: SourceRef,
    generous_budget: CostBudget,
    stub_builder: StubSketchBuilder,
) -> None:
    meter = ByteMeter()
    adapter = IcebergAdapter(golden_catalog, meter=meter, sketch_builder=stub_builder)
    snapshot = adapter.list_snapshots(golden_source)[-1]

    bundle = adapter.execute_probe(
        spec(golden_source, budget=generous_budget), snapshot, budget=generous_budget
    )

    assert set(bundle.sketches) == {"frequent_items:0"}
    assert bundle.seed == 5
    assert bundle.produced_at == AS_OF
    assert bundle.snapshot_id == snapshot.snapshot_id
    assert meter.data_bytes > 0, "a probe of this kind has to read data"
    assert bundle.cost_spent.bytes_scanned == meter.data_bytes

    kind, values, population = stub_builder.calls[0]
    assert kind is SketchKind.FREQUENT_ITEMS
    assert values is not None
    assert values.column_names == ["value", "count"]
    assert population == 18_000


def test_a_segment_filters_before_the_sketch_sees_anything(
    golden_catalog: Catalog,
    golden_source: SourceRef,
    generous_budget: CostBudget,
    stub_builder: StubSketchBuilder,
) -> None:
    """The documented drift's segment. ``PT`` is about 18% of the last snapshot."""
    adapter = IcebergAdapter(
        golden_catalog,
        meter=ByteMeter(),
        sketch_builder=stub_builder,
    )
    snapshot = adapter.list_snapshots(golden_source)[-1]
    segment = Segment(
        predicates=(
            Predicate(
                column=schema_name("country", source_id=golden_source.source_id, table="orders"),
                op=Operator.EQ,
                values=(data_value("PT", acquisition=Acquisition.SEGMENT_PREDICATE),),
            ),
        )
    )
    adapter.execute_probe(
        spec(golden_source, columns=("amount",), segment=segment, budget=generous_budget),
        snapshot,
        budget=generous_budget,
    )
    _, values, population = stub_builder.calls[0]
    assert values is not None
    assert 0 < population < 18_000
    assert values.num_rows == population


def test_a_probe_refuses_before_it_opens_anything(
    golden_catalog: Catalog,
    golden_source: SourceRef,
    generous_budget: CostBudget,
    stub_builder: StubSketchBuilder,
) -> None:
    """Invariant 6: the estimate comes from the manifest, before the first byte moves."""
    meter = ByteMeter()
    adapter = IcebergAdapter(golden_catalog, meter=meter, sketch_builder=stub_builder)
    snapshot = adapter.list_snapshots(golden_source)[-1]
    before = meter.data_bytes

    with pytest.raises(BudgetExceededError, match="bytes_scanned"):
        adapter.execute_probe(spec(golden_source, budget=generous_budget), snapshot, budget=TIGHT)

    assert meter.data_bytes == before, "data was read despite the refusal"
    assert stub_builder.calls == []


def test_the_spec_budget_composes_with_the_callers(
    golden_catalog: Catalog,
    golden_source: SourceRef,
    generous_budget: CostBudget,
    stub_builder: StubSketchBuilder,
) -> None:
    """Composition can only shrink a budget. A generous caller cannot widen a tight spec."""
    adapter = IcebergAdapter(
        golden_catalog,
        meter=ByteMeter(),
        sketch_builder=stub_builder,
    )
    snapshot = adapter.list_snapshots(golden_source)[-1]
    with pytest.raises(BudgetExceededError):
        adapter.execute_probe(spec(golden_source, budget=TIGHT), snapshot, budget=generous_budget)


def test_the_metadata_path_also_refuses_rather_than_overspends(
    golden_catalog: Catalog, golden_source: SourceRef
) -> None:
    """Manifests are files too. Reading ten thousand of them is not free either."""
    adapter = IcebergAdapter(golden_catalog, meter=ByteMeter())
    snapshot = adapter.list_snapshots(golden_source)[-1]
    no_budget = TIGHT.model_copy(update={"bytes_scanned": 0})
    with pytest.raises(BudgetExceededError, match="bytes_scanned"):
        adapter.read_metadata_stats(golden_source, snapshot, budget=no_budget)


def test_a_probe_without_a_builder_refuses(
    golden_catalog: Catalog, golden_source: SourceRef, generous_budget: CostBudget
) -> None:
    adapter = IcebergAdapter(golden_catalog, meter=ByteMeter())
    snapshot = adapter.list_snapshots(golden_source)[-1]
    with pytest.raises(UnsupportedProbeError, match="SketchBuilder"):
        adapter.execute_probe(
            spec(golden_source, budget=generous_budget), snapshot, budget=generous_budget
        )


def test_a_non_iceberg_source_is_refused(golden_catalog: Catalog) -> None:
    adapter = IcebergAdapter(golden_catalog, meter=ByteMeter())
    other = SourceId("elsewhere")
    postgres = SourceRef(
        source_id=other,
        kind=SourceKind.POSTGRES,
        catalog="x",
        namespace=schema_name("ns", source_id=other),
        table=schema_name("t", source_id=other),
    )
    with pytest.raises(UnsupportedSourceError, match="cannot read"):
        adapter.list_snapshots(postgres)


def test_snapshot_delta_walks_the_parent_chain(
    golden_catalog: Catalog, golden_source: SourceRef
) -> None:
    adapter = IcebergAdapter(golden_catalog, meter=ByteMeter())
    snapshots = adapter.list_snapshots(golden_source)
    delta = adapter.snapshot_delta(
        golden_source, since=snapshots[0].snapshot_id, until=snapshots[-1].snapshot_id
    )
    assert delta == (snapshots[1].snapshot_id, snapshots[2].snapshot_id)


def test_a_delta_read_sees_only_the_files_that_were_added(
    golden_catalog: Catalog, golden_source: SourceRef, generous_budget: CostBudget
) -> None:
    """Incremental support: statistics over the files added between X and Y."""
    adapter = IcebergAdapter(golden_catalog, meter=ByteMeter())
    snapshots = adapter.list_snapshots(golden_source)
    whole = adapter.read_metadata_stats(golden_source, snapshots[-1], budget=generous_budget)
    delta = adapter.read_metadata_stats(
        golden_source, snapshots[-1], budget=generous_budget, since=snapshots[-2].snapshot_id
    )

    assert whole.row_count is not None
    assert delta.row_count is not None
    assert whole.row_count.reveal() == 18_000
    assert delta.row_count.reveal() == 6_000
    assert delta.is_delta is True
    assert delta.baseline_snapshot_id == snapshots[-2].snapshot_id
    assert delta.layout is not None
    assert delta.layout.file_count.reveal() == 1


def test_puffin_statistics_round_trip_through_the_adapter(
    golden_catalog: Catalog,
    golden_source: SourceRef,
    generous_budget: CostBudget,
    stub_builder: StubSketchBuilder,
    tmp_path: Path,
) -> None:
    """Write a Godwit blob beside the table and read it back with our own reader."""
    adapter = IcebergAdapter(
        golden_catalog,
        meter=ByteMeter(),
        sketch_builder=stub_builder,
    )
    snapshot = adapter.list_snapshots(golden_source)[-1]
    bundle = adapter.execute_probe(
        spec(golden_source, budget=generous_budget), snapshot, budget=generous_budget
    )
    envelope = next(iter(bundle.sketches.values()))

    location = f"{tmp_path}/godwit-{snapshot.snapshot_id}.puffin".replace("\\", "/")
    written = adapter.write_statistics(
        golden_source, snapshot, [sketch_envelope_blob(envelope, fields=(1,))], location=location
    )
    assert written == location

    blobs = adapter.read_statistics(golden_source, location=location)
    assert len(blobs) == 1
    assert blobs[0].blob_type == "godwit-sketch-envelope-v1"
    assert blobs[0].payload == envelope.payload

    assert read_puffin(Path(location).read_bytes())[0].payload == envelope.payload


def test_locations_are_classified_conservatively() -> None:
    """An unrecognised extension counts as data. Deny by default applies to accounting."""
    assert classify_location("s3://bucket/data/00000-0-abc.parquet") is ReadClass.DATA
    assert classify_location("s3://bucket/metadata/snap-1.avro") is ReadClass.METADATA
    assert classify_location("s3://bucket/metadata/v3.metadata.json") is ReadClass.METADATA
    assert classify_location("s3://bucket/metadata/stats.puffin") is ReadClass.METADATA
    assert classify_location("s3://bucket/data/part-0.orc") is ReadClass.DATA
    assert classify_location("s3://bucket/who-knows") is ReadClass.DATA
