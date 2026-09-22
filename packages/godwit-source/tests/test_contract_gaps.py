"""The three places the contract could not express what this package needed.

Universal rule 2: do not fix a contract, file a change request, implement against it as
written, and leave a failing test showing what you needed. These are those tests. Each
one is written as though its change request had been accepted, so that accepting it is a
matter of deleting the ``xfail`` marker and watching the test pass.

* ``CR-A1-sketch-serialise-needs-context``
* ``CR-A1-evidence-kind-has-no-schema-change``
* ``CR-A1-source-kind-has-no-warehouse``

Every one of them is a single enum member or a single signature. None of them changes
``segment_key`` or ``probe_key``, so none is a key migration.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from godwit_contracts.discovery import EvidenceKind
from godwit_contracts.source import SourceKind
from godwit_source.detectors import schema_change

from .test_detectors import column, metadata, run


@pytest.mark.xfail(reason="CR-A1-sketch-serialise-needs-context", strict=True)
def test_a_sketch_can_serialise_itself() -> None:
    """``Sketch.serialise()`` should be able to produce a valid envelope.

    It takes no arguments, and a ``SketchEnvelope`` needs seven fields that a sketching
    algorithm has no way to know: the source, the snapshot, the probe key, the instant,
    the provenance, and through those the sensitivity and the population.

    What this package does instead: ``godwit_source.sketches.SketchBuilder``, a local
    injection point that takes the context explicitly. If the CR lands, that module is
    deleted and the adapters call ``serialise(...)`` directly.
    """
    from inspect import signature

    from godwit_contracts.protocols import Sketch

    parameters = set(signature(Sketch.serialise).parameters) - {"self"}
    assert parameters >= {
        "source_id",
        "snapshot_id",
        "produced_for",
        "produced_at",
        "provenance",
    }


@pytest.mark.xfail(reason="CR-A1-evidence-kind-has-no-schema-change", strict=True)
def test_schema_change_has_an_evidence_kind() -> None:
    """A schema change is an observed event, not a statistical claim.

    ``EvidenceKind`` has no member for it, so ``schema_change`` reports ``RATE_CHANGE``
    with a p-value of zero. That validates and stores fine; what it costs is A8, whose
    whole job is finding the deploy or schema change that explains away the drift found
    at the same snapshot, and which currently has to match on a detector-name string.
    """
    assert hasattr(EvidenceKind, "SCHEMA_CHANGE")


def test_schema_change_reports_rate_change_until_then() -> None:
    """The implementation against the contract as written. Not an xfail: this passes."""
    history = [
        metadata(0, [column("amount"), column("patient_hiv_status")]),
        metadata(1, [column("amount"), column("patient_hiv_status")]),
        metadata(2, [column("amount")]),
    ]
    found = run(schema_change, history)
    assert len(found) == 1
    evidence = found[0].evidence[0]
    assert evidence.kind is EvidenceKind.RATE_CHANGE
    assert evidence.p_value is not None
    assert evidence.p_value.reveal() == 0.0
    assert evidence.statistic.reveal() == 1.0


@pytest.mark.xfail(reason="CR-A1-source-kind-has-no-warehouse", strict=True)
def test_a_warehouse_source_has_a_kind() -> None:
    """A Snowflake table has no honest ``SourceKind`` to declare.

    ``WarehouseSqlAdapter`` therefore accepts ``DUCKDB``, ``PARQUET`` and ``POSTGRES``,
    which means the kind no longer selects an adapter -- ``POSTGRES`` is accepted by
    two of them. Registering a Snowflake source means writing down something untrue in
    a field that ends up in a lineage record.
    """
    assert hasattr(SourceKind, "WAREHOUSE_SQL")


def test_the_warehouse_adapter_accepts_what_exists_until_then() -> None:
    """The implementation against the contract as written. Not an xfail: this passes."""
    from godwit_source.warehouse import WarehouseSqlAdapter

    accepted = {SourceKind.DUCKDB, SourceKind.PARQUET, SourceKind.POSTGRES}
    for kind in SourceKind:
        source = _source(kind)
        if kind in accepted:
            WarehouseSqlAdapter._require_warehouse(source)
        else:
            with pytest.raises(Exception, match="SQL-reachable"):
                WarehouseSqlAdapter._require_warehouse(source)


def _source(kind: SourceKind) -> object:
    from godwit_contracts.common import SourceId
    from godwit_contracts.source import SourceRef
    from godwit_contracts.taint import schema_name

    identifier = SourceId("gap")
    return SourceRef(
        source_id=identifier,
        kind=kind,
        catalog="gap",
        namespace=schema_name("ns", source_id=identifier),
        table=schema_name("t", source_id=identifier),
    )


def test_the_change_requests_are_filed() -> None:
    """A CR that was never written is a contract two packages now disagree about."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3] / "docs" / "change-requests"
    for slug in (
        "CR-A1-sketch-serialise-needs-context",
        "CR-A1-evidence-kind-has-no-schema-change",
        "CR-A1-source-kind-has-no-warehouse",
    ):
        document = root / f"{slug}.md"
        assert document.exists(), f"{slug} is referenced by an xfail but was never filed"
        text = document.read_text(encoding="utf-8")
        assert "## The smallest sufficient change" in text
        assert "## Who else this affects" in text


def test_the_frozen_instant_is_the_only_clock_these_tests_use() -> None:
    """A reminder in test form: universal rule 5 applies to tests too."""
    assert _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC).tzinfo is _dt.UTC
