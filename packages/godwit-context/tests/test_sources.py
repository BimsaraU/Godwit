"""Context source adapters: imports, webhooks, DQ signals and annotations."""

from __future__ import annotations

import datetime as _dt

import pytest
from _context_support import T0, candidate
from godwit_context import (
    AnnotationBook,
    ContextImportError,
    ContextSource,
    ContextType,
    MemoryAuditSink,
    StaticSource,
    collect_events,
    data_quality_from_candidates,
    import_csv,
    import_records,
    parse_deploy_webhook,
)
from godwit_contracts import Sensitivity, SourceId

PASTED_ROW = "ACME_CORP refund batch for jane.doe@example.com"


def test_csv_import_builds_scoped_tainted_events() -> None:
    text = (
        "id,start,end,kind,source_ids,columns,segment,label\n"
        f"c1,2024-03-01T09:00:00+01:00,2024-03-08T00:00:00Z,spring_sale,src_a;src_b,amount,"
        f"channel=web,{PASTED_ROW}\n"
    )
    (event,) = import_csv(text, context_type=ContextType.CAMPAIGN, origin="marketing")
    assert event.kind == "campaign.spring_sale"
    assert event.start == _dt.datetime(2024, 3, 1, 8, tzinfo=_dt.UTC)
    assert event.scope.source_ids == (SourceId("src_a"), SourceId("src_b"))
    assert event.label is not None and event.label.sensitivity is Sensitivity.DATA_VALUE
    assert PASTED_ROW not in repr(event)
    assert event.scope.segments[0].predicates[0].values[0].sensitivity is Sensitivity.DATA_VALUE


def test_import_is_deterministic_and_dedups_by_upstream_id() -> None:
    record = {"id": "rel-42", "start": "2024-03-01T00:00:00Z"}
    first = import_records([record], context_type=ContextType.MARKET, origin="feed")
    second = import_records([record], context_type=ContextType.MARKET, origin="feed")
    assert first == second
    source = StaticSource("feed", first + second)
    assert len(source.events(start=T0 - _dt.timedelta(days=1), end=T0)) == 1


@pytest.mark.parametrize(
    "record",
    [
        {"start": PASTED_ROW},
        {"start": "2024-03-01T00:00:00"},  # naive
        {"start": "2024-03-01T00:00:00Z", "kind": PASTED_ROW},
        {"start": "2024-03-01T00:00:00Z", "segment": PASTED_ROW},
        {},
    ],
)
def test_import_errors_never_echo_the_value(record: dict[str, object]) -> None:
    with pytest.raises(ContextImportError) as caught:
        import_records([record], context_type=ContextType.DEPLOY, origin="x")
    assert PASTED_ROW not in str(caught.value)
    assert "ACME" not in str(caught.value)


def test_deploy_webhook() -> None:
    event = parse_deploy_webhook(
        {
            "deploy_id": "d-1",
            "deployed_at": "2024-03-01T14:00:00Z",
            "source_ids": ["src_a"],
            "columns": ["refund_amount"],
            "description": PASTED_ROW,
        }
    )
    assert event.context_type is ContextType.DEPLOY
    assert event.kind == "deploy.release"
    assert event.start == event.end
    assert event.label is not None and event.label.sensitivity is Sensitivity.DATA_VALUE
    assert PASTED_ROW not in repr(event)


def test_schema_changes_become_data_quality_context_but_not_volume() -> None:
    schema = candidate("dq1", detector="metadata.schema_change")
    volume = candidate("dq2", detector="metadata.row_volume_anomaly")
    (event,) = data_quality_from_candidates([schema, volume])
    assert event.context_type is ContextType.DATA_QUALITY
    assert event.derived_from == "dq1"
    assert event.scope.source_ids == (SourceId("src_a"),)


def test_annotations_are_permanent_and_audited() -> None:
    sink = MemoryAuditSink()
    book = AnnotationBook(sink)
    event = book.annotate(
        author="rev_17",
        at=T0,
        start=T0 - _dt.timedelta(days=3),
        end=T0,
        source_ids=[SourceId("src_a")],
        note=PASTED_ROW,
    )
    assert event.permanent
    assert book.events(start=T0 - _dt.timedelta(days=1), end=T0 + _dt.timedelta(days=400))
    (audited,) = sink.events
    assert audited.action == "context_annotate" and audited.subject_id == event.event_id
    assert PASTED_ROW not in audited.model_dump_json()
    with pytest.raises(ContextImportError):
        book.annotate(author="Jane Doe", at=T0, start=T0, end=T0)


def test_sources_satisfy_the_protocol_and_collect_dedups() -> None:
    events = import_records(
        [{"id": "a", "start": "2024-03-01T00:00:00Z"}], context_type=ContextType.MARKET, origin="m"
    )
    one, two = StaticSource("one", events), StaticSource("two", events)
    assert isinstance(one, ContextSource)
    assert len(collect_events([one, two], start=T0 - _dt.timedelta(days=1), end=T0)) == 1
