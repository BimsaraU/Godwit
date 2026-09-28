"""The label ledger, attacked.

**Acceptance criterion.** *"An adversarial test trying several routes to a label with
``label_time`` after the requested instant, failing on all."*

The scenario is the one from the golden classification fixture: a chargeback lands 45
days after the transaction. A model trained "as of" the transaction date must not be
able to see it, by any route. The routes tried here are the ones a real pipeline
actually takes, in the order somebody reaches for them when the first one is
inconvenient:

1. the ordinary listing,
2. the per-entity lookup, which is the one that tempts an implementation into ordering
   before filtering,
3. the aggregate, on the grounds that a count "is not really data",
4. the ``LabelSet`` builder, whose result gets passed around and serialised,
5. ``LabelSet.visible_as_of`` on the object that came back, in case the filter was only
   applied at the edge,
6. the coverage query, which must not reveal a label's existence either.

A leak needs only one unfiltered route.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from godwit_contracts import (
    Acquisition,
    CoverageScope,
    Instant,
    Label,
    Segment,
    data_value,
)
from godwit_store.errors import UncoveredRegionError
from godwit_store.labels import LabelLedger, entity_pseudonym
from sqlalchemy.orm import Session

_ENTITY = "customer"
_CHARGEBACK_LAG = _dt.timedelta(days=45)


def _label(entity: str, *, event_time: Instant, lag: _dt.timedelta, value: bool) -> Label:
    """One label with the two timestamps that matter.

    ``entity_id`` and ``value`` are both row values -- an entity id identifies a person
    and the label is a fact about them -- so both are tainted ``DATA_VALUE``.
    """
    return Label(
        entity_id=data_value(entity, acquisition=Acquisition.USER_SUPPLIED, column="customer_id"),
        value=data_value(value, acquisition=Acquisition.USER_SUPPLIED, column="is_fraud"),
        event_time=event_time,
        label_time=event_time + lag,
        source="chargeback_feed",
    )


@pytest.fixture
def ledger(session: Session, at: Instant) -> LabelLedger:
    """A ledger holding one label that arrives 45 days after its event.

    Also one that arrived immediately, so that a filter which returns *nothing* passes
    for the wrong reason.
    """
    active = LabelLedger(session)
    active.record_coverage(
        CoverageScope(
            entity_type=_ENTITY,
            population=Segment(),
            complete_from=at,
            complete_to=at + _dt.timedelta(days=365),
            is_exhaustive=True,
        ),
        coverage_id="cov_1",
        source="chargeback_feed",
        at=at,
    )
    active.record_labels(
        [
            _label("entity_known", event_time=at, lag=_dt.timedelta(0), value=False),
            _label("entity_future", event_time=at, lag=_CHARGEBACK_LAG, value=True),
        ],
        entity_type=_ENTITY,
        coverage_id="cov_1",
        at=at,
    )
    return active


def _future_key() -> str:
    return entity_pseudonym(
        data_value("entity_future", acquisition=Acquisition.USER_SUPPLIED, column="customer_id")
    )


# ------------------------------------------------------------------------------------
# The six routes
# ------------------------------------------------------------------------------------


def test_route_one_the_ordinary_listing(ledger: LabelLedger, at: Instant) -> None:
    visible = ledger.visible_as_of(instant=at, entity_type=_ENTITY)
    assert len(visible) == 1, "the filter must not simply return everything"
    assert visible[0].entity_id.value == "entity_known"


def test_route_two_the_per_entity_lookup(ledger: LabelLedger, at: Instant) -> None:
    """The route that tempts an implementation into ordering before filtering.

    "Take the newest row, then check its label_time" returns ``None`` here, which looks
    like a pass. "Filter, then take the newest" returns the label that was current,
    which is the right answer. Both are asserted, because only one of them is correct
    for an entity that also has an older visible label.
    """
    assert (
        ledger.latest_for_entity(instant=at, entity_type=_ENTITY, entity_key=_future_key()) is None
    )
    later = ledger.latest_for_entity(
        instant=at + _CHARGEBACK_LAG,
        entity_type=_ENTITY,
        entity_key=_future_key(),
    )
    assert later is not None
    assert later.value.value is True


def test_route_three_the_aggregate(ledger: LabelLedger, at: Instant) -> None:
    """A count is a read. "How many labels will this eventually have" is future knowledge."""
    assert ledger.count_as_of(instant=at, entity_type=_ENTITY) == 1
    assert ledger.count_as_of(instant=at + _CHARGEBACK_LAG, entity_type=_ENTITY) == 2


def test_route_four_the_label_set_builder(ledger: LabelLedger, at: Instant) -> None:
    """A ``LabelSet`` gets passed around and serialised; it must not carry the future."""
    label_set = ledger.label_set(instant=at, entity_type=_ENTITY, coverage_id="cov_1")
    assert len(label_set.labels) == 1
    assert all(label.label_time <= at for label in label_set.labels)


def test_route_five_the_contract_filter_on_what_came_back(ledger: LabelLedger, at: Instant) -> None:
    """Filtering at the edge is not enough if the object itself is full of future labels."""
    label_set = ledger.label_set(instant=at, entity_type=_ENTITY, coverage_id="cov_1")
    assert label_set.visible_as_of(instant=at + _dt.timedelta(days=3650)) == label_set.labels


def test_route_six_coverage_does_not_reveal_a_labels_existence(
    ledger: LabelLedger, at: Instant
) -> None:
    """Coverage answers "may I compute a metric here", never "is there a label there"."""
    verdict = ledger.coverage_at(instant=at, entity_type=_ENTITY)
    rendered = verdict.model_dump_json()
    assert "entity_future" not in rendered
    assert "is_fraud" not in rendered


def test_no_read_path_takes_a_default_instant() -> None:
    """The design, asserted rather than assumed.

    Every method that can return a label requires ``instant`` keyword-only with no
    default. The most common leakage bug in the industry is a pipeline that quietly
    used "now"; this is what makes writing that bug impossible here rather than merely
    discouraged.
    """
    import inspect

    for name in ("visible_as_of", "latest_for_entity", "count_as_of", "label_set"):
        parameter = inspect.signature(getattr(LabelLedger, name)).parameters["instant"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, name
        assert parameter.default is inspect.Parameter.empty, name


# ------------------------------------------------------------------------------------
# Coverage
# ------------------------------------------------------------------------------------


def test_a_metric_over_an_uncovered_period_is_refused(session: Session, at: Instant) -> None:
    ledger = LabelLedger(session)
    ledger.record_coverage(
        CoverageScope(
            entity_type=_ENTITY,
            complete_from=at,
            complete_to=at + _dt.timedelta(days=30),
            is_exhaustive=True,
        ),
        coverage_id="cov_1",
        source="chargeback_feed",
        at=at,
    )
    ledger.assert_covered(
        entity_type=_ENTITY, window_from=at, window_to=at + _dt.timedelta(days=30)
    )
    with pytest.raises(UncoveredRegionError, match="nobody promised"):
        ledger.assert_covered(
            entity_type=_ENTITY, window_from=at, window_to=at + _dt.timedelta(days=60)
        )


def test_two_adjacent_windows_do_not_silently_cover_the_gap(session: Session, at: Instant) -> None:
    """ "We have labels for that quarter" must not become true by stitching.

    Coverage of a period requires one declaration that spans it. Two windows with a day
    between them cover neither the gap nor, honestly, the period.
    """
    ledger = LabelLedger(session)
    for index, (start, end) in enumerate(
        ((0, 30), (31, 60)),
    ):
        ledger.record_coverage(
            CoverageScope(
                entity_type=_ENTITY,
                complete_from=at + _dt.timedelta(days=start),
                complete_to=at + _dt.timedelta(days=end),
                is_exhaustive=True,
            ),
            coverage_id=f"cov_{index}",
            source="chargeback_feed",
            at=at,
        )
    verdict = ledger.coverage_over(
        entity_type=_ENTITY, window_from=at, window_to=at + _dt.timedelta(days=60)
    )
    assert not verdict.covered


def test_non_exhaustive_coverage_means_unlabelled_is_unknown(session: Session, at: Instant) -> None:
    """The distinction a trainer needs. Treating unknown as negative is training on noise."""
    ledger = LabelLedger(session)
    ledger.record_coverage(
        CoverageScope(
            entity_type=_ENTITY,
            complete_from=at,
            complete_to=at + _dt.timedelta(days=30),
            is_exhaustive=False,
        ),
        coverage_id="cov_partial",
        source="manual_review",
        at=at,
    )
    verdict = ledger.coverage_over(
        entity_type=_ENTITY, window_from=at, window_to=at + _dt.timedelta(days=30)
    )
    assert verdict.covered
    assert not verdict.exhaustive
    assert "unknown" in verdict.reason

    with pytest.raises(UncoveredRegionError):
        ledger.assert_covered(
            entity_type=_ENTITY,
            window_from=at,
            window_to=at + _dt.timedelta(days=30),
            require_exhaustive=True,
        )


def test_a_label_set_without_a_coverage_declaration_is_refused(
    session: Session, at: Instant
) -> None:
    ledger = LabelLedger(session)
    with pytest.raises(UncoveredRegionError, match="negative or an unknown"):
        ledger.label_set(instant=at, entity_type=_ENTITY, coverage_id="cov_missing")


# ------------------------------------------------------------------------------------
# Storage
# ------------------------------------------------------------------------------------


def test_the_same_label_delivered_twice_is_stored_once(session: Session, at: Instant) -> None:
    ledger = LabelLedger(session)
    labels = [_label("entity_a", event_time=at, lag=_CHARGEBACK_LAG, value=True)]
    assert ledger.record_labels(labels, entity_type=_ENTITY, coverage_id=None, at=at) == 1
    assert ledger.record_labels(labels, entity_type=_ENTITY, coverage_id=None, at=at) == 0


def test_the_entity_key_is_a_pseudonym_not_the_identifier(at: Instant) -> None:
    """A pseudonym, and documented as one: over a guessable id space it is enumerable."""
    tainted = data_value(
        "customer_00417", acquisition=Acquisition.USER_SUPPLIED, column="customer_id"
    )
    key = entity_pseudonym(tainted)
    assert "customer_00417" not in key
    assert key == entity_pseudonym(tainted), "two processes must agree, so it is unsalted"


def test_a_statistic_is_not_an_entity_id() -> None:
    from godwit_contracts import derived_statistic

    with pytest.raises(ValueError, match="not a statistic"):
        entity_pseudonym(derived_statistic("0.5"))  # type: ignore[arg-type]
