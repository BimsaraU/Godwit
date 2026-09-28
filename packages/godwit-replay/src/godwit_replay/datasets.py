"""Public dataset loaders, and the label-time assumption behind each one.

**This module runs in the DATA PLANE.** It reads raw rows off disk, writes them into
Iceberg tables and builds label sets. Nothing it returns to a caller contains a row value
except the ``LabelSet``, whose contents are ``Tainted`` and whose entity ids are row
values by definition.

WHAT A LOADER PRODUCES
----------------------
Each dataset becomes **two** Iceberg tables:

* the *event* table, partitioned in commits so that one commit is one period of history,
  with the label column **removed from the schema entirely**;
* the *label* table, carrying ``entity_id``, ``value``, ``event_time`` and ``label_time``.

Dropping the label column from the event table is not tidiness. It is the only structural
guarantee that a replay handler cannot see a label by reading the table, whatever it does
with its budget. Labels reach a handler through ``LabelSet.visible_as_of`` and nowhere
else.

THE LABEL-TIME ASSUMPTION, PER DATASET
--------------------------------------
Three of the four public datasets have no label timestamp. A chargeback lands sixty days
after the transaction; none of these files says when anybody learned anything. So a delay
has to come from somewhere, and where it came from is recorded on every dataset as
``LabelDelay.is_fabricated``.

**A fabricated delay that looks real is worse than no delay at all.** Every fabricated
value here is marked, printed by ``godwit-replay datasets``, echoed in the verdict output
and repeated in ``docs/packages/godwit-replay.md``. If you are quoting a
time-to-detection number from a dataset whose delay is fabricated, the number is a
measurement of our own assumption, not of the world.

| Dataset | Event time | Label | Delay | Fabricated? |
|---|---|---|---|---|
| ``ieee-cis`` | ``TransactionDT`` + anchor | ``isFraud`` | 60 days | **anchor and delay** |
| ``paysim`` | ``step`` hours + anchor | ``isFraud`` | 24 hours | **anchor and delay** |
| ``telco-churn`` | ``tenure`` before anchor | ``Churn`` | 30 days | **anchor and delay** |
| ``nyc-tlc`` | ``tpep_pickup_datetime`` | none | n/a | no labels, which is the point |
| ``golden-drift`` | ``created_at`` | none | n/a | in-repo fixture |
| ``golden-classification`` | ``event_time`` | ``label`` | in the data | **real** |

``golden-classification`` is the only labelled dataset in this list whose label delay is
a real field rather than our invention. That is why the reproducible expert baseline in
:mod:`godwit_replay.baseline` is built against it and why the IEEE-CIS baseline, which is
the one the brief names, carries the anchor assumption in its own record.

RAW FILES ARE NOT REDISTRIBUTED
-------------------------------
Nothing here downloads anything and nothing here ships a copy. Put the files under
``$GODWIT_REPLAY_DATA`` (default ``./data/replay/<dataset>``) and the loader finds them;
leave them out and it raises :class:`DatasetNotAvailableError` naming the file and its
origin. It never substitutes a synthetic stand-in, because a synthetic dataset presented
as a public benchmark is a lie that passes CI.
"""

from __future__ import annotations

import datetime as _dt
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pacsv
import pyarrow.parquet as pq
from godwit_contracts.common import Instant, SourceId, require_utc
from godwit_contracts.discovery import CoverageScope, Label, LabelSet
from godwit_contracts.segment import Segment
from godwit_contracts.source import SourceKind, SourceRef
from godwit_contracts.taint import Acquisition, data_value, schema_name
from pydantic import Field
from pyiceberg.catalog import Catalog
from pyiceberg.catalog.sql import SqlCatalog

from godwit_replay.errors import DatasetNotAvailableError

__all__ = [
    "REGISTRY",
    "DatasetSpec",
    "LabelDelay",
    "LoadedDataset",
    "Period",
    "build_label_set",
    "dataset_root",
    "list_datasets",
    "materialise",
    "missing_files",
    "prepare_table",
    "resolve",
]

from godwit_contracts.common import GodwitModel

_NAMESPACE: Final[str] = "godwit_replay"
_ENV_ROOT: Final[str] = "GODWIT_REPLAY_DATA"
_DEFAULT_ROOT: Final[str] = "data/replay"
_DECEMBER: Final[int] = 12


class Period(StrEnum):
    """How much history one Iceberg commit covers.

    One commit is one snapshot is one replay step. Choosing the period chooses the
    resolution of every time-to-detection number the harness reports, so it is a property
    of the dataset rather than a command-line flag.
    """

    DAY = "day"
    MONTH = "month"
    SNAPSHOT_FILE = "snapshot_file"
    """One commit per raw file, for fixtures that already ship pre-cut snapshots."""


class LabelDelay(GodwitModel):
    """How long after an event its label became known, and where that number came from.

    ``is_fabricated`` is not a footnote. When it is True, every downstream
    time-to-detection figure is measuring our assumption. The harness prints it next to
    the number rather than in a methods section nobody reads.
    """

    delay: _dt.timedelta
    is_fabricated: bool
    note: str = Field(description="Where the delay came from, in one sentence. No hedging.")

    def label_time(self, event_time: Instant) -> Instant:
        """When this label became visible."""
        return event_time + self.delay


class DatasetSpec(GodwitModel):
    """One replayable dataset, fully described before a byte is read."""

    name: str
    title: str
    is_public: bool = Field(
        description="True for a published benchmark whose column names carry no customer "
        "disclosure. Expert baselines may only be recorded for public datasets, because a "
        "baseline record stores feature names and a feature name is a leak path."
    )
    origin: str = Field(description="Where the raw files come from. A URL or 'in-repo fixture'.")
    raw_files: tuple[str, ...]
    period: Period
    event_time_column: str
    entity_id_column: str
    label_column: str | None = None
    label_time_column: str | None = Field(
        default=None,
        description="A real label timestamp in the data. When this is set, label_delay "
        "must be None: we do not invent a delay for data that states one.",
    )
    label_delay: LabelDelay | None = None
    epoch_anchor: Instant | None = Field(
        default=None,
        description="Anchor for datasets whose time column is an offset rather than a "
        "timestamp. Fabricated wherever it appears; see the module docstring.",
    )
    anchor_is_fabricated: bool = False
    drop_columns: tuple[str, ...] = Field(
        default=(),
        description="Columns removed before the event table is written, beyond the label.",
    )
    note: str = ""

    @property
    def is_labelled(self) -> bool:
        """True when this dataset can score anything supervised."""
        return self.label_column is not None

    @property
    def has_honest_label_time(self) -> bool:
        """True when the label delay came out of the data rather than out of us."""
        if self.label_time_column is not None:
            return True
        return self.label_delay is not None and not self.label_delay.is_fabricated

    @property
    def caveats(self) -> tuple[str, ...]:
        """Every fabricated assumption, as sentences fit to print next to a number."""
        found: list[str] = []
        if self.anchor_is_fabricated and self.epoch_anchor is not None:
            found.append(
                f"the calendar anchor {self.epoch_anchor.date().isoformat()} is fabricated: "
                f"{self.event_time_column} is an offset and the data names no start date"
            )
        if self.label_delay is not None and self.label_delay.is_fabricated:
            found.append(f"the label delay is fabricated: {self.label_delay.note}")
        if not self.is_labelled:
            found.append("this dataset has no labels; only unsupervised scoring applies")
        return tuple(found)


_IEEE_ANCHOR: Final[Instant] = _dt.datetime(2017, 12, 1, tzinfo=_dt.UTC)
_PAYSIM_ANCHOR: Final[Instant] = _dt.datetime(2020, 1, 1, tzinfo=_dt.UTC)
_TELCO_ANCHOR: Final[Instant] = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)


REGISTRY: Final[Mapping[str, DatasetSpec]] = {
    spec.name: spec
    for spec in (
        DatasetSpec(
            name="ieee-cis",
            title="IEEE-CIS Fraud Detection",
            is_public=True,
            origin="https://www.kaggle.com/c/ieee-fraud-detection",
            raw_files=("train_transaction.csv",),
            period=Period.MONTH,
            event_time_column="TransactionDT",
            entity_id_column="TransactionID",
            label_column="isFraud",
            label_delay=LabelDelay(
                delay=_dt.timedelta(days=60),
                is_fabricated=True,
                note=(
                    "IEEE-CIS ships no label timestamp. Sixty days is the card-network "
                    "chargeback window, which is a plausible order of magnitude and is not "
                    "a measurement. Every time-to-detection number on this dataset is "
                    "relative to that assumption."
                ),
            ),
            epoch_anchor=_IEEE_ANCHOR,
            anchor_is_fabricated=True,
            note=(
                "Heavy imbalance, real labels, 393 columns. Also the prediction benchmark: "
                "see half_labelled_split in godwit_replay.split."
            ),
        ),
        DatasetSpec(
            name="paysim",
            title="PaySim synthetic mobile money",
            is_public=True,
            origin="https://www.kaggle.com/datasets/ealaxi/paysim1",
            raw_files=("PS_20174392719_1491204439457_log.csv",),
            period=Period.DAY,
            event_time_column="step",
            entity_id_column="nameOrig",
            label_column="isFraud",
            drop_columns=("isFlaggedFraud",),
            label_delay=LabelDelay(
                delay=_dt.timedelta(hours=24),
                is_fabricated=True,
                note=(
                    "PaySim ships no label timestamp. Twenty-four hours stands for a "
                    "same-day mule investigation. Fabricated."
                ),
            ),
            epoch_anchor=_PAYSIM_ANCHOR,
            anchor_is_fabricated=True,
            note=(
                "Mule structure through nameOrig/nameDest, which is the shared-attribute "
                "graph case: both columns are direct identifiers and both are OPAQUE by "
                "default. isFlaggedFraud is dropped because it is another model's output."
            ),
        ),
        DatasetSpec(
            name="telco-churn",
            title="Telco customer churn",
            is_public=True,
            origin="https://www.kaggle.com/datasets/blastchar/telco-customer-churn",
            raw_files=("WA_Fn-UseC_-Telco-Customer-Churn.csv",),
            period=Period.MONTH,
            event_time_column="tenure",
            entity_id_column="customerID",
            label_column="Churn",
            label_delay=LabelDelay(
                delay=_dt.timedelta(days=30),
                is_fabricated=True,
                note=(
                    "Churn is a state, not an event, and the file has no dates at all. "
                    "Thirty days stands for one billing cycle. Fabricated."
                ),
            ),
            epoch_anchor=_TELCO_ANCHOR,
            anchor_is_fabricated=True,
            note=(
                "The slow end of the latency spectrum. Event time is derived from the real "
                "tenure column -- an account with tenure 12 started twelve months before "
                "the anchor -- so the ordering of rows in history is real and only the "
                "calendar position is ours."
            ),
        ),
        DatasetSpec(
            name="nyc-tlc",
            title="NYC TLC yellow taxi trips",
            is_public=True,
            origin="https://www.nyc.gov/site/tlc/about/tlc-trip-record-data.page",
            raw_files=("yellow_tripdata.parquet",),
            period=Period.MONTH,
            event_time_column="tpep_pickup_datetime",
            entity_id_column="VendorID",
            note=(
                "No labels, genuine multi-year drift including regime changes: the 2022 "
                "airport fee, the congestion surcharge, the 2020 collapse in volume. The "
                "unsupervised-only case, and the dataset the kill criterion runs on."
            ),
        ),
        DatasetSpec(
            name="golden-drift",
            title="Golden drift fixture (tests/golden/drift_table)",
            is_public=True,
            origin="in-repo fixture",
            raw_files=("snapshot_0.parquet", "snapshot_1.parquet", "snapshot_2.parquet"),
            period=Period.SNAPSHOT_FILE,
            event_time_column="created_at",
            entity_id_column="order_id",
            note=(
                "Three pre-cut snapshots with documented drift at snap_2 and a documented "
                "false-positive control. The determinism tests run on this."
            ),
        ),
        DatasetSpec(
            name="golden-classification",
            title="Golden half-labelled classification fixture",
            is_public=True,
            origin="in-repo fixture",
            raw_files=("train.parquet", "holdout.parquet"),
            period=Period.SNAPSHOT_FILE,
            event_time_column="event_time",
            entity_id_column="entity_id",
            label_column="label",
            label_time_column="label_time",
            note=(
                "The only labelled dataset here whose label_time is a real field. Carries a "
                "bayes_auc ceiling, so a model that beats it has leaked rather than learned."
            ),
        ),
    )
}


def list_datasets() -> tuple[DatasetSpec, ...]:
    """Every registered dataset, in registration order."""
    return tuple(REGISTRY.values())


def resolve(name: str) -> DatasetSpec:
    """Look a dataset up by name, or say which names exist."""
    try:
        return REGISTRY[name]
    except KeyError:
        known = ", ".join(REGISTRY)
        raise DatasetNotAvailableError(f"unknown dataset {name!r}; known: {known}") from None


def dataset_root(spec: DatasetSpec, *, root: Path | None = None) -> Path:
    """Where this dataset's raw files are expected to live.

    In-repo fixtures resolve against ``tests/golden``; everything else against
    ``$GODWIT_REPLAY_DATA`` or ``./data/replay``.
    """
    if root is not None:
        return root
    if spec.name == "golden-drift":
        return _repo_root() / "tests" / "golden" / "drift_table"
    if spec.name == "golden-classification":
        return _repo_root() / "tests" / "golden" / "classification"
    base = Path(os.environ.get(_ENV_ROOT, _DEFAULT_ROOT))
    return base / spec.name


def _repo_root() -> Path:
    """The workspace root, found by walking up for the uv workspace marker."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "tests" / "golden").is_dir():
            return parent
    raise DatasetNotAvailableError("cannot locate the repository root from this install")


def missing_files(spec: DatasetSpec, *, root: Path | None = None) -> tuple[Path, ...]:
    """Which of this dataset's raw files are absent. Empty means ready to load."""
    base = dataset_root(spec, root=root)
    return tuple(base / name for name in spec.raw_files if not (base / name).is_file())


def require_available(spec: DatasetSpec, *, root: Path | None = None) -> Path:
    """Return the dataset directory, or refuse with the exact files that are missing."""
    absent = missing_files(spec, root=root)
    if absent:
        names = ", ".join(path.name for path in absent)
        raise DatasetNotAvailableError(
            f"{spec.name}: missing {names} under {dataset_root(spec, root=root)}. "
            f"Fetch them from {spec.origin}. Nothing is substituted: a synthetic stand-in "
            "presented as a public benchmark would pass CI and mean nothing."
        )
    return dataset_root(spec, root=root)


# ---------------------------------------------------------------------------------------
# Raw file to event table
# ---------------------------------------------------------------------------------------


def _read_raw(path: Path) -> pa.Table:
    if path.suffix == ".parquet":
        return pq.read_table(path)
    return pacsv.read_csv(path)


def _offset_to_timestamp(
    table: pa.Table, *, column: str, unit: str, anchor: Instant, target: str
) -> pa.Table:
    """Turn an integer offset column into a real UTC timestamp column."""
    seconds_per = {"s": 1, "h": 3600, "d": 86400}[unit]
    offsets = pc.multiply(pc.cast(table.column(column), pa.int64()), seconds_per)
    stamps = pc.add(
        pa.scalar(anchor, type=pa.timestamp("us", tz="UTC")),
        pc.cast(offsets, pa.int64()).cast(pa.duration("s")),
    )
    return table.append_column(target, stamps.cast(pa.timestamp("us", tz="UTC")))


def _anchor(spec: DatasetSpec) -> Instant:
    """The declared calendar anchor, or a refusal naming the dataset that lacks one."""
    if spec.epoch_anchor is None:
        raise DatasetNotAvailableError(
            f"{spec.name}: {spec.event_time_column} is an offset and the spec declares no "
            "epoch_anchor; there is nothing honest to convert it against"
        )
    return spec.epoch_anchor


def _prepare_ieee(table: pa.Table, spec: DatasetSpec) -> pa.Table:
    return _offset_to_timestamp(
        table, column="TransactionDT", unit="s", anchor=_anchor(spec), target="event_time"
    )


def _prepare_paysim(table: pa.Table, spec: DatasetSpec) -> pa.Table:
    return _offset_to_timestamp(
        table, column="step", unit="h", anchor=_anchor(spec), target="event_time"
    )


def _prepare_telco(table: pa.Table, spec: DatasetSpec) -> pa.Table:
    """Tenure in months becomes a start date relative to the anchor.

    ``tenure`` is real data: an account with tenure 24 has been a customer for two years,
    so it started before one with tenure 3. The ordering that history replays in is
    therefore the real one. Only where that ordering sits on a calendar is ours, and the
    spec marks it fabricated.
    """
    anchor = _anchor(spec)
    months = pc.cast(pc.fill_null(table.column("tenure"), 0), pa.int64())
    seconds = pc.multiply(months, 30 * 86400)
    stamps = pc.subtract(
        pa.scalar(anchor, type=pa.timestamp("us", tz="UTC")),
        pc.cast(seconds, pa.int64()).cast(pa.duration("s")),
    )
    prepared = table.append_column("event_time", stamps.cast(pa.timestamp("us", tz="UTC")))
    churn = prepared.column("Churn")
    if pa.types.is_string(churn.type):
        prepared = prepared.set_column(
            prepared.schema.get_field_index("Churn"),
            "Churn",
            pc.cast(pc.equal(churn, "Yes"), pa.int64()),
        )
    return prepared


def _prepare_passthrough(table: pa.Table, spec: DatasetSpec) -> pa.Table:
    """The time column is already a timestamp: rename it to ``event_time``."""
    if spec.event_time_column == "event_time":
        return table
    index = table.schema.get_field_index(spec.event_time_column)
    if index < 0:
        raise DatasetNotAvailableError(
            f"{spec.name}: expected an event-time column named {spec.event_time_column}"
        )
    stamps = pc.cast(table.column(index), pa.timestamp("us", tz="UTC"))
    return table.append_column("event_time", stamps)


_PREPARERS: Final[Mapping[str, Callable[[pa.Table, DatasetSpec], pa.Table]]] = {
    "ieee-cis": _prepare_ieee,
    "paysim": _prepare_paysim,
    "telco-churn": _prepare_telco,
}


def prepare_table(raw: pa.Table, spec: DatasetSpec) -> pa.Table:
    """Give one raw table a real ``event_time`` column, dataset by dataset."""
    preparer = _PREPARERS.get(spec.name, _prepare_passthrough)
    return preparer(raw, spec)


def _period_keys(table: pa.Table, period: Period) -> pa.ChunkedArray:
    fmt = "%Y-%m-%d" if period is Period.DAY else "%Y-%m"
    return pc.strftime(table.column("event_time"), format=fmt)


def _period_end(key: str, period: Period) -> Instant:
    """The instant a period closes: the first moment after its last row could arrive."""
    if period is Period.DAY:
        start = _dt.datetime.strptime(key, "%Y-%m-%d").replace(tzinfo=_dt.UTC)
        return start + _dt.timedelta(days=1)
    start = _dt.datetime.strptime(key, "%Y-%m").replace(tzinfo=_dt.UTC)
    year, month = start.year, start.month
    return (
        _dt.datetime(year + 1, 1, 1, tzinfo=_dt.UTC)
        if month == _DECEMBER
        else _dt.datetime(year, month + 1, 1, tzinfo=_dt.UTC)
    )


@dataclass(frozen=True, slots=True)
class LoadedDataset:
    """A materialised dataset: one Iceberg table, and the instant each commit closed.

    ``clock_instants`` is the load-bearing field. An Iceberg snapshot's ``committed_at``
    is the wall-clock moment the loader ran, which is different on every machine and
    would make every digest unstable. Replay's virtual clock therefore runs on
    ``clock_instants`` -- derived from the *data's* event times -- and no digest anywhere
    in this package includes a commit time.
    """

    spec: DatasetSpec
    source: SourceRef
    catalog_uri: str
    warehouse_uri: str
    period_keys: tuple[str, ...]
    clock_instants: tuple[Instant, ...]
    row_counts: tuple[int, ...]
    labels: LabelSet | None

    @property
    def snapshot_count(self) -> int:
        """How many commits, which is how many replay steps."""
        return len(self.period_keys)


def _source_ref(spec: DatasetSpec) -> SourceRef:
    source_id = SourceId(f"src_{spec.name.replace('-', '_')}")
    return SourceRef(
        source_id=source_id,
        kind=SourceKind.ICEBERG,
        catalog="godwit-replay",
        namespace=schema_name(_NAMESPACE, source_id=source_id),
        table=schema_name(spec.name.replace("-", "_"), source_id=source_id),
    )


def build_label_set(
    table: pa.Table,
    spec: DatasetSpec,
    *,
    complete_from: Instant,
    complete_to: Instant,
) -> LabelSet:
    """Turn a prepared table's label column into a ``LabelSet``. Data plane.

    Coverage is declared exhaustive only when the label column has no nulls. Where it has
    nulls, ``is_exhaustive`` is False and an unlabelled entity means *unknown*, never
    negative -- which is the whole reason ``CoverageScope`` exists.
    """
    if spec.label_column is None:
        raise ValueError(f"{spec.name} has no label column")
    require_utc(complete_from)
    require_utc(complete_to)
    entity = table.column(spec.entity_id_column).to_pylist()
    values = table.column(spec.label_column).to_pylist()
    events = table.column("event_time").to_pylist()
    if spec.label_time_column is not None:
        reported = table.column(spec.label_time_column).to_pylist()
    elif spec.label_delay is not None:
        delay = spec.label_delay
        reported = [None if at is None else delay.label_time(at) for at in events]
    else:
        raise DatasetNotAvailableError(
            f"{spec.name} has labels but neither a label_time column nor a declared delay; "
            "training on such labels would read the future and the spec must say which it is"
        )

    labels: list[Label] = []
    exhaustive = True
    for identifier, value, event_at, label_at in zip(entity, values, events, reported, strict=True):
        if value is None or event_at is None or label_at is None:
            exhaustive = False
            continue
        labels.append(
            Label(
                entity_id=data_value(
                    str(identifier),
                    acquisition=Acquisition.SEGMENT_PREDICATE,
                    source_id=str(spec.name),
                    column=spec.entity_id_column,
                ),
                value=data_value(
                    int(value) if isinstance(value, bool | int) else value,
                    acquisition=Acquisition.SEGMENT_PREDICATE,
                    source_id=str(spec.name),
                    column=spec.label_column,
                ),
                event_time=event_at,
                label_time=label_at,
                source=f"{spec.name}:{spec.label_column}",
            )
        )
    return LabelSet(
        coverage=CoverageScope(
            entity_type=spec.entity_id_column,
            population=Segment(),
            complete_from=complete_from,
            complete_to=complete_to,
            is_exhaustive=exhaustive,
            note=(
                f"{spec.name}: {len(labels)} labels. "
                + (
                    "label_time is a real field in the data."
                    if spec.has_honest_label_time
                    else f"label_time is FABRICATED -- {spec.label_delay.note}"
                    if spec.label_delay is not None
                    else "no label time available."
                )
            ),
        ),
        labels=tuple(labels),
    )


def materialise(
    spec: DatasetSpec,
    *,
    workspace: Path,
    root: Path | None = None,
    max_periods: int | None = None,
) -> LoadedDataset:
    """Write one dataset into a local Iceberg table, one commit per period.

    ``workspace`` is a directory this function owns: it creates a SQLite catalog and a
    file warehouse inside it. The catalog is local because a replay is a local
    experiment; production reads a REST catalog through the same
    :class:`godwit_source.IcebergAdapter`, which is the only thing that touches Iceberg
    either way.

    The label column and everything in ``drop_columns`` are removed from the event
    table's schema before the first commit. A handler that wants a label has to ask the
    ``LabelSet`` for it, as of an instant.
    """
    base = require_available(spec, root=root)
    tables = [prepare_table(_read_raw(base / name), spec) for name in spec.raw_files]

    labels: LabelSet | None = None
    if spec.is_labelled:
        combined = pa.concat_tables(
            [t for t in tables if spec.label_column in t.schema.names], promote_options="default"
        )
        stamps = combined.column("event_time")
        labels = build_label_set(
            combined,
            spec,
            complete_from=pc.min(stamps).as_py(),
            complete_to=pc.max(stamps).as_py(),
        )

    hidden = {spec.event_time_column, *spec.drop_columns}
    if spec.label_column is not None:
        hidden.add(spec.label_column)
    if spec.label_time_column is not None:
        hidden.add(spec.label_time_column)
    hidden.discard("event_time")

    # One Iceberg table needs one schema, and the raw files need not agree: the
    # classification fixture ships ``label_observed`` in its training file and ``label`` in
    # its holdout. So the event table's columns are the intersection, in the first file's
    # order, minus everything hidden. A column that exists in only some files is dropped
    # rather than null-filled: a synthesised null is indistinguishable from a real one and
    # would quietly become a feature.
    shared = set(tables[0].schema.names)
    for table in tables[1:]:
        shared &= set(table.schema.names)
    keep = [name for name in tables[0].schema.names if name in shared and name not in hidden]

    def visible(table: pa.Table) -> pa.Table:
        return table.select(keep)

    if spec.period is Period.SNAPSHOT_FILE:
        chosen = tables if max_periods is None else tables[:max_periods]
        commits = [visible(table) for table in chosen]
        keys = [f"file_{index}" for index in range(len(commits))]
        instants = [pc.max(table.column("event_time")).as_py() for table in chosen]
    else:
        whole = pa.concat_tables(tables, promote_options="default")
        keyed = _period_keys(whole, spec.period)
        keys = sorted({key for key in keyed.to_pylist() if key is not None})
        if max_periods is not None:
            keys = keys[:max_periods]
        commits = [visible(whole.filter(pc.equal(keyed, key))) for key in keys]
        instants = [_period_end(key, spec.period) for key in keys]

    if not commits:
        raise DatasetNotAvailableError(f"{spec.name}: no rows to replay")

    warehouse = workspace / "warehouse"
    warehouse.mkdir(parents=True, exist_ok=True)
    catalog_uri = f"sqlite:///{(workspace / 'catalog.db').as_posix()}"
    warehouse_uri = f"file://{warehouse.as_posix()}"
    catalog = SqlCatalog("godwit-replay", uri=catalog_uri, warehouse=warehouse_uri)
    catalog.create_namespace_if_not_exists(_NAMESPACE)
    source = _source_ref(spec)
    identifier = f"{_NAMESPACE}.{source.table.reveal()}"
    iceberg_table = catalog.create_table_if_not_exists(identifier, schema=commits[0].schema)
    existing = len(iceberg_table.metadata.snapshots)
    if existing == 0:
        for commit in commits:
            iceberg_table.append(commit.cast(commits[0].schema))
    elif existing != len(commits):
        # Reusing a workspace is the point of --workspace, but reusing one that holds a
        # different history silently doubles or truncates the replay. Refuse instead.
        raise DatasetNotAvailableError(
            f"{spec.name}: workspace {workspace} already holds {existing} commits but this "
            f"load wants {len(commits)}. Use a fresh workspace or delete that one."
        )

    return LoadedDataset(
        spec=spec,
        source=source,
        catalog_uri=catalog_uri,
        warehouse_uri=warehouse_uri,
        period_keys=tuple(keys),
        clock_instants=tuple(instants),
        row_counts=tuple(commit.num_rows for commit in commits),
        labels=labels,
    )


def open_catalog(loaded: LoadedDataset) -> Catalog:
    """Reopen the catalog a :class:`LoadedDataset` was written into."""
    return SqlCatalog("godwit-replay", uri=loaded.catalog_uri, warehouse=loaded.warehouse_uri)


def periods_for_months(spec: DatasetSpec, months: int) -> int | None:
    """How many commits ``--months N`` means for this dataset.

    Returns None when the dataset's periods are files rather than calendar windows: a
    fixture with three pre-cut snapshots does not have twelve months in it and pretending
    otherwise would silently shorten the run.
    """
    if spec.period is Period.SNAPSHOT_FILE:
        return None
    return months * 30 if spec.period is Period.DAY else months


def sequence_summary(loaded: LoadedDataset) -> Sequence[tuple[str, Instant, int]]:
    """(period key, clock instant, row count) per commit. For the CLI's own printing."""
    return tuple(zip(loaded.period_keys, loaded.clock_instants, loaded.row_counts, strict=True))
