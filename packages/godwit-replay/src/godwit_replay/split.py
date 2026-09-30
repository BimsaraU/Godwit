"""Half-labelled splits: hiding labels in the two ways that matter.

The prediction objective is stated on *half-labelled* data with no human in the loop, so the
harness has to manufacture the half-labelled condition from a fully labelled public dataset.
There are two honest ways to do that and they test different failures:

* **Temporal.** Hide every label after a cut-off. This is the real situation: the recent
  period's chargebacks have not landed yet. It is also the harder one, because the hidden
  half is distributionally different from the visible half -- that is what drift means.
* **Random mask.** Hide a random half, drawn from a seeded generator. Distributionally
  identical, so a model that does well here and badly on the temporal variant is telling you
  it cannot extrapolate. Reporting only the random-mask number is the flattering choice and
  the harness reports both.

**This module runs in the DATA PLANE.** It takes an Arrow table and returns index arrays.
The record it produces alongside them carries counts, a seed and a digest -- no values.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from enum import StrEnum

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
from godwit_contracts.common import (
    ContentHash,
    GodwitModel,
    Instant,
    NonNegInt,
    canonical_json,
    content_hash,
)
from godwit_contracts.taint import schema_name
from godwit_contracts.training import SplitKind, SplitSpec
from numpy.typing import NDArray
from pydantic import Field

from godwit_replay.datasets import DatasetSpec

__all__ = ["HalfLabelled", "MaskKind", "SplitRecord", "half_labelled"]


class MaskKind(StrEnum):
    """Which way the labels were hidden."""

    TEMPORAL = "temporal"
    RANDOM_MASK = "random_mask"


class SplitRecord(GodwitModel):
    """A reproducible description of one split. Committable: no row values."""

    dataset: str
    mask: MaskKind
    spec: SplitSpec
    rows: NonNegInt
    labelled_rows: NonNegInt
    hidden_rows: NonNegInt
    eval_rows: NonNegInt
    cut_off: Instant | None = Field(
        default=None, description="The temporal boundary, for MaskKind.TEMPORAL."
    )
    hidden_fraction: float
    seed: int
    digest: ContentHash


@dataclass(frozen=True, slots=True)
class HalfLabelled:
    """Index arrays into the prepared table, plus the record that describes them.

    ``train_rows`` are rows a trainer may fit on; ``label_visible`` says which of those
    actually have a label -- the rest are *unknown*, never negative. ``eval_rows`` is the
    held-out half the labels were hidden from, which is what everything is scored on.
    """

    record: SplitRecord
    train_rows: NDArray[np.int64]
    label_visible: NDArray[np.bool_]
    eval_rows: NDArray[np.int64]


def _quantile_instant(stamps: pa.ChunkedArray, fraction: float) -> Instant:
    """The instant ``fraction`` of the way through the data, by row order of event time."""
    values = np.asarray(stamps.to_numpy(zero_copy_only=False), dtype="datetime64[us]")
    ordered = np.sort(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    moment = ordered[index].astype("datetime64[us]").astype(object)
    if not isinstance(moment, _dt.datetime):
        raise TypeError("event_time did not convert to a datetime; check the column's type")
    return moment.replace(tzinfo=_dt.UTC)


def half_labelled(
    table: pa.Table,
    spec: DatasetSpec,
    *,
    mask: MaskKind,
    seed: int,
    hidden_fraction: float = 0.5,
    embargo: _dt.timedelta = _dt.timedelta(days=0),
) -> HalfLabelled:
    """Build one half-labelled split over a prepared table.

    ``table`` must already carry ``event_time`` and the label column -- that is, it is the
    output of :func:`godwit_replay.datasets.prepare_table` and not the Iceberg event table,
    which has the label removed on purpose.

    For ``TEMPORAL``, ``embargo`` is the gap between the last training row and the first
    evaluation row. It defaults to zero because the datasets here have no adjacency between
    consecutive rows; set it wherever they do, and record it, because an undeclared embargo
    of zero and a forgotten one look the same in a report.
    """
    if spec.label_column is None:
        raise ValueError(f"{spec.name} has no labels to hide")
    if not 0.0 < hidden_fraction < 1.0:
        raise ValueError("hidden_fraction must be strictly between 0 and 1")

    stamps = table.column("event_time")
    total = table.num_rows
    labels = np.asarray(
        pc.is_valid(table.column(spec.label_column)).to_numpy(zero_copy_only=False), dtype=bool
    )

    if mask is MaskKind.TEMPORAL:
        cut_off = _quantile_instant(stamps, 1.0 - hidden_fraction)
        moments = np.asarray(stamps.to_numpy(zero_copy_only=False), dtype="datetime64[us]")
        boundary = np.datetime64(cut_off.replace(tzinfo=None), "us")
        before = moments < boundary
        after = moments >= boundary + np.timedelta64(int(embargo.total_seconds()), "s")
        train_rows = np.flatnonzero(before)
        eval_rows = np.flatnonzero(after)
        visible = labels[train_rows]
    else:
        cut_off = None
        generator = np.random.default_rng(seed)
        held = generator.permutation(total)[: round(hidden_fraction * total)]
        held_mask = np.zeros(total, dtype=bool)
        held_mask[held] = True
        train_rows = np.arange(total, dtype=np.int64)
        eval_rows = np.flatnonzero(held_mask)
        visible = labels & ~held_mask

    split_spec = SplitSpec(
        kind=SplitKind.TIME_ORDERED if mask is MaskKind.TEMPORAL else SplitKind.RANDOM,
        time_column=schema_name("event_time") if mask is MaskKind.TEMPORAL else None,
        train_end=cut_off,
        valid_end=(cut_off + embargo + _dt.timedelta(microseconds=1)) if cut_off else None,
        test_end=None,
        embargo=embargo,
        seed=seed,
    )
    record = SplitRecord(
        dataset=spec.name,
        mask=mask,
        spec=split_spec,
        rows=total,
        labelled_rows=int(labels.sum()),
        hidden_rows=int(labels.sum() - visible.sum()),
        eval_rows=int(eval_rows.size),
        cut_off=cut_off,
        hidden_fraction=hidden_fraction,
        seed=seed,
        digest=content_hash(
            canonical_json(
                {
                    "dataset": spec.name,
                    "mask": mask.value,
                    "rows": total,
                    "hidden_fraction": hidden_fraction,
                    "embargo_seconds": embargo.total_seconds(),
                    "seed": seed,
                    "train_rows": int(train_rows.size),
                    "eval_rows": int(eval_rows.size),
                    "visible_labels": int(visible.sum()),
                }
            ),
            prefix="spl",
        ),
    )
    return HalfLabelled(
        record=record,
        train_rows=train_rows.astype(np.int64),
        label_visible=visible.astype(bool),
        eval_rows=eval_rows.astype(np.int64),
    )
