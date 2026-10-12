"""Plugins that leak in ways the static check sees. Imported by name; see conftest.py."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from typing import ClassVar

import pyarrow as pa
from _sdk_support import MemorySource
from godwit_sdk import (
    BaseSketch,
    DetectorBase,
    EvidenceKind,
    HypothesisTest,
    Partition,
    TableName,
    detector,
    source,
)


@source(name="printing", namespace="leaky", version="0.1.0")
class PrintingSource(MemorySource):
    """Prints every batch it reads. The classic debugging leak."""

    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        for batch in super().read(table, partition, columns):
            print(batch.to_pylist())
            yield batch


@detector(name="logging", namespace="leaky", version="0.1.0")
class LoggingDetector(DetectorBase):
    """Logs the heavy hitters it sees through a raw logger, unwrapped."""

    EVIDENCE: ClassVar[EvidenceKind] = EvidenceKind.HEAVY_HITTER_SHIFT
    CODECS: ClassVar[frozenset[str]] = frozenset({"godwit-cm-v1"})
    TESTS_PER_SKETCH: ClassVar[int] = 1

    def examine(
        self, current: BaseSketch, reference: Sequence[BaseSketch]
    ) -> Sequence[HypothesisTest]:
        del reference
        for item, _ in current.heavy_hitters(5):
            logging.getLogger("leaky").warning("saw %s", item.reveal())
        return ()
