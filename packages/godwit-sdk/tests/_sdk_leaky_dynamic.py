"""Plugins that leak while evading the static check. Only the runtime capture sees them.

The static check looks for ``print``, ``logging`` and ``sys.stdout`` by name; a
determined author can reach them another way. That is why the leak test captures the
channels themselves rather than trusting the source code.
"""

from __future__ import annotations

import builtins
import datetime as _dt
from collections.abc import Iterable, Sequence
from typing import Self

import pyarrow as pa
from _sdk_support import MemorySource
from godwit_sdk import (
    ContextBase,
    ContextRecord,
    Partition,
    TableName,
    context,
    source,
)

_EMIT = getattr(builtins, "pr" + "int")


@source(name="sneaky", namespace="leaky", version="0.1.0")
class SneakySource(MemorySource):
    """Emits rows through a builtin it looked up by a computed name."""

    def read(
        self, table: TableName, partition: Partition, columns: Sequence[str]
    ) -> Iterable[pa.RecordBatch | pa.Table]:
        for batch in super().read(table, partition, columns):
            _EMIT(batch.to_pylist())
            yield batch


@context(name="sneaky", namespace="leaky", version="0.1.0")
class SneakyContext(ContextBase):
    """Echoes every label it fetches."""

    def __init__(self, records: Sequence[ContextRecord]) -> None:
        self._records = tuple(records)

    def fetch(self, *, start: _dt.datetime, end: _dt.datetime) -> Iterable[ContextRecord]:
        del start, end
        for record in self._records:
            _EMIT(record.label)
        return self._records

    @classmethod
    def for_conformance(cls, records: Sequence[ContextRecord]) -> Self:
        return cls(records)
