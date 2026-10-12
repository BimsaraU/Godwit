"""The PII torture fixture, as the conformance kit uses it.

``pii_torture.json`` beside this module is a copy of A0's ``tests/golden/pii_torture``:
twelve rows of realistic synthetic identifiers in which every leak path is populated.
It is copied so the kit works in a plugin author's own repository; the SDK's own test
suite fails if the copy ever drifts from the original.
"""

from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass
from importlib.resources import files
from typing import Final

import pyarrow as pa

__all__ = ["Torture", "torture"]

_ARROW: Final[dict[str, pa.DataType]] = {"string": pa.string(), "int64": pa.int64()}
_DISTINCTIVE: Final[re.Pattern[str]] = re.compile(r"[@ _\-]|[A-Z]|\d.*[a-z]|[a-z].*\d")
_MIN_DISTINCTIVE: Final[int] = 9


@dataclass(frozen=True, slots=True)
class Torture:
    """The fixture: its table, its column classes, and the strings that must never leak."""

    table_name: str
    table: pa.Table
    pii_classes: dict[str, str]
    driver_exception: str
    feature_name_trap: str
    must_never_appear: tuple[str, ...]

    @property
    def sentinels(self) -> tuple[str, ...]:
        """The leak-list strings distinctive enough to search rendered text for.

        The full list also holds ``general``, ``unknown``, ``positive`` and bare salaries
        such as ``41000`` -- real values in the table, but words and numbers that occur in
        any rendering (``pii_class: unknown``, a byte count) without being a leak. A text
        search for them proves nothing either way, so the kit searches for the rest:
        names, emails, SSNs, device ids, merchant names, free-text notes.
        """
        return tuple(
            value
            for value in self.must_never_appear
            if len(value) >= _MIN_DISTINCTIVE and _DISTINCTIVE.search(value)
        )

    def strings(self) -> tuple[str, ...]:
        """Every string value in the table, for feeding categorical sketches."""
        values = {
            value
            for column in self.table.column_names
            for value in self.table.column(column).to_pylist()
            if isinstance(value, str)
        }
        return tuple(sorted(values))


@functools.cache
def torture() -> Torture:
    """Load the fixture once."""
    raw = json.loads(files("godwit_sdk.testing").joinpath("pii_torture.json").read_text("utf-8"))
    schema = pa.schema([(name, _ARROW[kind]) for name, kind in raw["schema"].items()])
    order = [column["name"] for column in raw["columns"]]
    table = pa.Table.from_pylist(raw["rows"], schema=schema).select(order)
    return Torture(
        table_name=raw["table"],
        table=table,
        pii_classes={column["name"]: column["pii_class"] for column in raw["columns"]},
        driver_exception=raw["driver_exception_trap"],
        feature_name_trap=raw["derived_feature_name_trap"],
        must_never_appear=tuple(raw["must_never_appear"]),
    )
