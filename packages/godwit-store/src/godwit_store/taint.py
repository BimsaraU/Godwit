"""The two unwraps this package is allowed to perform, and the storage convention.

godwit-store is **control plane**. It holds tainted values, and it must be able to key,
rank and deduplicate them without reading any of them. Two unwraps are legitimate:

* a ``DERIVED_STATISTIC`` -- a p-value, an effect size, a count. Ranking a queue by
  effect size is the job; there is no row value in the number.
* a ``SCHEMA_NAME`` -- a customer column name. The dedup signature is over a column
  set, so the names have to be compared. They are still disclosive (leak path 9) and
  never reach a rendering that leaves this package.

Reading a ``DATA_VALUE`` is not on the list, and :func:`reveal_statistic` and
:func:`reveal_schema_name` refuse it rather than trusting a convention. Grep this
package for ``.reveal()`` and you will find it only here.

STORAGE CONVENTION
------------------
Every tainted value is stored in a group of dedicated columns::

    <name>_value          JSONB   the value, and nothing else
    <name>_sensitivity    text    what it is
    <name>_acquisition    text    how it was obtained
    <name>_population     int     how many rows stand behind it, NULL for unknown

The derived statistics that drive queues -- ``score``, ``p_value``, ``q_value`` -- are
*also* stored as plain numeric columns next to their tainted group, because they carry
no row value. That is what "make the safe query the easy one" means in practice: a
dashboard reads ``patterns.q_value`` and touches nothing tainted, and the ``_safe``
views exist so it cannot touch anything tainted by accident.
"""

from __future__ import annotations

from typing import Any, Final

from godwit_contracts import Acquisition, Provenance, Sensitivity, Tainted

from godwit_store.errors import RevealRefusedError

__all__ = [
    "TaintedColumns",
    "rebuild_tainted",
    "reveal_schema_name",
    "reveal_statistic",
    "store_tainted",
]


def reveal_statistic(value: Tainted[float]) -> float:
    """Unwrap a number that is an aggregate. Refuses anything else.

    A mean is a derived statistic. A maximum is not: the maximum IS some row's value,
    and it arrives here tainted DATA_VALUE for exactly that reason.
    """
    if value.sensitivity is not Sensitivity.DERIVED_STATISTIC:
        raise RevealRefusedError(
            f"refusing to reveal a {value.sensitivity.value}; godwit-store reads "
            "statistics and schema names, never row values"
        )
    return float(value.reveal())


def reveal_schema_name(value: Tainted[str]) -> str:
    """Unwrap a customer column or table name. Refuses anything else.

    The name is disclosive on its own (``patient_hiv_status``). It is read here to key
    and to deduplicate, and nothing this package renders for a human contains one.
    """
    if value.sensitivity is not Sensitivity.SCHEMA_NAME:
        raise RevealRefusedError(f"refusing to reveal a {value.sensitivity.value} as a schema name")
    return str(value.reveal())


class TaintedColumns:
    """The four column values a tainted field decomposes into, as a plain tuple.

    Deliberately not a Pydantic model: this is the shape that goes into
    ``session.execute(insert(...))``, and one allocation per stored value matters when
    a batch is ten thousand candidates.
    """

    __slots__ = ("acquisition", "population", "sensitivity", "value")

    def __init__(
        self,
        *,
        value: object,
        sensitivity: str,
        acquisition: str,
        population: int | None,
    ) -> None:
        self.value = value
        self.sensitivity = sensitivity
        self.acquisition = acquisition
        self.population = population

    def as_mapping(self, prefix: str) -> dict[str, Any]:
        """Render as ``{prefix}_value``, ``{prefix}_sensitivity`` and friends."""
        return {
            f"{prefix}_value": self.value,
            f"{prefix}_sensitivity": self.sensitivity,
            f"{prefix}_acquisition": self.acquisition,
            f"{prefix}_population": self.population,
        }


_NULL_COLUMNS: Final[TaintedColumns] = TaintedColumns(
    value=None, sensitivity="", acquisition="", population=None
)


def store_tainted(value: Tainted[Any] | None) -> TaintedColumns:
    """Decompose a tainted value into its storage columns, without reading it.

    ``value.value`` is touched here rather than ``value.reveal()``: this is a copy into
    a column that is declared tainted, not a disclosure. Nothing downstream of this
    function sees the value unless it reads that column, and the ``_safe`` views do not
    expose it.
    """
    if value is None:
        return _NULL_COLUMNS
    return TaintedColumns(
        value=value.value,
        sensitivity=value.sensitivity.value,
        acquisition=value.provenance.acquisition.value,
        population=value.population,
    )


def rebuild_tainted(
    *,
    value: object,
    sensitivity: str,
    acquisition: str,
    population: int | None,
    column: str | None = None,
) -> Tainted[Any]:
    """Rebuild a tainted value from its storage columns.

    The rebuilt provenance is honest about being a rebuild: it keeps the acquisition,
    which is what the gate's floor check uses, and drops the rest rather than inventing
    a source it did not store.
    """
    return Tainted[Any](
        value=value,
        sensitivity=Sensitivity(sensitivity),
        provenance=Provenance(acquisition=Acquisition(acquisition), column=column),
        population=population,
    )
