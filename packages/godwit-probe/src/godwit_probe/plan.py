"""Access modes as a planning constraint, not a filter.

DATA PLANE. This module turns a ``ProbeSpec`` into the exact query a probe will run, or
into a :class:`Refusal` that says why it cannot. Every column's mode is resolved *here*,
before a query exists:

``BLIND``   absent from the projection, the predicates and the sort. A spec that needs a
            BLIND column to measure or to filter is refused, not quietly narrowed:
            measuring something other than what was asked is a wrong answer.
``OPAQUE``  enters the query only as ``godwit_opaque_<type>(column)``, a keyed HMAC the
            query engine computes, and leaves it as ``<column>__opaque``. A predicate on
            it compares hashes with hashes, so ``=``, ``<>``, ``IN``, ``NOT IN`` and the
            null tests work and ranges do not -- a range over a hash means nothing.
``OPEN``    read as itself, and still gated on the way out.

A column with no confirmed classification is BLIND (``godwit-guard`` resolves it so). A
column the spec names that the table does not have is refused too.

The emitted SQL never contains a row value: predicate values are bound parameters. It is
checked with ``godwit_guard.verify_sql`` against every BLIND column of the table before
it is returned, and the executor checks the Arrow schema of what comes back with
``verify_arrow_schema`` before a single value reaches a sketch.

HEAVY HITTERS ON IDENTIFIERS
----------------------------
A value-bearing sketch over an OPAQUE column, or over an OPEN column classified
``DIRECT_IDENTIFIER``, stores hashed keys (``godwit_sketch.KeyHasher`` in OPAQUE mode)
unless a guardrail explicitly permits plain keys. "Explicitly" means an ``ALLOW``
guardrail that fires for this column *and* names the purpose :data:`PLAIN_KEYS_PURPOSE`;
a generic ALLOW does not count, and any DENY, REDACT or REQUIRE_APPROVAL that also fires
wins. The permission is recorded on the probe outcome, sketch by sketch.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from godwit_contracts import (
    CostBudget,
    CostSpend,
    Guardrail,
    GuardrailAction,
    GuardrailAttribute,
    LogicalType,
    Operator,
    PiiClass,
    Plane,
    ProbeKind,
    ProbeSpec,
    ScalarValue,
    Sensitivity,
    SketchKind,
    Version,
)
from godwit_contracts.common import GodwitModel
from godwit_contracts.segment import canonical_column
from godwit_guard import (
    OPAQUE_SUFFIX,
    AccessMode,
    AccessModeMap,
    ModeDecision,
    ProjectionViolationError,
    verify_sql,
)
from godwit_guard.guardrails import applicable, strongest_action
from godwit_sketch import (
    MIN_OPAQUE_ENTROPY_BITS,
    BaseSketch,
    CategoryHistogram,
    CountMinHeavy,
    GraphDegree,
    HllCount,
    KllQuantile,
    Moments,
    NullRate,
    ThetaNdv,
)

from godwit_probe.keyring import ProbeKeyring

__all__ = [
    "DEFAULT_SKETCHES",
    "OPAQUE_FUNCTIONS",
    "PLAIN_KEYS_PURPOSE",
    "ROW_COUNT_FIELD",
    "SOURCE_VIEW",
    "ColumnRole",
    "KeyPermission",
    "PlannedColumn",
    "PlannedSketch",
    "ProbePlan",
    "Refusal",
    "RefusalReason",
    "plan_probe",
]

PLAIN_KEYS_PURPOSE: Final[str] = "probe.plain_keys"
"""The ``PURPOSE`` a guardrail must name to permit plain heavy-hitter keys."""

ROW_COUNT_FIELD: Final[str] = "__godwit_rows"
"""The one result field that is ours rather than a column: ``count(*)`` per file."""

SOURCE_VIEW: Final[str] = "godwit_src"
"""The name the query engine gives the stream of rows read from one data file."""

OPAQUE_FUNCTIONS: Final[Mapping[LogicalType, str]] = {
    LogicalType.STRING: "godwit_opaque_string",
    LogicalType.INT: "godwit_opaque_int",
    LogicalType.FLOAT: "godwit_opaque_float",
    LogicalType.BOOL: "godwit_opaque_bool",
    LogicalType.DATE: "godwit_opaque_date",
}
"""One keyed-hash function per type the engine can hash with an exact canonical form.

``TIMESTAMP`` is absent on purpose: a naive timestamp has no canonical form (the segment
normalisation rejects it), and hashing it under an assumed timezone would make the same
instant two different pseudonyms in two workers.
"""

DEFAULT_SKETCHES: Final[Mapping[ProbeKind, tuple[SketchKind, ...]]] = {
    ProbeKind.ROW_COUNT: (SketchKind.EXACT_COUNT,),
    ProbeKind.NULL_RATE: (SketchKind.EXACT_COUNT,),
    ProbeKind.DISTINCT_COUNT: (SketchKind.THETA,),
    ProbeKind.QUANTILES: (SketchKind.KLL,),
    ProbeKind.HEAVY_HITTERS: (SketchKind.COUNT_MIN,),
    ProbeKind.CATEGORY_HISTOGRAM: (SketchKind.FREQUENT_ITEMS,),
    ProbeKind.GRAPH_DEGREE: (SketchKind.COUNT_MIN,),
}
"""What a spec with an empty ``sketches`` tuple measures. The spec's key is unchanged."""

_UNSUPPORTED_KINDS: Final[frozenset[ProbeKind]] = frozenset(
    {
        ProbeKind.COLUMN_BOUNDS,
        ProbeKind.FRESHNESS,
        ProbeKind.SEGMENT_AGGREGATE,
        ProbeKind.JOIN_CARDINALITY,
    }
)

_GRAPH_COLUMNS: Final[int] = 2
"""A graph-degree probe names exactly a source column and a target column."""

_PARAM_KEYS: Final[Mapping[type[BaseSketch], tuple[str, ...]]] = {
    ThetaNdv: ("lg_k", "seed"),
    HllCount: ("lg_k", "seed"),
    KllQuantile: ("k", "seed", "cdf_grid"),
    CountMinHeavy: ("width", "depth", "seed", "capacity"),
    CategoryHistogram: ("max_exact_cardinality", "width", "depth", "seed", "capacity"),
    GraphDegree: ("lg_k", "k", "width", "depth", "seed", "capacity"),
    NullRate: (),
    Moments: (),
}
"""Which ``ProbeSpec.params`` each sketch class receives. Anything else stays out of the
envelope, where it would become part of the merge identity."""

_NUMERIC: Final[frozenset[LogicalType]] = frozenset(
    {LogicalType.INT, LogicalType.FLOAT, LogicalType.DECIMAL}
)
_CATEGORICAL: Final[frozenset[LogicalType]] = frozenset(
    {LogicalType.STRING, LogicalType.INT, LogicalType.BOOL, LogicalType.FLOAT}
)
_HASHABLE_SKETCHES: Final[frozenset[type[BaseSketch]]] = frozenset({CountMinHeavy, GraphDegree})
_OPAQUE_SAFE_SKETCHES: Final[frozenset[type[BaseSketch]]] = frozenset(
    {ThetaNdv, HllCount, NullRate, CountMinHeavy, GraphDegree}
)
_OPAQUE_OPERATORS: Final[frozenset[Operator]] = frozenset(
    {Operator.EQ, Operator.NE, Operator.IN, Operator.NOT_IN, Operator.IS_NULL, Operator.NOT_NULL}
)
_SQL_OPERATORS: Final[Mapping[Operator, str]] = {
    Operator.EQ: "=",
    Operator.NE: "<>",
    Operator.LT: "<",
    Operator.LE: "<=",
    Operator.GT: ">",
    Operator.GE: ">=",
}


class RefusalReason(StrEnum):
    """Why a probe did not run. A refusal is a normal outcome and a signal to A10."""

    BUDGET = "budget"
    UNSUPPORTED_PROBE = "unsupported_probe"
    UNKNOWN_COLUMN = "unknown_column"
    UNCLASSIFIED_COLUMN = "unclassified_column"
    BLIND_COLUMN = "blind_column"
    OPAQUE_OPERATOR = "opaque_operator"
    OPAQUE_TYPE = "opaque_type"
    NO_KEYRING = "no_keyring"
    SKETCH_FORBIDDEN_FOR_MODE = "sketch_forbidden_for_mode"
    SKETCH_TYPE_MISMATCH = "sketch_type_mismatch"
    PLAIN_KEYS_NOT_PERMITTED = "plain_keys_not_permitted"
    ENTROPY_BELOW_SKETCH_FLOOR = "entropy_below_sketch_floor"
    PLAN_VERIFICATION = "plan_verification"


_EXPLANATIONS: Final[Mapping[RefusalReason, str]] = {
    RefusalReason.BUDGET: "the metadata estimate exceeds the budget; nothing was read",
    RefusalReason.UNSUPPORTED_PROBE: "this probe kind is not executed by probe workers",
    RefusalReason.UNKNOWN_COLUMN: "a named column is not in the table's schema",
    RefusalReason.UNCLASSIFIED_COLUMN: "a needed column has no confirmed classification",
    RefusalReason.BLIND_COLUMN: "a needed column is BLIND and may not enter a query",
    RefusalReason.OPAQUE_OPERATOR: "an OPAQUE column supports equality and null tests only",
    RefusalReason.OPAQUE_TYPE: "an OPAQUE column's type has no canonical keyed-hash form",
    RefusalReason.NO_KEYRING: "an OPAQUE column needs a data-plane keyring",
    RefusalReason.SKETCH_FORBIDDEN_FOR_MODE: "this sketch would expose values of this column",
    RefusalReason.SKETCH_TYPE_MISMATCH: "this sketch cannot summarise this column's type",
    RefusalReason.PLAIN_KEYS_NOT_PERMITTED: "plain keys on an identifier need a guardrail",
    RefusalReason.ENTROPY_BELOW_SKETCH_FLOOR: "the column is too enumerable to hash safely",
    RefusalReason.PLAN_VERIFICATION: "the planned query failed its access-mode verification",
}


class ColumnRole(StrEnum):
    """Why the plan needed a column."""

    MEASURE = "measure"
    PREDICATE = "predicate"


class Refusal(GodwitModel):
    """A probe that did not run, and why. Columns are identified by position only.

    ``column_index`` is the position in ``ProbeSpec.columns`` for a measured column and
    in ``ProbeSpec.segment.predicates`` for a predicate, so the orchestrator can act on
    it without anyone writing a column name into a record that crosses the boundary.
    """

    reason: RefusalReason
    column_role: ColumnRole | None = None
    column_index: int | None = None
    sketch_kind: SketchKind | None = None
    estimated_cost: CostSpend | None = None
    budget: CostBudget | None = None

    @property
    def explanation(self) -> str:
        """A fixed sentence for this reason. Never interpolated."""
        return _EXPLANATIONS[self.reason]


class KeyPermission(GodwitModel):
    """A guardrail that permitted plain heavy-hitter keys for one sketch."""

    sketch_name: str
    guardrail_id: str
    guardrail_version: Version


@dataclass(frozen=True, slots=True)
class PlannedColumn:
    """One column the plan reads. **Data plane**: ``name`` is the customer's name."""

    name: str
    logical_type: LogicalType
    decision: ModeDecision

    @property
    def mode(self) -> AccessMode:
        """The resolved access mode."""
        return self.decision.mode

    @property
    def output(self) -> str:
        """The field this column appears as in the query result."""
        return self.name + OPAQUE_SUFFIX if self.mode is AccessMode.OPAQUE else self.name


@dataclass(frozen=True, slots=True)
class PlannedSketch:
    """One sketch the plan will build, over one or two result fields."""

    name: str
    kind: SketchKind
    sketch_cls: type[BaseSketch]
    fields: tuple[str, ...]
    columns: tuple[PlannedColumn, ...]
    params: Mapping[str, int | float | str | bool]
    hashed_entropy_bits: float | None
    """Set when keys are stored hashed: the declared input entropy. None means plain."""
    permission: KeyPermission | None = None


@dataclass(frozen=True, slots=True)
class ProbePlan:
    """The exact work a probe will do. **Data plane**: holds names and bound values.

    Never logged and never returned across the boundary. Tests assert on ``sql`` and
    ``read_columns``; nothing else should read them.
    """

    sql: str
    parameters: tuple[ScalarValue, ...]
    read_columns: tuple[str, ...]
    output_fields: tuple[str, ...]
    sketches: tuple[PlannedSketch, ...]
    blind_columns: tuple[str, ...]
    metadata_only: bool
    """True when the answer is a row count over the whole delta: manifests suffice."""

    @property
    def permissions(self) -> tuple[KeyPermission, ...]:
        """Every plain-key permission the plan relies on."""
        return tuple(item.permission for item in self.sketches if item.permission is not None)


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def plan_probe(
    spec: ProbeSpec,
    *,
    access: AccessModeMap,
    column_types: Mapping[str, LogicalType],
    keyring: ProbeKeyring | None,
    guardrails: Sequence[Guardrail] = (),
) -> ProbePlan | Refusal:
    """Plan one probe, or refuse it. Pure: no I/O, no clock."""
    if spec.kind in _UNSUPPORTED_KINDS:
        return Refusal(reason=RefusalReason.UNSUPPORTED_PROBE)
    kinds = spec.sketches or DEFAULT_SKETCHES[spec.kind]
    if spec.kind is ProbeKind.GRAPH_DEGREE and (
        len(spec.columns) != _GRAPH_COLUMNS or kinds != (SketchKind.COUNT_MIN,)
    ):
        return Refusal(reason=RefusalReason.UNSUPPORTED_PROBE)

    resolver = _Resolver(spec, access=access, column_types=column_types)
    measured: list[PlannedColumn] = []
    for index, column in enumerate(spec.columns):
        resolved = resolver.resolve(column.reveal(), ColumnRole.MEASURE, index)
        if isinstance(resolved, Refusal):
            return resolved
        measured.append(resolved)

    where = _Where(keyring)
    for index, predicate in enumerate(spec.segment.predicates):
        resolved = resolver.resolve(predicate.column.reveal(), ColumnRole.PREDICATE, index)
        if isinstance(resolved, Refusal):
            return resolved
        refusal = where.add(resolved, predicate.op, [v.reveal() for v in predicate.values], index)
        if refusal is not None:
            return refusal

    for index, planned in enumerate(measured):
        if planned.mode is AccessMode.OPAQUE:
            refusal = _check_opaque(planned, keyring, ColumnRole.MEASURE, index)
            if refusal is not None:
                return refusal

    sketches = _plan_sketches(spec, kinds, measured, keyring=keyring, guardrails=guardrails)
    if isinstance(sketches, Refusal):
        return sketches

    outputs = list(dict.fromkeys(column.output for column in measured))
    selected = {column.output: column for column in measured}
    if outputs:
        projection = ", ".join(
            f"{_expression(selected[name])} AS {_quote(name)}" for name in outputs
        )
    else:
        projection = f"count(*) AS {_quote(ROW_COUNT_FIELD)}"
        outputs = [ROW_COUNT_FIELD]
    parts = ["SELECT", projection, "FROM", SOURCE_VIEW]
    if where.clauses:
        parts += ["WHERE", " AND ".join(where.clauses)]
    sql = " ".join(parts)

    blind = resolver.blind_columns()
    try:
        verify_sql(sql, blind_columns=blind)
    except ProjectionViolationError:
        return Refusal(reason=RefusalReason.PLAN_VERIFICATION)

    read_columns = tuple(dict.fromkeys([c.name for c in measured] + where.columns))
    metadata_only = not measured and not where.clauses
    return ProbePlan(
        sql=sql,
        parameters=tuple(where.parameters),
        read_columns=() if metadata_only else read_columns,
        output_fields=tuple(outputs),
        sketches=sketches,
        blind_columns=blind,
        metadata_only=metadata_only,
    )


class _Resolver:
    """Resolves spec column names against the schema and the mode map."""

    def __init__(
        self,
        spec: ProbeSpec,
        *,
        access: AccessModeMap,
        column_types: Mapping[str, LogicalType],
    ) -> None:
        self._source_id = str(spec.source.source_id)
        self._table = spec.source.table.reveal()
        self._access = access
        self._types = column_types
        self._by_canonical = {canonical_column(name): name for name in column_types}

    def resolve(self, requested: str, role: ColumnRole, index: int) -> PlannedColumn | Refusal:
        actual = self._by_canonical.get(canonical_column(requested))
        if actual is None:
            return Refusal(
                reason=RefusalReason.UNKNOWN_COLUMN, column_role=role, column_index=index
            )
        decision = self._access.decision_for(self._source_id, self._table, actual)
        if decision is None or not decision.confirmed:
            return Refusal(
                reason=RefusalReason.UNCLASSIFIED_COLUMN, column_role=role, column_index=index
            )
        if decision.mode is AccessMode.BLIND:
            return Refusal(reason=RefusalReason.BLIND_COLUMN, column_role=role, column_index=index)
        return PlannedColumn(name=actual, logical_type=self._types[actual], decision=decision)

    def blind_columns(self) -> tuple[str, ...]:
        """Every column of the table that must not appear in the SQL."""
        blind: list[str] = []
        for name in sorted(self._types):
            decision = self._access.decision_for(self._source_id, self._table, name)
            if decision is None or decision.mode is AccessMode.BLIND:
                blind.append(name)
        return tuple(blind)


def _expression(column: PlannedColumn) -> str:
    if column.mode is AccessMode.OPAQUE:
        return f"{OPAQUE_FUNCTIONS[column.logical_type]}({_quote(column.name)})"
    return _quote(column.name)


def _check_opaque(
    column: PlannedColumn, keyring: ProbeKeyring | None, role: ColumnRole, index: int
) -> Refusal | None:
    if keyring is None:
        return Refusal(reason=RefusalReason.NO_KEYRING, column_role=role, column_index=index)
    if column.logical_type not in OPAQUE_FUNCTIONS:
        return Refusal(reason=RefusalReason.OPAQUE_TYPE, column_role=role, column_index=index)
    return None


class _Where:
    """Accumulates predicate clauses with bound parameters. Values never enter the SQL."""

    def __init__(self, keyring: ProbeKeyring | None) -> None:
        self._keyring = keyring
        self.clauses: list[str] = []
        self.parameters: list[ScalarValue] = []
        self.columns: list[str] = []

    def _bind(self, value: ScalarValue) -> str:
        self.parameters.append(value)
        return f"${len(self.parameters)}"

    def add(
        self, column: PlannedColumn, op: Operator, values: list[ScalarValue], index: int
    ) -> Refusal | None:
        role = ColumnRole.PREDICATE
        if column.mode is AccessMode.OPAQUE:
            refusal = _check_opaque(column, self._keyring, role, index)
            if refusal is not None:
                return refusal
            if op not in _OPAQUE_OPERATORS:
                return Refusal(
                    reason=RefusalReason.OPAQUE_OPERATOR, column_role=role, column_index=index
                )
            if self._keyring is not None:
                hasher = self._keyring.column_hasher
                values = [hasher.hash_for(value, decision=column.decision) for value in values]
        operand = _expression(column)
        self.columns.append(column.name)
        self.clauses.append(self._clause(operand, op, values))
        return None

    def _clause(self, operand: str, op: Operator, values: list[ScalarValue]) -> str:
        match op:
            case Operator.IS_NULL:
                return f"{operand} IS NULL"
            case Operator.NOT_NULL:
                return f"{operand} IS NOT NULL"
            case Operator.IN | Operator.NOT_IN:
                members = ", ".join(self._bind(value) for value in values)
                negation = "NOT " if op is Operator.NOT_IN else ""
                return f"{operand} {negation}IN ({members})"
            case Operator.BETWEEN:
                return f"{operand} BETWEEN {self._bind(values[0])} AND {self._bind(values[1])}"
            case Operator.PREFIX:
                return f"starts_with({operand}, {self._bind(values[0])})"
            case _:
                return f"{operand} {_SQL_OPERATORS[op]} {self._bind(values[0])}"


def _sketch_class(kind: SketchKind, spec: ProbeSpec) -> type[BaseSketch]:
    if spec.kind is ProbeKind.GRAPH_DEGREE:
        return GraphDegree
    if kind is SketchKind.EXACT_COUNT:
        return Moments if spec.params.get("exact_count") == "moments" else NullRate
    classes: Mapping[SketchKind, type[BaseSketch]] = {
        SketchKind.THETA: ThetaNdv,
        SketchKind.HLL: HllCount,
        SketchKind.KLL: KllQuantile,
        SketchKind.COUNT_MIN: CountMinHeavy,
        SketchKind.FREQUENT_ITEMS: CategoryHistogram,
    }
    return classes[kind]


def _plan_sketches(
    spec: ProbeSpec,
    kinds: tuple[SketchKind, ...],
    measured: list[PlannedColumn],
    *,
    keyring: ProbeKeyring | None,
    guardrails: Sequence[Guardrail],
) -> tuple[PlannedSketch, ...] | Refusal:
    planned: list[PlannedSketch] = []
    for kind in kinds:
        cls = _sketch_class(kind, spec)
        params = {key: spec.params[key] for key in _PARAM_KEYS[cls] if key in spec.params}
        if cls is GraphDegree:
            groups: list[tuple[str, tuple[PlannedColumn, ...], int]] = [
                (f"{kind.value}:graph", tuple(measured), 0)
            ]
        elif not measured:
            if cls is not NullRate:
                return Refusal(reason=RefusalReason.SKETCH_TYPE_MISMATCH, sketch_kind=kind)
            planned.append(
                PlannedSketch(
                    name=f"{kind.value}:table",
                    kind=kind,
                    sketch_cls=NullRate,
                    fields=(ROW_COUNT_FIELD,),
                    columns=(),
                    params={},
                    hashed_entropy_bits=None,
                )
            )
            continue
        else:
            groups = [
                (f"{kind.value}:{index}", (column,), index) for index, column in enumerate(measured)
            ]
        for name, columns, index in groups:
            item = _plan_one(
                name,
                kind,
                cls,
                columns,
                index,
                params=params,
                spec=spec,
                keyring=keyring,
                guardrails=guardrails,
            )
            if isinstance(item, Refusal):
                return item
            planned.append(item)
    return tuple(planned)


def _plan_one(
    name: str,
    kind: SketchKind,
    cls: type[BaseSketch],
    columns: tuple[PlannedColumn, ...],
    index: int,
    *,
    params: Mapping[str, int | float | str | bool],
    spec: ProbeSpec,
    keyring: ProbeKeyring | None,
    guardrails: Sequence[Guardrail],
) -> PlannedSketch | Refusal:
    def refuse(reason: RefusalReason) -> Refusal:
        return Refusal(
            reason=reason, column_role=ColumnRole.MEASURE, column_index=index, sketch_kind=kind
        )

    opaque = any(column.mode is AccessMode.OPAQUE for column in columns)
    if opaque and cls not in _OPAQUE_SAFE_SKETCHES:
        return refuse(RefusalReason.SKETCH_FORBIDDEN_FOR_MODE)
    for column in columns:
        if cls in (KllQuantile, Moments) and column.logical_type not in _NUMERIC:
            return refuse(RefusalReason.SKETCH_TYPE_MISMATCH)
        needs_categorical = cls in (CountMinHeavy, CategoryHistogram, GraphDegree)
        if needs_categorical and not opaque and column.logical_type not in _CATEGORICAL:
            return refuse(RefusalReason.SKETCH_TYPE_MISMATCH)

    identifier = any(
        column.mode is AccessMode.OPAQUE or column.decision.pii_class is PiiClass.DIRECT_IDENTIFIER
        for column in columns
    )
    bits: float | None = None
    permission: KeyPermission | None = None
    if cls.VALUE_BEARING and identifier:
        if not opaque:
            permission = _plain_keys_permission(name, columns, spec, guardrails)
        if permission is None:
            if cls not in _HASHABLE_SKETCHES:
                return refuse(RefusalReason.PLAIN_KEYS_NOT_PERMITTED)
            if keyring is None:
                return refuse(RefusalReason.NO_KEYRING)
            declared = [
                column.decision.entropy.bits if column.decision.entropy is not None else 0.0
                for column in columns
            ]
            bits = min(declared)
            if bits < MIN_OPAQUE_ENTROPY_BITS:
                return refuse(RefusalReason.ENTROPY_BELOW_SKETCH_FLOOR)
    return PlannedSketch(
        name=name,
        kind=kind,
        sketch_cls=cls,
        fields=tuple(column.output for column in columns),
        columns=columns,
        params=params,
        hashed_entropy_bits=bits,
        permission=permission,
    )


def _plain_keys_permission(
    name: str,
    columns: tuple[PlannedColumn, ...],
    spec: ProbeSpec,
    guardrails: Sequence[Guardrail],
) -> KeyPermission | None:
    """The ALLOW guardrail naming :data:`PLAIN_KEYS_PURPOSE` for every column, if any."""
    chosen: Guardrail | None = None
    for column in columns:
        attrs: dict[GuardrailAttribute, str | int | float | bool | None] = {
            GuardrailAttribute.PURPOSE: PLAIN_KEYS_PURPOSE,
            GuardrailAttribute.PII_CLASS: column.decision.pii_class.value,
            GuardrailAttribute.SOURCE_ID: str(spec.source.source_id),
            GuardrailAttribute.TABLE_NAME: spec.source.table.reveal(),
            GuardrailAttribute.COLUMN_NAME: column.name,
            GuardrailAttribute.PLANE: Plane.DATA.value,
            GuardrailAttribute.SENSITIVITY: Sensitivity.DATA_VALUE.value,
        }
        fired = applicable(guardrails, attrs)
        if strongest_action(g.action for g in fired) is not GuardrailAction.ALLOW:
            return None
        explicit = [
            g
            for g in fired
            if any(cond.attribute is GuardrailAttribute.PURPOSE for cond in g.predicate.all_of)
        ]
        if not explicit:
            return None
        chosen = explicit[0]
    if chosen is None:
        return None
    return KeyPermission(
        sketch_name=name, guardrail_id=chosen.guardrail_id, guardrail_version=chosen.version
    )
