"""Explained-away layer: deploys, campaigns, holidays, DQ failures (L3).

Owner: A8. Plane: **control**. Handles data-derived values: candidate segments quote row
values, context scopes name customer columns, imported labels are free text. Nothing here
reads a row, calls an LLM, reads a clock or issues a billable query.

Join every candidate against the mundane reasons the world changed, and let only the
unexplained residual proceed. Start with ``ContextRouter.route``; read
``docs/packages/godwit-context.md`` for the why.
"""

from godwit_context.audit import AuditRecord, AuditSink, MemoryAuditSink, StoreAuditSink
from godwit_context.business import (
    BusinessCalendarSource,
    BusinessCalendarSpec,
    Payroll,
    PayrollRule,
    SettlementCycle,
)
from godwit_context.events import ContextEvent, ContextScope, ContextType, event_id_for
from godwit_context.holidays import (
    CALENDARS,
    EasterOffset,
    Fixed,
    Holiday,
    HolidayCalendar,
    HolidayRule,
    HolidaySource,
    NthWeekday,
    Observance,
    easter,
    orthodox_easter,
)
from godwit_context.matching import (
    DEFAULT_TEMPORAL,
    Counterfactual,
    CounterfactualPolicy,
    CounterfactualVerdict,
    Match,
    MatchPolicy,
    OverlapTier,
    PeerObservation,
    StrengthWeights,
    TemporalPolicy,
    Window,
    detector_family,
)
from godwit_context.priors import Outcome, PriorBook
from godwit_context.routing import (
    ContextRouter,
    Route,
    RoutingDecision,
    RoutingPolicy,
    UnknownDecisionError,
)
from godwit_context.sources import (
    DEFAULT_DQ_DETECTORS,
    AnnotationBook,
    ContextImportError,
    ContextSource,
    StaticSource,
    collect_events,
    data_quality_from_candidates,
    import_csv,
    import_records,
    parse_deploy_webhook,
)

__all__ = [
    "CALENDARS",
    "DEFAULT_DQ_DETECTORS",
    "DEFAULT_TEMPORAL",
    "AnnotationBook",
    "AuditRecord",
    "AuditSink",
    "BusinessCalendarSource",
    "BusinessCalendarSpec",
    "ContextEvent",
    "ContextImportError",
    "ContextRouter",
    "ContextScope",
    "ContextSource",
    "ContextType",
    "Counterfactual",
    "CounterfactualPolicy",
    "CounterfactualVerdict",
    "EasterOffset",
    "Fixed",
    "Holiday",
    "HolidayCalendar",
    "HolidayRule",
    "HolidaySource",
    "Match",
    "MatchPolicy",
    "MemoryAuditSink",
    "NthWeekday",
    "Observance",
    "Outcome",
    "OverlapTier",
    "Payroll",
    "PayrollRule",
    "PeerObservation",
    "PriorBook",
    "Route",
    "RoutingDecision",
    "RoutingPolicy",
    "SettlementCycle",
    "StaticSource",
    "StoreAuditSink",
    "StrengthWeights",
    "TemporalPolicy",
    "UnknownDecisionError",
    "Window",
    "__version__",
    "collect_events",
    "data_quality_from_candidates",
    "detector_family",
    "easter",
    "event_id_for",
    "import_csv",
    "import_records",
    "orthodox_easter",
    "parse_deploy_webhook",
]

__version__ = "1.0.0"
