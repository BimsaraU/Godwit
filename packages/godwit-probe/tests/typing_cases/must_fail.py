"""Code that MUST NOT type-check: the logger cannot be handed a customer value.

Each marked line carries ``# EXPECT: <mypy-error-code>``. ``test_leaks.py`` runs mypy
over this file and asserts that every marked line produced that error and no unmarked
line produced any. Excluded from the normal mypy run by the root ``exclude`` pattern.
"""

from __future__ import annotations

from godwit_contracts import Acquisition, data_value, schema_name
from godwit_probe.errors import ErrorCode, ProbeError, Stage
from godwit_probe.telemetry import Event, Field, ProbeTelemetry, SafeId

telemetry = ProbeTelemetry()
column = schema_name("customer_ssn")
value = data_value("100-40-1000", acquisition=Acquisition.DRIVER_EXCEPTION)

# Allowed: our enums, numbers, SafeIds.
telemetry.event(Event.PROBE, {Field.KIND: Event.PROBE, Field.FILES: 3})
telemetry.event(Event.PROBE, {Field.SOURCE: SafeId.of("src", "orders")})

# Refused by the type checker.
telemetry.event(Event.PROBE, {Field.SOURCE: "orders"})  # EXPECT: dict-item
telemetry.event(Event.PROBE, {Field.SOURCE: column})  # EXPECT: dict-item
telemetry.event(Event.PROBE, {Field.REASON: value})  # EXPECT: dict-item
telemetry.event(Event.PROBE, {"source": 1})  # EXPECT: dict-item
telemetry.event("probe.execute", {})  # EXPECT: arg-type
ProbeError("driver said 100-40-1000", stage=Stage.READ)  # EXPECT: arg-type
ProbeError(ErrorCode.SCAN_FAILED, stage=Stage.READ, detail="x")  # EXPECT: call-arg
