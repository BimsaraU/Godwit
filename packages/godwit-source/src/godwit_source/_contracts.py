"""Single import point for A0's contracts.

Everything in ``godwit-source`` imports contract types from here and never from the stub
directly. When ``godwit-contracts`` is installed its types win, unconditionally, with no
merge and no adaptation layer -- this module is an import switch, not a compatibility shim.
"""

from __future__ import annotations

try:  # pragma: no cover - exercised by whichever half of the branch is installed
    from godwit_contracts import (
        Candidate,
        ColumnAccessMode,
        CostBudget,
        CostBudgetExceeded,
        Evidence,
        PiiClass,
        ProbeSpec,
        Segment,
        SemanticRole,
        SketchBundle,
        Tainted,
        TaintKind,
        data_value,
        derived_statistic,
    )

    CONTRACTS_ARE_PROVISIONAL = False
except ImportError:  # pragma: no cover
    from ._contracts_stub import (
        Candidate,
        ColumnAccessMode,
        CostBudget,
        CostBudgetExceeded,
        Evidence,
        PiiClass,
        ProbeSpec,
        Segment,
        SemanticRole,
        SketchBundle,
        Tainted,
        TaintKind,
        data_value,
        derived_statistic,
    )

    CONTRACTS_ARE_PROVISIONAL = True

__all__ = [
    "CONTRACTS_ARE_PROVISIONAL",
    "Candidate",
    "ColumnAccessMode",
    "CostBudget",
    "CostBudgetExceeded",
    "Evidence",
    "PiiClass",
    "ProbeSpec",
    "Segment",
    "SemanticRole",
    "SketchBundle",
    "TaintKind",
    "Tainted",
    "data_value",
    "derived_statistic",
]
