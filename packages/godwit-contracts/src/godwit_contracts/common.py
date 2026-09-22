"""Primitives every other contract module builds on.

Nothing here has I/O, wall-clock access or randomness. Contracts are data
definitions plus validation and nothing else.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Final, NewType

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

__all__ = [
    "ArtifactId",
    "AuditId",
    "CandidateId",
    "ContentHash",
    "DeploymentId",
    "GodwitModel",
    "Instant",
    "NonNegFloat",
    "NonNegInt",
    "PatternId",
    "Plane",
    "Probability",
    "ProbeId",
    "ProbeKey",
    "RunId",
    "ScalarValue",
    "SegmentKey",
    "SnapshotId",
    "SourceId",
    "Version",
    "canonical_json",
    "content_hash",
    "is_safe_identifier",
    "require_utc",
]

# --------------------------------------------------------------------------------------
# Identifiers
#
# These are OUR identifiers, minted by Godwit. They are never derived from customer
# values, so they are not tainted. Anything derived from a row value is Tainted[...]
# instead -- see godwit_contracts.taint.
# --------------------------------------------------------------------------------------

SourceId = NewType("SourceId", str)
SnapshotId = NewType("SnapshotId", str)
ProbeId = NewType("ProbeId", str)
CandidateId = NewType("CandidateId", str)
PatternId = NewType("PatternId", str)
RunId = NewType("RunId", str)
ArtifactId = NewType("ArtifactId", str)
AuditId = NewType("AuditId", str)
DeploymentId = NewType("DeploymentId", str)
ContentHash = NewType("ContentHash", str)

ProbeKey = NewType("ProbeKey", str)
"""Stable hash of a ProbeSpec's identity fields. See godwit_contracts.probe.probe_key."""

SegmentKey = NewType("SegmentKey", str)
"""Stable hash of a normalised Segment.

WARNING -- this is a PSEUDONYM, not an anonymisation. A segment over a low-cardinality
domain (``country = 'US'``) can be brute-forced from its key by anyone who can guess the
domain. Guardrails must treat a SegmentKey as DATA_VALUE whenever the population behind
it is small. See docs/ARCHITECTURE.md, open question 3.
"""

type Version = int
"""A monotonically increasing schema or artifact version.

A plain alias rather than a NewType: passing one version where another is expected is
not a category error, and making every model write ``Version(1)`` would buy nothing.
Identifiers are different -- those stay NewTypes, because a PatternId where a SourceId
belongs is a real bug.
"""


class Plane(StrEnum):
    """Which side of the perimeter a thing lives on."""

    CONTROL = "control"
    DATA = "data"
    BOUNDARY = "boundary"


# --------------------------------------------------------------------------------------
# Constrained scalars
# --------------------------------------------------------------------------------------

NonNegInt = Annotated[int, Field(ge=0)]
NonNegFloat = Annotated[float, Field(ge=0.0)]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]


def require_utc(value: _dt.datetime) -> _dt.datetime:
    """Reject naive datetimes and normalise everything else to UTC.

    A naive timestamp is a determinism bug waiting to happen: two agents in two
    timezones would produce two different lineages for the same run.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("naive datetime is not allowed; supply a tz-aware instant")
    return value.astimezone(_dt.UTC)


Instant = Annotated[_dt.datetime, AfterValidator(require_utc)]
"""A tz-aware instant, normalised to UTC. Time is always injected, never read."""

type ScalarValue = str | int | float | bool | Decimal | _dt.date | _dt.datetime | bytes | None
"""Every value type a column predicate or a column bound can hold."""


# --------------------------------------------------------------------------------------
# Base model
# --------------------------------------------------------------------------------------


class GodwitModel(BaseModel):
    """Base for every contract model.

    Frozen, because a contract that mutates under you is not a contract.
    ``extra="forbid"``, because a field nobody declared is a field nobody gated.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        validate_assignment=True,
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )


# --------------------------------------------------------------------------------------
# Canonical serialisation -- the basis of every stable key in the system
# --------------------------------------------------------------------------------------

_JSON_SEPARATORS: Final[tuple[str, str]] = (",", ":")


def canonical_json(obj: object) -> str:
    """Render ``obj`` as the one canonical JSON string Godwit agrees on.

    Rules, so that two independently written implementations agree byte for byte:

    1. Separators are exactly ``","`` and ``":"`` -- no whitespace anywhere.
    2. ``ensure_ascii`` is false; the output is UTF-8 text, not escaped ASCII.
    3. Object keys are sorted by Unicode code point.
    4. Floats, dates, bytes and decimals must already have been rendered to strings by
       :func:`godwit_contracts.segment.canonical_scalar`. Passing a raw float here is a
       bug, because JSON float formatting is not portable.
    """
    return json.dumps(
        obj,
        separators=_JSON_SEPARATORS,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )


def content_hash(payload: str | bytes, *, prefix: str = "b2") -> ContentHash:
    """BLAKE2b-128 of ``payload``, hex, prefixed.

    128 bits is enough: these are identity keys and dedup keys, not MACs. Nothing in
    Godwit relies on a content hash being unguessable -- see the SegmentKey warning.
    """
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    return ContentHash(f"{prefix}_{hashlib.blake2b(data, digest_size=16).hexdigest()}")


_IDENT_RE: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z_][A-Za-z0-9_.\-]{0,127}\Z")


def is_safe_identifier(value: str) -> bool:
    """True if ``value`` is a plain identifier we minted, not something from a row."""
    return bool(_IDENT_RE.match(value))
