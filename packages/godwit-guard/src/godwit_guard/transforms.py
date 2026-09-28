"""The transforms: suppress, hash, bucket, generalise, and tokenise-and-restore.

**Plane: data** for :class:`TokenVault` -- it holds the token-to-value map, which never
crosses the boundary -- and for every function here that takes a revealed value.

TOKENISE AND RESTORE
--------------------
The LLM reasons about ``MERCHANT_7`` and writes a narrative about ``MERCHANT_7``. The
Vision Board resolves ``MERCHANT_7`` back to a value locally, for viewers whose role
permits it. Narrative quality is preserved and zero values egress.

* Tokens are ``<NAMESPACE>_<n>``. The namespace comes from policy or from the column's
  concept (``PERSON``, ``EMAIL``, ``MERCHANT``), never from a value.
* Maps are scoped: one scope per pattern (or per conversation), with an expiry. The
  same value gets the same token within a scope and an unrelated one in another, so
  two narratives cannot be joined on tokens by anyone outside the perimeter.
* Numbering is by first appearance within a scope: deterministic for a given sequence
  of calls, and it carries no information about the value.
* The vault refuses to be copied, pickled or rendered. The gate only ever sees the
  ``Tainted[str]`` tokens it issues; :meth:`TokenVault.map_ref` is the *reference* the
  EgressRecord carries.
"""

from __future__ import annotations

import datetime as _dt
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from types import MappingProxyType
from typing import Final, NoReturn

from godwit_contracts import (
    Acquisition,
    Instant,
    Provenance,
    SafeScalar,
    ScalarValue,
    Sensitivity,
    Tainted,
    canonical_json,
    content_hash,
    token,
)
from godwit_contracts.segment import canonical_scalar

from godwit_guard.errors import TokenScopeError

__all__ = [
    "BUILTIN_HIERARCHIES",
    "TOKEN_PATTERN",
    "Generaliser",
    "TokenVault",
    "bucket",
    "generalise",
    "mapping_hierarchy",
    "to_safe_scalar",
]

type Generaliser = Callable[[ScalarValue, int], str | None]

TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"\b([A-Z][A-Z0-9]*)_(\d+)\b")
_NAMESPACE: Final[re.Pattern[str]] = re.compile(r"[A-Z][A-Z0-9]{0,31}")


def to_safe_scalar(value: ScalarValue) -> SafeScalar | None:
    """Render a value as a flat scalar, or None if it cannot be one safely.

    Bytes never leave as scalars. Non-finite floats cannot be canonicalised.
    """
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Decimal):
        return str(value) if value.is_finite() else None
    if isinstance(value, _dt.datetime | _dt.date):
        return value.isoformat()
    return None


# --------------------------------------------------------------------------------------
# Bucket
# --------------------------------------------------------------------------------------


def _as_number(value: ScalarValue) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float | Decimal):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return None
        return number if math.isfinite(number) else None
    return None


def _fmt(number: float) -> str:
    return str(int(number)) if number.is_integer() else repr(number)


def bucket(value: ScalarValue, params: Mapping[str, int | float | str | bool]) -> str | None:
    """Numbers into ``[lo, hi)`` ranges of ``width``; dates into ``period`` s.

    Returns None when the value does not fit the parameters, which callers treat as
    "suppress" -- a transform that cannot apply must never fall back to the raw value.
    """
    if isinstance(value, _dt.date):
        day = value.date() if isinstance(value, _dt.datetime) else value
        period = str(params.get("period", "month"))
        if period == "year":
            return f"{day.year:04d}"
        if period == "quarter":
            return f"{day.year:04d}-Q{(day.month - 1) // 3 + 1}"
        if period == "month":
            return f"{day.year:04d}-{day.month:02d}"
        return None
    width_param = params.get("width")
    number = _as_number(value)
    if number is None or isinstance(width_param, bool | str) or width_param is None:
        return None
    width = float(width_param)
    if width <= 0:
        return None
    origin_param = params.get("origin", 0)
    origin = 0.0 if isinstance(origin_param, bool | str) else float(origin_param)
    low = origin + math.floor((number - origin) / width) * width
    return f"[{_fmt(low)}, {_fmt(low + width)})"


# --------------------------------------------------------------------------------------
# Generalise
# --------------------------------------------------------------------------------------


def _postcode(value: ScalarValue, level: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    if re.fullmatch(r"\d{5}(-\d{4})?", text):
        keep = 3 if level <= 1 else 1
        return text[:keep] + "*" * (5 - keep)
    uk = re.fullmatch(r"([A-Z]{1,2})(\d[A-Z\d]?) ?\d[A-Z]{2}", text)
    if uk:
        return uk.group(1) + uk.group(2) if level <= 1 else uk.group(1)
    return None


def _prefix(value: ScalarValue, level: int) -> str | None:
    if not isinstance(value, str) or level < 1 or len(value) <= level:
        return None
    return value[:level] + "*"


def _magnitude(value: ScalarValue, _level: int) -> str | None:
    number = _as_number(value)
    if number is None:
        return None
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    exponent = math.floor(math.log10(abs(number)))
    low, high = 10**exponent, 10 ** (exponent + 1)
    return f"{sign}[{_fmt(float(low))}, {_fmt(float(high))})"


def _date(value: ScalarValue, level: int) -> str | None:
    if not isinstance(value, _dt.date):
        return None
    return bucket(value, {"period": "month" if level <= 1 else "year"})


def mapping_hierarchy(mapping: Mapping[str, str], *, default: str | None = None) -> Generaliser:
    """A one-level hierarchy from an explicit table, e.g. occupation to category.

    Unmapped values become ``default``, or are suppressed if there is none. The table is
    configuration written by a person; a value never becomes its own category.
    """
    table = {key.casefold(): target for key, target in mapping.items()}

    def _generalise(value: ScalarValue, _level: int) -> str | None:
        if not isinstance(value, str):
            return None
        return table.get(value.strip().casefold(), default)

    return _generalise


BUILTIN_HIERARCHIES: Final[Mapping[str, Generaliser]] = MappingProxyType(
    {
        "postcode": _postcode,
        "prefix": _prefix,
        "magnitude": _magnitude,
        "date": _date,
    }
)
"""``postcode``: UK outward code or area (level 1/2), US ZIP3 or ZIP1.
``prefix``: keep ``level`` leading characters. ``magnitude``: order-of-magnitude band.
``date``: month (level 1) or year (level 2)."""


def generalise(
    value: ScalarValue,
    params: Mapping[str, int | float | str | bool],
    hierarchies: Mapping[str, Generaliser] = BUILTIN_HIERARCHIES,
) -> str | None:
    """Apply the hierarchy named in ``params['hierarchy']`` at ``params['level']``."""
    name = params.get("hierarchy")
    level = params.get("level", 1)
    if not isinstance(name, str) or isinstance(level, bool) or not isinstance(level, int):
        return None
    generaliser = hierarchies.get(name)
    return None if generaliser is None else generaliser(value, level)


# --------------------------------------------------------------------------------------
# Tokenise and restore -- DATA PLANE
# --------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Scope:
    expires_at: Instant
    forward: dict[tuple[str, str], str] = field(default_factory=dict)
    reverse: dict[str, ScalarValue] = field(default_factory=dict)
    counters: dict[str, int] = field(default_factory=dict)


class TokenVault:
    """The token-to-value map. **Data plane.** It never crosses the boundary.

    ``restore_roles`` maps a token namespace (or ``"*"`` for all) to the viewer roles
    allowed to see the underlying values. A viewer without such a role gets the tokens
    back unchanged.
    """

    __slots__ = ("_restore_roles", "_scopes", "_vault_id")

    def __init__(self, vault_id: str, *, restore_roles: Mapping[str, frozenset[str]]) -> None:
        if not vault_id:
            raise ValueError("a vault needs an id")
        self._vault_id = vault_id
        self._restore_roles = dict(restore_roles)
        self._scopes: dict[str, _Scope] = {}

    def open_scope(self, scope_id: str, *, expires_at: Instant) -> None:
        """Create a scope. Re-opening with the same expiry is a no-op."""
        existing = self._scopes.get(scope_id)
        if existing is not None:
            if existing.expires_at != expires_at:
                raise TokenScopeError("a scope's expiry is fixed when it is opened")
            return
        self._scopes[scope_id] = _Scope(expires_at=expires_at)

    def has_live_scope(self, scope_id: str, *, at: Instant) -> bool:
        """True if the scope exists and has not expired."""
        scope = self._scopes.get(scope_id)
        return scope is not None and at < scope.expires_at

    def map_ref(self, scope_id: str) -> str:
        """An opaque *reference* to a scope's map, for the EgressRecord. Never the map."""
        return content_hash(canonical_json([self._vault_id, scope_id]), prefix="tmap")

    def tokenise(
        self, value: Tainted[ScalarValue], *, scope_id: str, namespace: str, at: Instant
    ) -> Tainted[str]:
        """Replace ``value`` with a token, stable within the scope."""
        if not _NAMESPACE.fullmatch(namespace):
            raise ValueError("token namespaces are upper-case words from policy, not data")
        scope = self._live(scope_id, at)
        key = (namespace, canonical_scalar(value.reveal()))
        issued = scope.forward.get(key)
        if issued is None:
            scope.counters[namespace] = scope.counters.get(namespace, 0) + 1
            issued = f"{namespace}_{scope.counters[namespace]}"
            scope.forward[key] = issued
            scope.reverse[issued] = value.reveal()
        return token(issued, upstream=value.provenance, population=value.population)

    def restore(
        self, text: str, *, scope_id: str, roles: frozenset[str], at: Instant
    ) -> Tainted[str]:
        """Resolve tokens in ``text`` for a viewer holding ``roles``. **Data plane.**

        The result contains row values again, so it comes back ``DATA_VALUE``-tainted:
        showing it to the viewer is a UI egress like any other.
        """
        scope = self._live(scope_id, at)

        def _swap(match: re.Match[str]) -> str:
            tok = match.group(0)
            if tok not in scope.reverse or not self._permits(match.group(1), roles):
                return tok
            return str(scope.reverse[tok])

        return Tainted[str](
            value=TOKEN_PATTERN.sub(_swap, text),
            sensitivity=Sensitivity.DATA_VALUE,
            provenance=Provenance(
                acquisition=Acquisition.GATE_TOKENISATION, detail="restored from a token scope"
            ),
        )

    def purge_expired(self, *, at: Instant) -> int:
        """Delete every expired scope's map. Returns how many were purged."""
        expired = [sid for sid, scope in self._scopes.items() if at >= scope.expires_at]
        for sid in expired:
            del self._scopes[sid]
        return len(expired)

    def _permits(self, namespace: str, roles: frozenset[str]) -> bool:
        allowed = self._restore_roles.get(namespace, frozenset()) | self._restore_roles.get(
            "*", frozenset()
        )
        return bool(allowed & roles)

    def _live(self, scope_id: str, at: Instant) -> _Scope:
        scope = self._scopes.get(scope_id)
        if scope is None:
            raise TokenScopeError("unknown token scope")
        if at >= scope.expires_at:
            raise TokenScopeError("token scope has expired")
        return scope

    def __repr__(self) -> str:
        return f"<TokenVault {self._vault_id} scopes={len(self._scopes)}>"

    def __reduce__(self) -> NoReturn:
        raise TypeError("the token map never leaves the data plane; it cannot be pickled")

    def __copy__(self) -> NoReturn:
        raise TypeError("the token map cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise TypeError("the token map cannot be copied")
