"""``SafePayload`` -- the only type the LLM adapter accepts.

Invariant 4 says the LLM never scans data. Invariant 2 says nothing data-derived
reaches an LLM except through the gate. Together they mean the LLM adapter must accept
exactly one input type, and that type must be impossible to produce by ordinary code.

The mechanism, in order of how much work it does:

1. ``SafePayload`` has no public constructor. ``__new__`` refuses.
2. It cannot be subclassed. ``__init_subclass__`` refuses.
3. **Its contents do not live on the instance.** They live in a module-private
   ``WeakKeyDictionary`` keyed by the object. A shell conjured with
   ``object.__new__`` is therefore inert: every accessor raises ``ForgedObjectError``.
   This is the load-bearing step. Bypassing a constructor gains you an empty husk.
4. Copy and pickle are refused, so an authentic payload cannot be cloned into a
   payload with different contents.
5. The single ``SafePayloadIssuer`` capability is claimed once per process, by name,
   and every issue records the ``EgressRecord`` that authorised it. No egress record,
   no payload.

Honest limit: this is a Python process, so ``ctypes`` or a debugger can still reach into
memory. The guarantee on offer is that a payload cannot be produced *by ordinary code*,
by accident, or without leaving an audit trail -- not that it resists a hostile
in-process attacker. See docs/ARCHITECTURE.md, open question 1.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, NoReturn, SupportsIndex
from weakref import WeakKeyDictionary

from godwit_contracts.common import ContentHash, canonical_json, content_hash
from godwit_contracts.errors import (
    ForgedObjectError,
    IssuerAlreadyClaimedError,
    SealedConstructionError,
)

__all__ = [
    "SafePayload",
    "SafePayloadIssuer",
    "SafeScalar",
    "claim_safe_payload_issuer",
    "issuer_claimant",
]

type SafeScalar = str | int | float | bool | None
"""What may appear in a SafePayload field. No nested structures, no bytes, no objects.

Flat scalars only, so the gate's audit log can record exactly what left, field by field,
and so nothing can smuggle a tainted object through inside a container.
"""


@dataclass(frozen=True, slots=True)
class _Contents:
    purpose: str
    fields: Mapping[str, SafeScalar]
    policy_id: str
    policy_version: int
    egress_record_id: str
    digest: ContentHash


_CONTENTS: Final[WeakKeyDictionary[SafePayload, _Contents]] = WeakKeyDictionary()
_CLAIM_LOCK: Final[threading.Lock] = threading.Lock()
_CLAIM_STATE: Final[dict[str, str]] = {}
"""Holds at most one entry, ``"claimant"``. A dict rather than a module global so that
claiming needs no ``global`` statement and therefore no lint suppression."""


def _refuse(what: str) -> NoReturn:
    raise SealedConstructionError(
        f"{what} may only be produced by godwit-guard via claim_safe_payload_issuer()"
    )


class SafePayload:
    """A flat bag of scalars that the gate has cleared for a named destination.

    Construction is impossible from outside this module. Read the module docstring for
    why, and ``tests/test_safe_payload_forgery.py`` for the five attempts that fail.
    """

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> SafePayload:
        """Always refuses. Declared as returning ``SafePayload`` so that the class is
        still a usable annotation; the body never returns."""
        _refuse("SafePayload")

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("SafePayload is final and cannot be subclassed")

    def _contents(self) -> _Contents:
        try:
            return _CONTENTS[self]
        except KeyError as exc:
            raise ForgedObjectError(
                "this SafePayload was never issued by the gate; it has no contents"
            ) from exc

    @property
    def purpose(self) -> str:
        """Why this left the perimeter. Recorded on the EgressRecord too."""
        return self._contents().purpose

    @property
    def fields(self) -> Mapping[str, SafeScalar]:
        """The cleared scalars. Read-only."""
        return self._contents().fields

    @property
    def policy_id(self) -> str:
        """Which RedactionPolicy cleared this."""
        return self._contents().policy_id

    @property
    def policy_version(self) -> int:
        """Which version of that policy. Policies are versioned, never edited in place."""
        return self._contents().policy_version

    @property
    def egress_record_id(self) -> str:
        """The immutable audit entry that authorised this payload."""
        return self._contents().egress_record_id

    @property
    def digest(self) -> ContentHash:
        """Hash of the cleared fields, so the audit log can prove what left."""
        return self._contents().digest

    def __repr__(self) -> str:
        try:
            contents = self._contents()
        except ForgedObjectError:
            return "<SafePayload forged: no contents>"
        return (
            f"<SafePayload purpose={contents.purpose!r} "
            f"policy={contents.policy_id}@{contents.policy_version} "
            f"egress={contents.egress_record_id} fields={len(contents.fields)}>"
        )

    # Copying a payload would let a caller clone the authorisation onto other contents.
    def __copy__(self) -> NoReturn:
        _refuse("A copy of SafePayload")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        _refuse("A copy of SafePayload")

    def __reduce__(self) -> NoReturn:
        _refuse("A pickled SafePayload")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        _refuse("A pickled SafePayload")

    def __getstate__(self) -> NoReturn:
        _refuse("A serialised SafePayload")


class SafePayloadIssuer:
    """The one capability that can mint a ``SafePayload``. Held by godwit-guard."""

    __slots__ = ("_claimant",)

    _claimant: str

    def __new__(cls, *_args: object, **_kwargs: object) -> SafePayloadIssuer:
        """Always refuses; the capability comes from claim_safe_payload_issuer()."""
        _refuse("SafePayloadIssuer")

    @property
    def claimant(self) -> str:
        """Name the holder registered under. Recorded so audits can attribute issues."""
        return self._claimant

    def issue(
        self,
        *,
        purpose: str,
        fields: Mapping[str, SafeScalar],
        policy_id: str,
        policy_version: int,
        egress_record_id: str,
    ) -> SafePayload:
        """Mint a payload.

        ``egress_record_id`` is mandatory and is not validated here -- contracts do no
        I/O -- but godwit-guard must have written the record *before* calling. The
        design rule is: a SafePayload exists if and only if an EgressRecord exists.
        """
        if not purpose:
            raise ValueError("purpose is required; the audit log needs a reason")
        if not egress_record_id:
            raise ValueError("egress_record_id is required; no record, no payload")
        cleared = _validate_fields(fields)
        payload = object.__new__(SafePayload)
        _CONTENTS[payload] = _Contents(
            purpose=purpose,
            fields=cleared,
            policy_id=policy_id,
            policy_version=policy_version,
            egress_record_id=egress_record_id,
            digest=content_hash(canonical_json(dict(cleared))),
        )
        return payload


def _validate_fields(fields: Mapping[str, SafeScalar]) -> Mapping[str, SafeScalar]:
    cleared: dict[str, SafeScalar] = {}
    for key, value in fields.items():
        if not isinstance(key, str):
            raise TypeError(f"SafePayload field names must be str, got {type(key)!r}")
        if not isinstance(value, str | int | float | bool | type(None)):
            raise TypeError(
                f"field {key!r}: SafePayload holds flat scalars only, got {type(value)!r}. "
                "If this is a Tainted value, it has not been through the gate."
            )
        cleared[key] = value
    return MappingProxyType(cleared)


def claim_safe_payload_issuer(*, claimant: str) -> SafePayloadIssuer:
    """Claim the single issuer capability. Succeeds exactly once per process.

    godwit-guard claims it at import time. Anything else that claims it first has, by
    construction, taken the gate's job -- and the second claim fails loudly, which is
    how you find out.
    """
    if not claimant:
        raise ValueError("claimant is required")
    with _CLAIM_LOCK:
        held = _CLAIM_STATE.get("claimant")
        if held is not None:
            raise IssuerAlreadyClaimedError(f"the SafePayload issuer is already held by {held!r}")
        _CLAIM_STATE["claimant"] = claimant
        issuer = object.__new__(SafePayloadIssuer)
        object.__setattr__(issuer, "_claimant", claimant)
        return issuer


def issuer_claimant() -> str | None:
    """Who holds the issuer, or None. For audit and for tests."""
    return _CLAIM_STATE.get("claimant")
