"""Column classification: refine A1's first pass into a proposal a human confirms.

**Plane: data** for :func:`propose` (it reads sample values to recognise formats) and
**boundary** for :class:`ClassificationRegistry` (which holds proposals and human
confirmations, and never a value).

Three rules shape everything here:

1. A classification is a PROPOSAL until a human confirms it.
2. An unconfirmed column is treated at the MOST RESTRICTIVE PLAUSIBLE class, not the most
   likely one. If one value in ten looks like a card number, the column is plausibly
   FINANCIAL and it is handled as such until somebody with authority says otherwise.
3. Quasi-identifiers matter in combination. Postcode, birth date and sex are each
   harmless-looking; together they re-identify most people. :func:`quasi_identifier_combinations`
   flags the combinations, not only the columns.

The name vocabulary in :data:`CONCEPTS` is shared with :mod:`godwit_guard.schema_names`
(which turns a column name into a description without echoing it) and with
:mod:`godwit_guard.access` (which uses its input-space priors for the entropy check).
"""

from __future__ import annotations

import itertools
import math
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from godwit_contracts import (
    ColumnProfile,
    ColumnRef,
    ColumnRole,
    GodwitModel,
    Instant,
    LogicalType,
    NonNegInt,
    PiiClass,
    Provenance,
    ScalarValue,
    SourceId,
    Tainted,
    canonical_json,
    content_hash,
)
from godwit_contracts.segment import canonical_column

from godwit_guard.disclosure import MIN_K

__all__ = [
    "CONCEPTS",
    "PII_RESTRICTIVENESS",
    "RECOGNISERS",
    "CatalogEntry",
    "ClassificationProposal",
    "ClassificationRegistry",
    "Concept",
    "Confirmation",
    "QuasiIdentifierCombination",
    "Recogniser",
    "Signal",
    "SignalSource",
    "column_key",
    "iban_valid",
    "luhn_valid",
    "match_concept",
    "most_restrictive",
    "propose",
    "quasi_identifier_combinations",
    "ref_key",
]

PII_RESTRICTIVENESS: Final[dict[PiiClass, int]] = {
    PiiClass.NONE: 0,
    PiiClass.QUASI_IDENTIFIER: 1,
    PiiClass.FINANCIAL: 2,
    PiiClass.SENSITIVE_ATTRIBUTE: 2,
    PiiClass.DIRECT_IDENTIFIER: 3,
    PiiClass.HEALTH: 3,
    PiiClass.CREDENTIAL: 4,
    PiiClass.UNKNOWN: 5,
}
"""Higher is more restricted. UNKNOWN is the most restricted class of all: deny by default."""

_CLASS_ORDER: Final[tuple[PiiClass, ...]] = tuple(PiiClass)


def most_restrictive(classes: Iterable[PiiClass]) -> PiiClass:
    """The most restricted class in ``classes``. Ties break by enum order, deterministically."""
    ranked = sorted(classes, key=lambda c: (PII_RESTRICTIVENESS[c], -_CLASS_ORDER.index(c)))
    if not ranked:
        raise ValueError("most_restrictive() needs at least one class")
    return ranked[-1]


# --------------------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------------------


def column_key(source_id: str | None, table: str | None, column: str) -> str:
    """Stable key for one column.

    A PSEUDONYM of the column's name, not an anonymisation: anyone who can guess the
    name can compute the key. It is used as an index inside the boundary, never shown.
    """
    canonical = canonical_json(
        [source_id or "", canonical_column(table or ""), canonical_column(column)]
    )
    return content_hash(canonical, prefix="col")


def ref_key(ref: ColumnRef) -> str:
    """:func:`column_key` for a contract ``ColumnRef``."""
    return column_key(ref.source_id, ref.table.reveal(), ref.column.reveal())


# --------------------------------------------------------------------------------------
# The name vocabulary
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Concept:
    """One thing a column name can mean, and what that implies.

    ``phrase`` is what DESCRIBED schema mode says instead of the name. It is drawn from
    this closed table and nowhere else, which is why a description cannot echo a name.
    ``space`` is the plausible number of distinct real-world values, used by the
    minimum-entropy check. ``None`` means "no prior; use the evidence".
    """

    name: str
    pattern: re.Pattern[str]
    pii_class: PiiClass | None
    phrase: str
    space: int | None = None


def _c(
    name: str, pattern: str, pii: PiiClass | None, phrase: str, space: int | None = None
) -> Concept:
    return Concept(name, re.compile(pattern), pii, phrase, space)


_P = PiiClass
CONCEPTS: Final[tuple[Concept, ...]] = (
    # Order matters: the first match wins, so the specific precede the generic.
    _c("pin", r"(^|_)pin(_|$)|pin_?code", _P.CREDENTIAL, "short numeric secret", 10**4),
    _c("credential", r"passw|secret|api_?key|token|credential", _P.CREDENTIAL, "credential"),
    _c(
        "health",
        r"hiv|diagnos|patient|medic|health|disease|icd_|prescri",
        _P.HEALTH,
        "health attribute",
    ),
    _c("nic_prefix", r"nic_?prefix", _P.QUASI_IDENTIFIER, "national identifier prefix", 73_200),
    _c(
        "government_id",
        r"ssn|social_?sec|national_?id|nino|(^|_)nic(_|$)|passport|tax_?id|(^|_)(tin|ein)(_|$)"
        r"|aadhaar|driver_?lic",
        _P.DIRECT_IDENTIFIER,
        "government identifier",
        10**9,
    ),
    _c("email", r"e_?mail", _P.DIRECT_IDENTIFIER, "email address", 2**32),
    _c("phone", r"phone|mobile|msisdn|(^|_)tel(_|$)", _P.DIRECT_IDENTIFIER, "phone number", 10**10),
    _c(
        "card",
        r"card_?(num|no)|credit_?card|(^|_)pan(_|$)",
        _P.FINANCIAL,
        "payment card number",
        10**12,
    ),
    _c(
        "bank_account",
        r"iban|account_?(num|no)|bank_?acc",
        _P.FINANCIAL,
        "bank account number",
        10**12,
    ),
    _c(
        "counterparty",
        r"merchant|vendor|payee|counterpart|seller",
        _P.QUASI_IDENTIFIER,
        "counterparty",
    ),
    _c("device", r"device|imei|fingerprint|user_?agent", _P.QUASI_IDENTIFIER, "device identifier"),
    _c("network", r"(^|_)ip(_|$)|ip_?addr", _P.QUASI_IDENTIFIER, "network address", 2**32),
    _c("birth_date", r"(^|_)dob(_|$)|birth", _P.QUASI_IDENTIFIER, "birth date", 36_525),
    _c("sex", r"(^|_)(sex|gender)(_|$)", _P.QUASI_IDENTIFIER, "demographic attribute", 16),
    _c("age", r"(^|_)age(_|$)", _P.QUASI_IDENTIFIER, "age", 130),
    _c("postcode", r"post_?code|postal|(^|_)zip", _P.QUASI_IDENTIFIER, "postal code", 1_800_000),
    _c("country", r"country|nationality", _P.QUASI_IDENTIFIER, "country", 250),
    _c(
        "location",
        r"city|region|address|street|(^|_)(lat|lon|lng)(_|$)|latitude|longitude",
        _P.QUASI_IDENTIFIER,
        "location",
    ),
    _c(
        "special_category",
        r"religio|ethnic|(^|_)race(_|$)|sexual|politic|trade_?union|biometric",
        _P.SENSITIVE_ATTRIBUTE,
        "special-category attribute",
    ),
    _c("income", r"salary|income|wage|payroll|compensation", _P.FINANCIAL, "income amount"),
    _c(
        "money",
        r"amount|price|balance|payment|(^|_)fee|revenue|cost|charge",
        _P.FINANCIAL,
        "monetary amount",
    ),
    _c(
        "person_name",
        r"(^|_)((full|first|last|sur|given|middle|maiden)_?)?name(_|$)",
        _P.DIRECT_IDENTIFIER,
        "personal name",
        2**30,
    ),
    _c(
        "free_text",
        r"note|comment|memo|remark|descript|message|(^|_)body(_|$)",
        _P.SENSITIVE_ATTRIBUTE,
        "free text",
    ),
    _c(
        "grouping",
        r"cohort|segment|(^|_)group|tier|(^|_)band(_|$)",
        _P.QUASI_IDENTIFIER,
        "grouping label",
    ),
    _c("timestamp", r"_at$|_time$|_date$|timestamp|_ts$|(^|_)date(_|$)", None, "timestamp"),
    _c(
        "label",
        r"(^|_)(label|target|outcome)(_|$)|is_fraud|fraud_flag|churn",
        None,
        "outcome label",
    ),
    _c("status", r"status|state|(^|_)flag(_|$)", None, "status"),
    _c("identifier", r"(^|_)(id|uuid|guid|key)(_|$)", _P.QUASI_IDENTIFIER, "identifier"),
)


def match_concept(column_name: str) -> Concept | None:
    """The first concept whose pattern matches the casefolded name, or None."""
    lowered = canonical_column(column_name)
    for concept in CONCEPTS:
        if concept.pattern.search(lowered):
            return concept
    return None


# --------------------------------------------------------------------------------------
# Value recognisers -- DATA PLANE: these look at values
# --------------------------------------------------------------------------------------


_MIN_LUHN_DIGITS: Final[int] = 2
_LUHN_DOUBLED: Final[tuple[int, ...]] = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)
_CARD_LENGTHS: Final[range] = range(13, 20)
_PHONE_DIGITS: Final[range] = range(8, 16)
_NIC_DAYS: Final[frozenset[int]] = frozenset(range(1, 367)) | frozenset(range(501, 867))
"""Day-of-year field of a Sri Lankan NIC: 1-366, plus 500 for women."""


def luhn_valid(digits: str) -> bool:
    """The Luhn checksum over a string of digits. Payment cards satisfy it."""
    if not digits.isdigit() or len(digits) < _MIN_LUHN_DIGITS:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit = _LUHN_DOUBLED[digit]
        total += digit
    return total % 10 == 0


def iban_valid(candidate: str) -> bool:
    """ISO 13616 mod-97 check. Spaces are ignored; case is not."""
    compact = candidate.replace(" ", "")
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1


def _card(value: str) -> bool:
    compact = re.sub(r"[ -]", "", value)
    return len(compact) in _CARD_LENGTHS and luhn_valid(compact)


def _phone(value: str) -> bool:
    if not re.fullmatch(r"\+?\d[\d\s().-]{6,}\d", value):
        return False
    return sum(char.isdigit() for char in value) in _PHONE_DIGITS


def _lk_nic(value: str) -> bool:
    """Sri Lankan NIC, old (9 digits + V/X) and new (12 digits) formats.

    Digits encode birth year and day of year (+500 for women), which is exactly why a
    NIC *prefix* is enumerable and fails the entropy check in :mod:`godwit_guard.access`.
    """
    old = re.fullmatch(r"\d{2}(\d{3})\d{4}[VvXx]", value)
    new = re.fullmatch(r"(?:19|20)\d{2}(\d{3})\d{5}", value)
    match = old or new
    if match is None:
        return False
    day = int(match.group(1))
    return day in _NIC_DAYS


_GIVEN_NAMES: Final[frozenset[str]] = frozenset(
    (
        "james",
        "mary",
        "john",
        "patricia",
        "robert",
        "jennifer",
        "michael",
        "linda",
        "william",
        "elizabeth",
        "david",
        "barbara",
        "richard",
        "susan",
        "joseph",
        "jessica",
        "thomas",
        "sarah",
        "charles",
        "karen",
        "mohammed",
        "muhammad",
        "ahmed",
        "fatima",
        "ali",
        "aisha",
        "omar",
        "yusuf",
        "wei",
        "li",
        "zhang",
        "ming",
        "hiroshi",
        "yuki",
        "haruto",
        "sakura",
        "raj",
        "anil",
        "sunil",
        "priya",
        "ravi",
        "deepa",
        "kumar",
        "nimal",
        "kamal",
        "chamari",
        "dilshan",
        "tharindu",
        "olga",
        "ivan",
        "dmitri",
        "anna",
        "maria",
        "jose",
        "juan",
        "carlos",
        "ana",
        "luis",
        "pedro",
        "pierre",
        "marie",
        "jean",
        "sophie",
        "hans",
        "lena",
        "erik",
        "lars",
        "ingrid",
        "sven",
        "emma",
        "noah",
        "liam",
        "olivia",
        "amara",
        "kwame",
        "kofi",
        "ama",
        "chinedu",
        "ngozi",
        "siobhan",
        "sean",
        "niamh",
        "ciaran",
    )
)
"""A deliberately small, multi-regional given-name vocabulary.

It is a *boost*, not the detector: the person-name recogniser fires on format when most
samples look like names, and the vocabulary lets it fire on a thinner sample."""


def _person_name(value: str) -> bool:
    if not re.fullmatch(r"[A-Z][a-z'\-]+(?: [A-Z][a-z'\-]+){1,3}", value):
        return False
    return value.split(" ", 1)[0].casefold() in _GIVEN_NAMES


def _person_name_format(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][a-z'\-]+(?: [A-Z][a-z'\-]+){1,3}", value))


@dataclass(frozen=True, slots=True)
class Recogniser:
    """A format signature over a single string value."""

    name: str
    pii_class: PiiClass
    matches: Callable[[str], bool]
    min_support: float = 0.0
    """Fraction of samples that must match before the signal counts. Zero means one
    match anywhere is enough to make the class *plausible* -- fail closed."""


def _rx(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern)
    return lambda value: compiled.fullmatch(value) is not None


RECOGNISERS: Final[tuple[Recogniser, ...]] = (
    Recogniser("us_ssn", _P.DIRECT_IDENTIFIER, _rx(r"\d{3}-\d{2}-\d{4}")),
    Recogniser("email", _P.DIRECT_IDENTIFIER, _rx(r"[^@\s]+@[^@\s]+\.[^@\s]+")),
    Recogniser("payment_card", _P.FINANCIAL, _card),
    Recogniser("iban", _P.FINANCIAL, iban_valid),
    Recogniser("lk_nic", _P.DIRECT_IDENTIFIER, _lk_nic),
    Recogniser(
        "uk_nino",
        _P.DIRECT_IDENTIFIER,
        _rx(r"(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]"),
    ),
    Recogniser("us_ein", _P.DIRECT_IDENTIFIER, _rx(r"\d{2}-\d{7}")),
    Recogniser("in_pan", _P.DIRECT_IDENTIFIER, _rx(r"[A-Z]{5}\d{4}[A-Z]")),
    Recogniser("phone", _P.DIRECT_IDENTIFIER, _phone),
    Recogniser("ipv4", _P.QUASI_IDENTIFIER, _rx(r"(?:\d{1,3}\.){3}\d{1,3}")),
    Recogniser("uk_postcode", _P.QUASI_IDENTIFIER, _rx(r"[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}")),
    Recogniser("iso_date", _P.QUASI_IDENTIFIER, _rx(r"(?:19|20)\d{2}-[01]\d-[0-3]\d")),
    Recogniser("person_name_vocab", _P.DIRECT_IDENTIFIER, _person_name),
    Recogniser("person_name_format", _P.DIRECT_IDENTIFIER, _person_name_format, 0.8),
)


# --------------------------------------------------------------------------------------
# Proposals
# --------------------------------------------------------------------------------------


class SignalSource(StrEnum):
    """Where a classification signal came from."""

    UPSTREAM = "upstream"
    NAME = "name"
    VALUE_FORMAT = "value_format"
    CARDINALITY = "cardinality"


class Signal(GodwitModel):
    """One piece of evidence for a class. Names a detector, never a value."""

    source: SignalSource
    detector: str
    pii_class: PiiClass
    support: float
    """Fraction of samples that matched, or 1.0 for name and first-pass signals."""


class ClassificationProposal(GodwitModel):
    """What the classifier thinks about one column, pending human confirmation."""

    column: ColumnRef
    logical_type: LogicalType
    role: ColumnRole
    first_pass: PiiClass
    likely: PiiClass
    plausible: tuple[PiiClass, ...]
    signals: tuple[Signal, ...] = ()
    concept: str | None = None
    row_count: NonNegInt | None = None
    distinct_estimate: NonNegInt | None = None

    @property
    def most_restrictive_plausible(self) -> PiiClass:
        """How an UNCONFIRMED column is treated. Not :attr:`likely`: fail closed."""
        return most_restrictive(self.plausible)


STRONG_SUPPORT: Final[float] = 0.5
"""Fraction of samples a format must match to drive the LIKELY class."""

NEAR_UNIQUE_RATIO: Final[float] = 0.9
"""Distinct-over-rows above which a column behaves like an identifier."""


def _reveal_int(value: Tainted[int] | None) -> int | None:
    # Derived statistics about the column; revealed inside the boundary to rank risk.
    return None if value is None else int(value.reveal())


def propose(
    profile: ColumnProfile, *, sample: Sequence[ScalarValue] = ()
) -> ClassificationProposal:
    """Refine A1's first-pass ``pii_class`` into a proposal. **Data plane.**

    Uses the column name, value format signatures over ``sample`` plus the profile's own
    bounds and most-common values, jurisdiction-specific identifier formats, and
    cardinality relative to row count. Returns a proposal; nothing is decided until a
    human calls :meth:`ClassificationRegistry.confirm`.
    """
    name = profile.ref.column.reveal()
    concept = match_concept(name)
    signals: list[Signal] = []
    if profile.pii_class is not PiiClass.UNKNOWN:
        signals.append(
            Signal(
                source=SignalSource.UPSTREAM,
                detector="godwit_source",
                pii_class=profile.pii_class,
                support=1.0,
            )
        )
    if concept is not None and concept.pii_class is not None:
        signals.append(
            Signal(
                source=SignalSource.NAME,
                detector=concept.name,
                pii_class=concept.pii_class,
                support=1.0,
            )
        )

    values = _string_samples(profile, sample)
    for recogniser in RECOGNISERS:
        if not values:
            break
        hits = sum(1 for value in values if recogniser.matches(value))
        support = hits / len(values)
        if hits and support >= recogniser.min_support:
            signals.append(
                Signal(
                    source=SignalSource.VALUE_FORMAT,
                    detector=recogniser.name,
                    pii_class=recogniser.pii_class,
                    support=round(support, 4),
                )
            )

    rows = _reveal_int(profile.row_count)
    distinct = _reveal_int(profile.distinct_estimate)
    near_unique = (
        rows is not None
        and distinct is not None
        and rows > 0
        and distinct / rows >= NEAR_UNIQUE_RATIO
        and profile.logical_type in (LogicalType.STRING, LogicalType.INT, LogicalType.BINARY)
    )
    if near_unique:
        signals.append(
            Signal(
                source=SignalSource.CARDINALITY,
                detector="near_unique",
                pii_class=PiiClass.QUASI_IDENTIFIER,
                support=1.0,
            )
        )

    likely = _likely(profile, concept, signals)
    plausible = {signal.pii_class for signal in signals} | {likely}
    if likely is PiiClass.NONE:
        # Anything can be a quasi-identifier in combination. Most likely harmless is
        # not the same as plausibly harmless.
        plausible.add(PiiClass.QUASI_IDENTIFIER)
    if len(plausible) > 1:
        plausible.discard(PiiClass.UNKNOWN)
    return ClassificationProposal(
        column=profile.ref,
        logical_type=profile.logical_type,
        role=profile.role,
        first_pass=profile.pii_class,
        likely=likely,
        plausible=tuple(sorted(plausible, key=lambda c: PII_RESTRICTIVENESS[c])),
        signals=tuple(signals),
        concept=None if concept is None else concept.name,
        row_count=rows,
        distinct_estimate=distinct,
    )


def _string_samples(profile: ColumnProfile, sample: Sequence[ScalarValue]) -> list[str]:
    raw: list[ScalarValue] = list(sample)
    raw.extend(value.reveal() for value in profile.most_common_values)
    raw.extend(b.reveal() for b in (profile.min_bound, profile.max_bound) if b is not None)
    return [value.strip() for value in raw if isinstance(value, str) and value.strip()]


def _likely(profile: ColumnProfile, concept: Concept | None, signals: list[Signal]) -> PiiClass:
    strong = [
        s.pii_class
        for s in signals
        if s.source is SignalSource.VALUE_FORMAT and s.support >= STRONG_SUPPORT
    ]
    if strong:
        return most_restrictive(strong)
    if concept is not None and concept.pii_class is not None:
        return concept.pii_class
    if profile.pii_class is not PiiClass.UNKNOWN:
        return profile.pii_class
    if any(s.source is SignalSource.CARDINALITY for s in signals):
        return PiiClass.QUASI_IDENTIFIER
    benign_roles = (ColumnRole.MEASURE, ColumnRole.LABEL, ColumnRole.EVENT_TIME)
    if profile.role in benign_roles or (concept is not None and concept.pii_class is None):
        return PiiClass.NONE
    return PiiClass.UNKNOWN


# --------------------------------------------------------------------------------------
# The registry: proposals plus human confirmations. Boundary; holds no values.
# --------------------------------------------------------------------------------------


class Confirmation(GodwitModel):
    """A human's decision about a column's class. The only thing that makes it final."""

    column: ColumnRef
    pii_class: PiiClass
    confirmed_by: str
    confirmed_at: Instant
    note: str = ""


class CatalogEntry(GodwitModel):
    """One column's proposal and, if a human has spoken, its confirmation."""

    proposal: ClassificationProposal
    confirmation: Confirmation | None = None

    @property
    def confirmed(self) -> bool:
        """True only when a human has confirmed the class."""
        return self.confirmation is not None

    @property
    def effective_class(self) -> PiiClass:
        """Confirmed class, else the most restrictive plausible one."""
        if self.confirmation is not None:
            return self.confirmation.pii_class
        return self.proposal.most_restrictive_plausible


class ClassificationRegistry:
    """The confirmed-or-proposed class of every known column. **Boundary.**

    Deny by default: a column that is not here is UNCLASSIFIED, and the gate refuses it.
    A column that is here but unconfirmed is treated at its most restrictive plausible
    class. A new proposal whose evidence is *more* restrictive than an existing
    confirmation revokes that confirmation: the data changed under the human's decision,
    so the decision no longer stands.
    """

    def __init__(self) -> None:
        self._entries: dict[str, CatalogEntry] = {}
        self._tables: dict[str, str] = {}

    def record(self, proposal: ClassificationProposal) -> CatalogEntry:
        """Store a proposal. Returns the resulting entry."""
        key = ref_key(proposal.column)
        previous = self._entries.get(key)
        confirmation = None if previous is None else previous.confirmation
        if confirmation is not None:
            confirmed_rank = PII_RESTRICTIVENESS[confirmation.pii_class]
            if any(
                PII_RESTRICTIVENESS[c] > confirmed_rank
                for c in proposal.plausible
                if c is not PiiClass.UNKNOWN
            ):
                confirmation = None
        entry = CatalogEntry(proposal=proposal, confirmation=confirmation)
        self._entries[key] = entry
        return entry

    def confirm(
        self, column: ColumnRef, pii_class: PiiClass, *, by: str, at: Instant, note: str = ""
    ) -> CatalogEntry:
        """A human confirms a column's class. The column must already have a proposal."""
        key = ref_key(column)
        entry = self._entries.get(key)
        if entry is None:
            raise KeyError("no proposal for this column; classify it before confirming")
        if not by:
            raise ValueError("a confirmation must name who confirmed it")
        confirmed = CatalogEntry(
            proposal=entry.proposal,
            confirmation=Confirmation(
                column=column, pii_class=pii_class, confirmed_by=by, confirmed_at=at, note=note
            ),
        )
        self._entries[key] = confirmed
        return confirmed

    def register_table(self, source_id: SourceId | str, table: str) -> None:
        """Make a table name known, so its SCHEMA_NAME taint can be described."""
        self._tables[column_key(source_id, None, table)] = table

    def is_known_table(self, source_id: str | None, name: str) -> bool:
        """True if ``name`` was registered as a table of ``source_id``."""
        return column_key(source_id, None, name) in self._tables

    def entry(self, ref: ColumnRef) -> CatalogEntry | None:
        """The entry for exactly this column, or None."""
        return self._entries.get(ref_key(ref))

    def entries(self) -> tuple[CatalogEntry, ...]:
        """Every entry, in key order."""
        return tuple(self._entries[key] for key in sorted(self._entries))

    def lookup(self, provenance: Provenance) -> CatalogEntry | None:
        """Resolve a tainted value's provenance to a column entry, or None.

        Exact match on (source, table, column) first. If the provenance omits the table
        or the source, a *unique* match on what it does carry is accepted; an ambiguous
        match is None, which the gate reads as unclassified. Fail closed.
        """
        if provenance.column is None:
            return None
        exact = self._entries.get(
            column_key(provenance.source_id, provenance.table, provenance.column)
        )
        if exact is not None:
            return exact
        wanted_column = canonical_column(provenance.column)
        wanted_table = None if provenance.table is None else canonical_column(provenance.table)
        matches = [
            entry
            for entry in self._entries.values()
            if canonical_column(entry.proposal.column.column.reveal()) == wanted_column
            and (
                provenance.source_id is None
                or entry.proposal.column.source_id == provenance.source_id
            )
            and (
                wanted_table is None
                or canonical_column(entry.proposal.column.table.reveal()) == wanted_table
            )
        ]
        return matches[0] if len(matches) == 1 else None


# --------------------------------------------------------------------------------------
# Quasi-identifier combinations
# --------------------------------------------------------------------------------------


class QuasiIdentifierCombination(GodwitModel):
    """A set of columns that together single people out."""

    columns: tuple[ColumnRef, ...]
    expected_class_size: float
    """Rows divided by the (independence-assumed) number of distinct combinations.

    This is an AVERAGE. Real distributions are skewed, so some equivalence classes are
    smaller than this; the flag is a floor on concern, not a ceiling."""
    known_triad: bool = False
    reason: str


_TRIAD: Final[frozenset[str]] = frozenset({"postcode", "birth_date", "sex"})


def quasi_identifier_combinations(
    entries: Sequence[CatalogEntry], *, k: int, max_width: int = 3
) -> tuple[QuasiIdentifierCombination, ...]:
    """Flag minimal column combinations whose expected equivalence class is below ``k``.

    Candidates are columns whose effective class is QUASI_IDENTIFIER or whose proposal
    lists it as plausible. Direct identifiers are excluded: they need no combination to
    identify. Distinct combinations are estimated as the product of per-column NDVs,
    capped at the row count. True joint NDV is never larger than that product, so the
    estimate is pessimistic -- it flags more, not less. The postcode / birth date / sex
    triad is flagged by name regardless of the estimate.
    """
    if k < MIN_K:
        raise ValueError("k must be at least 2; k-anonymity with k<2 is no anonymity")
    candidates = [
        entry
        for entry in entries
        if entry.effective_class is PiiClass.QUASI_IDENTIFIER
        or PiiClass.QUASI_IDENTIFIER in entry.proposal.plausible
    ]
    flagged: list[QuasiIdentifierCombination] = []
    flagged_sets: list[frozenset[str]] = []
    for width in range(2, max_width + 1):
        for combo in itertools.combinations(candidates, width):
            keys = frozenset(ref_key(entry.proposal.column) for entry in combo)
            if any(prior <= keys for prior in flagged_sets):
                continue
            finding = _assess_combo(combo, k)
            if finding is not None:
                flagged.append(finding)
                flagged_sets.append(keys)
    return tuple(flagged)


def _assess_combo(combo: Sequence[CatalogEntry], k: int) -> QuasiIdentifierCombination | None:
    concepts = frozenset(entry.proposal.concept or "" for entry in combo)
    triad = concepts >= _TRIAD
    rows_known = [e.proposal.row_count for e in combo if e.proposal.row_count is not None]
    ndvs = [e.proposal.distinct_estimate for e in combo]
    columns = tuple(entry.proposal.column for entry in combo)
    if rows_known and all(n is not None for n in ndvs):
        rows = max(rows_known)
        product = math.prod(max(1, n or 1) for n in ndvs)
        expected = rows / max(1, min(rows, product))
        if expected < k or triad:
            reason = (
                "known re-identification triad"
                if triad
                else (f"expected equivalence class {expected:.2f} is below k={k}")
            )
            return QuasiIdentifierCombination(
                columns=columns, expected_class_size=expected, known_triad=triad, reason=reason
            )
        return None
    if triad:
        return QuasiIdentifierCombination(
            columns=columns,
            expected_class_size=0.0,
            known_triad=True,
            reason="known re-identification triad",
        )
    return None
