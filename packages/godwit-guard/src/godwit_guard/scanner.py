"""The backstop scanner. A BACKSTOP. Not the control.

The control is the typed taint plus the gate. This scanner runs over every outbound
payload AFTER transformation, and a hit means the taint system leaked: a value was
mislabelled, or a package put data somewhere the type did not say it could be. A hit is
therefore handled as a DEFECT -- logged as an audit event, a person paged, the call
failed -- and never as a routine catch. :class:`BackstopMetrics` tracks the hit rate as
a quality metric of the primary control. It should trend to zero; if it does not, the
taint system is leaking and the scanner is merely noticing.

Most of the leak paths in the architecture document are invisible to any scanner: a
country code, a cohort label, a count of three. Do not read a zero hit rate as proof of
safety. Read it as the absence of one particular kind of bug.

Three layers, cheapest first:

1. **Echo.** Every value the gate revealed in this call and did not clear as ALLOW is
   searched for in the output -- raw, casefolded, URL-decoded, base64- and hex-decoded,
   digits-only, and concatenated across pairs of fields. This is the one layer that
   knows exactly what must not appear, because the gate just handled it.
2. **Custom recognisers** for identifier formats: SSN, card (Luhn), IBAN (mod 97),
   email, E.164 phone, Sri Lankan NIC, UK NINO.
3. **Presidio** (spaCy ``en_core_web_sm``) for names and anything else its recognisers
   know. Our own tokens and hashes are masked first so they are not mistaken for data.
"""

from __future__ import annotations

import base64
import binascii
import itertools
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote_plus

from godwit_contracts import GodwitModel, SafeScalar
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from godwit_guard.classify import iban_valid, luhn_valid
from godwit_guard.transforms import TOKEN_PATTERN

__all__ = [
    "PRESIDIO_ENTITIES",
    "Backstop",
    "BackstopFinding",
    "BackstopMetrics",
]

PRESIDIO_ENTITIES: Final[tuple[str, ...]] = (
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "IP_ADDRESS",
    "US_PASSPORT",
    "US_BANK_NUMBER",
    "UK_NHS",
    "MEDICAL_LICENSE",
)
"""DATE_TIME, URL, NRP, LOCATION and ORGANIZATION are excluded: on short gated strings
they fire on our own vocabulary far more often than on data, and a backstop that cries
wolf gets switched off."""

_MIN_ECHO_LENGTH: Final[int] = 4
_MIN_DIGIT_ECHO: Final[int] = 6
_HASH_PATTERN: Final[re.Pattern[str]] = re.compile(r"\bh_[0-9a-f]{32}\b")
_B64_RUN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX_RUN: Final[re.Pattern[str]] = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")


class BackstopFinding(GodwitModel):
    """One hit. Names the recogniser, the field and the encoding -- never the text."""

    recogniser: str
    field: str
    encoding: str = "raw"


@dataclass(slots=True)
class BackstopMetrics:
    """Quality of the primary control, as seen by the backstop."""

    scans: int = 0
    hits: int = 0

    @property
    def hit_rate(self) -> float:
        """Hits per scan. Should be zero. Anything else is the taint system leaking."""
        return 0.0 if self.scans == 0 else self.hits / self.scans


def _card_hit(text: str) -> bool:
    for match in re.finditer(r"(?<![\d.])\d(?:[ -]?\d){12,18}(?![\d.])", text):
        if luhn_valid(re.sub(r"[ -]", "", match.group(0))):
            return True
    return False


def _iban_hit(text: str) -> bool:
    return any(
        iban_valid(m.group(0)) for m in re.finditer(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", text)
    )


def _rx(pattern: str) -> Callable[[str], bool]:
    compiled = re.compile(pattern)
    return lambda text: compiled.search(text) is not None


_RECOGNISERS: Final[tuple[tuple[str, Callable[[str], bool]], ...]] = (
    ("us_ssn", _rx(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    ("email", _rx(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("payment_card", _card_hit),
    ("iban", _iban_hit),
    ("phone_e164", _rx(r"(?<![\w.])\+\d{8,15}(?!\d)")),
    ("lk_nic", _rx(r"(?<!\d)(?:\d{9}[VvXx]|(?:19|20)\d{10})(?![\dA-Za-z])")),
    ("uk_nino", _rx(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b")),
)

_ENGINE_LOCK: Final[threading.Lock] = threading.Lock()
_ENGINE: dict[str, AnalyzerEngine] = {}


def _presidio() -> AnalyzerEngine:
    with _ENGINE_LOCK:
        engine = _ENGINE.get("en")
        if engine is None:
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                }
            )
            engine = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
            _ENGINE["en"] = engine
        return engine


def _decoded_views(text: str) -> Iterable[tuple[str, str]]:
    yield "raw", text
    unquoted = unquote_plus(text)
    if unquoted != text:
        yield "url", unquoted
    for match in _B64_RUN.finditer(text):
        run = match.group(0)
        for offset in range(4):
            chunk = run[offset:]
            padded = chunk + "=" * (-len(chunk) % 4)
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    decoded = decoder(padded).decode("utf-8")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
                yield "base64", decoded
    for match in _HEX_RUN.finditer(text):
        try:
            yield "hex", bytes.fromhex(match.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue


def _digits(text: str) -> str:
    return "".join(char for char in text if char.isdigit())


class Backstop:
    """Scans cleared payloads for things that should not be there. A backstop only."""

    def __init__(
        self,
        *,
        use_presidio: bool = True,
        score_threshold: float = 0.6,
        pager: Callable[[tuple[BackstopFinding, ...]], None] | None = None,
    ) -> None:
        self._use_presidio = use_presidio
        self._threshold = score_threshold
        self._pager = pager
        self.metrics = BackstopMetrics()
        if use_presidio:
            _presidio()

    def scan(
        self, fields: Mapping[str, SafeScalar], *, forbidden: Iterable[str] = ()
    ) -> tuple[BackstopFinding, ...]:
        """Scan one outbound payload. Counts towards the hit rate; pages on a hit."""
        findings = self._echo(fields, forbidden) + self._patterns(fields)
        self.metrics.scans += 1
        if findings:
            self.metrics.hits += 1
            if self._pager is not None:
                self._pager(findings)
        return findings

    def _echo(
        self, fields: Mapping[str, SafeScalar], forbidden: Iterable[str]
    ) -> tuple[BackstopFinding, ...]:
        needles = {f.strip().casefold() for f in forbidden if len(f.strip()) >= _MIN_ECHO_LENGTH}
        digit_needles = {_digits(n) for n in needles if len(_digits(n)) >= _MIN_DIGIT_ECHO}
        if not needles:
            return ()
        texts = [(key, f"{key}={'' if value is None else value}") for key, value in fields.items()]
        # Split-across-fields and digit matching apply to text only. Gluing two statistics
        # together ("0.0004" + "10000") manufactures digit strings that were never there.
        values = [(key, value) for key, value in fields.items() if isinstance(value, str)]
        for (k1, v1), (k2, v2) in itertools.permutations(values, 2):
            texts.extend(((f"{k1}+{k2}", v1 + v2), (f"{k1}+{k2}", f"{v1} {v2}")))
        findings: list[BackstopFinding] = []
        for field, text in texts:
            for encoding, view in _decoded_views(text):
                folded = view.casefold()
                if any(needle in folded for needle in needles):
                    findings.append(
                        BackstopFinding(recogniser="echo", field=field, encoding=encoding)
                    )
                    break
        for key, value in values:
            if digit_needles and any(n in _digits(value) for n in digit_needles):
                findings.append(BackstopFinding(recogniser="echo", field=key, encoding="digits"))
        return tuple(findings)

    def _patterns(self, fields: Mapping[str, SafeScalar]) -> tuple[BackstopFinding, ...]:
        findings: list[BackstopFinding] = []
        for key, value in fields.items():
            for text in (key, value) if isinstance(value, str) else (key,):
                masked = _HASH_PATTERN.sub("HASH", TOKEN_PATTERN.sub("TOKEN", text))
                findings.extend(
                    BackstopFinding(recogniser=name, field=key)
                    for name, hit in _RECOGNISERS
                    if hit(masked)
                )
                # Keys are gate-validated identifiers; NER on "hh.c0.n0" sees a PERSON.
                if self._use_presidio and text is not key and masked.strip():
                    results = _presidio().analyze(
                        text=masked,
                        language="en",
                        entities=list(PRESIDIO_ENTITIES),
                        score_threshold=self._threshold,
                    )
                    findings.extend(
                        BackstopFinding(recogniser=f"presidio:{r.entity_type}", field=key)
                        for r in results
                    )
        return tuple(findings)
