"""Acceptance: the PII torture fixture, end to end, to an LLM provider.

Every leak path in ``tests/golden/pii_torture`` is built the way upstream packages build
it -- A1's first-pass classifier and role inference, manifest bounds, most-common values,
heavy hitters, a category histogram, a small cell, a small-population quantile, a derived
feature name, schema names and a driver exception -- then classified, confirmed,
mode-resolved and pushed through the gate to ``LLM_PROVIDER``. Every byte that would be
sent is captured and searched for every identifier in ``expected_leaks.json``, raw and
encoded, and split across fields.

Twice: once at the fixture's real populations (twelve rows, so small-cell control does
most of the work) and once with populations inflated to 10,000, so that the class-based
transforms -- tokenise, generalise, suppress -- are what stands between the data and the
provider.

The string search is a BACKSTOP assertion. What makes it pass is the taint typing.
"""

from __future__ import annotations

import base64
import binascii
import datetime as _dt
import itertools
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus, unquote_plus

import pyarrow.parquet as pq
import pytest
from _guard_support import SCOPE, SOURCE, TABLE, col_ref, make_vault
from godwit_contracts import (
    Acquisition,
    ColumnProfile,
    Destination,
    EvidenceKind,
    LogicalType,
    Operator,
    PiiClass,
    Predicate,
    SafePayload,
    Segment,
    Tainted,
    canonical_json,
    data_value,
    derived_statistic,
    schema_name,
)
from godwit_guard import (
    DEFAULT_POLICY,
    AccessControl,
    AccessMode,
    Backstop,
    ClassificationRegistry,
    EgressOptions,
    EgressRefusedError,
    Gate,
    KeyedHasher,
    MemoryLedger,
    RefusalReason,
    ReleaseLedger,
    assess_entropy,
    format_space_bits,
    propose,
)
from godwit_source import infer_pii_class, infer_role

NAMESPACE = "godwit_golden_pii"


@dataclass
class Capture:
    payloads: list[SafePayload] = field(default_factory=list)
    refusals: list[tuple[str, RefusalReason]] = field(default_factory=list)

    def texts(self) -> list[str]:
        out: list[str] = []
        for payload in self.payloads:
            fields = dict(payload.fields)
            out.append(canonical_json(fields))
            out.append("\n".join(f"{k}: {v}" for k, v in fields.items()))
            # Split-across-fields applies to text; gluing two statistics together makes
            # arbitrary digit strings ("0.0004" + "10000"), which is noise, not a leak.
            values = [v for v in fields.values() if isinstance(v, str)]
            out.extend(a + b for a, b in itertools.permutations(values, 2))
            out.extend(f"{a} {b}" for a, b in itertools.permutations(values, 2))
        return out


def _decoded(text: str) -> list[str]:
    """An independent decoder, deliberately not the scanner's."""
    views = [text, unquote_plus(text)]
    for run in re.findall(r"[A-Za-z0-9+/=_-]{8,}", text):
        for offset in range(4):
            chunk = run[offset:]
            chunk += "=" * (-len(chunk) % 4)
            for decode in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    views.append(decode(chunk).decode("utf-8", errors="ignore"))
                except (binascii.Error, ValueError):
                    continue
    for run in re.findall(r"(?:[0-9a-fA-F]{2}){4,}", text):
        views.append(bytes.fromhex(run).decode("utf-8", errors="ignore"))
    return views


def _logical(arrow_type: str) -> LogicalType:
    return LogicalType.INT if arrow_type.startswith("int") else LogicalType.STRING


def _build(golden_dir: Path, at: _dt.datetime) -> tuple[Gate, dict[str, Any], dict[str, list[Any]]]:
    fixture = json.loads((golden_dir / "pii_torture/fixture.json").read_text(encoding="utf-8"))
    arrow = pq.read_table(golden_dir / "pii_torture/table.parquet")
    rows = arrow.to_pydict()  # DATA PLANE: the test stands in for the probe worker here.
    registry = ClassificationRegistry()
    access = AccessControl(registry, ledger=MemoryLedger())
    for column in fixture["columns"]:
        name = column["name"]
        values = rows[name]
        logical = _logical(str(arrow.schema.field(name).type))
        first_pass = infer_pii_class(column_name=name, logical_type=logical, sample_values=values)
        role = infer_role(
            column_name=name,
            logical_type=logical,
            pii_class=first_pass,
            distinct_estimate=len(set(values)),
            row_count=len(values),
        )
        bounds = fixture["manifest_bounds"][name]
        mcv = fixture["pg_stats_most_common_vals"].get(name, [])
        profile = ColumnProfile(
            ref=col_ref(name),
            logical_type=logical,
            native_type=str(arrow.schema.field(name).type),
            nullable=False,
            role=role,
            pii_class=first_pass,
            row_count=derived_statistic(len(values), population=len(values)),
            distinct_estimate=derived_statistic(len(set(values)), population=len(values)),
            min_bound=_dv(bounds["lower"], name, Acquisition.ICEBERG_MANIFEST_BOUNDS, 12),
            max_bound=_dv(bounds["upper"], name, Acquisition.ICEBERG_MANIFEST_BOUNDS, 12),
            most_common_values=tuple(_dv(v, name, Acquisition.PG_STATS_MCV, 12) for v in mcv),
            observed_at=at,
            profile_version=1,
        )
        registry.record(propose(profile, sample=values))
        registry.confirm(profile.ref, PiiClass(column["pii_class"]), by="dpo@bank.test", at=at)
        access.record_entropy(
            profile.ref,
            assess_entropy(
                column_name=name,
                logical_type=logical,
                observed_distinct=len(set(values)),
                format_bits=format_space_bits(values),
                row_count=len(values),
            ),
        )
    registry.register_table(SOURCE, TABLE)
    registry.register_table(SOURCE, NAMESPACE)
    modes = access.mode_map(guardrails=(), at=at)
    gate = Gate(
        ledger=MemoryLedger(),
        registry=registry,
        backstop=Backstop(use_presidio=True),
        vault=make_vault(at),
        hasher=KeyedHasher(b"d" * 32, key_id="dp"),
        modes=modes,
        releases=ReleaseLedger(k=DEFAULT_POLICY.min_cell_size),
    )
    return gate, fixture, rows


def _dv(
    raw: Any, column: str | None, acquisition: Acquisition, population: int | None
) -> Tainted[Any]:
    return data_value(
        raw,
        acquisition=acquisition,
        population=population,
        source_id=SOURCE,
        table=TABLE,
        column=column,
    )


def _requests(
    fixture: dict[str, Any], rows: dict[str, list[Any]], scale: int | None
) -> list[tuple[str, dict[str, Tainted[Any]], EgressOptions]]:
    """Every leak path as an LLM request. ``scale`` overrides populations when set."""

    def pop(real: int) -> int:
        return real if scale is None else scale

    names = [c["name"] for c in fixture["columns"]]
    out: list[tuple[str, dict[str, Tainted[Any]], EgressOptions]] = []
    opts = EgressOptions(token_scope=SCOPE)

    bounds = {}
    for i, name in enumerate(names):
        b = fixture["manifest_bounds"][name]
        bounds[f"bounds.c{i}.lo"] = _dv(
            b["lower"], name, Acquisition.ICEBERG_MANIFEST_BOUNDS, pop(12)
        )
        bounds[f"bounds.c{i}.hi"] = _dv(
            b["upper"], name, Acquisition.ICEBERG_MANIFEST_BOUNDS, pop(12)
        )
    out.append(("manifest_bounds", bounds, opts))

    mcv = {
        f"mcv.c{i}.v{j}": _dv(v, name, Acquisition.PG_STATS_MCV, pop(12))
        for i, name in enumerate(names)
        for j, v in enumerate(fixture["pg_stats_most_common_vals"].get(name, []))
    }
    out.append(("most_common_values", mcv, opts))

    heavy: dict[str, Tainted[Any]] = {}
    for i, (name, hitters) in enumerate(sorted(fixture["count_min_heavy_hitters"].items())):
        for j, hit in enumerate(hitters):
            heavy[f"hh.c{i}.v{j}"] = _dv(
                hit["item"], name, Acquisition.COUNT_MIN_HEAVY_HITTER, pop(hit["estimate"])
            )
            heavy[f"hh.c{i}.n{j}"] = derived_statistic(
                hit["estimate"], population=pop(hit["estimate"])
            )
    out.append(("heavy_hitters", heavy, opts))

    histogram: dict[str, Tainted[Any]] = {}
    for j, (label, count) in enumerate(sorted(Counter(rows["patient_hiv_status"]).items())):
        histogram[f"hist.v{j}"] = _dv(
            label, "patient_hiv_status", Acquisition.CATEGORY_HISTOGRAM, pop(count)
        )
        histogram[f"hist.n{j}"] = derived_statistic(count, population=pop(count))
    out.append(("category_histogram", histogram, opts))

    cell = fixture["small_cells"][0]
    segment = Segment(
        predicates=(
            Predicate(
                column=schema_name("cohort", source_id=SOURCE, table=TABLE),
                op=Operator.EQ,
                values=(_dv(cell["segment"][0][2], "cohort", Acquisition.SEGMENT_PREDICATE, None),),
            ),
        ),
        population=pop(cell["population"]),
    )
    out.append(
        (
            "small_cell",
            {"score": derived_statistic(4.2, population=pop(3))},
            EgressOptions(token_scope=SCOPE, segments={"seg": segment}),
        )
    )

    q = fixture["small_population_quantile"]
    out.append(
        (
            "quantile",
            {"median": _dv(q["median"], q["column"], Acquisition.QUANTILE, pop(q["population"]))},
            opts,
        )
    )

    out.append(
        (
            "feature_name",
            {
                "feature": _dv(
                    fixture["derived_feature_name_trap"],
                    "merchant_name",
                    Acquisition.DERIVED_FEATURE_NAME,
                    pop(3),
                ),
                "importance": derived_statistic(0.31, population=pop(12)),
            },
            opts,
        )
    )

    schema: dict[str, Tainted[Any]] = {
        f"schema.c{i}": schema_name(n, source_id=SOURCE, table=TABLE) for i, n in enumerate(names)
    }
    schema["schema.table"] = schema_name(TABLE, source_id=SOURCE)
    schema["schema.namespace"] = schema_name(NAMESPACE, source_id=SOURCE)
    out.append(("schema_names", schema, opts))

    notes = {
        f"text.v{j}": _dv(v, "notes", Acquisition.PG_STATS_MCV, pop(1))
        for j, v in enumerate(rows["notes"][:3])
    }
    out.append(("free_text", notes, opts))

    candidate_segment = Segment(
        predicates=(
            Predicate(
                column=schema_name("merchant_name", source_id=SOURCE, table=TABLE),
                op=Operator.EQ,
                values=(_dv("ACME_CORP", "merchant_name", Acquisition.SEGMENT_PREDICATE, None),),
            ),
        ),
        population=pop(3),
    )
    out.append(
        (
            "explain_candidate",
            {
                "effect": derived_statistic(17.05, population=pop(3)),
                "p_value": derived_statistic(0.0004, population=pop(3)),
                "column": schema_name("merchant_name", source_id=SOURCE, table=TABLE),
            },
            EgressOptions(
                token_scope=SCOPE,
                segments={"seg": candidate_segment},
                literals={"kind": EvidenceKind.SEGMENT_DIVERGENCE},
            ),
        )
    )

    out.append(
        (
            "driver_exception",
            {
                "error": _dv(
                    fixture["driver_exception_trap"], None, Acquisition.DRIVER_EXCEPTION, None
                )
            },
            opts,
        )
    )
    return out


@pytest.fixture(scope="module")
def run(golden_dir: Path) -> tuple[Gate, Capture, dict[str, Any]]:
    at = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
    gate, fixture, rows = _build(golden_dir, at)
    capture = Capture()
    for scale in (None, 10_000):
        for purpose, fields, opts in _requests(fixture, rows, scale):
            try:
                payload, _ = gate.clear(
                    fields=fields,
                    destination=Destination.LLM_PROVIDER,
                    purpose=purpose,
                    policy=DEFAULT_POLICY,
                    guardrails=(),
                    actor="godwit-llm",
                    occurred_at=at,
                    options=opts,
                )
            except EgressRefusedError as refused:
                capture.refusals.append((purpose, refused.refusal.reason))
                continue
            capture.payloads.append(payload)
    return gate, capture, fixture


def test_no_identifier_reaches_the_llm_in_any_encoding(
    run: tuple[Gate, Capture, dict[str, Any]], golden_json: Any
) -> None:
    _, capture, _ = run
    leaks: list[str] = golden_json("pii_torture/expected_leaks.json")[
        "must_never_appear_in_any_egress"
    ]
    texts = capture.texts()
    haystacks = [view.casefold() for text in texts for view in _decoded(text)]
    for leak in leaks:
        folded = leak.casefold()
        encodings = {
            base64.b64encode(leak.encode()).decode(),
            quote(leak),
            quote_plus(leak),
            leak.encode().hex(),
            base64.urlsafe_b64encode(leak.encode()).decode(),
        }
        assert not any(folded in hay for hay in haystacks), f"leak #{leaks.index(leak)}"
        assert not any(enc in text for enc in encodings for text in texts), (
            f"encoded leak #{leaks.index(leak)}"
        )


def test_every_leak_path_was_exercised_and_something_useful_still_left(
    run: tuple[Gate, Capture, dict[str, Any]],
) -> None:
    _, capture, _ = run
    assert capture.refusals == [("driver_exception", RefusalReason.UNCLASSIFIED_FIELD)] * 2
    assert len(capture.payloads) == 2 * 10
    emitted = {v for p in capture.payloads for v in p.fields.values()}
    assert "MERCHANT_1" in emitted, "the candidate's segment value arrives as a token"
    assert "FEATURE_1" in emitted, "the feature name arrives as a token"
    assert "segment_divergence" in emitted
    assert any(isinstance(v, str) and "government identifier" in v for v in emitted)


def test_tokens_round_trip_and_the_map_never_leaves(
    run: tuple[Gate, Capture, dict[str, Any]],
) -> None:
    gate, capture, _ = run
    vault = gate._vault
    assert vault is not None
    at = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
    everything = "\n".join(capture.texts())
    tokens = sorted(
        {
            tok
            for p in capture.payloads
            for v in p.fields.values()
            for tok in re.findall(r"\b[A-Z][A-Z0-9]*_\d+\b", str(v))
        }
    )
    assert tokens
    for tok in tokens:
        restored = vault.restore(tok, scope_id=SCOPE, roles=frozenset({"investigator"}), at=at)
        assert restored.reveal() != tok, "every issued token resolves inside the data plane"
        if not tok.startswith(("COLUMN_", "TABLE_")):  # names may coincide with vocabulary
            assert restored.reveal().casefold() not in everything.casefold()
    assert vault.map_ref(SCOPE) not in everything


def test_the_backstop_hit_rate_is_zero(run: tuple[Gate, Capture, dict[str, Any]]) -> None:
    gate, capture, _ = run
    assert gate.backstop.metrics.scans == len(capture.payloads)
    assert gate.backstop.metrics.hits == 0, "a hit here is a defect in the taint system"


def test_blind_and_opaque_columns_resolve_as_designed(golden_dir: Path) -> None:
    at = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)
    gate, _, _ = _build(golden_dir, at)
    modes = gate._modes
    assert modes is not None
    by_name = {d.column.column.reveal(): d.mode for d in modes.decisions}
    assert by_name["notes"] is AccessMode.BLIND
    assert by_name["patient_hiv_status"] is AccessMode.BLIND, "3 values: hashing is not safe"
    assert by_name["device_id"] is AccessMode.OPAQUE
    assert by_name["email"] is AccessMode.OPAQUE
