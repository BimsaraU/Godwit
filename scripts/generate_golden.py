"""Regenerate every golden fixture under ``tests/golden``.

Deterministic: one seed, stdlib ``random`` only, no wall clock. Running this twice
produces identical logical content. Parquet *bytes* are not guaranteed stable across
pyarrow versions, so the fixtures are pinned by a content hash over the logical rows
(``manifest.json``) rather than by file checksum.

Usage::

    uv run python scripts/generate_golden.py

A0 seeds these. A5 extends the PII torture fixture. Any agent may add fixtures of its
own; nobody edits someone else's.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import math
import random
from decimal import Decimal
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
from godwit_contracts import (
    Acquisition,
    Candidate,
    CandidateId,
    ErrorBound,
    Evidence,
    EvidenceKind,
    Lineage,
    Operator,
    Predicate,
    ProbeKey,
    Provenance,
    ScalarValue,
    Segment,
    Sensitivity,
    SketchEnvelope,
    SketchKind,
    SnapshotId,
    SourceId,
    content_hash,
    data_value,
    derived_statistic,
    schema_name,
)

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "golden"
SEED = 20240117
EPOCH = _dt.datetime(2024, 1, 1, tzinfo=_dt.UTC)


# ----------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def _literal(value: object) -> str:
    """Unambiguous textual form of a test-vector input, paired with its ``py_type``.

    The pair (py_type, literal) is enough for an implementation in another language to
    reconstruct the input exactly: ``("Decimal", "1.2300")`` is not ``("str", "1.2300")``
    and the two produce different segment keys.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    return str(value)


def rows_digest(rows: list[dict[str, Any]]) -> str:
    """Content hash over logical rows, independent of the parquet encoding."""
    canonical = json.dumps(
        rows, separators=(",", ":"), ensure_ascii=False, sort_keys=True, default=str
    )
    return hashlib.blake2b(canonical.encode("utf-8"), digest_size=16).hexdigest()


def write_table(path: Path, rows: list[dict[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, path, compression="snappy")
    return rows_digest(rows)


def auc(scores: list[float], labels: list[int]) -> float:
    """Rank-based AUC with tie handling. No sklearn: fixtures must not need the stack."""
    paired = sorted(zip(scores, labels, strict=True), key=lambda item: item[0])
    ranks: list[float] = [0.0] * len(paired)
    index = 0
    while index < len(paired):
        stop = index
        while stop + 1 < len(paired) and paired[stop + 1][0] == paired[index][0]:
            stop += 1
        average_rank = (index + stop) / 2.0 + 1.0
        for position in range(index, stop + 1):
            ranks[position] = average_rank
        index = stop + 1
    positives = sum(label for _, label in paired)
    negatives = len(paired) - positives
    if positives == 0 or negatives == 0:
        raise ValueError("AUC needs both classes present")
    rank_sum = sum(rank for rank, (_, label) in zip(ranks, paired, strict=True) if label == 1)
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


# ----------------------------------------------------------------------------------
# 1. drifting table
# ----------------------------------------------------------------------------------

_COUNTRIES_BASE = ["US"] * 58 + ["GB"] * 20 + ["DE"] * 12 + ["FR"] * 7 + ["PT"] * 3
_COUNTRIES_DRIFT = ["US"] * 50 + ["GB"] * 17 + ["DE"] * 10 + ["FR"] * 5 + ["PT"] * 18
_STATUSES = ["settled"] * 88 + ["refund"] * 9 + ["chargeback"] * 3


def build_orders_snapshot(
    rng: random.Random, *, index: int, drifted: bool, rows: int
) -> list[dict[str, Any]]:
    countries = _COUNTRIES_DRIFT if drifted else _COUNTRIES_BASE
    out: list[dict[str, Any]] = []
    for row in range(rows):
        country = rng.choice(countries)
        status = rng.choice(_STATUSES)
        # The drift: refunds out of PT become large. Everything else is unchanged.
        if drifted and country == "PT" and status == "refund":
            amount = round(rng.uniform(400.0, 900.0), 2)
        else:
            amount = round(rng.lognormvariate(3.2, 0.7), 2)
        out.append(
            {
                "order_id": f"ord_{index:02d}_{row:05d}",
                "customer_email": f"user{row % 900:04d}@example{row % 7}.test",
                "country": country,
                "status": status,
                "amount": amount,
                "created_at": EPOCH + _dt.timedelta(days=index * 7, seconds=row * 13),
            }
        )
    return out


def column_bounds(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Iceberg-style per-column min/max.

    These are a LEAK PATH and the fixture exists to make that concrete: the bounds of
    ``customer_email`` below are two real addresses from the table.
    """
    bounds: dict[str, dict[str, Any]] = {}
    for column in rows[0]:
        values = [row[column] for row in rows if row[column] is not None]
        bounds[column] = {"lower": min(values), "upper": max(values)}
    return bounds


def generate_drift_table() -> dict[str, Any]:
    rng = random.Random(SEED)
    snapshots: list[dict[str, Any]] = []
    for index, drifted in enumerate((False, False, True)):
        rows = build_orders_snapshot(rng, index=index, drifted=drifted, rows=6000)
        digest = write_table(GOLDEN / "drift_table" / f"snapshot_{index}.parquet", rows)
        bounds = column_bounds(rows)
        snapshots.append(
            {
                "snapshot_id": f"snap_{index}",
                "sequence_number": index,
                "parent_snapshot_id": None if index == 0 else f"snap_{index - 1}",
                "committed_at": (EPOCH + _dt.timedelta(days=index * 7)).isoformat(),
                "file": f"snapshot_{index}.parquet",
                "row_count": len(rows),
                "rows_digest": digest,
                "drifted": drifted,
                "column_bounds": {
                    name: {"lower": str(value["lower"]), "upper": str(value["upper"])}
                    for name, value in bounds.items()
                },
            }
        )
    manifest = {
        "table": "orders",
        "namespace": "godwit_golden",
        "seed": SEED,
        "snapshots": snapshots,
        "documented_drift": {
            "introduced_at_snapshot": "snap_2",
            "segments": [
                {
                    "predicates": [["country", "eq", "PT"]],
                    "what_changed": "share of rows rises from about 3% to about 18%",
                    "detectable_by": "category histogram or heavy hitters on country",
                },
                {
                    "predicates": [["country", "eq", "PT"], ["status", "eq", "refund"]],
                    "what_changed": (
                        "amount moves from lognormal(3.2, 0.7) to uniform(400, 900); "
                        "the mean rises by roughly an order of magnitude"
                    ),
                    "detectable_by": "KLL quantiles on amount within the segment",
                },
            ],
            "unchanged_controls": [
                {
                    "predicates": [["country", "eq", "US"]],
                    "note": "must NOT be flagged; it is the false-positive control",
                }
            ],
        },
        "leak_note": (
            "column_bounds above are Iceberg manifest bounds. The customer_email "
            "bounds are two real addresses. Reading bounds is reading data."
        ),
    }
    write_json(GOLDEN / "drift_table" / "manifest.json", manifest)
    return manifest


# ----------------------------------------------------------------------------------
# 2. half-labelled classification fixture with a known ceiling
# ----------------------------------------------------------------------------------

_MERCHANTS = [f"merchant_{index:02d}" for index in range(48)] + ["ACME_CORP", "RARE_LTD"]


def generate_classification() -> dict[str, Any]:
    rng = random.Random(SEED + 1)
    rows: list[dict[str, Any]] = []
    true_probability: list[float] = []
    for index in range(6000):
        x1 = rng.gauss(0.0, 1.0)
        x2 = rng.gauss(0.0, 1.0)
        x3 = rng.gauss(0.0, 1.0)
        x4 = rng.uniform(-1.0, 1.0)
        merchant = _MERCHANTS[min(int(abs(rng.gauss(0, 14))), len(_MERCHANTS) - 1)]
        merchant_effect = 2.1 if merchant == "ACME_CORP" else 0.0
        logit = 2.6 * x1 - 1.9 * x2 + 1.3 * x3 * x4 + merchant_effect - 2.4
        probability = 1.0 / (1.0 + math.exp(-logit))
        label = 1 if rng.random() < probability else 0
        true_probability.append(probability)
        rows.append(
            {
                "entity_id": f"ent_{index:06d}",
                "merchant": merchant,
                "x1": x1,
                "x2": x2,
                "x3": x3,
                "x4": x4,
                "event_time": EPOCH + _dt.timedelta(minutes=index * 7),
                "label_time": EPOCH + _dt.timedelta(minutes=index * 7, days=45),
                "label": label,
                "label_observed": None,
            }
        )

    # Half the labels are hidden. The mask is deterministic and not time-correlated, so
    # a trainer cannot recover it from event_time.
    mask_rng = random.Random(SEED + 2)
    for row in rows:
        row["label_observed"] = row["label"] if mask_rng.random() < 0.5 else None

    split = int(len(rows) * 0.8)
    holdout = rows[split:]
    holdout_probability = true_probability[split:]
    ceiling = auc(holdout_probability, [int(row["label"]) for row in holdout])

    train_rows = [
        {key: value for key, value in row.items() if key != "label"} for row in rows[:split]
    ]
    holdout_rows = [
        {key: value for key, value in row.items() if key != "label_observed"} for row in holdout
    ]
    train_digest = write_table(GOLDEN / "classification" / "train.parquet", train_rows)
    holdout_digest = write_table(GOLDEN / "classification" / "holdout.parquet", holdout_rows)

    meta = {
        "seed": SEED + 1,
        "rows": len(rows),
        "train_rows": len(train_rows),
        "holdout_rows": len(holdout_rows),
        "train_digest": train_digest,
        "holdout_digest": holdout_digest,
        "labelled_fraction": round(
            sum(1 for row in rows[:split] if row["label_observed"] is not None) / len(train_rows),
            4,
        ),
        "positive_rate": round(sum(int(row["label"]) for row in rows) / len(rows), 4),
        "bayes_auc": round(ceiling, 4),
        "target_auc": round(ceiling - 0.02, 4),
        "generating_process": (
            "logit = 2.6*x1 - 1.9*x2 + 1.3*x3*x4 + 2.1*[merchant == 'ACME_CORP'] - 2.4"
        ),
        "why_this_is_ungameable": (
            "bayes_auc is the AUC of the TRUE probabilities on the holdout. No model can "
            "beat it on this data. target_auc is that ceiling minus 0.02, which is the "
            "prediction objective stated in the brief. Reaching bayes_auc exactly means "
            "the generating process leaked, not that the model is excellent."
        ),
        "leak_traps": {
            "entity_id": "unique per row; target encoding it memorises the labels",
            "merchant": "ACME_CORP carries real signal; a feature named "
            "is_merchant_ACME_CORP would leak a merchant name into every SHAP plot",
            "label_time": "45 days after event_time; training as of event_time is a "
            "45-day look into the future",
        },
    }
    write_json(GOLDEN / "classification" / "meta.json", meta)
    return meta


# ----------------------------------------------------------------------------------
# 3. PII torture fixture
# ----------------------------------------------------------------------------------

_NAMES = [
    "Aoife Brennan",
    "Kwame Mensah",
    "Priya Raghunathan",
    "Tomas Oliveira",
    "Marielle Dubois",
    "Hiroshi Nakamura",
    "Sofia Petrova",
    "Daniel Okonkwo",
    "Lena Vogt",
    "Mateo Alvarez",
    "Zainab Farouk",
    "Erik Lindqvist",
]
_TEAM = _NAMES[:12]


def generate_pii_torture() -> dict[str, Any]:
    rng = random.Random(SEED + 3)
    rows: list[dict[str, Any]] = []
    for index, name in enumerate(_NAMES):
        handle = name.lower().replace(" ", ".")
        rows.append(
            {
                "customer_ssn": f"{100 + index:03d}-{40 + index:02d}-{1000 + index * 7:04d}",
                "full_name": name,
                "email": f"{handle}@northfield-bank.test",
                "patient_hiv_status": rng.choice(["negative", "positive", "unknown"]),
                "salary_2024": 41000 + index * 3100,
                "device_id": f"dev-{index:04d}-{rng.randrange(16**8):08x}",
                "merchant_name": "ACME_CORP" if index % 5 == 0 else f"vendor_{index:02d}",
                "cohort": "pilot_group_a" if index < 3 else "general",
                "notes": f"called {name} on the number ending {2000 + index:04d}",
            }
        )
    digest = write_table(GOLDEN / "pii_torture" / "table.parquet", rows)

    bounds = column_bounds(rows)
    mcv = {
        "patient_hiv_status": ["negative", "unknown", "positive"],
        "merchant_name": ["ACME_CORP"],
        "cohort": ["general", "pilot_group_a"],
    }
    heavy_hitters = {
        "merchant_name": [{"item": "ACME_CORP", "estimate": 3}],
        "device_id": [{"item": rows[0]["device_id"], "estimate": 1}],
    }

    forbidden: set[str] = set()
    for row in rows:
        forbidden.update(
            str(row[column])
            for column in ("customer_ssn", "full_name", "email", "device_id", "notes")
        )
        forbidden.add(str(row["salary_2024"]))
    forbidden.update(str(edge["lower"]) for edge in bounds.values())
    forbidden.update(str(edge["upper"]) for edge in bounds.values())
    forbidden.update(item for values in mcv.values() for item in values)
    forbidden.add("ACME_CORP")
    forbidden.add("is_merchant_ACME_CORP")
    forbidden.update(_TEAM)

    salaries = sorted(int(row["salary_2024"]) for row in rows)
    median = (salaries[5] + salaries[6]) / 2.0

    fixture = {
        "table": "customers",
        "namespace": "godwit_golden_pii",
        "rows_digest": digest,
        "row_count": len(rows),
        "columns": [
            {
                "name": "customer_ssn",
                "pii_class": "direct_identifier",
                "leak_paths": ["column_name", "manifest_bounds", "most_common_values"],
            },
            {
                "name": "full_name",
                "pii_class": "direct_identifier",
                "leak_paths": ["manifest_bounds", "most_common_values"],
            },
            {"name": "email", "pii_class": "direct_identifier", "leak_paths": ["manifest_bounds"]},
            {
                "name": "patient_hiv_status",
                "pii_class": "health",
                "leak_paths": ["column_name", "category_histogram", "most_common_values"],
            },
            {
                "name": "salary_2024",
                "pii_class": "financial",
                "leak_paths": ["column_name", "quantile", "manifest_bounds"],
            },
            {
                "name": "device_id",
                "pii_class": "quasi_identifier",
                "leak_paths": ["count_min_heavy_hitter"],
            },
            {
                "name": "merchant_name",
                "pii_class": "quasi_identifier",
                "leak_paths": ["count_min_heavy_hitter", "derived_feature_name"],
            },
            {"name": "cohort", "pii_class": "quasi_identifier", "leak_paths": ["small_cell"]},
            {"name": "notes", "pii_class": "sensitive_attribute", "leak_paths": ["free_text"]},
        ],
        "manifest_bounds": {
            name: {"lower": str(edge["lower"]), "upper": str(edge["upper"])}
            for name, edge in bounds.items()
        },
        "pg_stats_most_common_vals": mcv,
        "count_min_heavy_hitters": heavy_hitters,
        "small_cells": [
            {
                "segment": [["cohort", "eq", "pilot_group_a"]],
                "population": 3,
                "why": "n=3 re-identifies without quoting a value",
            }
        ],
        "small_population_quantile": {
            "column": "salary_2024",
            "population": len(rows),
            "median": median,
            "why": "the median salary of a twelve-person team is nearly one person's salary",
        },
        "derived_feature_name_trap": "is_merchant_ACME_CORP",
        "driver_exception_trap": (
            'ERROR: duplicate key value violates unique constraint "customers_pkey" '
            "DETAIL: Key (customer_ssn)=(100-40-1000) already exists."
        ),
    }
    write_json(GOLDEN / "pii_torture" / "fixture.json", fixture)
    write_json(
        GOLDEN / "pii_torture" / "expected_leaks.json",
        {
            "must_never_appear_in_any_egress": sorted(forbidden),
            "how_to_use": (
                "Render your alert, log line, LLM payload, model card or UI response to "
                "text and assert that none of these strings appear in it. This is a "
                "BACKSTOP test. The control is the taint type plus the gate; a passing "
                "string search proves nothing on its own."
            ),
        },
    )
    return fixture


# ----------------------------------------------------------------------------------
# 4. contract fixtures: segment keys, sketch envelopes, candidates
# ----------------------------------------------------------------------------------


def generate_contract_fixtures() -> None:
    def predicate(column: str, op: Operator, *values: ScalarValue) -> Predicate:
        return Predicate(
            column=schema_name(column),
            op=op,
            values=tuple(
                data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE, column=column)
                for value in values
            ),
        )

    vectors: list[tuple[str, Segment]] = [
        ("empty segment is the whole population", Segment()),
        ("simple equality", Segment(predicates=(predicate("country", Operator.EQ, "PT"),))),
        (
            "column case and surrounding whitespace are normalised away",
            Segment(predicates=(predicate("  CoUnTry ", Operator.EQ, "PT"),)),
        ),
        (
            "value case is NOT normalised: values are data",
            Segment(predicates=(predicate("country", Operator.EQ, "pt"),)),
        ),
        (
            "predicate order does not matter",
            Segment(
                predicates=(
                    predicate("status", Operator.EQ, "refund"),
                    predicate("country", Operator.EQ, "PT"),
                )
            ),
        ),
        (
            "same predicates, written in the other order",
            Segment(
                predicates=(
                    predicate("country", Operator.EQ, "PT"),
                    predicate("status", Operator.EQ, "refund"),
                )
            ),
        ),
        (
            "duplicate predicates collapse",
            Segment(
                predicates=(
                    predicate("country", Operator.EQ, "PT"),
                    predicate("country", Operator.EQ, "PT"),
                )
            ),
        ),
        (
            "int 1 and str '1' are different values",
            Segment(predicates=(predicate("code", Operator.EQ, 1),)),
        ),
        (
            "str '1' again, for contrast",
            Segment(predicates=(predicate("code", Operator.EQ, "1"),)),
        ),
        (
            "bool is not int",
            Segment(predicates=(predicate("flag", Operator.EQ, True),)),
        ),
        (
            "negative zero float collapses to zero",
            Segment(predicates=(predicate("delta", Operator.EQ, -0.0),)),
        ),
        (
            "decimal is normalised, never scientific",
            Segment(predicates=(predicate("amount", Operator.EQ, Decimal("1.2300")),)),
        ),
        (
            "IN members are sorted and de-duplicated",
            Segment(predicates=(predicate("country", Operator.IN, "GB", "PT", "GB"),)),
        ),
        (
            "IN escaping: one member containing a comma is not two members",
            Segment(predicates=(predicate("label", Operator.IN, "a,b"),)),
        ),
        (
            "two members, for contrast with the escaped case",
            Segment(predicates=(predicate("label", Operator.IN, "a", "b"),)),
        ),
        (
            "BETWEEN keeps its order",
            Segment(predicates=(predicate("amount", Operator.BETWEEN, 10, 20),)),
        ),
        (
            "IS_NULL takes no values",
            Segment(predicates=(predicate("shipped_at", Operator.IS_NULL),)),
        ),
        (
            "timestamps are UTC with six fraction digits",
            Segment(
                predicates=(
                    predicate(
                        "created_at",
                        Operator.GE,
                        _dt.datetime(2024, 3, 1, 12, 30, tzinfo=_dt.UTC),
                    ),
                )
            ),
        ),
        (
            "unicode is NFC-normalised: composed and decomposed agree",
            Segment(predicates=(predicate("city", Operator.EQ, "São Paulo"),)),
        ),
        (
            "the same city, written with a combining tilde",
            Segment(predicates=(predicate("city", Operator.EQ, "São Paulo"),)),
        ),
    ]

    write_json(
        GOLDEN / "segment_key_vectors.json",
        {
            "normalisation_spec": "godwit_contracts.segment module docstring",
            "vectors": [
                {
                    "note": note,
                    "predicates": [
                        {
                            "column": item.column.reveal(),
                            "op": item.op.value,
                            "values": [
                                {
                                    "py_type": type(value.reveal()).__name__,
                                    "literal": _literal(value.reveal()),
                                }
                                for value in item.values
                            ],
                        }
                        for item in segment.predicates
                    ],
                    "canonical": segment.canonical_form(),
                    "segment_key": str(segment.key),
                }
                for note, segment in vectors
            ],
        },
    )

    bound = ErrorBound(kind="exact", note="an exact count has no error")
    count_payload = json.dumps({"count": 2000}, separators=(",", ":")).encode("utf-8")
    kll_payload = bytes(range(64))
    cm_payload = bytes(reversed(range(48)))

    envelopes = [
        SketchEnvelope(
            kind=SketchKind.EXACT_COUNT,
            codec="godwit-exact-v1",
            schema_version=1,
            payload=count_payload,
            payload_digest=content_hash(count_payload, prefix="sk"),
            sensitivity=Sensitivity.DERIVED_STATISTIC,
            provenance=Provenance(
                acquisition=Acquisition.COMPUTED_STATISTIC,
                source_id=SourceId("src_golden"),
                table="orders",
            ),
            population=2000,
            error_bound=bound,
            params={},
            source_id=SourceId("src_golden"),
            snapshot_id=SnapshotId("snap_0"),
            produced_for=ProbeKey("prb_golden_row_count"),
            produced_at=EPOCH,
        ),
        SketchEnvelope(
            kind=SketchKind.KLL,
            codec="datasketches-kll-v1",
            schema_version=1,
            payload=kll_payload,
            payload_digest=content_hash(kll_payload, prefix="sk"),
            sensitivity=Sensitivity.DERIVED_STATISTIC,
            provenance=Provenance(
                acquisition=Acquisition.SKETCH_SUMMARY,
                source_id=SourceId("src_golden"),
                table="orders",
                column="amount",
            ),
            population=2000,
            error_bound=ErrorBound(
                kind="epsilon_delta",
                epsilon=0.01,
                delta=0.01,
                note="normalised rank error, k=200",
            ),
            params={"k": 200},
            source_id=SourceId("src_golden"),
            snapshot_id=SnapshotId("snap_0"),
            produced_for=ProbeKey("prb_golden_amount_quantiles"),
            produced_at=EPOCH,
        ),
        SketchEnvelope(
            kind=SketchKind.COUNT_MIN,
            codec="godwit-cm-v1",
            schema_version=1,
            payload=cm_payload,
            payload_digest=content_hash(cm_payload, prefix="sk"),
            sensitivity=Sensitivity.DATA_VALUE,
            provenance=Provenance(
                acquisition=Acquisition.COUNT_MIN_HEAVY_HITTER,
                source_id=SourceId("src_golden"),
                table="orders",
                column="country",
            ),
            population=2000,
            error_bound=ErrorBound(
                kind="epsilon_delta",
                epsilon=0.001,
                delta=0.01,
                note="frequency over-estimate, width=2718 depth=5",
            ),
            params={"width": 2718, "depth": 5, "seed": 7},
            source_id=SourceId("src_golden"),
            snapshot_id=SnapshotId("snap_0"),
            produced_for=ProbeKey("prb_golden_country_heavy_hitters"),
            produced_at=EPOCH,
        ),
    ]
    write_json(
        GOLDEN / "sketch_envelopes.json",
        {
            "note": (
                "Three envelopes covering the three sensitivity situations: a pure "
                "statistic, an opaque summary, and an item-bearing sketch whose payload "
                "contains row values. A2 replaces the opaque payloads with real "
                "datasketches bytes; the ENVELOPE SHAPE is what downstream agrees on."
            ),
            "envelopes": [json.loads(envelope.model_dump_json()) for envelope in envelopes],
        },
    )


def generate_candidates() -> None:
    def predicate(column: str, value: str) -> Predicate:
        return Predicate(
            column=schema_name(column),
            op=Operator.EQ,
            values=(data_value(value, acquisition=Acquisition.SEGMENT_PREDICATE, column=column),),
        )

    pt_segment = Segment(predicates=(predicate("country", "PT"),), population=361)
    refund_segment = Segment(
        predicates=(predicate("country", "PT"), predicate("status", "refund")),
        population=34,
    )
    lineage = Lineage(
        probe_key=ProbeKey("prb_golden_country_heavy_hitters"),
        snapshot_id=SnapshotId("snap_2"),
        baseline_snapshot_id=SnapshotId("snap_1"),
        detector="category_share_shift",
        detector_version=1,
        code_version="golden-fixture",
        seed=20240117,
    )
    candidates = [
        Candidate(
            candidate_id=CandidateId("cand_golden_0001"),
            source_id=SourceId("src_golden"),
            segment=pt_segment,
            evidence=(
                Evidence(
                    kind=EvidenceKind.RATE_CHANGE,
                    probe_key=ProbeKey("prb_golden_country_heavy_hitters"),
                    snapshot_id=SnapshotId("snap_2"),
                    baseline_snapshot_id=SnapshotId("snap_1"),
                    segment=pt_segment,
                    columns=(schema_name("country"),),
                    statistic=derived_statistic(0.1805, population=2000),
                    baseline=derived_statistic(0.0100, population=2000),
                    effect_size=derived_statistic(17.05, population=2000),
                    p_value=derived_statistic(1.2e-40, population=2000),
                    population=361,
                    sketch_names=("country_counts",),
                ),
            ),
            score=0.94,
            lineage=lineage,
            created_at=EPOCH + _dt.timedelta(days=14, hours=1),
        ),
        Candidate(
            candidate_id=CandidateId("cand_golden_0002"),
            source_id=SourceId("src_golden"),
            segment=refund_segment,
            evidence=(
                Evidence(
                    kind=EvidenceKind.DISTRIBUTION_SHIFT,
                    probe_key=ProbeKey("prb_golden_amount_quantiles"),
                    snapshot_id=SnapshotId("snap_2"),
                    baseline_snapshot_id=SnapshotId("snap_1"),
                    segment=refund_segment,
                    columns=(schema_name("amount"),),
                    statistic=derived_statistic(648.2, population=34),
                    baseline=derived_statistic(31.4, population=31),
                    effect_size=derived_statistic(4.81, population=34),
                    p_value=derived_statistic(3.4e-12, population=34),
                    population=34,
                    sketch_names=("amount_kll",),
                ),
            ),
            score=0.88,
            lineage=lineage.model_copy(
                update={"probe_key": "prb_golden_amount_quantiles", "detector": "quantile_shift"}
            ),
            created_at=EPOCH + _dt.timedelta(days=14, hours=1),
        ),
    ]
    write_json(
        GOLDEN / "candidates.json",
        {
            "note": (
                "Two candidates matching the documented drift in drift_table. The "
                "second has population 34, which is ABOVE the default small-cell "
                "threshold of 20. That is deliberate: what makes it unsafe to show is "
                "its segment predicates, which quote real column values, not the size "
                "of the cell. Small-cell suppression alone would let this one through."
            ),
            "candidates": [json.loads(candidate.model_dump_json()) for candidate in candidates],
        },
    )


def main() -> None:
    GOLDEN.mkdir(parents=True, exist_ok=True)
    drift = generate_drift_table()
    classification = generate_classification()
    generate_pii_torture()
    generate_contract_fixtures()
    generate_candidates()
    print(f"drift snapshots: {len(drift['snapshots'])}")
    print(f"bayes_auc: {classification['bayes_auc']} target_auc: {classification['target_auc']}")
    print(f"wrote fixtures under {GOLDEN}")


if __name__ == "__main__":
    main()
