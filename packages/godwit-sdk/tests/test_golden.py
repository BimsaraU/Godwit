"""Against tests/golden: the kit's copy of the torture fixture, and a run over it."""

from __future__ import annotations

from pathlib import Path

import pyarrow.parquet as pq
from godwit_sdk.testing import torture


def test_the_kits_copy_of_the_pii_torture_fixture_matches_the_original(
    golden_json: object, golden_dir: Path
) -> None:
    load = golden_json
    fixture = load("pii_torture/fixture.json")
    leaks = load("pii_torture/expected_leaks.json")
    copy = torture()
    assert copy.table_name == fixture["table"]
    assert copy.driver_exception == fixture["driver_exception_trap"]
    assert copy.must_never_appear == tuple(leaks["must_never_appear_in_any_egress"])
    original = pq.read_table(golden_dir / "pii_torture" / "table.parquet")
    assert copy.table.to_pylist() == original.to_pylist()
    assert copy.pii_classes == {c["name"]: c["pii_class"] for c in fixture["columns"]}


def test_the_searchable_sentinels_cover_every_identifier_class() -> None:
    sentinels = set(torture().sentinels)
    for expected in (
        "Aoife Brennan",
        "aoife.brennan@northfield-bank.test",
        "100-40-1000",
        "dev-0000-a4f7723b",
        "ACME_CORP",
        "is_merchant_ACME_CORP",
        "pilot_group_a",
    ):
        assert expected in sentinels
    assert "unknown" not in sentinels
