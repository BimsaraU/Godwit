"""ACCEPTANCE: peak memory is bounded by the batch, not by the table.

Each measurement runs in a fresh interpreter and reports the process's *peak* resident
set -- Python heap, Arrow buffers and DuckDB's allocator alike, which is the number an
operator's OOM killer looks at. A small table and a large one are probed with the same
batch size; the peaks must agree to within a fixed allowance, and the large probe must
really have counted every row.

The default large table is five million rows so ``make test`` stays quick. The
acceptance figure is a hundred million:

    GODWIT_PROBE_BIG_ROWS=100000000 uv run pytest packages/godwit-probe -k memory -s

Measured results are recorded in ``docs/packages/godwit-probe.md``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SMALL_ROWS = 500_000
BIG_ROWS = int(os.environ.get("GODWIT_PROBE_BIG_ROWS", "5000000"))
SKETCH_SMALL_ROWS = 100_000
SKETCH_BIG_ROWS = int(os.environ.get("GODWIT_PROBE_SKETCH_ROWS", "1000000"))
ALLOWANCE_BYTES = 96 * 2**20

_SCRIPT = r"""
import ctypes, json, sys, time
from godwit_contracts import ProbeKind, SketchKind
from godwit_guard import AccessMode
from godwit_probe.testing import (
    Distribution, ProbeSimulator, SyntheticColumn, SyntheticCommit, SyntheticTable,
)
from godwit_sketch import decode_envelope

def peak_rss() -> int:
    if sys.platform == "win32":
        class Counters(ctypes.Structure):
            _fields_ = [(n, ctypes.c_size_t) for n in (
                "cb", "PageFaultCount", "PeakWorkingSetSize", "WorkingSetSize",
                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
                "PagefileUsage", "PeakPagefileUsage")]
        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        current = ctypes.windll.kernel32.GetCurrentProcess
        current.restype = ctypes.c_void_p
        info = ctypes.windll.psapi.GetProcessMemoryInfo
        info.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        if not info(current(), ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)
    import resource
    scale = 1 if sys.platform == "darwin" else 1024
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * scale

rows = int(sys.argv[1])
kinds = [SketchKind(kind) for kind in sys.argv[2].split(",")]
table = SyntheticTable(
    namespace="bench", name="events", seed=5,
    columns=(
        SyntheticColumn("amount", Distribution.NORMAL, mean=50.0, sigma=10.0, null_fraction=0.01),
        SyntheticColumn("row_no", Distribution.SEQUENCE),
    ),
    commits=(SyntheticCommit(rows=rows),),
    rows_per_file=4_000_000, block_rows=262_144,
)
sim = ProbeSimulator(table, modes={"amount": AccessMode.OPEN, "row_no": AccessMode.OPEN},
                     batch_rows=262_144)
spec = sim.spec(ProbeKind.NULL_RATE, ["amount"], sketches=kinds)
baseline = peak_rss()
started = time.perf_counter()
outcome = sim.run(spec)
elapsed = time.perf_counter() - started
population = next(iter(outcome.bundle.sketches.values())).population
print(json.dumps({"rows": rows, "population": population, "baseline": baseline,
                  "peak": peak_rss(), "seconds": elapsed,
                  "bytes": outcome.cost_spent.bytes_scanned}))
"""


def _measure(rows: int, kinds: str) -> dict[str, float]:
    completed = subprocess.run(
        [sys.executable, "-c", _SCRIPT, str(rows), kinds],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=3600,
    )
    assert completed.returncode == 0, completed.stderr[-5000:]
    result: dict[str, float] = json.loads(completed.stdout.strip().splitlines()[-1])
    return result


def test_peak_memory_does_not_grow_with_the_table() -> None:
    small = _measure(SMALL_ROWS, "exact_count")
    big = _measure(BIG_ROWS, "exact_count")
    print(f"\nsmall: {small}\nbig:   {big}")
    assert small["population"] == SMALL_ROWS
    assert big["population"] == BIG_ROWS
    assert small["peak"] > 0
    assert big["peak"] - small["peak"] < ALLOWANCE_BYTES


def test_value_sketches_are_bounded_too() -> None:
    """KLL and HLL are fed value by value in Python; their state is fixed-size."""
    small = _measure(SKETCH_SMALL_ROWS, "kll,hll")
    big = _measure(SKETCH_BIG_ROWS, "kll,hll")
    print(f"\nsmall: {small}\nbig:   {big}")
    # KLL and HLL skip nulls, and the column is 1% null.
    assert big["population"] > 0.98 * SKETCH_BIG_ROWS
    assert big["peak"] - small["peak"] < ALLOWANCE_BYTES
