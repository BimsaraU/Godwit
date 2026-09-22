"""Accuracy and memory benchmarks for godwit-sketch. Run it, paste the table into the docs.

    uv run python packages/godwit-sketch/benchmarks/run_benchmarks.py
    uv run python packages/godwit-sketch/benchmarks/run_benchmarks.py --distinct 100000000

Two things are measured, because two different claims need evidence.

**Accuracy.** Every estimate is compared against the exact answer computed the slow way
over the same rows, and the observed error is printed next to the bound the sketch
declares. A sketch whose observed error exceeds its documented bound is worse than a
sketch with a loose bound: detectors at L2 subtract the bound before deciding something
moved, so an optimistic bound turns directly into false positives.

**Memory.** Both the live Python footprint and the serialised payload size, because they
are different numbers and both matter. The payload is what the pattern store holds for
every probe of every column of every snapshot; the live size is what a probe worker has
to fit while it runs.

Everything here is seeded. Run it twice and get the same table.
"""

from __future__ import annotations

import argparse
import bisect
import statistics
import time
import tracemalloc
from collections import Counter
from collections.abc import Callable, Iterator

from godwit_sketch.deterministic import lognormals, zipf_indices
from godwit_sketch.distinct import ThetaNdv
from godwit_sketch.frequency import CountMinHeavy
from godwit_sketch.hll import HllCount
from godwit_sketch.items import canonical_item_key
from godwit_sketch.moments import Moments
from godwit_sketch.quantile import KllQuantile

ROWS = 1_000_000
SEED = 20240101


def _rule(title: str) -> None:
    print(f"\n{title}\n{'=' * len(title)}")


def _lognormal(count: int, seed: int) -> list[float]:
    return lognormals(count, salt=f"amount/{seed}")


def _zipf_keys(count: int, distinct: int, seed: int) -> list[str]:
    """Zipf-ish categorical stream: a few very heavy hitters and a long tail."""
    return [f"key-{index}" for index in zipf_indices(count, distinct=distinct, salt=f"cat/{seed}")]


# --------------------------------------------------------------------------------------
# Accuracy
# --------------------------------------------------------------------------------------


def quantile_accuracy(rows: int, trials: int = 3) -> None:
    """KLL rank error against exact quantiles, over lognormal amounts.

    Reported over several seeds, and the comparison to make is ``p67`` against the
    bound, not ``max``. The declared bound is one standard deviation of a *single*
    query's rank error. Taking the worst of 99 correlated probes and holding it against
    a 1-sigma figure asks the bound to be something it never claimed to be: on a single
    seed that maximum lands anywhere between 0.5x and 2x the bound purely by luck, which
    is how a perfectly healthy sketch can be made to look broken. ``p67`` is the
    like-for-like number; ``median max`` is shown beside it because it is what a
    detector comparing two snapshots across a whole column actually runs into.
    """
    _rule(f"KLL quantile accuracy, {rows:,} lognormal rows, {trials} seeds")
    probes = [index / 100 for index in range(1, 100)]
    print(
        f"{'k':>6}  {'bound(1sd)':>11}  {'p67 err':>9}  {'p67/bound':>10}  "
        f"{'median max':>11}  {'max/bound':>10}"
    )
    for k in (100, 200, 400, 800):
        worsts: list[float] = []
        typicals: list[float] = []
        bound = 0.0
        for trial in range(trials):
            data = _lognormal(rows, SEED + trial)
            exact = sorted(data)
            sketch = KllQuantile.from_items(data, {"k": k, "seed": trial})
            errors = sorted(
                abs(bisect.bisect_right(exact, sketch.quantile(q).reveal()) / rows - q)
                for q in probes
            )
            bound = sketch.error_bound().epsilon or 0.0
            worsts.append(errors[-1])
            typicals.append(errors[int(0.67 * len(errors))])
        typical = statistics.median(typicals)
        worst = statistics.median(worsts)
        print(
            f"{k:>6}  {bound:>11.5f}  {typical:>9.5f}  {typical / bound:>10.2f}  "
            f"{worst:>11.5f}  {worst / bound:>10.2f}"
        )


def distinct_accuracy(rows: int, trials: int = 7) -> None:
    """Theta and HLL cardinality error against the exact distinct count.

    Reported as bias and observed spread over several seeds, not as one seed's error.
    The declared bound is a *standard deviation*: a single draw sitting 1.5x outside it
    is unremarkable, and judging an estimator on one draw is how a healthy sketch gets
    replaced by a worse one. What matters is that the bias is near zero and the observed
    spread is in line with the bound.
    """
    _rule(f"Distinct-count accuracy, {rows:,} distinct values, {trials} seeds")
    print(f"{'sketch':>10} {'lg_k':>5} {'bias':>9} {'observed sd':>12} {'bound(1sd)':>11}")
    for lg_k in (10, 12, 14):
        errors: dict[str, list[float]] = {"Theta": [], "HLL": []}
        bounds: dict[str, float] = {}
        for trial in range(trials):
            data = [f"id-{trial}-{index}" for index in range(rows)]
            for name, sketch in (
                ("Theta", ThetaNdv.from_items(data, {"lg_k": lg_k})),
                ("HLL", HllCount.from_items(data, {"lg_k": lg_k, "seed": trial})),
            ):
                errors[name].append((sketch.estimate() - rows) / rows)
                bounds[name] = sketch.error_bound().epsilon or 0.0
        for name in ("Theta", "HLL"):
            print(
                f"{name:>10} {lg_k:>5} {statistics.fmean(errors[name]):>+8.3%} "
                f"{statistics.pstdev(errors[name]):>11.3%} {bounds[name]:>10.3%}"
            )


def frequency_accuracy(rows: int) -> None:
    """Count-Min over-estimate against exact counts, on a Zipf stream."""
    _rule(f"Count-Min frequency accuracy, {rows:,} Zipf rows")
    data = _zipf_keys(rows, distinct=50_000, seed=SEED)
    exact = Counter(data)
    print(
        f"{'width':>7} {'depth':>6} {'bound eps*N':>12} {'max over':>10} "
        f"{'mean over':>10} {'top10 hit':>10}"
    )
    for width, depth in ((2718, 5), (8192, 5)):
        sketch = CountMinHeavy.from_items(data, {"width": width, "depth": depth, "seed": 1})
        overs = [sketch.estimate(key) - count for key, count in exact.items()]
        if min(overs) < 0:
            raise AssertionError(
                f"Count-Min under-counted by {min(overs)}; its one hard guarantee is that "
                "it never does"
            )
        bound = (sketch.error_bound().epsilon or 0.0) * rows
        # Heavy hitters come back in canonical tagged form ("s:key-3"), the same form a
        # Segment predicate uses, so the true top has to be canonicalised to compare.
        true_top = {canonical_item_key(key) for key, _ in exact.most_common(10)}
        found = {key.reveal() for key, _ in sketch.heavy_hitters(10)}
        print(
            f"{width:>7} {depth:>6} {bound:>12.1f} {max(overs):>10} "
            f"{statistics.fmean(overs):>10.2f} {len(true_top & found):>9}/10"
        )


def moment_accuracy(rows: int) -> None:
    """Moments against the exact statistics, and the merged path against the streamed one."""
    _rule(f"Moment accuracy, {rows:,} lognormal rows")
    data = _lognormal(rows, SEED)
    sketch = Moments.from_items(data, {})
    shard = rows // 7
    merged = Moments.identity({})
    for start in range(0, rows, shard):
        merged = merged.merge(Moments.from_items(data[start : start + shard], {}))
    truth_mean = statistics.fmean(data)
    truth_var = statistics.variance(data)
    print(f"{'statistic':>10} {'exact':>18} {'streamed':>18} {'merged':>18} {'rel err':>10}")
    for name, got, want in (
        ("mean", sketch.mean(), truth_mean),
        ("variance", sketch.variance(), truth_var),
    ):
        merged_value = merged.mean() if name == "mean" else merged.variance()
        print(
            f"{name:>10} {want:>18.9f} {got:>18.9f} {merged_value:>18.9f} "
            f"{abs(got - want) / abs(want):>10.2e}"
        )


# --------------------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------------------


def _distinct_stream(count: int) -> Iterator[str]:
    for index in range(count):
        yield f"entity-{index}"


def _fill_theta(distinct: int) -> bytes:
    sketch = ThetaNdv.identity({"lg_k": 12})
    for key in _distinct_stream(distinct):
        sketch.update(key)
    return sketch.encode()


def _fill_hll(distinct: int) -> bytes:
    sketch = HllCount.identity({"lg_k": 12, "seed": 1})
    for key in _distinct_stream(distinct):
        sketch.update(key)
    return sketch.encode()


def _fill_count_min(distinct: int) -> bytes:
    sketch = CountMinHeavy.identity({"width": 2718, "depth": 5, "seed": 1})
    for key in _distinct_stream(distinct):
        sketch.update(key)
    return sketch.encode()


def memory_profile(distinct_counts: tuple[int, ...]) -> None:
    """Live footprint and serialised size at each distinct-value count.

    The distinct-counting sketches are fixed-size by construction, so the interesting
    result is that the numbers do not move between 1M and 100M. That is the property
    being demonstrated, not an accident of the measurement.

    Each kind gets its own filler function rather than one loop over a common
    ``update``. ``update`` is deliberately *not* on ``BaseSketch``: the kinds take
    genuinely different observations -- a string, a float, a directed edge -- and
    flattening that into one base signature would let a caller feed an edge to a
    quantile sketch and find out at runtime.
    """
    _rule("Memory, by distinct values")
    print(f"{'sketch':>10} {'distinct':>12} {'live KiB':>10} {'payload KiB':>12} {'secs':>7}")

    fillers: dict[str, Callable[[int], bytes]] = {
        "Theta": _fill_theta,
        "HLL": _fill_hll,
        "CountMin": _fill_count_min,
    }

    for distinct in distinct_counts:
        for name, fill in fillers.items():
            tracemalloc.start()
            started = time.perf_counter()
            payload = fill(distinct)
            elapsed = time.perf_counter() - started
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            print(
                f"{name:>10} {distinct:>12,} {peak / 1024:>10.1f} "
                f"{len(payload) / 1024:>12.1f} {elapsed:>7.1f}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=ROWS, help="rows for accuracy runs")
    parser.add_argument(
        "--distinct",
        type=int,
        nargs="*",
        default=[1_000_000],
        help="distinct-value counts for the memory profile; pass 100000000 for the full run",
    )
    parser.add_argument("--skip-memory", action="store_true")
    arguments = parser.parse_args()

    quantile_accuracy(arguments.rows)
    distinct_accuracy(arguments.rows)
    frequency_accuracy(arguments.rows)
    moment_accuracy(arguments.rows)
    if not arguments.skip_memory:
        memory_profile(tuple(arguments.distinct))
    print(f"\nsalted with seed={SEED}; rerunning gives byte-identical numbers.")


if __name__ == "__main__":
    main()
