"""Null false-positive rates and minimum detectable effects, per detector.

    uv run python packages/godwit-detect/tests/benchmark_detectors.py [--null 1000] [--sims 60]

Prints two markdown tables, the ones recorded in docs/packages/godwit-detect.md.
Seeded throughout, so a rerun on the same numpy gives the same numbers.

Lives beside the tests because it shares their synthetic worlds; its name does not
start with ``test_`` so pytest does not collect it.
"""

from __future__ import annotations

import argparse

from _detect_null import WORLDS, World, detected, null_rate

ALPHA = 0.05
TARGET_POWER = 0.8
BISECTION_STEPS = 7


def power(world: World, effect: float, size: int, sims: int) -> float:
    hits = sum(detected(world, world.run(10_000 + s, effect, size)) for s in range(sims))
    return hits / sims


def minimum_detectable(world: World, size: int, sims: int) -> str:
    if power(world, world.max_effect, size, sims) < TARGET_POWER:
        return f"> {world.max_effect:g}"
    low, high = 0.0, world.max_effect
    for _ in range(BISECTION_STEPS):
        middle = (low + high) / 2
        if power(world, middle, size, sims) >= TARGET_POWER:
            high = middle
        else:
            low = middle
    return f"{high:.3g}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--null", type=int, default=1000)
    parser.add_argument("--sims", type=int, default=60)
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    names = [n for n in WORLDS if args.only in n]

    print("| detector | series | tests | emitted | rate |")
    print("|---|---|---|---|---|")
    for name in names:
        emitted, tests = null_rate(WORLDS[name], args.null)
        print(f"| {name} | {args.null} | {tests} | {emitted} | {emitted / tests:.4f} |", flush=True)

    print()
    print("| detector | effect unit | sizes | minimum effect at 80% power |")
    print("|---|---|---|---|")
    for name in names:
        world = WORLDS[name]
        cells = ", ".join(
            f"{size}: {minimum_detectable(world, size, args.sims)}" for size in world.sizes
        )
        print(f"| {name} | {world.effect_unit} | {world.sizes} | {cells} |", flush=True)


if __name__ == "__main__":
    main()
