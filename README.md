# Godwit

Two capabilities on one substrate.

**Discovery** finds emerging patterns nobody asked it to look for — payment fraud,
churn, silent data-quality collapse, novel abuse — by watching the *statistics* of
tables change over time rather than by scanning rows.

**Prediction** takes a partially labelled dataset, works out what the labels mean, and
predicts the rest, producing a deployable, versioned prediction engine.

They are one product because of a single idea: **a discovered pattern is a feature.**
The segment divergences, graph anomalies and heavy-hitter shifts the detectors find are
exactly what a human would hand-engineer into a fraud model.

Named for the bird, which works a mudflat by pushing a long, nerve-rich bill into water
it cannot see through, finding prey by touch. It moves nothing and it is told nothing.
The name is a codename; replace it freely.

---

## Start here

```sh
make install     # uv sync --all-packages
make test        # the whole workspace; needs no docker
make up          # Postgres 16 + pgvector, MinIO, Iceberg REST catalog
make seed        # regenerate tests/golden (deterministic)
make check       # ruff + mypy --strict + pytest, i.e. what CI runs
```

Requirements: Python 3.12, [uv](https://docs.astral.sh/uv/), and Docker for `make up`.

Then read, in order:

1. **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the seven invariants, the leak
   paths, the plane boundary, the layer map, and the open questions. Not optional.
2. **[docs/packages/godwit-contracts.md](docs/packages/godwit-contracts.md)** — the
   types every package codes against.
3. **[tests/golden/README.md](tests/golden/README.md)** — the shared fixtures.
4. Your own package's `HANDOFF.md`.

---

## The two planes

| | Control plane | Data plane |
|---|---|---|
| Holds | orchestrator, pattern store, Vision Board, LLM layer, registry metadata | probe workers, feature computation, training, inference, tokenisation map |
| Sees | sketches, gated statistics, metrics, artifact metadata | rows, in place |
| Emits | alerts, dashboards, explanations | gated artifacts only |

Between them sits `godwit-guard`, the egress gate. **Compute goes to the data. The data
never moves.**

---

## Layout

```
packages/godwit-contracts/      A0   types, taint, protocols — immutable to everyone but A0
packages/godwit-source/         A1   source adapters, semantic catalog (L-1, L0)
packages/godwit-sketch/         A2   mergeable monoid sketches (L1)
packages/godwit-store/          A3   Postgres + pgvector pattern store (L5)
packages/godwit-replay/         A4   deterministic replay from lineage
packages/godwit-guard/          A5   THE GATE: classify, redact, tokenise, audit
packages/godwit-probe/          A6   probe workers (L1)
packages/godwit-detect/         A7   drift statistics, unsupervised scoring (L2)
packages/godwit-context/        A8   explained-away layer (L3)
packages/godwit-sdk/            A9   public extension surface
packages/godwit-orchestrator/   A10  budgeted bandit over the probe space (L4)
packages/godwit-features/       A11  feature factory (L6)
packages/godwit-subtractor/     A12  removes already-explained signal
packages/godwit-predict/        A13  semi-supervised training and evaluation (L7)
packages/godwit-serve/          A14  registry, shadow deploy, drift, rollback (L8)
packages/godwit-llm/            A15  provider-agnostic LLM adapter (L9)
packages/godwit-vision/         A16  Vision Board server (L10)
apps/vision-board/              A17  Vision Board UI
docs/  tests/golden/  infra/    A0
```

---

## The rules, in one screen

1. **Write only inside the package you own**, plus your own files under `docs/` and
   `tests/golden/`. Never edit another agent's package. Never edit `godwit-contracts`
   unless you are A0.
2. **If a contract is wrong, missing or impossible: do not fix it.** Write
   `docs/change-requests/CR-<your-id>-<slug>.md`, then implement against the contract
   exactly as written with a failing `xfail` test showing what you needed. A human
   decides.
3. Types on every public function. `ruff` and `mypy --strict` pass with **zero
   suppressions**.
4. Unit tests for logic, at least one test against `tests/golden/`, and property tests
   (hypothesis) for anything claiming a mathematical property.
5. **Determinism**: no wall-clock reads, no unseeded randomness, anywhere on a path that
   can produce a pattern or a prediction. Time is injected. Seeds are explicit.
6. **Cost**: anything that can issue a billable query or a training run takes a
   `CostBudget` and refuses rather than exceeds it. Refusing is a normal outcome.
7. Write `docs/packages/<your-package>.md` and your `HANDOFF.md`. Assume the reader has
   never seen your code and cannot ask you anything.
8. No `TODO` comments in finished code. Unfinished work goes under "known limits".
9. If your package runs in the data plane or handles data-derived values, **say so at
   the top of its docs** and treat every output as something a bank's security team will
   inspect line by line.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to run the checks and what "done" means.
