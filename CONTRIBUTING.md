# Contributing

Twenty agents, no shared session, one contract layer. This file is how the mechanics
work. The rules themselves are in [README.md](README.md) and the reasoning behind them
is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Setup

```sh
make install          # uv sync --all-packages, creates .venv
make check            # ruff + ruff format --check + mypy --strict + pytest
```

`uv` owns the environment and the lockfile. Do not `pip install` into `.venv`; add the
dependency to your package's `pyproject.toml` and re-run `make install`.

## Adding a dependency

Add it to `dependencies` in **your own** `packages/<pkg>/pyproject.toml`, then
`make install` to update `uv.lock`. Commit the lockfile.

Two rules:

* `godwit-contracts` depends on Pydantic and the standard library. Nothing else. There
  is a test that enforces it (`test_dependency_hygiene.py`), because a dependency added
  there is a dependency added to all seventeen packages, inside a bank that reviews
  every transitive package it runs.
* Do not substitute stack choices. The stack in the brief is fixed: DuckDB not Spark,
  Postgres `SKIP LOCKED` not Kafka or Celery, `apache-datasketches` not a hand-rolled
  HLL, our own registry not MLflow.

## What the checks are, and what they cover

| Command | Scope |
|---|---|
| `uv run ruff check .` | everything, including tests and scripts |
| `uv run ruff format --check .` | everything |
| `uv run mypy packages scripts` | package **source** and `scripts/`, in `--strict` |
| `uv run pytest` | everything |

**Tests are not type-checked.** Seventeen packages each ship a `tests/` directory and
the file basenames collide — every package has a `test_smoke.py` — which mypy cannot map
to distinct modules without an `__init__.py` in each. Rather than add seventeen package
markers, `tests/` is excluded from mypy. pytest runs in `--import-mode=importlib` for
the same reason. If you want your own tests type-checked, that is a change request.

**Zero suppressions** means no `# noqa` and no `# type: ignore` in package source.
Where a lint is genuinely wrong for a whole category of file — tests assert, the fixture
generator uses `random` — the exemption lives in `[tool.ruff.lint.per-file-ignores]` in
the root `pyproject.toml`, where it is visible and reviewable, rather than scattered
through the code. A `test_dependency_hygiene.py` test asserts that contracts source has
neither.

## Change requests

You may not edit `packages/godwit-contracts/` unless you are A0. If a contract is wrong,
missing or impossible:

1. Write `docs/change-requests/CR-<your-id>-<slug>.md` using
   [the template](docs/change-requests/TEMPLATE.md). State the problem, the **smallest
   sufficient** change, and who else it affects.
2. Implement against the contract exactly as written.
3. Leave one `@pytest.mark.xfail(reason="CR-<your-id>-<slug>")` test showing what you
   needed and could not have.

A human decides. Do not work around a contract silently — a workaround that ships is a
contract that two packages now disagree about.

## Golden fixtures

`tests/golden/` is shared. A0 seeded it, A5 extends the PII torture fixture, and any
agent may add a fixture of its own. **Nobody edits someone else's.**

Regenerate with `make seed`. The generator is seeded and reads no clock, so the JSON
output is byte-stable and CI diffs it. Parquet bytes are not stable across pyarrow
versions, so tables are pinned by `rows_digest` — a hash over the logical rows — and the
tests check that instead.

If `make seed` changes a fixture you did not mean to change, stop. Either the generator
changed or someone hand-edited a fixture, and both are things to understand before
committing.

## Tests

* Unit tests for logic.
* **At least one test against `tests/golden/`.**
* **Property tests (hypothesis) for anything claiming a mathematical property.** Sketch
  merge associativity and commutativity are the obvious ones. Example tests will not
  find the associativity bug.
* Tests must be deterministic: use the `frozen_now` fixture from the root `conftest.py`
  rather than reading a clock, and seed anything random.

If your package handles data-derived values, add a leak test against
`tests/golden/pii_torture/expected_leaks.json`: render your output to text and assert
that none of those strings appear. Remember what that test is — a **backstop**. The
control is the taint type plus the gate.

## Commit and branch hygiene

Small commits with a message that says why. Branch per unit of work. Do not commit
`.venv/`, `infra/.data/`, or anything under a directory listed in `.gitignore`.

## Definition of done

* `make check` green from a clean checkout.
* `docs/packages/<your-package>.md` and `HANDOFF.md` written, for a reader who has never
  seen your code and cannot ask you anything.
* Golden fixture tests pass; benchmarks recorded where your brief asked for them.
* Contract disagreements filed as change requests, not patched.
* If your package runs in the data plane or handles data-derived values, that is stated
  at the top of its docs.
* No `TODO` comments. Unfinished work goes under a **Known limits** heading.
