# CR-A2-datasketches-needs-a-mypy-override

**Filed by:** A2 (`godwit-sketch`)
**Against:** root `pyproject.toml`
**Status:** open

## The problem

`datasketches` ships no `py.typed` marker, so under `mypy --strict` every import of it
is an `import-untyped` error. The root `pyproject.toml` already carries exactly this
override for `pyarrow`:

```toml
[[tool.mypy.overrides]]
module = ["pyarrow.*"]
ignore_missing_imports = true
```

`datasketches` needs the same. Universal rule 3 forbids suppressions, so `# type: ignore`
is not available, and universal rule 1 means this package does not edit the root config.

## Why it matters

Nothing breaks — it is just awkward, and the workaround is a directory that would not
otherwise exist. Lowest priority of anything A2 has filed.

## The smallest sufficient change

```toml
[[tool.mypy.overrides]]
module = ["pyarrow.*", "datasketches.*"]
ignore_missing_imports = true
```

## What I did instead

Added a PEP 561 stub-only package at `packages/godwit-sketch/src/datasketches-stubs/`.
`packages/godwit-sketch/src` is already on the repo's `mypy_path`, so mypy finds it
automatically with no config change anywhere. It is not shipped: the wheel build
packages `src/godwit_sketch` only, so it is a development-time artifact.

The stub deliberately covers only the Theta surface this package calls, rather than
transcribing a library we use a corner of. A typo in an unused DataSketches API will
therefore not be caught — an acceptable trade for not maintaining a speculative
transcription.

If the override is added to the root config, the directory can be deleted and nothing
else changes.

## Who else this affects

* **A0** owns the root config.
* **A2 (`godwit-sketch`)** is the only package importing `datasketches` today. A6 may
  later, if it reads Puffin blobs directly.

## Decision

_Left blank by the filer. A human fills this in._
