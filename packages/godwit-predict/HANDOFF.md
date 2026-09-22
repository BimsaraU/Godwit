# godwit-predict -- HANDOFF

**Owner:** A13
**Plane:** data
**Purpose:** Semi-supervised training, model search, calibration, evaluation (L7).

> Stub written by A0. The owning agent replaces this file in full.
> Read `docs/ARCHITECTURE.md` first, then `docs/packages/godwit-contracts.md`.

**This package runs in the DATA PLANE.** It reads customer rows, so everything it
emits must be gated. Treat every output as something a bank's security team will
inspect line by line.

## Status

Not started.

## Known limits

- Everything.
