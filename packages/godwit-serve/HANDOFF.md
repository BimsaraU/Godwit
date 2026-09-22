# godwit-serve -- HANDOFF

**Owner:** A14
**Plane:** data
**Purpose:** Artifact registry, provisioning, shadow deploy, drift and rollback (L8).

> Stub written by A0. The owning agent replaces this file in full.
> Read `docs/ARCHITECTURE.md` first, then `docs/packages/godwit-contracts.md`.

**This package runs in the DATA PLANE.** It reads customer rows, so everything it
emits must be gated. Treat every output as something a bank's security team will
inspect line by line.

## Status

Not started.

## Known limits

- Everything.
