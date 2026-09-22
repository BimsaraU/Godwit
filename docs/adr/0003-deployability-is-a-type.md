# ADR-0003: Deployability is a type, not a check

**Status:** accepted
**Date:** 2024-01-17
**Decided by:** A0

## Context

Invariant 3: model artifacts are audited for memorisation before they cross. A model can
memorise its training rows — target encoding on a high-cardinality column bakes
identifiers straight into the artifact, and a deep enough tree on a near-unique column
does the same thing with extra steps.

The usual way to enforce this is a check at the deployment call site:

```python
def deploy(artifact: ModelArtifact) -> Deployment:
    if not artifact.audit or not artifact.audit.passed:
        raise ...
```

That check lives in one function, and there will eventually be a second deployment path.

## Decision

`Deployment.model` has type `DeployableModel`, not `ModelArtifact`. `DeployableModel` is
produced only by `certify_deployable()`, and it carries `audit_passed: Literal[True]`
and a `certificate` that hashes the artifact digest together with the audit digest.

## Why

Three properties fall out that a runtime check does not give:

1. **mypy catches it.** `Deployment(model=artifact)` is a type error at the call site,
   in every deployment path anyone writes later, including ones that do not exist yet.
2. **A failed deployable is not representable.** `Literal[True]` means
   `audit_passed=False` neither constructs nor parses from JSON. There is no "deployable
   with a failed audit" object that could be passed around, logged, or half-checked.
3. **The certificate binds the bytes.** It is computed over
   `(artifact_id, version, artifact_digest, audit_id, audit_digest)` and validated on
   every construction, so a deployable cannot be re-pointed at a different artifact
   after the fact. Re-training and reusing last week's audit is the obvious way round
   invariant 3, and `ModelArtifact` separately refuses an audit whose
   `artifact_digest` does not match its own.

`certify_deployable()` has no `force`, no `skip_audit` and no `allow_unaudited`. There
is a test asserting its signature is exactly `(artifact)`, because the parameter someone
adds in a hurry at 3am is the whole failure mode.

Supporting decision: `MemorisationAudit.passed` is validated to equal the conjunction of
its checks, and `REQUIRED_MEMORISATION_CHECKS` must all be present. Otherwise "audit
passed" degrades into "we ran the two cheap checks".

## Consequences

* A trainer cannot certify its own output. `Trainer` produces a `ModelArtifact`; the
  registry certifies. That separation is stated in the `Trainer` protocol laws.
* The certificate is a plain hash, not a signature. Code that can import contracts can
  recompute it. This is deliberate: it defends against *mistakes and re-pointing*, not
  against a hostile insider with commit access. If the threat model needs more, it needs
  a signing key held outside the process, which is a deployment decision rather than a
  type decision.
* `DeployableModel` is a Pydantic model rather than a sealed object like `SafePayload`,
  so that it serialises into the registry and over HTTP. `SafePayload` is sealed because
  it must never be reconstructible from data; a deployable must.

## Alternatives rejected

* **Runtime check in `deploy()`.** Rejected: one call site today, three next quarter.
* **A boolean flag on `ModelArtifact`.** Rejected: a bool can be set by anyone
  constructing the model, including from a JSON payload.
* **Sealing `DeployableModel` like `SafePayload`.** Rejected: it has to round-trip
  through the registry and the API, and sealing it would mean a parallel serialisable
  twin — which is the thing being guarded against.
