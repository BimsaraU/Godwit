#!/usr/bin/env bash
# Regenerates the per-package skeleton. Idempotent: it never overwrites a file
# that already exists, so an owning agent's real work is safe.
set -euo pipefail
cd "$(dirname "$0")/.."

# name|owner|plane|summary
PKGS=(
"godwit-contracts|A0|control+data|Shared Pydantic contracts, taint types and protocols. Depends on nothing."
"godwit-source|A1|data|Source adapters and the semantic catalog (L-1, L0)."
"godwit-sketch|A2|data|Mergeable monoid sketches: Theta, KLL, HLL, Count-Min (L1)."
"godwit-store|A3|control|Postgres + pgvector persistence for patterns, runs and audit (L5)."
"godwit-replay|A4|control|Deterministic replay of a probe/detector run from lineage (invariant 7)."
"godwit-guard|A5|boundary|Classification, redaction, tokenisation and the egress gate (GATE)."
"godwit-probe|A6|data|Probe workers executing a ProbeSpec into a SketchBundle (L1)."
"godwit-detect|A7|control|Drift statistics and unsupervised scoring over sketches (L2)."
"godwit-context|A8|control|Explained-away layer: deploys, campaigns, holidays, DQ failures (L3)."
"godwit-sdk|A9|control+data|Public extension surface for third-party probes and detectors (SDK)."
"godwit-orchestrator|A10|control|Belief state and budgeted bandit allocation over the probe space (L4)."
"godwit-features|A11|data|Feature factory: entity, graph and time features, plus patterns as features (L6)."
"godwit-subtractor|A12|control|Removes already-explained signal so detectors see only the residual."
"godwit-predict|A13|data|Semi-supervised training, model search, calibration, evaluation (L7)."
"godwit-serve|A14|data|Artifact registry, provisioning, shadow deploy, drift and rollback (L8)."
"godwit-llm|A15|control|Provider-agnostic LLM adapter. Accepts SafePayload and nothing else (L9)."
"godwit-vision|A16|control|Vision Board server: datasources, dashboards, guardrails, actions (L10)."
)

for entry in "${PKGS[@]}"; do
  IFS='|' read -r name owner plane summary <<<"$entry"
  module="${name//-/_}"
  root="packages/${name}"
  mkdir -p "${root}/src/${module}" "${root}/tests"

  if [ ! -f "${root}/pyproject.toml" ]; then
    deps='dependencies = []'
    if [ "$name" != "godwit-contracts" ]; then
      deps='dependencies = ["godwit-contracts"]'
    fi
    cat > "${root}/pyproject.toml" <<EOF
[project]
name = "${name}"
version = "0.1.0"
description = "${summary}"
readme = "HANDOFF.md"
requires-python = ">=3.12,<3.13"
${deps}

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/${module}"]
EOF
  fi

  [ -f "${root}/src/${module}/py.typed" ] || : > "${root}/src/${module}/py.typed"

  if [ ! -f "${root}/src/${module}/__init__.py" ]; then
    cat > "${root}/src/${module}/__init__.py" <<EOF
"""${summary}

Owner: ${owner}. Plane: ${plane}.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
EOF
  fi

  if [ ! -f "${root}/tests/test_smoke.py" ]; then
    cat > "${root}/tests/test_smoke.py" <<EOF
"""Placeholder so a fresh checkout has a green pytest run for every package."""

from ${module} import __version__


def test_package_imports() -> None:
    assert __version__ == "0.1.0"
EOF
  fi

  PLANE_NOTE=""
  if [ "$plane" = "data" ]; then
    PLANE_NOTE="**This package runs in the DATA PLANE.** It reads customer rows, so everything it
emits must be gated. Treat every output as something a bank's security team will
inspect line by line."
  elif [ "$plane" = "boundary" ]; then
    PLANE_NOTE="**This package IS the boundary.** It is the only legitimate producer of
\`SafePayload\` and the only writer of \`EgressRecord\`."
  fi

  if [ ! -f "${root}/HANDOFF.md" ]; then
    cat > "${root}/HANDOFF.md" <<EOF
# ${name} -- HANDOFF

**Owner:** ${owner}
**Plane:** ${plane}
**Purpose:** ${summary}

> Stub written by A0. The owning agent replaces this file in full.
> Read \`docs/ARCHITECTURE.md\` first, then \`docs/packages/godwit-contracts.md\`.

${PLANE_NOTE}

## Status

Not started.

## Known limits

- Everything.
EOF
  fi
done

# Collapse the blank gap a control-plane package leaves where the plane note would be.
for handoff in packages/*/HANDOFF.md; do
  grep -q "Stub written by A0" "$handoff" || continue
  awk 'BEGIN{blank=0} /^$/{blank++; next} {while(blank>0){if(blank<=1)print ""; blank--}; print} END{}'     "$handoff" > "$handoff.tmp" && mv "$handoff.tmp" "$handoff"
done

echo "scaffolded ${#PKGS[@]} packages"
