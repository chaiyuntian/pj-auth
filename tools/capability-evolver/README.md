# Capability Evolver (pj-auth)

Protocol-style self-evolution engine for this repository.

## Goals
- Analyze current repo/runtime signals.
- Select one safe mutation gene.
- Apply mutation with validation.
- Roll back on validation failure.
- Persist auditable events/capsules/reports.

## Commands
- Review cycle:
  - `node tools/capability-evolver/index.mjs run --repo . --target src --review`
- Apply cycle:
  - `node tools/capability-evolver/index.mjs run --repo . --target src --apply`
- Force mutation:
  - `node tools/capability-evolver/index.mjs run --repo . --target src --apply --mutation add-e2e-smoke-script`
- Loop mode (recommended for autonomous refinement):
  - `EVOLVE_STRATEGY=innovate node tools/capability-evolver/index.mjs --loop --repo . --target src --apply`
- Finite loop run (for controlled execution):
  - `EVOLVE_STRATEGY=innovate node tools/capability-evolver/index.mjs --loop --repo . --target src --apply --interval-ms 2000 --heartbeat-ms 1000 --max-cycles 2`

## State Artifacts
- `tools/capability-evolver/assets/gep/genes.json`
- `tools/capability-evolver/assets/gep/events.jsonl`
- `tools/capability-evolver/assets/gep/capsules.json`
- `tools/capability-evolver/memory/reports/latest.md`

## Operating Rule
Run `--review` first in a new scope, then `--apply`.

## Strategy Presets
- `balanced`
- `innovate`
- `harden`
- `repair-only`
