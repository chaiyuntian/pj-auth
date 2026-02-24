#!/usr/bin/env node
import { runEvolution } from "./scripts/evolve.mjs";

const args = process.argv.slice(2);
const command = args[0] || "run";

if (!["run", "/evolve"].includes(command)) {
  console.log(
    "Usage: node tools/capability-evolver/index.mjs run [--repo <path>] [--target <path>] [--review|--apply] [--mutation <id>] [--no-rollback]"
  );
  process.exit(1);
}

try {
  const result = await runEvolution(args.slice(1));
  process.exit(result.ok ? 0 : 2);
} catch (error) {
  console.error(`[capability-evolver] fatal: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
}
