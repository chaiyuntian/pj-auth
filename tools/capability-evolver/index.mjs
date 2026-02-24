#!/usr/bin/env node
import { runEvolution } from "./scripts/evolve.mjs";

const WORK_INTERVAL_FALLBACK_MS = 4 * 60 * 60 * 1000;
const HEARTBEAT_FALLBACK_MS = 15 * 60 * 1000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const readNumberArg = (argv, key, fallback) => {
  const index = argv.indexOf(key);
  if (index === -1) return fallback;
  const raw = argv[index + 1];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
};

const stripArgs = (argv, keysWithValue, flags) => {
  const output = [];
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (keysWithValue.has(token)) {
      index += 1;
      continue;
    }
    if (flags.has(token)) {
      continue;
    }
    output.push(token);
  }
  return output;
};

const argv = process.argv.slice(2);
const explicitCommand = argv[0] && !argv[0].startsWith("-") ? argv[0] : null;
const args = explicitCommand ? argv.slice(1) : argv;

if (explicitCommand && !["run", "/evolve"].includes(explicitCommand)) {
  console.log(
    "Usage: node tools/capability-evolver/index.mjs [run] [--repo <path>] [--target <path>] [--review|--apply] [--mutation <id>] [--strategy <balanced|innovate|harden|repair-only>] [--loop] [--interval-ms <ms>] [--heartbeat-ms <ms>] [--max-cycles <n>] [--no-rollback]"
  );
  process.exit(1);
}

const runLoop = async (loopArgs) => {
  const intervalMs = readNumberArg(
    loopArgs,
    "--interval-ms",
    Number.parseInt(process.env.EVOLVE_WORK_INTERVAL_MS ?? "", 10) || WORK_INTERVAL_FALLBACK_MS
  );
  const heartbeatMs = readNumberArg(
    loopArgs,
    "--heartbeat-ms",
    Number.parseInt(process.env.EVOLVE_HEARTBEAT_INTERVAL_MS ?? "", 10) || HEARTBEAT_FALLBACK_MS
  );
  const maxCycles = readNumberArg(loopArgs, "--max-cycles", Number.parseInt(process.env.EVOLVE_MAX_CYCLES ?? "", 10) || 0);
  const cycleArgs = stripArgs(
    loopArgs,
    new Set(["--interval-ms", "--heartbeat-ms", "--max-cycles"]),
    new Set(["--loop"])
  );

  if (!cycleArgs.includes("--apply") && !cycleArgs.includes("--review")) {
    cycleArgs.push("--apply");
  }

  let cycle = 0;
  let hadFailure = false;
  console.log(
    `[capability-evolver] loop_start interval_ms=${intervalMs} heartbeat_ms=${heartbeatMs} max_cycles=${maxCycles || "infinite"}`
  );
  while (maxCycles === 0 || cycle < maxCycles) {
    cycle += 1;
    console.log(`[capability-evolver] cycle_start #${cycle}`);
    const result = await runEvolution(cycleArgs);
    if (!result.ok) {
      hadFailure = true;
      console.error(`[capability-evolver] cycle_failed #${cycle}`);
    }

    if (maxCycles > 0 && cycle >= maxCycles) {
      break;
    }

    const sleepStart = Date.now();
    while (Date.now() - sleepStart < intervalMs) {
      const elapsed = Date.now() - sleepStart;
      const remaining = intervalMs - elapsed;
      if (remaining <= 0) {
        break;
      }
      const waitMs = Math.min(heartbeatMs, remaining);
      await sleep(waitMs);
      console.log(`[capability-evolver] heartbeat cycle=${cycle} next_cycle_in_ms=${Math.max(0, intervalMs - (Date.now() - sleepStart))}`);
    }
  }
  console.log(`[capability-evolver] loop_end cycles=${cycle} status=${hadFailure ? "failed" : "ok"}`);
  return !hadFailure;
};

try {
  const loopMode = args.includes("--loop");
  const ok = loopMode ? await runLoop(args) : (await runEvolution(args)).ok;
  process.exit(ok ? 0 : 2);
} catch (error) {
  console.error(`[capability-evolver] fatal: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(2);
}
