import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CORS_HARDENED_VALUE = "https://users.pajamadot.com,http://127.0.0.1:8787";

const parseArgs = (argv) => {
  const options = {
    repo: process.cwd(),
    target: "src",
    apply: false,
    review: false,
    mutation: null,
    rollbackOnFailure: true
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--repo" && argv[index + 1]) {
      options.repo = argv[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--target" && argv[index + 1]) {
      options.target = argv[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--apply") {
      options.apply = true;
      continue;
    }
    if (arg === "--review") {
      options.review = true;
      continue;
    }
    if (arg === "--mutation" && argv[index + 1]) {
      options.mutation = argv[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--no-rollback") {
      options.rollbackOnFailure = false;
      continue;
    }
  }

  if (!options.apply && !options.review) {
    options.review = true;
  }
  return options;
};

const ensureDir = (dirPath) => {
  fs.mkdirSync(dirPath, { recursive: true });
};

const readJsonSafe = (filePath, fallback) => {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, "utf8");
    if (!raw.trim()) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
};

const writeJson = (filePath, value) => {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
};

const runCommand = (command, cwd, allowFailure = false) => {
  const result = spawnSync(command, {
    cwd,
    shell: true,
    encoding: "utf8",
    maxBuffer: 25 * 1024 * 1024
  });
  const code = typeof result.status === "number" ? result.status : 1;
  const output = {
    command,
    code,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? ""
  };
  if (!allowFailure && code !== 0) {
    throw new Error(`command failed (${code}): ${command}\n${output.stderr || output.stdout}`);
  }
  return output;
};

const hashText = (value) => crypto.createHash("sha1").update(value).digest("hex").slice(0, 12);

const parseGitStatus = (raw) =>
  raw
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean)
    .map((line) => ({
      status: line.slice(0, 2).trim(),
      file: line.slice(3).trim()
    }));

const extractCorsOrigins = (wranglerText) => {
  const match = wranglerText.match(/^\s*CORS_ORIGINS\s*=\s*"([^"]*)"/m);
  return match ? match[1] : "";
};

const gatherSignals = (repoRoot, target) => {
  const absoluteRepo = path.resolve(repoRoot);
  const absoluteTarget = path.resolve(absoluteRepo, target);
  const packagePath = path.join(absoluteRepo, "package.json");
  const wranglerPath = path.join(absoluteRepo, "wrangler.toml");
  const indexPath = path.join(absoluteRepo, "src", "index.ts");
  const e2eScriptPath = path.join(absoluteRepo, "scripts", "e2e-smoke.ps1");

  const gitStatus = runCommand("git status --short", absoluteRepo, true);
  const changes = parseGitStatus(gitStatus.stdout);

  const todoScan = runCommand(`rg -n "(TODO|FIXME|HACK)" "${target}"`, absoluteRepo, true);
  const todos = todoScan.code === 0 ? todoScan.stdout.split(/\r?\n/).filter(Boolean) : [];

  const packageJson = readJsonSafe(packagePath, {});
  const scripts = typeof packageJson.scripts === "object" && packageJson.scripts ? packageJson.scripts : {};
  const wranglerText = fs.existsSync(wranglerPath) ? fs.readFileSync(wranglerPath, "utf8") : "";
  const indexText = fs.existsSync(indexPath) ? fs.readFileSync(indexPath, "utf8") : "";

  const corsOrigins = extractCorsOrigins(wranglerText);
  const hasWildcardCors = corsOrigins.includes("*");

  return {
    repoRoot: absoluteRepo,
    target,
    targetPath: absoluteTarget,
    packagePath,
    wranglerPath,
    e2eScriptPath,
    changes,
    todos,
    hasTypecheckScript: typeof scripts.typecheck === "string",
    hasDeployScript: typeof scripts.deploy === "string",
    hasE2ESmokeNpmScript: typeof scripts["e2e:smoke"] === "string",
    hasE2ESmokeScriptFile: fs.existsSync(e2eScriptPath),
    corsOrigins,
    hasWildcardCors,
    hasDbHealthCheck: indexText.includes("SELECT 1 AS ok")
  };
};

const candidate = (genesById, id, score, reason) => {
  const gene = genesById[id];
  if (!gene) return null;
  return { id, score, reason, gene };
};

const evaluateGenes = (signals, genes) => {
  const genesById = Object.fromEntries(genes.map((gene) => [gene.id, gene]));
  const candidates = [];

  if (!signals.hasE2ESmokeNpmScript || !signals.hasE2ESmokeScriptFile) {
    candidates.push(
      candidate(
        genesById,
        "add-e2e-smoke-script",
        95,
        "Missing e2e smoke script file or npm command."
      )
    );
  }

  if (signals.hasWildcardCors) {
    candidates.push(
      candidate(
        genesById,
        "tighten-cors-allowlist",
        90,
        "CORS_ORIGINS uses wildcard; explicit allowlist required for production."
      )
    );
  }

  if (signals.hasTypecheckScript) {
    candidates.push(
      candidate(genesById, "run-typecheck", 70, "Typecheck should run in every evolution cycle.")
    );
  }

  if (signals.hasDeployScript) {
    candidates.push(
      candidate(genesById, "run-deploy-dry-run", 66, "Deploy dry-run validates release readiness.")
    );
  }

  candidates.push(
    candidate(
      genesById,
      "refresh-evolution-backlog",
      50,
      "Backlog should reflect current signals and unfinished hardening work."
    )
  );

  return candidates.filter(Boolean).sort((left, right) => right.score - left.score);
};

const backupFile = (stack, filePath) => {
  if (stack.some((entry) => entry.filePath === filePath)) return;
  if (fs.existsSync(filePath)) {
    stack.push({ filePath, existed: true, content: fs.readFileSync(filePath, "utf8") });
    return;
  }
  stack.push({ filePath, existed: false, content: "" });
};

const rollback = (stack) => {
  for (let index = stack.length - 1; index >= 0; index -= 1) {
    const entry = stack[index];
    if (entry.existed) {
      fs.writeFileSync(entry.filePath, entry.content, "utf8");
      continue;
    }
    if (fs.existsSync(entry.filePath)) {
      fs.unlinkSync(entry.filePath);
    }
  }
};

const addE2ESmokeScript = (signals, rollbackStack) => {
  const packageJson = readJsonSafe(signals.packagePath, null);
  if (!packageJson || typeof packageJson !== "object") {
    return {
      note: "Skipped: package.json not found.",
      changedFiles: []
    };
  }

  const changedFiles = [];

  if (!signals.hasE2ESmokeScriptFile) {
    const content = `param(
  [string]$BaseUrl = "https://users.pajamadot.com",
  [string]$Password = "Passw0rd123!"
)

$ErrorActionPreference = "Stop"
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$email = "smoke-$stamp@pajamadot.com"

Write-Host "Running health check against $BaseUrl"
$health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/healthz"
if (-not $health.ok) {
  throw "Health check failed"
}

Write-Host "Creating smoke user: $email"
$signup = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/sign-up" -ContentType "application/json" -Body (@{
  email = $email
  password = $Password
  fullName = "Smoke User"
} | ConvertTo-Json -Compress)

$token = $signup.session.accessToken
if (-not $token) {
  throw "No access token from sign-up"
}

Write-Host "Fetching current user"
$me = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/auth/me" -Headers @{ Authorization = "Bearer $token" }
if ($me.user.email -ne $email) {
  throw "Unexpected /me email"
}

Write-Host "Listing sessions"
$sessions = Invoke-RestMethod -Method Get -Uri "$BaseUrl/v1/auth/sessions" -Headers @{ Authorization = "Bearer $token" }
if (-not $sessions.sessions -or $sessions.sessions.Count -lt 1) {
  throw "No active sessions returned"
}

Write-Host "Smoke test succeeded for $email"
`;
    backupFile(rollbackStack, signals.e2eScriptPath);
    ensureDir(path.dirname(signals.e2eScriptPath));
    fs.writeFileSync(signals.e2eScriptPath, content, "utf8");
    changedFiles.push(signals.e2eScriptPath);
  }

  if (!signals.hasE2ESmokeNpmScript) {
    backupFile(rollbackStack, signals.packagePath);
    if (!packageJson.scripts || typeof packageJson.scripts !== "object") {
      packageJson.scripts = {};
    }
    packageJson.scripts["e2e:smoke"] =
      "powershell -NoProfile -ExecutionPolicy Bypass -File ./scripts/e2e-smoke.ps1";
    writeJson(signals.packagePath, packageJson);
    changedFiles.push(signals.packagePath);
  }

  return {
    note: changedFiles.length > 0 ? "Added e2e smoke script + npm command." : "Skipped: e2e smoke already configured.",
    changedFiles,
    validations: [{ command: "npm run typecheck", cwd: signals.repoRoot }]
  };
};

const tightenCorsAllowlist = (signals, rollbackStack) => {
  if (!signals.hasWildcardCors) {
    return { note: "Skipped: CORS is already explicit.", changedFiles: [] };
  }
  if (!fs.existsSync(signals.wranglerPath)) {
    return { note: "Skipped: wrangler.toml not found.", changedFiles: [] };
  }
  const before = fs.readFileSync(signals.wranglerPath, "utf8");
  const after = before.replace(/^\s*CORS_ORIGINS\s*=\s*"[^"]*"/m, `CORS_ORIGINS = "${CORS_HARDENED_VALUE}"`);
  if (before === after) {
    return { note: "Skipped: unable to patch CORS_ORIGINS line.", changedFiles: [] };
  }
  backupFile(rollbackStack, signals.wranglerPath);
  fs.writeFileSync(signals.wranglerPath, after, "utf8");
  return {
    note: "Replaced wildcard CORS_ORIGINS with explicit allowlist.",
    changedFiles: [signals.wranglerPath],
    validations: [
      { command: "npm run typecheck", cwd: signals.repoRoot },
      { command: "npx wrangler deploy --dry-run", cwd: signals.repoRoot }
    ]
  };
};

const runTypecheckGene = (signals) => ({
  note: "Running typecheck validation.",
  changedFiles: [],
  validations: [{ command: "npm run typecheck", cwd: signals.repoRoot }]
});

const runDeployDryRunGene = (signals) => ({
  note: "Running deploy dry-run validation.",
  changedFiles: [],
  validations: [{ command: "npx wrangler deploy --dry-run", cwd: signals.repoRoot }]
});

const refreshBacklogGene = (signals, rollbackStack) => {
  const backlogPath = path.join(signals.repoRoot, "docs", "EVOLUTION_BACKLOG.md");
  const signalChanges = signals.changes.slice(0, 15).map((entry) => `- ${entry.status || "??"} ${entry.file}`);
  const signalTodos = signals.todos.slice(0, 15).map((line) => `- ${line}`);
  const content = [
    "# Evolution Backlog",
    "",
    `Last refreshed: ${new Date().toISOString()}`,
    "",
    "## Signals",
    `- changed files: ${signals.changes.length}`,
    `- TODO/FIXME lines in target: ${signals.todos.length}`,
    `- db health check in source: ${signals.hasDbHealthCheck ? "yes" : "no"}`,
    `- e2e smoke script present: ${signals.hasE2ESmokeScriptFile && signals.hasE2ESmokeNpmScript ? "yes" : "no"}`,
    "",
    "## Working Tree Sample",
    ...(signalChanges.length > 0 ? signalChanges : ["- clean working tree"]),
    "",
    "## TODO/FIXME Sample",
    ...(signalTodos.length > 0 ? signalTodos : ["- no TODO/FIXME lines detected"]),
    "",
    "## Next Mutation Priorities",
    "- Keep CORS allowlist explicit for production domains.",
    "- Keep e2e smoke script green in CI and before deploys.",
    "- Add deeper integration tests for Google OAuth callback and reset flows.",
    "- Add worker rate-limiting and abuse controls on auth endpoints.",
    ""
  ].join("\n");

  backupFile(rollbackStack, backlogPath);
  ensureDir(path.dirname(backlogPath));
  fs.writeFileSync(backlogPath, content, "utf8");

  return {
    note: "Refreshed docs/EVOLUTION_BACKLOG.md.",
    changedFiles: [backlogPath]
  };
};

const applyGene = (selected, signals, rollbackStack) => {
  switch (selected.id) {
    case "add-e2e-smoke-script":
      return addE2ESmokeScript(signals, rollbackStack);
    case "tighten-cors-allowlist":
      return tightenCorsAllowlist(signals, rollbackStack);
    case "run-typecheck":
      return runTypecheckGene(signals);
    case "run-deploy-dry-run":
      return runDeployDryRunGene(signals);
    case "refresh-evolution-backlog":
      return refreshBacklogGene(signals, rollbackStack);
    default:
      return {
        note: `No mutation handler for ${selected.id}`,
        changedFiles: []
      };
  }
};

const formatReport = ({ event, selected, candidates, applyResult, validations }) => {
  const lines = [
    "# Capability Evolver Report",
    "",
    `- Run ID: \`${event.runId}\``,
    `- Timestamp: ${event.timestamp}`,
    `- Mode: ${event.mode}`,
    `- Status: **${event.status}**`,
    `- Selected Gene: \`${selected ? selected.id : "none"}\``,
    "",
    "## Top Candidates",
    ...candidates.slice(0, 8).map((entry) => `- \`${entry.id}\` (score ${entry.score}): ${entry.reason}`),
    "",
    "## Apply Result",
    `- ${applyResult.note}`,
    ...(applyResult.changedFiles?.length
      ? applyResult.changedFiles.map((filePath) => `- changed: \`${path.relative(event.repoRoot, filePath)}\``)
      : ["- no file changes"]),
    "",
    "## Validation",
    ...(validations.length === 0
      ? ["- no validation commands executed"]
      : validations.map((item) => `- [${item.code === 0 ? "PASS" : "FAIL"}] \`${item.command}\``)),
    ""
  ];
  return lines.join("\n");
};

const writeEventAndCapsules = (skillRoot, event, report, selected, validations) => {
  const gepDir = path.join(skillRoot, "assets", "gep");
  const reportDir = path.join(skillRoot, "memory", "reports");
  ensureDir(gepDir);
  ensureDir(reportDir);

  const eventsPath = path.join(gepDir, "events.jsonl");
  fs.appendFileSync(eventsPath, `${JSON.stringify(event)}\n`, "utf8");

  const capsulesPath = path.join(gepDir, "capsules.json");
  const capsules = readJsonSafe(capsulesPath, { version: 1, capsules: [] });
  if (!Array.isArray(capsules.capsules)) capsules.capsules = [];
  if (event.status === "success" && selected) {
    capsules.capsules.unshift({
      id: `${selected.id}-${hashText(`${event.runId}:${event.target}`)}`,
      geneId: selected.id,
      target: event.target,
      summary: `Successful ${selected.id} cycle`,
      createdAt: event.timestamp,
      validations: validations.map((entry) => ({ command: entry.command, code: entry.code }))
    });
    capsules.capsules = capsules.capsules.slice(0, 200);
    writeJson(capsulesPath, capsules);
  }

  const stamp = event.timestamp.replace(/[:.]/g, "-");
  fs.writeFileSync(path.join(reportDir, `run-${stamp}.md`), report, "utf8");
  fs.writeFileSync(path.join(reportDir, "latest.md"), report, "utf8");
};

export const runEvolution = async (argv) => {
  const options = parseArgs(argv);
  const skillRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const genesPath = path.join(skillRoot, "assets", "gep", "genes.json");
  const genesPayload = readJsonSafe(genesPath, { genes: [] });
  const genes = Array.isArray(genesPayload.genes) ? genesPayload.genes : [];
  if (genes.length === 0) {
    throw new Error(`No genes found at ${genesPath}`);
  }

  const signals = gatherSignals(options.repo, options.target);
  const candidates = evaluateGenes(signals, genes);
  let selected = candidates[0] ?? null;
  if (options.mutation) {
    const forced = candidates.find((entry) => entry.id === options.mutation);
    if (!forced) {
      throw new Error(`Requested mutation '${options.mutation}' is not applicable to current signals.`);
    }
    selected = forced;
  }

  const rollbackStack = [];
  let applyResult = { note: "Review mode; no mutation applied.", changedFiles: [] };
  let validations = [];
  let status = "review";

  if (options.apply && selected) {
    applyResult = applyGene(selected, signals, rollbackStack);
    status = "applied";
    const checks = applyResult.validations ?? [];
    validations = checks.map((check) => runCommand(check.command, check.cwd ?? signals.repoRoot, true));
    const failed = validations.find((entry) => entry.code !== 0);
    if (failed) {
      status = "failed";
      if (options.rollbackOnFailure) {
        rollback(rollbackStack);
        applyResult.note = `${applyResult.note} Rolled back due to failed validation.`;
      }
    } else {
      status = "success";
    }
  }

  const timestamp = new Date().toISOString();
  const event = {
    id: `evt_${Date.now()}_${hashText(`${Math.random()}:${signals.target}`)}`,
    runId: `run_${Date.now()}_${hashText(`${signals.repoRoot}:${signals.target}`)}`,
    timestamp,
    mode: options.apply ? "apply" : "review",
    status,
    repoRoot: signals.repoRoot,
    target: signals.target,
    selectedGeneId: selected ? selected.id : null,
    candidateSummary: candidates.slice(0, 10).map((entry) => ({
      id: entry.id,
      score: entry.score,
      reason: entry.reason
    })),
    changedFiles: (applyResult.changedFiles ?? []).map((filePath) => path.relative(signals.repoRoot, filePath)),
    validations: validations.map((entry) => ({
      command: entry.command,
      code: entry.code
    })),
    signals: {
      changes: signals.changes.length,
      todos: signals.todos.length,
      hasE2ESmokeNpmScript: signals.hasE2ESmokeNpmScript,
      hasE2ESmokeScriptFile: signals.hasE2ESmokeScriptFile,
      corsOrigins: signals.corsOrigins,
      hasWildcardCors: signals.hasWildcardCors,
      hasDbHealthCheck: signals.hasDbHealthCheck
    }
  };

  const report = formatReport({
    event,
    selected,
    candidates,
    applyResult,
    validations
  });
  writeEventAndCapsules(skillRoot, event, report, selected, validations);

  console.log(`[capability-evolver] mode=${event.mode} status=${event.status}`);
  if (selected) {
    console.log(`[capability-evolver] selected=${selected.id} score=${selected.score}`);
  }
  console.log(`[capability-evolver] report=${path.join(skillRoot, "memory", "reports", "latest.md")}`);
  console.log(`[capability-evolver] events=${path.join(skillRoot, "assets", "gep", "events.jsonl")}`);

  return { ok: status !== "failed", event };
};
