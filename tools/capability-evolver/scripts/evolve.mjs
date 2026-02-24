import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CORS_HARDENED_VALUE = "https://users.pajamadot.com,http://127.0.0.1:8787";
const ALLOWED_STRATEGIES = new Set(["balanced", "innovate", "harden", "repair-only"]);

const sanitizeStrategy = (raw) => {
  const value = (raw ?? "").trim().toLowerCase();
  if (!value) return "balanced";
  return ALLOWED_STRATEGIES.has(value) ? value : "balanced";
};

const parseArgs = (argv) => {
  const options = {
    repo: process.cwd(),
    target: "src",
    apply: false,
    review: false,
    mutation: null,
    rollbackOnFailure: true,
    strategy: sanitizeStrategy(process.env.EVOLVE_STRATEGY ?? "balanced")
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
    if (arg === "--strategy" && argv[index + 1]) {
      options.strategy = sanitizeStrategy(argv[index + 1]);
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
  const rateLimitMiddlewarePath = path.join(absoluteRepo, "src", "middleware", "rate-limit.ts");
  const rateLimitMigrationPath = path.join(absoluteRepo, "migrations", "0003_rate_limits.sql");

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
    rateLimitMiddlewarePath,
    rateLimitMigrationPath,
    changes,
    todos,
    hasTypecheckScript: typeof scripts.typecheck === "string",
    hasDeployScript: typeof scripts.deploy === "string",
    hasE2ESmokeNpmScript: typeof scripts["e2e:smoke"] === "string",
    hasE2ESmokeScriptFile: fs.existsSync(e2eScriptPath),
    hasAuthRateLimitMiddleware: fs.existsSync(rateLimitMiddlewarePath) && indexText.includes("createAuthRateLimitMiddleware"),
    hasRateLimitMigration: fs.existsSync(rateLimitMigrationPath),
    corsOrigins,
    hasWildcardCors,
    hasDbHealthCheck: indexText.includes("SELECT 1 AS ok")
  };
};

const candidate = (genesById, id, score, reason) => {
  const gene = genesById[id];
  if (!gene) return null;
  return { id, baseScore: score, score, reason, gene };
};

const STRATEGY_BONUS_BY_INTENT = {
  balanced: {
    repair: 6,
    harden: 6,
    optimize: 4,
    innovate: 4,
    validate: 1
  },
  innovate: {
    innovate: 20,
    optimize: 10,
    repair: 2,
    harden: -3,
    validate: -6
  },
  harden: {
    harden: 20,
    repair: 10,
    validate: 6,
    optimize: 2,
    innovate: -2
  },
  "repair-only": {
    repair: 20,
    harden: 8,
    validate: 4,
    optimize: -4,
    innovate: -10
  }
};

const applyStrategyBias = (entry, strategy) => {
  const strategyMap = STRATEGY_BONUS_BY_INTENT[strategy] ?? STRATEGY_BONUS_BY_INTENT.balanced;
  const intent = typeof entry.gene?.intent === "string" ? entry.gene.intent : "repair";
  const bonus = strategyMap[intent] ?? 0;
  return {
    ...entry,
    strategy,
    strategyBonus: bonus,
    score: entry.baseScore + bonus
  };
};

const evaluateGenes = (signals, genes, strategy) => {
  const genesById = Object.fromEntries(genes.map((gene) => [gene.id, gene]));
  const candidates = [];

  if (!signals.hasAuthRateLimitMiddleware || !signals.hasRateLimitMigration) {
    candidates.push(
      candidate(
        genesById,
        "add-auth-rate-limit-middleware",
        98,
        "Auth endpoints should enforce D1-backed rate limiting for abuse resistance."
      )
    );
  }

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

  if (signals.hasE2ESmokeNpmScript && signals.hasE2ESmokeScriptFile) {
    candidates.push(
      candidate(genesById, "run-e2e-smoke", 72, "E2E smoke should stay green for release confidence.")
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

  return candidates
    .filter(Boolean)
    .map((entry) => applyStrategyBias(entry, strategy))
    .sort((left, right) => right.score - left.score);
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

const replaceOrThrow = (filePath, rollbackStack, searchValue, replacementValue) => {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Cannot patch missing file: ${filePath}`);
  }
  const before = fs.readFileSync(filePath, "utf8");
  if (!before.includes(searchValue)) {
    throw new Error(`Patch anchor not found in ${filePath}`);
  }
  const after = before.replace(searchValue, replacementValue);
  if (after === before) {
    return false;
  }
  backupFile(rollbackStack, filePath);
  fs.writeFileSync(filePath, after, "utf8");
  return true;
};

const addAuthRateLimitMiddlewareGene = (signals, rollbackStack) => {
  const changedFiles = [];
  const migrationContent = `CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,
  window_start TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (key, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_updated_at ON rate_limits(updated_at);
`;

  if (!signals.hasRateLimitMigration) {
    backupFile(rollbackStack, signals.rateLimitMigrationPath);
    fs.writeFileSync(signals.rateLimitMigrationPath, migrationContent, "utf8");
    changedFiles.push(signals.rateLimitMigrationPath);
  }

  const middlewareContent = `import type { Context, Next } from "hono";
import type { EnvBindings } from "../types";
import { getAuthRateLimitSettings } from "../lib/config";
import { readRequestIp } from "../lib/auth";

const buildWindowStartIso = (nowMs: number, windowSeconds: number): string => {
  const epochSeconds = Math.floor(nowMs / 1000);
  const windowStart = Math.floor(epochSeconds / windowSeconds) * windowSeconds;
  return new Date(windowStart * 1000).toISOString();
};

const buildResetUnix = (nowMs: number, windowSeconds: number): number => {
  const epochSeconds = Math.floor(nowMs / 1000);
  const resetAt = Math.floor(epochSeconds / windowSeconds) * windowSeconds + windowSeconds;
  return resetAt;
};

const consume = async (env: EnvBindings, key: string, windowStart: string, now: string): Promise<number> => {
  await env.DB.prepare(
    \`INSERT INTO rate_limits (key, window_start, count, updated_at)
     VALUES (?, ?, 1, ?)
     ON CONFLICT(key, window_start) DO UPDATE SET
       count = count + 1,
       updated_at = excluded.updated_at\`
  )
    .bind(key, windowStart, now)
    .run();

  const row = await env.DB.prepare(
    \`SELECT count
     FROM rate_limits
     WHERE key = ? AND window_start = ?\`
  )
    .bind(key, windowStart)
    .first<{ count: number }>();
  return row?.count ?? 0;
};

const maybeCleanup = async (env: EnvBindings, nowMs: number, windowSeconds: number): Promise<void> => {
  if (Math.random() > 0.01) {
    return;
  }
  const cutoffMs = nowMs - windowSeconds * 1000 * 12;
  const cutoffIso = new Date(cutoffMs).toISOString();
  await env.DB.prepare("DELETE FROM rate_limits WHERE updated_at < ?").bind(cutoffIso).run();
};

export const createAuthRateLimitMiddleware = (bucket = "auth") =>
  async (context: Context<{ Bindings: EnvBindings }>, next: Next) => {
    const settings = getAuthRateLimitSettings(context.env);
    if (!settings.enabled) {
      await next();
      return;
    }

    const nowMs = Date.now();
    const nowIso = new Date(nowMs).toISOString();
    const windowStart = buildWindowStartIso(nowMs, settings.windowSeconds);
    const ip = readRequestIp(context.req.raw) ?? "unknown";
    const key = \`\${bucket}:\${ip}\`;

    let count = 0;
    try {
      count = await consume(context.env, key, windowStart, nowIso);
      await maybeCleanup(context.env, nowMs, settings.windowSeconds);
    } catch (error) {
      console.error(\`[rate_limit] fail-open key=\${key} error=\${error instanceof Error ? error.message : String(error)}\`);
      await next();
      return;
    }

    const remaining = Math.max(settings.maxRequests - count, 0);
    context.header("x-ratelimit-limit", String(settings.maxRequests));
    context.header("x-ratelimit-remaining", String(remaining));
    context.header("x-ratelimit-reset", String(buildResetUnix(nowMs, settings.windowSeconds)));

    if (count > settings.maxRequests) {
      context.header("retry-after", String(settings.windowSeconds));
      return context.json(
        {
          error: {
            code: "RATE_LIMITED",
            message: "Too many requests. Please retry later."
          }
        },
        429
      );
    }

    await next();
  };
`;

  if (!signals.hasAuthRateLimitMiddleware) {
    backupFile(rollbackStack, signals.rateLimitMiddlewarePath);
    fs.writeFileSync(signals.rateLimitMiddlewarePath, middlewareContent, "utf8");
    changedFiles.push(signals.rateLimitMiddlewarePath);
  }

  const typesPath = path.join(signals.repoRoot, "src", "types.ts");
  if (
    replaceOrThrow(
      typesPath,
      rollbackStack,
      `  PASSWORD_RESET_TTL_SECONDS?: string;
  COOKIE_NAME?: string;`,
      `  PASSWORD_RESET_TTL_SECONDS?: string;
  AUTH_RATE_LIMIT_ENABLED?: string;
  AUTH_RATE_LIMIT_MAX_REQUESTS?: string;
  AUTH_RATE_LIMIT_WINDOW_SECONDS?: string;
  COOKIE_NAME?: string;`
    )
  ) {
    changedFiles.push(typesPath);
  }

  const configPath = path.join(signals.repoRoot, "src", "lib", "config.ts");
  if (
    replaceOrThrow(
      configPath,
      rollbackStack,
      `const parsePositiveInt = (value: string | undefined, fallback: number): number => {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
};`,
      `const parsePositiveInt = (value: string | undefined, fallback: number): number => {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
};

const parseBoolean = (value: string | undefined, fallback: boolean): boolean => {
  if (!value) {
    return fallback;
  }
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return fallback;
};`
    )
  ) {
    changedFiles.push(configPath);
  }

  if (
    replaceOrThrow(
      configPath,
      rollbackStack,
      `export const getPasswordResetTtlSeconds = (env: EnvBindings): number =>
  parsePositiveInt(env.PASSWORD_RESET_TTL_SECONDS, 15 * 60);

export const getCookieName = (env: EnvBindings): string => env.COOKIE_NAME?.trim() || "pj_auth_refresh";`,
      `export const getPasswordResetTtlSeconds = (env: EnvBindings): number =>
  parsePositiveInt(env.PASSWORD_RESET_TTL_SECONDS, 15 * 60);

export const getAuthRateLimitSettings = (
  env: EnvBindings
): {
  enabled: boolean;
  maxRequests: number;
  windowSeconds: number;
} => ({
  enabled: parseBoolean(env.AUTH_RATE_LIMIT_ENABLED, true),
  maxRequests: parsePositiveInt(env.AUTH_RATE_LIMIT_MAX_REQUESTS, 120),
  windowSeconds: parsePositiveInt(env.AUTH_RATE_LIMIT_WINDOW_SECONDS, 60)
});

export const getCookieName = (env: EnvBindings): string => env.COOKIE_NAME?.trim() || "pj_auth_refresh";`
    )
  ) {
    changedFiles.push(configPath);
  }

  const indexPath = path.join(signals.repoRoot, "src", "index.ts");
  if (
    replaceOrThrow(
      indexPath,
      rollbackStack,
      `import { applyApiCors } from "./middleware/cors";`,
      `import { applyApiCors } from "./middleware/cors";
import { createAuthRateLimitMiddleware } from "./middleware/rate-limit";`
    )
  ) {
    changedFiles.push(indexPath);
  }

  if (
    replaceOrThrow(
      indexPath,
      rollbackStack,
      `app.use("/v1/*", applyApiCors);`,
      `app.use("/v1/*", applyApiCors);

const authRateLimit = createAuthRateLimitMiddleware();

app.use("/v1/auth/*", authRateLimit);
app.use("/v1/oauth/*", authRateLimit);`
    )
  ) {
    changedFiles.push(indexPath);
  }

  const wranglerPath = path.join(signals.repoRoot, "wrangler.toml");
  if (
    replaceOrThrow(
      wranglerPath,
      rollbackStack,
      `PASSWORD_RESET_TTL_SECONDS = "900"
COOKIE_NAME = "pj_auth_refresh"`,
      `PASSWORD_RESET_TTL_SECONDS = "900"
AUTH_RATE_LIMIT_ENABLED = "true"
AUTH_RATE_LIMIT_MAX_REQUESTS = "120"
AUTH_RATE_LIMIT_WINDOW_SECONDS = "60"
COOKIE_NAME = "pj_auth_refresh"`
    )
  ) {
    changedFiles.push(wranglerPath);
  }

  const devVarsPath = path.join(signals.repoRoot, ".dev.vars.example");
  if (
    replaceOrThrow(
      devVarsPath,
      rollbackStack,
      `PASSWORD_RESET_TTL_SECONDS="900"
EXPOSE_TEST_TOKENS="true"`,
      `PASSWORD_RESET_TTL_SECONDS="900"
AUTH_RATE_LIMIT_ENABLED="true"
AUTH_RATE_LIMIT_MAX_REQUESTS="120"
AUTH_RATE_LIMIT_WINDOW_SECONDS="60"
EXPOSE_TEST_TOKENS="true"`
    )
  ) {
    changedFiles.push(devVarsPath);
  }

  const roadmapPath = path.join(signals.repoRoot, "ROADMAP.md");
  if (
    replaceOrThrow(
      roadmapPath,
      rollbackStack,
      `- [ ] Auth endpoint rate-limiting and abuse protection.`,
      `- [x] Auth endpoint rate-limiting and abuse protection (D1 fixed-window).`
    )
  ) {
    changedFiles.push(roadmapPath);
  }

  const readmePath = path.join(signals.repoRoot, "README.md");
  if (
    replaceOrThrow(
      readmePath,
      rollbackStack,
      `- DB-backed health check and explicit CORS allowlist support.`,
      `- DB-backed health check and explicit CORS allowlist support.
- D1-backed auth rate limiting for \`/v1/auth/*\` and \`/v1/oauth/*\`.`
    )
  ) {
    changedFiles.push(readmePath);
  }

  if (
    replaceOrThrow(
      readmePath,
      rollbackStack,
      `- \`migrations/0002_verification_indexes.sql\`: token/session indexes.`,
      `- \`migrations/0002_verification_indexes.sql\`: token/session indexes.
- \`migrations/0003_rate_limits.sql\`: D1 fixed-window rate-limit store.`
    )
  ) {
    changedFiles.push(readmePath);
  }

  return {
    note:
      changedFiles.length > 0
        ? "Added D1-backed auth rate-limiting middleware, env config, and migration."
        : "Skipped: auth rate-limiting already configured.",
    changedFiles,
    validations: [
      { command: "npm run typecheck", cwd: signals.repoRoot },
      { command: "npx wrangler deploy --dry-run", cwd: signals.repoRoot }
    ]
  };
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

const runE2ESmokeGene = (signals) => ({
  note: "Running end-to-end smoke validation.",
  changedFiles: [],
  validations: [{ command: "npm run e2e:smoke", cwd: signals.repoRoot }]
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
    case "add-auth-rate-limit-middleware":
      return addAuthRateLimitMiddlewareGene(signals, rollbackStack);
    case "add-e2e-smoke-script":
      return addE2ESmokeScript(signals, rollbackStack);
    case "tighten-cors-allowlist":
      return tightenCorsAllowlist(signals, rollbackStack);
    case "run-typecheck":
      return runTypecheckGene(signals);
    case "run-e2e-smoke":
      return runE2ESmokeGene(signals);
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
    `- Strategy: ${event.strategy}`,
    `- Status: **${event.status}**`,
    `- Selected Gene: \`${selected ? selected.id : "none"}\``,
    "",
    "## Top Candidates",
    ...candidates
      .slice(0, 8)
      .map(
        (entry) =>
          `- \`${entry.id}\` [${entry.gene?.intent ?? "unknown"}] (score ${entry.score}, base ${entry.baseScore}, bonus ${entry.strategyBonus ?? 0}): ${entry.reason}`
      ),
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
  const candidates = evaluateGenes(signals, genes, options.strategy);
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
    strategy: options.strategy,
    status,
    repoRoot: signals.repoRoot,
    target: signals.target,
    selectedGeneId: selected ? selected.id : null,
    candidateSummary: candidates.slice(0, 10).map((entry) => ({
      id: entry.id,
      intent: entry.gene?.intent ?? "unknown",
      baseScore: entry.baseScore,
      strategyBonus: entry.strategyBonus ?? 0,
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
      hasAuthRateLimitMiddleware: signals.hasAuthRateLimitMiddleware,
      hasRateLimitMigration: signals.hasRateLimitMigration,
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
