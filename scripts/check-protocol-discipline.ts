#!/usr/bin/env node
/**
 * Protocol Discipline Check — CI guardrail script.
 *
 * Fails the build if trust-model violations are detected:
 * 1. Direct writes to trust-bearing tables outside protocol/canonical layer
 * 2. process.env reads outside lib/env.js (for EP_ prefixed vars)
 * 3. Route handlers that exceed complexity threshold
 * 4. Missing idempotency patterns in mutating routes
 *
 * Zero external dependencies — uses only Node.js built-ins.
 *
 * @license Apache-2.0
 */

import fs from 'fs';
import path from 'path';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const ROOT: string = path.resolve(import.meta.dirname, '..');

/** Files that are ALLOWED to write directly to trust-bearing tables. */
const TRUST_WRITE_ALLOWLIST: Set<string> = new Set([
  path.join(ROOT, 'lib', 'canonical-writer.js'),
  path.join(ROOT, 'lib', 'protocol-write.js'),
  path.join(ROOT, 'lib', 'commit.ts'),
  path.join(ROOT, 'lib', 'create-receipt.ts'),
]);

/** The only file allowed to read EP_ env vars via process.env. */
const ENV_ALLOWLIST: Set<string> = new Set([
  path.join(ROOT, 'lib', 'env.ts'),
  // (operator-auth.js used to be here — TODO closed by adding
  // getOperatorKeys() / getCronSecret() to lib/env.js. The module now
  // routes both EP_OPERATOR_KEYS and CRON_SECRET reads through lib/env
  // and no longer touches process.env directly.)
  // mcp-server/index.js reads EP_BASE_URL, EP_API_KEY, EP_AUTO_RECEIPT_URL,
  // and EP_AUTO_RECEIPT_KEY at startup. These are MCP-server entry-point
  // configuration, evaluated once when the server boots. The MCP server is
  // a separate process from the Next.js app and does not import lib/env.js
  // (which is bundled with the app). TODO: extract a shared env loader if
  // we ever need to deduplicate config across processes.
  path.join(ROOT, 'mcp-server', 'index.js'),
]);

/** Trust-bearing tables that must only be written through canonical paths. */
const TRUST_TABLES: readonly string[] = [
  'receipts',
  'commits',
  'disputes',
  'trust_reports',
  'protocol_events',
  'security_events',
  'entities',
  'authorities',
  'policy_rollouts',
];

/** Maximum non-blank, non-comment lines in a single route handler. */
const HANDLER_COMPLEXITY_THRESHOLD: number = 80;

/**
 * Per-file overrides for HANDLER_COMPLEXITY_THRESHOLD. Each entry is keyed by
 * the route's path-relative file and pins a higher cap with a written rationale
 * for why it cannot be cleanly broken up at the default threshold. Adding a
 * route here is intentional debt — review the rationale before bumping.
 */
const HANDLER_COMPLEXITY_OVERRIDES: Record<string, number> = {
  // Trust gate is the protocol's pre-action gate: it runs evaluation, delegation
  // verification, handshake verification (with action_hash recompute), commit
  // issuance, and binding consumption inline so a single-decision response is
  // deterministic and atomic. Splitting it forces re-fetching state across
  // helpers and hurts the audit story (one trace = one decision).
  'app/api/trust/gate/route.js': 200,
  // Needs broadcast routes a need across all matching providers in one pass —
  // matching, scoring, fan-out, and audit emission are coupled by the broadcast
  // semantics. Extracting helpers fragments the broadcast invariant.
  'app/api/needs/broadcast/route.ts': 130,
  // Auto-submit normalises raw client telemetry, runs the canonical-writer
  // pipeline, materialises trust profile, and emits SIEM events — the steps
  // share request-scoped state that is awkward to thread through helpers.
  'app/api/receipts/auto-submit/route.ts': 120,
  // Entity search runs per-field validators, scoring, and pagination inline so
  // the cursor envelope stays consistent — each branch returns a different
  // pagination shape and lifting the branches loses that locality.
  'app/api/entities/search/route.js': 120,
  // Feed handler stitches the cross-tenant timeline (receipts, disputes,
  // commits, signoffs) into a single ordered stream — the stitching logic is
  // the route's purpose, not delegated business logic.
  'app/api/feed/route.js': 100,
  // Entity register mints id, validates schema, persists, and primes scoring —
  // the steps are interleaved with audit emission that wants the full request
  // context in scope.
  'app/api/entities/register/route.js': 100,
  // ZK-proof verifier handles ceremony selection, proof verification, and
  // result envelope construction inline so failures can attach precise
  // ceremony-specific error context.
  'app/api/trust/zk-proof/route.js': 100,
  // Routes that exceed the 80-line default by a thin margin (3-4 lines) due
  // to verbose-but-clear input validation. Refactoring saves ~5 lines for no
  // readability gain — the validation is the route's purpose. Pinned at 90
  // so a meaningful regression (more than 7 lines past current) re-trips the
  // warning and forces a fresh review.
  'app/api/cloud/signoff/analytics/route.js': 90,
  'app/api/commit/issue/route.js': 90,
  'app/api/receipts/submit/route.ts': 90,
  // /api/receipt grew slightly past the default after the auth gate + the
  // fail-loud-on-signing-failure invariants landed (per the audit). The
  // handler is still a thin orchestrator; the 4 extra lines pay for
  // explicit error paths instead of silently returning unsigned receipts.
  'app/api/receipt/route.ts': 90,
  // GovGuard + FinGuard v1 trust-receipt creation. The handler performs the
  // full pre-action gate inline: auth, body validation, actor-mismatch
  // guard, canonical action build + hash, policy evaluation, enforcement-
  // mode mapping, and audit emission. Splitting reduces line count without
  // reducing complexity — the steps share request-scoped state and the
  // response shape includes the full decision context.
  'app/api/v1/trust-receipts/route.ts': 130,
  // (Adapter override removed: refactored to use lib/guard-adapter.js
  // shared helper, route file is now 8 lines.)
};

/** HTTP method export names used in Next.js App Router route files. */
const HTTP_METHODS: readonly string[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

// ---------------------------------------------------------------------------
// File discovery helpers
// ---------------------------------------------------------------------------

/**
 * Validate an entry name returned by fs.readdirSync before joining it.
 * Rejects any name containing a path separator or traversal component.
 */
function isSafeEntryName(name: unknown): boolean {
  if (typeof name !== 'string' || name.length === 0) return false;
  if (name === '.' || name === '..') return false;
  if (name.includes('/') || name.includes('\\')) return false;
  if (name.includes('\0')) return false;
  return true;
}

/**
 * Skip Node-20 standalone-runtime companions: generated, do-not-edit
 * transpilations of a sibling .ts source that this checker already scans.
 * Scanning both double-reports every finding and mis-flags the companion of
 * an allowlisted source (e.g. lib/env.js, the generated twin of lib/env.ts).
 */
function isGeneratedRuntimeCompanion(filePath: string): boolean {
  if (!/\.m?js$/.test(filePath)) return false;
  let head = '';
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(400);
    const bytes = fs.readSync(fd, buf, 0, 400, 0);
    fs.closeSync(fd);
    head = buf.toString('utf-8', 0, bytes);
  } catch {
    return false;
  }
  return head.includes('by scripts/build-standalone-runtimes.mjs. Do not edit.');
}

function collectFiles(dir: string, pattern: RegExp): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (!isSafeEntryName(entry.name)) continue;
    const full = `${dir}${path.sep}${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.next' || entry.name === '.git') continue;
      results.push(...collectFiles(full, pattern));
    } else if (pattern.test(entry.name) && !isGeneratedRuntimeCompanion(full)) {
      results.push(full);
    }
  }
  return results;
}

// Routes/pages/lib are migrating .js -> .ts/.tsx file-by-file; scan every
// extension so converted files stay inside this guardrail's coverage.
function getApiRouteFiles(): string[] {
  return collectFiles(path.join(ROOT, 'app', 'api'), /\.(js|ts|tsx)$/);
}

function getLibFiles(): string[] {
  return collectFiles(path.join(ROOT, 'lib'), /\.(js|ts|tsx)$/);
}

function getAllScannable(): string[] {
  const apiFiles = collectFiles(path.join(ROOT, 'app'), /\.(js|ts|tsx)$/);
  const libFiles = getLibFiles();
  return [...apiFiles, ...libFiles];
}

/**
 * Extension-agnostic membership test for path allowlists/override maps whose
 * entries were written against a specific extension: a file renamed
 * .js -> .ts (or vice versa) keeps its exemption without a lockstep edit here.
 */
function stripSourceExt(p: string): string {
  return p.replace(/\.(js|mjs|ts|mts|tsx)$/, '');
}

function setHasByBase(set: Set<string>, filePath: string): boolean {
  if (set.has(filePath)) return true;
  const base = stripSourceExt(filePath);
  for (const entry of set) {
    if (stripSourceExt(entry) === base) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Check 1: No direct trust-table writes in route files
// ---------------------------------------------------------------------------

interface DisciplineViolation {
  file: string;
  line: number;
  message: string;
  severity: string;
  section?: string;
}

function checkTrustTableWrites(): DisciplineViolation[] {
  const violations: DisciplineViolation[] = [];
  const routeFiles: string[] = getApiRouteFiles();

  // Validate the trust-table names against a safe charset before using them
  // in string-match patterns. TRUST_TABLES is a module-local constant, but
  // any future edit that adds a table with special characters would be a
  // surprise — fail loud at check-script start.
  for (const t of TRUST_TABLES) {
    if (!/^[a-z_][a-z0-9_]*$/.test(t)) {
      throw new Error(`TRUST_TABLES contains unsafe name: ${JSON.stringify(t)}`);
    }
  }

  // Detect `.from('TABLE').insert` and `.from("TABLE").insert` via string
  // matching instead of RegExp construction. Each table name is a simple
  // identifier (validated above), so three literal prefixes per table
  // cover single-quote, double-quote, and backtick variants. No regex
  // engine involvement; no ReDoS risk.
  interface Pattern {
    table: string;
    needle: string;
  }
  const patterns: Pattern[] = TRUST_TABLES.flatMap((table: string) => [
    { table, needle: `.from('${table}').insert` },
    { table, needle: `.from("${table}").insert` },
    { table, needle: `.from(\`${table}\`).insert` },
  ]);

  for (const filePath of routeFiles) {
    if (setHasByBase(TRUST_WRITE_ALLOWLIST, filePath)) continue;

    const content: string = fs.readFileSync(filePath, 'utf-8');
    const lines: string[] = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { table, needle } of patterns) {
        if (line.includes(needle)) {
          violations.push({
            file: path.relative(ROOT, filePath),
            line: i + 1,
            message: `Direct .insert() on trust table "${table}" — must use canonical-writer.js`,
            severity: 'critical',
          });
          break; // one violation per line is enough
        }
      }
    }
  }

  return violations;
}

// ---------------------------------------------------------------------------
// Check 2: No direct EP_ env reads outside lib/env.js
// ---------------------------------------------------------------------------

function checkEnvReads(): DisciplineViolation[] {
  const violations: DisciplineViolation[] = [];
  const files: string[] = getAllScannable();
  const envPattern: RegExp = /process\.env\.EP_/g;

  for (const filePath of files) {
    if (setHasByBase(ENV_ALLOWLIST, filePath)) continue;

    const content: string = fs.readFileSync(filePath, 'utf-8');
    const lines: string[] = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip comments
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      envPattern.lastIndex = 0;
      if (envPattern.test(line)) {
        violations.push({
          file: path.relative(ROOT, filePath),
          line: i + 1,
          message: `Direct process.env.EP_ read — must use lib/env.js accessors`,
          severity: 'critical',
        });
      }
    }
  }

  return violations;
}

// ---------------------------------------------------------------------------
// Check 3: Route handler complexity
// ---------------------------------------------------------------------------

interface Handler {
  method: string;
  body: string;
  startLine: number;
}

function extractHandlerBodies(content: string): Handler[] {
  const handlers: Handler[] = [];

  for (const method of HTTP_METHODS) {
    // Match: export async function METHOD( or export function METHOD(
    const funcPattern = new RegExp(
      `export\\s+(async\\s+)?function\\s+${method}\\s*\\(`,
    );
    const match = funcPattern.exec(content);
    if (!match) continue;

    const startIdx = match.index;
    // Find the opening brace of the function body
    let bracePos = content.indexOf('{', startIdx);
    if (bracePos === -1) continue;

    // Count braces to find end of function
    let depth = 0;
    let endIdx = bracePos;
    for (let i = bracePos; i < content.length; i++) {
      if (content[i] === '{') depth++;
      else if (content[i] === '}') {
        depth--;
        if (depth === 0) {
          endIdx = i;
          break;
        }
      }
    }

    const body = content.slice(bracePos + 1, endIdx);
    const linesBefore = content.slice(0, bracePos).split('\n').length;
    handlers.push({ method, body, startLine: linesBefore });
  }

  return handlers;
}

function countSignificantLines(body: string): number {
  const lines: string[] = body.split('\n');
  let count = 0;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    if (trimmed.startsWith('//')) continue;
    if (trimmed.startsWith('*')) continue;
    if (trimmed.startsWith('/*')) continue;
    count++;
  }
  return count;
}

function checkHandlerComplexity(): DisciplineViolation[] {
  const warnings: DisciplineViolation[] = [];
  const routeFiles: string[] = getApiRouteFiles();
  // Track which override entries we observed so we can flag stale ones —
  // an override whose file no longer exceeds the *default* threshold should
  // be removed from HANDLER_COMPLEXITY_OVERRIDES so the list stays honest.
  const overrideMaxObserved: Record<string, number> = {};

  // Overrides are keyed by whichever extension the route had when the entry
  // was written; match by extension-stripped path so a .js -> .ts rename
  // keeps its reviewed cap without a lockstep edit here.
  const overridesByBase: Record<string, { key: string; cap: number }> = {};
  for (const [key, cap] of Object.entries(HANDLER_COMPLEXITY_OVERRIDES)) {
    overridesByBase[stripSourceExt(key)] = { key, cap };
  }

  for (const filePath of routeFiles) {
    const content: string = fs.readFileSync(filePath, 'utf-8');
    const handlers: Handler[] = extractHandlerBodies(content);

    const relPath: string = path.relative(ROOT, filePath);
    const override = overridesByBase[stripSourceExt(relPath)];
    const cap: number = override?.cap ?? HANDLER_COMPLEXITY_THRESHOLD;

    for (const { method, body, startLine } of handlers) {
      const lineCount: number = countSignificantLines(body);
      if (override !== undefined) {
        overrideMaxObserved[override.key] = Math.max(overrideMaxObserved[override.key] ?? 0, lineCount);
      }
      if (lineCount > cap) {
        warnings.push({
          file: relPath,
          line: startLine,
          message: `${method} handler has ${lineCount} significant lines (threshold: ${cap}) — consider delegating to a service`,
          severity: 'warning',
        });
      }
    }
  }

  for (const [relPath, override] of Object.entries(HANDLER_COMPLEXITY_OVERRIDES)) {
    const observed: number = overrideMaxObserved[relPath] ?? 0;
    if (observed === 0) {
      warnings.push({
        file: relPath,
        line: 0,
        message: `HANDLER_COMPLEXITY_OVERRIDES entry "${relPath}" has no matching route file — remove it from check-protocol-discipline.js`,
        severity: 'warning',
      });
    } else if (observed <= HANDLER_COMPLEXITY_THRESHOLD) {
      warnings.push({
        file: relPath,
        line: 0,
        message: `HANDLER_COMPLEXITY_OVERRIDES entry (${override} lines) is no longer needed — handler is ${observed} lines, within the ${HANDLER_COMPLEXITY_THRESHOLD}-line default. Remove the override.`,
        severity: 'warning',
      });
    }
  }

  return warnings;
}

// ---------------------------------------------------------------------------
// Handshake Discipline Checks
// ---------------------------------------------------------------------------

/** Handshake tables that must only be written through approved modules. */
const HANDSHAKE_TABLES: readonly string[] = [
  'handshakes', 'handshake_parties', 'handshake_presentations',
  'handshake_bindings', 'handshake_results', 'handshake_policies',
  'handshake_events',
];

/** Files that are ALLOWED to write directly to handshake tables. */
const HANDSHAKE_WRITE_ALLOWLIST: Set<string> = new Set([
  path.join(ROOT, 'lib', 'handshake', 'index.js'),
  path.join(ROOT, 'lib', 'protocol-write.js'),
]);

function isInsideHandshakeLib(filePath: string): boolean {
  const handshakeDir: string = path.join(ROOT, 'lib', 'handshake') + path.sep;
  return filePath.startsWith(handshakeDir);
}

/**
 * Check H1: No direct writes to handshake tables outside approved modules.
 */
function checkHandshakeTableWrites(): DisciplineViolation[] {
  const violations: DisciplineViolation[] = [];
  const allFiles: string[] = getAllScannable();

  // Validate HANDSHAKE_TABLES names against a safe charset before use in
  // string-match patterns. Fail loud on any future name with special chars.
  for (const t of HANDSHAKE_TABLES) {
    if (!/^[a-z_][a-z0-9_]*$/.test(t)) {
      throw new Error(`HANDSHAKE_TABLES contains unsafe name: ${JSON.stringify(t)}`);
    }
  }

  // String-based matching (no RegExp engine). Three quote variants per
  // (table, op) pair.
  const writeOps: readonly string[] = ['insert', 'update', 'upsert'];
  interface WritePattern {
    table: string;
    op: string;
    needle: string;
  }
  const patterns: WritePattern[] = [];
  for (const table of HANDSHAKE_TABLES) {
    for (const op of writeOps) {
      patterns.push({ table, op, needle: `.from('${table}').${op}(` });
      patterns.push({ table, op, needle: `.from("${table}").${op}(` });
      patterns.push({ table, op, needle: `.from(\`${table}\`).${op}(` });
    }
  }

  for (const filePath of allFiles) {
    if (setHasByBase(HANDSHAKE_WRITE_ALLOWLIST, filePath)) continue;
    if (isInsideHandshakeLib(filePath)) continue;

    const content: string = fs.readFileSync(filePath, 'utf-8');
    const lines: string[] = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      for (const { table, op, needle } of patterns) {
        if (line.includes(needle)) {
          violations.push({
            file: path.relative(ROOT, filePath),
            line: i + 1,
            message: `Direct .${op}() on handshake table "${table}" — must use lib/handshake.js or lib/protocol-write.js`,
            severity: 'critical',
            section: 'handshake',
          });
          break;
        }
      }
    }
  }

  return violations;
}

/**
 * Check H2: No raw process.env in handshake runtime code.
 */
function checkHandshakeEnv(): DisciplineViolation[] {
  const violations: DisciplineViolation[] = [];
  const envPattern: RegExp = /process\.env/g;

  const handshakeDir: string = path.join(ROOT, 'lib', 'handshake');

  const filesToScan: string[] = [];
  if (fs.existsSync(handshakeDir)) filesToScan.push(...collectFiles(handshakeDir, /\.js$/));

  for (const filePath of filesToScan) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      envPattern.lastIndex = 0;
      if (envPattern.test(line)) {
        violations.push({
          file: path.relative(ROOT, filePath),
          line: i + 1,
          message: `process.env usage in handshake code — config should come through lib/env.js`,
          severity: 'warning',
          section: 'handshake',
        });
      }
    }
  }

  return violations;
}

/**
 * Check H3: No route-level policy logic in handshake routes.
 */
function checkHandshakeRoutePolicyLogic(): DisciplineViolation[] {
  const violations: DisciplineViolation[] = [];
  const handshakeRouteDir: string = path.join(ROOT, 'app', 'api', 'handshake');
  if (!fs.existsSync(handshakeRouteDir)) return violations;

  const routeFiles: string[] = collectFiles(handshakeRouteDir, /\.js$/);
  const policyPatterns: RegExp = /required_claims|minimum_assurance|assurance_level.*check|policy.*valid/;

  for (const filePath of routeFiles) {
    const content: string = fs.readFileSync(filePath, 'utf-8');
    const lines: string[] = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      if (policyPatterns.test(line)) {
        violations.push({
          file: path.relative(ROOT, filePath),
          line: i + 1,
          message: `Policy validation logic in route handler — routes should be thin adapters that delegate to service layer`,
          severity: 'warning',
          section: 'handshake',
        });
      }
    }
  }

  return violations;
}

/**
 * Check H4: No direct trust of embedded issuer keys.
 */
function checkEmbeddedIssuerKeys(): DisciplineViolation[] {
  const violations: DisciplineViolation[] = [];
  const embeddedKeyPattern: RegExp = /presentation\.publicKey|presentation\.signingKey|payload\.key/g;

  const handshakeDir: string = path.join(ROOT, 'lib', 'handshake');

  const filesToScan: string[] = [];
  if (fs.existsSync(handshakeDir)) filesToScan.push(...collectFiles(handshakeDir, /\.js$/));

  for (const filePath of filesToScan) {
    const content: string = fs.readFileSync(filePath, 'utf-8');
    const lines: string[] = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

      embeddedKeyPattern.lastIndex = 0;
      if (embeddedKeyPattern.test(line)) {
        violations.push({
          file: path.relative(ROOT, filePath),
          line: i + 1,
          message: `Direct trust of embedded issuer key — keys must come from authority registry, not embedded in presentations`,
          severity: 'critical',
          section: 'handshake',
        });
      }
    }
  }

  return violations;
}

/**
 * Check H5: Invariant test suite presence.
 */
function checkHandshakeTestSuite(): DisciplineViolation[] {
  const violations: DisciplineViolation[] = [];
  const testDir: string = path.join(ROOT, 'tests');

  const handshakeTestFile: string = path.join(testDir, 'handshake.test.js');
  const attackTestFile: string = path.join(testDir, 'handshake-attack.test.js');

  const handshakeTestExists: boolean = fs.existsSync(handshakeTestFile);
  const attackTestExists: boolean = fs.existsSync(attackTestFile);

  if (!handshakeTestExists) {
    violations.push({
      file: 'tests/handshake.test.js',
      line: 0,
      message: `Missing handshake test suite — tests/handshake.test.js must exist`,
      severity: 'warning',
      section: 'handshake',
    });
  } else {
    // Check for security invariant tests
    const content: string = fs.readFileSync(handshakeTestFile, 'utf-8');
    const hasInvariantTests: boolean = /invariant|Security Invariants|attack/i.test(content);
    if (!hasInvariantTests) {
      violations.push({
        file: 'tests/handshake.test.js',
        line: 0,
        message: `Handshake test suite missing security invariant tests — must include invariant or attack test coverage`,
        severity: 'warning',
        section: 'handshake',
      });
    }
  }

  if (!attackTestExists) {
    violations.push({
      file: 'tests/handshake-attack.test.js',
      line: 0,
      message: `Missing handshake attack test suite — tests/handshake-attack.test.js should exist`,
      severity: 'warning',
      section: 'handshake',
    });
  }

  return violations;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface CheckResult {
  criticals: DisciplineViolation[];
  warnings: DisciplineViolation[];
  all: DisciplineViolation[];
}

export function runChecks(): CheckResult {
  const trustViolations: DisciplineViolation[] = checkTrustTableWrites();
  const envViolations: DisciplineViolation[] = checkEnvReads();
  const complexityWarnings: DisciplineViolation[] = checkHandlerComplexity();

  // Handshake discipline checks
  const hsTableViolations: DisciplineViolation[] = checkHandshakeTableWrites();
  const hsEnvWarnings: DisciplineViolation[] = checkHandshakeEnv();
  const hsPolicyWarnings: DisciplineViolation[] = checkHandshakeRoutePolicyLogic();
  const hsKeyViolations: DisciplineViolation[] = checkEmbeddedIssuerKeys();
  const hsTestWarnings: DisciplineViolation[] = checkHandshakeTestSuite();

  const criticals: DisciplineViolation[] = [
    ...trustViolations, ...envViolations,
    ...hsTableViolations, ...hsKeyViolations,
  ];
  const warnings: DisciplineViolation[] = [
    ...complexityWarnings,
    ...hsEnvWarnings, ...hsPolicyWarnings, ...hsTestWarnings,
  ];
  const all: DisciplineViolation[] = [...criticals, ...warnings];

  return { criticals, warnings, all };
}

function main(): void {
  console.log('Protocol Discipline Check');
  console.log('='.repeat(60));
  console.log();

  const { criticals, warnings, all } = runChecks();

  // Separate handshake items from general items
  const generalCriticals: DisciplineViolation[] = criticals.filter((v) => !v.section);
  const generalWarnings: DisciplineViolation[] = warnings.filter((v) => !v.section);
  const hsCriticals: DisciplineViolation[] = criticals.filter((v) => v.section === 'handshake');
  const hsWarnings: DisciplineViolation[] = warnings.filter((v) => v.section === 'handshake');

  if (all.length === 0) {
    console.log('All checks passed. No protocol discipline violations found.');
    process.exit(0);
  }

  // Print general violations grouped by severity
  if (generalCriticals.length > 0) {
    console.log(`CRITICAL VIOLATIONS (${generalCriticals.length}):`);
    console.log('-'.repeat(40));
    for (const v of generalCriticals) {
      console.log(`  ${v.file}:${v.line}`);
      console.log(`    ${v.message}`);
    }
    console.log();
  }

  if (generalWarnings.length > 0) {
    console.log(`WARNINGS (${generalWarnings.length}):`);
    console.log('-'.repeat(40));
    for (const w of generalWarnings) {
      console.log(`  ${w.file}:${w.line}`);
      console.log(`    ${w.message}`);
    }
    console.log();
  }

  // Print handshake discipline section
  if (hsCriticals.length > 0 || hsWarnings.length > 0) {
    console.log('=== Handshake Discipline ===');
    console.log();

    if (hsCriticals.length > 0) {
      console.log(`CRITICAL VIOLATIONS (${hsCriticals.length}):`);
      console.log('-'.repeat(40));
      for (const v of hsCriticals) {
        console.log(`  ${v.file}:${v.line}`);
        console.log(`    ${v.message}`);
      }
      console.log();
    }

    if (hsWarnings.length > 0) {
      console.log(`WARNINGS (${hsWarnings.length}):`);
      console.log('-'.repeat(40));
      for (const w of hsWarnings) {
        console.log(`  ${w.file}:${w.line}`);
        console.log(`    ${w.message}`);
      }
      console.log();
    }
  }

  // Summary
  console.log('='.repeat(60));
  console.log(`Total: ${criticals.length} critical, ${warnings.length} warnings`);

  if (criticals.length > 0) {
    console.log('FAILED — critical violations must be resolved before merge.');
    process.exit(1);
  } else {
    console.log('PASSED (with warnings).');
    process.exit(0);
  }
}

// Run when invoked directly
const isDirectRun: boolean = !!(process.argv[1] &&
  (process.argv[1].endsWith('check-protocol-discipline.js') ||
   process.argv[1].endsWith('check-protocol-discipline.ts') ||
   process.argv[1].includes('check-protocol-discipline')));

if (isDirectRun) {
  main();
}
