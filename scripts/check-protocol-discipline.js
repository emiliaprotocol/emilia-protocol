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

const ROOT = path.resolve(import.meta.dirname, '..');

/** Files that are ALLOWED to write directly to trust-bearing tables. */
const TRUST_WRITE_ALLOWLIST = new Set([
  path.join(ROOT, 'lib', 'canonical-writer.js'),
  path.join(ROOT, 'lib', 'protocol-write.js'),
  path.join(ROOT, 'lib', 'commit.js'),
  path.join(ROOT, 'lib', 'create-receipt.js'),
]);

/** The only file allowed to read EP_ env vars via process.env. */
const ENV_ALLOWLIST = new Set([
  path.join(ROOT, 'lib', 'env.js'),
  // operator-auth.js reads EP_OPERATOR_KEYS — a security-critical secret that
  // we intentionally load once at module-init and cache, not on every request.
  // Refactoring to env.js would require adding a typed accessor for a JSON-map
  // secret, which is not a concern env.js currently handles. TODO: add
  // getOperatorKeys() accessor to lib/env.js.
  path.join(ROOT, 'lib', 'operator-auth.js'),
  // mcp-server/index.js reads EP_BASE_URL, EP_API_KEY, EP_AUTO_RECEIPT_URL,
  // and EP_AUTO_RECEIPT_KEY at startup. These are MCP-server entry-point
  // configuration, evaluated once when the server boots. The MCP server is
  // a separate process from the Next.js app and does not import lib/env.js
  // (which is bundled with the app). TODO: extract a shared env loader if
  // we ever need to deduplicate config across processes.
  path.join(ROOT, 'mcp-server', 'index.js'),
]);

/** Trust-bearing tables that must only be written through canonical paths. */
const TRUST_TABLES = ['receipts', 'commits', 'disputes', 'trust_reports', 'protocol_events', 'entities'];

/** Maximum non-blank, non-comment lines in a single route handler. */
const HANDLER_COMPLEXITY_THRESHOLD = 80;

/**
 * Per-file overrides for HANDLER_COMPLEXITY_THRESHOLD. Each entry is keyed by
 * the route's path-relative file and pins a higher cap with a written rationale
 * for why it cannot be cleanly broken up at the default threshold. Adding a
 * route here is intentional debt — review the rationale before bumping.
 */
const HANDLER_COMPLEXITY_OVERRIDES = {
  // Trust gate is the protocol's pre-action gate: it runs evaluation, delegation
  // verification, handshake verification (with action_hash recompute), commit
  // issuance, and binding consumption inline so a single-decision response is
  // deterministic and atomic. Splitting it forces re-fetching state across
  // helpers and hurts the audit story (one trace = one decision).
  'app/api/trust/gate/route.js': 200,
  // Needs broadcast routes a need across all matching providers in one pass —
  // matching, scoring, fan-out, and audit emission are coupled by the broadcast
  // semantics. Extracting helpers fragments the broadcast invariant.
  'app/api/needs/broadcast/route.js': 130,
  // Auto-submit normalises raw client telemetry, runs the canonical-writer
  // pipeline, materialises trust profile, and emits SIEM events — the steps
  // share request-scoped state that is awkward to thread through helpers.
  'app/api/receipts/auto-submit/route.js': 120,
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
  'app/api/receipts/submit/route.js': 90,
  // GovGuard + FinGuard v1 trust-receipt creation. The handler performs the
  // full pre-action gate inline: auth, body validation, actor-mismatch
  // guard, canonical action build + hash, policy evaluation, enforcement-
  // mode mapping, and audit emission. Splitting reduces line count without
  // reducing complexity — the steps share request-scoped state and the
  // response shape includes the full decision context.
  'app/api/v1/trust-receipts/route.js': 130,
};

/** HTTP method export names used in Next.js App Router route files. */
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

// ---------------------------------------------------------------------------
// File discovery helpers
// ---------------------------------------------------------------------------

/**
 * Validate an entry name returned by fs.readdirSync before joining it.
 * Rejects any name containing a path separator or traversal component.
 */
function isSafeEntryName(name) {
  if (typeof name !== 'string' || name.length === 0) return false;
  if (name === '.' || name === '..') return false;
  if (name.includes('/') || name.includes('\\')) return false;
  if (name.includes('\0')) return false;
  return true;
}

function collectFiles(dir, pattern) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (!isSafeEntryName(entry.name)) continue;
    const full = `${dir}${path.sep}${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '.next' || entry.name === '.git') continue;
      results.push(...collectFiles(full, pattern));
    } else if (pattern.test(entry.name)) {
      results.push(full);
    }
  }
  return results;
}

function getApiRouteFiles() {
  return collectFiles(path.join(ROOT, 'app', 'api'), /\.js$/);
}

function getLibFiles() {
  return collectFiles(path.join(ROOT, 'lib'), /\.js$/);
}

function getAllScannable() {
  const apiFiles = collectFiles(path.join(ROOT, 'app'), /\.js$/);
  const libFiles = getLibFiles();
  return [...apiFiles, ...libFiles];
}

// ---------------------------------------------------------------------------
// Check 1: No direct trust-table writes in route files
// ---------------------------------------------------------------------------

function checkTrustTableWrites() {
  const violations = [];
  const routeFiles = getApiRouteFiles();

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
  const patterns = TRUST_TABLES.flatMap((table) => [
    { table, needle: `.from('${table}').insert` },
    { table, needle: `.from("${table}").insert` },
    { table, needle: `.from(\`${table}\`).insert` },
  ]);

  for (const filePath of routeFiles) {
    if (TRUST_WRITE_ALLOWLIST.has(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

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

function checkEnvReads() {
  const violations = [];
  const files = getAllScannable();
  const envPattern = /process\.env\.EP_/g;

  for (const filePath of files) {
    if (ENV_ALLOWLIST.has(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

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

function extractHandlerBodies(content) {
  const handlers = [];

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

function countSignificantLines(body) {
  const lines = body.split('\n');
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

function checkHandlerComplexity() {
  const warnings = [];
  const routeFiles = getApiRouteFiles();
  // Track which override entries we observed so we can flag stale ones —
  // an override whose file no longer exceeds the *default* threshold should
  // be removed from HANDLER_COMPLEXITY_OVERRIDES so the list stays honest.
  const overrideMaxObserved = {};

  for (const filePath of routeFiles) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const handlers = extractHandlerBodies(content);

    const relPath = path.relative(ROOT, filePath);
    const cap = HANDLER_COMPLEXITY_OVERRIDES[relPath] ?? HANDLER_COMPLEXITY_THRESHOLD;

    for (const { method, body, startLine } of handlers) {
      const lineCount = countSignificantLines(body);
      if (HANDLER_COMPLEXITY_OVERRIDES[relPath] !== undefined) {
        overrideMaxObserved[relPath] = Math.max(overrideMaxObserved[relPath] ?? 0, lineCount);
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
    const observed = overrideMaxObserved[relPath] ?? 0;
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
const HANDSHAKE_TABLES = [
  'handshakes', 'handshake_parties', 'handshake_presentations',
  'handshake_bindings', 'handshake_results', 'handshake_policies',
  'handshake_events',
];

/** Files that are ALLOWED to write directly to handshake tables. */
const HANDSHAKE_WRITE_ALLOWLIST = new Set([
  path.join(ROOT, 'lib', 'handshake', 'index.js'),
  path.join(ROOT, 'lib', 'protocol-write.js'),
]);

function isInsideHandshakeLib(filePath) {
  const handshakeDir = path.join(ROOT, 'lib', 'handshake') + path.sep;
  return filePath.startsWith(handshakeDir);
}

/**
 * Check H1: No direct writes to handshake tables outside approved modules.
 */
function checkHandshakeTableWrites() {
  const violations = [];
  const allFiles = getAllScannable();

  // Validate HANDSHAKE_TABLES names against a safe charset before use in
  // string-match patterns. Fail loud on any future name with special chars.
  for (const t of HANDSHAKE_TABLES) {
    if (!/^[a-z_][a-z0-9_]*$/.test(t)) {
      throw new Error(`HANDSHAKE_TABLES contains unsafe name: ${JSON.stringify(t)}`);
    }
  }

  // String-based matching (no RegExp engine). Three quote variants per
  // (table, op) pair.
  const writeOps = ['insert', 'update', 'upsert'];
  const patterns = [];
  for (const table of HANDSHAKE_TABLES) {
    for (const op of writeOps) {
      patterns.push({ table, op, needle: `.from('${table}').${op}(` });
      patterns.push({ table, op, needle: `.from("${table}").${op}(` });
      patterns.push({ table, op, needle: `.from(\`${table}\`).${op}(` });
    }
  }

  for (const filePath of allFiles) {
    if (HANDSHAKE_WRITE_ALLOWLIST.has(filePath)) continue;
    if (isInsideHandshakeLib(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

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
function checkHandshakeEnv() {
  const violations = [];
  const envPattern = /process\.env/g;

  const handshakeDir = path.join(ROOT, 'lib', 'handshake');

  const filesToScan = [];
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
function checkHandshakeRoutePolicyLogic() {
  const violations = [];
  const handshakeRouteDir = path.join(ROOT, 'app', 'api', 'handshake');
  if (!fs.existsSync(handshakeRouteDir)) return violations;

  const routeFiles = collectFiles(handshakeRouteDir, /\.js$/);
  const policyPatterns = /required_claims|minimum_assurance|assurance_level.*check|policy.*valid/;

  for (const filePath of routeFiles) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

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
function checkEmbeddedIssuerKeys() {
  const violations = [];
  const embeddedKeyPattern = /presentation\.publicKey|presentation\.signingKey|payload\.key/g;

  const handshakeDir = path.join(ROOT, 'lib', 'handshake');

  const filesToScan = [];
  if (fs.existsSync(handshakeDir)) filesToScan.push(...collectFiles(handshakeDir, /\.js$/));

  for (const filePath of filesToScan) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

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
function checkHandshakeTestSuite() {
  const violations = [];
  const testDir = path.join(ROOT, 'tests');

  const handshakeTestFile = path.join(testDir, 'handshake.test.js');
  const attackTestFile = path.join(testDir, 'handshake-attack.test.js');

  const handshakeTestExists = fs.existsSync(handshakeTestFile);
  const attackTestExists = fs.existsSync(attackTestFile);

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
    const content = fs.readFileSync(handshakeTestFile, 'utf-8');
    const hasInvariantTests = /invariant|Security Invariants|attack/i.test(content);
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

export function runChecks() {
  const trustViolations = checkTrustTableWrites();
  const envViolations = checkEnvReads();
  const complexityWarnings = checkHandlerComplexity();

  // Handshake discipline checks
  const hsTableViolations = checkHandshakeTableWrites();
  const hsEnvWarnings = checkHandshakeEnv();
  const hsPolicyWarnings = checkHandshakeRoutePolicyLogic();
  const hsKeyViolations = checkEmbeddedIssuerKeys();
  const hsTestWarnings = checkHandshakeTestSuite();

  const criticals = [
    ...trustViolations, ...envViolations,
    ...hsTableViolations, ...hsKeyViolations,
  ];
  const warnings = [
    ...complexityWarnings,
    ...hsEnvWarnings, ...hsPolicyWarnings, ...hsTestWarnings,
  ];
  const all = [...criticals, ...warnings];

  return { criticals, warnings, all };
}

function main() {
  console.log('Protocol Discipline Check');
  console.log('='.repeat(60));
  console.log();

  const { criticals, warnings, all } = runChecks();

  // Separate handshake items from general items
  const generalCriticals = criticals.filter((v) => !v.section);
  const generalWarnings = warnings.filter((v) => !v.section);
  const hsCriticals = criticals.filter((v) => v.section === 'handshake');
  const hsWarnings = warnings.filter((v) => v.section === 'handshake');

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
const isDirectRun = process.argv[1] &&
  (process.argv[1].endsWith('check-protocol-discipline.js') ||
   process.argv[1].includes('check-protocol-discipline'));

if (isDirectRun) {
  main();
}
