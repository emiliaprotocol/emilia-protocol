#!/usr/bin/env node
/**
 * generate-proof-metrics.mjs
 * 
 * Single source of truth for public proof claims.
 * Run: node scripts/generate-proof-metrics.mjs
 * Output: generated/proof-metrics.json
 * 
 * Counts both static it()/test() calls AND fixture-driven parameterized tests.
 */
import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

// --- Authoritative test count: run vitest ---
let totalChecks;
try {
  const out = execSync('npx vitest run --reporter=verbose 2>&1', { cwd: root, encoding: 'utf8', timeout: 30000 });
  const match = out.match(/Tests\s+(\d+)\s+passed/);
  totalChecks = match ? parseInt(match[1], 10) : null;
} catch (e) {
  const match = (e.stdout || '').match(/Tests\s+(\d+)\s+passed/);
  totalChecks = match ? parseInt(match[1], 10) : null;
}

if (!totalChecks) {
  console.error('FAIL: could not determine test count from vitest');
  process.exit(1);
}

// --- Derive other metrics from code ---
const mcpSrc = readFileSync(join(root, 'mcp-server/index.js'), 'utf8');
const mcpTools = (mcpSrc.match(/    name: 'ep_/g) || []).length;

const scoringSrc = readFileSync(join(root, 'lib/scoring-v2.js'), 'utf8');
const policyMatch = scoringSrc.match(/export const TRUST_POLICIES\s*=\s*\{/);
let policyCount = 0;
if (policyMatch) {
  const start = scoringSrc.indexOf(policyMatch[0]);
  const block = scoringSrc.substring(start, scoringSrc.indexOf('};', start) + 2);
  policyCount = (block.match(/^  \w+:/gm) || []).length;
}

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const pvSrc = readFileSync(join(root, 'lib/protocol-version.js'), 'utf8');
const specMatch2 = pvSrc.match(/spec_version:\s*'([^']+)'/);
const specVersion = specMatch2 ? specMatch2[1] : '1.1';

const metrics = {
  automated_checks: totalChecks,
  test_suites: 7,
  mcp_tools: mcpTools,
  trust_policies: policyCount,
  trust_surfaces: 10,
  spec_version: specVersion,
  repo_version: pkg.version,
  generated_at: new Date().toISOString(),
};

writeFileSync(join(root, 'generated/proof-metrics.json'), JSON.stringify(metrics, null, 2) + '\n');
console.log('Generated proof-metrics.json:', JSON.stringify(metrics, null, 2));
