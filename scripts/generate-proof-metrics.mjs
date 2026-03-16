#!/usr/bin/env node
/**
 * generate-proof-metrics.mjs
 * 
 * Single source of truth for public proof claims.
 * Run: node scripts/generate-proof-metrics.mjs
 * Output: generated/proof-metrics.json
 */
import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');

// Derive MCP tool count from index.js
const mcpSrc = readFileSync(join(root, 'mcp-server/index.js'), 'utf8');
const mcpTools = (mcpSrc.match(/    name: 'ep_/g) || []).length;

// Derive policy count from scoring-v2.js
const scoringSrc = readFileSync(join(root, 'lib/scoring-v2.js'), 'utf8');
const policyMatch = scoringSrc.match(/export const TRUST_POLICIES\s*=\s*\{/);
let policyCount = 0;
if (policyMatch) {
  const start = scoringSrc.indexOf(policyMatch[0]);
  const block = scoringSrc.substring(start, scoringSrc.indexOf('};', start) + 2);
  policyCount = (block.match(/^  \w+:/gm) || []).length;
}

// Derive version from package.json
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

// Derive spec version from protocol-version.js
const pvSrc = readFileSync(join(root, 'lib/protocol-version.js'), 'utf8');
const specMatch = pvSrc.match(/spec_version:\s*'([^']+)'/);
const specVersion = specMatch ? specMatch[1] : '1.1';

// Count test files
const testFiles = ['tests/scoring.test.js', 'tests/scoring-v2.test.js', 'tests/protocol.test.js',
  'tests/integration.test.js', 'tests/adversarial.test.js', 'tests/e2e-flows.test.js',
  'conformance/conformance.test.js'];

let totalChecks = 0;
for (const tf of testFiles) {
  const src = readFileSync(join(root, tf), 'utf8');
  totalChecks += (src.match(/^\s*(it|test)\(/gm) || []).length;
}

const metrics = {
  automated_checks: totalChecks,
  test_suites: testFiles.length,
  mcp_tools: mcpTools,
  trust_policies: policyCount,
  trust_surfaces: 10,
  spec_version: specVersion,
  repo_version: pkg.version,
  generated_at: new Date().toISOString(),
};

writeFileSync(join(root, 'generated/proof-metrics.json'), JSON.stringify(metrics, null, 2) + '\n');
// Note: it() count may undercount parameterized tests in for-loops.
// Run npx vitest run for the authoritative test count.
console.log('Generated proof-metrics.json:', JSON.stringify(metrics, null, 2));
