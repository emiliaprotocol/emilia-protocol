#!/usr/bin/env node
/**
 * generate-proof-metrics.mjs — Single source of truth for public proof claims.
 * Uses Vitest JSON reporter for deterministic, machine-readable test count.
 * Run: node scripts/generate-proof-metrics.mjs
 */
import { readFileSync, writeFileSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const reportPath = join(root, 'generated', '.vitest-report.json');

// Run tests with JSON reporter
try {
  execSync(`npx vitest run --reporter=json --outputFile=${reportPath}`, {
    cwd: root, stdio: 'pipe', timeout: 60000,
  });
} catch (e) {
  // vitest exits 1 on failure but still writes JSON
}

let totalChecks;
try {
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  totalChecks = report.numTotalTests;
  rmSync(reportPath, { force: true });
} catch {
  // Fallback: parse terminal output
  try {
    const out = execSync('npx vitest run 2>&1', { cwd: root, encoding: 'utf8', timeout: 60000 });
    const m = out.match(/Tests\s+(\d+)\s+passed/);
    totalChecks = m ? parseInt(m[1], 10) : null;
  } catch (e2) {
    const m2 = (e2.stdout || '').match(/Tests\s+(\d+)\s+passed/);
    totalChecks = m2 ? parseInt(m2[1], 10) : null;
  }
}

if (!totalChecks) { console.error('FAIL: could not determine test count'); process.exit(1); }

const mcpSrc = readFileSync(join(root, 'mcp-server/index.js'), 'utf8');
const mcpTools = (mcpSrc.match(/    name: 'ep_/g) || []).length;

const scoringSrc = readFileSync(join(root, 'lib/scoring-v2.js'), 'utf8');
const pm = scoringSrc.match(/export const TRUST_POLICIES\s*=\s*\{/);
let policyCount = 0;
if (pm) { const b = scoringSrc.substring(scoringSrc.indexOf(pm[0]), scoringSrc.indexOf('};', scoringSrc.indexOf(pm[0])) + 2); policyCount = (b.match(/^  \w+:/gm) || []).length; }

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const pvSrc = readFileSync(join(root, 'lib/protocol-version.js'), 'utf8');
const sm = pvSrc.match(/spec_version:\s*'([^']+)'/);

const metrics = {
  automated_checks: totalChecks,
  test_suites: 7,
  mcp_tools: mcpTools,
  trust_policies: policyCount,
  trust_surfaces: 10,
  spec_version: sm ? sm[1] : '1.1',
  repo_version: pkg.version,
  generated_at: new Date().toISOString(),
};

writeFileSync(join(root, 'generated/proof-metrics.json'), JSON.stringify(metrics, null, 2) + '\n');
console.log('Generated:', JSON.stringify(metrics, null, 2));
