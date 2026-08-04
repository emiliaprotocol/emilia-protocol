// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path: string): string => readFileSync(resolve(ROOT, path), 'utf8');
const runner = read('scripts/run-gate-reference-proof.mjs');
const freshness = read('scripts/check-gate-runtime-freshness.mjs');
const workflow = read('.github/workflows/ci.yml');
const packageJson = JSON.parse(read('package.json'));

function workflowJob(name: string): string {
  const marker = `\n  ${name}:\n`;
  const start = workflow.indexOf(marker);
  if (start < 0) return '';
  const bodyStart = start + marker.length;
  const next = workflow.slice(bodyStart).search(/\n  [a-zA-Z0-9_-]+:\n/);
  return workflow.slice(start, next < 0 ? undefined : bodyStart + next);
}

describe('Gate reference proof release contract', () => {
  it('refuses stale compiled and standalone runtimes before running examples', () => {
    const compiled = runner.indexOf("label: 'Gate compiled-runtime freshness'");
    const standalone = runner.indexOf("label: 'standalone Node 20 runtime freshness'");
    const firstExample = runner.indexOf("label: 'indeterminate-effect reconciliation demo'");

    expect(compiled).toBeGreaterThan(-1);
    expect(standalone).toBeGreaterThan(compiled);
    expect(firstExample).toBeGreaterThan(standalone);
    expect(freshness).toContain("console.error('GATE RUNTIME FRESHNESS: FAIL')");
    expect(freshness).toContain("rmSync(scratch, { recursive: true, force: true })");
  });

  it('loads tsx through Node 20 instead of invoking a platform-specific binary', () => {
    expect(runner).toContain("const tsLoader = 'tsx'");
    expect(runner).toContain("'--import'");
    expect(runner).not.toContain("node_modules', '.bin', 'tsx");
    expect(runner).toContain("displayCommand: 'node'");
  });

  it('is a public npm command exercised by the Node 20 Gate product job', () => {
    expect(packageJson.scripts['proof:gate:reference']).toBe('node scripts/run-gate-reference-proof.mjs');
    const gateProduct = workflowJob('gate-product');
    expect(gateProduct).toContain('node-version: 20');
    expect(gateProduct).toContain('npm run proof:gate:reference');
  });

  it('states the local and mock scope instead of calling randomized evidence deterministic', () => {
    expect(runner).toContain('Self-contained local examples');
    expect(runner).toContain('not evidence of a real human, external bank, production deployment');
    expect(runner).not.toContain('Deterministic local examples');
  });
});
