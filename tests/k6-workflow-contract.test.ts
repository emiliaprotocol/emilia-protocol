// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import YAML from 'yaml';

const ROOT = path.resolve(import.meta.dirname, '..');
const WORKFLOW_PATH = path.join(ROOT, '.github/workflows/k6.yml');

describe('k6 workflow contract', () => {
  it('only invokes existing load-test entrypoints and keeps the perf key main-only', () => {
    const source = fs.readFileSync(WORKFLOW_PATH, 'utf8');
    const workflow = YAML.parse(source);
    const entrypoints = [...source.matchAll(/\bk6 run (tests\/k6\/[^\s\\]+)/g)]
      .map((match) => match[1]);

    expect(entrypoints).toEqual([
      'tests/k6/baseline.ts',
      'tests/k6/staircase.ts',
    ]);

    for (const entrypoint of entrypoints) {
      expect(
        fs.existsSync(path.join(ROOT, entrypoint)),
        `${entrypoint} referenced by .github/workflows/k6.yml`,
      ).toBe(true);
    }

    // The production perf API key stays in the main-only `performance`
    // environment and is sent only after the origin guard. No trigger runs
    // pull request, merge-queue or arbitrary branch code.
    expect(Object.keys(workflow.on).sort()).toEqual(['schedule', 'workflow_dispatch']);

    const users = Object.entries(workflow.jobs).filter(([, job]) =>
      JSON.stringify(job).includes('secrets.PERF_TEST_API_KEY'));
    expect(users.map(([name]) => name)).toEqual(['baseline']);
    for (const [, job] of users) {
      expect(job.environment).toBe('performance');
      expect(job.if).toBe(
        "github.ref == 'refs/heads/main' && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')",
      );
      const steps = job.steps.map((step) => step.name ?? step.uses);
      const guard = steps.indexOf('Send the API key only to an emiliaprotocol.ai origin');
      const firstKeyUse = job.steps.findIndex((step) =>
        JSON.stringify(step).includes('secrets.PERF_TEST_API_KEY'));
      expect(guard).toBeGreaterThan(-1);
      expect(guard).toBeLessThan(firstKeyUse);
    }
  });
});
