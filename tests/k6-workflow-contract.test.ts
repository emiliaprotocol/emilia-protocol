// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = path.resolve(import.meta.dirname, '..');
const WORKFLOW_PATH = path.join(ROOT, '.github/workflows/k6.yml');

describe('k6 workflow contract', () => {
  it('only invokes load-test entrypoints that exist in the repository', () => {
    const workflow = fs.readFileSync(WORKFLOW_PATH, 'utf8');
    const entrypoints = [...workflow.matchAll(/\bk6 run (tests\/k6\/[^\s\\]+)/g)]
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
  });
});
