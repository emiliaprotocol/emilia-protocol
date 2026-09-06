// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const source = readFileSync(
  new URL('../scripts/verify-security-case.mts', import.meta.url),
  'utf8',
);

describe('security-case Node test runner', () => {
  it('loads TypeScript sources and budgets every child test process', () => {
    expect(source).toMatch(
      /process\.execPath,[\s\S]+--import[\s\S]+scripts", "ts-loader", "register\.mjs"[\s\S]+--test/,
    );
    // The per-test budget moved to tests/security-case-vitest-runner-contract.ts
    // when main narrowed it to tests/release-reproducibility.test.ts, the one
    // file doing real Git and npm work. Every other evidence file keeps the
    // outer 600-second deadline and Vitest's own defaults, which that suite
    // asserts. Nothing is checked here so the two contracts cannot disagree.
  });
});
