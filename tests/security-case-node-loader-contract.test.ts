// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const source = readFileSync(
  new URL('../scripts/verify-security-case.mts', import.meta.url),
  'utf8',
);

describe('security-case Node test runner', () => {
  it('loads TypeScript-migrated sources in every child node:test process', () => {
    expect(source).toMatch(
      /process\.execPath,[\s\S]+--import[\s\S]+scripts", "ts-loader", "register\.mjs"[\s\S]+--test/,
    );
  });
});
