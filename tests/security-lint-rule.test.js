// SPDX-License-Identifier: Apache-2.0

import { beforeAll, describe, expect, it } from 'vitest';
import { ESLint } from 'eslint';

let eslint;

beforeAll(() => {
  eslint = new ESLint({ overrideConfigFile: './eslint.config.mjs' });
});

async function lintFixture(source) {
  const [result] = await eslint.lintText(source, { filePath: 'app/security/lint-fixture.js' });
  return result;
}

describe('security lint boundary', () => {
  // ESLint's first lintText() call in a process cold-loads eslint-config-next
  // and its full plugin set; under a loaded CI runner (full suite running
  // concurrently) that one-time cost alone can exceed vitest's default 5s
  // timeout even though the rule itself resolves in well under a second.
  // This is the first test to touch `eslint` in this file, so it pays that
  // cost; give it real headroom instead of a fragile default.
  it('rejects direct auth.entity access in runtime code', async () => {
    const result = await lintFixture('export function probe(auth) { return auth.entity; }');
    expect(result.errorCount).toBeGreaterThan(0);
    expect(result.messages.some((message) => message.ruleId === 'ep-security/no-raw-auth-entity')).toBe(true);
  }, 20000);

  it('rejects computed access and destructuring from the auth object', async () => {
    const computed = await lintFixture('export function probe(auth) { return auth[\'entity\']; }');
    const destructured = await lintFixture('export function probe(auth) { const { entity: row } = auth; return row; }');
    expect(computed.messages.some((message) => message.ruleId === 'ep-security/no-raw-auth-entity')).toBe(true);
    expect(destructured.messages.some((message) => message.ruleId === 'ep-security/no-raw-auth-entity')).toBe(true);
  });

  it('allows the stable identity projection', async () => {
    const result = await lintFixture('export function probe(auth) { return authEntityId(auth); }');
    expect(result.errorCount).toBe(0);
  });
});
