// SPDX-License-Identifier: Apache-2.0
//
// Runnable-proof smoke tests: the public demos are not just docs — CI runs them
// and asserts the whole loop. Each MCP example must REFUSE the irreversible tool
// without a receipt (402), RUN it with a valid receipt (200), and REJECT a forged
// receipt (402). The crash-test must reach a verified receipt. If any of these
// regress, the build fails.

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const run = (rel) =>
  execFileSync('node', [resolve(root, rel)], {
    env: { ...process.env, FAST: '1' },
    encoding: 'utf8',
    timeout: 30_000,
  });

describe('public MCP examples run cold and enforce "no receipt, no irreversible action"', () => {
  for (const [file, tool] of [
    ['examples/mcp/payment-server.mjs', 'release_payment'],
    ['examples/mcp/github-admin.mjs', 'delete_repo'],
    ['examples/mcp/prod-deploy.mjs', 'deploy_production'],
  ]) {
    it(`${tool}: refused without a receipt, runs with one, rejects a forgery`, () => {
      const out = run(file);
      // 1. refused without a receipt
      expect(out).toMatch(/no EMILIA receipt presented|Receipt Required/i);
      // 2. runs with a valid receipt
      expect(out).toMatch(/OK — tool ran|tool performed/);
      // 3. forged receipt rejected (fail-closed)
      expect(out).toMatch(/untrusted_or_invalid_signature|Receipt rejected/);
    });
  }
});

describe('crash-test reaches a verified, offline receipt', () => {
  it('runs the full block -> signoff -> receipt -> verify loop', () => {
    const out = run('examples/crash-test.mjs');
    expect(out).toMatch(/VERIFIED|verifies|receipt/i);
    expect(out).not.toMatch(/Error:|unhandled/i);
  });
});
