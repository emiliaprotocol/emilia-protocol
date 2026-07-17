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
    ['examples/mcp/supabase-admin.mjs', 'run_destructive_sql'],
    ['examples/mcp/linear-export.mjs', 'export_customer_data'],
  ]) {
    it(`${tool}: full rail — 428 without receipt, runs, replay refused, forgery refused`, () => {
      const out = run(file);
      // manifest-driven gate
      expect(out).toMatch(new RegExp(`manifest: ${tool}`));
      // 1. refused without a receipt — 428 Receipt Required
      expect(out).toMatch(/428 .*Receipt Required/i);
      // 2. runs with a valid receipt
      expect(out).toMatch(/OK — tool ran|tool performed/);
      // 3. the same receipt replayed is refused (one-time consumption)
      expect(out).toMatch(/replay_refused/);
      // 4. forged receipt rejected (fail-closed)
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

describe('Google Cloud external reliance lab runs the real MCP boundary', () => {
  it('allows local controls, refuses five evidence failures, and executes exactly once', () => {
    const out = run('examples/google-cloud-reliance/demo.mjs');
    expect(out).toMatch(/IAM ALLOW · Model Armor ALLOW/);
    expect(out.match(/REFUSE ·/g)).toHaveLength(5);
    expect(out).toMatch(/RELY\s+· exact-quorum-evidence-runs-once/);
    expect(out).toMatch(/Real mutation count: 1 \(expected exactly 1\)/);
    expect(out).toMatch(/execution binds authorization: yes/);
  });
});

describe('continuous-assurance example re-performs signed material, not presenter claims', () => {
  it('accepts the clean population and isolates the planted authority-ceiling drift', () => {
    const out = run('examples/reliance/ey-continuous-assurance.mjs');
    expect(out).toMatch(/admissible\(rely\): 8 \| refused: 3 \| drift: 1/);
    expect(out).toMatch(/PA-over-ceiling: stated=rely recomputed=do_not_rely_amount_exceeded/);
    expect(out).toMatch(/OK — re-performance independently caught the PA/);
    expect(out).not.toMatch(/FAILED/);
  });
});
