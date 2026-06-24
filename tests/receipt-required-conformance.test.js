// SPDX-License-Identifier: Apache-2.0
//
// Receipt Required conformance — the badge is EARNED, not asserted. CI runs the
// conformance harness against the three canonical example servers and the
// published Action Risk Manifest; if any vector regresses, the build fails and
// the RR-1 badge claim is no longer true.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { receiptRequiredConformance } from '../packages/require-receipt/index.js';
import { makeGuardedServer, signAction } from '../examples/mcp/_kit.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(HERE, '../public/.well-known/agent-actions.json'), 'utf8'));

const TARGETS = [
  ['release_payment', 'payment.release'],
  ['delete_repo', 'github.repo.delete'],
  ['deploy_production', 'deploy.production'],
  ['run_destructive_sql', 'database.destructive_sql'],
  ['export_customer_data', 'saas.data_export'],
];

describe('Receipt Required conformance — example servers earn level RR-1', () => {
  for (const [tool, action] of TARGETS) {
    it(`${tool}: RR-1 (challenge -> runs -> replay refused -> forged refused)`, async () => {
      const report = await receiptRequiredConformance({
        dispatch: makeGuardedServer({ tool }),
        tool,
        args: { demo: true },
        action,
        issueReceipt: () => signAction(action, { approver: 'ep:approver:conformance-test' }),
        manifest,
      });
      expect(report.checks.manifest_valid).toBe(true);
      expect(report.checks.challenge_on_missing).toBe(true);
      expect(report.checks.runs_on_valid).toBe(true);
      expect(report.checks.replay_refused).toBe(true);
      expect(report.checks.forged_refused).toBe(true);
      expect(report.passed).toBe(true);
      expect(report.level).toBe('RR-1');
    });
  }
});
