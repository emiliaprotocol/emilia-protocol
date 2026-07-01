// SPDX-License-Identifier: Apache-2.0
//
// Boundary red-team for every public MCP Receipt Required example.
// The manifest is the source of truth: every receipt_required MCP action must
// refuse missing/forged/replayed/wrong-action/wrong-target/too-low-tier receipts.

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { actionForCall, makeGuardedServer, signAction } from '../examples/mcp/_kit.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(HERE, '../public/.well-known/agent-actions.json'), 'utf8'));

const TARGET_ARGS = {
  release_payment: { destination: 'acct:vendor-acme-250000', amount_usd: 250000, currency: 'USD' },
  delete_repo: { repo: 'emilia/prod-ledger' },
  deploy_production: { service: 'payments-api', environment: 'prod' },
  run_destructive_sql: { database: 'prod-ledger', sql: 'DROP TABLE payouts;' },
  export_customer_data: { workspace: 'acme-prod', format: 'csv' },
};

const TARGET_KEY = {
  release_payment: 'destination',
  delete_repo: 'repo',
  deploy_production: 'service',
  run_destructive_sql: 'database',
  export_customer_data: 'workspace',
};

const mcpRequirements = manifest.actions.filter((action) =>
  action.receipt_required === true && action.match?.protocol === 'mcp' && action.match?.tool,
);

function freshServer(tool) {
  return makeGuardedServer({ tool });
}

function argsFor(tool) {
  return TARGET_ARGS[tool] || { demo: true };
}

function boundFor(req, args) {
  return actionForCall(req.match.tool, req.action_type, args);
}

describe('MCP Receipt Required boundary red-team', () => {
  for (const req of mcpRequirements) {
    const tool = req.match.tool;

    it(`${tool}: refuses no receipt, forged receipt, replay, action swap, and target swap`, async () => {
      const args = argsFor(tool);
      const bound = boundFor(req, args);

      const missing = await freshServer(tool)(tool, args, null);
      expect(missing.status).toBe(428);
      expect(missing.body.required.action).toBe(bound);

      const validReceipt = signAction(bound, {
        approver: `ep:approver:${tool}`,
        quorum: req.quorum,
      });
      const replayServer = freshServer(tool);
      const valid = await replayServer(tool, args, validReceipt);
      expect(valid.status).toBe(200);
      expect(valid.body.ran).toBe(true);

      const replay = await replayServer(tool, args, validReceipt);
      expect(replay.status).toBe(428);
      expect(replay.body.rejected.reason).toBe('replay_refused');

      const forged = await freshServer(tool)(tool, args, signAction(bound, {
        approver: `ep:approver:${tool}`,
        quorum: req.quorum,
        tamper: true,
      }));
      expect(forged.status).toBe(428);
      expect(forged.body.rejected.reason).toBe('untrusted_or_invalid_signature');

      const wrongAction = await freshServer(tool)(tool, args, signAction('something.harmless', {
        approver: `ep:approver:${tool}`,
        quorum: req.quorum,
      }));
      expect(wrongAction.status).toBe(428);
      expect(wrongAction.body.rejected.reason).toBe('action_mismatch');

      const targetKey = TARGET_KEY[tool];
      if (targetKey) {
        const otherArgs = { ...args, [targetKey]: `${args[targetKey]}:attacker` };
        const wrongTargetReceipt = signAction(boundFor(req, otherArgs), {
          approver: `ep:approver:${tool}`,
          quorum: req.quorum,
        });
        const wrongTarget = await freshServer(tool)(tool, args, wrongTargetReceipt);
        expect(wrongTarget.status).toBe(428);
        expect(wrongTarget.body.rejected.reason).toBe('action_mismatch');
      }
    });

    it(`${tool}: refuses receipts below the manifest assurance class`, async () => {
      const args = argsFor(tool);
      const bound = boundFor(req, args);
      const software = signAction(bound, {
        approver: `ep:approver:${tool}`,
        outcome: 'allow',
      });
      const softwareResult = await freshServer(tool)(tool, args, software);
      expect(softwareResult.status).toBe(428);
      expect(softwareResult.body.rejected.reason).toBe('assurance_too_low');

      if (req.assurance_class === 'quorum') {
        const singleHuman = signAction(bound, {
          approver: `ep:approver:${tool}`,
        });
        const singleHumanResult = await freshServer(tool)(tool, args, singleHuman);
        expect(singleHumanResult.status).toBe(428);
        expect(singleHumanResult.body.rejected.reason).toBe('assurance_too_low');

        const duplicateQuorum = signAction(bound, {
          approver: `ep:approver:${tool}`,
          quorum: { required: true, m: 2, second_approver: `ep:approver:${tool}` },
        });
        const duplicateResult = await freshServer(tool)(tool, args, duplicateQuorum);
        expect(duplicateResult.status).toBe(428);
        expect(duplicateResult.body.rejected.reason).toBe('assurance_too_low');
      }
    });
  }

  it('explicitly unguarded read-only MCP tools still pass through without a receipt', async () => {
    const res = await freshServer('search_payments')('search_payments', { q: 'vendor' }, null);
    expect(res.status).toBe(200);
    expect(res.body.ran).toBe(true);
  });
});
