// SPDX-License-Identifier: Apache-2.0
//
// HTTP/API conformance for the public Receipt Required demo. Verifier
// conformance proves cryptographic parity; this proves the product rail at the
// HTTP boundary: challenge, exact-action receipt, one-time consumption, tamper
// refusal, and evidence export.

import { describe, expect, it } from 'vitest';
import { GET, POST } from '../app/api/demo/require-receipt/route.js';
import { signAction } from '../examples/mcp/_kit.mjs';

function request(body, headers = {}) {
  return new Request('https://www.emiliaprotocol.ai/api/demo/require-receipt', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

function b64(doc) {
  return Buffer.from(JSON.stringify(doc), 'utf8').toString('base64');
}

async function catalog() {
  const res = await GET();
  expect(res.status).toBe(200);
  const body = await res.json();
  expect(body.core_message).toContain('agent accountability verifiable');
  expect(body.actions.map((a) => a.id)).toEqual([
    'release_funds',
    'delete_repo',
    'change_bank_account',
  ]);
  return body.actions;
}

describe('HTTP/API Receipt Required conformance', () => {
  it('advertises the public demo catalog and the exact core message', async () => {
    const actions = await catalog();
    expect(actions).toHaveLength(3);
    for (const action of actions) {
      expect(action.action).toMatch(`${action.action_type}:`);
      expect(action.policy_id).toMatch(/^demo\./);
    }
  });

  it('earns HTTP-RR-1 on release funds, repo deletion, and bank-account changes', async () => {
    for (const action of await catalog()) {
      const missing = await POST(request({ demo: action.id }));
      expect(missing.status).toBe(428);
      expect(missing.headers.get('receipt-required')).toContain(action.action);
      const missingBody = await missing.json();
      expect(missingBody.required.action).toBe(action.action);
      expect(missingBody.loop.invariant).toBe('No receipt, no irreversible action.');

      const receipt = signAction(action.action, { approver: `ep:approver:http-${action.id}` });
      const valid = await POST(request({ demo: action.id, emilia_receipt: receipt }));
      expect(valid.status).toBe(200);
      const validBody = await valid.json();
      expect(validBody.allowed).toBe(true);
      expect(validBody.action).toBe(action.action);
      expect(validBody.evidence.receipt_id).toBe(receipt.payload.receipt_id);
      expect(validBody.evidence_packet.authorized_action).toBe(action.action);
      expect(validBody.evidence_packet.policy_id).toBe(action.policy_id);
      expect(validBody.evidence_packet.checks).toContain('replay_refused');

      const replay = await POST(request({ demo: action.id, emilia_receipt: receipt }));
      expect(replay.status).toBe(428);
      const replayBody = await replay.json();
      expect(replayBody.rejected.reason).toBe('replay_refused');

      const forged = signAction(action.action, { approver: 'ep:approver:forged', tamper: true });
      const forgedRes = await POST(request({ demo: action.id, emilia_receipt: forged }));
      expect(forgedRes.status).toBe(428);
      const forgedBody = await forgedRes.json();
      expect(forgedBody.rejected.reason).toBe('untrusted_or_invalid_signature');
    }
  });

  it('accepts the standard X-EMILIA-Receipt header and still exports evidence', async () => {
    const [action] = await catalog();
    const receipt = signAction(action.action, { approver: 'ep:approver:http-header' });
    const res = await POST(request(
      { demo: action.id },
      { 'x-emilia-receipt': b64(receipt) },
    ));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.evidence.receipt_id).toBe(receipt.payload.receipt_id);
    expect(body.evidence_packet.verifier.offline).toBe(true);
  });
});
