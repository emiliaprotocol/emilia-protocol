// SPDX-License-Identifier: Apache-2.0
//
// HTTP/API conformance for the public Receipt Required demo. Verifier
// conformance proves cryptographic parity; this proves the product rail at the
// HTTP boundary: challenge, exact-action receipt, one-time consumption, tamper
// refusal, and evidence export.

import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { GET, POST } from '../app/api/demo/require-receipt/route.js';

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

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

function mint(action, { outcome = 'allow_with_signoff', quorum = null, extra = {} } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'rcpt_http_' + crypto.randomBytes(6).toString('hex'),
    subject: 'agent:http-redteam',
    created_at: new Date().toISOString(),
    claim: {
      action_type: action,
      outcome,
      approver: 'ep:approver:http-redteam',
      ...(quorum ? { quorum } : {}),
      ...extra,
    },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
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
      expect(missing.headers.get('content-type')).toContain('application/problem+json');
      expect(missing.headers.get('receipt-required')).toContain(action.action);
      const missingBody = await missing.json();
      expect(missingBody.status).toBe(missing.status);
      expect(missingBody.required.status).toBe(missing.status);
      expect(missingBody.required.action).toBe(action.action);
      expect(missingBody.loop.invariant).toBe('No receipt, no irreversible action.');

      const signed = await POST(request({
        demo: action.id,
        sign_demo_receipt: true,
        approver: `ep:approver:http-${action.id}`,
      }));
      expect(signed.status).toBe(200);
      const signedBody = await signed.json();
      expect(signedBody.signed.action).toBe(action.action);
      const receipt = signedBody.receipt;

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
      expect(replay.headers.get('content-type')).toContain('application/problem+json');
      const replayBody = await replay.json();
      expect(replayBody.rejected.reason).toBe('replay_refused');

      const forged = JSON.parse(JSON.stringify(receipt));
      forged.payload.claim.action_type = 'payment.release:wire:attacker';
      const forgedRes = await POST(request({ demo: action.id, emilia_receipt: forged }));
      expect(forgedRes.status).toBe(428);
      const forgedBody = await forgedRes.json();
      expect(forgedBody.rejected.reason).toBe('untrusted_or_invalid_signature');
    }
  });

  it('accepts the standard X-EMILIA-Receipt header and still exports evidence', async () => {
    const [action] = await catalog();
    const signed = await POST(request({
      demo: action.id,
      sign_demo_receipt: true,
      approver: 'ep:approver:http-header',
    }));
    const { receipt } = await signed.json();
    const res = await POST(request(
      { demo: action.id },
      { 'x-emilia-receipt': b64(receipt) },
    ));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.evidence.receipt_id).toBe(receipt.payload.receipt_id);
    expect(body.evidence_packet.verifier.offline).toBe(true);
  });

  it('refuses receipts below the advertised assurance tier at the HTTP boundary', async () => {
    for (const action of await catalog()) {
      const software = await POST(request({
        demo: action.id,
        emilia_receipt: mint(action.action, {
          extra: {
            policy_id: action.policy_id,
            assurance_class: action.assurance_class,
            human_present: true,
            quorum: { threshold: 2, signers: ['alice', 'bob'] },
          },
        }),
      }));
      expect(software.status).toBe(428);
      expect((await software.json()).rejected.reason).toBe('assurance_proof_required');

      if (action.assurance_class === 'quorum') {
        const singleHuman = await POST(request({
          demo: action.id,
          emilia_receipt: mint(action.action, {
            extra: { policy_id: action.policy_id, assurance_class: action.assurance_class },
          }),
        }));
        expect(singleHuman.status).toBe(428);
        expect((await singleHuman.json()).rejected.reason).toBe('assurance_proof_required');

        const signed = await POST(request({
          demo: action.id,
          sign_demo_receipt: true,
          approver: 'ep:approver:quorum-fixture',
        }));
        const { receipt } = await signed.json();
        const quorum = await POST(request({
          demo: action.id,
          emilia_receipt: receipt,
        }));
        expect(quorum.status).toBe(200);
      }
    }
  });
});
