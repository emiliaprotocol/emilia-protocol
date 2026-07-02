// SPDX-License-Identifier: Apache-2.0
//
// /api/v1/guarded — replay defense + freshness fail-closed.
//
// The reference DEMAND route must (a) run on a valid, action-bound receipt,
// (b) REFUSE a replay of that same receipt (one-time consumption), and
// (c) REFUSE a receipt that omits created_at when a max age is enforced.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

// A single deterministic issuer keypair pinned as the trusted issuer for the run.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const trustedKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

// NOTE: pass `omitCreatedAt: true` to actually drop created_at. A destructuring
// default (`createdAt = ...`) fires on an explicit `undefined`, so it cannot be
// used to omit the field — hence the explicit flag.
function mint(action, { createdAt, receiptId, omitCreatedAt = false } = {}) {
  const ts = createdAt || new Date().toISOString();
  const payload = {
    receipt_id: receiptId || `rcpt_test_${crypto.randomBytes(6).toString('hex')}`,
    subject: 'agent:test',
    ...(omitCreatedAt ? {} : { created_at: ts }),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'ep:approver:test' },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}

function guardedRequest(doc, { action = 'payment.release' } = {}) {
  const url = `https://www.emiliaprotocol.ai/api/v1/guarded?action=${encodeURIComponent(action)}`;
  return {
    url,
    method: 'POST',
    headers: new Headers({ 'content-type': 'application/json' }),
    // The route uses readLimitedJson, which for test doubles (no .body stream)
    // falls back to request.json().
    json: async () => ({ emilia_receipt: doc }),
  };
}

describe('/api/v1/guarded replay + freshness', () => {
  let POST;

  beforeEach(async () => {
    process.env.EP_TRUSTED_ISSUER_KEYS = trustedKeyB64u;
    // Force dev posture so the consumption store uses the in-memory backend.
    delete process.env.NODE_ENV;
    const consumption = await import('../lib/http/guarded-consumption.js');
    consumption.__resetGuardedConsumptionStoreForTests();
    ({ POST } = await import('../app/api/v1/guarded/route.js'));
  });

  afterEach(() => {
    delete process.env.EP_TRUSTED_ISSUER_KEYS;
  });

  it('allows a valid, action-bound receipt', async () => {
    const doc = mint('payment.release');
    const res = await POST(guardedRequest(doc));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.allowed).toBe(true);
    expect(body.receipt_id).toBe(doc.payload.receipt_id);
  });

  it('REFUSES a replay of the same receipt (409)', async () => {
    const doc = mint('payment.release', { receiptId: 'rcpt_replay_fixed' });
    const first = await POST(guardedRequest(doc));
    expect(first.status).toBe(200);

    const replay = await POST(guardedRequest(doc));
    expect(replay.status).toBe(409);
    const body = await replay.json();
    expect(body.rejected?.reason).toBe('receipt_replayed');
  });

  it('REFUSES a receipt with no created_at when max age is enforced (402)', async () => {
    const doc = mint('payment.release', { omitCreatedAt: true });
    const res = await POST(guardedRequest(doc));
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.rejected?.reason).toBe('missing_created_at');
  });

  it('distinct receipts for the same action are each allowed once', async () => {
    const a = await POST(guardedRequest(mint('payment.release')));
    const b = await POST(guardedRequest(mint('payment.release')));
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
  });
});
