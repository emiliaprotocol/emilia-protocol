// SPDX-License-Identifier: Apache-2.0
//
// /api/v1/guarded — replay defense + freshness fail-closed.
//
// The reference DEMAND route must (a) run on a valid, action-bound, tier-proven
// receipt, (b) REFUSE a replay of that same receipt (one-time consumption), and
// (c) REFUSE a receipt that omits created_at when a max age is enforced.
//
// payment.release is a Class-A action in the default action-control manifest, so
// the allowed-path cases mint a PROOF-BACKED Class-A receipt (via the EG-1
// harness) whose assurance_proof verifies against pinned approver keys. Tier
// enforcement itself (software-on-quorum refused, quorum allowed) is covered in
// tests/guarded-assurance.test.js.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { createEg1Harness } from '../packages/gate/eg1-conformance.js';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

// A single deterministic issuer keypair pinned as the trusted issuer for the run.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const trustedKeyB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

// A Class-A action per the default action-control manifest — the route's default.
const ACTION = 'payment.release';

// Proof-backed Class-A minter for the allowed-path cases. The harness pins its
// own issuer key + approver keys; we trust BOTH so a valid Class-A receipt runs.
const harness = createEg1Harness({ action: { action_type: ACTION }, idPrefix: 'guarded_ok' });

// A software-tier (unproven) receipt bound to `action`, for the fail-closed
// (missing receipt_id / missing created_at) cases that must be caught BEFORE
// the tier check — those refuse regardless of tier.
function mintSoftware(action, { createdAt, receiptId, omitCreatedAt = false, omitReceiptId = false } = {}) {
  const ts = createdAt || new Date().toISOString();
  const payload = {
    ...(omitReceiptId ? {} : { receipt_id: receiptId || `rcpt_test_${crypto.randomBytes(6).toString('hex')}` }),
    subject: 'agent:test',
    ...(omitCreatedAt ? {} : { created_at: ts }),
    claim: { action_type: action, outcome: 'allow_with_signoff', approver: 'ep:approver:test' },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}

function guardedRequest(doc, { action = ACTION } = {}) {
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
    // Trust BOTH the software issuer key (fail-closed cases) and the harness
    // issuer key (proof-backed allow cases), and pin the harness approver keys
    // so a genuine Class-A proof verifies.
    process.env.EP_TRUSTED_ISSUER_KEYS = `${trustedKeyB64u},${harness.publicKey}`;
    process.env.EP_PINNED_APPROVER_KEYS = JSON.stringify(harness.approverKeys);
    process.env.EP_WEBAUTHN_RP_ID = harness.rpId;
    process.env.EP_WEBAUTHN_ALLOWED_ORIGINS = harness.allowedOrigins.join(',');
    // Force dev posture so the consumption store uses the in-memory backend.
    delete process.env.NODE_ENV;
    const consumption = await import('../lib/http/guarded-consumption.js');
    consumption.__resetGuardedConsumptionStoreForTests();
    ({ POST } = await import('../app/api/v1/guarded/route.js'));
  });

  afterEach(() => {
    delete process.env.EP_TRUSTED_ISSUER_KEYS;
    delete process.env.EP_PINNED_APPROVER_KEYS;
    delete process.env.EP_WEBAUTHN_RP_ID;
    delete process.env.EP_WEBAUTHN_ALLOWED_ORIGINS;
  });

  it('REFUSES a verified receipt with no receipt_id (cannot enforce one-time consumption)', async () => {
    const doc = mintSoftware(ACTION, { omitReceiptId: true });
    const res = await POST(guardedRequest(doc));
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.rejected?.reason).toBe('missing_receipt_id');
  });

  it('allows a valid, action-bound, tier-proven receipt', async () => {
    const doc = harness.mint({ outcome: 'allow_with_signoff' });
    const res = await POST(guardedRequest(doc));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.allowed).toBe(true);
    expect(body.receipt_id).toBe(doc.payload.receipt_id);
  });

  it('REFUSES a replay of the same receipt (409)', async () => {
    const doc = harness.mint({ outcome: 'allow_with_signoff' });
    const first = await POST(guardedRequest(doc));
    expect(first.status).toBe(200);

    const replay = await POST(guardedRequest(doc));
    expect(replay.status).toBe(409);
    const body = await replay.json();
    expect(body.rejected?.reason).toBe('receipt_replayed');
  });

  it('REFUSES a receipt with no created_at when max age is enforced (402)', async () => {
    const doc = mintSoftware(ACTION, { omitCreatedAt: true });
    const res = await POST(guardedRequest(doc));
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.rejected?.reason).toBe('missing_created_at');
  });

  it('distinct receipts for the same action are each allowed once', async () => {
    const a = await POST(guardedRequest(harness.mint({ outcome: 'allow_with_signoff' })));
    const b = await POST(guardedRequest(harness.mint({ outcome: 'allow_with_signoff' })));
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
  });
});
