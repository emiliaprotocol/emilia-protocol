// SPDX-License-Identifier: Apache-2.0
//
// /api/v1/guarded — assurance-tier fail-closed.
//
// A valid signature proves a receipt is authentic and action-bound; it does NOT
// prove the human-authorization tier the action demands. The action-control
// manifest sets that tier (deploy.production = quorum, payment.release =
// class_a, …). The demand route MUST resolve that tier and refuse a receipt
// whose PROVEN tier is below it — a self-asserted `allow_with_signoff` /
// `quorum` field is software-tier until proven against pinned approver keys.
//
// Regression for the HIGH finding: a valid software-tier receipt bound to a
// quorum action (deploy.production) was returning { allowed:true } because the
// route never called evaluateReceiptAssurance.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import crypto from 'node:crypto';
import { createEg1Harness } from '../packages/gate/eg1-conformance.js';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

const QUORUM_ACTION = 'deploy.production';   // assurance_class: quorum
const CLASS_A_ACTION = 'payment.release';    // assurance_class: class_a
const PASS_THROUGH = 'read.status';          // receipt_required: false

// The trusted issuer for the software-tier (unproven) receipts.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const softwareIssuerB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

function mintSoftware(action) {
  const payload = {
    receipt_id: `rcpt_sw_${crypto.randomBytes(6).toString('hex')}`,
    subject: 'agent:test',
    created_at: new Date().toISOString(),
    // outcome:'allow' + NO assurance_proof => software tier only.
    claim: { action_type: action, outcome: 'allow' },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}

// A receipt that SELF-ASSERTS a signoff/quorum in its claim but carries no
// verifiable assurance_proof — this is the exact attack: a software-tier receipt
// dressed up to look authorized. Must still be refused.
function mintSelfAssertedSignoff(action) {
  const payload = {
    receipt_id: `rcpt_selfassert_${crypto.randomBytes(6).toString('hex')}`,
    subject: 'agent:test',
    created_at: new Date().toISOString(),
    claim: {
      action_type: action,
      outcome: 'allow_with_signoff',
      approver: 'ep:approver:i-say-so',
      quorum: { threshold: 2, signers: ['ep:approver:a', 'ep:approver:b'] },
    },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}

function guardedRequest(doc, action) {
  return {
    url: `https://www.emiliaprotocol.ai/api/v1/guarded?action=${encodeURIComponent(action)}`,
    method: 'POST',
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => ({ emilia_receipt: doc }),
  };
}

// NOTE: every EG-1 harness hardcodes the SAME approver_key_id values
// (ep:key:eg1:class-a / ep:key:eg1:controller) over its OWN keypairs. Merging
// two harnesses' approverKeys would collide on those ids and silently break
// proof verification. So proof-backed cases create their harness inline and pin
// ONLY that harness's keys via a per-test env setup.
async function setupWith({ harness } = {}) {
  process.env.EP_TRUSTED_ISSUER_KEYS = [softwareIssuerB64u, ...(harness ? [harness.publicKey] : [])].join(',');
  process.env.EP_PINNED_APPROVER_KEYS = JSON.stringify(harness ? harness.approverKeys : {});
  delete process.env.NODE_ENV;
  const consumption = await import('../lib/http/guarded-consumption.js');
  consumption.__resetGuardedConsumptionStoreForTests();
  const mod = await import('../app/api/v1/guarded/route.js');
  return mod.POST;
}

describe('/api/v1/guarded assurance-tier enforcement', () => {
  afterEach(() => {
    delete process.env.EP_TRUSTED_ISSUER_KEYS;
    delete process.env.EP_PINNED_APPROVER_KEYS;
  });

  it('REFUSES a valid software-tier receipt for a quorum action (deploy.production)', async () => {
    const POST = await setupWith();
    const doc = mintSoftware(QUORUM_ACTION);
    const res = await POST(guardedRequest(doc, QUORUM_ACTION));
    expect(res.status).toBe(428);
    const body = await res.json();
    expect(body.allowed).toBeUndefined();
    expect(body.rejected?.reason).toMatch(/assurance_(too_low|proof_required)/);
    expect(body.rejected?.need_tier).toBe('quorum');
    expect(body.rejected?.have_tier).toBe('software');
  });

  it('REFUSES a self-asserted signoff/quorum claim with no verifiable proof (quorum action)', async () => {
    const POST = await setupWith();
    const doc = mintSelfAssertedSignoff(QUORUM_ACTION);
    const res = await POST(guardedRequest(doc, QUORUM_ACTION));
    expect(res.status).toBe(428);
    const body = await res.json();
    expect(body.rejected?.need_tier).toBe('quorum');
    expect(body.rejected?.have_tier).toBe('software');
  });

  it('REFUSES a valid software-tier receipt for a Class-A action (payment.release)', async () => {
    const POST = await setupWith();
    const doc = mintSoftware(CLASS_A_ACTION);
    const res = await POST(guardedRequest(doc, CLASS_A_ACTION));
    expect(res.status).toBe(428);
    const body = await res.json();
    expect(body.rejected?.need_tier).toBe('class_a');
    expect(body.rejected?.have_tier).toBe('software');
  });

  it('ALLOWS a proof-backed quorum receipt for a quorum action (deploy.production)', async () => {
    const harness = createEg1Harness({ action: { action_type: QUORUM_ACTION }, idPrefix: 'q' });
    const POST = await setupWith({ harness });
    const doc = harness.mint({ outcome: 'allow_with_signoff', quorum: { threshold: 2 } });
    const res = await POST(guardedRequest(doc, QUORUM_ACTION));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.allowed).toBe(true);
    expect(body.receipt_id).toBe(doc.payload.receipt_id);
  });

  it('ALLOWS a proof-backed Class-A receipt for a Class-A action (payment.release)', async () => {
    const harness = createEg1Harness({ action: { action_type: CLASS_A_ACTION }, idPrefix: 'ca' });
    const POST = await setupWith({ harness });
    const doc = harness.mint({ outcome: 'allow_with_signoff' });
    const res = await POST(guardedRequest(doc, CLASS_A_ACTION));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.allowed).toBe(true);
  });

  it('REFUSES a Class-A-only proof for a quorum action (proven tier below required)', async () => {
    // A single Class-A signoff proves class_a, not quorum. deploy.production
    // demands quorum, so this must fail closed with assurance_too_low.
    const harness = createEg1Harness({ action: { action_type: QUORUM_ACTION }, idPrefix: 'q' });
    const POST = await setupWith({ harness });
    const doc = harness.mint({ outcome: 'allow_with_signoff' }); // Class-A proof only
    const res = await POST(guardedRequest(doc, QUORUM_ACTION));
    expect(res.status).toBe(428);
    const body = await res.json();
    expect(body.rejected?.reason).toBe('assurance_too_low');
    expect(body.rejected?.need_tier).toBe('quorum');
    expect(body.rejected?.have_tier).toBe('class_a');
  });

  it('ALLOWS a plain software receipt for a pass-through action (read.status)', async () => {
    // Not receipt-required in the manifest → software tier, no proof needed.
    // (The route still verifies signature/freshness/replay.)
    const POST = await setupWith();
    const doc = mintSoftware(PASS_THROUGH);
    const res = await POST(guardedRequest(doc, PASS_THROUGH));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.allowed).toBe(true);
  });
});
