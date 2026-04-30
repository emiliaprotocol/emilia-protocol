// SPDX-License-Identifier: Apache-2.0
//
// Shared demo trust-receipt module — used by:
//   - /r/[receiptId] (the public-facing rendered page)
//   - /api/demo/trust-receipts/[receiptId]/evidence (the public, unauth'd
//     evidence-fetch endpoint that the "verify yourself" code block targets)
//
// Two important properties:
//
//   1. Stable keypair. The Ed25519 keypair is hardcoded as a JWK so the
//      same key serves every cold-started serverless function, every
//      Vercel region, every page render. Both the page and the API
//      endpoint quote the same public key; verifyReceipt() over the
//      document the API returns will pass.
//
//      The private key is in source. This is deliberate: it is the
//      DEMO key, never used to sign anything other than the synthetic
//      Acme Industrial vendor-bank-change scenario rendered on
//      /r/example. Any production receipt is signed by an operator
//      key held in EP_OPERATOR_KEYS (env var, never in source).
//
//   2. Recursive canonicalization. The signed payload is hashed with
//      a recursive canonical-JSON function — same depth-first
//      key-sorting algorithm used by lib/guard-policies.js
//      (hashCanonicalAction) and the corrected
//      @emilia-protocol/verify@1.0.1 verifier. Nested fields (claim,
//      claim.context, claim.context.change, claim.context.risk_signals)
//      are all cryptographically bound — a buyer cannot tamper with
//      the deeply-nested vendor_id or risk_signals without the
//      signature breaking.

import crypto from 'node:crypto';

// ─── Stable demo keypair (Ed25519, JWK format, demo-only) ─────────────────

const DEMO_PRIVATE_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  d: '5wY2-Hj9wBu-DtV5cV5EuRD-ei-g9Xor8GHr4hUvnOI',
  x: 'ElZsl_xk08JOnjfQXhZCy7H1us1TrV8lzJ7-lVFgKgo',
};
const DEMO_PUBLIC_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'ElZsl_xk08JOnjfQXhZCy7H1us1TrV8lzJ7-lVFgKgo',
};

// Lazily build KeyObjects — they're cached after first use.
let _privateKeyObject = null;
let _publicKeyObject = null;
let _publicKeyBase64url = null;

function getPrivateKey() {
  if (!_privateKeyObject) {
    _privateKeyObject = crypto.createPrivateKey({ key: DEMO_PRIVATE_JWK, format: 'jwk' });
  }
  return _privateKeyObject;
}

function getPublicKey() {
  if (!_publicKeyObject) {
    _publicKeyObject = crypto.createPublicKey({ key: DEMO_PUBLIC_JWK, format: 'jwk' });
  }
  return _publicKeyObject;
}

export function getDemoPublicKeyBase64url() {
  if (!_publicKeyBase64url) {
    _publicKeyBase64url = getPublicKey().export({ type: 'spki', format: 'der' }).toString('base64url');
  }
  return _publicKeyBase64url;
}

// ─── Recursive canonical JSON (matches lib/guard-policies.js + verify@1.0.1) ─
// Same recursive algorithm: arrays preserve order, objects emit keys in
// sorted order at every depth. Calling JSON.stringify with the
// `replacer` array form (as the v1.0.0 verifier did) only sorts the top
// level — nested objects keep insertion order, breaking determinism.

export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

// ─── Build the demo receipt (cached at module load) ───────────────────────

function buildDemoReceiptInner() {
  const issuedAt = new Date('2026-04-15T22:14:08Z').toISOString();
  const expiresAt = new Date('2026-04-16T22:14:08Z').toISOString();

  // Hash the proposed-account fields rather than embed them. The receipt
  // is public — we don't print real(-ish) bank numbers.
  const beforeBank = crypto
    .createHash('sha256')
    .update('demo|routing:121000358|account:7421-9933-4421')
    .digest('hex');
  const afterBank = crypto
    .createHash('sha256')
    .update('demo|routing:063100277|account:8884-2210-9988')
    .digest('hex');

  const payload = {
    receipt_id: 'tr_example',
    issuer: 'ep_demo_treasury_v1',
    subject: 'vendor:VEND-9821',
    claim: {
      action_type: 'vendor_bank_account_change',
      outcome: 'allow_with_signoff',
      context: {
        organization: 'demo_treasury',
        vendor_id: 'VEND-9821',
        vendor_name: 'Acme Industrial LLC',
        change: {
          before_bank_hash: `sha256:${beforeBank}`,
          after_bank_hash: `sha256:${afterBank}`,
        },
        submitted_via: 'vendor_self_service_portal',
        submitter_session_hash: 'sha256:8b2f0a1c4e9d…',
        risk_signals: [
          'NEW_DESTINATION',
          'AFTER_HOURS_SUBMISSION',
          'NO_PRIOR_CHANGE_30D',
          'UNUSUAL_SUBMITTER_ASN',
        ],
        approval_policy: 'two_party_independent_approval',
        outbound_payments_pending_usd: 248750,
      },
    },
    created_at: issuedAt,
    protocol_version: 'EP-CORE-v1.0',
  };

  // Recursive canonicalize — same algorithm verify@1.0.1 uses, so a
  // buyer running verifyReceipt() over the document we return will
  // re-derive the exact same bytes and the signature will validate.
  const canonicalPayload = canonicalize(payload);
  const signatureValue = crypto
    .sign(null, Buffer.from(canonicalPayload, 'utf8'), getPrivateKey())
    .toString('base64url');

  const document = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      signer: payload.issuer,
      value: signatureValue,
      // Demo receipts are NOT registered in /.well-known/ep-keys.json —
      // that file holds operator keys for production-signed receipts.
      // Pointing demo receipts at it would mislead a buyer who follows
      // the discovery hint and finds the demo signer absent. The public
      // demo evidence endpoint (/api/demo/trust-receipts/.../evidence)
      // returns the public key inline so the verifyReceipt() flow has
      // everything it needs without external lookup.
      key_source: 'inline-demo-only',
    },
    metadata: {
      operator: 'ep_operator_emilia_primary',
      issued_at: issuedAt,
      _demo_only: true,
    },
  };

  // Page-level fields used by /r/[receiptId]/page.js renderer:
  return {
    receipt_id: 'tr_example',
    document,
    public_key: getDemoPublicKeyBase64url(),
    organization_id: 'org_demo_treasury',
    action_type: 'vendor_bank_account_change',
    decision: 'allow_with_signoff',
    enforcement_mode: 'enforce',
    expires_at: expiresAt,
    narrative: {
      headline:
        'Vendor bank-account change — fraud signals tripped, two-party approval required.',
      body:
        'On April 15, 2026 at 22:14 UTC, the vendor self-service portal received a request to change the deposit account of record for Acme Industrial LLC (vendor VEND-9821). EMILIA flagged four risk signals (new destination, after-hours, no change in 30 days, unusual submitter ASN). Policy required two independent named humans to approve before the change could be applied. With $248,750 in vendor payments scheduled to that account, no payment was released until both approvals were on record.',
      outcome:
        'Two named humans approved. Change applied. Cryptographic record below.',
    },
    risk_signals: payload.claim.context.risk_signals,
    change_hashes: payload.claim.context.change,
    payments_at_risk_usd: payload.claim.context.outbound_payments_pending_usd,
    timeline: [
      { event: 'guard.trust_receipt.created',  actor_id: 'vendor_portal_agent',     at: '2026-04-15T22:14:08Z', action: 'submit_change' },
      { event: 'eye.risk.flagged',             actor_id: 'ep_eye',                  at: '2026-04-15T22:14:08Z', action: 'flag_high_risk' },
      { event: 'guard.signoff.requested',      actor_id: 'ep_policy_engine',        at: '2026-04-15T22:14:09Z', action: 'request_two_party_approval' },
      { event: 'guard.signoff.approved',       actor_id: 'ap_controller_jane_park', at: '2026-04-15T22:32:41Z', action: 'approve_1_of_2' },
      { event: 'guard.signoff.approved',       actor_id: 'cfo_delegate_kevin_chen', at: '2026-04-15T22:48:17Z', action: 'approve_2_of_2' },
      { event: 'guard.trust_receipt.consumed', actor_id: 'vendor_master_data_svc',  at: '2026-04-15T22:48:22Z', action: 'apply_change' },
    ],
    signoff: {
      required: true,
      threshold: 'two_party_independent_approval',
      approvers: [
        { id: 'ap_controller_jane_park', role: 'AP Controller',  approved_at: '2026-04-15T22:32:41Z' },
        { id: 'cfo_delegate_kevin_chen', role: 'CFO Delegate',   approved_at: '2026-04-15T22:48:17Z' },
      ],
      approver_id: 'ap_controller_jane_park',
      approved_at: '2026-04-15T22:48:17Z',
    },
    consume: {
      consumed_at: '2026-04-15T22:48:22Z',
      consumed_by_system: 'vendor_master_data_svc',
      execution_reference_id: 'vmd_change_8E2A1F4B',
    },
    is_demo: true,
  };
}

const DEMO_RECEIPT = buildDemoReceiptInner();

export function getDemoReceipt() {
  return DEMO_RECEIPT;
}

// Slug → demo decision: accept both the marketing slug ('example') and
// the canonical receipt_id ('tr_example'). Both render the same demo.
export function isDemoReceiptId(receiptId) {
  return receiptId === 'example' || receiptId === 'tr_example';
}
