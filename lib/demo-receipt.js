// SPDX-License-Identifier: Apache-2.0
//
// Shared demo trust-receipt module — used by:
//   - /r/[receiptId] (the public-facing rendered page)
//   - /api/demo/trust-receipts/[receiptId]/evidence (the public, unauth'd
//     evidence-fetch endpoint that the "verify yourself" code block targets)
//
// Three important properties:
//
//   1. The public /r/example receipt is a signed fixture. Only its public key
//      and signature are committed; no private key is present in source.
//      This keeps the page and unauthenticated evidence endpoint stable across
//      cold starts and regions without turning the repository into a signer.
//
//      Dynamic crash-test receipts use EP_DEMO_SIGNING_KEY in production. A
//      missing production key fails closed; development/test uses a process-
//      local ephemeral key and exposes its matching public key explicitly.
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
import { getDemoSigningKey, isProduction } from './env.js';
import { privateKeyFromSeedB64 } from './key-custody.js';

// Public-only signature material for the synthetic /r/example fixture. The
// corresponding private key is intentionally not retained anywhere in the
// repository or runtime. Dynamic demo artifacts use the separate runtime key
// below and return its matching public key.
const DEMO_FIXTURE_PUBLIC_KEY_SPKI_B64U = 'MCowBQYDK2VwAyEAeEhbhyXqpDaWwF8DZ4nLswNZCa7u2yh-2N42ruZZVHg';
const DEMO_FIXTURE_SIGNATURE_B64U = 'DKFBYPBSoCeoj7rpUmpNbQiO4dKhce4vUsgrgi6h9VXt_fYrFJbKnFj5hDuJrshbv0v8zj9yLBZxpJPLJJsPCQ';

let _runtimeKeypair = null;

function getRuntimeKeypair() {
  if (_runtimeKeypair) return _runtimeKeypair;

  const configuredSeed = getDemoSigningKey();
  if (configuredSeed) {
    const privateKey = privateKeyFromSeedB64(configuredSeed);
    _runtimeKeypair = { privateKey, publicKey: crypto.createPublicKey(privateKey) };
    return _runtimeKeypair;
  }

  if (isProduction()) {
    const error = new Error(
      'EP_DEMO_SIGNING_KEY is required in production for dynamic demo receipts; refusing to sign with source or an implicit fallback.',
    );
    error.code = 'demo_signing_key_required';
    throw error;
  }

  _runtimeKeypair = crypto.generateKeyPairSync('ed25519');
  return _runtimeKeypair;
}

/** Public key for the stable, public-only /r/example fixture. */
export function getDemoPublicKeyBase64url() {
  return DEMO_FIXTURE_PUBLIC_KEY_SPKI_B64U;
}

/** Public key matching dynamic crash-test signatures. */
export function getDemoRuntimePublicKeyBase64url() {
  return getRuntimeKeypair().publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
}

// Sign an arbitrary synthetic payload with deployment-held demo material.
// This is never a production authorization signer; it exists only for the
// public crash-test surface and fails closed when production is misconfigured.
export function signDemoPayload(payload) {
  const canonical = canonicalize(payload);
  return crypto.sign(null, Buffer.from(canonical, 'utf8'), getRuntimeKeypair().privateKey).toString('base64url');
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
  // re-derive the exact same bytes and the fixture signature will validate.
  const canonicalPayload = canonicalize(payload);
  // Keep the public demo receipt stable without retaining a signing key.
  // `DEMO_FIXTURE_SIGNATURE_B64U` was generated offline for this exact payload.
  const signatureValue = DEMO_FIXTURE_SIGNATURE_B64U;

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
