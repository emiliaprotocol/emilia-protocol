// SPDX-License-Identifier: Apache-2.0
//
// Build a cryptographically SIGNED EP-RECEIPT-v1 document from a GovGuard +
// FinGuard receipt's append-only audit_events log, so the production
// /api/v1/trust-receipts/{id}/evidence endpoint can serve a receipt that an
// offline verifier (@emilia-protocol/verify's verifyReceipt(), the pure-Python
// emilia_verify, examples/grok_guard.py) checks WITHOUT trusting the server.
//
// THE SHAPE. This mirrors the public demo endpoint (lib/demo-receipt.js):
//   { document: <signed EP-RECEIPT-v1>, public_key: <base64url SPKI DER> }
// verifyReceipt(document, public_key) re-derives canonicalize(payload) and
// checks the Ed25519 signature — the same algorithm both sides run.
//
// WHAT THE SIGNATURE ATTESTS — be precise, claim no more than is true. The
// EP server signs over the receipt's authoritative state: the EXACT canonical
// action that was hashed at receipt creation (WYSIWYS, draft §11.3 — the same
// bytes the approval surface rendered), plus the decision and the named
// approver/consume facts the immutable audit log records. The signer is the
// operator's commit signing key (EP_COMMIT_SIGNING_KEY, published as
// ep-signing-key-1). This is OPERATOR-CUSTODIED assurance (key_class C, draft
// §5.1): it proves the operator's log states this exact action was approved by
// this named human at this time, and that the operator attests to it. It is NOT
// a forgery of the human's own device signature. When a Class A (WebAuthn)
// assertion exists, the route surfaces it separately under evidence.signoff so a
// relying party can independently verify the human-held key — but the headline
// document here is the operator-attested receipt.
//
// HONESTY GATE. signEvidenceReceipt() returns null unless the receipt has
// genuinely reached a terminal positive state (approved or consumed) AND carries
// the canonical action it must sign over. A pending, denied, rejected, expired,
// or canonical-action-less receipt yields null — the route then keeps returning
// the existing unsigned ep-guard-evidence-v1 packet and fabricates NOTHING.

import crypto from 'node:crypto';
import { getCommitSigningConfig } from './env.js';
import { logger } from './logger.js';

// RFC 8410 DER prefixes for Ed25519 keys built from a 32-byte seed / raw key.
const ED25519_PKCS8_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * Recursive canonical JSON — depth-first key sort at every level. BYTE-IDENTICAL
 * to packages/verify, packages/issue, and lib/demo-receipt.js, so a verifier
 * re-derives exactly these bytes.
 */
export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(value[k]))
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

// ── Signing key ──────────────────────────────────────────────────────────────
//
// The operator's commit signing key (lib/commit.js uses the identical seed via
// getCommitSigningConfig). In production EP_COMMIT_SIGNING_KEY is REQUIRED; in
// dev/test an ephemeral key is generated so the round-trip still verifies. The
// keypair is cached for the process lifetime.

let _cachedKeypair = null;

/**
 * Resolve the Ed25519 signing keypair. Returns { privateKey, publicKeySpkiB64u }
 * or null when no key is configured AND we are in production (fail closed — we
 * never sign with an unverifiable ephemeral key in prod).
 *
 * @returns {{ privateKey: crypto.KeyObject, publicKeySpkiB64u: string } | null}
 */
export function getEvidenceSigningKeypair() {
  if (_cachedKeypair) return _cachedKeypair;

  const config = getCommitSigningConfig();

  if (config.signingKey) {
    const seed = Buffer.from(config.signingKey, 'base64');
    if (seed.length !== 32) {
      throw new Error('EP_COMMIT_SIGNING_KEY must be a base64-encoded 32-byte Ed25519 seed');
    }
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]);
    const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey(privateKey);
    const publicKeySpkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    _cachedKeypair = { privateKey, publicKeySpkiB64u };
    return _cachedKeypair;
  }

  // No key configured. In production this is fatal for trust-bearing signing —
  // refuse rather than mint an unverifiable signature. The route degrades to the
  // unsigned packet, which is the correct, honest fallback.
  if (config.isProduction) {
    logger.warn('[guard-evidence] EP_COMMIT_SIGNING_KEY absent in production — serving unsigned evidence');
    return null;
  }

  // Dev/test: an ephemeral key lets the offline round-trip verify locally.
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeySpkiB64u = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  _cachedKeypair = { privateKey, publicKeySpkiB64u };
  return _cachedKeypair;
}

/** Reset the cached keypair. For tests only. @private */
export function _resetForTesting() {
  _cachedKeypair = null;
}

// ── Receipt assembly from the audit log ──────────────────────────────────────

const POSITIVE_STATES = new Set(['approved_pending_consume', 'consumed']);

/**
 * Derive the receipt's resolved status from its events. Mirrors the read route's
 * terminal-state logic: a consume event ⇒ consumed; an approval with no rejection
 * ⇒ approved_pending_consume; a rejection ⇒ rejected; otherwise pending/issued.
 *
 * @param {object} base - the created event's after_state
 * @param {{approved?:object, rejected?:object, consumed?:object}} marks
 * @returns {string}
 */
export function resolveReceiptStatus(base, { approved, rejected, consumed }) {
  if (consumed) return 'consumed';
  if (rejected) return 'rejected';
  if (approved) return 'approved_pending_consume';
  // No signoff was ever required and a non-deny decision ⇒ already authorized.
  if (base?.signoff_required === false && base?.decision && base.decision !== 'deny') {
    return 'approved_pending_consume';
  }
  if (base?.decision === 'deny') return 'denied';
  return base?.receipt_status || 'pending_signoff';
}

/**
 * Build a signed EP-RECEIPT-v1 document for a receipt that has reached a terminal
 * positive state and carries the canonical action it must sign over. Returns
 * `{ document, public_key }` ONLY when the result genuinely verifies; otherwise
 * returns null and the caller keeps serving the unsigned packet.
 *
 * @param {object} args
 * @param {string} args.receiptId
 * @param {object} args.base - the guard.trust_receipt.created after_state
 * @param {object|null} args.approved - the guard.signoff.approved event (if any)
 * @param {object|null} args.rejected - the guard.signoff.rejected event (if any)
 * @param {object|null} args.consumed - the guard.trust_receipt.consumed event (if any)
 * @param {string} args.issuedAt - the receipt's issued_at (created_at)
 * @returns {{ document: object, public_key: string } | null}
 */
export function signEvidenceReceipt({ receiptId, base, approved, rejected, consumed, issuedAt }) {
  if (!base || typeof base !== 'object') return null;

  const status = resolveReceiptStatus(base, { approved, rejected, consumed });
  // HONESTY GATE: only sign a receipt that is genuinely authorized. Never sign a
  // pending, denied, rejected, or expired receipt.
  if (!POSITIVE_STATES.has(status)) return null;

  // WYSIWYS: the canonical action persisted at creation is the exact byte
  // sequence that was hashed and rendered. Without it we cannot honestly sign
  // (older receipts predating canonical_action persistence). Fall back to the
  // unsigned packet rather than re-describe the action.
  const canonicalAction = base.canonical_action;
  if (!canonicalAction || typeof canonicalAction !== 'object') return null;

  const keypair = getEvidenceSigningKeypair();
  if (!keypair) return null;

  const approverId = approved?.actor_id || approved?.after_state?.approver_id || null;
  const approvedAt = approved?.created_at || approved?.after_state?.decided_at || null;
  const keyClass = approved?.after_state?.key_class || null;

  // The signed payload — the receipt's authoritative, operator-attested state.
  // Every field the verifier re-canonicalizes is bound by the signature.
  const payload = {
    receipt_id: receiptId,
    issuer: 'ep_operator_emilia_primary',
    protocol_version: 'EP-CORE-v1.0',
    claim: {
      action_type: base.action_type,
      outcome: base.decision,
      enforcement_mode: base.enforcement_mode,
      // The exact canonical action that was hashed at creation (WYSIWYS).
      canonical_action: canonicalAction,
      action_hash: base.action_hash,
      before_state_hash: base.before_state_hash ?? null,
      after_state_hash: base.after_state_hash ?? null,
      policy_id: base.policy_id,
      policy_hash: base.policy_hash,
    },
    authorization: {
      status,
      signoff_required: base.signoff_required ?? null,
      approver_id: approverId,
      approved_at: approvedAt,
      // Honest assurance tier of the approval the operator is attesting to.
      approver_key_class: keyClass,
      consumed_at: consumed?.after_state?.consumed_at ?? null,
      consumed_by_system: consumed?.after_state?.consumed_by_system ?? null,
      execution_reference_id: consumed?.after_state?.execution_reference_id ?? null,
    },
    created_at: issuedAt,
    expires_at: base.expires_at ?? null,
  };

  const signatureValue = crypto
    .sign(null, Buffer.from(canonicalize(payload), 'utf8'), keypair.privateKey)
    .toString('base64url');

  const document = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      signer: payload.issuer,
      // Operator-custodied attestation over the log's authoritative state.
      // The key is discoverable at /.well-known/ep-keys.json (ep-signing-key-1).
      key_class: 'C',
      key_id: 'ep-signing-key-1',
      key_source: 'operator-commit-signing-key',
      value: signatureValue,
    },
    metadata: {
      operator: 'ep_operator_emilia_primary',
      issued_at: issuedAt,
    },
  };

  return { document, public_key: keypair.publicKeySpkiB64u };
}
