// SPDX-License-Identifier: Apache-2.0
//
// Build a cryptographically SIGNED EP-RECEIPT-v1 document from a GovGuard +
// FinGuard receipt's append-only audit_events log, so the production
// /api/v1/trust-receipts/{id}/evidence endpoint can serve a receipt that an
// offline verifier (@emilia-protocol/verify's verifyReceipt(), the pure-Python
// emilia_verify, examples/executor_approval_gate.py) checks WITHOUT trusting the server.
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
import { hybridReceiptSignedBytes, HYBRID_RECEIPT_PROFILE, HYBRID_RECEIPT_REQUIRED_ALGORITHMS } from '@emilia-protocol/verify/receipt-hybrid';
import { canonicalize as canonicalizeProtocol } from './canonical-json.js';
import { getCommitSigningConfig } from './env.js';
import {
  getRegisteredCustodySigner,
  isHybridCustodySigner,
  resolveHybridPublicKeys,
  type CustodySignatureSetEntry,
  type HybridCustodySigner,
} from './key-custody.js';
import { logger } from './logger.js';

// RFC 8410 DER prefixes for Ed25519 keys built from a 32-byte seed / raw key.
const ED25519_PKCS8_DER_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * Recursive canonical JSON — depth-first key sort at every level. BYTE-IDENTICAL
 * to packages/verify, packages/issue, and lib/demo-receipt.js, so a verifier
 * re-derives exactly these bytes.
 */
export function canonicalize(value) {
  return canonicalizeProtocol(value);
}

// ── Signing key ──────────────────────────────────────────────────────────────
//
// The operator's commit signing key (lib/commit.js uses the identical seed via
// getCommitSigningConfig). In production EP_COMMIT_SIGNING_KEY is REQUIRED; in
// dev/test an ephemeral key is generated so the round-trip still verifies. The
// keypair is cached for the process lifetime.

type EvidenceSigningKeypair = { privateKey: crypto.KeyObject; publicKeySpkiB64u: string };

let _cachedKeypair: EvidenceSigningKeypair | null = null;

/**
 * Resolve the Ed25519 signing keypair. Returns { privateKey, publicKeySpkiB64u }
 * or null when no key is configured AND we are in production (fail closed — we
 * never sign with an unverifiable ephemeral key in prod).
 *
 * @returns {{ privateKey: crypto.KeyObject, publicKeySpkiB64u: string } | null}
 */
export function getEvidenceSigningKeypair(): EvidenceSigningKeypair | null {
  if (_cachedKeypair) return _cachedKeypair;

  const config = getCommitSigningConfig();

  if (config.signingKey) {
    const seed = Buffer.from(config.signingKey, 'base64');
    if (seed.length !== 32) {
      throw new Error('EP_COMMIT_SIGNING_KEY must be a base64-encoded 32-byte Ed25519 seed');
    }
    const pkcs8Der = Buffer.concat([ED25519_PKCS8_DER_PREFIX, seed]);
    const privateKey = crypto.createPrivateKey({ key: pkcs8Der, format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey(privateKey as unknown as crypto.PublicKeyInput);
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
  const payload = evidenceReceiptPayload({ receiptId, base, approved, rejected, consumed, issuedAt });
  if (!payload) return null;

  const keypair = getEvidenceSigningKeypair();
  if (!keypair) return null;

  let signedBytes;
  try {
    signedBytes = Buffer.from(canonicalize(payload), 'utf8');
  } catch {
    return null;
  }
  const signatureValue = crypto
    .sign(null, signedBytes, keypair.privateKey)
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

/**
 * The signed payload and every honesty gate in front of it, built ONCE so the
 * classical and the hybrid path cannot drift on WHICH receipts they are willing
 * to sign. Returns null (never throws) when the receipt has not genuinely
 * reached a terminal positive state or lacks the canonical action it must sign
 * over — the caller then keeps serving the unsigned packet and fabricates
 * nothing.
 *
 * The payload is IDENTICAL under both profiles. What differs is the envelope
 * that carries it and the bytes the signatures cover: the classical path signs
 * canonicalize(payload), the hybrid path signs the EP-RECEIPT-HYBRID-v1 signed
 * material which wraps that same payload alongside the required algorithm set.
 */
function evidenceReceiptPayload({ receiptId, base, approved, rejected, consumed, issuedAt }) {
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

  const approverId = approved?.actor_id || approved?.after_state?.approver_id || null;
  const approvedAt = approved?.created_at || approved?.after_state?.decided_at || null;
  const keyClass = approved?.after_state?.key_class || null;

  // The signed payload — the receipt's authoritative, operator-attested state.
  // Every field the verifier re-canonicalizes is bound by the signature.
  return {
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
}

// ── EP-RECEIPT-HYBRID-v1 evidence (OPT-IN post-quantum leg) ──────────────────
//
// signEvidenceReceipt() above is unchanged, still synchronous, and still emits
// the flat-signature EP-RECEIPT-v1 the /evidence route serves and every
// deployed offline verifier reads. The hybrid path is a SEPARATE, ASYNC entry
// point (ML-DSA signing is async) under a NEW version marker: a deployed
// EP-RECEIPT-v1 verifier handed a hybrid evidence receipt refuses on
// `Unsupported version: EP-RECEIPT-HYBRID-v1` BEFORE inspecting any signature,
// and does not crash. It never accepts the document on the strength of the one
// leg it understands.
//
// WHERE THE SECOND KEY COMES FROM. Not from a new env variable and not from a
// key this module mints. It comes from the process-wide dual-signer registered
// through lib/key-custody.ts (createHybridCustodySigner), the same seam
// lib/commit.ts uses for EP-COMMIT-HYBRID-v1. With no hybrid signer registered
// this function returns null and the caller keeps serving whatever it served
// before; it never falls back to signing one leg and calling it hybrid.
//
// THE CUSTODY BOUNDARY IS NOT SYMMETRIC, AND THAT IS RECORDED, NOT SMOOTHED
// OVER. The Ed25519 leg may sit behind Vault Transit or a PKCS#11 HSM. The PQ
// leg may use the bundled software backend or the external signer contract,
// including the AWS KMS adapter. The declared custody label is not verified by
// this code, no live AWS interop result exists, and neither path makes the
// ML-DSA operation FIPS validated. Serving this document is not a certification
// claim, and this profile is not on in any deployment.
//
// ANTI-STRIPPING IS NOT REIMPLEMENTED HERE. The bytes both legs sign come from
// @emilia-protocol/verify's hybridReceiptSignedBytes(), which wraps the payload
// with the profile id and the required algorithm SET, so dropping the ML-DSA leg
// and narrowing the set breaks the surviving Ed25519 signature. This module
// supplies the payload and the signer; it owns no crypto and no pins.

/** The public halves a relying party pins to verify a hybrid evidence receipt. */
export interface HybridEvidenceVerificationKeys {
  ed25519PublicKey: string;
  ed25519KeyId: string;
  mldsaPublicKey: string;
  mldsaKeyId: string;
}

export interface HybridEvidenceReceiptResult {
  document: {
    '@version': string;
    profile: { id: string; required_algorithms: string[] };
    payload: Record<string, unknown>;
    signatures: CustodySignatureSetEntry[];
    metadata: Record<string, unknown>;
  };
  verification_keys: HybridEvidenceVerificationKeys;
}

/**
 * Build an EP-RECEIPT-HYBRID-v1 evidence receipt for a receipt that has reached
 * a terminal positive state, signed under BOTH Ed25519 and ML-DSA-65 through the
 * registered dual-signer custody seam.
 *
 * Returns null — never a partial or downgraded document — when any of the
 * following holds: the receipt is not in a terminal positive state, it lacks the
 * canonical action, no dual-signer is registered, or either public half is
 * unpublishable (a relying party who cannot be told what to pin has been handed
 * nothing verifiable, so handing them a document would be worse than handing
 * them none).
 *
 * A thrown signer is also null, not a partial document: the ML-DSA leg's signer
 * throws when no backend is available, and a missing backend must never become a
 * pass on the classical leg.
 */
export async function signEvidenceReceiptHybrid({ receiptId, base, approved, rejected, consumed, issuedAt }): Promise<HybridEvidenceReceiptResult | null> {
  const payload = evidenceReceiptPayload({ receiptId, base, approved, rejected, consumed, issuedAt });
  if (!payload) return null;

  const registered = getRegisteredCustodySigner();
  if (!isHybridCustodySigner(registered)) {
    logger.warn('[guard-evidence] no EP-CUSTODY-HYBRID-v1 signer registered — refusing to mint a hybrid evidence receipt');
    return null;
  }
  const signer = registered as HybridCustodySigner;

  const keys = await resolveHybridPublicKeys(signer);
  if (!keys.ed25519PublicKeySpkiB64u || !keys.mldsaPublicKeyRawB64u) {
    logger.warn('[guard-evidence] hybrid signer cannot publish both public halves — refusing to mint an unpinnable receipt');
    return null;
  }

  let signatures: CustodySignatureSetEntry[];
  try {
    const messageBytes = hybridReceiptSignedBytes(payload, HYBRID_RECEIPT_REQUIRED_ALGORITHMS);
    signatures = await signer.signSet(messageBytes, {
      profile: HYBRID_RECEIPT_PROFILE,
      receipt_id: receiptId,
    });
  } catch (error) {
    logger.warn('[guard-evidence] hybrid signing refused — serving no hybrid receipt', {
      reason: error instanceof Error ? error.message : String(error),
    });
    return null;
  }

  // Order the emitted signatures to match the committed set, so the document
  // reads the same way the bytes commit. A missing leg is a refusal.
  const byAlg = new Map(signatures.map((s) => [s?.alg, s]));
  const ordered: CustodySignatureSetEntry[] = [];
  for (const alg of HYBRID_RECEIPT_REQUIRED_ALGORITHMS) {
    const s = byAlg.get(alg as CustodySignatureSetEntry['alg']);
    if (!s || typeof s.sig !== 'string') {
      logger.warn(`[guard-evidence] hybrid signing produced no ${alg} leg — refusing to serve a half-hybrid receipt`);
      return null;
    }
    ordered.push(s);
  }

  return {
    document: {
      '@version': HYBRID_RECEIPT_PROFILE,
      profile: { id: HYBRID_RECEIPT_PROFILE, required_algorithms: [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS] },
      payload,
      signatures: ordered,
      // UNSIGNED, exactly as in the EP-RECEIPT-v1 envelope. Nothing a relying
      // party authorizes on may live here.
      metadata: {
        operator: 'ep_operator_emilia_primary',
        issued_at: issuedAt,
      },
    },
    verification_keys: {
      ed25519PublicKey: keys.ed25519PublicKeySpkiB64u,
      ed25519KeyId: keys.ed25519KeyId,
      mldsaPublicKey: keys.mldsaPublicKeyRawB64u,
      mldsaKeyId: keys.mldsaKeyId,
    },
  };
}
