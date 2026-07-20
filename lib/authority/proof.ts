// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-PROOF-v1 — a portable, offline-verifiable snapshot of ONE
 * scoped-authority grant.
 *
 * WHY A PROOF, NOT A LOOKUP
 * A verdict alone forces the relying party to trust EP's live database at
 * verification time. That is the exact anti-pattern the admissibility doctrine
 * forbids ("Verified is not accepted; accepted requires pinned policy"). This
 * proof is a signed, self-contained statement of what the registry held for a
 * subject at authorization time: subject, role, scope, limits, validity,
 * revocation-checked-at, and the registry head/epoch it was drawn from. The
 * registry signs it under an issuer key; a relying party accepts it ONLY by
 * pinning that issuer key out of band. No pin, no acceptance.
 *
 * The signing/verification shape is deliberately identical to
 * packages/gate/reports/external-verification.js: domain-separated Ed25519 over
 * canonical bytes, a key_id RE-DERIVED from the carried public key (the
 * envelope key_id is attacker-malleable and must match), and a two-field
 * { verified, accepted } result that never collapses the crypto check into the
 * trust decision.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../canonical-json.js';

export const AUTHORITY_PROOF_VERSION = 'EP-AUTHORITY-PROOF-v1';
export const AUTHORITY_PROOF_DOMAIN = 'EP-AUTHORITY-PROOF-v1\0';

const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;
const AUTHORITY_PROOF_KEY_ID_RE = /^ep:authority-registry-key:sha256:[0-9a-f]{64}$/;

function sha256hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
function publicKeyToB64u(key) {
  return crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
}
function keyIdFor(publicKeyB64u) {
  return `ep:authority-registry-key:sha256:${sha256hex(Buffer.from(publicKeyB64u, 'base64url'))}`;
}
function signingBytes(unsignedProof) {
  return Buffer.from(AUTHORITY_PROOF_DOMAIN + canonicalize(unsignedProof), 'utf8');
}
function unsigned(proof) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) throw new Error('proof must be an object');
  const { signature: _sig, ...body } = proof;
  return body;
}

/** Digest of the signed proof body, excluding the signature envelope. */
export function authorityProofDigest(proof) {
  return `sha256:${sha256hex(signingBytes(unsigned(proof)))}`;
}

/**
 * Build and sign an EP-AUTHORITY-PROOF-v1.
 *
 * @param {object} args
 * @param {string} args.authority_id
 * @param {string} args.subject                 the approver/principal the grant is for
 * @param {string} [args.organization_id]
 * @param {string} [args.registry_issuer_id] stable identity of the registry issuer
 * @param {{head_digest:string,head_seq:number,issuer_kid:string}} [args.authority_document]
 * @param {string} args.role
 * @param {string[]} args.scope                 action scopes granted
 * @param {object} [args.limits]                { max_amount_usd, currency }
 * @param {object} [args.validity]              { from, to }
 * @param {object} [args.revocation]            { status:'not_revoked'|'revoked', checked_at, revoked_at? }
 * @param {string} args.registry_head           'sha256:...'
 * @param {number} args.registry_epoch          safe integer
 * @param {string} [args.policy_hash]
 * @param {string|number} [args.issued_at]
 * @param {crypto.KeyObject} privateKey         registry issuer Ed25519 private key
 */
export function signAuthorityProof(args, privateKey) {
  if (!privateKey) throw new Error('privateKey is required');
  const issuedAt = args?.issued_at !== undefined ? new Date(args.issued_at).toISOString() : new Date().toISOString();
  const publicKey = publicKeyToB64u(privateKey);
  const body = {
    '@type': AUTHORITY_PROOF_VERSION,
    authority_id: args?.authority_id ?? null,
    subject: args?.subject ?? null,
    ...(args?.organization_id ? { organization_id: args.organization_id } : {}),
    ...(args?.registry_issuer_id ? { registry_issuer_id: args.registry_issuer_id } : {}),
    ...(args?.authority_document ? {
      authority_document: {
        head_digest: args.authority_document.head_digest,
        head_seq: args.authority_document.head_seq,
        issuer_kid: args.authority_document.issuer_kid,
      },
    } : {}),
    role: args?.role ?? null,
    scope: Array.isArray(args?.scope) ? args.scope.map(String) : [],
    limits: {
      max_amount_usd: typeof args?.limits?.max_amount_usd === 'number' ? args.limits.max_amount_usd : null,
      currency: args?.limits?.currency ?? 'USD',
    },
    validity: {
      from: args?.validity?.from ?? null,
      to: args?.validity?.to ?? null,
    },
    revocation: {
      status: args?.revocation?.status ?? 'not_revoked',
      checked_at: args?.revocation?.checked_at ?? issuedAt,
      ...(args?.revocation?.revoked_at ? { revoked_at: args.revocation.revoked_at } : {}),
    },
    registry_head: args?.registry_head ?? null,
    registry_epoch: Number.isSafeInteger(args?.registry_epoch) ? args.registry_epoch : null,
    ...(args?.policy_hash ? { policy_hash: args.policy_hash } : {}),
    issued_at: issuedAt,
    limitations: [
      'This proof records what the authority registry held for the subject at issuance; it does not itself authorize the action.',
      'It is a snapshot: revocation.status is as of checked_at, and a later revocation is not reflected here.',
      'Acceptance requires the relying party to pin the registry issuer key out of band; verification alone is not acceptance.',
    ],
  };
  const digest = authorityProofDigest(body);
  const sig = crypto.sign(null, signingBytes(body), privateKey).toString('base64url');
  return Object.freeze({
    ...body,
    signature: {
      algorithm: 'Ed25519',
      key_id: keyIdFor(publicKey),
      public_key: publicKey,
      proof_digest: digest,
      signature_b64u: sig,
    },
  });
}

/**
 * Verify only the cryptographic integrity of an EP-AUTHORITY-PROOF-v1.
 *
 * This function deliberately performs no issuer acceptance, registry-head
 * policy, grant/action evaluation, or delegation check. It exists so an
 * Authority Document trust join can establish issuer acceptance separately
 * from proof mathematics.
 *
 * @returns {{verified:boolean,accepted:false,checks:object,reason?:string,
 *   proof_digest?:string,key_id?:string}}
 */
export function verifyAuthorityProofSignature(proof) {
  const checks = {
    version: proof?.['@type'] === AUTHORITY_PROOF_VERSION,
    proof_digest: false,
    key_id: false,
    signature: false,
  };
  const fail = (reason, extra = {}) => ({
    verified: false,
    accepted: /** @type {const} */ (false),
    checks,
    reason,
    ...extra,
  });
  if (!checks.version) return fail('unsupported_version');
  const sig = proof?.signature;
  if (!sig || sig.algorithm !== 'Ed25519'
      || typeof sig.public_key !== 'string'
      || typeof sig.signature_b64u !== 'string'
      || typeof sig.proof_digest !== 'string'
      || !SHA256_RE.test(sig.proof_digest)
      || typeof sig.key_id !== 'string'
      || !AUTHORITY_PROOF_KEY_ID_RE.test(sig.key_id)) {
    return fail('signature_missing_or_malformed');
  }
  let proofDigest;
  try {
    proofDigest = authorityProofDigest(proof);
  } catch {
    return fail('proof_uncanonicalizable');
  }
  checks.proof_digest = proofDigest === sig.proof_digest;
  if (!checks.proof_digest) return fail('proof_digest_mismatch', { proof_digest: proofDigest });
  const derivedKeyId = keyIdFor(sig.public_key);
  checks.key_id = sig.key_id === derivedKeyId;
  if (!checks.key_id) return fail('key_id_mismatch', { proof_digest: proofDigest });
  try {
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(sig.public_key, 'base64url'),
      type: 'spki',
      format: 'der',
    });
    checks.signature = publicKey.asymmetricKeyType === 'ed25519'
      && crypto.verify(
        null,
        signingBytes(unsigned(proof)),
        publicKey,
        Buffer.from(sig.signature_b64u, 'base64url'),
      );
  } catch {
    checks.signature = false;
  }
  if (!checks.signature) return fail('signature_invalid', { proof_digest: proofDigest });
  return {
    verified: true,
    accepted: false,
    checks,
    key_id: derivedKeyId,
    proof_digest: proofDigest,
  };
}

/**
 * Verify an EP-AUTHORITY-PROOF-v1 against pinned registry issuer keys.
 *
 * @param {object} proof
 * @param {object} [opts]
 * @param {Array<{issuer_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectRegistryHead]  if set, the proof's registry_head must match (equivocation check)
 * @param {number} [opts.expectMinEpoch]      if set, the proof's registry_epoch must be >= this (staleness check)
 * @returns {{verified:boolean, accepted:boolean, checks:object, reason?:string, proof_digest?:string, key_id?:string}}
 */
export function verifyAuthorityProof(proof, opts = {}) {
  opts = opts && typeof opts === 'object' ? opts : {};
  const checks = {
    version: proof?.['@type'] === AUTHORITY_PROOF_VERSION,
    signature: false,
    pinned_registry_key: false,
    proof_digest: false,
    registry_head: true,
    epoch_fresh: true,
  };
  /**
   * @param {string} reason
   * @param {{ checks?: object, proof_digest?: string }} [extra]
   * @returns {{verified:boolean, accepted:boolean, checks:object, reason?:string, proof_digest?:string}}
   */
  const fail = (reason, extra = {}) => ({ verified: false, accepted: false, checks: { ...checks, ...extra.checks }, reason, ...('proof_digest' in extra ? { proof_digest: extra.proof_digest } : {}) });

  if (proof?.['@type'] !== AUTHORITY_PROOF_VERSION) return fail('unsupported_version');

  const sig = proof.signature;
  if (!sig || sig.algorithm !== 'Ed25519' || typeof sig.public_key !== 'string' || typeof sig.signature_b64u !== 'string') {
    return fail('signature_missing_or_malformed');
  }
  if (typeof sig.proof_digest !== 'string' || !SHA256_RE.test(sig.proof_digest)) {
    return fail('proof_digest_missing_or_malformed');
  }

  let digest;
  try {
    digest = authorityProofDigest(proof);
  } catch {
    return fail('proof_uncanonicalizable');
  }
  if (digest !== sig.proof_digest) return fail('proof_digest_mismatch', { proof_digest: digest });
  checks.proof_digest = true;

  // key_id is ALWAYS re-derived from the carried public key; the envelope key_id
  // sits outside the signed bytes, so a present-but-divergent one is a refusal.
  const derivedKeyId = keyIdFor(sig.public_key);
  if (sig.key_id !== undefined && sig.key_id !== derivedKeyId) {
    return fail('key_id_mismatch', { proof_digest: digest });
  }

  // Registry-head equivocation and staleness pins (optional, relying-party set).
  if (typeof opts.expectRegistryHead === 'string' && proof.registry_head !== opts.expectRegistryHead) {
    checks.registry_head = false;
    return { verified: false, accepted: false, checks, reason: 'registry_head_mismatch', proof_digest: digest };
  }
  if (Number.isSafeInteger(opts.expectMinEpoch) && !(Number.isSafeInteger(proof.registry_epoch) && proof.registry_epoch >= /** @type {number} */ (opts.expectMinEpoch))) {
    checks.epoch_fresh = false;
    return { verified: false, accepted: false, checks, reason: 'stale_registry', proof_digest: digest };
  }

  // Pin: a usable pin must match the carried public key AND name the issuer_id it
  // vouches for (a pin grants an identity, not just a key).
  const pinned = Array.isArray(opts.pinnedRegistryKeys) ? opts.pinnedRegistryKeys : [];
  const keyMatched = pinned.filter((k) => k?.public_key === sig.public_key && (k.key_id === undefined || k.key_id === derivedKeyId));
  const pin = keyMatched.find((k) => typeof k?.issuer_id === 'string'
    && k.issuer_id.length > 0
    && k.issuer_id === proof.authority_id);
  if (!pin) {
    return { verified: false, accepted: false, checks, reason: keyMatched.length ? 'pin_mismatched_issuer' : 'registry_key_not_pinned', proof_digest: digest };
  }
  checks.pinned_registry_key = true;

  let ok = false;
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(sig.public_key, 'base64url'), type: 'spki', format: 'der' });
    ok = crypto.verify(null, signingBytes(unsigned(proof)), publicKey, Buffer.from(sig.signature_b64u, 'base64url'));
  } catch {
    ok = false;
  }
  if (!ok) return { verified: false, accepted: false, checks, reason: 'signature_invalid', proof_digest: digest };
  checks.signature = true;

  return {
    verified: true,
    accepted: true,
    checks,
    key_id: derivedKeyId,
    proof_digest: digest,
  };
}

const proofApi = {
  AUTHORITY_PROOF_VERSION,
  AUTHORITY_PROOF_DOMAIN,
  authorityProofDigest,
  signAuthorityProof,
  verifyAuthorityProofSignature,
  verifyAuthorityProof,
};
export default proofApi;
