// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-PROOF-v1 — offline verifier (published-package port).
 *
 * Byte-identical port of the verify half of the reference lib/authority/proof.js,
 * so a relying party can check a portable authority proof with the same offline
 * package that checks the receipt — no EP server, no lib/ import (the published
 * verify package must resolve from its own root). Mirrors the same relationship
 * revocation.js has to lib/revocation/revocation.js. A conformance test asserts
 * this port and the reference compute the same proof_digest.
 *
 * A proof is a signed snapshot of ONE scoped-authority grant. verifyAuthorityProof
 * is FAIL-CLOSED and returns the house { verified, accepted } split, never
 * collapsed: `verified` = the Ed25519 signature and digest hold; `accepted` =
 * verified AND the registry issuer key was pinned out of band by the relying
 * party (and any head/epoch freshness pins are satisfied).
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';

export const AUTHORITY_PROOF_VERSION = 'EP-AUTHORITY-PROOF-v1';
export const AUTHORITY_PROOF_DOMAIN = 'EP-AUTHORITY-PROOF-v1\0';

const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;

function sha256hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
function keyIdFor(publicKeyB64u) {
  return `ep:authority-registry-key:sha256:${sha256hex(Buffer.from(publicKeyB64u, 'base64url')).slice(0, 16)}`;
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
 * Verify an EP-AUTHORITY-PROOF-v1 against pinned registry issuer keys.
 * @param {object} proof
 * @param {object} opts
 * @param {Array<{issuer_id:string,key_id?:string,public_key:string}>} opts.pinnedRegistryKeys
 * @param {string} [opts.expectRegistryHead]  proof.registry_head must equal this (equivocation)
 * @param {number} [opts.expectMinEpoch]      proof.registry_epoch must be >= this (staleness)
 * @returns {{verified:boolean, accepted:boolean, checks:object, reason?:string, proof_digest?:string}}
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

  const derivedKeyId = keyIdFor(sig.public_key);
  if (sig.key_id !== undefined && sig.key_id !== derivedKeyId) {
    return fail('key_id_mismatch', { proof_digest: digest });
  }

  if (typeof opts.expectRegistryHead === 'string' && proof.registry_head !== opts.expectRegistryHead) {
    checks.registry_head = false;
    return { verified: false, accepted: false, checks, reason: 'registry_head_mismatch', proof_digest: digest };
  }
  if (Number.isSafeInteger(opts.expectMinEpoch) && !(Number.isSafeInteger(proof.registry_epoch) && proof.registry_epoch >= opts.expectMinEpoch)) {
    checks.epoch_fresh = false;
    return { verified: false, accepted: false, checks, reason: 'stale_registry', proof_digest: digest };
  }

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

  return { verified: true, accepted: true, checks, key_id: derivedKeyId, proof_digest: digest };
}
