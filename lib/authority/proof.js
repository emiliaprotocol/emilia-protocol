// SPDX-License-Identifier: Apache-2.0
// Generated from proof.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
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
import { authorityInstantMs } from './authority-doc.js';
import { AUTHORITY_PROOF_V2_VERSION, AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS, authorityProofV2SignedBytes, authorityProofV2Digest, } from '../../packages/verify/authority-proof.js';
import { signAgileSet, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, } from '../../packages/verify/pq-signature-agility.js';
export const AUTHORITY_PROOF_VERSION = 'EP-AUTHORITY-PROOF-v1';
export const AUTHORITY_PROOF_DOMAIN = 'EP-AUTHORITY-PROOF-v1\0';
// ── EP-AUTHORITY-PROOF-v2 (hybrid) lockstep ─────────────────────────────────
// The v2 VERIFIER is not re-implemented here. lib/authority/proof.ts and
// packages/verify/src/authority-proof.ts are twins that must stay in lockstep;
// for v2 that lockstep is maintained BY CONSTRUCTION. The reference verifier
// lives in the published offline package (a portable authority proof must be
// checkable with the same package that checks the receipt), and this module
// re-exports it — exactly the relationship the revocation twins already have,
// and the same reason canonicalize() is composed rather than re-derived. There
// is exactly one v2 verification body in the repository and both entry points
// run it, so the two cannot drift; the test asserts the same function object.
export { AUTHORITY_PROOF_V2_VERSION, AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS, authorityProofV2SignedBytes, authorityProofV2Digest, verifyAuthorityProofV2, } from '../../packages/verify/authority-proof.js';
const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;
const AUTHORITY_PROOF_KEY_ID_RE = /^ep:authority-registry-key:sha256:[0-9a-f]{64}$/;
function sha256hex(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
function publicKeyToB64u(key) {
    // crypto.createPublicKey() accepts a private KeyObject at runtime (it derives
    // the public key from it) even though @types/node's overloads don't cover
    // this case; the cast reflects that gap, not a behavior change.
    return crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64url');
}
function keyIdFor(publicKeyB64u) {
    return `ep:authority-registry-key:sha256:${sha256hex(Buffer.from(publicKeyB64u, 'base64url'))}`;
}
function signingBytes(unsignedProof) {
    return Buffer.from(AUTHORITY_PROOF_DOMAIN + canonicalize(unsignedProof), 'utf8');
}
function unsigned(proof) {
    if (!proof || typeof proof !== 'object' || Array.isArray(proof))
        throw new Error('proof must be an object');
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
 * Issuing a new proof cannot manufacture a fresh `not_revoked` result. When
 * supplied, `checked_at` names when the authority source was actually
 * observed. When omitted, the signed proof carries `revocation: null` and
 * cannot satisfy a relying party's revocation-freshness requirement.
 *
 * @param args
 * @param privateKey  registry issuer Ed25519 private key
 */
export function signAuthorityProof(args, privateKey) {
    if (!privateKey)
        throw new Error('privateKey is required');
    const issuedAt = args?.issued_at !== undefined ? new Date(args.issued_at).toISOString() : new Date().toISOString();
    if (args?.revocation !== undefined && args.revocation !== null
        && ((args.revocation.status !== 'not_revoked'
            && args.revocation.status !== 'revoked'
            && args.revocation.status !== 'unknown')
            || !Number.isFinite(authorityInstantMs(args.revocation.checked_at)))) {
        throw new TypeError('revocation observation must carry an explicit status and checked_at instant');
    }
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
        revocation: args.revocation === undefined || args.revocation === null ? null : {
            status: args.revocation.status,
            checked_at: args.revocation.checked_at,
            ...(args.revocation.revoked_at ? { revoked_at: args.revocation.revoked_at } : {}),
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
    const signature = {
        algorithm: 'Ed25519',
        key_id: keyIdFor(publicKey),
        public_key: publicKey,
        proof_digest: digest,
        signature_b64u: sig,
    };
    return Object.freeze({
        ...body,
        signature,
    });
}
function pqRegistryKeyIdOf(rawB64u) {
    return `ep:authority-registry-key:ml-dsa-65:sha256:${crypto
        .createHash('sha256').update(Buffer.from(rawB64u, 'base64url')).digest('hex')}`;
}
function toRawB64u(value, expectedLength, label) {
    const bytes = value instanceof Uint8Array
        ? Buffer.from(value)
        : (/^[A-Za-z0-9_-]+$/.test(String(value)) ? Buffer.from(String(value), 'base64url') : Buffer.alloc(0));
    if (bytes.length !== expectedLength) {
        throw new Error(`signAuthorityProofV2: ${label} must be ${expectedLength} raw bytes (or base64url of them)`);
    }
    return bytes.toString('base64url');
}
/**
 * Build and sign an EP-AUTHORITY-PROOF-v2 under BOTH registered algorithms over
 * one set of bytes that COMMIT to the required algorithm set. THROWS rather than
 * emit a half-hybrid proof: an unavailable ML-DSA backend makes signAgileSet
 * throw, so a proof missing the PQ leg is never produced.
 */
export async function signAuthorityProofV2(args, signer, opts = {}) {
    if (!signer || !signer.privateKey || !signer.pqSecretKey || !signer.pqPublicKey) {
        throw new Error('signAuthorityProofV2 requires signer.{privateKey,pqSecretKey,pqPublicKey}');
    }
    const issuedAt = args?.issued_at !== undefined ? new Date(args.issued_at).toISOString() : new Date().toISOString();
    if (args?.revocation !== undefined && args.revocation !== null
        && ((args.revocation.status !== 'not_revoked'
            && args.revocation.status !== 'revoked'
            && args.revocation.status !== 'unknown')
            || !Number.isFinite(authorityInstantMs(args.revocation.checked_at)))) {
        throw new TypeError('revocation observation must carry an explicit status and checked_at instant');
    }
    const edPublic = publicKeyToB64u(signer.privateKey);
    const edKeyId = keyIdFor(edPublic);
    const pqPublic = toRawB64u(signer.pqPublicKey, ML_DSA_65_PUBLIC_KEY_BYTES, 'signer.pqPublicKey');
    const pqSecret = toRawB64u(signer.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'signer.pqSecretKey');
    const pqKeyId = pqRegistryKeyIdOf(pqPublic);
    const body = {
        '@type': AUTHORITY_PROOF_V2_VERSION,
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
        revocation: args.revocation === undefined || args.revocation === null ? null : {
            status: args.revocation.status,
            checked_at: args.revocation.checked_at,
            ...(args.revocation.revoked_at ? { revoked_at: args.revocation.revoked_at } : {}),
        },
        registry_head: args?.registry_head ?? null,
        registry_epoch: Number.isSafeInteger(args?.registry_epoch) ? args.registry_epoch : null,
        ...(args?.policy_hash ? { policy_hash: args.policy_hash } : {}),
        issued_at: issuedAt,
        limitations: [
            'This proof records what the authority registry held for the subject at issuance; it does not itself authorize the action.',
            'It is a snapshot: revocation.status is as of checked_at, and a later revocation is not reflected here.',
            'Acceptance requires the relying party to pin BOTH registry issuer keys (Ed25519 + ML-DSA-65) out of band; verification alone is not acceptance.',
        ],
    };
    const messageBytes = authorityProofV2SignedBytes(body, AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS);
    const signatures = await signAgileSet(new Uint8Array(messageBytes), [
        { alg: 'Ed25519', private_key: signer.privateKey, key_id: edKeyId },
        { alg: 'ML-DSA-65', private_key: pqSecret, key_id: pqKeyId },
    ], opts.deterministic === true ? { deterministic: true } : {});
    const byAlg = new Map(signatures.map((s) => [s.alg, s]));
    const ordered = AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS.map((alg) => {
        const s = byAlg.get(alg);
        if (!s)
            throw new Error(`signAuthorityProofV2: signing produced no ${alg} leg`);
        return s;
    });
    const digest = authorityProofV2Digest(body);
    return Object.freeze({
        ...body,
        signature: {
            profile: AUTHORITY_PROOF_V2_VERSION,
            required_algorithms: [...AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS],
            key_id: edKeyId,
            public_key: edPublic,
            pq_key_id: pqKeyId,
            pq_public_key: pqPublic,
            proof_digest: digest,
            signatures: ordered,
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
        accepted: false,
        checks,
        reason,
        ...extra,
    });
    if (!checks.version)
        return fail('unsupported_version');
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
    }
    catch {
        return fail('proof_uncanonicalizable');
    }
    checks.proof_digest = proofDigest === sig.proof_digest;
    if (!checks.proof_digest)
        return fail('proof_digest_mismatch', { proof_digest: proofDigest });
    const derivedKeyId = keyIdFor(sig.public_key);
    checks.key_id = sig.key_id === derivedKeyId;
    if (!checks.key_id)
        return fail('key_id_mismatch', { proof_digest: proofDigest });
    try {
        const publicKey = crypto.createPublicKey({
            key: Buffer.from(sig.public_key, 'base64url'),
            type: 'spki',
            format: 'der',
        });
        checks.signature = publicKey.asymmetricKeyType === 'ed25519'
            && crypto.verify(null, signingBytes(unsigned(proof)), publicKey, Buffer.from(sig.signature_b64u, 'base64url'));
    }
    catch {
        checks.signature = false;
    }
    if (!checks.signature)
        return fail('signature_invalid', { proof_digest: proofDigest });
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
    const fail = (reason, extra = {}) => ({
        verified: false,
        accepted: false,
        checks: { ...checks, ...extra.checks },
        reason,
        ...('proof_digest' in extra ? { proof_digest: extra.proof_digest } : {}),
    });
    if (proof?.['@type'] !== AUTHORITY_PROOF_VERSION)
        return fail('unsupported_version');
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
    }
    catch {
        return fail('proof_uncanonicalizable');
    }
    if (digest !== sig.proof_digest)
        return fail('proof_digest_mismatch', { proof_digest: digest });
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
    if (Number.isSafeInteger(opts.expectMinEpoch) && !(Number.isSafeInteger(proof.registry_epoch) && proof.registry_epoch >= opts.expectMinEpoch)) {
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
    }
    catch {
        ok = false;
    }
    if (!ok)
        return { verified: false, accepted: false, checks, reason: 'signature_invalid', proof_digest: digest };
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
