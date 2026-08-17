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
import { verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, } from './pq-signature-agility.js';
export const AUTHORITY_PROOF_VERSION = 'EP-AUTHORITY-PROOF-v1';
export const AUTHORITY_PROOF_DOMAIN = 'EP-AUTHORITY-PROOF-v1\0';
const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;
const AUTHORITY_PROOF_KEY_ID_RE = /^ep:authority-registry-key:sha256:[0-9a-f]{64}$/;
function sha256hex(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
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
 * Verify an EP-AUTHORITY-PROOF-v1 against pinned registry issuer keys.
 * @param {object} proof
 * @param {object} opts
 * @param {Array<{issuer_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectRegistryHead]  proof.registry_head must equal this (equivocation)
 * @param {number} [opts.expectMinEpoch]      proof.registry_epoch must be >= this (staleness)
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
    /** @param {string} reason @param {{checks?:object, proof_digest?:string}} [extra] */
    const fail = (reason, extra = {}) => ({ verified: false, accepted: false, checks: { ...checks, ...extra.checks }, reason, ...('proof_digest' in extra ? { proof_digest: extra.proof_digest } : {}) });
    if (proof?.['@type'] !== AUTHORITY_PROOF_VERSION)
        return fail('unsupported_version');
    const sig = proof.signature;
    if (!sig || sig.algorithm !== 'Ed25519'
        || typeof sig.public_key !== 'string'
        || typeof sig.signature_b64u !== 'string'
        || typeof sig.key_id !== 'string'
        || !AUTHORITY_PROOF_KEY_ID_RE.test(sig.key_id)) {
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
    const derivedKeyId = keyIdFor(sig.public_key);
    if (sig.key_id !== undefined && sig.key_id !== derivedKeyId) {
        return fail('key_id_mismatch', { proof_digest: digest });
    }
    if (typeof opts.expectRegistryHead === 'string' && proof.registry_head !== opts.expectRegistryHead) {
        checks.registry_head = false;
        return { verified: false, accepted: false, checks, reason: 'registry_head_mismatch', proof_digest: digest };
    }
    const registryEpoch = typeof proof.registry_epoch === 'number' ? proof.registry_epoch : NaN;
    const minimumEpoch = opts.expectMinEpoch;
    if (typeof minimumEpoch === 'number' && Number.isSafeInteger(minimumEpoch)
        && !(Number.isSafeInteger(registryEpoch) && registryEpoch >= minimumEpoch)) {
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
        const publicKey = crypto.createPublicKey({ key: Buffer.from(String(sig.public_key), 'base64url'), type: 'spki', format: 'der' });
        ok = crypto.verify(null, signingBytes(unsigned(proof)), publicKey, Buffer.from(String(sig.signature_b64u), 'base64url'));
    }
    catch {
        ok = false;
    }
    if (!ok)
        return { verified: false, accepted: false, checks, reason: 'signature_invalid', proof_digest: digest };
    checks.signature = true;
    return { verified: true, accepted: true, checks, key_id: derivedKeyId, proof_digest: digest };
}
// ===========================================================================
// EP-AUTHORITY-PROOF-v2 -- the hybrid (Ed25519 + ML-DSA-65) authority proof
// ===========================================================================
/**
 * HYBRID MIGRATION of EP-AUTHORITY-PROOF, following the reference pattern in
 * docs/protocol/pq-hybrid-program.md ("PATTERN: the reference hybrid
 * migration") and packages/verify/src/revocation.ts's EP-REVOCATION-v2. Five
 * moving parts, in order:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the `signature` block, which is a wire-format change, so the artifact
 *    takes a new `@type` (EP-AUTHORITY-PROOF-v1 -> EP-AUTHORITY-PROOF-v2). The
 *    v1 verifiers above are untouched and refuse a v2 proof on the version
 *    marker BEFORE inspecting any signature (`unsupported_version`): a deployed
 *    v1 verifier must never accept a hybrid proof on the strength of the one
 *    leg it understands, and it must not crash.
 * 2. SET SHAPE. `signature` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm in the registered order.
 *    Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65 carries raw
 *    base64url public key bytes.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes (authorityProofV2SignedBytes below). Drop the ML-DSA leg and narrow
 *    `required_algorithms` and the surviving Ed25519 signature no longer
 *    verifies, because the bytes changed. The verifier rebuilds the bytes from
 *    the REGISTERED set and the fields it recomputed, never from what the proof
 *    claims. This is a byte-level commitment, strictly stronger than
 *    EP-SIG-AGILITY-v1's `hybrid_all` policy alone.
 * 4. V1 COMPATIBILITY. v1 proofs keep verifying through the unchanged
 *    synchronous verifiers. v2 verification is ASYNC (ML-DSA verification is
 *    async), so it is a SEPARATE entry point rather than a signature change to
 *    the v1 function.
 * 5. NAMED REFUSALS. Every failure sets a named check false and pushes a
 *    readable reason; nothing throws on caller input. An absent ML-DSA backend
 *    is `pq_backend_unavailable` surfaced through the agility result, never a
 *    skipped check and never a pass on the classical leg.
 *
 * HOUSE SPLIT PRESERVED. The { verified, accepted } split is not collapsed:
 * `verified` = both signatures hold over the recomputed bytes; `accepted` =
 * verified AND both registry issuer halves were pinned out of band for the
 * proof's authority_id (and any head/epoch freshness pins are satisfied).
 *
 * HONEST BOUNDARIES. The ML-DSA backend is @noble/post-quantum's pure-JS
 * FIPS 204 implementation, which is not independently audited and is not a FIPS
 * validated module; verifying under this profile is not a certification claim.
 * v2 does NOT retroactively protect proofs already signed under v1.
 */
export const AUTHORITY_PROOF_V2_VERSION = 'EP-AUTHORITY-PROOF-v2';
export const AUTHORITY_PROOF_V2_DOMAIN = 'EP-AUTHORITY-PROOF-v2\0';
/** The registered required algorithm set, in canonical order. */
export const AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
const AUTHORITY_PROOF_PQ_KEY_ID_RE = /^ep:authority-registry-key:ml-dsa-65:sha256:[0-9a-f]{64}$/;
const AUTHORITY_PROOF_V2_SIGNATURE_KEYS = new Set([
    'profile', 'required_algorithms', 'key_id', 'public_key',
    'pq_key_id', 'pq_public_key', 'proof_digest', 'signatures',
]);
function exactKeys(value, allowed) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === allowed.size
        && Object.keys(value).every((key) => allowed.has(key));
}
function algorithmSetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS[i]);
}
/** ML-DSA-65 registry-key identifier: the SHA-256 of the raw public key bytes. */
function pqKeyIdFor(publicKeyRawB64u) {
    try {
        if (typeof publicKeyRawB64u !== 'string' || publicKeyRawB64u.length === 0)
            return '';
        const raw = Buffer.from(publicKeyRawB64u, 'base64url');
        if (raw.length !== ML_DSA_65_PUBLIC_KEY_BYTES || raw.toString('base64url') !== publicKeyRawB64u)
            return '';
        return `ep:authority-registry-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(raw).digest('hex')}`;
    }
    catch {
        return '';
    }
}
/**
 * The bytes BOTH legs sign: the domain tag, the unsigned proof body, and the
 * registered `required_algorithms` set. Exported so the lib issuer produces
 * byte-identical material to what this verifier recomputes (the same discipline
 * revocation.ts uses via revocationV2SignedPayload). canonicalize() sorts keys.
 */
export function authorityProofV2SignedBytes(unsignedBody, requiredAlgorithms = AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS) {
    if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
        throw new Error('authorityProofV2SignedBytes: algorithm set is not the registered EP-AUTHORITY-PROOF-v2 set');
    }
    return Buffer.from(AUTHORITY_PROOF_V2_DOMAIN + canonicalize({ ...unsignedBody, required_algorithms: [...requiredAlgorithms] }), 'utf8');
}
/** Digest of the v2 signed body, excluding the signature envelope. */
export function authorityProofV2Digest(proof) {
    return `sha256:${sha256hex(authorityProofV2SignedBytes(unsigned(proof)))}`;
}
/**
 * verifyAuthorityProofV2 -- FAIL-CLOSED hybrid authority-proof check. Never
 * throws on caller input. `verified` requires both legs to verify over the
 * recomputed bytes under the pinned keys; `accepted` additionally requires the
 * issuer pin (both halves) to name the proof's authority_id.
 */
export async function verifyAuthorityProofV2(proof, opts = {}) {
    opts = opts && typeof opts === 'object' ? opts : {};
    const checks = {
        version: true,
        structure: true,
        algorithm_set: true,
        legs_present: true,
        proof_digest: true,
        registry_head: true,
        epoch_fresh: true,
        pinned_registry_key: true,
        signature: true,
    };
    const errors = [];
    const fail = (key, msg) => { checks[key] = false; errors.push(msg); };
    const done = (extra = {}) => {
        const verified = Object.values(checks).every(Boolean);
        return {
            verified,
            accepted: verified,
            checks,
            ...(errors.length ? { reason: errors[0] } : {}),
            ...extra,
        };
    };
    if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
        fail('signature', 'no authority proof presented (fail-closed)');
        return { verified: false, accepted: false, checks, reason: errors[0] };
    }
    // 1. Version marker. A v1 proof handed here refuses on the marker, the
    //    mirror image of the v1 verifiers refusing a v2 proof.
    if (proof['@type'] !== AUTHORITY_PROOF_V2_VERSION) {
        fail('version', `unsupported_version: ${String(proof['@type'])}`);
    }
    const sig = (proof.signature || null);
    if (!exactKeys(sig, AUTHORITY_PROOF_V2_SIGNATURE_KEYS)) {
        fail('structure', 'authority proof signature must use the exact closed EP-AUTHORITY-PROOF-v2 schema');
    }
    if (sig?.profile !== AUTHORITY_PROOF_V2_VERSION) {
        fail('structure', `authority proof signature profile must be ${AUTHORITY_PROOF_V2_VERSION}`);
    }
    // 2. Committed algorithm set: exact and order-sensitive.
    if (!algorithmSetMatchesRegistered(sig?.required_algorithms)) {
        fail('algorithm_set', `signature.required_algorithms must be exactly ${JSON.stringify([...AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
    }
    // 3. Exactly one signature per required algorithm; no duplicates, no strays.
    const signatures = Array.isArray(sig?.signatures) ? sig.signatures : null;
    if (!signatures || signatures.length === 0) {
        fail('legs_present', 'signature.signatures must carry one signature per required algorithm');
    }
    else {
        const presented = new Set();
        let malformed = false;
        for (const s of signatures) {
            if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
                fail('legs_present', 'each signature entry must be { alg, sig, key_id? }');
                malformed = true;
                break;
            }
            if (presented.has(s.alg)) {
                fail('legs_present', `duplicate signature for algorithm "${s.alg}"`);
                malformed = true;
                break;
            }
            presented.add(s.alg);
        }
        if (!malformed) {
            for (const alg of AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS) {
                if (!presented.has(alg))
                    fail('legs_present', `missing required ${alg} signature (leg stripped)`);
            }
            for (const alg of presented) {
                if (!AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS.includes(alg)) {
                    fail('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
                }
            }
        }
    }
    // 4. Key identifiers: re-derived from the carried public keys, never trusted
    //    from the envelope. keyIdFor() curve-pins the Ed25519 key (a non-Ed25519
    //    SPKI produces a key type this port cannot derive an id for).
    const presentedEdKey = typeof sig?.public_key === 'string' ? sig.public_key : '';
    const presentedPqKey = typeof sig?.pq_public_key === 'string' ? sig.pq_public_key : '';
    let derivedKeyId = '';
    try {
        if (presentedEdKey) {
            const edObj = crypto.createPublicKey({ key: Buffer.from(presentedEdKey, 'base64url'), type: 'spki', format: 'der' });
            if (edObj.asymmetricKeyType === 'ed25519')
                derivedKeyId = keyIdFor(presentedEdKey);
        }
    }
    catch {
        derivedKeyId = '';
    }
    const derivedPqKeyId = pqKeyIdFor(presentedPqKey);
    if (!derivedKeyId
        || !AUTHORITY_PROOF_KEY_ID_RE.test(typeof sig?.key_id === 'string' ? sig.key_id : '')
        || sig?.key_id !== derivedKeyId) {
        fail('structure', 'signature.key_id must be the full SPKI digest of the presented Ed25519 registry key');
    }
    if (!derivedPqKeyId
        || !AUTHORITY_PROOF_PQ_KEY_ID_RE.test(typeof sig?.pq_key_id === 'string' ? sig.pq_key_id : '')
        || sig?.pq_key_id !== derivedPqKeyId) {
        fail('structure', 'signature.pq_key_id must be the full digest of the presented ML-DSA-65 registry key');
    }
    // 5. proof_digest: recompute over body + registered set; the presented digest
    //    sits outside the signed bytes, so a divergent one is a refusal.
    let digest = null;
    try {
        digest = authorityProofV2Digest(proof);
    }
    catch {
        digest = null;
    }
    if (!digest) {
        fail('proof_digest', 'authority proof body is not canonicalizable');
    }
    else if (typeof sig?.proof_digest !== 'string' || !SHA256_RE.test(sig.proof_digest) || sig.proof_digest !== digest) {
        fail('proof_digest', 'proof_digest is missing, malformed, or does not match the recomputed body digest');
    }
    // 6. Registry-head equivocation and staleness pins (optional, relying-party set).
    if (typeof opts.expectRegistryHead === 'string' && proof.registry_head !== opts.expectRegistryHead) {
        fail('registry_head', 'registry_head_mismatch');
    }
    if (Number.isSafeInteger(opts.expectMinEpoch)
        && !(Number.isSafeInteger(proof.registry_epoch) && proof.registry_epoch >= opts.expectMinEpoch)) {
        fail('epoch_fresh', 'stale_registry');
    }
    // 7. Pin: a usable pin names the proof's authority_id and carries BOTH halves,
    //    each equal to the presented one. No pin, or half a pin, confers nothing.
    const pinned = Array.isArray(opts.pinnedRegistryKeys) ? opts.pinnedRegistryKeys : [];
    const pin = pinned.find((k) => k
        && typeof k.issuer_id === 'string' && k.issuer_id.length > 0
        && k.issuer_id === proof.authority_id
        && k.public_key === presentedEdKey
        && k.pq_public_key === presentedPqKey
        && (k.key_id === undefined || k.key_id === derivedKeyId)
        && (k.pq_key_id === undefined || k.pq_key_id === derivedPqKeyId));
    if (!pin) {
        fail('pinned_registry_key', 'registry issuer Ed25519 + ML-DSA-65 key pair is not pinned for this authority_id (verified is not accepted)');
    }
    // 8. Signature set: both legs, over bytes rebuilt from the presented body and
    //    the REGISTERED set, under the PINNED keys only. Policy hybrid_all with
    //    requiredAlgorithms pinned to the full set, so a missing leg never passes.
    let recomputedBytes = null;
    try {
        recomputedBytes = authorityProofV2SignedBytes(unsigned(proof), AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS);
    }
    catch {
        recomputedBytes = null;
    }
    if (!recomputedBytes) {
        fail('signature', 'authority proof body is not canonicalizable');
        return done({ ...(digest ? { proof_digest: digest } : {}) });
    }
    const verificationKeys = [
        { alg: 'Ed25519', public_key: pin?.public_key ?? '', key_id: derivedKeyId || undefined },
        { alg: 'ML-DSA-65', public_key: pin?.pq_public_key ?? '', key_id: derivedPqKeyId || undefined },
    ];
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(recomputedBytes), signatures ?? [], verificationKeys, {
            ...agilityPassthrough(opts),
            policy: 'hybrid_all',
            requiredAlgorithms: [...AUTHORITY_PROOF_V2_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        setResult = null;
    }
    if (setResult?.verified !== true) {
        const reason = String(setResult?.reason ?? 'signature_set_unverified');
        fail('signature', `registry signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
    }
    return done({
        ...(digest ? { proof_digest: digest } : {}),
        ...(derivedKeyId ? { key_id: derivedKeyId } : {}),
        ...(derivedPqKeyId ? { pq_key_id: derivedPqKeyId } : {}),
    });
}
function agilityPassthrough(opts) {
    const out = {};
    if (opts.mldsaBackend !== undefined)
        out.mldsaBackend = opts.mldsaBackend;
    if (opts.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = opts.mldsaBackendLoader;
    return out;
}
//# sourceMappingURL=authority-proof.js.map