// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
import { signAgileSet, verifyAgileSignatureSet, ML_DSA_65_PUBLIC_KEY_BYTES, } from '@emilia-protocol/verify/pq-signature-agility';
export const RISK_DIGEST = /^sha256:[0-9a-f]{64}$/;
export const RISK_CAID = /^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:jcs-sha256:[A-Za-z0-9_-]{43}$/;
export const RISK_ID = /^[A-Za-z0-9][A-Za-z0-9:_.@/+\-]{0,511}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;
export function riskRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null)
        return false;
    return Reflect.ownKeys(value).every((key) => {
        if (typeof key !== 'string')
            return false;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
    });
}
export function riskExact(value, keys) {
    return riskRecord(value) && Reflect.ownKeys(value).length === keys.length
        && keys.every((key) => Object.hasOwn(value, key));
}
export function riskIdentifier(value) {
    return typeof value === 'string' && RISK_ID.test(value);
}
export function riskInstant(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339);
    if (!match)
        return NaN;
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed))
        return NaN;
    return new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19) ? parsed : NaN;
}
export function riskDigest(value) {
    return `sha256:${hashCanonical(value)}`;
}
export function riskClone(value) {
    return JSON.parse(canonicalize(value));
}
export function riskFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    Object.freeze(value);
    for (const child of Object.values(value))
        riskFreeze(child);
    return value;
}
function signingBytes(version, body) {
    return Buffer.from(`${version}\0${canonicalize(body)}`, 'utf8');
}
export function signRiskBody(version, bodyInput, signer) {
    const key = signer.private_key instanceof crypto.KeyObject
        ? signer.private_key : crypto.createPrivateKey(signer.private_key);
    if (key.asymmetricKeyType !== 'ed25519')
        throw new TypeError('risk artifact signing key must be Ed25519');
    if (!riskIdentifier(signer.issuer_id) || !riskIdentifier(signer.key_id))
        throw new TypeError('risk artifact issuer is invalid');
    const body = riskClone({ ...bodyInput, issuer: { id: signer.issuer_id, key_id: signer.key_id } });
    const bodyDigest = riskDigest(body);
    const proof = {
        algorithm: 'Ed25519',
        key_id: signer.key_id,
        body_digest: bodyDigest,
        signature_b64u: crypto.sign(null, signingBytes(version, body), key).toString('base64url'),
    };
    return riskFreeze({ ...body, proof });
}
export function verifyRiskBody(artifact, version, trustedKeys) {
    const refuse = (reason) => ({ valid: false, reason, body: null, artifact_digest: null });
    try {
        if (!riskRecord(artifact) || !riskRecord(artifact.proof) || !riskRecord(artifact.issuer))
            return refuse('artifact_shape_invalid');
        const proof = artifact.proof;
        const { proof: _proof, ...body } = artifact;
        if (artifact['@version'] !== version || !riskExact(artifact.issuer, ['id', 'key_id'])
            || !riskIdentifier(artifact.issuer.id) || !riskIdentifier(artifact.issuer.key_id)
            || !riskExact(proof, ['algorithm', 'key_id', 'body_digest', 'signature_b64u'])
            || proof.algorithm !== 'Ed25519' || proof.key_id !== artifact.issuer.key_id
            || typeof proof.body_digest !== 'string' || !RISK_DIGEST.test(proof.body_digest)
            || typeof proof.signature_b64u !== 'string' || !/^[A-Za-z0-9_-]+$/.test(proof.signature_b64u)) {
            return refuse('artifact_signature_envelope_invalid');
        }
        if (riskDigest(body) !== proof.body_digest)
            return refuse('digest_mismatch');
        const pin = trustedKeys?.[artifact.issuer.key_id];
        if (!pin || pin.issuer_id !== artifact.issuer.id)
            return refuse('issuer_untrusted');
        const keyBytes = Buffer.from(pin.public_key, 'base64url');
        if (keyBytes.toString('base64url') !== pin.public_key)
            return refuse('pinned_key_invalid');
        const key = crypto.createPublicKey({ key: keyBytes, type: 'spki', format: 'der' });
        if (key.asymmetricKeyType !== 'ed25519')
            return refuse('pinned_key_invalid');
        const signature = Buffer.from(proof.signature_b64u, 'base64url');
        if (signature.length !== 64 || signature.toString('base64url') !== proof.signature_b64u
            || !crypto.verify(null, signingBytes(version, body), key, signature))
            return refuse('signature_invalid');
        return { valid: true, reason: null, body, artifact_digest: riskDigest(artifact) };
    }
    catch {
        return refuse('artifact_invalid');
    }
}
// ===========================================================================
// EP-RISK-HYBRID-v2 -- opt-in hybrid (Ed25519 + ML-DSA-65) risk-artifact proof
// ===========================================================================
//
// This is the SHARED-HELPER application of the reference hybrid migration
// documented under "PATTERN: the reference hybrid migration" in
// docs/protocol/pq-hybrid-program.md (EP-REVOCATION-v2 is the template). It is
// ADDITIVE: signRiskBody / verifyRiskBody above are untouched, existing callers
// keep the flat single-Ed25519 proof by default, and a caller opts into the
// set-shaped hybrid proof ONLY by calling signRiskBodyV2 / verifyRiskBodyV2
// with a distinct -v2 @version marker. A caller migrates in one line by
// swapping signRiskBody(V) -> signRiskBodyV2(V) at issuance and
// verifyRiskBody(a, V, keys) -> await verifyRiskBodyV2(a, V, keys) at
// verification (its trusted-keys map gains a pq_public_key half per pin).
/** Marker committed inside the hybrid signed bytes and carried in proof.profile. */
export const RISK_HYBRID_PROFILE = 'EP-RISK-HYBRID-v2';
/** The registered required algorithm set for the hybrid proof, in canonical order. */
export const RISK_HYBRID_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
const RISK_PROOF_V2_KEYS = ['profile', 'required_algorithms', 'key_id', 'body_digest', 'signatures'];
function algorithmSetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === RISK_HYBRID_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === RISK_HYBRID_REQUIRED_ALGORITHMS[i]);
}
/**
 * The bytes BOTH legs sign. Same body the v1 helper signs, plus the
 * `required_algorithms` SET and the hybrid `profile`/`version` markers, so the
 * algorithm set and profile are cryptographically committed (anti-stripping).
 * canonicalize() sorts keys, so the field order here is irrelevant. The
 * verifier rebuilds these bytes from the PRESENTED body and the REGISTERED set,
 * never from anything the artifact chooses.
 */
function riskV2SigningBytes(version, body, requiredAlgorithms = RISK_HYBRID_REQUIRED_ALGORITHMS) {
    if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
        throw new Error('riskV2SigningBytes: algorithm set is not the registered EP-RISK-HYBRID-v2 set');
    }
    return Buffer.from(canonicalize({
        profile: RISK_HYBRID_PROFILE,
        required_algorithms: [...requiredAlgorithms],
        version,
        body,
    }), 'utf8');
}
/**
 * signRiskBodyV2 -- mint the hybrid, set-committed twin of signRiskBody.
 *
 * Reference: "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2) in
 * docs/protocol/pq-hybrid-program.md. Five moves, applied here:
 *   1. VERSION BUMP, NOT A FIELD BUMP. The caller passes a distinct -v2 marker
 *      (e.g. EP-GATE-ALLOWANCE-v2); the v1 helper and its callers keep the flat
 *      `signature` proof. A deployed v1 verifier handed a v2 artifact refuses on
 *      its version/envelope check BEFORE inspecting any signature (never a leg
 *      pass, never a crash).
 *   2. SET SHAPE. `proof.signatures` is an EP-SIG-AGILITY-v1 AgileSignature
 *      array ({ alg, sig, key_id? }), one entry per required algorithm.
 *   3. ANTI-STRIPPING BYTES. `required_algorithms` and the profile are inside
 *      the signed bytes (riskV2SigningBytes). Drop a leg and narrow the set and
 *      the surviving signature no longer verifies, because the bytes changed.
 *   4. V1 COMPATIBILITY. v1 stays synchronous and unchanged; v2 is a SEPARATE
 *      async entry point (ML-DSA verification is async).
 *   5. NAMED REFUSALS. Issuer-side misuse throws (a programming error);
 *      verifyRiskBodyV2 never throws on caller input and never passes on a
 *      missing ML-DSA backend.
 *
 * HONEST BOUNDARY: the ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, which is not independently audited and is not a FIPS
 * validated module; verifying under this profile is not a certification claim.
 * v2 does NOT retroactively protect artifacts already issued under v1.
 */
export async function signRiskBodyV2(version, bodyInput, signer, options = {}) {
    const key = signer.private_key instanceof crypto.KeyObject
        ? signer.private_key : crypto.createPrivateKey(signer.private_key);
    if (key.asymmetricKeyType !== 'ed25519')
        throw new TypeError('risk artifact signing key must be Ed25519');
    if (!riskIdentifier(signer.issuer_id) || !riskIdentifier(signer.key_id))
        throw new TypeError('risk artifact issuer is invalid');
    const body = riskClone({ ...bodyInput, issuer: { id: signer.issuer_id, key_id: signer.key_id } });
    const bodyDigest = riskDigest(body);
    const bytes = riskV2SigningBytes(version, body, RISK_HYBRID_REQUIRED_ALGORITHMS);
    const signatures = await signAgileSet(new Uint8Array(bytes), [
        { alg: 'Ed25519', private_key: key, key_id: signer.key_id },
        { alg: 'ML-DSA-65', private_key: signer.pq_private_key, key_id: signer.key_id },
    ], options);
    const byAlg = new Map(signatures.map((s) => [s.alg, s]));
    const proof = {
        profile: RISK_HYBRID_PROFILE,
        required_algorithms: [...RISK_HYBRID_REQUIRED_ALGORITHMS],
        key_id: signer.key_id,
        body_digest: bodyDigest,
        signatures: [byAlg.get('Ed25519'), byAlg.get('ML-DSA-65')],
    };
    return riskFreeze({ ...body, proof });
}
/**
 * verifyRiskBodyV2 -- FAIL-CLOSED hybrid verify, the set-committed twin of
 * verifyRiskBody. Same result shape ({ valid, reason, body, artifact_digest })
 * so a caller migrates by swapping the call and awaiting it. Both legs verify
 * over bytes rebuilt from the PRESENTED body and the REGISTERED algorithm set,
 * under the PINNED Ed25519 + ML-DSA-65 keys; a v2 artifact NEVER verifies on one
 * leg alone. See "PATTERN: the reference hybrid migration" in
 * docs/protocol/pq-hybrid-program.md.
 */
export async function verifyRiskBodyV2(artifact, version, trustedKeys, options = {}) {
    const refuse = (reason) => ({ valid: false, reason, body: null, artifact_digest: null });
    try {
        if (!riskRecord(artifact) || !riskRecord(artifact.proof) || !riskRecord(artifact.issuer))
            return refuse('artifact_shape_invalid');
        const proof = artifact.proof;
        const { proof: _proof, ...body } = artifact;
        // 1. Version + envelope shape. A v1 artifact (flat proof, -v1 marker) fails
        //    here, the mirror of the v1 verifier refusing a v2 artifact.
        if (artifact['@version'] !== version
            || !riskExact(artifact.issuer, ['id', 'key_id'])
            || !riskIdentifier(artifact.issuer.id) || !riskIdentifier(artifact.issuer.key_id)
            || !riskExact(proof, RISK_PROOF_V2_KEYS)
            || proof.profile !== RISK_HYBRID_PROFILE
            || proof.key_id !== artifact.issuer.key_id
            || typeof proof.body_digest !== 'string' || !RISK_DIGEST.test(proof.body_digest)) {
            return refuse('artifact_signature_envelope_invalid');
        }
        // 2. Committed algorithm set: exact and order-sensitive (narrowing/widening
        //    is the stripping attack's cover story, refused structurally here and
        //    again cryptographically by the recomputed bytes).
        if (!algorithmSetMatchesRegistered(proof.required_algorithms))
            return refuse('algorithm_set_invalid');
        // 3. Exactly one well-formed signature per required algorithm, no duplicate,
        //    no algorithm outside the registered set.
        if (!Array.isArray(proof.signatures) || proof.signatures.length === 0)
            return refuse('signature_set_invalid');
        const presented = new Set();
        for (const s of proof.signatures) {
            if (!riskRecord(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string'
                || !(riskExact(s, ['alg', 'sig']) || riskExact(s, ['alg', 'sig', 'key_id']))
                || (Object.hasOwn(s, 'key_id') && typeof s.key_id !== 'string')) {
                return refuse('signature_set_invalid');
            }
            if (presented.has(s.alg))
                return refuse('signature_set_invalid');
            presented.add(s.alg);
        }
        for (const alg of presented) {
            if (!RISK_HYBRID_REQUIRED_ALGORITHMS.includes(alg))
                return refuse('signature_set_invalid');
        }
        for (const alg of RISK_HYBRID_REQUIRED_ALGORITHMS) {
            if (!presented.has(alg))
                return refuse('signature_set_incomplete');
        }
        // 4. Body digest binding (identical discipline to v1).
        if (riskDigest(body) !== proof.body_digest)
            return refuse('digest_mismatch');
        // 5. Pin BOTH halves under the issuer key id. Identified-but-not-trusted:
        //    a self-asserted, unpinned key confers NOTHING.
        const pin = trustedKeys?.[artifact.issuer.key_id];
        if (!pin || pin.issuer_id !== artifact.issuer.id)
            return refuse('issuer_untrusted');
        if (typeof pin.public_key !== 'string' || pin.public_key.length === 0
            || typeof pin.pq_public_key !== 'string' || pin.pq_public_key.length === 0) {
            return refuse('issuer_untrusted');
        }
        const edBytes = Buffer.from(pin.public_key, 'base64url');
        if (edBytes.length === 0 || edBytes.toString('base64url') !== pin.public_key)
            return refuse('pinned_key_invalid');
        const edKey = crypto.createPublicKey({ key: edBytes, type: 'spki', format: 'der' });
        if (edKey.asymmetricKeyType !== 'ed25519')
            return refuse('pinned_key_invalid');
        const pqBytes = Buffer.from(pin.pq_public_key, 'base64url');
        if (pqBytes.length !== ML_DSA_65_PUBLIC_KEY_BYTES || pqBytes.toString('base64url') !== pin.pq_public_key) {
            return refuse('pinned_key_invalid');
        }
        // 6. Both legs, over bytes rebuilt from the PRESENTED body and the
        //    REGISTERED set, under the PINNED keys only. Policy hybrid_all with the
        //    full set required, so a missing leg is never a pass and an absent
        //    ML-DSA backend is a refusal, not a skipped check.
        let bytes;
        try {
            bytes = riskV2SigningBytes(version, body, RISK_HYBRID_REQUIRED_ALGORITHMS);
        }
        catch {
            return refuse('artifact_invalid');
        }
        let setResult;
        try {
            setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), proof.signatures, [
                { alg: 'Ed25519', public_key: pin.public_key },
                { alg: 'ML-DSA-65', public_key: pin.pq_public_key },
            ], { ...options, policy: 'hybrid_all', requiredAlgorithms: [...RISK_HYBRID_REQUIRED_ALGORITHMS] });
        }
        catch {
            setResult = null;
        }
        if (setResult?.verified !== true) {
            // An absent ML-DSA backend is a REFUSAL, surfaced distinctly, never a
            // skipped check and never a pass on the surviving classical leg.
            const reason = typeof setResult?.reason === 'string' ? setResult.reason : '';
            return refuse(reason.includes('pq_backend_unavailable') ? 'pq_backend_unavailable' : 'signature_invalid');
        }
        return { valid: true, reason: null, body, artifact_digest: riskDigest(artifact) };
    }
    catch {
        return refuse('artifact_invalid');
    }
}
//# sourceMappingURL=reliance-risk-crypto.js.map