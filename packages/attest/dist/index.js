// SPDX-License-Identifier: Apache-2.0
/**
 * @emilia-protocol/attest — match identity bytes to a relying-party pin, then
 * sign a work-product binding as an EP-RECEIPT-v1.
 *
 * This is the standardized, drop-in version of the "Identity Manager" pattern
 * (hash an identity → compare to a known-good → sign the work): the same idea,
 * but the thing it signs is an EP receipt anyone can re-derive offline with
 * @emilia-protocol/verify — re-hash the identity file, re-hash the work file,
 * check the Ed25519 signature, and check the EP-MERKLE-v2 inclusion structure.
 * Acceptance still requires an out-of-band pinned signer key and identity pin.
 *
 * Two calls:
 *   verifyIdentity()  — SHA-256 an agent's identity bytes, constant-time compare
 *                       to a known-good hash (e.g. from a Keeper vault).
 *   signWorkReceipt() — bind the verified identity + the work-product hash into a
 *                       receipt. Fail-closed: refuses to sign if identity != known-good.
 *
 * Zero runtime deps beyond node:crypto and the sibling issuer/verifier packages.
 *
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
import { canonicalize, buildReceiptAnchorV2, publicKeyToSpkiB64u, privateKeyFromPkcs8B64u, } from '../../issue/index.js';
export const ATTEST_VERSION = 'EP-ATTEST-v2';
function toBuf(input) {
    if (Buffer.isBuffer(input))
        return input;
    if (input instanceof Uint8Array)
        return Buffer.from(input);
    if (typeof input === 'string')
        return Buffer.from(input, 'utf8');
    throw new TypeError('attest: input must be a Buffer, Uint8Array, or string');
}
/** SHA-256 of arbitrary bytes (Buffer | Uint8Array | string) -> hex. */
export function sha256Hex(input) {
    return crypto.createHash('sha256').update(toBuf(input)).digest('hex');
}
/** Constant-time hex-string comparison. */
function hexEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length)
        return false;
    try {
        return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
    }
    catch {
        return false;
    }
}
/**
 * Verify an agent identity against a known-good SHA-256.
 * @param {{ identity?: Buffer|Uint8Array|string, knownGoodHash?: string }} args
 * @returns {{ verified: boolean, computedHash: string | null }}
 */
export function verifyIdentity({ identity, knownGoodHash } = {}) {
    let computedHash = null;
    try {
        computedHash = sha256Hex(identity);
    }
    catch {
        return { verified: false, computedHash };
    }
    const normalizedPin = typeof knownGoodHash === 'string' ? knownGoodHash.toLowerCase() : '';
    const verified = /^[0-9a-f]{64}$/.test(normalizedPin) && hexEqual(computedHash, normalizedPin);
    return { verified, computedHash };
}
/**
 * The signed payload, built ONCE for both the classical and the hybrid entry
 * point so the two can never drift on which facts they bind or on how they
 * validate their inputs. `profile` is the only difference between them, and it
 * is INSIDE the signed material: an EP-ATTEST-v2 payload and an
 * EP-ATTEST-HYBRID-v1 payload over the same identity and work bytes are
 * different signed bytes, so neither signature can be lifted into the other
 * envelope.
 *
 * Every check below is a REFUSAL TO SIGN. Issuance is not attacker input: a
 * caller that reaches this function with a mismatched identity pin, a
 * mismatched subject, or a malformed timestamp has a bug, and minting an
 * attestation anyway would be the failure this module exists to prevent.
 */
function buildAttestPayload(profile, { identity, knownGoodHash, knownGoodSubject, work, subject, issuedAt, workName = null, receiptId, }) {
    const idCheck = verifyIdentity({ identity, knownGoodHash });
    if (!idCheck.verified) {
        throw new Error('attest: identity does not match the known-good hash — refusing to sign (fail-closed)');
    }
    if (!subject)
        throw new Error('attest: subject (identity id) is required');
    if (typeof knownGoodSubject !== 'string' || !knownGoodSubject) {
        throw new Error('attest: knownGoodSubject is required from relying-party trust material');
    }
    if (subject !== knownGoodSubject) {
        throw new Error('attest: subject does not match the relying-party identity pin — refusing to sign');
    }
    if (typeof issuedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(issuedAt)
        || !Number.isFinite(Date.parse(issuedAt))) {
        throw new Error('attest: issuedAt must be a valid UTC RFC3339 timestamp');
    }
    if (receiptId !== undefined && (typeof receiptId !== 'string' || !receiptId)) {
        throw new Error('attest: receiptId must be a non-empty string');
    }
    if (workName !== null && (typeof workName !== 'string' || !workName)) {
        throw new Error('attest: workName must be null or a non-empty string');
    }
    return {
        attest_profile: profile,
        receipt_id: receiptId || `att_${crypto.randomBytes(12).toString('hex')}`,
        subject,
        // A subject + content hash matched to relying-party trust material. This is
        // a binding claim, not proof of real-world identity or authority.
        identity: { algorithm: 'SHA-256', hash: idCheck.computedHash, matched_known_good: true },
        // The work product, by hash — re-derivable by re-hashing the artifact.
        work: { algorithm: 'SHA-256', hash: sha256Hex(work), ...(workName ? { name: workName } : {}) },
        claim: { action_type: 'work.signed', outcome: 'attested' },
        issued_at: issuedAt,
    };
}
/**
 * Sign a work product as an EP-RECEIPT-v1, bound to a verified identity.
 * Fail-closed: throws if the identity does not match knownGoodHash.
 *
 * @param {object} args
 * @param {Buffer|Uint8Array|string} [args.identity]        identity-file bytes
 * @param {string} [args.knownGoodHash]                     SHA-256 hex (e.g. from Keeper)
 * @param {string} [args.knownGoodSubject]                  identity id pinned with that hash
 * @param {Buffer|Uint8Array|string} [args.work]            the work-product bytes
 * @param {crypto.KeyObject|string} [args.signerPrivateKey] Ed25519 key (KeyObject or b64u PKCS#8)
 * @param {string} [args.subject]                           identity id (e.g. ep:approver:cfo)
 * @param {string} [args.issuedAt]                          ISO-8601 (caller-supplied — no Date.now lock-in)
 * @param {string|null} [args.workName]
 * @param {string} [args.receiptId]
 * @param {boolean} [args.anchor=false]                   attach an EP-MERKLE-v2 anchor
 * @param {string[]} [args.priorLeaves]                   existing v2 leaves for a real inclusion proof
 * @returns {{ document: object, public_key: string }}   EP-RECEIPT-v1 + the signer SPKI (b64u)
 */
export function signWorkReceipt({ identity, knownGoodHash, knownGoodSubject, work, signerPrivateKey, subject, issuedAt, workName = null, receiptId, anchor = false, priorLeaves = [], } = {}) {
    const payload = buildAttestPayload(ATTEST_VERSION, {
        identity, knownGoodHash, knownGoodSubject, work, subject, issuedAt, workName, receiptId,
    });
    const privateKey = typeof signerPrivateKey === 'string'
        ? privateKeyFromPkcs8B64u(signerPrivateKey)
        : signerPrivateKey;
    if (!privateKey || privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
        throw new Error('attest: signerPrivateKey must be Ed25519');
    }
    const publicKey = crypto.createPublicKey(privateKey.export({ type: 'pkcs8', format: 'pem' }));
    if (publicKey.asymmetricKeyType !== 'ed25519') {
        throw new Error('attest: signerPrivateKey must be Ed25519');
    }
    const signature = crypto
        .sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey)
        .toString('base64url');
    const document = {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: signature },
        ...(anchor ? { anchor: buildReceiptAnchorV2(payload, priorLeaves) } : {}),
    };
    return { document, public_key: publicKeyToSpkiB64u(publicKey) };
}
// ── EP-ATTEST-HYBRID-v1 (OPT-IN post-quantum attestation) ────────────────────
//
// signWorkReceipt() above is unchanged and still mints the flat-signature
// EP-RECEIPT-v1 that every deployed verifier reads. The hybrid path is a
// SEPARATE, ASYNC entry point (ML-DSA verification and signing are async), and
// it takes a NEW version marker at both levels:
//
//   envelope:  EP-RECEIPT-v1        ->  EP-RECEIPT-HYBRID-v1
//   profile:   EP-ATTEST-v2         ->  EP-ATTEST-HYBRID-v1   (inside `payload`)
//
// A deployed EP-RECEIPT-v1 verifier handed a hybrid attestation refuses on the
// envelope marker BEFORE inspecting any signature, and does not crash. It never
// accepts a hybrid document on the strength of the one leg it understands. The
// profile marker inside the payload gives the same protection one level down: an
// EP-ATTEST-v2 payload and an EP-ATTEST-HYBRID-v1 payload over identical
// identity and work bytes canonicalize differently, so a leg cannot be lifted
// between profiles.
//
// The hybrid receipt construction itself is NOT reimplemented here. It is
// packages/issue/src/hybrid-issuance.ts's createHybridReceipt, which puts the
// required algorithm set inside the signed bytes (the anti-stripping
// commitment) and signs through EP-SIG-AGILITY-v1's signAgileSet. This module
// contributes only the attestation payload, held to exactly the same
// identity-pin and subject-pin refusals as the classical path because both call
// buildAttestPayload().
//
// NO ANCHOR, ON PURPOSE. `anchor` is unavailable in this path. An EP-MERKLE-v2
// anchor self-checks its leaf against `doc.payload`, which is not what a hybrid
// receipt commits to, so an anchor here would be a structure no verifier checks
// end to end. hybrid-issuance.ts records the same boundary.
//
// HONEST BOUNDARY. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
// implementation: not independently audited, not a FIPS validated module.
// Issuing under this profile is not a certification claim, and this profile is
// not on in any deployment.
// Resolved through the built output rather than the package root shim: the root
// packages/issue/hybrid-issuance.js has no sibling .d.ts, and the "./hybrid-issuance"
// exports entry is only consulted for BARE specifiers, which this in-repo
// sibling import is not. Both packages/attest/src and packages/attest/dist sit
// one level under packages/attest, so this relative path resolves identically
// from the source and from the build — the same property that makes
// '../../issue/index.js' work above.
import { createHybridReceipt, signingKeysFromHybridBundle, verificationKeysFromHybridBundle, HYBRID_RECEIPT_PROFILE, } from '../../issue/dist/hybrid-issuance.js';
/** The attestation profile marker carried INSIDE a hybrid attestation payload. */
export const ATTEST_HYBRID_VERSION = 'EP-ATTEST-HYBRID-v1';
/** The envelope profile a hybrid attestation is wrapped in. Re-exported so a
 *  relying party can pin the marker without depending on @emilia-protocol/issue. */
export const ATTEST_HYBRID_ENVELOPE = HYBRID_RECEIPT_PROFILE;
/**
 * Sign a work product as an EP-RECEIPT-HYBRID-v1 (Ed25519 AND ML-DSA-65), bound
 * to a verified identity. Fail-closed in both directions: it refuses to sign
 * when the identity does not match the pin, and it refuses to sign when no
 * ML-DSA backend is available rather than emit a receipt missing the PQ leg.
 *
 * Verify the result with verifyHybridReceipt() from @emilia-protocol/verify
 * (packages/verify/src/receipt-hybrid.ts), passing `verification_keys`.
 *
 * @throws on any pin mismatch, malformed key material, or unavailable ML-DSA
 *   backend. Issuer-side misuse is a programming error, not attacker input.
 */
export async function signWorkReceiptHybrid({ identity, knownGoodHash, knownGoodSubject, work, keyBundle, subject, issuedAt, workName = null, receiptId, ...options } = {}) {
    if (!keyBundle || typeof keyBundle !== 'object') {
        throw new Error('attest: keyBundle is required for a hybrid attestation (an EP-HYBRID-ISSUER-KEYS-v1 bundle from @emilia-protocol/issue)');
    }
    // Both throw on a bundle missing either half, so a "hybrid" attestation can
    // never be minted from half a bundle.
    const keys = signingKeysFromHybridBundle(keyBundle);
    const verification_keys = verificationKeysFromHybridBundle(keyBundle);
    const payload = buildAttestPayload(ATTEST_HYBRID_VERSION, {
        identity, knownGoodHash, knownGoodSubject, work, subject, issuedAt, workName, receiptId,
    });
    // createHybridReceipt curve-pins the Ed25519 key, length-pins the ML-DSA
    // secret key, puts the required algorithm set inside the signed bytes, and
    // throws when the PQ backend is missing. None of that is duplicated here.
    const document = await createHybridReceipt({ payload, keys, ...options });
    return { document, verification_keys };
}
//# sourceMappingURL=index.js.map