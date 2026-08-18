// SPDX-License-Identifier: Apache-2.0
/**
 * The RELYING-PARTY half of the hybrid receipt spine: offline verification of
 * EP-RECEIPT-HYBRID-v1 receipts and of EP-LOG-CHECKPOINT-HYBRID-v1 checkpoint
 * proofs, using only @emilia-protocol/verify.
 *
 * WHY THIS FILE EXISTS. EP-RECEIPT-HYBRID-v1 was issuable before it was
 * verifiable by the published verifier. packages/issue/src/hybrid-issuance.ts
 * mints the receipt and carries a verifier next to the minting code, but
 * @emilia-protocol/verify -- the package a relying party actually installs to
 * check an EP artifact offline, with no issuer code and no EP backend -- had no
 * entry point for it. A portable artifact that only its issuer's package can
 * check is not portable. This module closes that gap. It is a SECOND
 * implementation only in the sense that it lives in the verifying package; the
 * signature math, the closed algorithm registry, the curve pin, the exact
 * length pins, and the "no ML-DSA backend is a refusal" rule are NOT
 * reimplemented here -- every one of them is EP-SIG-AGILITY-v1's
 * (./pq-signature-agility.js), reached through verifyAgileSignatureSet.
 *
 * BYTE COMPATIBILITY IS THE CONTRACT. hybridReceiptSignedBytes() below must
 * produce bytes identical to hybridSignedBytes() in
 * packages/issue/src/hybrid-issuance.ts, or a receipt this repository issues
 * would not verify with the verifier this repository publishes. Both sides
 * build the SAME object over the SAME canonicalization
 * (canonicalizeStrictJson, the single JCS-equivalent source of truth both
 * packages import), and the cross-package test asserts the bytes are equal
 * rather than assuming it.
 *
 * --- THE FIVE MOVES (docs/protocol/pq-hybrid-program.md) --------------------
 *
 * 1. VERSION MARKER, NOT A FIELD. EP-RECEIPT-v1's verifyReceipt() in ./index.ts
 *    is untouched and stays SYNCHRONOUS. Handed a hybrid receipt it refuses on
 *    the version marker -- `Unsupported version: EP-RECEIPT-HYBRID-v1` -- before
 *    inspecting any signature, and it does not throw. That is the required
 *    outcome for a deployed v1 verifier: never accept a hybrid receipt on the
 *    strength of the one leg it happens to understand.
 *
 * 2. SET SHAPE. `signatures` is an array of EP-SIG-AGILITY-v1 AgileSignature
 *    objects ({ alg, sig, key_id? }), one per registered algorithm, in the
 *    registered order. Ed25519 verifies under a base64url SPKI DER public key;
 *    ML-DSA-65 under raw base64url public key bytes.
 *
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes. Delete the ML-DSA leg and narrow `profile.required_algorithms` to
 *    ["Ed25519"] and the surviving Ed25519 signature no longer verifies,
 *    because the bytes changed. Leave the set intact and the missing leg is a
 *    structural refusal. The verifier rebuilds the bytes from the REGISTERED
 *    set and from `doc.payload`; the presented document never chooses what it
 *    is checked against.
 *
 * 4. SEPARATE ASYNC ENTRY POINT. ML-DSA verification is asynchronous, so
 *    verifyHybridReceipt() is its own async function rather than a signature
 *    change to verifyReceipt(). verifyReceiptOfAnyProfile() routes a mixed bag
 *    on the version marker for callers that hold both.
 *
 * 5. NAMED REFUSALS. Every failure returns a named reason; nothing throws on
 *    caller input. An absent ML-DSA backend is `pq_backend_unavailable`, never
 *    a skipped check and never a pass on the classical leg.
 *
 * --- HONEST BOUNDARIES ------------------------------------------------------
 *   - OPT-IN. EP-RECEIPT-v1 remains the receipt format EP issues by default.
 *     Nothing here is on in any deployment.
 *   - The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 *     implementation: not independently audited, not a FIPS validated module.
 *     Verifying under this profile is not a certification claim.
 *   - VERIFIED is not ACCEPTED. A true verdict says both signatures check out
 *     over the receipt's own bytes under the keys the CALLER pinned. Whether
 *     those keys are trusted is the relying party's separate decision.
 *   - Merkle anchoring is out of scope for the hybrid receipt profile, exactly
 *     as the issuance module records: an EP-MERKLE-v2 anchor self-checks its
 *     leaf against `doc.payload`, which is not what a hybrid receipt commits
 *     to. An `anchor` member on a hybrid receipt is therefore refused rather
 *     than half-checked.
 *   - Neither profile retroactively protects an artifact already issued under
 *     a single algorithm.
 */
import { canonicalizeStrictJson, isStrictCanonicalJson } from './strict-json.js';
import { verifyAgileSignatureSet, } from './pq-signature-agility.js';
const canonicalize = canonicalizeStrictJson;
// ---------------------------------------------------------------------------
// EP-RECEIPT-HYBRID-v1
// ---------------------------------------------------------------------------
/** The profile id, used as both `@version` and `profile.id`. */
export const HYBRID_RECEIPT_PROFILE = 'EP-RECEIPT-HYBRID-v1';
/**
 * The registered required algorithm set, in canonical order. This exact array
 * goes into the signed bytes, so its contents AND order are part of what every
 * leg commits to. It is duplicated from packages/issue deliberately: the
 * verifying package must not need the issuing package installed to know what
 * it requires, and the cross-package test pins the two to be equal.
 */
export const HYBRID_RECEIPT_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
/** Named refusals. Every failure path returns one of these; none throw. */
export const HYBRID_RECEIPT_REASONS = Object.freeze({
    MALFORMED_RECEIPT: 'malformed_receipt',
    MALFORMED_PAYLOAD: 'malformed_payload',
    UNKNOWN_PROFILE: 'unknown_profile',
    ALGORITHM_SET_MISMATCH: 'algorithm_set_mismatch',
    HYBRID_LEG_MISSING: 'hybrid_leg_missing',
    UNEXPECTED_ALGORITHM: 'unexpected_algorithm',
    DUPLICATE_ALGORITHM: 'duplicate_algorithm',
    UNSUPPORTED_ANCHOR: 'unsupported_anchor',
    MISSING_KEY: 'missing_key',
    SIGNATURE_INVALID: 'signature_invalid',
    PQ_BACKEND_UNAVAILABLE: 'pq_backend_unavailable',
});
/**
 * The closed top-level member set of a hybrid receipt. `metadata` is OPTIONAL
 * and UNSIGNED (the same role it plays in EP-RECEIPT-v1), so nothing a relying
 * party authorizes on may live there. Any member outside this set is refused
 * rather than ignored: an ignored member on a signed document is an unsigned
 * member a producer can smuggle, and this profile is new enough to have no
 * historical emitters to accommodate.
 */
const RECEIPT_KEYS = new Set(['@version', 'profile', 'payload', 'signatures', 'metadata']);
const PROFILE_KEYS = new Set(['id', 'required_algorithms']);
function algorithmSetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === HYBRID_RECEIPT_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === HYBRID_RECEIPT_REQUIRED_ALGORITHMS[i]);
}
function exactKeys(value, allowed, optional = new Set()) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const keys = Object.keys(value);
    if (!keys.every((key) => allowed.has(key)))
        return false;
    for (const required of allowed) {
        if (!optional.has(required) && !keys.includes(required))
            return false;
    }
    return true;
}
/**
 * Build the exact object both legs sign. The required algorithm set and the
 * profile id are INSIDE it: that is the anti-stripping commitment.
 *
 * BYTE-IDENTICAL by contract to hybridSignedMaterial() in
 * packages/issue/src/hybrid-issuance.ts. Exported so a conformance vector or an
 * independent implementation can rebuild the bytes without reading either
 * module's internals.
 *
 * @throws if the payload is outside the EP canonicalization profile, or if the
 *   algorithm set is not the registered one. Issuer-side and vector-side misuse
 *   is a programming error; verifyHybridReceipt() catches this and turns it
 *   into a named refusal, so caller input never reaches a throw.
 */
export function hybridReceiptSignedMaterial(payload, requiredAlgorithms = HYBRID_RECEIPT_REQUIRED_ALGORITHMS) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new TypeError('hybridReceiptSignedMaterial: payload must be a plain object');
    }
    if (!isStrictCanonicalJson(payload)) {
        throw new Error('hybridReceiptSignedMaterial: payload is outside the EP canonicalization profile; encode non-integer quantities as strings');
    }
    if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
        throw new Error(`hybridReceiptSignedMaterial: refusing: ${HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH}`);
    }
    return {
        '@version': HYBRID_RECEIPT_PROFILE,
        payload,
        required_algorithms: [...requiredAlgorithms],
    };
}
/** UTF-8 canonical bytes of hybridReceiptSignedMaterial(). What every leg signs. */
export function hybridReceiptSignedBytes(payload, requiredAlgorithms = HYBRID_RECEIPT_REQUIRED_ALGORITHMS) {
    return Buffer.from(canonicalize(hybridReceiptSignedMaterial(payload, requiredAlgorithms)), 'utf8');
}
/**
 * Verify an EP-RECEIPT-HYBRID-v1 receipt offline against PINNED keys.
 * FAIL-CLOSED: every malformed, unknown, or stripped input returns a named
 * refusal; nothing throws on caller input.
 *
 * Order of checks, and why:
 *   1. Structure and profile marker. An unknown `@version` or `profile.id`
 *      refuses with `unknown_profile`; this is not a general receipt verifier
 *      and never guesses at another format. The member set is CLOSED, so an
 *      unsigned member cannot ride along unnoticed.
 *   2. `profile.required_algorithms` must EXACTLY equal the registered set,
 *      order included. A narrowed set is the stripping attack's cover story, so
 *      it is refused structurally, before the (also failing) signature check.
 *   3. Exactly one signature per required algorithm: a missing leg is
 *      `hybrid_leg_missing`, an extra one `unexpected_algorithm`, a repeat
 *      `duplicate_algorithm`.
 *   4. The bytes are rebuilt from `doc.payload` and the REGISTERED set, then
 *      handed to EP-SIG-AGILITY-v1's verifyAgileSignatureSet under policy
 *      `hybrid_all` with requiredAlgorithms pinned to the FULL set. Every leg
 *      must verify over identical bytes. Verification uses the keys the CALLER
 *      pinned, never key material carried by the document.
 *
 * ON `key_id`, PRECISELY. Keys are selected by ALGORITHM, not by the `key_id` a
 * signature carries. A signature's `key_id` is a label the set verifier reports
 * back and never uses to choose a key, so a document claiming some other
 * `key_id` still verifies under the pinned key of its declared algorithm, and a
 * document claiming the RIGHT `key_id` gains nothing by it. Treat `key_id` as a
 * routing hint for finding which pin to load, never as evidence about which key
 * signed.
 */
export async function verifyHybridReceipt(doc, keys, options = {}) {
    const checks = {
        profile: false,
        algorithm_set: null,
        legs_present: null,
        signatures_valid: null,
    };
    const refuse = (reason, failedAlgorithm = null, setResult = null) => ({
        verified: false,
        reason,
        failed_algorithm: failedAlgorithm,
        checks,
        set_result: setResult,
    });
    // 1. Structure + profile marker. isStrictCanonicalJson inspects the COMPLETE
    //    caller-supplied object before any member is read, so hostile Proxy traps
    //    and values that vanish from JSON become a closed result rather than a
    //    surprise during canonicalization.
    if (!doc || typeof doc !== 'object' || Array.isArray(doc))
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
    if (!isStrictCanonicalJson(doc))
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
    const d = doc;
    if (d['@version'] !== HYBRID_RECEIPT_PROFILE)
        return refuse(HYBRID_RECEIPT_REASONS.UNKNOWN_PROFILE);
    // Named ahead of the closed-set check so the reason says WHY, rather than the
    // generic malformed_receipt an unknown member would otherwise produce. An
    // EP-MERKLE-v2 anchor self-checks its leaf against `doc.payload`, which is not
    // what a hybrid receipt commits to, so a half-checked anchor is worse than a
    // refused one.
    if (Object.prototype.hasOwnProperty.call(d, 'anchor')) {
        return refuse(HYBRID_RECEIPT_REASONS.UNSUPPORTED_ANCHOR);
    }
    if (!exactKeys(d, RECEIPT_KEYS, new Set(['metadata']))) {
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
    }
    if (!exactKeys(d.profile, PROFILE_KEYS))
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
    if (d.profile.id !== HYBRID_RECEIPT_PROFILE)
        return refuse(HYBRID_RECEIPT_REASONS.UNKNOWN_PROFILE);
    checks.profile = true;
    // 2. Committed algorithm set, exact and order-sensitive.
    if (!algorithmSetMatchesRegistered(d.profile.required_algorithms)) {
        checks.algorithm_set = false;
        return refuse(HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH);
    }
    checks.algorithm_set = true;
    // 3. Exactly one signature per required algorithm.
    if (!Array.isArray(d.signatures) || d.signatures.length === 0) {
        checks.legs_present = false;
        return refuse(HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING);
    }
    const presented = new Set();
    for (const s of d.signatures) {
        if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
            checks.legs_present = false;
            return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
        }
        if (presented.has(s.alg)) {
            checks.legs_present = false;
            return refuse(HYBRID_RECEIPT_REASONS.DUPLICATE_ALGORITHM, s.alg);
        }
        presented.add(s.alg);
    }
    for (const alg of HYBRID_RECEIPT_REQUIRED_ALGORITHMS) {
        if (!presented.has(alg)) {
            checks.legs_present = false;
            return refuse(HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING, alg);
        }
    }
    for (const alg of presented) {
        if (!HYBRID_RECEIPT_REQUIRED_ALGORITHMS.includes(alg)) {
            checks.legs_present = false;
            return refuse(HYBRID_RECEIPT_REASONS.UNEXPECTED_ALGORITHM, alg);
        }
    }
    checks.legs_present = true;
    // 4. Rebuild the bytes from the payload and the REGISTERED set, then delegate
    //    the set verdict to EP-SIG-AGILITY-v1.
    if (!d.payload || typeof d.payload !== 'object' || Array.isArray(d.payload) || !isStrictCanonicalJson(d.payload)) {
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_PAYLOAD);
    }
    if (!keys || typeof keys !== 'object' || !keys.ed25519PublicKey || !keys.mldsaPublicKey) {
        return refuse(HYBRID_RECEIPT_REASONS.MISSING_KEY);
    }
    let messageBytes;
    try {
        // The REGISTERED set, never d.profile.required_algorithms: the document
        // does not get to choose what it is checked against.
        messageBytes = hybridReceiptSignedBytes(d.payload, HYBRID_RECEIPT_REQUIRED_ALGORITHMS);
    }
    catch {
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_PAYLOAD);
    }
    const verificationKeys = [
        { alg: 'Ed25519', public_key: keys.ed25519PublicKey, ...(keys.ed25519KeyId ? { key_id: keys.ed25519KeyId } : {}) },
        { alg: 'ML-DSA-65', public_key: keys.mldsaPublicKey, ...(keys.mldsaKeyId ? { key_id: keys.mldsaKeyId } : {}) },
    ];
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(messageBytes), d.signatures, verificationKeys, {
            ...agilityPassthrough(options),
            policy: 'hybrid_all',
            requiredAlgorithms: [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        // verifyAgileSignatureSet documents that it never throws; an injected
        // backend that does is still a refusal here, never a pass.
        checks.signatures_valid = false;
        return refuse(HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
    }
    if (setResult?.verified === true) {
        checks.signatures_valid = true;
        return { verified: true, reason: null, failed_algorithm: null, checks, set_result: setResult };
    }
    checks.signatures_valid = false;
    return refuse(...mapSetFailure(setResult), setResult);
}
/**
 * Map EP-SIG-AGILITY-v1's set reason onto this profile's named vocabulary. The
 * full agility result stays attached in `set_result`, so nothing is lost.
 */
function mapSetFailure(setResult) {
    const failed = Array.isArray(setResult?.results)
        ? setResult.results.find((r) => r?.verified !== true) ?? null
        : null;
    const failedAlgorithm = failed?.alg ?? null;
    const rawReason = String(setResult?.reason ?? '');
    if (rawReason === 'missing_required_algorithm') {
        return [HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING, failedAlgorithm];
    }
    if (rawReason.endsWith('pq_backend_unavailable') || failed?.reason === 'pq_backend_unavailable') {
        return [HYBRID_RECEIPT_REASONS.PQ_BACKEND_UNAVAILABLE, failedAlgorithm];
    }
    if (failed?.reason === 'malformed_key' || failed?.reason === 'algorithm_key_mismatch') {
        return [HYBRID_RECEIPT_REASONS.MISSING_KEY, failedAlgorithm];
    }
    return [HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID, failedAlgorithm];
}
function agilityPassthrough(options) {
    const out = {};
    if (options?.mldsaBackend !== undefined)
        out.mldsaBackend = options.mldsaBackend;
    if (options?.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = options.mldsaBackendLoader;
    return out;
}
/**
 * Route a receipt of EITHER profile to its verifier, for a caller holding a
 * mixed bag. EP-RECEIPT-v1 documents get the EXACT v1 verdict from the
 * unchanged synchronous verifyReceipt(); EP-RECEIPT-HYBRID-v1 documents get the
 * hybrid check. A document declaring neither refuses with `unknown_profile`,
 * which is the fail-closed answer.
 *
 * `keys` carries whichever material the presented profile needs: a v1 receipt
 * needs `ed25519PublicKey` as base64url SPKI DER, a hybrid receipt needs both
 * halves. A caller that supplies only one and is handed the other profile gets
 * a refusal, never a pass.
 *
 * verifyReceipt is imported LAZILY. ./index.ts re-exports this module, so a
 * static import here would be a cycle through the package's largest module for
 * every consumer of the hybrid verifier.
 */
export async function verifyReceiptOfAnyProfile(doc, keys, options = {}) {
    const version = doc && typeof doc === 'object' && !Array.isArray(doc)
        ? doc['@version']
        : null;
    if (version === HYBRID_RECEIPT_PROFILE) {
        const result = await verifyHybridReceipt(doc, keys, options);
        return {
            profile: HYBRID_RECEIPT_PROFILE,
            valid: result.verified,
            checks: result.checks,
            reason: result.reason,
            error: null,
        };
    }
    const { verifyReceipt } = await import('./index.js');
    const edKey = keys && typeof keys === 'object' && typeof keys.ed25519PublicKey === 'string'
        ? keys.ed25519PublicKey
        : '';
    const result = verifyReceipt(doc, edKey, { allowLegacyMerkle: options?.allowLegacyMerkle === true });
    return {
        profile: typeof version === 'string' ? version : null,
        valid: result.valid === true,
        checks: result.checks,
        reason: null,
        error: typeof result.error === 'string' ? result.error : null,
    };
}
// ---------------------------------------------------------------------------
// EP-LOG-CHECKPOINT-HYBRID-v1
// ---------------------------------------------------------------------------
/**
 * The hybrid leg of EP-AUTHORIZATION-RECEIPT-v1, as a DETACHED proof over the
 * log checkpoint.
 *
 * WHY THE CHECKPOINT AND NOT THE WHOLE RECEIPT. An authorization receipt
 * carries two kinds of signature and EP controls only one of them:
 *
 *   - Approver signoffs. Class A is a WebAuthn assertion from a FIDO2
 *     authenticator or platform passkey (ES256, P-256). EP does not decide what
 *     that device signs or with which algorithm, so a post-quantum leg there is
 *     gated on FIDO Alliance and W3C WebAuthn PQC support landing in hardware
 *     and browsers, not on EP code. Class B/C signoffs are made with the
 *     APPROVER's own key, whose custody EP likewise does not hold.
 *   - The log checkpoint signature. This one IS EP's: the log operator signs
 *     `{tree_size, root_hash, log_key_id, merkle_alg}` with a key it holds, and
 *     it is the commitment that makes the receipt's inclusion checkable at all.
 *
 * So this profile hybridizes the leg EP can honestly hybridize, and says
 * plainly that it does not hybridize the other. It is a DETACHED proof, exactly
 * like EP-COMMIT-HYBRID-v1 (lib/commit-hybrid.ts): the receipt itself keeps its
 * frozen EP-AUTHORIZATION-RECEIPT-v1 shape byte for byte, no consumer has to
 * move, and no schema changes.
 *
 * WHAT A TRUE VERDICT MEANS, EXACTLY. Both legs signed the SAME checkpoint the
 * verifier independently recomputed from the receipt it holds. It does NOT mean
 * the receipt's approver signoffs are post-quantum protected (they are not), and
 * it does NOT establish inclusion on its own: the inclusion path still has to be
 * checked against `root_hash`, which is verifyTrustReceipt's job and stays
 * unchanged. This proof says the pinned log operator committed to that root
 * under both algorithms.
 *
 * THE PIN IS THE RELYING PARTY'S. The receipt remains a valid v1 artifact, so a
 * verifier that never asks for the proof gets a v1 verdict. Requiring the PQ leg
 * is a relying-party decision expressed by calling this function; the profile
 * makes the pin available and refuses without it, and cannot make a verifier
 * that never asks.
 */
export const LOG_CHECKPOINT_HYBRID_PROFILE = 'EP-LOG-CHECKPOINT-HYBRID-v1';
/** The registered required algorithm set, in canonical order. */
export const LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS = HYBRID_RECEIPT_REQUIRED_ALGORITHMS;
export const LOG_CHECKPOINT_HYBRID_REASONS = Object.freeze({
    MALFORMED_PROOF: 'malformed_proof',
    MALFORMED_CHECKPOINT: 'malformed_checkpoint',
    UNKNOWN_PROFILE: 'unknown_profile',
    ALGORITHM_SET_MISMATCH: 'algorithm_set_mismatch',
    CHECKPOINT_MISMATCH: 'checkpoint_mismatch',
    UNSUPPORTED_MERKLE_ALG: 'unsupported_merkle_alg',
    HYBRID_LEG_MISSING: 'hybrid_leg_missing',
    UNEXPECTED_ALGORITHM: 'unexpected_algorithm',
    DUPLICATE_ALGORITHM: 'duplicate_algorithm',
    MISSING_KEY: 'missing_key',
    SIGNATURE_INVALID: 'signature_invalid',
    PQ_BACKEND_UNAVAILABLE: 'pq_backend_unavailable',
});
/**
 * The exact members of a checkpoint that the hybrid proof signs. `log_signature`
 * is deliberately absent: it is the classical signature OVER these fields, and
 * a signature can never be inside its own signed material. The set is CLOSED,
 * and `merkle_alg` is REQUIRED, so a legacy EP-MERKLE-v1 checkpoint (which has
 * no `merkle_alg`) cannot enter this profile at all.
 */
const CHECKPOINT_SIGNED_KEYS = new Set(['tree_size', 'root_hash', 'log_key_id', 'merkle_alg']);
const CHECKPOINT_PROOF_KEYS = new Set(['@version', 'profile', 'checkpoint', 'signatures']);
/** The Merkle algorithm this profile accepts. */
export const LOG_CHECKPOINT_HYBRID_MERKLE_ALG = 'EP-MERKLE-v2';
/**
 * Normalize a checkpoint to exactly the members this profile signs, dropping
 * `log_signature` if present so a caller can pass `receipt.log_proof.checkpoint`
 * verbatim. Returns null when the checkpoint is not shaped for this profile, so
 * every caller path is a named refusal rather than a throw.
 */
export function logCheckpointSignedFields(checkpoint) {
    if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint))
        return null;
    if (!isStrictCanonicalJson(checkpoint))
        return null;
    const source = checkpoint;
    const fields = {};
    for (const key of Object.keys(source)) {
        if (key === 'log_signature')
            continue;
        if (!CHECKPOINT_SIGNED_KEYS.has(key))
            return null; // closed set; no smuggled members
        fields[key] = source[key];
    }
    if (!exactKeys(fields, CHECKPOINT_SIGNED_KEYS))
        return null;
    if (!Number.isSafeInteger(fields.tree_size) || fields.tree_size < 1)
        return null;
    if (typeof fields.root_hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(fields.root_hash))
        return null;
    if (typeof fields.log_key_id !== 'string' || fields.log_key_id.length === 0)
        return null;
    if (typeof fields.merkle_alg !== 'string' || fields.merkle_alg.length === 0)
        return null;
    return fields;
}
/**
 * Build the exact object both legs sign for a checkpoint. The required
 * algorithm set and the profile id are INSIDE it: the same anti-stripping
 * commitment EP-RECEIPT-HYBRID-v1 uses.
 *
 * @throws on a checkpoint outside the profile, or an algorithm set that is not
 *   the registered one. Verification catches this and refuses by name.
 */
export function logCheckpointHybridSignedMaterial(checkpoint, requiredAlgorithms = LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS) {
    const fields = logCheckpointSignedFields(checkpoint);
    if (!fields) {
        throw new Error('logCheckpointHybridSignedMaterial: checkpoint must carry exactly {tree_size, root_hash, log_key_id, merkle_alg} (log_signature optional and ignored)');
    }
    if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
        throw new Error(`logCheckpointHybridSignedMaterial: refusing: ${LOG_CHECKPOINT_HYBRID_REASONS.ALGORITHM_SET_MISMATCH}`);
    }
    return {
        '@version': LOG_CHECKPOINT_HYBRID_PROFILE,
        checkpoint: fields,
        required_algorithms: [...requiredAlgorithms],
    };
}
/** UTF-8 canonical bytes of logCheckpointHybridSignedMaterial(). */
export function logCheckpointHybridSignedBytes(checkpoint, requiredAlgorithms = LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS) {
    return Buffer.from(canonicalize(logCheckpointHybridSignedMaterial(checkpoint, requiredAlgorithms)), 'utf8');
}
/**
 * Verify an EP-LOG-CHECKPOINT-HYBRID-v1 proof against the checkpoint the
 * VERIFIER independently holds (normally `receipt.log_proof.checkpoint`).
 * FAIL-CLOSED; never throws on caller input.
 *
 * The proof's own `checkpoint` member is checked for byte equality against the
 * held one before any signature is examined (`checkpoint_mismatch`): a proof for
 * some other log head never speaks for this receipt. The signed bytes are then
 * rebuilt from the HELD checkpoint and the REGISTERED algorithm set.
 */
export async function verifyLogCheckpointHybridProof(heldCheckpoint, proof, keys, options = {}) {
    const checks = {
        profile: false,
        algorithm_set: null,
        checkpoint_bound: null,
        legs_present: null,
        signatures_valid: null,
    };
    const refuse = (reason, failedAlgorithm = null, setResult = null) => ({
        verified: false,
        reason,
        failed_algorithm: failedAlgorithm,
        checks,
        set_result: setResult,
    });
    // 1. Structure + profile marker, closed member set.
    if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_PROOF);
    }
    if (!isStrictCanonicalJson(proof))
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_PROOF);
    const p = proof;
    if (p['@version'] !== LOG_CHECKPOINT_HYBRID_PROFILE) {
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.UNKNOWN_PROFILE);
    }
    if (!exactKeys(p, CHECKPOINT_PROOF_KEYS))
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_PROOF);
    if (!exactKeys(p.profile, PROFILE_KEYS))
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_PROOF);
    if (p.profile.id !== LOG_CHECKPOINT_HYBRID_PROFILE) {
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.UNKNOWN_PROFILE);
    }
    checks.profile = true;
    // 2. Committed algorithm set, exact and order-sensitive.
    if (!algorithmSetMatchesRegistered(p.profile.required_algorithms)) {
        checks.algorithm_set = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.ALGORITHM_SET_MISMATCH);
    }
    checks.algorithm_set = true;
    // 3. The proof must speak for the checkpoint the verifier actually holds.
    const heldFields = logCheckpointSignedFields(heldCheckpoint);
    if (!heldFields) {
        checks.checkpoint_bound = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_CHECKPOINT);
    }
    if (heldFields.merkle_alg !== LOG_CHECKPOINT_HYBRID_MERKLE_ALG) {
        checks.checkpoint_bound = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.UNSUPPORTED_MERKLE_ALG);
    }
    const presentedFields = logCheckpointSignedFields(p.checkpoint);
    if (!presentedFields) {
        checks.checkpoint_bound = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_CHECKPOINT);
    }
    if (canonicalize(presentedFields) !== canonicalize(heldFields)) {
        checks.checkpoint_bound = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.CHECKPOINT_MISMATCH);
    }
    checks.checkpoint_bound = true;
    // 4. Exactly one signature per required algorithm.
    if (!Array.isArray(p.signatures) || p.signatures.length === 0) {
        checks.legs_present = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.HYBRID_LEG_MISSING);
    }
    const presented = new Set();
    for (const s of p.signatures) {
        if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
            checks.legs_present = false;
            return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_PROOF);
        }
        if (presented.has(s.alg)) {
            checks.legs_present = false;
            return refuse(LOG_CHECKPOINT_HYBRID_REASONS.DUPLICATE_ALGORITHM, s.alg);
        }
        presented.add(s.alg);
    }
    for (const alg of LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS) {
        if (!presented.has(alg)) {
            checks.legs_present = false;
            return refuse(LOG_CHECKPOINT_HYBRID_REASONS.HYBRID_LEG_MISSING, alg);
        }
    }
    for (const alg of presented) {
        if (!LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS.includes(alg)) {
            checks.legs_present = false;
            return refuse(LOG_CHECKPOINT_HYBRID_REASONS.UNEXPECTED_ALGORITHM, alg);
        }
    }
    checks.legs_present = true;
    // 5. Rebuild from the HELD checkpoint and the REGISTERED set; delegate.
    if (!keys || typeof keys !== 'object' || !keys.ed25519PublicKey || !keys.mldsaPublicKey) {
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MISSING_KEY);
    }
    let messageBytes;
    try {
        messageBytes = logCheckpointHybridSignedBytes(heldFields, LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS);
    }
    catch {
        checks.checkpoint_bound = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.MALFORMED_CHECKPOINT);
    }
    const verificationKeys = [
        { alg: 'Ed25519', public_key: keys.ed25519PublicKey, ...(keys.ed25519KeyId ? { key_id: keys.ed25519KeyId } : {}) },
        { alg: 'ML-DSA-65', public_key: keys.mldsaPublicKey, ...(keys.mldsaKeyId ? { key_id: keys.mldsaKeyId } : {}) },
    ];
    let setResult;
    try {
        setResult = await verifyAgileSignatureSet(new Uint8Array(messageBytes), p.signatures, verificationKeys, {
            ...agilityPassthrough(options),
            policy: 'hybrid_all',
            requiredAlgorithms: [...LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        checks.signatures_valid = false;
        return refuse(LOG_CHECKPOINT_HYBRID_REASONS.SIGNATURE_INVALID);
    }
    if (setResult?.verified === true) {
        checks.signatures_valid = true;
        return { verified: true, reason: null, failed_algorithm: null, checks, set_result: setResult };
    }
    checks.signatures_valid = false;
    return refuse(...mapSetFailure(setResult), setResult);
}
//# sourceMappingURL=receipt-hybrid.js.map