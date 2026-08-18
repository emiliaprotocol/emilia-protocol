// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RECEIPT-HYBRID-v1 -- ISSUANCE of receipts carrying BOTH an Ed25519 and an
 * ML-DSA-65 (FIPS 204) signature over one set of canonical bytes.
 *
 * WHY THIS FILE EXISTS. Before it, hybrid classical + post-quantum signing in
 * this repository was verify-side only: packages/verify/src/pq-signature-agility.ts
 * (EP-SIG-AGILITY-v1) can check a signature set, and packages/verify/src/pq-hybrid.ts
 * (EP-HYBRID-v1) wraps EP INFRASTRUCTURE keys. Nothing ISSUED a hybrid RECEIPT.
 * This module is the issuance path, so "post-quantum receipts" names something
 * a Gate or issuer can actually mint, as an OPT-IN profile.
 *
 * --- THE PROFILE DECISION: WHY A DISTINCT @version --------------------------
 *
 * A hybrid receipt MUST NOT be silently downgradable to a single-signature
 * receipt. Two independent controls enforce that, and the version marker is the
 * second one.
 *
 * 1. CRYPTOGRAPHIC SET COMMITMENT (the anti-stripping property). The bytes both
 *    legs sign are NOT canonicalize(payload). They are:
 *
 *      signed_material = {
 *        "@version":            "EP-RECEIPT-HYBRID-v1",
 *        "payload":             <the receipt payload>,
 *        "required_algorithms": ["Ed25519", "ML-DSA-65"]
 *      }
 *      message_bytes   = UTF8(canonicalize(signed_material))
 *
 *    The required algorithm SET is inside the signed bytes. Delete the ML-DSA
 *    leg and narrow `required_algorithms` to ["Ed25519"] and the surviving
 *    Ed25519 signature no longer verifies: the bytes changed. Leave the set
 *    intact and the missing leg is a structural refusal. Either way, stripping
 *    is detected, not tolerated. This is a real byte-level commitment, the same
 *    class of control EP-HYBRID-v1 gets from its domain-separated signing
 *    input, and it is STRONGER than relying-party policy alone (see the honest
 *    boundary in pq-signature-agility.ts: `hybrid_all` with pinned
 *    requiredAlgorithms is verifier POLICY, not a commitment).
 *
 * 2. CLEAN REFUSAL BY EXISTING v1 VERIFIERS. EP-RECEIPT-v1 verifiers pin
 *    SUPPORTED_VERSIONS = ['EP-RECEIPT-v1'] and read a single `signature`
 *    object. Handed a hybrid receipt they refuse on the version check with
 *    `Unsupported version: EP-RECEIPT-HYBRID-v1` BEFORE any signature is
 *    inspected. That is the outcome we want: an old verifier must not accept a
 *    hybrid receipt on the strength of one leg it happens to understand, and it
 *    must not crash. Reusing `@version: EP-RECEIPT-v1` for hybrid receipts
 *    would have forced exactly that choice on every deployed verifier. So the
 *    profile takes its own version marker and old verifiers fail closed with a
 *    named, boring reason.
 *
 *    Belt and braces: because control 1 puts the profile id inside the signed
 *    bytes, lifting a hybrid receipt's Ed25519 leg into an EP-RECEIPT-v1
 *    envelope with the same payload ALSO fails the signature check. A v1
 *    verifier refuses a hybrid receipt twice over, at the version and at the
 *    signature. conformance/hybrid-receipts/ proves both.
 *
 * --- DOCUMENT SHAPE ---------------------------------------------------------
 *
 *   {
 *     "@version": "EP-RECEIPT-HYBRID-v1",
 *     "profile": {
 *       "id": "EP-RECEIPT-HYBRID-v1",
 *       "required_algorithms": ["Ed25519", "ML-DSA-65"]
 *     },
 *     "payload": { ... },
 *     "signatures": [
 *       { "alg": "Ed25519",   "sig": "<base64url>", "key_id": "..." },
 *       { "alg": "ML-DSA-65", "sig": "<base64url>", "key_id": "..." }
 *     ],
 *     "metadata": { ... }        // OPTIONAL, unsigned, same role as in v1
 *   }
 *
 * `metadata` is deliberately OUTSIDE the signed material, matching the
 * EP-RECEIPT-v1 envelope, where the Ed25519 signature covers `payload` only.
 * Nothing a relying party authorizes on may live there.
 *
 * --- HONEST BOUNDARIES (substance, not hedging) -----------------------------
 *   - OPT-IN PROFILE. EP-RECEIPT-v1 remains the default receipt format. This
 *     profile is not on by default in any deployment.
 *   - The ML-DSA backend (@noble/post-quantum) is a pure-JS FIPS 204
 *     implementation. Per its own README it is not independently audited and it
 *     is NOT a FIPS-validated module. Issuing under this profile is not a
 *     certification claim.
 *   - No backend means REFUSAL. createHybridReceipt THROWS rather than emit a
 *     receipt missing the PQ leg; verifyHybridReceipt REFUSES with
 *     `pq_backend_unavailable` rather than pass on the classical leg alone.
 *   - This profile protects receipts issued FROM NOW ON. It does not
 *     retroactively protect already-issued single-algorithm receipts; that
 *     needs re-attestation while the classical algorithm is still unbroken
 *     (EP-EVIDENCE-REATTESTATION-v1).
 *   - Merkle anchoring is OUT OF SCOPE for v1 of this profile. An
 *     EP-MERKLE-v2 anchor self-checks its leaf against `doc.payload`, which is
 *     NOT what a hybrid receipt commits to; emitting one would be a structure
 *     no verifier actually checks end to end. Anchor the hybrid signed material
 *     under a profile that says so, or do not anchor.
 *
 * --- DEPENDENCY POSTURE -----------------------------------------------------
 * @emilia-protocol/issue is zero-dependency and its core EP-RECEIPT-v1 /
 * EP-AUTHORIZATION-RECEIPT-v1 paths stay that way: this module imports NOTHING
 * statically beyond node:crypto and ./index.js. The EP-SIG-AGILITY-v1
 * implementation is resolved at call time, either injected by the caller
 * (`agility`) or lazily loaded from @emilia-protocol/verify. Absent, every
 * entry point refuses with `agility_module_unavailable`; it never degrades to
 * a single-signature receipt.
 *
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
import { canonicalize, isCanonicalizable } from './index.js';
/** The profile id, used as both `@version` and `profile.id`. */
export const HYBRID_RECEIPT_PROFILE = 'EP-RECEIPT-HYBRID-v1';
/**
 * The registered required algorithm set, in canonical order. v1 is a FIXED
 * two-algorithm hybrid. This array is what goes into the signed material, so
 * its exact contents and order are part of what every leg commits to.
 */
export const HYBRID_RECEIPT_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
/** FIPS 204 ML-DSA-65 fixed sizes (bytes); mirrored from the agility module. */
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SECRET_KEY_BYTES = 4032;
/** Named refusals. Every failure path returns one of these; none throw. */
export const HYBRID_RECEIPT_REASONS = Object.freeze({
    MALFORMED_RECEIPT: 'malformed_receipt',
    MALFORMED_PAYLOAD: 'malformed_payload',
    UNKNOWN_PROFILE: 'unknown_profile',
    ALGORITHM_SET_MISMATCH: 'algorithm_set_mismatch',
    HYBRID_LEG_MISSING: 'hybrid_leg_missing',
    UNEXPECTED_ALGORITHM: 'unexpected_algorithm',
    DUPLICATE_ALGORITHM: 'duplicate_algorithm',
    MISSING_KEY: 'missing_key',
    SIGNATURE_INVALID: 'signature_invalid',
    PQ_BACKEND_UNAVAILABLE: 'pq_backend_unavailable',
    AGILITY_MODULE_UNAVAILABLE: 'agility_module_unavailable',
});
// ---------------------------------------------------------------------------
// Agility module resolution (lazy, fail-closed, never statically imported)
// ---------------------------------------------------------------------------
// Non-literal specifiers on purpose: neither tsc nor a bundler should try to
// resolve these, and @emilia-protocol/issue must not gain a hard dependency on
// @emilia-protocol/verify. Same pattern as
// packages/gate/src/trust-program-adapters.ts.
const AGILITY_PACKAGE_SPECIFIER = '@emilia-protocol/verify/pq-signature-agility';
const AGILITY_LOCAL_SPECIFIER = '../../verify/dist/pq-signature-agility.js';
let cachedAgility;
function isAgilityModule(value) {
    const m = value;
    return !!m && typeof m.signAgileSet === 'function' && typeof m.verifyAgileSignatureSet === 'function';
}
/**
 * Resolve the EP-SIG-AGILITY-v1 implementation. Returns null rather than
 * throwing, so callers refuse with a named reason. Tries the published subpath
 * first, then the in-repo sibling build (packages/issue/{src,dist}/../../verify
 * both resolve to packages/verify).
 */
export async function loadAgilityModule() {
    if (cachedAgility !== undefined)
        return cachedAgility;
    for (const specifier of [AGILITY_PACKAGE_SPECIFIER, AGILITY_LOCAL_SPECIFIER]) {
        try {
            const mod = await import(specifier);
            if (isAgilityModule(mod)) {
                cachedAgility = mod;
                return cachedAgility;
            }
        }
        catch {
            // try the next specifier; absence is a refusal, never a crash
        }
    }
    cachedAgility = null;
    return null;
}
async function resolveAgility(options) {
    if (options.agility !== undefined && options.agility !== null) {
        return isAgilityModule(options.agility) ? options.agility : null;
    }
    return loadAgilityModule();
}
function agilityPassthrough(options) {
    const out = {};
    if (options.mldsaBackend !== undefined)
        out.mldsaBackend = options.mldsaBackend;
    if (options.mldsaBackendLoader !== undefined)
        out.mldsaBackendLoader = options.mldsaBackendLoader;
    if (options.deterministic === true)
        out.deterministic = true;
    return out;
}
// ---------------------------------------------------------------------------
// The signed material (produced ONCE, signed by every leg)
// ---------------------------------------------------------------------------
/**
 * Build the exact object both legs sign. The required algorithm set and the
 * profile id are INSIDE it: that is the anti-stripping commitment. Exported so
 * a verifier, a conformance vector, or an independent implementation can
 * rebuild the bytes without reading this module's internals.
 *
 * @throws if the payload is outside the EP canonicalization profile, or if the
 *   algorithm set is not the registered one (a receipt committing to a set we
 *   do not recognize must never be minted).
 */
export function hybridSignedMaterial(payload, requiredAlgorithms = HYBRID_RECEIPT_REQUIRED_ALGORITHMS) {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new TypeError('hybridSignedMaterial: payload must be a plain object');
    }
    if (!isCanonicalizable(payload)) {
        throw new Error('hybridSignedMaterial: payload is outside the EP canonicalization profile; encode non-integer quantities as strings');
    }
    if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
        throw new Error(`hybridSignedMaterial: refusing: ${HYBRID_RECEIPT_REASONS.ALGORITHM_SET_MISMATCH}`);
    }
    return {
        '@version': HYBRID_RECEIPT_PROFILE,
        payload,
        required_algorithms: [...requiredAlgorithms],
    };
}
/** UTF-8 canonical bytes of hybridSignedMaterial(). What every leg signs. */
export function hybridSignedBytes(payload, requiredAlgorithms = HYBRID_RECEIPT_REQUIRED_ALGORITHMS) {
    return Buffer.from(canonicalize(hybridSignedMaterial(payload, requiredAlgorithms)), 'utf8');
}
function algorithmSetMatchesRegistered(algorithms) {
    return Array.isArray(algorithms)
        && algorithms.length === HYBRID_RECEIPT_REQUIRED_ALGORITHMS.length
        && algorithms.every((a, i) => a === HYBRID_RECEIPT_REQUIRED_ALGORITHMS[i]);
}
// ---------------------------------------------------------------------------
// Key material helpers (EP-HYBRID-ISSUER-KEYS-v1)
// ---------------------------------------------------------------------------
/**
 * The hybrid sibling of EP-ISSUER-KEYS-v1 (see generateIssuerKeyBundle in
 * ./index.ts): one bundle carrying BOTH signing keys plus their public halves,
 * so an issuer configures one artifact rather than two loose key files. The
 * bundle carries private material; share only verificationKeysFromHybridBundle().
 *
 * ML-DSA keygen is not in node:crypto, so it is injected or lazily loaded from
 * @noble/post-quantum. Absent, this THROWS: a "hybrid" bundle with no PQ key is
 * worse than no bundle.
 */
export async function generateHybridIssuerKeyBundle({ ed25519KeyId = 'ep:key:hybrid-issuer-ed25519#1', mldsaKeyId = 'ep:key:hybrid-issuer-ml-dsa-65#1', seed, mldsaKeygen, } = {}) {
    const keygen = mldsaKeygen ?? await loadDefaultMldsaKeygen();
    if (typeof keygen !== 'function') {
        throw new Error(`generateHybridIssuerKeyBundle: refusing: ${HYBRID_RECEIPT_REASONS.PQ_BACKEND_UNAVAILABLE}`);
    }
    const ed = crypto.generateKeyPairSync('ed25519');
    const pq = keygen(seed ?? new Uint8Array(crypto.randomBytes(32)));
    if (!pq || !(pq.publicKey instanceof Uint8Array) || !(pq.secretKey instanceof Uint8Array)) {
        throw new Error('generateHybridIssuerKeyBundle: ML-DSA keygen returned invalid key material');
    }
    return {
        '@version': 'EP-HYBRID-ISSUER-KEYS-v1',
        profile: HYBRID_RECEIPT_PROFILE,
        ed25519: {
            key_id: ed25519KeyId,
            private_key: ed.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url'),
            public_key: ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        },
        'ml-dsa-65': {
            key_id: mldsaKeyId,
            private_key: Buffer.from(pq.secretKey).toString('base64url'),
            public_key: Buffer.from(pq.publicKey).toString('base64url'),
        },
    };
}
const MLDSA_PACKAGE_SPECIFIER = '@noble/post-quantum/ml-dsa.js';
async function loadDefaultMldsaKeygen() {
    try {
        const mod = await import(MLDSA_PACKAGE_SPECIFIER);
        const impl = mod?.ml_dsa65;
        return typeof impl?.keygen === 'function' ? (s) => impl.keygen(s) : null;
    }
    catch {
        return null;
    }
}
/** Signing keys (private material) from an EP-HYBRID-ISSUER-KEYS-v1 bundle. */
export function signingKeysFromHybridBundle(bundle) {
    const ed = bundle?.ed25519;
    const pq = bundle?.['ml-dsa-65'];
    if (!ed?.private_key || !pq?.private_key) {
        throw new Error('signingKeysFromHybridBundle: bundle must be EP-HYBRID-ISSUER-KEYS-v1 with both private keys');
    }
    return {
        ed25519PrivateKey: crypto.createPrivateKey({
            key: Buffer.from(ed.private_key, 'base64url'),
            format: 'der',
            type: 'pkcs8',
        }),
        ed25519KeyId: ed.key_id,
        mldsaSecretKey: pq.private_key,
        mldsaKeyId: pq.key_id,
    };
}
/** Public verification material from an EP-HYBRID-ISSUER-KEYS-v1 bundle. */
export function verificationKeysFromHybridBundle(bundle) {
    const ed = bundle?.ed25519;
    const pq = bundle?.['ml-dsa-65'];
    if (!ed?.public_key || !pq?.public_key) {
        throw new Error('verificationKeysFromHybridBundle: bundle must be EP-HYBRID-ISSUER-KEYS-v1 with both public keys');
    }
    return {
        ed25519PublicKey: ed.public_key,
        ed25519KeyId: ed.key_id,
        mldsaPublicKey: pq.public_key,
        mldsaKeyId: pq.key_id,
    };
}
// ---------------------------------------------------------------------------
// createHybridReceipt (issuer side; THROWS on misuse, never downgrades)
// ---------------------------------------------------------------------------
/**
 * Mint an EP-RECEIPT-HYBRID-v1 receipt: canonical bytes computed ONCE, signed
 * under Ed25519 AND ML-DSA-65 via EP-SIG-AGILITY-v1's signAgileSet.
 *
 * Issuer-side misuse is a programming error, so this THROWS (matching signAgile
 * and signHybrid). In particular it throws rather than emit a receipt missing
 * the PQ leg when no ML-DSA backend is available.
 *
 * @param payload  the receipt payload; the same object an EP-RECEIPT-v1 issuer
 *                 would put in `payload`, held to the same canonicalization
 *                 profile.
 * @param keys     both private keys (see signingKeysFromHybridBundle).
 * @param metadata OPTIONAL unsigned envelope metadata, as in EP-RECEIPT-v1.
 */
export async function createHybridReceipt({ payload, keys, metadata, ...options }) {
    if (!keys || typeof keys !== 'object')
        throw new TypeError('createHybridReceipt: keys is required');
    const edPriv = keys.ed25519PrivateKey;
    if (!edPriv || typeof edPriv !== 'object' || edPriv.type !== 'private') {
        throw new TypeError('createHybridReceipt: keys.ed25519PrivateKey must be a node crypto private KeyObject');
    }
    // signAgile curve-pins too; refusing here as well keeps the misuse message
    // attached to the issuance call the operator actually wrote.
    if (edPriv.asymmetricKeyType !== 'ed25519') {
        throw new Error('createHybridReceipt: refusing to sign: keys.ed25519PrivateKey is not Ed25519');
    }
    const pqSecret = toRawBytes(keys.mldsaSecretKey);
    if (!pqSecret || pqSecret.length !== ML_DSA_65_SECRET_KEY_BYTES) {
        throw new TypeError(`createHybridReceipt: keys.mldsaSecretKey must be ${ML_DSA_65_SECRET_KEY_BYTES} raw bytes (or base64url of them)`);
    }
    if (metadata !== undefined && !isCanonicalizable(metadata)) {
        throw new Error('createHybridReceipt: metadata is outside the EP canonicalization profile');
    }
    const agility = await resolveAgility(options);
    if (!agility) {
        throw new Error(`createHybridReceipt: refusing to sign: ${HYBRID_RECEIPT_REASONS.AGILITY_MODULE_UNAVAILABLE}`);
    }
    const requiredAlgorithms = [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS];
    // ONE set of canonical bytes; both legs sign exactly these.
    const messageBytes = hybridSignedBytes(payload, requiredAlgorithms);
    const signingKeys = [
        { alg: 'Ed25519', private_key: edPriv, ...(keys.ed25519KeyId ? { key_id: keys.ed25519KeyId } : {}) },
        { alg: 'ML-DSA-65', private_key: pqSecret, ...(keys.mldsaKeyId ? { key_id: keys.mldsaKeyId } : {}) },
    ];
    // signAgileSet throws on an unavailable ML-DSA backend, which is the
    // fail-closed behaviour we want: no half-hybrid receipt is ever emitted.
    const signatures = await agility.signAgileSet(new Uint8Array(messageBytes), signingKeys, agilityPassthrough(options));
    // Order the emitted signatures to match the committed set, so the document
    // reads the same way the bytes commit.
    const byAlg = new Map(signatures.map((s) => [s.alg, s]));
    const ordered = [];
    for (const alg of requiredAlgorithms) {
        const s = byAlg.get(alg);
        if (!s)
            throw new Error(`createHybridReceipt: signing produced no ${alg} leg`);
        ordered.push(s);
    }
    const doc = {
        '@version': HYBRID_RECEIPT_PROFILE,
        profile: { id: HYBRID_RECEIPT_PROFILE, required_algorithms: requiredAlgorithms },
        payload,
        signatures: ordered,
    };
    if (metadata !== undefined)
        doc.metadata = metadata;
    return doc;
}
/**
 * Mint an EP-RECEIPT-HYBRID-v1 receipt from a CUSTODY SIGNER rather than from
 * raw private key material.
 *
 * WHY BOTH ENTRY POINTS EXIST. createHybridReceipt() takes the secret bytes
 * and drives EP-SIG-AGILITY-v1 itself, which is right for an issuer that holds
 * its own keys. A deployment whose classical leg is behind a KMS/HSM boundary
 * has no secret bytes to hand over: it has a registered dual signer that will
 * sign(bytes) on request. Without this entry point such a deployment could not
 * mint a hybrid receipt at all, so a custody-resolved default would resolve to
 * a posture it could not execute.
 *
 * WHAT IS IDENTICAL, AND WHY THAT MATTERS. The bytes are built HERE by
 * hybridSignedBytes() from the REGISTERED algorithm set, exactly as
 * createHybridReceipt() builds them, so the anti-stripping commitment (profile
 * id + required-algorithm set inside the signed bytes) is a property of this
 * module and not of the signer. The signer chooses nothing about what it is
 * signing, and the emitted document is the same shape verifyHybridReceipt()
 * already checks. The set is never narrowed to what a signer returned: a signer
 * that answers with anything other than one signature per REGISTERED algorithm
 * is a THROW, never a receipt with a missing leg.
 *
 * Issuer-side misuse is a programming error, so this THROWS, matching
 * createHybridReceipt() and createLogCheckpointHybridProof(). A PQ signer with
 * no ML-DSA backend throws `pq_backend_unavailable` from its own sign(); that
 * propagates as a refusal to issue, never as a classical-only receipt.
 */
export async function createHybridReceiptFromSignSet({ payload, signSet, metadata, context, }) {
    if (typeof signSet !== 'function') {
        throw new TypeError('createHybridReceiptFromSignSet: signSet must be a dual-signer signSet(bytes) (see createHybridCustodySigner)');
    }
    if (metadata !== undefined && !isCanonicalizable(metadata)) {
        throw new Error('createHybridReceiptFromSignSet: metadata is outside the EP canonicalization profile');
    }
    const requiredAlgorithms = [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS];
    // ONE set of canonical bytes, built from the REGISTERED set; every leg signs
    // exactly these. Throws on a payload outside the canonicalization profile.
    const messageBytes = hybridSignedBytes(payload, requiredAlgorithms);
    const signatures = await signSet(messageBytes, {
        profile: HYBRID_RECEIPT_PROFILE,
        required_algorithms: requiredAlgorithms,
        ...(context ?? {}),
    });
    if (!Array.isArray(signatures)) {
        throw new Error('createHybridReceiptFromSignSet: signSet must return one signature per required algorithm');
    }
    // Order the emitted signatures to match the committed set, so the document
    // reads the same way the bytes commit. A missing or malformed leg is a throw.
    const byAlg = new Map(signatures.map((s) => [s?.alg, s]));
    const ordered = [];
    for (const alg of requiredAlgorithms) {
        const s = byAlg.get(alg);
        if (!s || typeof s.sig !== 'string' || s.sig.length === 0) {
            throw new Error(`createHybridReceiptFromSignSet: signing produced no ${alg} leg`);
        }
        ordered.push(s.key_id === undefined ? { alg, sig: s.sig } : { alg, sig: s.sig, key_id: s.key_id });
    }
    // An extra leg means the signer signed under an algorithm this profile does
    // not commit to; the document must not carry it.
    for (const s of signatures) {
        if (!requiredAlgorithms.includes(s?.alg)) {
            throw new Error(`createHybridReceiptFromSignSet: signSet returned an unexpected algorithm: ${String(s?.alg)}`);
        }
    }
    const doc = {
        '@version': HYBRID_RECEIPT_PROFILE,
        profile: { id: HYBRID_RECEIPT_PROFILE, required_algorithms: requiredAlgorithms },
        payload,
        signatures: ordered,
    };
    if (metadata !== undefined)
        doc.metadata = metadata;
    return doc;
}
function toRawBytes(value) {
    if (value instanceof Uint8Array)
        return value;
    if (typeof value === 'string' && value.length > 0) {
        if (!/^[A-Za-z0-9_-]+$/.test(value))
            return null;
        try {
            return new Uint8Array(Buffer.from(value, 'base64url'));
        }
        catch {
            return null;
        }
    }
    return null;
}
// ---------------------------------------------------------------------------
// verifyHybridReceipt (never throws)
// ---------------------------------------------------------------------------
/**
 * Verify an EP-RECEIPT-HYBRID-v1 receipt. FAIL-CLOSED: every malformed,
 * unknown, or stripped input returns a named refusal; nothing throws on caller
 * input.
 *
 * Order of checks, and why:
 *   1. Structure and profile marker. An unknown `@version` or `profile.id`
 *      refuses with `unknown_profile` -- this module is not a general receipt
 *      verifier and never guesses at another format.
 *   2. `profile.required_algorithms` must EXACTLY equal the registered set,
 *      order included (`algorithm_set_mismatch`). A narrowed set is the
 *      stripping attack's cover story, so it is refused structurally, before
 *      the (also failing) signature check.
 *   3. Exactly one signature per required algorithm: a missing leg is
 *      `hybrid_leg_missing`, an extra one `unexpected_algorithm`, a repeat
 *      `duplicate_algorithm`.
 *   4. The bytes are rebuilt from `doc.payload` and the REGISTERED set (never
 *      from anything the document could have narrowed), then handed to
 *      EP-SIG-AGILITY-v1's verifyAgileSignatureSet under policy `hybrid_all`
 *      with requiredAlgorithms pinned to the full set. Every leg must verify
 *      over identical bytes.
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
    // 1. Structure + profile marker.
    if (!doc || typeof doc !== 'object' || Array.isArray(doc))
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
    if (!isCanonicalizable(doc))
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
    const d = doc;
    if (d['@version'] !== HYBRID_RECEIPT_PROFILE)
        return refuse(HYBRID_RECEIPT_REASONS.UNKNOWN_PROFILE);
    if (!d.profile || typeof d.profile !== 'object' || Array.isArray(d.profile)) {
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_RECEIPT);
    }
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
    // 4. Rebuild the bytes and delegate the set verdict.
    if (!d.payload || typeof d.payload !== 'object' || Array.isArray(d.payload) || !isCanonicalizable(d.payload)) {
        return refuse(HYBRID_RECEIPT_REASONS.MALFORMED_PAYLOAD);
    }
    if (!keys || typeof keys !== 'object' || !keys.ed25519PublicKey || !keys.mldsaPublicKey) {
        return refuse(HYBRID_RECEIPT_REASONS.MISSING_KEY);
    }
    const agility = await resolveAgility(options);
    if (!agility)
        return refuse(HYBRID_RECEIPT_REASONS.AGILITY_MODULE_UNAVAILABLE);
    let messageBytes;
    try {
        // The REGISTERED set, never d.profile.required_algorithms: the document
        // does not get to choose what it is checked against.
        messageBytes = hybridSignedBytes(d.payload, HYBRID_RECEIPT_REQUIRED_ALGORITHMS);
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
        setResult = await agility.verifyAgileSignatureSet(new Uint8Array(messageBytes), d.signatures, verificationKeys, {
            ...agilityPassthrough(options),
            policy: 'hybrid_all',
            requiredAlgorithms: [...HYBRID_RECEIPT_REQUIRED_ALGORITHMS],
        });
    }
    catch {
        // verifyAgileSignatureSet documents that it never throws; if an injected
        // implementation does, that is still a refusal here, never a pass.
        checks.signatures_valid = false;
        return refuse(HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID);
    }
    if (setResult?.verified === true) {
        checks.signatures_valid = true;
        return { verified: true, reason: null, failed_algorithm: null, checks, set_result: setResult };
    }
    checks.signatures_valid = false;
    const failed = Array.isArray(setResult?.results)
        ? setResult.results.find((r) => r?.verified !== true) ?? null
        : null;
    const failedAlgorithm = failed?.alg ?? null;
    // Map the set verifier's reason onto this profile's named vocabulary. The
    // full agility result stays attached in `set_result` so nothing is lost.
    const rawReason = String(setResult?.reason ?? '');
    if (rawReason === 'missing_required_algorithm') {
        return refuse(HYBRID_RECEIPT_REASONS.HYBRID_LEG_MISSING, failedAlgorithm, setResult);
    }
    if (rawReason.endsWith('pq_backend_unavailable') || failed?.reason === 'pq_backend_unavailable') {
        return refuse(HYBRID_RECEIPT_REASONS.PQ_BACKEND_UNAVAILABLE, failedAlgorithm, setResult);
    }
    if (failed?.reason === 'malformed_key' || failed?.reason === 'algorithm_key_mismatch') {
        return refuse(HYBRID_RECEIPT_REASONS.MISSING_KEY, failedAlgorithm, setResult);
    }
    return refuse(HYBRID_RECEIPT_REASONS.SIGNATURE_INVALID, failedAlgorithm, setResult);
}
//# sourceMappingURL=hybrid-issuance.js.map