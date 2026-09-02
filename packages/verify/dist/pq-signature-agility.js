// SPDX-License-Identifier: Apache-2.0
/**
 * EP-SIG-AGILITY-v1 -- per-artifact signature-algorithm agility for EP
 * evidence (receipts, evidence records, and other canonicalized artifacts).
 *
 * WHY THIS EXISTS. Authorization evidence has a decades-long verification
 * horizon: disputes, statutes of limitations, and government retention
 * schedules (10-25+ years) mean an Ed25519 receipt signed today must still be
 * trustworthy testimony in 2035 and beyond. No single algorithm survives that
 * horizon on faith. This module makes the SIGNATURE ALGORITHM an explicit,
 * verifier-checked field over the SAME canonical bytes the existing
 * EP-RECEIPT-v1 path signs (the JCS-style canonicalization of the payload),
 * so a receipt can be signed and verified under Ed25519, under ML-DSA-65
 * (FIPS 204, module-lattice post-quantum), or under both at once, without
 * changing what is signed.
 *
 * CLOSED ALGORITHM REGISTRY. Exactly { Ed25519, ML-DSA-65 } in v1. An
 * algorithm outside the registry is a REFUSAL with reason
 * 'unknown_algorithm', never a pass-through: an INDETERMINATE algorithm never
 * authorizes anything.
 *
 * FAIL-CLOSED. verifyAgileSignature and verifyAgileSignatureSet never throw
 * on caller input: malformed message, signature, or key material returns a
 * structured refusal naming the reason. Signing functions throw (issuer-side
 * misuse is a programming error, not attacker input).
 *
 * SYNCHRONOUS TWIN. verifyAgileSignatureSync applies the SAME rules with no
 * await, so EP's frozen synchronous Class A verifier (verifyWebAuthnSignoff)
 * can be algorithm-agile without a second copy of these checks living next to
 * it. The shared preflight and per-algorithm crypto steps are literally the
 * same functions; only ML-DSA backend acquisition differs, and the sync path
 * takes an injected backend or the node:crypto-native FIPS 204 provider, never
 * an async loader. A runtime with neither refuses ('pq_backend_unavailable').
 *
 * HYBRID MODE. verifyAgileSignatureSet checks several signatures over the
 * SAME message bytes. Policy 'hybrid_all' requires every required algorithm
 * to be present and every presented signature to verify. Policy
 * 'per_algorithm' reports each algorithm's verdict separately and sets the
 * top-level verdict to null: VERIFIED stays per-algorithm and is never
 * collapsed; null never authorizes.
 *
 * HONEST BOUNDARIES (substance, not hedging):
 *   - This module does NOT cryptographically commit the signatures to the
 *     algorithm set. A stripped signature is detected only because the
 *     relying party pins requiredAlgorithms as verifier policy. For an
 *     envelope whose signatures themselves commit to the full set
 *     (anti-stripping), use EP-HYBRID-v1 (./pq-hybrid.js).
 *   - Algorithm agility protects artifacts signed FROM NOW ON under the new
 *     algorithm. It does not retroactively protect an already-issued
 *     single-algorithm artifact; that requires re-attestation while the old
 *     algorithm is still unbroken (see evidence-record.ts,
 *     EP-EVIDENCE-REATTESTATION-v1).
 *   - The default ML-DSA backend (@noble/post-quantum 0.7.0) is a pure-JS
 *     FIPS 204 implementation that is not a FIPS-validated module. No
 *     backend present means REFUSAL ('pq_backend_unavailable'), never a
 *     skipped check.
 *
 * KEY / SIGNATURE ENCODING (matches index.ts and pq-hybrid.ts conventions)
 *   - Ed25519 public key: base64url SPKI DER (or a node crypto KeyObject).
 *   - Ed25519 private key: node crypto KeyObject.
 *   - ML-DSA-65 public key: raw bytes (Uint8Array, 1952 bytes) or base64url.
 *   - ML-DSA-65 secret key: raw bytes (Uint8Array, 4032 bytes) or base64url.
 *   - Signatures: base64url strings (Ed25519 64 bytes, ML-DSA-65 3309 bytes).
 *
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
export const SIGNATURE_AGILITY_VERSION = 'EP-SIG-AGILITY-v1';
/** The closed v1 algorithm registry, in canonical order. */
export const AGILE_SIGNATURE_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65']);
/** FIPS 204 ML-DSA-65 fixed sizes (bytes). */
export const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
export const ML_DSA_65_SECRET_KEY_BYTES = 4032;
export const ML_DSA_65_SIGNATURE_BYTES = 3309;
export const AGILITY_REASONS = Object.freeze({
    MALFORMED_INPUT: 'malformed_input',
    UNKNOWN_ALGORITHM: 'unknown_algorithm',
    UNKNOWN_POLICY: 'unknown_policy',
    MALFORMED_KEY: 'malformed_key',
    MALFORMED_SIGNATURE: 'malformed_signature',
    ALGORITHM_KEY_MISMATCH: 'algorithm_key_mismatch',
    SIGNATURE_INVALID: 'signature_invalid',
    PQ_BACKEND_UNAVAILABLE: 'pq_backend_unavailable',
    DUPLICATE_ALGORITHM: 'duplicate_algorithm',
    MISSING_REQUIRED_ALGORITHM: 'missing_required_algorithm',
    EMPTY_SIGNATURE_SET: 'empty_signature_set',
});
// ---------------------------------------------------------------------------
// ML-DSA backend (lazy, fail-closed; mirrors pq-hybrid.ts but passes opts
// through so the FIPS 204 deterministic variant is reachable)
// ---------------------------------------------------------------------------
/**
 * Load the default ML-DSA-65 backend (@noble/post-quantum). Returns a backend
 * or null; NEVER throws. Absence yields null so callers refuse.
 */
export async function loadDefaultAgilityMldsaBackend() {
    try {
        const mod = await import('@noble/post-quantum/ml-dsa.js');
        const impl = mod.ml_dsa65;
        if (!impl || typeof impl.sign !== 'function' || typeof impl.verify !== 'function')
            return null;
        return {
            sign: (messageBytes, secretKeyBytes, opts) => impl.sign(messageBytes, secretKeyBytes, opts),
            verify: (signatureBytes, messageBytes, publicKeyBytes) => {
                try {
                    return impl.verify(signatureBytes, messageBytes, publicKeyBytes) === true;
                }
                catch {
                    return false; // malformed sig/key refuses, never throws upward
                }
            },
        };
    }
    catch {
        return null;
    }
}
/**
 * DER SPKI header for an ML-DSA-65 public key: SEQUENCE(1970) {
 *   SEQUENCE(11) { OID 2.16.840.1.101.3.4.3.18 (id-ml-dsa-65) },
 *   BIT STRING(1953, 0 unused) }. Fixed by construction because the key body
 * is a fixed 1952 bytes, so prefix || raw is the whole SPKI encoding.
 */
export const ML_DSA_65_SPKI_PREFIX = Uint8Array.from(Buffer.from('308207b2300b0609608648016503040312038207a100', 'hex'));
/** raw ML-DSA-65 public key bytes -> SPKI DER. Returns null on a wrong length. */
export function mldsaSpkiFromRawPublicKey(raw) {
    const bytes = toRawKeyBytes(raw);
    if (!bytes || bytes.length !== ML_DSA_65_PUBLIC_KEY_BYTES)
        return null;
    const out = new Uint8Array(ML_DSA_65_SPKI_PREFIX.length + bytes.length);
    out.set(ML_DSA_65_SPKI_PREFIX, 0);
    out.set(bytes, ML_DSA_65_SPKI_PREFIX.length);
    return out;
}
/**
 * SPKI DER -> raw ML-DSA-65 public key bytes. Returns null unless the input is
 * exactly the ML-DSA-65 SPKI encoding: a different algorithm OID, a different
 * length, or a truncated key is a null, never a best-effort slice.
 */
export function mldsaRawPublicKeyFromSpki(spki) {
    const bytes = toRawKeyBytes(spki);
    if (!bytes || bytes.length !== ML_DSA_65_SPKI_PREFIX.length + ML_DSA_65_PUBLIC_KEY_BYTES)
        return null;
    for (let i = 0; i < ML_DSA_65_SPKI_PREFIX.length; i++) {
        if (bytes[i] !== ML_DSA_65_SPKI_PREFIX[i])
            return null;
    }
    return bytes.subarray(ML_DSA_65_SPKI_PREFIX.length);
}
// A runtime with native FIPS 204 support in node:crypto (Node 24+ builds
// against an OpenSSL that carries ML-DSA) can verify ML-DSA-65 synchronously.
// Older runtimes have no such provider, so the probe caches null and every
// caller refuses with 'pq_backend_unavailable' rather than skipping a check.
let nativeMldsaProbe;
/**
 * The node:crypto-native ML-DSA-65 backend, or null when this runtime has no
 * ML-DSA provider. Synchronous by construction (no dynamic import), which is
 * what lets a synchronous verifier -- verifyWebAuthnSignoff -- reach the same
 * verification code path as the async one.
 */
export function nodeNativeMldsaBackend() {
    if (nativeMldsaProbe !== undefined)
        return nativeMldsaProbe;
    try {
        // Feature probe: can this runtime parse an ML-DSA-65 SPKI at all?
        const probeSpki = mldsaSpkiFromRawPublicKey(new Uint8Array(ML_DSA_65_PUBLIC_KEY_BYTES));
        if (!probeSpki) {
            nativeMldsaProbe = null;
            return null;
        }
        const probeKey = crypto.createPublicKey({ key: Buffer.from(probeSpki), format: 'der', type: 'spki' });
        if (probeKey.asymmetricKeyType !== 'ml-dsa-65') {
            nativeMldsaProbe = null;
            return null;
        }
    }
    catch {
        nativeMldsaProbe = null;
        return null;
    }
    nativeMldsaProbe = {
        verify: (signatureBytes, messageBytes, publicKeyBytes) => {
            try {
                const spki = mldsaSpkiFromRawPublicKey(publicKeyBytes);
                if (!spki)
                    return false;
                const keyObject = crypto.createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
                if (keyObject.asymmetricKeyType !== 'ml-dsa-65')
                    return false;
                // FIPS 204 pure ML-DSA: no pre-hash, so the digest argument is null.
                // Passing a digest name here is what throws ERR_OSSL_INVALID_DIGEST.
                return crypto.verify(null, Buffer.from(messageBytes), keyObject, Buffer.from(signatureBytes)) === true;
            }
            catch {
                return false; // malformed sig/key refuses, never throws upward
            }
        },
    };
    return nativeMldsaProbe;
}
/**
 * Backend resolution for the SYNCHRONOUS path. An injected `mldsaBackend` wins
 * (tests and hosts that carry their own FIPS 204 provider); otherwise the
 * node-native backend; otherwise null, which every caller turns into
 * 'pq_backend_unavailable'. `mldsaBackendLoader` is deliberately NOT consulted:
 * it is async and a synchronous verifier cannot await it, so silently ignoring
 * an injected loader would be worse than refusing.
 */
function resolveSyncAgilityBackend(options) {
    if (options.mldsaBackend !== undefined && options.mldsaBackend !== null) {
        return typeof options.mldsaBackend.verify === 'function' ? options.mldsaBackend : null;
    }
    return nodeNativeMldsaBackend();
}
async function resolveAgilityBackend(options) {
    if (options.mldsaBackend !== undefined && options.mldsaBackend !== null) {
        if (typeof options.mldsaBackend.verify !== 'function')
            return null;
        return options.mldsaBackend;
    }
    const loader = typeof options.mldsaBackendLoader === 'function'
        ? options.mldsaBackendLoader
        : loadDefaultAgilityMldsaBackend;
    try {
        const b = await loader();
        if (!b || typeof b.verify !== 'function')
            return null;
        return b;
    }
    catch {
        return null;
    }
}
// ---------------------------------------------------------------------------
// Input normalization (strict; lenient decoding would mask tampering class)
// ---------------------------------------------------------------------------
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
/**
 * Decode unpadded base64url, CANONICALLY. Buffer.from(..., 'base64url') ignores
 * the slack bits in the final character, so without the round-trip check below
 * many distinct strings decode to the same bytes: a 64-byte Ed25519 signature
 * is 86 characters whose last character carries 4 significant bits and 2 slack
 * bits, so 4 encodings of every signature would verify. That makes a signed
 * document's serialized bytes malleable without touching the signature itself.
 * Re-encoding and comparing pins exactly one encoding per byte string, and
 * matches the receipt path (packages/verify/src/index.ts decodeBase64url) and
 * lib/signatures.ts decodeBase64Strict.
 */
function b64urlToBytes(s) {
    if (typeof s !== 'string' || s.length === 0 || !B64URL_RE.test(s))
        return null;
    if (s.length % 4 === 1)
        return null;
    try {
        const b = Buffer.from(s, 'base64url');
        if (b.length === 0 || b.toString('base64url') !== s)
            return null;
        return b;
    }
    catch {
        return null;
    }
}
function toRawKeyBytes(key) {
    if (key instanceof Uint8Array)
        return key;
    if (typeof key === 'string')
        return b64urlToBytes(key);
    return null;
}
function toEd25519PublicKeyObject(key) {
    try {
        if (key && typeof key === 'object' && key.type === 'public') {
            const k = key;
            return k.asymmetricKeyType === 'ed25519' ? k : null;
        }
        if (typeof key === 'string') {
            const der = b64urlToBytes(key);
            if (!der)
                return null;
            const k = crypto.createPublicKey({ key: Buffer.from(der), format: 'der', type: 'spki' });
            // Pin the curve: a non-Ed25519 SPKI key must never be verified under a
            // different algorithm than the signature declares (same guard as
            // verifyReceipt in index.ts).
            return k.asymmetricKeyType === 'ed25519' ? k : null;
        }
    }
    catch {
        return null;
    }
    return null;
}
function isKnownAlgorithm(alg) {
    return typeof alg === 'string' && AGILE_SIGNATURE_ALGORITHMS.includes(alg);
}
// ---------------------------------------------------------------------------
// signAgile / signAgileSet (issuer side; throws on misuse, fail-closed on
// missing PQ backend -- never silently downgrades)
// ---------------------------------------------------------------------------
/**
 * Sign canonical artifact bytes under one registered algorithm.
 * The caller supplies the SAME canonical bytes the existing EP receipt path
 * signs: Buffer.from(canonicalize(payload), 'utf8').
 *
 * @throws on unknown algorithm, malformed key, or unavailable ML-DSA backend.
 */
export async function signAgile(messageBytes, key, options = {}) {
    if (!(messageBytes instanceof Uint8Array)) {
        throw new TypeError('signAgile: messageBytes must be a Uint8Array');
    }
    if (!key || typeof key !== 'object')
        throw new TypeError('signAgile: key is required');
    if (!isKnownAlgorithm(key.alg)) {
        throw new Error(`signAgile: refusing to sign: ${AGILITY_REASONS.UNKNOWN_ALGORITHM} "${String(key?.alg)}"`);
    }
    if (key.alg === 'Ed25519') {
        const priv = key.private_key;
        if (!priv || typeof priv !== 'object' || priv.type !== 'private') {
            throw new TypeError('signAgile: Ed25519 private_key must be a node crypto private KeyObject');
        }
        // Curve-pin the signing key: a non-Ed25519 private key (e.g. Ed448) would
        // otherwise mint a 114-byte signature LABELED 'Ed25519', which the verify
        // path then refuses (malformed_signature / malformed_key) -- but the honest
        // fix is to refuse at issuance so a mislabeled artifact is never produced.
        if (priv.asymmetricKeyType !== 'ed25519') {
            throw new Error(`signAgile: refusing to sign: ${AGILITY_REASONS.ALGORITHM_KEY_MISMATCH} (private_key is not Ed25519)`);
        }
        const sig = crypto.sign(null, Buffer.from(messageBytes), priv);
        const out = { alg: 'Ed25519', sig: Buffer.from(sig).toString('base64url') };
        if (typeof key.key_id === 'string')
            out.key_id = key.key_id;
        return out;
    }
    // ML-DSA-65
    const sk = toRawKeyBytes(key.private_key);
    if (!sk || sk.length !== ML_DSA_65_SECRET_KEY_BYTES) {
        throw new TypeError(`signAgile: ML-DSA-65 private_key must be ${ML_DSA_65_SECRET_KEY_BYTES} raw bytes`);
    }
    const backend = await resolveAgilityBackend(options);
    if (!backend || typeof backend.sign !== 'function') {
        throw new Error(`signAgile: refusing to sign: ${AGILITY_REASONS.PQ_BACKEND_UNAVAILABLE}`);
    }
    const opts = options.deterministic === true ? { extraEntropy: false } : undefined;
    const sig = backend.sign(new Uint8Array(messageBytes), new Uint8Array(sk), opts);
    if (!(sig instanceof Uint8Array) || sig.length === 0) {
        throw new Error('signAgile: ML-DSA backend returned an invalid signature');
    }
    const out = { alg: 'ML-DSA-65', sig: Buffer.from(sig).toString('base64url') };
    if (typeof key.key_id === 'string')
        out.key_id = key.key_id;
    return out;
}
/**
 * Sign the SAME message bytes under several algorithms (hybrid issuance).
 * Duplicate algorithms are refused; each signature covers identical content,
 * which is the property the conformance vectors exercise.
 */
export async function signAgileSet(messageBytes, keys, options = {}) {
    if (!Array.isArray(keys) || keys.length === 0) {
        throw new TypeError('signAgileSet: keys must be a non-empty array');
    }
    const seen = new Set();
    const out = [];
    for (const key of keys) {
        if (seen.has(String(key?.alg))) {
            throw new Error(`signAgileSet: refusing to sign: ${AGILITY_REASONS.DUPLICATE_ALGORITHM} "${String(key?.alg)}"`);
        }
        seen.add(String(key?.alg));
        out.push(await signAgile(messageBytes, key, options));
    }
    return out;
}
function agileVerifyPreflight(messageBytes, signature, key) {
    const checks = {
        algorithm_known: false,
        key_wellformed: null,
        signature_wellformed: null,
        signature_valid: null,
    };
    const base = { alg: null, key_id: null };
    const refuse = (reason) => ({ ok: false, result: { verified: false, reason, ...base, checks } });
    if (!(messageBytes instanceof Uint8Array))
        return refuse(AGILITY_REASONS.MALFORMED_INPUT);
    if (!signature || typeof signature !== 'object' || Array.isArray(signature)) {
        return refuse(AGILITY_REASONS.MALFORMED_INPUT);
    }
    const sig = signature;
    if (typeof sig.alg === 'string')
        base.alg = sig.alg;
    if (typeof sig.key_id === 'string')
        base.key_id = sig.key_id;
    // 1. Algorithm: closed registry, explicit field. Unknown refuses.
    if (!isKnownAlgorithm(sig.alg))
        return refuse(AGILITY_REASONS.UNKNOWN_ALGORITHM);
    checks.algorithm_known = true;
    // 2. Key must be tagged with the SAME algorithm the signature declares;
    //    verifying a signature under a key pinned for a different algorithm is
    //    exactly the confusion this field exists to prevent.
    if (!key || typeof key !== 'object' || key.alg !== sig.alg) {
        checks.key_wellformed = false;
        return refuse(AGILITY_REASONS.ALGORITHM_KEY_MISMATCH);
    }
    // 3. Signature bytes: strict base64url, exact expected length.
    const sigBytes = b64urlToBytes(sig.sig);
    const expectedSigLen = sig.alg === 'Ed25519' ? 64 : ML_DSA_65_SIGNATURE_BYTES;
    if (!sigBytes || sigBytes.length !== expectedSigLen) {
        checks.signature_wellformed = false;
        return refuse(AGILITY_REASONS.MALFORMED_SIGNATURE);
    }
    checks.signature_wellformed = true;
    return {
        ok: true,
        alg: sig.alg,
        sigBytes,
        publicKey: key.public_key,
        checks,
        base,
    };
}
/** The Ed25519 crypto step (synchronous in both entry points). */
function finishEd25519(messageBytes, pre) {
    const { checks, base, sigBytes } = pre;
    const keyObject = toEd25519PublicKeyObject(pre.publicKey);
    if (!keyObject) {
        checks.key_wellformed = false;
        return { verified: false, reason: AGILITY_REASONS.MALFORMED_KEY, ...base, checks };
    }
    checks.key_wellformed = true;
    let ok = false;
    try {
        ok = crypto.verify(null, Buffer.from(messageBytes), keyObject, Buffer.from(sigBytes));
    }
    catch {
        ok = false;
    }
    checks.signature_valid = ok === true;
    if (!checks.signature_valid) {
        return { verified: false, reason: AGILITY_REASONS.SIGNATURE_INVALID, ...base, checks };
    }
    return { verified: true, reason: null, ...base, checks };
}
/** ML-DSA-65 key normalization, shared by both entry points. */
function mldsaPublicKeyOrRefuse(pre) {
    const pk = toRawKeyBytes(pre.publicKey);
    if (!pk || pk.length !== ML_DSA_65_PUBLIC_KEY_BYTES) {
        pre.checks.key_wellformed = false;
        return { ok: false, result: { verified: false, reason: AGILITY_REASONS.MALFORMED_KEY, ...pre.base, checks: pre.checks } };
    }
    pre.checks.key_wellformed = true;
    return { ok: true, pk };
}
/** The ML-DSA-65 crypto step, given an already-resolved backend (or null). */
function finishMldsa(messageBytes, pre, pk, backend) {
    const { checks, base, sigBytes } = pre;
    if (!backend || typeof backend.verify !== 'function') {
        // No backend is a REFUSAL, never a skipped check and never a pass.
        return { verified: false, reason: AGILITY_REASONS.PQ_BACKEND_UNAVAILABLE, ...base, checks };
    }
    let ok = false;
    try {
        ok = backend.verify(new Uint8Array(sigBytes), new Uint8Array(messageBytes), new Uint8Array(pk)) === true;
    }
    catch {
        ok = false;
    }
    checks.signature_valid = ok;
    if (!ok)
        return { verified: false, reason: AGILITY_REASONS.SIGNATURE_INVALID, ...base, checks };
    return { verified: true, reason: null, ...base, checks };
}
/**
 * Verify one agile signature over canonical artifact bytes. FAIL-CLOSED:
 * every malformed or unknown input is a structured refusal with a reason;
 * an unknown algorithm NEVER verifies (INDETERMINATE never authorizes).
 */
export async function verifyAgileSignature(messageBytes, signature, key, options = {}) {
    const pre = agileVerifyPreflight(messageBytes, signature, key);
    if (!pre.ok)
        return pre.result;
    if (pre.alg === 'Ed25519')
        return finishEd25519(messageBytes, pre);
    const pk = mldsaPublicKeyOrRefuse(pre);
    if (!pk.ok)
        return pk.result;
    // Backend resolution stays LATE and lazy: an Ed25519-only verification never
    // pays for the ML-DSA dynamic import.
    return finishMldsa(messageBytes, pre, pk.pk, await resolveAgilityBackend(options));
}
/**
 * The SYNCHRONOUS twin of verifyAgileSignature: identical rules, identical
 * refusal reasons, no await. It exists because EP's frozen Class A verifier
 * (verifyWebAuthnSignoff) is synchronous and every one of its dozens of call
 * sites is synchronous; making that verifier algorithm-agile must not mean
 * reimplementing these checks a second time next door.
 *
 * The ONE difference from the async entry point, stated plainly: ML-DSA
 * backend resolution is synchronous, so an injected `mldsaBackendLoader` is
 * not consulted and the pure-JS @noble default is not dynamically imported.
 * The backend is an injected `mldsaBackend`, or the node:crypto-native FIPS
 * 204 provider when this runtime has one, or nothing -- and nothing is
 * 'pq_backend_unavailable', a refusal.
 */
export function verifyAgileSignatureSync(messageBytes, signature, key, options = {}) {
    const pre = agileVerifyPreflight(messageBytes, signature, key);
    if (!pre.ok)
        return pre.result;
    if (pre.alg === 'Ed25519')
        return finishEd25519(messageBytes, pre);
    const pk = mldsaPublicKeyOrRefuse(pre);
    if (!pk.ok)
        return pk.result;
    return finishMldsa(messageBytes, pre, pk.pk, resolveSyncAgilityBackend(options));
}
// ---------------------------------------------------------------------------
// verifyAgileSignatureSet (hybrid; never throws)
// ---------------------------------------------------------------------------
/**
 * Verify a SET of agile signatures over the same message bytes.
 *
 * policy 'hybrid_all' (default): verified:true iff
 *   - every algorithm in options.requiredAlgorithms (default: the FULL
 *     registry) is present exactly once, and
 *   - EVERY presented signature verifies.
 *   A missing required algorithm refuses ('missing_required_algorithm');
 *   this is relying-party policy, not a cryptographic set commitment --
 *   see the module header and EP-HYBRID-v1 for the distinction.
 *
 * policy 'per_algorithm': verified is ALWAYS null; each algorithm's verdict
 * is reported separately in results. VERIFIED stays per-algorithm; a null
 * top-level verdict never authorizes.
 */
export async function verifyAgileSignatureSet(messageBytes, signatures, keys, options = {}) {
    const policy = options.policy === undefined ? 'hybrid_all' : options.policy;
    const refuse = (reason, results = []) => ({ policy, verified: false, reason, results });
    if (policy !== 'hybrid_all' && policy !== 'per_algorithm') {
        return { policy, verified: false, reason: AGILITY_REASONS.UNKNOWN_POLICY, results: [] };
    }
    if (!(messageBytes instanceof Uint8Array))
        return refuse(AGILITY_REASONS.MALFORMED_INPUT);
    if (!Array.isArray(signatures))
        return refuse(AGILITY_REASONS.MALFORMED_INPUT);
    if (signatures.length === 0)
        return refuse(AGILITY_REASONS.EMPTY_SIGNATURE_SET);
    if (!Array.isArray(keys))
        return refuse(AGILITY_REASONS.MALFORMED_INPUT);
    // Pinned keys by algorithm; a duplicate pin for one algorithm is malformed.
    const keyByAlg = new Map();
    for (const k of keys) {
        if (!k || typeof k !== 'object' || typeof k.alg !== 'string')
            return refuse(AGILITY_REASONS.MALFORMED_KEY);
        if (keyByAlg.has(k.alg))
            return refuse(AGILITY_REASONS.DUPLICATE_ALGORITHM);
        keyByAlg.set(k.alg, k);
    }
    // Duplicate presented algorithms refuse: one verdict per algorithm.
    const presented = new Set();
    for (const s of signatures) {
        const a = typeof s?.alg === 'string' ? s.alg : '';
        if (presented.has(a))
            return refuse(AGILITY_REASONS.DUPLICATE_ALGORITHM);
        presented.add(a);
    }
    const results = [];
    for (const s of signatures) {
        const key = typeof s?.alg === 'string' ? keyByAlg.get(s.alg) ?? null : null;
        results.push(await verifyAgileSignature(messageBytes, s, key, options));
    }
    if (policy === 'per_algorithm') {
        // Never collapse: verdicts stay per-algorithm; null never authorizes.
        return { policy, verified: null, reason: null, results };
    }
    // hybrid_all
    const required = Array.isArray(options.requiredAlgorithms) && options.requiredAlgorithms.length > 0
        ? options.requiredAlgorithms
        : AGILE_SIGNATURE_ALGORITHMS;
    for (const alg of required) {
        if (!presented.has(alg))
            return refuse(AGILITY_REASONS.MISSING_REQUIRED_ALGORITHM, results);
    }
    const firstFailure = results.find((r) => r.verified !== true);
    if (firstFailure) {
        return refuse(`${firstFailure.alg ?? 'unknown'}:${firstFailure.reason}`, results);
    }
    return { policy, verified: true, reason: null, results };
}
//# sourceMappingURL=pq-signature-agility.js.map