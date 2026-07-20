/**
 * @emilia-protocol/verify: HYBRID classical + post-quantum signature envelope
 * (EP-HYBRID-v1) for EP INFRASTRUCTURE keys (transparency-log, directory,
 * checkpoint signing keys).
 *
 * See docs/POST-QUANTUM-MIGRATION.md (section "EP-HYBRID-v1 hybrid envelope").
 *
 * ENVELOPE
 *   {
 *     alg: 'EP-HYBRID-v1',
 *     signature_algos: ['Ed25519', 'ML-DSA-65'],   // canonical order, exact set
 *     sigs: {
 *       'Ed25519':   '<base64url>',
 *       'ML-DSA-65': '<base64url>'
 *     }
 *   }
 *
 * ANTI-STRIPPING (the property this module exists for)
 *   BOTH signatures are computed over a domain-separated signing input that
 *   INCLUDES a canonical encoding of `signature_algos`:
 *
 *     signing_input = UTF8('emilia-protocol/pq-hybrid/v1') || 0x00
 *                  || UTF8(JSON.stringify(signature_algos)) || 0x00
 *                  || message
 *
 *   Therefore an attacker who strips the ML-DSA-65 signature and presents the
 *   Ed25519 signature as if it were a plain / classical-only signature fails:
 *   the Ed25519 signature does not verify over the bare message, nor over a
 *   signing input that commits to a reduced algorithm set. Removing an
 *   algorithm from the set changes what was signed, so every remaining
 *   signature fails. verifyHybrid() additionally requires the PRESENTED
 *   `signature_algos` to equal the registered EP-HYBRID-v1 set exactly
 *   (order-sensitive) and requires one signature per committed algorithm,
 *   no more, no fewer.
 *
 * FAIL-CLOSED
 *   - Missing / malformed envelope, message, or key material refuses.
 *   - Tampered or reduced `signature_algos` refuses (algo_set_mismatch).
 *   - A committed algorithm with no signature refuses (missing_signature).
 *   - Either signature invalid refuses (classical_signature_invalid /
 *     pq_signature_invalid).
 *   - If no ML-DSA backend is available, verifyHybrid REFUSES with
 *     reason 'pq_backend_unavailable'. It NEVER skips the PQ leg and never
 *     returns verified:true on the classical leg alone.
 *
 * ML-DSA BACKEND (honesty)
 *   packages/verify ships with ZERO runtime dependencies, so this module does
 *   not (and must not) import an ML-DSA implementation statically. The ML-DSA
 *   leg is cryptographically live only when a backend is present, via either:
 *     1. caller injection: pass { mldsaBackend } implementing
 *        sign(messageBytes, secretKeyBytes) -> Uint8Array and
 *        verify(signatureBytes, messageBytes, publicKeyBytes) -> boolean; or
 *     2. lazy dynamic import of '@noble/post-quantum/ml-dsa.js' (ml_dsa65),
 *        which resolves only if that package is installed by the consumer
 *        (it is a devDependency at this repo's root for tests, NOT a
 *        dependency of this package).
 *   If neither is available the module refuses; absence of the backend is a
 *   refusal, never a crash and never a pass. If a caller injects a bogus
 *   always-true backend, the PQ leg is only as strong as that backend (i.e.
 *   vacuous); the classical leg and the algo-set commitment are still
 *   enforced independently, but the caller owns the PQ leg's honesty.
 *
 *   @noble/post-quantum v0.6.1 is a pure-JS implementation of FIPS 204
 *   ML-DSA. Per its own README it is self-audited by its authors and has NOT
 *   been independently audited; it is not a FIPS-validated module. This envelope does NOT make EP
 *   post-quantum secure by itself; see docs/POST-QUANTUM-MIGRATION.md for the
 *   migration phases and the pre-CRQC historical re-anchoring requirement.
 *
 * KEY / SIGNATURE ENCODING (matches index.js conventions)
 *   - Ed25519 public key: base64url SPKI DER (or a node crypto KeyObject).
 *   - Ed25519 private key: node crypto KeyObject (from generateKeyPairSync /
 *     createPrivateKey).
 *   - ML-DSA-65 public key: raw bytes (Uint8Array, 1952 bytes) or base64url.
 *   - ML-DSA-65 secret key: raw bytes (Uint8Array, 4032 bytes).
 *   - Signatures in the envelope: base64url strings.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

export const HYBRID_ALG = 'EP-HYBRID-v1';

/**
 * The registered algorithm set for EP-HYBRID-v1, in canonical order.
 * v1 is a FIXED two-algorithm hybrid: exactly Ed25519 + ML-DSA-65.
 */
export const HYBRID_SIGNATURE_ALGOS = Object.freeze(['Ed25519', 'ML-DSA-65']);

/**
 * Domain-separation label. Trailing 0x00 separators in the signing input keep
 * label / algo-set / message unambiguous (JSON never contains a raw 0x00).
 */
export const HYBRID_DOMAIN = 'emilia-protocol/pq-hybrid/v1';

const REASONS = Object.freeze({
  INVALID_INPUT: 'invalid_input',
  INVALID_ENVELOPE: 'invalid_envelope',
  ALGO_SET_MISMATCH: 'algo_set_mismatch',
  MISSING_SIGNATURE: 'missing_signature',
  MISSING_KEY: 'missing_key',
  CLASSICAL_INVALID: 'classical_signature_invalid',
  PQ_INVALID: 'pq_signature_invalid',
  PQ_BACKEND_UNAVAILABLE: 'pq_backend_unavailable',
});
export { REASONS as HYBRID_REASONS };

// ---------------------------------------------------------------------------
// Signing input (the anti-stripping commitment)
// ---------------------------------------------------------------------------

/**
 * Build the domain-separated signing input BOTH legs sign.
 * Commits to the full signature_algos array; changing the array in any way
 * (strip, reorder, substitute) changes these bytes.
 *
 * @param {Uint8Array} messageBytes
 * @param {string[]} signatureAlgos
 * @returns {Buffer}
 */
export function hybridSigningInput(messageBytes, signatureAlgos) {
  if (!(messageBytes instanceof Uint8Array)) {
    throw new TypeError('hybridSigningInput: messageBytes must be a Uint8Array');
  }
  if (!Array.isArray(signatureAlgos) || signatureAlgos.length === 0
      || !signatureAlgos.every((a) => typeof a === 'string' && a.length > 0)) {
    throw new TypeError('hybridSigningInput: signatureAlgos must be a non-empty string array');
  }
  const zero = Buffer.from([0x00]);
  return Buffer.concat([
    Buffer.from(HYBRID_DOMAIN, 'utf8'), zero,
    Buffer.from(JSON.stringify(signatureAlgos), 'utf8'), zero,
    Buffer.from(messageBytes),
  ]);
}

// ---------------------------------------------------------------------------
// ML-DSA backend resolution (lazy, fail-closed)
// ---------------------------------------------------------------------------

/**
 * Try to load the default ML-DSA-65 backend (@noble/post-quantum). Returns a
 * backend object or null. NEVER throws; absence yields null so callers refuse.
 *
 * @returns {Promise<{sign: Function, verify: Function}|null>}
 */
export async function loadDefaultMldsaBackend() {
  try {
    const mod = await import('@noble/post-quantum/ml-dsa.js');
    const impl = mod.ml_dsa65;
    if (!impl || typeof impl.sign !== 'function' || typeof impl.verify !== 'function') return null;
    return {
      // noble API: sign(msg, secretKey) -> sig; verify(sig, msg, publicKey) -> boolean
      sign: (messageBytes, secretKeyBytes) => impl.sign(messageBytes, secretKeyBytes),
      verify: (signatureBytes, messageBytes, publicKeyBytes) => {
        try {
          return impl.verify(signatureBytes, messageBytes, publicKeyBytes) === true;
        } catch {
          return false; // malformed sig/key lengths refuse, never throw upward
        }
      },
    };
  } catch {
    return null;
  }
}

async function resolveBackend(mldsaBackend, mldsaBackendLoader) {
  if (mldsaBackend !== undefined && mldsaBackend !== null) {
    if (typeof mldsaBackend.verify !== 'function') return null; // malformed injection refuses
    return mldsaBackend;
  }
  const loader = typeof mldsaBackendLoader === 'function' ? mldsaBackendLoader : loadDefaultMldsaBackend;
  try {
    const b = await loader();
    if (!b || typeof b.verify !== 'function') return null;
    return b;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Input normalization helpers
// ---------------------------------------------------------------------------

function toMessageBytes(message) {
  if (message instanceof Uint8Array) return message;
  if (typeof message === 'string') return Buffer.from(message, 'utf8');
  return null;
}

function toEd25519PublicKeyObject(key) {
  try {
    if (key && typeof key === 'object' && key.type === 'public') return key; // KeyObject
    if (typeof key === 'string' && key.length > 0) {
      const der = Buffer.from(key, 'base64url');
      return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    }
  } catch {
    return null;
  }
  return null;
}

function toRawBytes(key) {
  if (key instanceof Uint8Array) return key;
  if (typeof key === 'string' && key.length > 0) {
    try { return Buffer.from(key, 'base64url'); } catch { return null; }
  }
  return null;
}

function algosEqual(a, b) {
  return Array.isArray(a) && Array.isArray(b) && a.length === b.length
    && a.every((v, i) => v === b[i]);
}

// ---------------------------------------------------------------------------
// signHybrid
// ---------------------------------------------------------------------------

/**
 * Produce an EP-HYBRID-v1 envelope: Ed25519 AND ML-DSA-65 signatures, both
 * over the domain-separated signing input that commits to the full algo set.
 *
 * THROWS (fail-closed) if the ML-DSA backend is unavailable: this function
 * never silently emits a classical-only envelope.
 *
 * @param {Uint8Array|string} message
 * @param {object} keys
 * @param {import('crypto').KeyObject} keys.ed25519PrivateKey
 * @param {Uint8Array} keys.mldsaSecretKey - raw ML-DSA-65 secret key bytes
 * @param {object} [options]
 * @param {{sign:Function,verify:Function}} [options.mldsaBackend] - injected backend
 * @param {Function} [options.mldsaBackendLoader] - async () => backend|null
 * @returns {Promise<{alg:string, signature_algos:string[], sigs:Record<string,string>}>}
 */
export async function signHybrid(message, keys, options = {}) {
  const messageBytes = toMessageBytes(message);
  if (!messageBytes) throw new TypeError('signHybrid: message must be a Uint8Array or string');
  if (!keys || !keys.ed25519PrivateKey) throw new TypeError('signHybrid: keys.ed25519PrivateKey is required');
  const mldsaSecretKey = toRawBytes(keys.mldsaSecretKey);
  if (!mldsaSecretKey) throw new TypeError('signHybrid: keys.mldsaSecretKey is required');

  const backend = await resolveBackend(options.mldsaBackend, options.mldsaBackendLoader);
  if (!backend || typeof backend.sign !== 'function') {
    // Fail closed: never emit an envelope missing the PQ leg.
    throw new Error(`signHybrid: refusing to sign: ${REASONS.PQ_BACKEND_UNAVAILABLE}`);
  }

  const signatureAlgos = [...HYBRID_SIGNATURE_ALGOS];
  const signingInput = hybridSigningInput(messageBytes, signatureAlgos);

  const edSig = crypto.sign(null, signingInput, keys.ed25519PrivateKey);
  const pqSig = backend.sign(new Uint8Array(signingInput), mldsaSecretKey);
  if (!(pqSig instanceof Uint8Array) || pqSig.length === 0) {
    throw new Error('signHybrid: ML-DSA backend returned an invalid signature');
  }

  return {
    alg: HYBRID_ALG,
    signature_algos: signatureAlgos,
    sigs: {
      'Ed25519': Buffer.from(edSig).toString('base64url'),
      'ML-DSA-65': Buffer.from(pqSig).toString('base64url'),
    },
  };
}

// ---------------------------------------------------------------------------
// verifyHybrid
// ---------------------------------------------------------------------------

/**
 * Verify an EP-HYBRID-v1 envelope. verified:true requires ALL of:
 *   - well-formed envelope with alg 'EP-HYBRID-v1'
 *   - presented signature_algos EXACTLY equals the registered set
 *     ['Ed25519','ML-DSA-65'] (order-sensitive; this is also what both
 *     signatures commit to, so tampering fails twice)
 *   - exactly one signature per committed algorithm (no extras, none missing)
 *   - Ed25519 signature valid over the committed signing input
 *   - ML-DSA-65 signature valid over the committed signing input, checked by
 *     a REAL backend; if no backend is available the result is
 *     { verified:false, reason:'pq_backend_unavailable' } - the PQ leg is
 *     never skipped.
 *
 * @param {Uint8Array|string} message
 * @param {object} envelope - { alg, signature_algos, sigs }
 * @param {object} keys
 * @param {string|import('crypto').KeyObject} keys.ed25519PublicKey - base64url SPKI DER or KeyObject
 * @param {Uint8Array|string} keys.mldsaPublicKey - raw ML-DSA-65 public key bytes or base64url
 * @param {object} [options]
 * @param {{verify:Function}} [options.mldsaBackend] - injected backend
 * @param {Function} [options.mldsaBackendLoader] - async () => backend|null
 * @returns {Promise<{verified:boolean, reason:string|null, checks:object}>}
 */
export async function verifyHybrid(message, envelope, keys, options = {}) {
  /** @type {{envelope: boolean, algo_set: boolean, classical_signature: boolean|null, pq_signature: boolean|null}} */
  const checks = { envelope: false, algo_set: false, classical_signature: null, pq_signature: null };
  const refuse = (reason) => ({ verified: false, reason, checks });

  const messageBytes = toMessageBytes(message);
  if (!messageBytes) return refuse(REASONS.INVALID_INPUT);

  // 1. Envelope shape (fail closed on anything unexpected)
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) return refuse(REASONS.INVALID_ENVELOPE);
  if (envelope.alg !== HYBRID_ALG) return refuse(REASONS.INVALID_ENVELOPE);
  if (!envelope.sigs || typeof envelope.sigs !== 'object' || Array.isArray(envelope.sigs)) return refuse(REASONS.INVALID_ENVELOPE);
  checks.envelope = true;

  // 2. Algo-set commitment: presented set must EXACTLY equal the registered
  //    set. (Both signatures also commit to it cryptographically below.)
  if (!algosEqual(envelope.signature_algos, HYBRID_SIGNATURE_ALGOS)) {
    return refuse(REASONS.ALGO_SET_MISMATCH);
  }
  checks.algo_set = true;

  // 3. Exactly one signature per committed algorithm; extras refuse.
  const sigKeys = Object.keys(envelope.sigs);
  if (sigKeys.length !== HYBRID_SIGNATURE_ALGOS.length) {
    return refuse(sigKeys.length < HYBRID_SIGNATURE_ALGOS.length ? REASONS.MISSING_SIGNATURE : REASONS.INVALID_ENVELOPE);
  }
  for (const algo of HYBRID_SIGNATURE_ALGOS) {
    if (typeof envelope.sigs[algo] !== 'string' || envelope.sigs[algo].length === 0) {
      return refuse(REASONS.MISSING_SIGNATURE);
    }
  }

  // 4. Key material (fail closed on missing/invalid input)
  if (!keys || !keys.ed25519PublicKey || !keys.mldsaPublicKey) return refuse(REASONS.MISSING_KEY);
  const edKey = toEd25519PublicKeyObject(keys.ed25519PublicKey);
  if (!edKey) return refuse(REASONS.MISSING_KEY);
  const pqKey = toRawBytes(keys.mldsaPublicKey);
  if (!pqKey || pqKey.length === 0) return refuse(REASONS.MISSING_KEY);

  const signingInput = hybridSigningInput(messageBytes, envelope.signature_algos);

  // 5. Classical leg (Ed25519) over the committed signing input
  let edOk = false;
  try {
    edOk = crypto.verify(null, signingInput, edKey, Buffer.from(envelope.sigs['Ed25519'], 'base64url'));
  } catch {
    edOk = false;
  }
  checks.classical_signature = edOk === true;
  if (!checks.classical_signature) return refuse(REASONS.CLASSICAL_INVALID);

  // 6. PQ leg (ML-DSA-65). No backend => REFUSE. Never skip, never pass.
  const backend = await resolveBackend(options.mldsaBackend, options.mldsaBackendLoader);
  if (!backend) return refuse(REASONS.PQ_BACKEND_UNAVAILABLE);
  let pqOk = false;
  try {
    pqOk = backend.verify(
      new Uint8Array(Buffer.from(envelope.sigs['ML-DSA-65'], 'base64url')),
      new Uint8Array(signingInput),
      new Uint8Array(pqKey),
    ) === true;
  } catch {
    pqOk = false;
  }
  checks.pq_signature = pqOk;
  if (!pqOk) return refuse(REASONS.PQ_INVALID);

  return { verified: true, reason: null, checks };
}
