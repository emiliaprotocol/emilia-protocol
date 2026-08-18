// SPDX-License-Identifier: Apache-2.0
/**
 * EP-TIME-ATTESTATION-v1 — independent, offline-verifiable proof of WHEN.
 *
 * An EP signoff's `issued_at` is asserted by whoever stamped it. For the
 * absolute time of a signoff or receipt to be trustworthy to a third party, an
 * INDEPENDENT timestamping authority (TSA) — a party EP identifies but does not
 * trust — signs over (the hash of) the artifact plus the time. This is the
 * trusted-time analogue of everything else in EP: ASYMMETRIC, key-PINNED,
 * fail-closed. It composes with the strong ordered chain (which already proves
 * relative ORDER cryptographically): the chain proves sequence, a time
 * attestation bounds the absolute instant.
 *
 *   { "@version": "EP-TIME-ATTESTATION-v1",
 *     ts_authority_id: "ep:tsa:...",
 *     hashed: "sha256:<hex>",          // the artifact this attestation timestamps
 *     time:   "<RFC 3339>",            // the attested instant
 *     proof:  { algorithm:"Ed25519", ts_key_id, signature_b64u, public_key } }
 *
 * verifyTimeAttestation(att, opts) is FAIL-CLOSED: it accepts only when the
 * version matches, the TSA is PINNED (opts.tsaKeys[ts_authority_id], and the
 * proof key equals the pinned key), the Ed25519 proof verifies over the
 * verifier-recomputed canonical bytes, the time is a well-formed instant, and
 * (when supplied) the attested `hashed` equals opts.expectedHash and the time
 * falls within [opts.notBefore, opts.notAfter].
 *
 * HONEST BOUNDARY: this proves an independent authority attested this exact
 * content existed at time T. It does not prove the TSA's clock was correct, nor
 * that no EARLIER attestation exists. It bounds, it does not divine.
 */
import crypto, { type KeyObject } from 'node:crypto';
import { canonicalize } from './index.js';
import {
  verifyAgileSignatureSet,
  signAgileSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  type AgilityOptions,
} from './pq-signature-agility.js';

export const TIME_ATTESTATION_VERSION = 'EP-TIME-ATTESTATION-v1';

export interface TimeAttestation {
  '@version'?: unknown;
  ts_authority_id?: unknown;
  hashed?: unknown;
  time?: unknown;
  proof?: {
    public_key?: unknown;
    signature_b64u?: unknown;
    [key: string]: unknown;
  } | null;
  [key: string]: unknown;
}

export interface TimeAttestationOptions {
  tsaKeys?: Record<string, { public_key: string }>;
  expectedHash?: string;
  notBefore?: string | number | Date;
  notAfter?: string | number | Date;
  [key: string]: unknown;
}

export interface TimeAttestationResult {
  valid: boolean;
  checks: Record<string, boolean>;
  errors: string[];
}

// Validate to a well-formed 64-char SHA-256; malformed -> '' so comparisons
// fail closed (never match a real digest) and stay cross-language consistent. (HI-2)
const hexOf = (h: unknown): string => {
  const s = String(h ?? '').replace(/^sha256:/, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
};

function instantMs(s: unknown): number | null {
  if (typeof s !== 'string' || s.length === 0) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

/**
 * The fixed bytes a TSA signature over this attestation is bound to,
 * recomputed independently of how the attestation was presented.
 *
 * Exported so an algorithm-agile verifier (see evidence-record.ts) checks a
 * ML-DSA-65 proof over the SAME bytes the Ed25519 path checks, rather than
 * carrying its own second definition of what a time attestation commits to.
 * One definition of the signed bytes, one place to change it.
 */
export function timeAttestationSignedBytes(att: TimeAttestation): Buffer {
  return timeSignedPayload(att);
}

// The fixed bytes the TSA signature is bound to, recomputed independently.
function timeSignedPayload(att: TimeAttestation): Buffer {
  return Buffer.from(
    canonicalize({
      '@version': TIME_ATTESTATION_VERSION,
      hashed: att.hashed ?? null,
      time: att.time ?? null,
      ts_authority_id: att.ts_authority_id ?? null,
    }),
    'utf8',
  );
}

function verifyEd25519(bytes: Buffer, publicKeyB64u: unknown, signatureB64u: unknown): boolean {
  try {
    if (!bytes || !publicKeyB64u || !signatureB64u) return false;
    const key = crypto.createPublicKey({ key: Buffer.from(String(publicKeyB64u), 'base64url'), format: 'der', type: 'spki' });
    return crypto.verify(null, bytes, key, Buffer.from(String(signatureB64u), 'base64url'));
  } catch {
    return false;
  }
}

/**
 * @param {object} att  the EP-TIME-ATTESTATION-v1 statement.
 * @param {object} [opts]
 * @param {Object<string,{public_key:string}>} [opts.tsaKeys]  pinned TSA keys by ts_authority_id.
 * @param {string} [opts.expectedHash]  the artifact hash this attestation MUST cover.
 * @param {string|number|Date} [opts.notBefore]  attested time must be >= this.
 * @param {string|number|Date} [opts.notAfter]   attested time must be <= this.
 * @returns {{valid:boolean, checks:object, errors:string[]}}
 */
export function verifyTimeAttestation(att: TimeAttestation | null | undefined, opts: TimeAttestationOptions = {}): TimeAttestationResult {
  opts = opts && typeof opts === 'object' ? opts : {};
  const tsaKeys = opts.tsaKeys || {};
  const checks: Record<string, boolean> = {
    version: true,
    tsa_key_pinned: true,
    time_present: true,
    signature_valid: true,
    hash_bound: true,   // vacuous unless opts.expectedHash supplied
    within_bounds: true, // vacuous unless opts.notBefore/notAfter supplied
  };
  const errors: string[] = [];
  const fail = (k: string, m: string) => { checks[k] = false; errors.push(m); };

  if (!att || typeof att !== 'object') {
    fail('signature_valid', 'no time attestation presented (fail-closed)');
    return { valid: false, checks, errors };
  }
  if (att['@version'] !== TIME_ATTESTATION_VERSION) fail('version', `unsupported version: ${att['@version']}`);

  const proof = att.proof || null;
  const authorityId = typeof att.ts_authority_id === 'string' ? att.ts_authority_id : '';
  const pinned = tsaKeys[authorityId]?.public_key;
  const presentedKey = proof?.public_key ?? null;
  if (!pinned) fail('tsa_key_pinned', `no pinned key for ts_authority "${authorityId}" (identified but not trusted)`);
  else if (presentedKey && pinned !== presentedKey) fail('tsa_key_pinned', `presented TSA key != pinned key for "${authorityId}"`);

  const ms = instantMs(att.time);
  if (ms === null) fail('time_present', 'time is absent or not a well-formed RFC 3339 instant');

  const sigOk = pinned && verifyEd25519(timeSignedPayload(att), pinned, proof?.signature_b64u);
  if (!sigOk) fail('signature_valid', 'TSA signature does not verify under the pinned key over the recomputed bytes');

  if (typeof opts.expectedHash === 'string') {
    if (hexOf(att.hashed) !== hexOf(opts.expectedHash)) {
      fail('hash_bound', `attestation hashed ${hexOf(att.hashed)} != expected ${hexOf(opts.expectedHash)}`);
    }
  }

  if (ms !== null) {
    const nb = opts.notBefore === undefined ? null : new Date(opts.notBefore).getTime();
    const na = opts.notAfter === undefined ? null : new Date(opts.notAfter).getTime();
    if (nb !== null && !Number.isNaN(nb) && ms < nb) fail('within_bounds', 'attested time is before notBefore');
    if (na !== null && !Number.isNaN(na) && ms > na) fail('within_bounds', 'attested time is after notAfter');
  }

  const valid = Object.values(checks).every(Boolean);
  return { valid, checks, errors };
}

// ===========================================================================
// EP-TIME-ATTESTATION-v2 -- the hybrid (Ed25519 + ML-DSA-65) time attestation
// ===========================================================================
/**
 * REFERENCE HYBRID MIGRATION, applied to the TSA attestation. This follows the
 * same five moves as EP-REVOCATION-v2 (packages/verify/src/revocation.ts):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    `proof`, so the artifact takes a new `@version`
 *    (EP-TIME-ATTESTATION-v1 -> EP-TIME-ATTESTATION-v2) instead of growing an
 *    optional field on v1. verifyTimeAttestation() above is untouched: it
 *    still accepts exactly what it accepted before, and it refuses a v2
 *    attestation on the version marker without throwing -- every subsequent
 *    line in that function reaches v2's differently-shaped `proof` only
 *    through optional chaining (`proof?.public_key`, `proof?.signature_b64u`),
 *    which is safe against a `proof.signatures` array instead of a flat
 *    `signature_b64u` string.
 *
 * 2. SET SHAPE. `proof` carries `required_algorithms` plus a `signatures`
 *    array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({ alg, sig, key_id? }), one entry per algorithm, in the registered
 *    order. Ed25519 keeps its base64url SPKI DER public key; ML-DSA-65
 *    carries raw base64url public key bytes.
 *
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is inside the signed
 *    bytes (timeAttestationV2SignedBytes below), always rebuilt by the
 *    verifier from the REGISTERED set -- never from what the presented
 *    attestation claims. Narrowing `proof.required_algorithms` is refused
 *    structurally (algorithm_set), and independently, any signature actually
 *    minted over a narrowed-set commitment does not verify over the bytes the
 *    verifier recomputes from the full registered set.
 *
 * 4. V1 COMPATIBILITY. timeAttestationSignedBytes/timeSignedPayload above are
 *    UNTOUCHED: evidence-record.ts's algorithm-AGILE per-attestation path
 *    depends on those exact bytes, and this migration does not change them.
 *    v2 needs different bytes (v2 version string + committed algorithm set),
 *    so it gets its own, separate signed-bytes function, the same way
 *    revocation.ts keeps revocationSignedPayload (v1) and
 *    revocationV2SignedPayload (v2) as two independent functions. v2
 *    verification is ASYNC (ML-DSA verification is async), so it is a
 *    separate entry point rather than a signature change to
 *    verifyTimeAttestation; verifyTimeAttestationStatement() routes on
 *    `@version` for callers holding a mixed bag.
 *
 * 5. NAMED REFUSALS. Every failure path sets a named check to false and
 *    pushes a human-readable error; nothing throws on caller input. An
 *    absent ML-DSA backend is a refusal ('pq_backend_unavailable' surfaced
 *    through the agility result), never a skipped check and never a pass on
 *    the classical leg.
 *
 * HONEST BOUNDARIES. Everything the v1 header says about this profile still
 * holds: a verified v2 attestation proves an independent, pinned authority
 * attested this exact content existed at time T; it does not prove the TSA's
 * clock was correct, nor that no earlier attestation exists. The ML-DSA
 * backend is @noble/post-quantum's pure-JS FIPS 204 implementation, which is
 * not independently audited and is not a FIPS validated module; verifying
 * under this profile is not a certification claim. v2 does NOT retroactively
 * protect attestations already issued under v1.
 */

export const TIME_ATTESTATION_V2_VERSION = 'EP-TIME-ATTESTATION-v2';

/** The registered required algorithm set, in canonical order. */
export const TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

export interface TimeAttestationV2Signature { alg?: unknown; sig?: unknown; key_id?: unknown; }
export interface TimeAttestationV2Proof {
  required_algorithms?: unknown;
  ts_key_id?: unknown;
  /** Ed25519: base64url SPKI DER. */
  public_key?: unknown;
  pq_key_id?: unknown;
  /** ML-DSA-65: base64url of the raw 1952-byte public key. */
  pq_public_key?: unknown;
  signatures?: unknown;
  [key: string]: unknown;
}
export interface TimeAttestationV2 {
  '@version'?: unknown;
  ts_authority_id?: unknown;
  hashed?: unknown;
  time?: unknown;
  proof?: TimeAttestationV2Proof | null;
  [key: string]: unknown;
}

/** A v2 TSA pin: BOTH public halves, pinned out of band. */
export interface TsaV2KeyPin {
  /** Ed25519 base64url SPKI DER. */
  public_key?: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key?: string;
  key_id?: string;
  pq_key_id?: string;
}

export interface TimeAttestationV2Options extends AgilityOptions {
  tsaKeys?: Record<string, TsaV2KeyPin>;
  expectedHash?: string;
  notBefore?: string | number | Date;
  notAfter?: string | number | Date;
  [key: string]: unknown;
}

export interface TimeAttestationV2Result {
  valid: boolean;
  checks: Record<string, boolean>;
  errors: string[];
}

function algorithmSetMatchesRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS[i]);
}

function agilityPassthrough(opts: TimeAttestationV2Options): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend as AgilityOptions['mldsaBackend'];
  if (opts.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader as AgilityOptions['mldsaBackendLoader'];
  return out;
}

/**
 * The bytes BOTH legs sign. Same fixed field set as v1
 * (hashed/time/ts_authority_id), plus the `required_algorithms` set and the
 * v2 `@version` marker, so the algorithm set is cryptographically committed.
 * Recomputed independently by the verifier from the PRESENTED artifact
 * fields and the REGISTERED algorithm set. canonicalize() sorts keys, so
 * field order here is irrelevant.
 *
 * This is a NEW, separate function from timeAttestationSignedBytes /
 * timeSignedPayload above -- it does not replace or delegate to them, and
 * evidence-record.ts's existing v1 agile-per-attestation path is unaffected.
 */
export function timeAttestationV2SignedBytes(
  att: TimeAttestationV2,
  requiredAlgorithms: readonly string[] = TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
    throw new Error('timeAttestationV2SignedBytes: algorithm set is not the registered EP-TIME-ATTESTATION-v2 set');
  }
  return Buffer.from(
    canonicalize({
      '@version': TIME_ATTESTATION_V2_VERSION,
      hashed: att.hashed ?? null,
      required_algorithms: [...requiredAlgorithms],
      time: att.time ?? null,
      ts_authority_id: att.ts_authority_id ?? null,
    }),
    'utf8',
  );
}

/**
 * verifyTimeAttestationV2 -- FAIL-CLOSED hybrid TSA attestation check. Never
 * throws on caller input. Every gating check must be true; a v2 attestation
 * never verifies on one leg alone.
 */
export async function verifyTimeAttestationV2(
  att: TimeAttestationV2 | null | undefined,
  opts: TimeAttestationV2Options = {},
): Promise<TimeAttestationV2Result> {
  opts = opts && typeof opts === 'object' ? opts : {};
  const tsaKeys = opts.tsaKeys || {};
  const checks: Record<string, boolean> = {
    version: true,
    structure: true,
    algorithm_set: true,
    tsa_key_pinned: true,
    time_present: true,
    signature_set_valid: true,
    hash_bound: true,    // vacuous unless opts.expectedHash supplied
    within_bounds: true, // vacuous unless opts.notBefore/notAfter supplied
  };
  const errors: string[] = [];
  const fail = (k: string, m: string) => { checks[k] = false; errors.push(m); };
  const done = () => ({ valid: Object.values(checks).every(Boolean), checks, errors });

  if (!att || typeof att !== 'object' || Array.isArray(att)) {
    fail('signature_set_valid', 'no time attestation presented (fail-closed)');
    return done();
  }

  // 1. Version marker. A v1 attestation handed to the v2 verifier refuses
  //    here, the mirror image of the v1 verifier refusing a v2 attestation.
  if (att['@version'] !== TIME_ATTESTATION_V2_VERSION) {
    fail('version', `unsupported version: ${att['@version']}`);
  }

  const proof = (att.proof || null) as TimeAttestationV2Proof | null;
  const requiredAlgorithms = proof?.required_algorithms;
  const signatures = Array.isArray(proof?.signatures) ? proof!.signatures as TimeAttestationV2Signature[] : null;

  // 2. Structural well-formedness: proof must carry required_algorithms and
  //    signatures arrays, each signature entry shaped { alg, sig, key_id? }.
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)
    || !Array.isArray(requiredAlgorithms) || !signatures) {
    fail('structure', 'proof must carry required_algorithms and signatures arrays');
  } else {
    for (const s of signatures) {
      if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        fail('structure', 'each proof.signatures entry must be { alg, sig, key_id? }');
        break;
      }
    }
  }

  // 3. Committed algorithm set: exact and order-sensitive. A narrowed or
  //    widened set is the stripping attack's cover story, refused
  //    structurally here and (independently) by the signature check, which
  //    rebuilds the bytes from the REGISTERED set regardless of what the
  //    attestation claims.
  if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
    fail('algorithm_set',
      `proof.required_algorithms must be exactly ${JSON.stringify([...TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
  }

  // 4. TSA keys: BOTH halves pinned, and the presented halves must equal the
  //    pinned ones. Identified-but-not-trusted, per leg. A self-asserted,
  //    unpinned key confers NOTHING -- never fall back to the attestation's
  //    own presented key material.
  const authorityId = typeof att.ts_authority_id === 'string' ? att.ts_authority_id : '';
  const pin: TsaV2KeyPin = authorityId && tsaKeys && typeof tsaKeys === 'object'
    ? tsaKeys[authorityId] || {}
    : {};
  const presentedEdKey = proof?.public_key ?? null;
  const presentedPqKey = proof?.pq_public_key ?? null;
  if (!authorityId) {
    fail('tsa_key_pinned', 'ts_authority_id must be a non-empty string');
  } else if (!pin.public_key || !pin.pq_public_key) {
    fail('tsa_key_pinned',
      `no pinned Ed25519 + ML-DSA-65 key pair for ts_authority "${authorityId}" (identified but not trusted)`);
  } else {
    if (typeof presentedEdKey !== 'string' || presentedEdKey.length === 0 || pin.public_key !== presentedEdKey) {
      fail('tsa_key_pinned', `presented Ed25519 TSA key != pinned key for "${authorityId}" (key substitution)`);
    }
    if (typeof presentedPqKey !== 'string' || presentedPqKey.length === 0 || pin.pq_public_key !== presentedPqKey) {
      fail('tsa_key_pinned', `presented ML-DSA-65 TSA key != pinned key for "${authorityId}" (key substitution)`);
    }
  }

  // 5. Time presence: identical semantics to v1 (reuses instantMs above, no
  //    second definition of what a well-formed instant is).
  const ms = instantMs(att.time);
  if (ms === null) fail('time_present', 'time is absent or not a well-formed RFC 3339 instant');

  // 6. Signature set: both legs, over bytes rebuilt from the PRESENTED
  //    artifact fields and the REGISTERED algorithm set, under the PINNED
  //    keys. Policy 'hybrid_all' with requiredAlgorithms pinned to the full
  //    set, so a missing leg is 'missing_required_algorithm' and never a pass.
  let recomputedBytes: Buffer | null = null;
  try {
    recomputedBytes = timeAttestationV2SignedBytes(att, TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS);
  } catch {
    recomputedBytes = null;
  }
  if (!recomputedBytes) {
    fail('signature_set_valid', 'time attestation fields are not canonicalizable');
  } else {
    // Verify under the PINNED keys only. Never fall back to the proof's own
    // self-asserted key material: that is the whole point of the pin.
    const verificationKeys = [
      { alg: 'Ed25519', public_key: pin.public_key ?? '' },
      { alg: 'ML-DSA-65', public_key: pin.pq_public_key ?? '' },
    ];
    let setResult;
    try {
      setResult = await verifyAgileSignatureSet(
        new Uint8Array(recomputedBytes),
        signatures ?? [],
        verificationKeys,
        {
          ...agilityPassthrough(opts),
          policy: 'hybrid_all',
          requiredAlgorithms: [...TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS],
        },
      );
    } catch {
      // verifyAgileSignatureSet documents that it never throws; an injected
      // backend that does is still a refusal here, never a pass.
      setResult = null;
    }
    if (setResult?.verified !== true) {
      const reason = String(setResult?.reason ?? 'signature_set_unverified');
      fail('signature_set_valid',
        `TSA signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
    }
  }

  if (typeof opts.expectedHash === 'string') {
    if (hexOf(att.hashed) !== hexOf(opts.expectedHash)) {
      fail('hash_bound', `attestation hashed ${hexOf(att.hashed)} != expected ${hexOf(opts.expectedHash)}`);
    }
  }

  if (ms !== null) {
    const nb = opts.notBefore === undefined ? null : new Date(opts.notBefore).getTime();
    const na = opts.notAfter === undefined ? null : new Date(opts.notAfter).getTime();
    if (nb !== null && !Number.isNaN(nb) && ms < nb) fail('within_bounds', 'attested time is before notBefore');
    if (na !== null && !Number.isNaN(na) && ms > na) fail('within_bounds', 'attested time is after notAfter');
  }

  return done();
}

/**
 * Route an attestation of EITHER version to its verifier. v1 attestations
 * keep the exact v1 verdict; v2 attestations get the hybrid check. An
 * attestation whose `@version` is neither refuses on the version marker,
 * through the v1 verifier, which is the fail-closed answer.
 */
export async function verifyTimeAttestationStatement(
  att: TimeAttestation | TimeAttestationV2 | null | undefined,
  opts: TimeAttestationV2Options = {},
): Promise<TimeAttestationResult | TimeAttestationV2Result> {
  if (att && typeof att === 'object' && !Array.isArray(att)
    && (att as TimeAttestationV2)['@version'] === TIME_ATTESTATION_V2_VERSION) {
    return verifyTimeAttestationV2(att as TimeAttestationV2, opts);
  }
  return verifyTimeAttestation(att as TimeAttestation, opts as TimeAttestationOptions);
}

// ---------------------------------------------------------------------------
// buildTimeAttestationV2 -- issuer-side reference tooling
// ---------------------------------------------------------------------------
// This repo does not hold a real TSA's private key; this helper exists for
// tests and reference/conformance tooling, the same role buildRevocationV2
// plays in lib/revocation/revocation.ts.

export interface TimeAttestationV2Signer {
  /** Ed25519 private key. */
  privateKey: KeyObject;
  /** Ed25519 public key, base64url SPKI DER. */
  publicKeyB64u: string;
  /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
  pqSecretKey: Uint8Array | string;
  /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
  pqPublicKeyB64u: Uint8Array | string;
}

export interface BuildTimeAttestationV2Args {
  ts_authority_id?: unknown;
  hashed?: unknown;
  time?: unknown;
  signer?: TimeAttestationV2Signer | null;
  /** ML-DSA-65 FIPS 204 deterministic variant; conformance vectors only. */
  deterministic?: boolean;
}

function toRawB64u(value: Uint8Array | string, expectedLength: number, label: string): string {
  const bytes = value instanceof Uint8Array
    ? Buffer.from(value)
    : (/^[A-Za-z0-9_-]+$/.test(String(value)) ? Buffer.from(String(value), 'base64url') : Buffer.alloc(0));
  if (bytes.length !== expectedLength) {
    throw new Error(`buildTimeAttestationV2: ${label} must be ${expectedLength} raw bytes (or base64url of them)`);
  }
  return bytes.toString('base64url');
}

/** Ed25519 TSA public-key identifier: the SHA-256 of the SPKI DER bytes. */
function tsKeyId(publicKeyB64u: unknown): string {
  try {
    if (typeof publicKeyB64u !== 'string' || publicKeyB64u.length === 0) return '';
    const der = Buffer.from(publicKeyB64u, 'base64url');
    if (der.length === 0 || der.toString('base64url') !== publicKeyB64u) return '';
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return '';
    return `ep:tsa-key:sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
  } catch {
    return '';
  }
}

/** ML-DSA-65 TSA public-key identifier: the SHA-256 of the raw public key bytes. */
function pqTsKeyId(publicKeyRawB64u: string): string {
  return `ep:tsa-key:ml-dsa-65:sha256:${crypto.createHash('sha256')
    .update(Buffer.from(publicKeyRawB64u, 'base64url')).digest('hex')}`;
}

/**
 * buildTimeAttestationV2 -- produce an EP-TIME-ATTESTATION-v2 attestation
 * over the exact (hashed, time, ts_authority_id), signed under BOTH
 * registered algorithms over one set of bytes that COMMITS to the required
 * algorithm set (see timeAttestationV2SignedBytes).
 *
 * THROWS rather than emit a half-hybrid attestation: issuer-side misuse is a
 * programming error, and an unavailable ML-DSA backend makes signAgileSet
 * throw, so an attestation missing the PQ leg is never produced.
 */
export async function buildTimeAttestationV2({
  ts_authority_id: tsAuthorityId,
  hashed,
  time = new Date().toISOString(),
  signer,
  deterministic = false,
}: BuildTimeAttestationV2Args = {}): Promise<TimeAttestationV2> {
  if (typeof tsAuthorityId !== 'string' || tsAuthorityId.length === 0) {
    throw new Error('buildTimeAttestationV2 requires ts_authority_id');
  }
  if (typeof hashed !== 'string' || hexOf(hashed) === '') {
    throw new Error('buildTimeAttestationV2 requires hashed as sha256:<hex> (fail-closed honesty gate)');
  }
  if (typeof time !== 'string' || instantMs(time) === null) {
    throw new Error('buildTimeAttestationV2 requires a well-formed RFC 3339 time');
  }
  if (!signer || !signer.privateKey || !signer.publicKeyB64u || !signer.pqSecretKey || !signer.pqPublicKeyB64u) {
    throw new Error('buildTimeAttestationV2 requires signer.{privateKey,publicKeyB64u,pqSecretKey,pqPublicKeyB64u}');
  }

  const derivedTsKeyId = tsKeyId(signer.publicKeyB64u);
  if (!derivedTsKeyId) throw new Error('buildTimeAttestationV2 requires a valid base64url Ed25519 SPKI public key');
  const pqPublicB64u = toRawB64u(signer.pqPublicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES, 'signer.pqPublicKeyB64u');
  const pqSecret = toRawB64u(signer.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'signer.pqSecretKey');
  const derivedPqKeyId = pqTsKeyId(pqPublicB64u);

  const att: TimeAttestationV2 = {
    '@version': TIME_ATTESTATION_V2_VERSION,
    ts_authority_id: tsAuthorityId,
    hashed,
    time,
  };

  // ONE set of bytes; both legs sign exactly these, and the required
  // algorithm set is inside them.
  const messageBytes = timeAttestationV2SignedBytes(att, TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS);
  const signatures = await signAgileSet(
    new Uint8Array(messageBytes),
    [
      { alg: 'Ed25519', private_key: signer.privateKey, key_id: derivedTsKeyId },
      { alg: 'ML-DSA-65', private_key: pqSecret, key_id: derivedPqKeyId },
    ],
    deterministic === true ? { deterministic: true } : {},
  );

  // Emit in the registered order, so the document reads the way the bytes commit.
  const byAlg = new Map(signatures.map((s) => [s.alg, s]));
  const ordered = TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS.map((alg) => {
    const s = byAlg.get(alg);
    if (!s) throw new Error(`buildTimeAttestationV2: signing produced no ${alg} leg`);
    return s;
  });

  return {
    ...att,
    proof: {
      required_algorithms: [...TIME_ATTESTATION_V2_REQUIRED_ALGORITHMS],
      ts_key_id: derivedTsKeyId,
      public_key: signer.publicKeyB64u,
      pq_key_id: derivedPqKeyId,
      pq_public_key: pqPublicB64u,
      signatures: ordered,
    },
  };
}
