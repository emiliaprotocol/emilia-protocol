// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-PROFILE-REGISTRY-v1 — signed, pinnable regulated reliance profiles.
 *
 * The business layer above the kernel is not another verifier. It is a REGISTRY
 * of certified reliance profiles: EMILIA (or any registrar) publishes and signs
 * a named EP-RELIANCE-PROFILE-v1 for a regulated flow — NCPDP specialty prior
 * auth, CMS prior auth, Medicaid, specialty pharmacy, government benefits,
 * procurement, agentic payments — so a relying party pins ONE registry key and a
 * profile_id + epoch instead of hand-authoring the rule. The relying party then
 * feeds the resolved profile to evaluateReliance and computes the SAME reliance
 * verdict over the SAME automated action as every other party pinning that
 * profile. That is the clearinghouse: which evidence is admissible before a
 * payer, PBM, pharmacy, agency, bank, or model platform acts.
 *
 * VERIFIED ≠ ACCEPTED, kept separate as everywhere else: `verified` = the entry's
 * Ed25519 signature, entry digest, and inner profile hash all hold; `accepted` =
 * verified AND the registrar key was pinned out of band by the relying party AND
 * any profile_id / epoch freshness pins are satisfied. A signed entry under an
 * unpinned key is identified, not trusted. FAIL-CLOSED throughout.
 *
 * IMMUTABILITY: every profile a verification result carries is a deep,
 * recursively frozen CLONE that shares no object identity with the caller's
 * entry, and the result restates the `profile_hash` those exact bytes hash to,
 * so a verdict can never be re-pointed at a profile the acceptance was not
 * computed over (re-check it with assertRelianceProfileBound).
 */
import crypto from 'node:crypto';
import { canonicalize } from './index.js';
import { validateRelianceProfile, RELIANCE_PROFILE_VERSION } from './reliance.js';
import {
  signAgileSet,
  verifyAgileSignatureSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  type AgilityOptions,
} from './pq-signature-agility.js';

type Obj = Record<string, any>;

interface RegistryOptions {
  pinnedRegistryKeys?: Obj[];
  expectProfileId?: string;
  expectMinEpoch?: number;
}

export const PROFILE_REGISTRY_VERSION = 'EP-RELIANCE-PROFILE-REGISTRY-v1';
export const PROFILE_REGISTRY_DOMAIN = 'EP-RELIANCE-PROFILE-REGISTRY-v1\0';

const SHA256_RE = /^sha256:[0-9a-f]{64}$/i;
const sha256hex = (bytes: Uint8Array): string => crypto.createHash('sha256').update(bytes).digest('hex');
const keyIdFor = (pub: string): string => `ep:reliance-registry-key:sha256:${sha256hex(Buffer.from(pub, 'base64url')).slice(0, 16)}`;

function profileHash(profile: Obj): string {
  return `sha256:${sha256hex(Buffer.from(canonicalize(profile), 'utf8'))}`;
}

/**
 * Deep clone + recursive structural freeze, in one pass. Pure, zero-dependency.
 *
 * The clone shares NO object identity with the input: a caller can neither
 * mutate what it is handed nor reach the registry entry through it. Every
 * nested object and array is frozen too, so a downgrade one level in
 * (`profile.quorum_policy.required = 1`) is as ineffective as one at the top.
 * Only own string-keyed enumerable value properties are carried, which is
 * exactly the member set canonicalize() hashes, so profileHash(deepFreeze(p))
 * === profileHash(p) for any p that canonicalized.
 */
function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return Object.freeze(value.map((item) => deepFreeze(item))) as unknown as T;
  const out: Obj = {};
  for (const key of Object.getOwnPropertyNames(value as Obj)) {
    const descriptor = Object.getOwnPropertyDescriptor(value as Obj, key);
    if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) continue;
    // defineProperty, not assignment: a literal own `__proto__` member must
    // become an own property of the clone, never a prototype swap.
    Object.defineProperty(out, key, { value: deepFreeze(descriptor.value), enumerable: true, writable: false, configurable: false });
  }
  return Object.freeze(out) as unknown as T;
}
function entrySigningBytes(unsignedEntry: Obj): Buffer {
  return Buffer.from(PROFILE_REGISTRY_DOMAIN + canonicalize(unsignedEntry), 'utf8');
}
function unsigned(entry: Obj): Obj {
  const { signature: _sig, ...body } = entry;
  return body;
}

/** Digest of the signed entry body, excluding the signature envelope. */
export function profileRegistryEntryDigest(entry: Obj): string {
  return `sha256:${sha256hex(entrySigningBytes(unsigned(entry)))}`;
}

/**
 * Sign a reliance profile into a registry entry. `privateKey` is a Node
 * Ed25519 KeyObject held by the REGISTRAR (never in this repo).
 * @returns {object} the signed EP-RELIANCE-PROFILE-REGISTRY-v1 entry
 */
export function signRelianceProfileEntry({ registry_id, profile_id, profile, registry_epoch, issued_at }: Obj, privateKey: any): Obj {
  const v = validateRelianceProfile(profile);
  if (!v.ok) throw new Error(`invalid inner profile: ${v.issues.join('; ')}`);
  if (typeof registry_id !== 'string' || !registry_id) throw new Error('registry_id is required');
  if (typeof profile_id !== 'string' || !profile_id) throw new Error('profile_id is required');
  // Store an immutable copy so the signed entry cannot be mutated through the
  // caller's reference to `profile` after signing (the signature/hash would then
  // silently disagree with the body a verifier canonicalizes).
  const frozenProfile = structuredClone(profile);
  const body = {
    '@type': PROFILE_REGISTRY_VERSION,
    registry_id,
    profile_id,
    registry_epoch: Number.isSafeInteger(registry_epoch) ? registry_epoch : 1,
    profile: frozenProfile,
    profile_hash: profileHash(frozenProfile),
    issued_at: issued_at ?? null,
  };
  const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  const entry_digest = `sha256:${sha256hex(entrySigningBytes(body))}`;
  const signature_b64u = crypto.sign(null, entrySigningBytes(body), privateKey).toString('base64url');
  return { ...body, signature: { algorithm: 'Ed25519', public_key: publicKey, key_id: keyIdFor(publicKey), entry_digest, signature_b64u } };
}

/**
 * Verify a registry entry against pinned registrar keys.
 * @param {object} entry
 * @param {object} [opts]
 * @param {Array<{registry_id:string,key_id?:string,public_key:string}>} [opts.pinnedRegistryKeys]
 * @param {string} [opts.expectProfileId]
 * @param {number} [opts.expectMinEpoch]
 * @returns {{verified:boolean, accepted:boolean, profile:(object|null), checks:object, reason?:string, entry_digest?:string, profile_hash?:string, key_id?:string, registry_id?:string, profile_id?:string, registry_epoch?:number}}
 *   `profile`, when present, is a deep frozen clone of the entry's profile and
 *   `profile_hash` is the digest of those exact bytes.
 */
export function verifyRelianceProfileEntry(entry: Obj, opts: RegistryOptions = {}) {
  const checks: Record<string, boolean> = { version: false, signature: false, entry_digest: false, profile_hash: false, pinned_registry_key: false, profile_id: true, epoch_fresh: true, profile_wellformed: false };
  const fail = (reason: string, extra: Obj = {}) => ({ verified: false, accepted: false, profile: null, checks: { ...checks }, reason, ...extra });

  if (!entry || typeof entry !== 'object' || entry['@type'] !== PROFILE_REGISTRY_VERSION) return fail('unsupported_version');
  checks.version = true;

  const sig = entry.signature;
  if (typeof entry.registry_id !== 'string' || !entry.registry_id) return fail('registry_id_missing_or_malformed');
  if (!sig || sig.algorithm !== 'Ed25519' || typeof sig.public_key !== 'string' || typeof sig.signature_b64u !== 'string') return fail('signature_missing_or_malformed');
  if (typeof sig.entry_digest !== 'string' || !SHA256_RE.test(sig.entry_digest)) return fail('entry_digest_malformed');

  let digest;
  try { digest = profileRegistryEntryDigest(entry); } catch { return fail('entry_uncanonicalizable'); }
  if (digest !== sig.entry_digest) return fail('entry_digest_mismatch', { entry_digest: digest });
  checks.entry_digest = true;

  // The inner profile must be well-formed AND bound by profile_hash (a lying
  // profile_hash cannot substitute a different profile under the same signature).
  const pv = validateRelianceProfile(entry.profile);
  checks.profile_wellformed = pv.ok;
  if (!pv.ok) return fail('inner_profile_invalid', { entry_digest: digest });
  if (entry.profile_hash !== profileHash(entry.profile)) return fail('profile_hash_mismatch', { entry_digest: digest });
  checks.profile_hash = true;

  if (typeof opts.expectProfileId === 'string' && entry.profile_id !== opts.expectProfileId) {
    checks.profile_id = false;
    return { verified: false, accepted: false, profile: null, checks, reason: 'profile_id_mismatch', entry_digest: digest };
  }
  const minEpoch = opts.expectMinEpoch;
  if (typeof minEpoch === 'number' && Number.isSafeInteger(minEpoch) && !(Number.isSafeInteger(entry.registry_epoch) && entry.registry_epoch >= minEpoch)) {
    checks.epoch_fresh = false;
    return { verified: false, accepted: false, profile: null, checks, reason: 'stale_registry', entry_digest: digest };
  }

  // Signature must verify (regardless of pinning) so `verified` is honest.
  let sigOk = false;
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(sig.public_key, 'base64url'), type: 'spki', format: 'der' });
    sigOk = crypto.verify(null, entrySigningBytes(unsigned(entry)), publicKey, Buffer.from(sig.signature_b64u, 'base64url'));
  } catch { sigOk = false; }
  if (!sigOk) return { verified: false, accepted: false, profile: null, checks, reason: 'signature_invalid', entry_digest: digest };
  checks.signature = true;

  const derivedKeyId = keyIdFor(sig.public_key);
  if (sig.key_id !== undefined && sig.key_id !== derivedKeyId) {
    return { verified: false, accepted: false, profile: null, checks, reason: 'key_id_mismatch', entry_digest: digest };
  }
  const pinned = Array.isArray(opts.pinnedRegistryKeys) ? opts.pinnedRegistryKeys : [];
  const keyMatched = pinned.filter((k: Obj) => k?.public_key === sig.public_key
    && (k.key_id === undefined || k.key_id === derivedKeyId));
  const pin = keyMatched.find((k: Obj) => typeof k.registry_id === 'string' && k.registry_id === entry.registry_id);
  // The resolved profile leaves this function as a frozen clone, never the
  // caller's object: a live reference would let a holder of an ACCEPTED verdict
  // rewrite the profile the acceptance was computed over (and the entry with
  // it, through the shared reference), leaving a result that describes bytes
  // the entry_digest and profile_hash never covered.
  const resolved = deepFreeze(entry.profile as Obj);
  const resolvedHash = profileHash(resolved);
  if (!pin) {
    // VERIFIED (signature holds) but NOT ACCEPTED (registrar key not pinned).
    return {
      verified: true,
      accepted: false,
      profile: resolved,
      checks,
      reason: keyMatched.length ? 'pin_missing_or_mismatched_registry_id' : 'registry_key_not_pinned',
      entry_digest: digest,
      profile_hash: resolvedHash,
      key_id: derivedKeyId,
      registry_id: entry.registry_id,
    };
  }
  checks.pinned_registry_key = true;

  return { verified: true, accepted: true, profile: resolved, checks, key_id: derivedKeyId, registry_id: entry.registry_id, profile_id: entry.profile_id, registry_epoch: entry.registry_epoch, entry_digest: digest, profile_hash: resolvedHash };
}

/**
 * Re-check that a verification result's profile still hashes to the
 * `profile_hash` the result was issued with. Pure, offline, and independent of
 * the registry entry: a consumer holding only the result can prove the bytes it
 * is about to evaluate are the bytes the verdict was computed over.
 *
 * BINDING ONLY, never acceptance: `ok` says the profile matches its hash, and
 * says nothing about `verified` or `accepted` — read those fields separately.
 * Fail-closed with a reason; an expected mismatch returns, it never throws.
 *
 * @param {object} result a verifyRelianceProfileEntry() result
 * @returns {{ok:boolean, reason:(string|null), profile_hash:(string|null)}}
 */
export function assertRelianceProfileBound(result: Obj): { ok: boolean; reason: string | null; profile_hash: string | null } {
  const refuse = (reason: string) => ({ ok: false, reason, profile_hash: null });
  if (!result || typeof result !== 'object' || Array.isArray(result)) return refuse('result_malformed');
  const profile = result.profile;
  if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return refuse('profile_missing');
  if (typeof result.profile_hash !== 'string' || !SHA256_RE.test(result.profile_hash)) return refuse('profile_hash_missing_or_malformed');
  let recomputed;
  try { recomputed = profileHash(profile); } catch { return refuse('profile_uncanonicalizable'); }
  if (recomputed !== result.profile_hash) return refuse('profile_hash_mismatch');
  return { ok: true, reason: null, profile_hash: recomputed };
}

export { RELIANCE_PROFILE_VERSION };

// ===========================================================================
// EP-RELIANCE-PROFILE-REGISTRY-v2 -- the hybrid (Ed25519 + ML-DSA-65) registry entry
// ===========================================================================
/**
 * Same five-move hybrid migration as packages/verify/src/revocation.ts's
 * EP-REVOCATION-v2 (read that file's header for the full write-up); applied
 * here to the registry entry.
 *
 * 1. VERSION BUMP. `@type: EP-RELIANCE-PROFILE-REGISTRY-v2`, not a field grown
 *    on v1. verifyRelianceProfileEntry() above is untouched: its first check
 *    is `entry['@type'] !== PROFILE_REGISTRY_VERSION -> fail('unsupported_version')`,
 *    an immediate return before any v2-only field is ever read, so a v2 entry
 *    handed to the v1 verifier refuses cleanly and never throws.
 *
 * 2. SET SHAPE + FIELD LAYOUT CHOICE. The single `signature: {algorithm,
 *    public_key, key_id, entry_digest, signature_b64u}` object v1 carries has
 *    no room for a second algorithm, so v2 replaces it with a `proof: {...}`
 *    sub-object carrying `entry_digest`, `required_algorithms`, the Ed25519
 *    `key_id`/`public_key`, the ML-DSA-65 `pq_key_id`/`pq_public_key`, and a
 *    `signatures` array shaped exactly like EP-SIG-AGILITY-v1's AgileSignature
 *    ({alg, sig, key_id?}). CHOICE: nested `proof`, not flattened onto the
 *    entry, because that is this file's OWN v1 idiom -- v1 already keeps its
 *    envelope under a nested `signature` sub-object rather than flattening
 *    `public_key`/`entry_digest` onto the entry body, and `unsigned(entry)` /
 *    `entrySigningBytes()` already assume "the envelope is one sibling key to
 *    strip". `unsignedV2()` mirrors that exactly: it strips `proof`, not five
 *    separate top-level fields. `profile` and `profile_hash` stay top-level
 *    exactly as in v1, since they are the SIGNED BODY, not part of the
 *    signature envelope.
 *
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` is inside the signed bytes
 *    (entrySigningBytesV2 below), under a v2-only domain separator distinct
 *    from PROFILE_REGISTRY_DOMAIN so a v1 and v2 signature over similar-looking
 *    fields can never collide. Narrowing the set after signing changes the
 *    bytes, so the surviving Ed25519 signature stops verifying even though it
 *    was never touched -- proved by a hostile test, not merely asserted.
 *
 * 4. V1 COMPATIBILITY. v1 stays synchronous, unchanged.
 *    verifyRelianceProfileEntryV2() is a separate async entry point (ML-DSA
 *    verification is async), and verifyRelianceProfileEntryStatement() routes
 *    a caller's mixed bag by `@type`, mirroring verifyRevocationStatement().
 *
 * 5. NAMED REFUSALS. Every gate is a named boolean in `checks` plus a
 *    `reason` string; nothing throws on entry/key content, and an absent
 *    ML-DSA backend is a refusal ('pq_backend_unavailable', surfaced through
 *    the agility result), never a skipped check or a pass on the Ed25519 leg
 *    alone. `verified` is computed under the entry's OWN presented key
 *    material (never the pin) so it is honest about what the bytes prove;
 *    `accepted` is a SEPARATE check that both presented key halves equal a
 *    pin for this exact registry_id -- the same two-step structure v1 already
 *    uses ("signature must verify regardless of pinning, so verified is
 *    honest").
 */

export const PROFILE_REGISTRY_V2_VERSION = 'EP-RELIANCE-PROFILE-REGISTRY-v2';
export const PROFILE_REGISTRY_V2_DOMAIN = 'EP-RELIANCE-PROFILE-REGISTRY-v2\0';

/** The registered required algorithm set, in canonical order. */
export const PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

export interface ProfileRegistryV2Signature { alg?: unknown; sig?: unknown; key_id?: unknown; }
export interface ProfileRegistryV2Proof {
  entry_digest?: unknown;
  required_algorithms?: unknown;
  /** Ed25519: base64url SPKI DER. */
  key_id?: unknown;
  public_key?: unknown;
  /** ML-DSA-65: base64url of the raw 1952-byte public key. */
  pq_key_id?: unknown;
  pq_public_key?: unknown;
  signatures?: unknown;
  [key: string]: unknown;
}
export interface RegistryV2KeyPin {
  registry_id?: string;
  /** Ed25519 base64url SPKI DER. */
  public_key?: string;
  key_id?: string;
  /** ML-DSA-65 base64url raw public key bytes. */
  pq_public_key?: string;
  pq_key_id?: string;
}
export interface RegistryV2Options {
  pinnedRegistryKeys?: RegistryV2KeyPin[];
  expectProfileId?: string;
  expectMinEpoch?: number;
  mldsaBackend?: AgilityOptions['mldsaBackend'];
  mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}

/** ML-DSA-65 registry-key identifier: same truncated-digest convention as keyIdFor. */
const pqKeyIdFor = (pubRawB64u: string): string =>
  `ep:reliance-registry-key:ml-dsa-65:sha256:${sha256hex(Buffer.from(pubRawB64u, 'base64url')).slice(0, 16)}`;

function algorithmSetMatchesRegisteredV2(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS[i]);
}

function unsignedV2(entry: Obj): Obj {
  const { proof: _proof, ...body } = entry;
  return body;
}

/**
 * The bytes BOTH legs sign: the v2 unsigned body plus the committed
 * `required_algorithms` set, under the v2-only domain separator. Throws if
 * `requiredAlgorithms` is not exactly the registered set -- mirrors
 * revocationV2SignedPayload's guard, so an issuer can never mint bytes over a
 * narrowed or widened set through this function. The verifier always calls
 * this with the REGISTERED default, never the presented `required_algorithms`.
 */
export function entrySigningBytesV2(
  unsignedEntryV2: Obj,
  requiredAlgorithms: readonly string[] = PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS,
): Buffer {
  if (!algorithmSetMatchesRegisteredV2(requiredAlgorithms)) {
    throw new Error('entrySigningBytesV2: algorithm set is not the registered EP-RELIANCE-PROFILE-REGISTRY-v2 set');
  }
  return Buffer.from(
    PROFILE_REGISTRY_V2_DOMAIN + canonicalize({ ...unsignedEntryV2, required_algorithms: [...requiredAlgorithms] }),
    'utf8',
  );
}

/** Digest of the signed v2 entry body, excluding the `proof` envelope. */
export function profileRegistryEntryDigestV2(
  entry: Obj,
  requiredAlgorithms: readonly string[] = PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS,
): string {
  return `sha256:${sha256hex(entrySigningBytesV2(unsignedV2(entry), requiredAlgorithms))}`;
}

function toRawB64uV2(value: unknown, expectedLength: number, label: string): string {
  const bytes = value instanceof Uint8Array
    ? Buffer.from(value)
    : Buffer.from(String(value), 'base64url');
  if (bytes.length !== expectedLength) {
    throw new Error(`signRelianceProfileEntryV2: ${label} must be ${expectedLength} raw bytes (or base64url of them)`);
  }
  return bytes.toString('base64url');
}

export interface RelianceProfileEntryV2Signer {
  /** Ed25519 private key, node crypto KeyObject. */
  privateKey: any;
  /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
  pqSecretKey: Uint8Array | string;
  /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
  pqPublicKeyB64u: Uint8Array | string;
}

/**
 * Sign a reliance profile into a v2 (hybrid) registry entry, under BOTH
 * registered algorithms over one set of bytes that COMMIT to the required
 * algorithm set (see entrySigningBytesV2). Issuer-side reference tooling:
 * THROWS rather than emit a half-hybrid entry, the same fail-closed honesty
 * gate buildRevocationV2 uses in lib/revocation/revocation.ts -- issuer-side
 * misuse (missing profile fields, missing PQ key material, unavailable ML-DSA
 * backend) is a programming error, never a silently downgraded artifact.
 */
export async function signRelianceProfileEntryV2(
  { registry_id, profile_id, profile, registry_epoch, issued_at }: Obj,
  signer: RelianceProfileEntryV2Signer,
): Promise<Obj> {
  const v = validateRelianceProfile(profile);
  if (!v.ok) throw new Error(`invalid inner profile: ${v.issues.join('; ')}`);
  if (typeof registry_id !== 'string' || !registry_id) throw new Error('registry_id is required');
  if (typeof profile_id !== 'string' || !profile_id) throw new Error('profile_id is required');
  if (!signer || !signer.privateKey || !signer.pqSecretKey || !signer.pqPublicKeyB64u) {
    throw new Error('signRelianceProfileEntryV2 requires signer.{privateKey,pqSecretKey,pqPublicKeyB64u}');
  }

  // Same immutable-copy discipline as v1: the stored profile can never drift
  // out from under the signature/hash through the caller's own reference.
  const frozenProfile = structuredClone(profile);
  const body = {
    '@type': PROFILE_REGISTRY_V2_VERSION,
    registry_id,
    profile_id,
    registry_epoch: Number.isSafeInteger(registry_epoch) ? registry_epoch : 1,
    profile: frozenProfile,
    profile_hash: profileHash(frozenProfile),
    issued_at: issued_at ?? null,
  };

  const publicKey = crypto.createPublicKey(signer.privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
  const pqPublicB64u = toRawB64uV2(signer.pqPublicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES, 'signer.pqPublicKeyB64u');
  const pqSecretB64u = toRawB64uV2(signer.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'signer.pqSecretKey');
  const keyId = keyIdFor(publicKey);
  const pqKeyId = pqKeyIdFor(pqPublicB64u);

  const bytes = entrySigningBytesV2(body);
  const entry_digest = `sha256:${sha256hex(bytes)}`;

  const signatures = await signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: signer.privateKey, key_id: keyId },
    { alg: 'ML-DSA-65', private_key: pqSecretB64u, key_id: pqKeyId },
  ]);

  return {
    ...body,
    proof: {
      entry_digest,
      required_algorithms: [...PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS],
      key_id: keyId,
      public_key: publicKey,
      pq_key_id: pqKeyId,
      pq_public_key: pqPublicB64u,
      signatures,
    },
  };
}

function agilityPassthroughV2(opts: RegistryV2Options): AgilityOptions {
  const out: AgilityOptions = {};
  if (opts.mldsaBackend !== undefined) out.mldsaBackend = opts.mldsaBackend;
  if (opts.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = opts.mldsaBackendLoader;
  return out;
}

/**
 * Verify a v2 (hybrid) registry entry against pinned registrar keys. ASYNC,
 * unlike v1, because ML-DSA-65 verification is async. FAIL-CLOSED throughout:
 * nothing here throws on entry or key content, and a missing ML-DSA backend
 * is a named refusal, never a skipped check.
 *
 * VERIFIED (both signatures cryptographically hold under the registered
 * algorithm set, the recomputed entry_digest, and the recomputed profile_hash
 * -- checked under the entry's OWN presented key material) is kept strictly
 * separate from ACCEPTED (verified AND both presented key halves equal a pin
 * registered for this exact registry_id).
 */
export async function verifyRelianceProfileEntryV2(entry: Obj, opts: RegistryV2Options = {}) {
  const checks: Record<string, boolean> = {
    version: false,
    entry_digest: false,
    profile_hash: false,
    profile_wellformed: false,
    profile_id: true,
    epoch_fresh: true,
    algorithm_set: false,
    legs_present: false,
    signature_set_valid: false,
    pinned_registry_key: false,
  };
  const fail = (reason: string, extra: Obj = {}) => ({ verified: false, accepted: false, profile: null, checks: { ...checks }, reason, ...extra });

  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || entry['@type'] !== PROFILE_REGISTRY_V2_VERSION) {
    return fail('unsupported_version');
  }
  checks.version = true;

  if (typeof entry.registry_id !== 'string' || !entry.registry_id) return fail('registry_id_missing_or_malformed');
  if (typeof entry.profile_id !== 'string' || !entry.profile_id) return fail('profile_id_missing_or_malformed');

  const proof = (entry.proof || null) as ProfileRegistryV2Proof | null;
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)
    || typeof proof.public_key !== 'string' || typeof proof.pq_public_key !== 'string'
    || typeof proof.key_id !== 'string' || typeof proof.pq_key_id !== 'string') {
    return fail('proof_missing_or_malformed');
  }
  if (typeof proof.entry_digest !== 'string' || !SHA256_RE.test(proof.entry_digest)) {
    return fail('entry_digest_malformed');
  }

  // Algorithm set: exact registered set, order-sensitive, never the presented
  // set standing in for the registered one. A narrowed/widened set refuses
  // structurally here; the digest and signature checks below independently
  // rebuild the bytes from the REGISTERED set regardless of what is presented.
  if (!algorithmSetMatchesRegisteredV2(proof.required_algorithms)) {
    return fail('algorithm_set_invalid');
  }
  checks.algorithm_set = true;

  let bytes: Buffer;
  try {
    bytes = entrySigningBytesV2(unsignedV2(entry), PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS);
  } catch {
    return fail('entry_uncanonicalizable');
  }
  const digest = `sha256:${sha256hex(bytes)}`;
  if (digest !== proof.entry_digest) return fail('entry_digest_mismatch', { entry_digest: digest });
  checks.entry_digest = true;

  // The inner profile must be well-formed AND bound by profile_hash, exactly
  // as v1 requires (a lying profile_hash cannot substitute a different
  // profile under the same signature).
  const pv = validateRelianceProfile(entry.profile);
  checks.profile_wellformed = pv.ok;
  if (!pv.ok) return fail('inner_profile_invalid', { entry_digest: digest });
  if (entry.profile_hash !== profileHash(entry.profile)) return fail('profile_hash_mismatch', { entry_digest: digest });
  checks.profile_hash = true;

  if (typeof opts.expectProfileId === 'string' && entry.profile_id !== opts.expectProfileId) {
    checks.profile_id = false;
    return { verified: false, accepted: false, profile: null, checks, reason: 'profile_id_mismatch', entry_digest: digest };
  }
  const minEpoch = opts.expectMinEpoch;
  if (typeof minEpoch === 'number' && Number.isSafeInteger(minEpoch)
    && !(Number.isSafeInteger(entry.registry_epoch) && entry.registry_epoch >= minEpoch)) {
    checks.epoch_fresh = false;
    return { verified: false, accepted: false, profile: null, checks, reason: 'stale_registry', entry_digest: digest };
  }

  // Legs present: exactly one signature per required algorithm, no dupes/extras
  // and no leg stripped (this is the structural half of anti-stripping; the
  // cryptographic half is that a narrowed-then-signed set never verifies).
  const signatures = Array.isArray(proof.signatures) ? proof.signatures as ProfileRegistryV2Signature[] : null;
  let legsOk = false;
  let legsReason = 'legs_missing';
  if (signatures && signatures.length > 0) {
    const presented = new Set<string>();
    let malformed = false;
    for (const s of signatures) {
      if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        malformed = true;
        legsReason = 'leg_malformed';
        break;
      }
      if (presented.has(s.alg)) {
        malformed = true;
        legsReason = `duplicate_algorithm:${s.alg}`;
        break;
      }
      presented.add(s.alg);
    }
    if (!malformed) {
      const missing = PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS.filter((alg) => !presented.has(alg));
      const extra = [...presented].filter((alg) => !(PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg));
      legsOk = missing.length === 0 && extra.length === 0;
      if (!legsOk) legsReason = missing.length ? `missing_required_algorithm:${missing.join(',')}` : `unexpected_algorithm:${extra.join(',')}`;
    }
  }
  checks.legs_present = legsOk;
  if (!legsOk) return { verified: false, accepted: false, profile: null, checks, reason: legsReason, entry_digest: digest };

  // Signature set: verified under the entry's OWN presented key material
  // (never the pin) so `verified` is honest about what the bytes prove. A
  // missing/unavailable ML-DSA backend surfaces as a named refusal via the
  // agility module's own reason, never a silent pass on the Ed25519 leg.
  const presentedKeys = [
    { alg: 'Ed25519', public_key: proof.public_key as string },
    { alg: 'ML-DSA-65', public_key: proof.pq_public_key as string },
  ];
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(new Uint8Array(bytes), signatures, presentedKeys, {
      ...agilityPassthroughV2(opts),
      policy: 'hybrid_all',
      requiredAlgorithms: [...PROFILE_REGISTRY_V2_REQUIRED_ALGORITHMS],
    });
  } catch {
    // verifyAgileSignatureSet documents that it never throws; an injected
    // backend that does is still a refusal here, never a pass.
    setResult = null;
  }
  const sigOk = setResult?.verified === true;
  checks.signature_set_valid = sigOk;
  if (!sigOk) {
    const reason = String(setResult?.reason ?? 'signature_set_unverified');
    return { verified: false, accepted: false, profile: null, checks, reason: `signature_invalid:${reason}`, entry_digest: digest };
  }

  const derivedKeyId = keyIdFor(proof.public_key as string);
  const derivedPqKeyId = pqKeyIdFor(proof.pq_public_key as string);
  if (proof.key_id !== derivedKeyId || proof.pq_key_id !== derivedPqKeyId) {
    return { verified: false, accepted: false, profile: null, checks, reason: 'key_id_mismatch', entry_digest: digest };
  }

  // verified:true from here: both signatures hold, over bytes committing to
  // the registered set, under keys whose ids match the presented material.
  // The resolved profile leaves this function as a frozen clone, same
  // discipline as v1, for the same reason: a live reference would let an
  // ACCEPTED verdict be re-pointed at bytes the acceptance never covered.
  const resolved = deepFreeze(entry.profile as Obj);
  const resolvedHash = profileHash(resolved);

  const pinned = Array.isArray(opts.pinnedRegistryKeys) ? opts.pinnedRegistryKeys : [];
  const keyMatched = pinned.filter((k: RegistryV2KeyPin) => k
    && k.public_key === proof.public_key && k.pq_public_key === proof.pq_public_key
    && (k.key_id === undefined || k.key_id === derivedKeyId)
    && (k.pq_key_id === undefined || k.pq_key_id === derivedPqKeyId));
  const pin = keyMatched.find((k: RegistryV2KeyPin) => typeof k.registry_id === 'string' && k.registry_id === entry.registry_id);

  if (!pin) {
    // VERIFIED (both signatures hold) but NOT ACCEPTED (registrar keys not
    // pinned for this exact registry_id) -- distinct, honest reason.
    return {
      verified: true,
      accepted: false,
      profile: resolved,
      checks,
      reason: keyMatched.length ? 'pin_missing_or_mismatched_registry_id' : 'registry_key_not_pinned',
      entry_digest: digest,
      profile_hash: resolvedHash,
      key_id: derivedKeyId,
      pq_key_id: derivedPqKeyId,
      registry_id: entry.registry_id,
    };
  }
  checks.pinned_registry_key = true;

  return {
    verified: true,
    accepted: true,
    profile: resolved,
    checks,
    key_id: derivedKeyId,
    pq_key_id: derivedPqKeyId,
    registry_id: entry.registry_id,
    profile_id: entry.profile_id,
    registry_epoch: entry.registry_epoch,
    entry_digest: digest,
    profile_hash: resolvedHash,
  };
}

/**
 * Route an entry of EITHER version to its verifier. v1 entries get the exact
 * v1 verdict (sync, resolved as a Promise); v2 entries get the hybrid check.
 * An entry whose `@type` is neither refuses on the version marker, through
 * the v1 verifier, which is the fail-closed answer. Mirrors
 * verifyRevocationStatement() in revocation.ts.
 */
export async function verifyRelianceProfileEntryStatement(entry: Obj, opts: RegistryOptions & RegistryV2Options = {}) {
  if (entry && typeof entry === 'object' && !Array.isArray(entry) && (entry as Obj)['@type'] === PROFILE_REGISTRY_V2_VERSION) {
    return verifyRelianceProfileEntryV2(entry, opts);
  }
  return verifyRelianceProfileEntry(entry, opts as RegistryOptions);
}
