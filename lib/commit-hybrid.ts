/**
 * EMILIA Protocol -- EP-COMMIT-HYBRID-v1
 *
 * OPT-IN hybrid (Ed25519 + ML-DSA-65) proof over an EP Commit's canonical
 * fields, issued through the dual-signer custody seam in lib/key-custody.ts
 * and verified with EP-SIG-AGILITY-v1
 * (packages/verify/src/pq-signature-agility.ts).
 *
 * @license Apache-2.0
 *
 * --- WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT --------------------------
 *
 * A commit row in the `commits` table is an EP v1 artifact: one flat Ed25519
 * `signature` over JSON.stringify(deepSortKeys(canonicalFields)). That format
 * is what verifyCommit(), the MCP tools, the DB contract, and every deployed
 * relying party read, and this module does NOT change a byte of it. With no
 * hybrid signer configured, lib/commit.ts emits exactly the row it emitted
 * before this module existed.
 *
 * When a deployment registers a HybridCustodySigner, issuance ADDITIONALLY
 * emits an EP-COMMIT-HYBRID-v1 proof: a detached, self-contained document
 * carrying the same canonical fields plus one signature per required
 * algorithm. The proof is returned to the issuer as `hybrid_proof`; it is not
 * written to the `commits` table, so no schema change and no migration is
 * involved, and a deployment stores or forwards it exactly as it stores any
 * other portable EP artifact.
 *
 * --- ANTI-STRIPPING: THE SET IS INSIDE THE SIGNED BYTES ---------------------
 *
 * Both legs sign the SAME bytes, and those bytes are not the commit's
 * canonical payload. They are:
 *
 *   signed_material = {
 *     "@version":            "EP-COMMIT-HYBRID-v1",
 *     "payload":             <the commit's canonicalFields>,
 *     "required_algorithms": ["Ed25519", "ML-DSA-65"]
 *   }
 *   message_bytes   = UTF8(JSON.stringify(deepSortKeys(signed_material)))
 *
 * Delete the ML-DSA leg and narrow `required_algorithms` to ["Ed25519"] and
 * the surviving Ed25519 signature no longer verifies, because the bytes
 * changed. Leave the set intact and the missing leg is a structural refusal
 * (`hybrid_leg_missing`). Either way stripping is detected, not tolerated.
 * This is the same byte-level commitment EP-RECEIPT-HYBRID-v1 uses
 * (packages/issue/src/hybrid-issuance.ts), and it is STRONGER than
 * EP-SIG-AGILITY-v1's `hybrid_all` policy alone, which is relying-party policy
 * rather than a commitment. Verification here rebuilds the bytes from the
 * REGISTERED algorithm set and from the VERIFIER's own canonical fields, never
 * from anything the presented proof could have narrowed or substituted.
 *
 * --- HONEST BOUNDARY -- READ THIS ------------------------------------------
 *
 * Within an EP-COMMIT-HYBRID-v1 proof, one leg alone NEVER verifies. That is a
 * cryptographic property of the bytes above and it is what the hostile tests
 * exercise.
 *
 * It does NOT follow that a hybrid deployment cannot be downgraded. The commit
 * ROW remains a valid v1 artifact by design, so a relying party handed only
 * the row, who never asks for the proof, gets a v1 Ed25519 verdict. Requiring
 * the PQ leg is therefore a RELYING-PARTY PIN, expressed as
 * verifyCommit(id, { hybrid: { required: true, proof, keys } }), exactly as
 * pinning a revoker key is a relying-party pin in the revocation profile. This
 * module makes that pin available and refuses without it; it cannot make a
 * verifier that never asks.
 *
 * The PQ key is SOFTWARE-HELD (see the custody-boundary note in
 * lib/key-custody.ts): no KMS or HSM ML-DSA-65 signing path exists for EP
 * today, and the default backend is a pure-JS FIPS 204 implementation that is
 * not independently audited and is not a FIPS validated module. Issuing under
 * this profile is not a certification claim.
 *
 * An absent ML-DSA backend is a REFUSAL (`pq_backend_unavailable`), never a
 * pass on the classical leg alone.
 */

import { verifyAgileSignatureSet } from '@emilia-protocol/verify/pq-signature-agility';

import { deepSortKeys } from './handshake/binding.js';
import {
  HYBRID_CUSTODY_ALGORITHMS,
  type CustodySignatureSetEntry,
  type HybridCustodySigner,
  type HybridCustodyAlgorithm,
} from './key-custody.js';

/** The profile id, used as both `@version` and `profile.id`. */
export const COMMIT_HYBRID_PROFILE = 'EP-COMMIT-HYBRID-v1';

/**
 * The registered required algorithm set, in canonical order. v1 is a FIXED
 * two-algorithm hybrid. This array goes INTO the signed material, so its exact
 * contents and order are part of what every leg commits to.
 */
export const COMMIT_HYBRID_REQUIRED_ALGORITHMS = HYBRID_CUSTODY_ALGORITHMS;

/** Named refusals. Every verification failure returns one of these; none throw. */
export const COMMIT_HYBRID_REASONS = Object.freeze({
  MALFORMED_PROOF: 'malformed_proof',
  UNKNOWN_PROFILE: 'unknown_profile',
  ALGORITHM_SET_MISMATCH: 'algorithm_set_mismatch',
  PAYLOAD_MISMATCH: 'payload_mismatch',
  HYBRID_LEG_MISSING: 'hybrid_leg_missing',
  UNEXPECTED_ALGORITHM: 'unexpected_algorithm',
  DUPLICATE_ALGORITHM: 'duplicate_algorithm',
  MISSING_KEY: 'missing_key',
  SIGNATURE_INVALID: 'signature_invalid',
  PQ_BACKEND_UNAVAILABLE: 'pq_backend_unavailable',
});

export interface CommitHybridProof {
  '@version': string;
  profile: { id: string; required_algorithms: string[] };
  /**
   * UNSIGNED convenience label for storage and lookup, the same role
   * `metadata` plays in EP-RECEIPT-v1. It is NOT what binds the proof to a
   * commit: `payload` is, and `payload.commit_id` inside it is covered by both
   * signatures. Verification ignores this field, so nothing may be authorized
   * on it.
   */
  commit_id: string;
  payload: Record<string, unknown>;
  signatures: CustodySignatureSetEntry[];
}

/** The public halves a relying party pins to check a hybrid proof. */
export interface CommitHybridVerificationKeys {
  /** base64url SPKI DER, or a node crypto public KeyObject. */
  ed25519PublicKey: unknown;
  ed25519KeyId?: string;
  /** base64url raw 1952 bytes, or the raw bytes. */
  mldsaPublicKey: unknown;
  mldsaKeyId?: string;
}

export interface CommitHybridChecks {
  profile: boolean;
  algorithm_set: boolean | null;
  payload_bound: boolean | null;
  legs_present: boolean | null;
  signatures_valid: boolean | null;
}

export interface CommitHybridVerifyResult {
  verified: boolean;
  reason: string | null;
  /** Which algorithm's leg failed, when the failure is attributable to one. */
  failed_algorithm: string | null;
  checks: CommitHybridChecks;
}

/** Options threaded to EP-SIG-AGILITY-v1 (backend injection for tests/vectors). */
export interface CommitHybridOptions {
  mldsaBackend?: unknown;
  mldsaBackendLoader?: unknown;
}

// ---------------------------------------------------------------------------
// The signed material (produced ONCE, signed by every leg)
// ---------------------------------------------------------------------------

/**
 * Build the exact object both legs sign. The required algorithm set and the
 * profile id are INSIDE it: that is the anti-stripping commitment. Exported so
 * a verifier or an independent implementation can rebuild the bytes without
 * reading this module's internals.
 */
export function commitHybridSignedMaterial(
  payload: Record<string, unknown>,
  requiredAlgorithms: readonly string[] = COMMIT_HYBRID_REQUIRED_ALGORITHMS,
): Record<string, unknown> {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new TypeError('commitHybridSignedMaterial: payload must be a plain object');
  }
  if (!algorithmSetMatchesRegistered(requiredAlgorithms)) {
    throw new Error(`commitHybridSignedMaterial: refusing: ${COMMIT_HYBRID_REASONS.ALGORITHM_SET_MISMATCH}`);
  }
  return {
    '@version': COMMIT_HYBRID_PROFILE,
    payload,
    required_algorithms: [...requiredAlgorithms],
  };
}

/**
 * UTF-8 canonical bytes of commitHybridSignedMaterial(). What every leg signs.
 * Canonicalization is deepSortKeys + JSON.stringify, byte-for-byte the same
 * function lib/commit.ts uses for the v1 payload, so a hybrid deployment has
 * exactly one canonicalization to reason about.
 */
export function commitHybridSignedBytes(
  payload: Record<string, unknown>,
  requiredAlgorithms: readonly string[] = COMMIT_HYBRID_REQUIRED_ALGORITHMS,
): Buffer {
  return Buffer.from(
    JSON.stringify(deepSortKeys(commitHybridSignedMaterial(payload, requiredAlgorithms))),
    'utf8',
  );
}

function algorithmSetMatchesRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === COMMIT_HYBRID_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === COMMIT_HYBRID_REQUIRED_ALGORITHMS[i]);
}

// ---------------------------------------------------------------------------
// Issuance (throws on misuse; never downgrades)
// ---------------------------------------------------------------------------

/**
 * Mint an EP-COMMIT-HYBRID-v1 proof for a commit's canonical fields, signing
 * through the dual-signer custody seam.
 *
 * Issuer-side misuse is a programming error, so this THROWS, matching
 * signAgile and createHybridReceipt. In particular the PQ leg's own signer
 * throws when no ML-DSA backend is available, so a proof missing the PQ leg is
 * never emitted.
 */
export async function createCommitHybridProof({ commit_id: commitId, payload, signer }: {
  commit_id: string;
  payload: Record<string, unknown>;
  signer: HybridCustodySigner;
}): Promise<CommitHybridProof> {
  if (!commitId || typeof commitId !== 'string') {
    throw new TypeError('createCommitHybridProof: commit_id is required');
  }
  if (!signer || typeof signer.signSet !== 'function') {
    throw new TypeError('createCommitHybridProof: signer must be a HybridCustodySigner (see createHybridCustodySigner)');
  }

  const requiredAlgorithms = [...COMMIT_HYBRID_REQUIRED_ALGORITHMS];
  // ONE set of bytes; both legs sign exactly these.
  const messageBytes = commitHybridSignedBytes(payload, requiredAlgorithms);
  const signatures = await signer.signSet(messageBytes, { profile: COMMIT_HYBRID_PROFILE, commit_id: commitId });

  // Order the emitted signatures to match the committed set, so the document
  // reads the same way the bytes commit.
  const byAlg = new Map(signatures.map((s) => [s.alg, s]));
  const ordered: CustodySignatureSetEntry[] = [];
  for (const alg of requiredAlgorithms) {
    const s = byAlg.get(alg as HybridCustodyAlgorithm);
    if (!s) throw new Error(`createCommitHybridProof: signing produced no ${alg} leg`);
    ordered.push(s);
  }

  return {
    '@version': COMMIT_HYBRID_PROFILE,
    profile: { id: COMMIT_HYBRID_PROFILE, required_algorithms: requiredAlgorithms },
    commit_id: commitId,
    payload,
    signatures: ordered,
  };
}

// ---------------------------------------------------------------------------
// Verification (never throws on caller input)
// ---------------------------------------------------------------------------

/**
 * Verify an EP-COMMIT-HYBRID-v1 proof against the canonical fields the
 * VERIFIER independently recomputed from the commit it holds.
 *
 * Order of checks, and why:
 *   1. Structure and profile marker. An unknown `@version` or `profile.id`
 *      refuses with `unknown_profile`; this is not a general proof verifier
 *      and never guesses at another format.
 *   2. `profile.required_algorithms` must EXACTLY equal the registered set,
 *      order included. A narrowed set is the stripping attack's cover story,
 *      so it is refused structurally, before the (also failing) signature
 *      check.
 *   3. The proof's `payload` must canonicalize to the same bytes as the
 *      verifier's own canonical fields (`payload_mismatch`); a proof for some
 *      other commit never speaks for this one.
 *   4. Exactly one signature per required algorithm: a missing leg is
 *      `hybrid_leg_missing`, an extra one `unexpected_algorithm`, a repeat
 *      `duplicate_algorithm`.
 *   5. Bytes are rebuilt from the VERIFIER's payload and the REGISTERED set,
 *      then handed to EP-SIG-AGILITY-v1's verifyAgileSignatureSet under policy
 *      `hybrid_all` with requiredAlgorithms pinned to the full set. Every leg
 *      must verify over identical bytes. The agility module curve-pins the
 *      Ed25519 key, so an Ed448 (or any non-Ed25519) SPKI presented as the
 *      Ed25519 verification key refuses with `missing_key` rather than being
 *      verified under the wrong algorithm.
 */
export async function verifyCommitHybridProof(
  payload: Record<string, unknown> | null | undefined,
  proof: unknown,
  keys: CommitHybridVerificationKeys | null | undefined,
  options: CommitHybridOptions = {},
): Promise<CommitHybridVerifyResult> {
  const checks: CommitHybridChecks = {
    profile: false,
    algorithm_set: null,
    payload_bound: null,
    legs_present: null,
    signatures_valid: null,
  };
  const refuse = (reason: string, failedAlgorithm: string | null = null): CommitHybridVerifyResult => ({
    verified: false,
    reason,
    failed_algorithm: failedAlgorithm,
    checks,
  });

  // 1. Structure + profile marker.
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) return refuse(COMMIT_HYBRID_REASONS.MALFORMED_PROOF);
  const d = proof as Partial<CommitHybridProof>;
  if (d['@version'] !== COMMIT_HYBRID_PROFILE) return refuse(COMMIT_HYBRID_REASONS.UNKNOWN_PROFILE);
  if (!d.profile || typeof d.profile !== 'object' || Array.isArray(d.profile)) {
    return refuse(COMMIT_HYBRID_REASONS.MALFORMED_PROOF);
  }
  if (d.profile.id !== COMMIT_HYBRID_PROFILE) return refuse(COMMIT_HYBRID_REASONS.UNKNOWN_PROFILE);
  checks.profile = true;

  // 2. Committed algorithm set, exact and order-sensitive.
  if (!algorithmSetMatchesRegistered(d.profile.required_algorithms)) {
    checks.algorithm_set = false;
    return refuse(COMMIT_HYBRID_REASONS.ALGORITHM_SET_MISMATCH);
  }
  checks.algorithm_set = true;

  // 3. The proof must speak for the commit the verifier actually holds.
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    checks.payload_bound = false;
    return refuse(COMMIT_HYBRID_REASONS.PAYLOAD_MISMATCH);
  }
  let heldBytes: Buffer;
  try {
    heldBytes = commitHybridSignedBytes(payload, COMMIT_HYBRID_REQUIRED_ALGORITHMS);
  } catch {
    checks.payload_bound = false;
    return refuse(COMMIT_HYBRID_REASONS.PAYLOAD_MISMATCH);
  }
  let presentedBytes: Buffer | null = null;
  try {
    presentedBytes = d.payload && typeof d.payload === 'object' && !Array.isArray(d.payload)
      ? commitHybridSignedBytes(d.payload as Record<string, unknown>, COMMIT_HYBRID_REQUIRED_ALGORITHMS)
      : null;
  } catch {
    presentedBytes = null;
  }
  if (!presentedBytes || !presentedBytes.equals(heldBytes)) {
    checks.payload_bound = false;
    return refuse(COMMIT_HYBRID_REASONS.PAYLOAD_MISMATCH);
  }
  checks.payload_bound = true;

  // 4. Exactly one signature per required algorithm.
  if (!Array.isArray(d.signatures) || d.signatures.length === 0) {
    checks.legs_present = false;
    return refuse(COMMIT_HYBRID_REASONS.HYBRID_LEG_MISSING);
  }
  const presented = new Set<string>();
  for (const s of d.signatures) {
    if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
      checks.legs_present = false;
      return refuse(COMMIT_HYBRID_REASONS.MALFORMED_PROOF);
    }
    if (presented.has(s.alg)) {
      checks.legs_present = false;
      return refuse(COMMIT_HYBRID_REASONS.DUPLICATE_ALGORITHM, s.alg);
    }
    presented.add(s.alg);
  }
  for (const alg of COMMIT_HYBRID_REQUIRED_ALGORITHMS) {
    if (!presented.has(alg)) {
      checks.legs_present = false;
      return refuse(COMMIT_HYBRID_REASONS.HYBRID_LEG_MISSING, alg);
    }
  }
  for (const alg of presented) {
    if (!(COMMIT_HYBRID_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
      checks.legs_present = false;
      return refuse(COMMIT_HYBRID_REASONS.UNEXPECTED_ALGORITHM, alg);
    }
  }
  checks.legs_present = true;

  // 5. Delegate the set verdict to EP-SIG-AGILITY-v1.
  if (!keys || typeof keys !== 'object' || !keys.ed25519PublicKey || !keys.mldsaPublicKey) {
    return refuse(COMMIT_HYBRID_REASONS.MISSING_KEY);
  }
  const verificationKeys = [
    { alg: 'Ed25519', public_key: keys.ed25519PublicKey, ...(keys.ed25519KeyId ? { key_id: keys.ed25519KeyId } : {}) },
    { alg: 'ML-DSA-65', public_key: keys.mldsaPublicKey, ...(keys.mldsaKeyId ? { key_id: keys.mldsaKeyId } : {}) },
  ];

  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(heldBytes),
      d.signatures,
      verificationKeys,
      {
        ...passthrough(options),
        policy: 'hybrid_all',
        requiredAlgorithms: [...COMMIT_HYBRID_REQUIRED_ALGORITHMS],
      } as any,
    );
  } catch {
    // verifyAgileSignatureSet documents that it never throws; if an injected
    // backend makes it, that is still a refusal here, never a pass.
    checks.signatures_valid = false;
    return refuse(COMMIT_HYBRID_REASONS.SIGNATURE_INVALID);
  }

  if (setResult?.verified === true) {
    checks.signatures_valid = true;
    return { verified: true, reason: null, failed_algorithm: null, checks };
  }

  checks.signatures_valid = false;
  const failed = Array.isArray(setResult?.results)
    ? setResult.results.find((r) => r?.verified !== true) ?? null
    : null;
  const failedAlgorithm = failed?.alg ?? null;
  const rawReason = String(setResult?.reason ?? '');
  if (rawReason === 'missing_required_algorithm') {
    return refuse(COMMIT_HYBRID_REASONS.HYBRID_LEG_MISSING, failedAlgorithm);
  }
  if (rawReason.endsWith('pq_backend_unavailable') || failed?.reason === 'pq_backend_unavailable') {
    return refuse(COMMIT_HYBRID_REASONS.PQ_BACKEND_UNAVAILABLE, failedAlgorithm);
  }
  if (failed?.reason === 'malformed_key' || failed?.reason === 'algorithm_key_mismatch') {
    return refuse(COMMIT_HYBRID_REASONS.MISSING_KEY, failedAlgorithm);
  }
  return refuse(COMMIT_HYBRID_REASONS.SIGNATURE_INVALID, failedAlgorithm);
}

function passthrough(options: CommitHybridOptions): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (options.mldsaBackend !== undefined) out.mldsaBackend = options.mldsaBackend;
  if (options.mldsaBackendLoader !== undefined) out.mldsaBackendLoader = options.mldsaBackendLoader;
  return out;
}

const commitHybrid = {
  COMMIT_HYBRID_PROFILE,
  COMMIT_HYBRID_REQUIRED_ALGORITHMS,
  COMMIT_HYBRID_REASONS,
  commitHybridSignedMaterial,
  commitHybridSignedBytes,
  createCommitHybridProof,
  verifyCommitHybridProof,
};
export default commitHybrid;
