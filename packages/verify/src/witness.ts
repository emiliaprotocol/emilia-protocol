/**
 * @emilia-protocol/verify — WITNESS COSIGNATURE verification (EP-WITNESS-v1)
 *
 * Step 3 of the transparency layer (see docs/security/TRANSPARENCY-LAYER-DESIGN.md
 * and consistency.js). A transparency-log operator signs its own checkpoint
 * {tree_size, root_hash, log_key_id, ...}. A single operator signature does NOT
 * make a split view (equivocation) detectable: the operator can sign two
 * internally-consistent but divergent heads and show each to a different
 * verifier. An INDEPENDENT WITNESS re-signs the SAME committed checkpoint bytes.
 * When several independent witnesses each cosign whatever head they observed,
 * two verifiers who later gossip their witness cosignatures can detect that the
 * log presented divergent heads at the same tree_size.
 *
 * WHAT A WITNESS COSIGNATURE PROVES
 *   "I, witness <witness_id>, observed a checkpoint claiming this tree_size and
 *    this root_hash under this log_key_id, and I attest to having seen exactly
 *    these committed bytes."
 *
 * WHAT IT DOES *NOT* PROVE (honesty)
 *   - It does NOT vouch for the log's honesty or that the log is append-only. A
 *     witness signs the bytes it was shown; it does not re-derive the tree.
 *   - It does NOT establish CURRENT validity. A cosignature attests to a head as
 *     OBSERVED at cosign time only; currency needs a fresh signed head / online
 *     check, exactly as for the log's own signature.
 *   - A SINGLE witness detects nothing. Equivocation is only detectable when
 *     multiple INDEPENDENT witnesses cosign and their views are later compared
 *     (gossip). requireWitnessQuorum() enforces the "multiple distinct pinned
 *     witnesses agree on ONE head" half of that; cross-view gossip is the
 *     deployment's job.
 *
 * DOMAIN SEPARATION (critical)
 *   The log signs   Ed25519( null, SHA-256( canonicalize(signedCheckpoint) ) ).
 *   A witness signs  Ed25519( null, SHA-256( WITNESS_DOMAIN_TAG || canonicalize(signedCheckpoint) ) ).
 *   `signedCheckpoint` is the checkpoint with its own `log_signature` removed —
 *   i.e. the identical committed bytes the log signed. Prepending the domain tag
 *   to the pre-image means a witness cosignature and a log signature are
 *   computed over DIFFERENT bytes and can never be confused or replayed for one
 *   another, even if (by misconfiguration) the same key were pinned in both
 *   roles. Byte-identical convention used by witness/server.mjs.
 *
 * KEY / HASH ENCODING (matches index.js exactly)
 *   - Public keys: base64url-encoded SPKI DER, verified with crypto.verify(null,…).
 *   - Signatures:  base64url.
 *   - Hashes in the checkpoint: "sha256:<hex>" or bare hex; compared prefix-stripped.
 *
 * FAIL-CLOSED
 *   Every check refuses on missing / malformed / unrecognized input and never
 *   silently passes. An unknown or unpinned witness key refuses. A signature over
 *   different bytes refuses. A cosignature presented for a different checkpoint
 *   (different tree_size / root_hash / log_key_id than the one being verified)
 *   refuses. The k-of-n helper refuses on fewer than k DISTINCT pinned witnesses.
 *
 * This module imports canonicalize() from index.js so the witness and every other
 * signed-material computation in the package share one canonicalization source of
 * truth. It adds NO new canonicalization.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { canonicalize } from './index.js';
import {
  verifyAgileSignatureSet,
  signAgileSet,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  type AgilityOptions,
} from './pq-signature-agility.js';

export const WITNESS_VERSION = 'EP-WITNESS-v1';

/**
 * Domain-separation tag prepended to the SHA-256 pre-image a witness signs.
 * A UTF-8 label with a trailing 0x00 so it can never be a prefix of the
 * canonical JSON that follows (canonical JSON begins with '{' 0x7b, never 0x00).
 * The log's own signature has NO such prefix, so the two pre-images are disjoint.
 */
export const WITNESS_DOMAIN_TAG = 'EP-WITNESS-COSIGN-v1\0';

const HASH_PREFIX = /^sha256:/i;

export interface WitnessCheckpoint { tree_size?: unknown; root_hash?: unknown; log_key_id?: unknown; [key: string]: unknown }
export interface WitnessCosignature { witness_id?: unknown; signature?: unknown; alg?: unknown; tree_size?: unknown; root_hash?: unknown; log_key_id?: unknown; [key: string]: unknown }
export interface PinnedWitnessKey { witness_id?: unknown; public_key?: unknown; [key: string]: unknown }

function hexOf(h: unknown): string {
  return String(h || '').replace(HASH_PREFIX, '').toLowerCase();
}

// The committed bytes: the checkpoint the log signed, i.e. WITHOUT its own
// log_signature and WITHOUT any witness cosignature envelope fields. This is the
// same object the log ran through canonicalize() before signing (see
// verifyTrustReceipt step 5b in index.js). Deep-clone so we never mutate the
// caller's object.
function committedCheckpoint(checkpoint: unknown): Record<string, unknown> | null {
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) return null;
  const signed: Record<string, unknown> = { ...(checkpoint as Record<string, unknown>) };
  delete signed.log_signature;
  return signed;
}

// The exact bytes a witness signs / a verifier re-derives: the domain tag
// followed by the canonical committed checkpoint, then SHA-256'd to a 32-byte
// digest. Ed25519 is applied over this digest with crypto.verify(null, …),
// matching the log-signature convention in index.js (which signs the digest,
// not the message).
export function witnessSigningDigest(checkpoint: unknown): Buffer | null {
  const signed = committedCheckpoint(checkpoint);
  if (signed === null) return null;
  const preimage = Buffer.concat([
    Buffer.from(WITNESS_DOMAIN_TAG, 'utf8'),
    Buffer.from(canonicalize(signed), 'utf8'),
  ]);
  return crypto.createHash('sha256').update(preimage).digest();
}

function refuse(reason: string): { verified: false; witness_id: null; reason: string } {
  return { verified: false, witness_id: null, reason };
}

/**
 * Verify a single witness cosignature over a checkpoint.
 *
 * @param {object} checkpoint  the log checkpoint {tree_size, root_hash, log_key_id, ...}.
 *   May or may not still carry `log_signature` — it is stripped before hashing,
 *   so a witness cosignature is over the same committed bytes the log signed.
 * @param {object} cosignature  {
 *     witness_id: string,        // stable id of the cosigning witness
 *     signature: string,         // base64url Ed25519 over witnessSigningDigest(checkpoint)
 *     tree_size?: number,        // OPTIONAL echo of the head the witness cosigned
 *     root_hash?: string,        //   ... used to refuse a cosignature reused for a
 *     log_key_id?: string,       //   different checkpoint (fail-closed when echoed)
 *     alg?: string,              // OPTIONAL, must equal 'EP-WITNESS-v1' when present
 *   }
 * @param {{witness_id: string, public_key: string}} pinnedWitnessKey  the ONE
 *   witness the caller trusts for this cosignature: a stable witness_id plus its
 *   base64url SPKI-DER Ed25519 public key. An unknown / unpinned witness refuses.
 * @returns {{verified: boolean, witness_id: string|null, reason?: string}}
 */
export function verifyWitnessCosignature(checkpoint: WitnessCheckpoint | null | undefined, cosignature: WitnessCosignature | null | undefined, pinnedWitnessKey: PinnedWitnessKey | null | undefined): { verified: boolean; witness_id: string | null; reason?: string } {
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) {
    return refuse('checkpoint is missing or not an object');
  }
  if (!cosignature || typeof cosignature !== 'object' || Array.isArray(cosignature)) {
    return refuse('cosignature is missing or not an object');
  }
  if (!pinnedWitnessKey || typeof pinnedWitnessKey !== 'object') {
    return refuse('pinnedWitnessKey is missing');
  }

  const pinnedId = pinnedWitnessKey.witness_id;
  const pinnedPub = pinnedWitnessKey.public_key;
  if (typeof pinnedId !== 'string' || !pinnedId) {
    return refuse('pinnedWitnessKey.witness_id is missing');
  }
  if (typeof pinnedPub !== 'string' || !pinnedPub) {
    return refuse('pinnedWitnessKey.public_key is missing');
  }

  const coId = cosignature.witness_id;
  if (typeof coId !== 'string' || !coId) {
    return refuse('cosignature.witness_id is missing');
  }
  // Unknown / unpinned witness: the cosignature names a witness we do not trust.
  if (coId !== pinnedId) {
    return refuse('cosignature witness_id is not the pinned witness (unpinned witness refused)');
  }

  if (cosignature.alg !== undefined && cosignature.alg !== WITNESS_VERSION) {
    return refuse(`cosignature alg must be ${WITNESS_VERSION} when present`);
  }

  if (typeof cosignature.signature !== 'string' || !cosignature.signature) {
    return refuse('cosignature.signature is missing');
  }

  // A cosignature carrying an echoed head must match the checkpoint being
  // verified; this refuses a cosignature lifted from a DIFFERENT checkpoint even
  // before the crypto runs. Each echoed field is fail-closed: present-and-wrong
  // refuses (absent is allowed, since the signed digest already binds all bytes).
  if (cosignature.tree_size !== undefined && cosignature.tree_size !== checkpoint.tree_size) {
    return refuse('cosignature tree_size does not match the checkpoint (cosignature for a different head)');
  }
  if (cosignature.root_hash !== undefined && hexOf(cosignature.root_hash) !== hexOf(checkpoint.root_hash)) {
    return refuse('cosignature root_hash does not match the checkpoint (cosignature for a different head)');
  }
  if (cosignature.log_key_id !== undefined && cosignature.log_key_id !== checkpoint.log_key_id) {
    return refuse('cosignature log_key_id does not match the checkpoint (cosignature for a different log)');
  }

  const digest = witnessSigningDigest(checkpoint);
  if (digest === null) return refuse('checkpoint could not be canonicalized');

  let ok = false;
  try {
    const keyObject = crypto.createPublicKey({
      key: Buffer.from(pinnedPub, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    ok = crypto.verify(null, digest, keyObject, Buffer.from(cosignature.signature, 'base64url'));
  } catch (e) {
    return refuse(`cosignature verification failed: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (!ok) {
    // Signature is over different bytes (tampered checkpoint) or a wrong key.
    return refuse('cosignature does not verify over the checkpoint committed bytes');
  }
  return { verified: true, witness_id: coId };
}

/**
 * Require >= k DISTINCT pinned witnesses to have validly cosigned the SAME head.
 *
 * Detects the "not enough independent observers agree on one head" condition:
 * accepts iff at least `k` cosignatures verify, each from a DIFFERENT pinned
 * witness_id, all over the ONE checkpoint passed in. Duplicate witness_ids count
 * ONCE (a single witness cannot satisfy a k-of-n threshold by cosigning twice).
 * Cosignatures that fail verification, name an unpinned witness, or reference a
 * different head are ignored (they do not count toward k) and recorded in
 * `reasons` for diagnostics.
 *
 * HONESTY: this proves k distinct trusted witnesses attest to ONE head. It does
 * NOT by itself detect that the log showed a DIFFERENT head to someone else —
 * that cross-view comparison (gossip) is the deployment's responsibility. This
 * helper is the local, single-view half of the check.
 *
 * @param {object} checkpoint  the ONE checkpoint head all witnesses must have cosigned.
 * @param {object[]} cosignatures  candidate witness cosignatures (see verifyWitnessCosignature).
 * @param {Array<{witness_id:string, public_key:string}>} pinnedWitnessKeys  the set of
 *   trusted witnesses. Entries with a duplicate or missing witness_id are dropped.
 * @param {number} k  threshold; must be an integer >= 1.
 * @returns {{ ok: boolean, met: number, required: number,
 *   witness_ids: string[], reasons: string[] }}
 *   `met` is the number of DISTINCT pinned witnesses that validly cosigned this
 *   head; `witness_ids` lists them. Fail-closed: bad inputs return ok:false.
 */
export function requireWitnessQuorum(checkpoint: WitnessCheckpoint | null | undefined, cosignatures: unknown, pinnedWitnessKeys: unknown, k: number) {
  const reasons: string[] = [];
  const empty = { ok: false, met: 0, required: 0, witness_ids: [] as string[], reasons };

  if (!Number.isInteger(k) || k < 1) {
    reasons.push('k must be an integer >= 1');
    return { ...empty, required: typeof k === 'number' ? k : 0 };
  }
  empty.required = k;
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) {
    reasons.push('checkpoint is missing or not an object');
    return { ok: false, met: 0, required: k, witness_ids: [], reasons };
  }
  if (!Array.isArray(cosignatures)) {
    reasons.push('cosignatures must be an array');
    return { ok: false, met: 0, required: k, witness_ids: [], reasons };
  }
  if (!Array.isArray(pinnedWitnessKeys)) {
    reasons.push('pinnedWitnessKeys must be an array');
    return { ok: false, met: 0, required: k, witness_ids: [], reasons };
  }

  // Build the pinned-witness directory. A duplicated witness_id across pinned
  // entries is ambiguous (which key is authoritative?), so it is dropped rather
  // than trusted — fail-closed.
  const pinnedById = new Map<string, PinnedWitnessKey>();
  const seenPinned = new Set<string>();
  const dupPinned = new Set<string>();
  for (const w of pinnedWitnessKeys as unknown[]) {
    const id = w && typeof w === 'object' ? (w as Record<string, unknown>).witness_id : undefined;
    if (typeof id !== 'string' || !id) {
      reasons.push('a pinned witness entry is missing witness_id (dropped)');
      continue;
    }
    if (seenPinned.has(id)) {
      dupPinned.add(id);
      continue;
    }
    seenPinned.add(id);
    pinnedById.set(id, w as PinnedWitnessKey);
  }
  for (const id of dupPinned) {
    pinnedById.delete(id);
    reasons.push(`pinned witness_id "${id}" appears more than once (dropped as ambiguous)`);
  }

  // Count DISTINCT pinned witnesses whose cosignature over THIS head verifies.
  const met = new Set<string>();
  for (const cosig of cosignatures as unknown[]) {
    const id = cosig && typeof cosig === 'object' ? (cosig as Record<string, unknown>).witness_id : undefined;
    if (typeof id !== 'string' || !id) {
      reasons.push('a cosignature is missing witness_id (ignored)');
      continue;
    }
    if (met.has(id)) {
      // Duplicate witness_id among cosignatures: already counted once; a witness
      // cannot boost the tally by cosigning twice.
      reasons.push(`duplicate cosignature from witness "${id}" (counted once)`);
      continue;
    }
    const pinned = pinnedById.get(id);
    if (!pinned) {
      reasons.push(`cosignature from unpinned witness "${id}" (ignored)`);
      continue;
    }
    const res = verifyWitnessCosignature(checkpoint, cosig as WitnessCosignature, pinned);
    if (res.verified) {
      if (res.witness_id !== null) met.add(res.witness_id);
    } else {
      reasons.push(`cosignature from "${id}" did not verify: ${res.reason}`);
    }
  }

  const witness_ids = [...met].sort();
  return {
    ok: met.size >= k,
    met: met.size,
    required: k,
    witness_ids,
    reasons,
  };
}

// ===========================================================================
// EP-WITNESS-v2 -- the hybrid (Ed25519 + ML-DSA-65) witness cosignature
// ===========================================================================
/**
 * Applies the EP-REVOCATION-v2 template (packages/verify/src/revocation.ts)
 * to the witness cosignature. Five moving parts, in order:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the cosignature (`signature` string -> `signatures` array), which is a
 *    wire-format change, so it takes a new `alg` marker (EP-WITNESS-v1 ->
 *    EP-WITNESS-v2) rather than an optional field grown on v1. The v1
 *    verifier, verifyWitnessCosignature() above, is untouched and refuses a
 *    v2 cosignature TWO independent ways before any crypto runs: its own
 *    `cosignature.alg !== undefined && cosignature.alg !== WITNESS_VERSION`
 *    check refuses on the alg marker, and its
 *    `typeof cosignature.signature !== 'string'` check refuses on shape,
 *    because a v2 cosignature carries `signatures` (plural) and has no
 *    top-level `signature` string at all. A deployed v1 verifier must never
 *    accept a hybrid cosignature on the strength of the one leg it happens to
 *    understand, and it must not crash; both guards above are what make that
 *    true, independently of each other.
 *
 * 2. SET SHAPE. The v2 cosignature is `{witness_id, alg: WITNESS_V2_VERSION,
 *    required_algorithms: [...], signatures: [{alg,sig,key_id?}, ...],
 *    tree_size?, root_hash?, log_key_id?}` -- `signatures` mirrors
 *    EP-SIG-AGILITY-v1's AgileSignature shape verbatim, one entry per
 *    algorithm, in the registered order. Unlike EP-REVOCATION-v2, the v2
 *    cosignature carries NO per-leg key material of its own: exactly like
 *    v1, a witness's keys (both the Ed25519 half and, now, the ML-DSA-65
 *    half) are pinned entirely out of band via pinnedWitnessKeyV2, never
 *    self-asserted in the cosignature.
 *
 * 3. ANTI-STRIPPING BYTES. witnessSigningDigestV2() is the sibling of
 *    witnessSigningDigest() above: it hashes a NEW, distinct domain tag
 *    (WITNESS_DOMAIN_TAG_V2) prepended to canonicalize(committed checkpoint +
 *    required_algorithms), so a v1 digest and a v2 digest can never collide
 *    even for byte-identical checkpoints, and the required algorithm SET is
 *    baked into what both legs sign. Narrow the set or strip a leg after
 *    signing and the surviving signature no longer verifies, because the
 *    bytes changed. The verifier always recomputes this digest from the
 *    REGISTERED set (WITNESS_V2_REQUIRED_ALGORITHMS) and the checkpoint it
 *    holds -- never from cosignature.required_algorithms, which is checked
 *    structurally but never trusted for what bytes to verify against.
 *
 * 4. V1 COMPATIBILITY. v1 stays synchronous and completely unmodified.
 *    verifyWitnessCosignatureV2() is a separate, ASYNC entry point (ML-DSA
 *    verification is async), and verifyWitnessCosignatureStatement() routes a
 *    cosignature of either version to its own verifier by inspecting `alg`,
 *    mirroring verifyRevocationStatement().
 *
 * 5. NAMED REFUSALS. verifyWitnessCosignatureV2() returns
 *    {verified, witness_id, reason?} like v1, extended with a
 *    `checks: Record<string,boolean>` object covering the independent gates
 *    (version, algorithm_set, legs_present, key_material,
 *    echoed_head_consistent, signature_set_valid). Nothing throws on
 *    cosignature/checkpoint/key content; crypto calls are wrapped in
 *    try/catch. A missing or unavailable ML-DSA backend surfaces through
 *    verifyAgileSignatureSet's 'pq_backend_unavailable' reason as a named
 *    refusal on signature_set_valid, never a silent pass on the classical leg
 *    alone.
 *
 * HONEST BOUNDARIES. Everything the v1 header says still holds: a v2
 * cosignature proves the witness observed exactly these committed bytes; it
 * does not vouch for the log's honesty, does not establish current validity,
 * and a single witness (of either version) detects no equivocation --
 * requireWitnessQuorum() is deliberately left v1-only and out of scope here
 * (multiple DISTINCT witnesses, not multiple algorithms from one witness).
 */

export const WITNESS_V2_VERSION = 'EP-WITNESS-v2';

/** The registered required algorithm set, in canonical order. */
export const WITNESS_V2_REQUIRED_ALGORITHMS = Object.freeze(['Ed25519', 'ML-DSA-65'] as const);

/**
 * Domain-separation tag for EP-WITNESS-v2, distinct from WITNESS_DOMAIN_TAG
 * (v1) so a v1 and v2 digest over the same checkpoint can never collide, even
 * by misconfiguration. Same trailing-0x00 convention as v1: canonical JSON
 * always begins with '{' (0x7b), never 0x00, so the tag can never be a prefix
 * of the JSON that follows.
 */
export const WITNESS_DOMAIN_TAG_V2 = 'EP-WITNESS-COSIGN-v2\0';

export interface WitnessV2Signature { alg?: unknown; sig?: unknown; key_id?: unknown; }
export interface WitnessCosignatureV2 {
  witness_id?: unknown;
  alg?: unknown;
  required_algorithms?: unknown;
  signatures?: unknown;
  tree_size?: unknown;
  root_hash?: unknown;
  log_key_id?: unknown;
  [key: string]: unknown;
}

/** A v2 witness pin: BOTH public halves, pinned out of band. */
export interface PinnedWitnessKeyV2 {
  witness_id?: unknown;
  /** Ed25519 base64url SPKI DER. */
  public_key?: unknown;
  /** ML-DSA-65 base64url of the raw 1952-byte public key. */
  pq_public_key?: unknown;
  [key: string]: unknown;
}

export interface WitnessVerifyV2Result {
  verified: boolean;
  witness_id: string | null;
  reason?: string;
  checks: Record<string, boolean>;
}

function witnessAlgorithmSetMatchesRegistered(algorithms: unknown): algorithms is string[] {
  return Array.isArray(algorithms)
    && algorithms.length === WITNESS_V2_REQUIRED_ALGORITHMS.length
    && algorithms.every((a, i) => a === WITNESS_V2_REQUIRED_ALGORITHMS[i]);
}

/**
 * The digest BOTH legs sign for EP-WITNESS-v2: SHA-256 of the v2 domain tag
 * followed by canonicalize(committed checkpoint + required_algorithms), so
 * the algorithm set is cryptographically committed alongside the checkpoint
 * bytes. Recomputed independently by the verifier from the checkpoint it
 * holds and the REGISTERED set -- never from a presented one. Throws if
 * `requiredAlgorithms` is not exactly the registered EP-WITNESS-v2 set
 * (mirrors revocationV2SignedPayload's guard); pass the registered constant
 * itself when reconstructing bytes for comparison against a narrowed claim.
 */
export function witnessSigningDigestV2(
  checkpoint: unknown,
  requiredAlgorithms: readonly string[] = WITNESS_V2_REQUIRED_ALGORITHMS,
): Buffer | null {
  if (!witnessAlgorithmSetMatchesRegistered(requiredAlgorithms)) {
    throw new Error('witnessSigningDigestV2: algorithm set is not the registered EP-WITNESS-v2 set');
  }
  const signed = committedCheckpoint(checkpoint);
  if (signed === null) return null;
  const preimage = Buffer.concat([
    Buffer.from(WITNESS_DOMAIN_TAG_V2, 'utf8'),
    Buffer.from(canonicalize({ ...signed, required_algorithms: [...requiredAlgorithms] }), 'utf8'),
  ]);
  return crypto.createHash('sha256').update(preimage).digest();
}

/**
 * verifyWitnessCosignatureV2 -- FAIL-CLOSED hybrid witness check. Never
 * throws on caller input. Every gating check must be true; any one false
 * yields verified:false, and a v2 cosignature NEVER verifies on one leg
 * alone.
 */
export async function verifyWitnessCosignatureV2(
  checkpoint: WitnessCheckpoint | null | undefined,
  cosignature: WitnessCosignatureV2 | null | undefined,
  pinnedWitnessKeyV2: PinnedWitnessKeyV2 | null | undefined,
  options: AgilityOptions = {},
): Promise<WitnessVerifyV2Result> {
  const checks: Record<string, boolean> = {
    version: true,
    algorithm_set: true,
    legs_present: true,
    key_material: true,
    echoed_head_consistent: true,
    signature_set_valid: true,
  };
  const errors: string[] = [];
  const fail = (key: string, msg: string): void => { checks[key] = false; errors.push(msg); };
  const done = (witnessId: string | null): WitnessVerifyV2Result => {
    const verified = Object.values(checks).every(Boolean);
    const result: WitnessVerifyV2Result = { verified, witness_id: verified ? witnessId : null, checks };
    if (errors.length > 0) result.reason = errors.join(' | ');
    return result;
  };

  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) {
    fail('echoed_head_consistent', 'checkpoint is missing or not an object');
    fail('signature_set_valid', 'checkpoint is missing or not an object');
    return done(null);
  }
  if (!cosignature || typeof cosignature !== 'object' || Array.isArray(cosignature)) {
    fail('legs_present', 'cosignature is missing or not an object');
    fail('signature_set_valid', 'cosignature is missing or not an object');
    return done(null);
  }
  if (!pinnedWitnessKeyV2 || typeof pinnedWitnessKeyV2 !== 'object') {
    fail('key_material', 'pinnedWitnessKeyV2 is missing');
    fail('signature_set_valid', 'pinnedWitnessKeyV2 is missing');
    return done(null);
  }

  // 1. Version marker. A v1 cosignature handed to the v2 verifier refuses
  //    here, the mirror image of v1 refusing a v2 cosignature.
  if (cosignature.alg !== WITNESS_V2_VERSION) {
    fail('version', `unsupported version: ${String(cosignature.alg)} (expected ${WITNESS_V2_VERSION})`);
  }

  // 2. Witness pin: identified-but-not-trusted. BOTH halves must be pinned
  //    out of band, and the cosignature must name the pinned witness_id. The
  //    cosignature carries no key material of its own to substitute.
  const pinnedId = pinnedWitnessKeyV2.witness_id;
  const pinnedEdPub = pinnedWitnessKeyV2.public_key;
  const pinnedPqPub = pinnedWitnessKeyV2.pq_public_key;
  const coId = cosignature.witness_id;
  if (typeof pinnedId !== 'string' || !pinnedId
    || typeof pinnedEdPub !== 'string' || !pinnedEdPub
    || typeof pinnedPqPub !== 'string' || !pinnedPqPub) {
    fail('key_material', 'pinnedWitnessKeyV2 requires witness_id, public_key (Ed25519), and pq_public_key (ML-DSA-65)');
  } else if (typeof coId !== 'string' || !coId) {
    fail('key_material', 'cosignature.witness_id is missing');
  } else if (coId !== pinnedId) {
    fail('key_material', 'cosignature witness_id is not the pinned witness (unpinned witness refused)');
  }
  const edKeyMaterial: string = typeof pinnedEdPub === 'string' ? pinnedEdPub : '';
  const pqKeyMaterial: string = typeof pinnedPqPub === 'string' ? pinnedPqPub : '';
  const witnessId = typeof coId === 'string' && coId ? coId : null;

  // 3. Committed algorithm set: exact and order-sensitive. A narrowed set is
  //    the stripping attack's cover story, refused structurally here and
  //    (independently) by the signature check, which rebuilds the digest
  //    from the REGISTERED set regardless of what the cosignature claims.
  if (!witnessAlgorithmSetMatchesRegistered(cosignature.required_algorithms)) {
    fail('algorithm_set',
      `required_algorithms must be exactly ${JSON.stringify([...WITNESS_V2_REQUIRED_ALGORITHMS])} (set narrowing / widening refused)`);
  }

  // 4. Exactly one signature per required algorithm.
  const signatures = Array.isArray(cosignature.signatures) ? cosignature.signatures as WitnessV2Signature[] : null;
  if (!signatures || signatures.length === 0) {
    fail('legs_present', 'cosignature.signatures must carry one signature per required algorithm');
  } else {
    const presented = new Set<string>();
    let malformed = false;
    for (const s of signatures) {
      if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.alg !== 'string' || typeof s.sig !== 'string') {
        fail('legs_present', 'each cosignature.signatures entry must be { alg, sig, key_id? }');
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
      for (const alg of WITNESS_V2_REQUIRED_ALGORITHMS) {
        if (!presented.has(alg)) fail('legs_present', `missing required ${alg} signature (leg stripped)`);
      }
      for (const alg of presented) {
        if (!(WITNESS_V2_REQUIRED_ALGORITHMS as readonly string[]).includes(alg)) {
          fail('legs_present', `unexpected algorithm "${alg}" outside the registered set`);
        }
      }
    }
  }

  // 5. Echoed-head consistency: identical to v1's guard, so a cosignature
  //    lifted for a DIFFERENT checkpoint refuses before the crypto runs. Each
  //    echoed field is fail-closed: present-and-wrong refuses; absent is
  //    allowed since the signed digest already binds all bytes.
  if (cosignature.tree_size !== undefined && cosignature.tree_size !== checkpoint.tree_size) {
    fail('echoed_head_consistent', 'cosignature tree_size does not match the checkpoint (cosignature for a different head)');
  }
  if (cosignature.root_hash !== undefined && hexOf(cosignature.root_hash) !== hexOf(checkpoint.root_hash)) {
    fail('echoed_head_consistent', 'cosignature root_hash does not match the checkpoint (cosignature for a different head)');
  }
  if (cosignature.log_key_id !== undefined && cosignature.log_key_id !== checkpoint.log_key_id) {
    fail('echoed_head_consistent', 'cosignature log_key_id does not match the checkpoint (cosignature for a different log)');
  }

  // 6. Signature set: both legs, over the digest rebuilt from the checkpoint
  //    the verifier holds and the REGISTERED algorithm set, under the PINNED
  //    keys only -- never a cosignature-supplied key (there is none) and
  //    never the cosignature's own required_algorithms.
  let digest: Buffer | null = null;
  try {
    digest = witnessSigningDigestV2(checkpoint, WITNESS_V2_REQUIRED_ALGORITHMS);
  } catch {
    digest = null;
  }
  if (!digest) {
    fail('signature_set_valid', 'checkpoint could not be canonicalized');
    return done(witnessId);
  }
  const verificationKeys = [
    { alg: 'Ed25519', public_key: edKeyMaterial },
    { alg: 'ML-DSA-65', public_key: pqKeyMaterial },
  ];
  let setResult;
  try {
    setResult = await verifyAgileSignatureSet(
      new Uint8Array(digest),
      signatures ?? [],
      verificationKeys,
      { ...options, policy: 'hybrid_all', requiredAlgorithms: [...WITNESS_V2_REQUIRED_ALGORITHMS] },
    );
  } catch {
    // verifyAgileSignatureSet documents that it never throws; an injected
    // backend that does is still a refusal here, never a pass.
    setResult = null;
  }
  if (setResult?.verified !== true) {
    const reason = String(setResult?.reason ?? 'signature_set_unverified');
    fail('signature_set_valid',
      `witness signature set does not verify under the pinned Ed25519 + ML-DSA-65 keys (${reason})`);
  }

  return done(witnessId);
}

/**
 * Route a cosignature of EITHER version to its own verifier. v1 cosignatures
 * get the exact v1 verdict (sync, called through this async wrapper); v2
 * cosignatures get the hybrid check. `pinnedWitnessKeyV2` carries both halves
 * ({witness_id, public_key, pq_public_key}); its {witness_id, public_key}
 * shape is exactly what the v1 verifier expects, so it is reused as-is for
 * the v1 path without a second pin object.
 */
export async function verifyWitnessCosignatureStatement(
  checkpoint: WitnessCheckpoint | null | undefined,
  cosignature: WitnessCosignature | WitnessCosignatureV2 | null | undefined,
  pinnedWitnessKeyV2: PinnedWitnessKeyV2 | null | undefined,
  options: AgilityOptions = {},
): Promise<WitnessVerifyV2Result | { verified: boolean; witness_id: string | null; reason?: string }> {
  if (cosignature && typeof cosignature === 'object' && !Array.isArray(cosignature)
    && (cosignature as WitnessCosignatureV2).alg === WITNESS_V2_VERSION) {
    return verifyWitnessCosignatureV2(checkpoint, cosignature as WitnessCosignatureV2, pinnedWitnessKeyV2, options);
  }
  return verifyWitnessCosignature(checkpoint, cosignature as WitnessCosignature, pinnedWitnessKeyV2 as PinnedWitnessKey);
}

// -- issuer side (witness node) ----------------------------------------------

export interface WitnessV2Signer {
  /** Ed25519 private key. */
  privateKey: import('crypto').KeyObject;
  /** Ed25519 public key, base64url SPKI DER. */
  publicKeyB64u: string;
  /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
  pqSecretKey: Uint8Array | string;
  /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
  pqPublicKeyB64u: Uint8Array | string;
}

export interface BuildWitnessCosignatureV2Args {
  checkpoint: WitnessCheckpoint;
  witness_id: string;
  signer: WitnessV2Signer;
  /** ML-DSA-65 FIPS 204 deterministic variant; conformance vectors only. */
  deterministic?: boolean;
}

function toRawB64u(value: Uint8Array | string, expectedLength: number, label: string): string {
  const bytes = value instanceof Uint8Array
    ? Buffer.from(value)
    : (/^[A-Za-z0-9_-]+$/.test(String(value)) ? Buffer.from(String(value), 'base64url') : Buffer.alloc(0));
  if (bytes.length !== expectedLength) {
    throw new Error(`buildWitnessCosignatureV2: ${label} must be ${expectedLength} raw bytes (or base64url of them)`);
  }
  return bytes.toString('base64url');
}

/**
 * buildWitnessCosignatureV2 -- produce an EP-WITNESS-v2 cosignature over
 * `checkpoint`, signed under BOTH registered algorithms over the ONE digest
 * that COMMITS to the required algorithm set (witnessSigningDigestV2).
 *
 * THROWS rather than emit a half-hybrid cosignature: issuer-side misuse is a
 * programming error, and an unavailable ML-DSA backend makes signAgileSet
 * throw, so a cosignature missing the PQ leg is never produced.
 */
export async function buildWitnessCosignatureV2({
  checkpoint,
  witness_id: witnessId,
  signer,
  deterministic = false,
}: BuildWitnessCosignatureV2Args): Promise<WitnessCosignatureV2> {
  if (!checkpoint || typeof checkpoint !== 'object' || Array.isArray(checkpoint)) {
    throw new Error('buildWitnessCosignatureV2 requires a checkpoint object');
  }
  if (typeof witnessId !== 'string' || witnessId.length === 0) {
    throw new Error('buildWitnessCosignatureV2 requires witness_id');
  }
  if (!signer || !signer.privateKey || !signer.publicKeyB64u || !signer.pqSecretKey || !signer.pqPublicKeyB64u) {
    throw new Error('buildWitnessCosignatureV2 requires signer.{privateKey,publicKeyB64u,pqSecretKey,pqPublicKeyB64u}');
  }
  if (signer.privateKey.type !== 'private' || signer.privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('buildWitnessCosignatureV2 requires signer.privateKey to be an Ed25519 private KeyObject');
  }
  try {
    const edPub = crypto.createPublicKey({
      key: Buffer.from(String(signer.publicKeyB64u), 'base64url'),
      format: 'der',
      type: 'spki',
    });
    if (edPub.asymmetricKeyType !== 'ed25519') throw new Error('not ed25519');
  } catch {
    throw new Error('buildWitnessCosignatureV2 requires signer.publicKeyB64u to be a valid base64url Ed25519 SPKI public key');
  }
  // Validates length (and base64url shape); the value itself is not carried
  // in the wire cosignature -- witness keys are pinned out of band.
  toRawB64u(signer.pqPublicKeyB64u, ML_DSA_65_PUBLIC_KEY_BYTES, 'signer.pqPublicKeyB64u');
  const pqSecretB64u = toRawB64u(signer.pqSecretKey, ML_DSA_65_SECRET_KEY_BYTES, 'signer.pqSecretKey');

  const digest = witnessSigningDigestV2(checkpoint, WITNESS_V2_REQUIRED_ALGORITHMS);
  if (digest === null) throw new Error('buildWitnessCosignatureV2: checkpoint could not be canonicalized');

  const signatures = await signAgileSet(
    new Uint8Array(digest),
    [
      { alg: 'Ed25519', private_key: signer.privateKey },
      { alg: 'ML-DSA-65', private_key: pqSecretB64u },
    ],
    deterministic === true ? { deterministic: true } : {},
  );

  // Emit in the registered order, so the document reads the way the digest commits.
  const byAlg = new Map(signatures.map((s) => [s.alg, s]));
  const ordered = WITNESS_V2_REQUIRED_ALGORITHMS.map((alg) => {
    const s = byAlg.get(alg);
    if (!s) throw new Error(`buildWitnessCosignatureV2: signing produced no ${alg} leg`);
    return s;
  });

  const out: WitnessCosignatureV2 = {
    witness_id: witnessId,
    alg: WITNESS_V2_VERSION,
    required_algorithms: [...WITNESS_V2_REQUIRED_ALGORITHMS],
    signatures: ordered,
  };
  if (checkpoint.tree_size !== undefined) out.tree_size = checkpoint.tree_size;
  if (checkpoint.root_hash !== undefined) out.root_hash = checkpoint.root_hash;
  if (checkpoint.log_key_id !== undefined) out.log_key_id = checkpoint.log_key_id;
  return out;
}
