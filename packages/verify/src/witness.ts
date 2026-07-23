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
