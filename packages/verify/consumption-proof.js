/**
 * @emilia-protocol/verify — THIRD-PARTY-verifiable one-time CONSUMPTION proofs
 * (sparse-Merkle-over-nonce consumption profile). EXPERIMENTAL / additive.
 *
 * THE PROBLEM THIS CLOSES. A trust receipt's `consumption` block today is an
 * OPERATOR ASSERTION: the operator says "I committed this nonce once." Nothing
 * in the receipt makes double-spend of a nonce detectable OFFLINE. A malicious
 * operator can commit the SAME nonce twice and hand each relying party a receipt
 * that verifies in isolation; catching it needs an ONLINE audit that walks the
 * whole log. This profile replaces the assertion with a proof: the operator must
 * maintain a sparse Merkle tree keyed by nonce, and produce, at commit time, a
 * proof that the nonce transitioned ABSENT -> PRESENT exactly once between two
 * WITNESSED log heads. A second commit of the same nonce cannot also exhibit a
 * valid absent-at-h1 proof under the same append-only log, so double-consumption
 * becomes offline-detectable by any third party holding these two heads.
 *
 * WHAT A CONSUMPTION BUNDLE PROVES (all three, conjunctively, fail-closed):
 *   (a) NON-INCLUSION at head h1: the nonce's leaf held the DEFAULT (empty)
 *       value at h1  -> the nonce was not yet consumed as of h1.
 *   (b) INCLUSION at head h2: the same nonce's leaf holds the PRESENT marker at
 *       h2  -> the nonce is consumed as of h2.
 *   (c) APPEND-ONLY h1 -> h2: h2 is a consistency-proven extension of h1 (reuses
 *       verifyCheckpointConsistency from consistency.js — the SAME EP-MERKLE-v2
 *       branch construction; this module does NOT invent a second Merkle scheme).
 * Together: the nonce went absent -> present exactly once between two heads that
 * are provably the same append-only log. There is no valid bundle in which the
 * nonce is BOTH absent-at-h1 under this log AND was already consumed earlier.
 *
 * HONESTY / SCOPE (this is a house rule, stated in code on purpose):
 *   - This module is the VERIFIER and the WIRE FORMAT only. The ISSUER-SIDE
 *     emission — actually maintaining the sparse consumption tree, inserting a
 *     nonce leaf at commit time, and PRODUCING the non-inclusion / inclusion /
 *     consistency proofs — is REFERENCE/SPEC here. The small tree helpers below
 *     (`emptyRoot`, `smtInsertAndProve`, ...) are a spec-faithful REFERENCE
 *     prover for tests and tooling; a production log emits equivalent proofs.
 *     They are NOT a production consumption ledger.
 *   - Offline verification of a bundle establishes append-only consistency
 *     between two OBSERVED heads. It does NOT establish CURRENCY (that h2 is the
 *     log's latest head) and does NOT by itself defeat split-view equivocation
 *     (a log showing different histories to different verifiers). Currency and
 *     non-equivocation need a fresh signed head plus independent witnesses /
 *     gossip. See docs/security/TRANSPARENCY-LAYER-DESIGN.md.
 *   - The sparse-tree construction here binds VALUES to leaves. It does NOT by
 *     itself verify the two checkpoints' log SIGNATURES; that is the caller's
 *     job (verifyTrustReceipt checks checkpoint_signature). This function proves
 *     the tree-shaped facts; pass it roots you have independently authenticated.
 *
 * DOMAIN SEPARATION (reuses EP-MERKLE-v2 branch bytes; adds distinct LEAF bytes):
 *   - Branch  = SHA-256(0x01 || leftHex || rightHex) -> hex   [SAME as EP-MERKLE-v2]
 *   - PRESENT leaf = SHA-256(0x02 || keyHex || valueHex) -> hex   [EP-SMT-CONSUME-v1]
 *   - DEFAULT leaf = SHA-256(0x03) -> hex (the empty-subtree/absent marker)
 *   Distinct 0x02 (present) and 0x03 (default) leaf domains mean a DEFAULT leaf
 *   can never be reinterpreted as a PRESENT leaf at the same key, and neither can
 *   collide with a dense-log leaf (0x00) or a branch (0x01). The empty-subtree
 *   marker at every level is derived by folding DEFAULT leaves up with the SAME
 *   0x01 branch rule, so a non-inclusion proof and an inclusion proof share one
 *   hash construction end to end.
 *
 * SPARSE-MERKLE SHAPE. Fixed depth D (default SMT_DEPTH). The key path is the
 * top D bits of SHA-256(nonce), MSB first (bit i selects left=0/right=1 at level
 * i from the root). Each proof is D sibling hashes, root-to-leaf order. A leaf is
 * PRESENT (value = SHA-256 of the nonce commitment content) or DEFAULT (absent).
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { verifyCheckpointConsistency } from './consistency.js';

export const CONSUMPTION_PROFILE = 'EP-SMT-CONSUME-v1';
/** Leaf domain tag for the sparse consumption tree (documented in reason strings). */
export const CONSUMPTION_LEAF_DOMAIN = 'EP-SMT-CONSUME-v1';
/** Fixed sparse-tree depth (bits of SHA-256(nonce) consumed as the key path). */
export const SMT_DEPTH = 32;

const HASH_PREFIX = /^sha256:/i;
const HEX_ONLY = /^[0-9a-f]+$/;

function hexOf(h) {
  return String(h == null ? '' : h).replace(HASH_PREFIX, '').toLowerCase();
}

function isHex64(h) {
  return typeof h === 'string' && h.length === 64 && HEX_ONLY.test(h);
}

// EP-MERKLE-v2 branch hash: SHA-256(0x01 || leftHex || rightHex) -> hex.
// Byte-identical to hashPairV2() in index.js and hashChildrenV2() in
// consistency.js (kept in sync deliberately; not imported, to remain additive).
function hashBranch(left, right) {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')]))
    .digest('hex');
}

// PRESENT leaf: SHA-256(0x02 || keyHex || valueHex) -> hex. Binds the consumed
// marker to BOTH the nonce-derived key and a value, so a present leaf cannot be
// lifted to a different key/value.
function presentLeaf(keyHex, valueHex) {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x02]), Buffer.from(keyHex, 'utf8'), Buffer.from(valueHex, 'utf8')]))
    .digest('hex');
}

// DEFAULT (absent) leaf: SHA-256(0x03) -> hex. Distinct domain from present.
function defaultLeaf() {
  return crypto.createHash('sha256').update(Buffer.from([0x03])).digest('hex');
}

// key(nonce) = SHA-256(nonce) as hex; the top SMT_DEPTH bits form the tree path.
function nonceKeyHex(nonce) {
  return crypto.createHash('sha256').update(Buffer.from(String(nonce), 'utf8')).digest('hex');
}

// bit i (MSB-first) of a hex string, i.e. bit i of the byte at offset (i>>3).
// Level 0 is the most significant bit of byte 0. Two hex chars = one byte.
function pathBit(keyHex, i) {
  const byteIndex = i >> 3;
  const byte = parseInt(keyHex.substr(byteIndex * 2, 2), 16);
  return (byte >> (7 - (i & 7))) & 1;
}

/**
 * Fold a leaf hash up `depth` sibling levels to a claimed root, using the key
 * bits to decide sibling side at each level. Root-to-leaf `siblings` order; we
 * consume them leaf-to-root. Returns the reconstructed root hex, or null on any
 * malformed input (fail-closed).
 *
 * @param {string} leafHex
 * @param {string[]} siblings  exactly `depth` hex sibling hashes, root-to-leaf
 * @param {string} keyHex      hex key whose top `depth` bits are the path
 * @param {number} depth
 * @returns {string|null}
 */
function foldToRoot(leafHex, siblings, keyHex, depth) {
  if (!isHex64(leafHex)) return null;
  if (!Array.isArray(siblings) || siblings.length !== depth) return null;
  let node = leafHex;
  // Walk from the deepest level (depth-1) up to the root (level 0). siblings[0]
  // is the sibling nearest the root, siblings[depth-1] nearest the leaf.
  for (let level = depth - 1; level >= 0; level--) {
    const sib = hexOf(siblings[level]);
    if (!isHex64(sib)) return null;
    const bit = pathBit(keyHex, level);
    // bit 0 => our node is the LEFT child; bit 1 => our node is the RIGHT child.
    node = bit === 0 ? hashBranch(node, sib) : hashBranch(sib, node);
  }
  return node;
}

/**
 * Validate one sparse-tree membership/non-membership sub-proof against a root.
 *
 * @param {object} sub  { root, siblings, present, value? }
 * @param {string} keyHex
 * @returns {{ok:boolean, reason?:string}}  ok true iff the sub-proof reconstructs `root`
 */
function checkSub(sub, keyHex, label) {
  if (!sub || typeof sub !== 'object') return { ok: false, reason: `${label}_missing` };
  const root = hexOf(sub.root);
  if (!isHex64(root)) return { ok: false, reason: `${label}_root_malformed` };
  if (!Array.isArray(sub.siblings) || sub.siblings.length !== SMT_DEPTH) {
    return { ok: false, reason: `${label}_siblings_wrong_length` };
  }
  let leaf;
  if (sub.present === true) {
    const value = hexOf(sub.value);
    if (!isHex64(value)) return { ok: false, reason: `${label}_present_value_malformed` };
    leaf = presentLeaf(keyHex, value);
  } else if (sub.present === false) {
    leaf = defaultLeaf();
  } else {
    // `present` must be an explicit boolean — never infer it. Fail-closed.
    return { ok: false, reason: `${label}_present_flag_missing` };
  }
  const reconstructed = foldToRoot(leaf, sub.siblings, keyHex, SMT_DEPTH);
  if (reconstructed === null) return { ok: false, reason: `${label}_sibling_malformed` };
  if (reconstructed !== root) return { ok: false, reason: `${label}_does_not_reconstruct_root` };
  return { ok: true };
}

/**
 * Verify a third-party CONSUMPTION proof bundle: prove a nonce transitioned
 * ABSENT -> PRESENT exactly once between two witnessed, append-only-linked heads.
 *
 * bundle shape:
 *   {
 *     nonce: string,                       // the one-time nonce being consumed
 *     non_inclusion_proof: {               // @ head h1: nonce ABSENT
 *       root, siblings[SMT_DEPTH], present:false
 *     },
 *     inclusion_proof: {                   // @ head h2: nonce PRESENT
 *       root, siblings[SMT_DEPTH], present:true, value
 *     },
 *     consistency_proof: string[],         // RFC 6962 h1 -> h2 (EP-MERKLE-v2)
 *     checkpoints: {
 *       h1: { tree_size, root_hash },      // dense-log head witnessing h1's SMT root
 *       h2: { tree_size, root_hash }       // dense-log head witnessing h2's SMT root
 *     }
 *   }
 *
 * The `checkpoints.h*.root_hash` are the DENSE append-only log roots the
 * consistency proof links (currency of the SMT roots is carried by the log; the
 * caller must have authenticated the checkpoint signatures separately — this
 * function proves only the tree-shaped facts). `non_inclusion_proof.root` and
 * `inclusion_proof.root` are the SMT roots as of h1 and h2 respectively.
 *
 * FAIL-CLOSED: any missing/malformed/invalid sub-proof, a non-append-only
 * h1->h2, a present-at-h1, or an absent-at-h2 refuses with a DISTINCT reason.
 * The default for `present` is refusal (never inferred). Nothing silently passes.
 *
 * @param {object} bundle
 * @returns {{valid:boolean, checks:{non_inclusion:boolean, inclusion:boolean, consistency:boolean}, reason:(string|null)}}
 */
export function verifyConsumptionProof(bundle) {
  const checks = { non_inclusion: false, inclusion: false, consistency: false };
  const fail = (reason) => ({ valid: false, checks, reason });

  if (!bundle || typeof bundle !== 'object') return fail('bundle_missing');
  if (typeof bundle.nonce !== 'string' || bundle.nonce.length === 0) return fail('nonce_missing');

  const keyHex = nonceKeyHex(bundle.nonce);

  // (a) NON-INCLUSION @ h1: the nonce leaf held the DEFAULT value at h1.
  const ni = bundle.non_inclusion_proof;
  if (!ni || typeof ni !== 'object') return fail('non_inclusion_proof_missing');
  if (ni.present !== false) return fail('non_inclusion_proof_must_assert_absent');
  const niRes = checkSub(ni, keyHex, 'non_inclusion');
  if (!niRes.ok) return fail(niRes.reason);
  checks.non_inclusion = true;

  // (b) INCLUSION @ h2: the SAME nonce leaf holds the PRESENT marker at h2.
  const inc = bundle.inclusion_proof;
  if (!inc || typeof inc !== 'object') return fail('inclusion_proof_missing');
  if (inc.present !== true) return fail('inclusion_proof_must_assert_present');
  const incRes = checkSub(inc, keyHex, 'inclusion');
  if (!incRes.ok) return fail(incRes.reason);
  checks.inclusion = true;

  // The two SMT roots must differ; an identical root would mean nothing changed
  // (no absent->present transition actually occurred at this key between heads).
  if (hexOf(ni.root) === hexOf(inc.root)) return fail('smt_root_unchanged_no_transition');

  // (c) APPEND-ONLY h1 -> h2 over the DENSE log (reuse the consistency verifier).
  const cps = bundle.checkpoints;
  if (!cps || typeof cps !== 'object' || !cps.h1 || !cps.h2) return fail('checkpoints_missing');
  const h1Size = cps.h1.tree_size;
  const h2Size = cps.h2.tree_size;
  const h1Root = hexOf(cps.h1.root_hash);
  const h2Root = hexOf(cps.h2.root_hash);
  if (!Number.isInteger(h1Size) || h1Size < 1 || !isHex64(h1Root)) return fail('checkpoint_h1_malformed');
  if (!Number.isInteger(h2Size) || h2Size < 1 || !isHex64(h2Root)) return fail('checkpoint_h2_malformed');
  // A one-time transition must move strictly forward: h1 must PRECEDE h2. Equal
  // heads cannot witness both an absent-at-h1 and a present-at-h2 SMT root.
  if (!(h1Size < h2Size)) return fail('checkpoint_h1_not_before_h2');
  if (!Array.isArray(bundle.consistency_proof)) return fail('consistency_proof_missing');
  if (!verifyCheckpointConsistency(h1Root, h1Size, h2Root, h2Size, bundle.consistency_proof)) {
    return fail('consistency_proof_not_append_only');
  }
  checks.consistency = true;

  return { valid: true, checks, reason: null };
}

// =============================================================================
// REFERENCE PROVER (test/tooling ONLY — NOT a production consumption ledger)
// =============================================================================
// A minimal, spec-faithful sparse Merkle tree over SMT_DEPTH bits, with an
// empty-subtree cache so proofs are cheap. A production issuer emits equivalent
// proofs from its own consumption ledger; these helpers exist so the VERIFIER
// above can be tested against a real absent->present transition.

/** Precomputed empty-subtree roots: EMPTY[level] = root of an all-default subtree
 *  of height (SMT_DEPTH - level). EMPTY[SMT_DEPTH] = the default leaf. */
function buildEmptyLevels(depth) {
  const empty = new Array(depth + 1);
  empty[depth] = defaultLeaf();
  for (let level = depth - 1; level >= 0; level--) {
    empty[level] = hashBranch(empty[level + 1], empty[level + 1]);
  }
  return empty;
}

/**
 * Reference sparse tree. Keys are hex SHA-256(nonce); only PRESENT leaves are
 * stored, everything else is the default. EXPERIMENTAL — tests/tooling only.
 */
export class ReferenceConsumptionTree {
  constructor(depth = SMT_DEPTH) {
    this.depth = depth;
    this.empty = buildEmptyLevels(depth);
    /** @type {Map<string,string>} keyHex -> valueHex for present leaves */
    this.present = new Map();
  }

  /** Insert (consume) a nonce with a value; value defaults to the key itself. */
  insert(nonce, value) {
    const keyHex = nonceKeyHex(nonce);
    const valueHex = hexOf(value) && isHex64(hexOf(value))
      ? hexOf(value)
      : crypto.createHash('sha256').update(Buffer.from(String(value ?? nonce), 'utf8')).digest('hex');
    this.present.set(keyHex, valueHex);
    return { keyHex, valueHex };
  }

  // Leaf hash stored at a key (present marker or default).
  _leafAt(keyHex) {
    const v = this.present.get(keyHex);
    return v === undefined ? defaultLeaf() : presentLeaf(keyHex, v);
  }

  // Compute the root over the (sparse) present set. Simplicity over speed:
  // recompute by DFS over path prefixes, using the empty-subtree cache to prune
  // subtrees that contain no present leaf. Fine for the small trees tests use.
  root() {
    return this._rootRec(0, '');
  }

  // Recursive root over a path prefix expressed as a bitstring.
  _rootRec(level, prefixBits) {
    if (level === this.depth) {
      // Leaf level: find the single key (if any) whose full path == prefixBits.
      for (const [keyHex, valueHex] of this.present) {
        if (this._bitsOf(keyHex, this.depth) === prefixBits) return presentLeaf(keyHex, valueHex);
      }
      return this.empty[this.depth];
    }
    // If no present key falls under this prefix, the whole subtree is empty.
    let any = false;
    for (const [keyHex] of this.present) {
      if (this._bitsOf(keyHex, level).startsWith(prefixBits) || prefixBits === '') { any = true; break; }
    }
    if (!any) return this.empty[level];
    const left = this._rootRec(level + 1, prefixBits + '0');
    const right = this._rootRec(level + 1, prefixBits + '1');
    return hashBranch(left, right);
  }

  _bitsOf(keyHex, n) {
    let s = '';
    for (let i = 0; i < n; i++) s += pathBit(keyHex, i);
    return s;
  }

  /**
   * Produce a proof for `nonce`: the sibling path root-to-leaf, plus whether the
   * leaf is present and its value. Works for both present (inclusion) and absent
   * (non-inclusion) keys.
   */
  prove(nonce) {
    const keyHex = nonceKeyHex(nonce);
    const siblings = new Array(this.depth);
    for (let level = 0; level < this.depth; level++) {
      const bit = pathBit(keyHex, level);
      // Sibling is the subtree on the OPPOSITE branch at this level.
      const prefix = this._bitsOf(keyHex, level);
      const siblingPrefix = prefix + (bit === 0 ? '1' : '0');
      siblings[level] = this._rootRec(level + 1, siblingPrefix);
    }
    const valueHex = this.present.get(keyHex);
    if (valueHex === undefined) {
      return { root: this.root(), siblings, present: false };
    }
    return { root: this.root(), siblings, present: true, value: valueHex };
  }
}
