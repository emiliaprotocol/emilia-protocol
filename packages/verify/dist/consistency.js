/**
 * @emilia-protocol/verify — Checkpoint CONSISTENCY proofs
 *
 * Wired into verifyTrustReceipt() as the OPT-IN `opts.priorCheckpoint` knob
 * (checks.consistency, fail-closed). Also exported directly from index.js for
 * log tooling and witnesses.
 *
 * This module addresses the DoD-audit MED-HIGH transparency finding: a trust
 * receipt today carries a SINGLE-signer checkpoint {log_key_id, root_hash,
 * tree_size, log_signature} and NO append-only (consistency) proof between
 * checkpoints. A malicious log operator can therefore present two different,
 * internally-consistent histories to two verifiers (a "split view" /
 * equivocation) and neither can detect it offline. See
 * docs/security/TRANSPARENCY-LAYER-DESIGN.md for the full threat + fix design.
 *
 * A consistency proof (RFC 6962 §2.1.2 / RFC 9162 §2.1.4) proves that the log
 * of size `newSize` with root `newRoot` is an APPEND-ONLY extension of the log
 * of size `oldSize` with root `oldRoot` — i.e. nothing already committed was
 * removed or rewritten. Combined with witness cosignatures + gossip (see the
 * design doc), it converts "the operator's word" into a cryptographically
 * enforced, non-equivocable history.
 *
 * DOMAIN SEPARATION: this uses the EP-MERKLE-v2 branch construction
 * (SHA-256(0x01 || left || right), hex) so it composes with the v2 inclusion
 * proofs already verified by verifyMerkleAnchor(..., { v2: true }) in index.js.
 * It stays standalone (no imports from index.js) so it can also be used alone.
 *
 * HONESTY: a consistency proof shows append-only extension between two
 * OBSERVED heads. It does NOT establish currency or split-view honesty by
 * itself — that needs independent witnesses + gossip (see the design doc).
 *
 * @license Apache-2.0
 */
import crypto from 'crypto';
export const CONSISTENCY_ALG = 'EP-MERKLE-v2';
const HASH_PREFIX = /^sha256:/i;
function hexOf(h) {
    return String(h || '').replace(HASH_PREFIX, '').toLowerCase();
}
// EP-MERKLE-v2 branch hash: SHA-256(0x01 || leftHex || rightHex) -> hex.
// Byte-identical to hashPairV2() in index.js (kept in sync deliberately; this
// module does not import it, to remain standalone and additive).
function hashChildrenV2(left, right) {
    return crypto
        .createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')]))
        .digest('hex');
}
function isPowerOfTwo(n) {
    return n > 0 && (n & (n - 1)) === 0;
}
// Largest power of two strictly less than n (RFC 6962 helper). n >= 2.
function largestPowerOfTwoLessThan(n) {
    let k = 1;
    while (k * 2 < n)
        k *= 2;
    return k;
}
/**
 * Verify an RFC 6962 §2.1.2 checkpoint consistency proof between two tree
 * states of the SAME append-only log.
 *
 * Proves: the size-`newSize` tree (root `newRoot`) is a prefix-preserving
 * append-only extension of the size-`oldSize` tree (root `oldRoot`).
 *
 * @param {string} oldRoot  hex (or "sha256:"-prefixed hex) root at oldSize
 * @param {number} oldSize  tree size m, 0 < oldSize <= newSize
 * @param {string} newRoot  hex (or "sha256:"-prefixed hex) root at newSize
 * @param {number} newSize  tree size n
 * @param {string[]} proof  ordered consistency-proof node hashes (hex or
 *                          "sha256:"-prefixed). Empty iff oldSize === newSize.
 * @returns {boolean} true iff the proof shows an append-only extension.
 */
export function verifyCheckpointConsistency(oldRoot, oldSize, newRoot, newSize, proof) {
    // ── Input validation (fail-closed) ─────────────────────────────────────────
    if (!Number.isInteger(oldSize) || !Number.isInteger(newSize))
        return false;
    if (oldSize < 0 || newSize < 0 || oldSize > newSize)
        return false;
    if (!Array.isArray(proof))
        return false;
    if (proof.length > 64)
        return false; // 2^64 leaves is far beyond any real log
    const oldR = hexOf(oldRoot);
    const newR = hexOf(newRoot);
    if (!oldR || !newR)
        return false;
    // Equal sizes: the only consistent proof is the empty one, and roots must match.
    if (oldSize === newSize) {
        return proof.length === 0 && oldR === newR;
    }
    // The empty tree is a prefix of everything and RFC 6962 emits no proof, but
    // its root is undefined. EP checkpoints never start below size 1, so treat
    // oldSize 0 as a caller error to stay fail-closed.
    if (oldSize === 0)
        return false;
    if (proof.length === 0)
        return false;
    const path = proof.map(hexOf);
    if (path.some((h) => !h))
        return false;
    // ── RFC 6962 §2.1.2 verification algorithm ──────────────────────────────────
    // If oldSize is an exact power of two, the reference algorithm implicitly
    // seeds both hash chains with the old root; otherwise the first proof node is
    // the shared seed.
    let node = path;
    let seed;
    if (isPowerOfTwo(oldSize)) {
        seed = oldR;
    }
    else {
        seed = node[0];
        node = node.slice(1);
    }
    let fn = oldSize - 1;
    let sn = newSize - 1;
    // Shift out the common lower bits (identical right-spine structure).
    while (fn % 2 === 1) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
    }
    let fr = seed; // running hash toward oldRoot
    let sr = seed; // running hash toward newRoot
    for (const c of node) {
        if (sn === 0)
            return false; // proof longer than the tree geometry allows
        if (fn % 2 === 1 || fn === sn) {
            fr = hashChildrenV2(c, fr);
            sr = hashChildrenV2(c, sr);
            while (fn % 2 === 0 && fn !== 0) {
                fn = Math.floor(fn / 2);
                sn = Math.floor(sn / 2);
            }
        }
        else {
            sr = hashChildrenV2(sr, c);
        }
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
    }
    // Both reconstructed roots must match their claimed values, and the proof
    // must have exactly consumed the tree (sn drained to 0).
    return sn === 0 && fr === oldR && sr === newR;
}
/**
 * Reference PROVER (test/tooling helper): build the RFC 6962 consistency proof
 * between two sizes of a log given all its leaf hashes. EXPERIMENTAL. Not used
 * by any verifier — provided so the verifier can be tested against a
 * spec-faithful prover, and so tooling/witnesses can generate proofs.
 *
 * @param {number} m  old size (1 <= m <= n)
 * @param {number} n  new size
 * @param {string[]} leaves  at least n leaf hashes (hex), index 0..n-1
 * @returns {string[]} ordered proof node hashes (hex)
 */
export function buildConsistencyProof(m, n, leaves) {
    if (!Array.isArray(leaves) || leaves.length < n) {
        throw new Error('buildConsistencyProof: need at least n leaf hashes');
    }
    if (!(m >= 1 && m <= n))
        throw new Error('buildConsistencyProof: require 1 <= m <= n');
    if (m === n)
        return [];
    return subproof(m, leaves.slice(0, n).map(hexOf), true);
}
// RFC 6962 §2.1.2 SUBPROOF(m, D[0:n], b).
function subproof(m, d, b) {
    const n = d.length;
    if (m === n) {
        return b ? [] : [merkleRoot(d)];
    }
    const k = largestPowerOfTwoLessThan(n);
    if (m <= k) {
        return [...subproof(m, d.slice(0, k), b), merkleRoot(d.slice(k, n))];
    }
    return [...subproof(m - k, d.slice(k, n), false), merkleRoot(d.slice(0, k))];
}
/**
 * Reference MERKLE ROOT over EP-MERKLE-v2 branch hashing (test/tooling helper).
 * Leaves are assumed to already be leaf hashes (hex). EXPERIMENTAL.
 *
 * @param {string[]} leaves  leaf hashes (hex)
 * @returns {string} root hash (hex)
 */
export function merkleRoot(leaves) {
    const d = leaves.map(hexOf);
    if (d.length === 0)
        throw new Error('merkleRoot: empty tree has no defined EP root');
    if (d.length === 1)
        return d[0];
    const k = largestPowerOfTwoLessThan(d.length);
    return hashChildrenV2(merkleRoot(d.slice(0, k)), merkleRoot(d.slice(k)));
}
//# sourceMappingURL=consistency.js.map