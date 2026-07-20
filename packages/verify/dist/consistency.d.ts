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
export declare const CONSISTENCY_ALG = "EP-MERKLE-v2";
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
export declare function verifyCheckpointConsistency(oldRoot: unknown, oldSize: number, newRoot: unknown, newSize: number, proof: unknown): boolean;
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
export declare function buildConsistencyProof(m: number, n: number, leaves: string[]): string[];
/**
 * Reference MERKLE ROOT over EP-MERKLE-v2 branch hashing (test/tooling helper).
 * Leaves are assumed to already be leaf hashes (hex). EXPERIMENTAL.
 *
 * @param {string[]} leaves  leaf hashes (hex)
 * @returns {string} root hash (hex)
 */
export declare function merkleRoot(leaves: string[]): string;
//# sourceMappingURL=consistency.d.ts.map