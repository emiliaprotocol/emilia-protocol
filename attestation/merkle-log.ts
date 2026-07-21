/**
 * Reference EP-MERKLE-v2 transparency-log builder (TOOLING, not the verifier).
 *
 * Produces the `log_entry` an attestation record carries: a leaf hash, an
 * inclusion proof, and the root — in the exact EP-MERKLE-v2 shape that
 * verifyMerkleAnchor(..., { v2: true }) checks. The root construction mirrors
 * merkleRoot() in @emilia-protocol/verify/consistency.js (RFC 6962 left-heavy
 * tree, 0x01 branch prefix), and the inclusion path mirrors that same recursion,
 * so a proof this builder emits is accepted by the production verifier.
 *
 * This is the "append to a transparency log" side of the chain. A production
 * deployment replaces this in-memory builder with a persistent, checkpointed,
 * witness-cosigned log (see witness/ and docs/security/TRANSPARENCY-LAYER-DESIGN.md);
 * the leaf hashing and proof shape stay identical.
 *
 * @license Apache-2.0
 */

import { merkleRoot } from '../packages/verify/consistency.js';
import { attestationSubject, attestationLeafHash } from './build-attestation.js';

function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Inclusion path for leaf index `i` in D[0:n], as {hash, position} steps
 * consumable by verifyMerkleAnchor. `position` is the side the SIBLING sits on.
 * Mirrors the RFC 6962 left-heavy split used by merkleRoot().
 */
function inclusionPath(i: number, leaves: string[]): Array<{ hash: string; position: 'left' | 'right' }> {
  const n = leaves.length;
  if (n === 1) return [];
  const k = largestPowerOfTwoLessThan(n);
  if (i < k) {
    const right = merkleRoot(leaves.slice(k, n));
    return [...inclusionPath(i, leaves.slice(0, k)), { hash: right, position: 'right' }];
  }
  const left = merkleRoot(leaves.slice(0, k));
  return [...inclusionPath(i - k, leaves.slice(k, n)), { hash: left, position: 'left' }];
}

/**
 * Build a log_entry for `subject` given the full ordered set of leaf subjects
 * already in the log (including this one). Returns the object to place under
 * record.log_entry.
 *
 * @param {object[]} leafSubjects - attestation subjects, in log order
 * @param {number} index - index of the subject being proven
 * @returns {{ alg: string, leaf_hash: string, merkle_proof: Array, merkle_root: string, tree_size: number }}
 */
export function buildLogEntry(
  leafSubjects: Record<string, any>[],
  index: number,
): {
  alg: string;
  leaf_hash: string;
  merkle_proof: Array<{ hash: string; position: 'left' | 'right' }>;
  merkle_root: string;
  tree_size: number;
} {
  if (!Array.isArray(leafSubjects) || leafSubjects.length === 0) {
    throw new Error('buildLogEntry: need at least one leaf subject');
  }
  if (!Number.isInteger(index) || index < 0 || index >= leafSubjects.length) {
    throw new Error('buildLogEntry: index out of range');
  }
  const leaves = leafSubjects.map(attestationLeafHash);
  const root = merkleRoot(leaves);
  const proof = inclusionPath(index, leaves);
  return {
    alg: 'EP-MERKLE-v2',
    leaf_hash: leaves[index],
    merkle_proof: proof,
    merkle_root: root,
    tree_size: leaves.length,
  };
}

/**
 * Convenience: assemble a complete EP-BUILD-ATTESTATION-v1 record for a single
 * build appended to a log alongside `otherSubjects`.
 *
 * @param {{ commit: string, package_path: string }} source
 * @param {{ filename: string, sha256: string, bytes: number }} artifact
 * @param {object[]} [otherSubjects] - other leaves already in the log
 * @returns {object} EP-BUILD-ATTESTATION-v1 record (no tpm_quote)
 */
export function assembleRecord(
  source: { commit: string; package_path: string },
  artifact: { filename: string; sha256: string; bytes: number },
  otherSubjects: Record<string, any>[] = [],
): Record<string, any> {
  const record: Record<string, any> = {
    '@version': 'EP-BUILD-ATTESTATION-v1',
    source: { commit: source.commit, package_path: source.package_path },
    artifact: { filename: artifact.filename, sha256: artifact.sha256, bytes: artifact.bytes },
  };
  const subject = attestationSubject(record);
  const subjects = [...otherSubjects, subject];
  record.log_entry = buildLogEntry(subjects, subjects.length - 1);
  return record;
}
