// SPDX-License-Identifier: Apache-2.0
//
// Checkpoint CONSISTENCY proofs (RFC 6962 §2.1.2 / RFC 9162). Faithful port of
// packages/verify/consistency.js.
//
// A consistency proof proves that the log of size newSize with root newRoot is
// an APPEND-ONLY extension of the log of size oldSize with root oldRoot — nothing
// already committed was removed or rewritten. Combined with witness cosignatures
// + gossip it converts "the operator's word" into a cryptographically enforced,
// non-equivocable history.
//
// DOMAIN SEPARATION: uses the EP-MERKLE-v2 branch construction
// SHA-256(0x01 || left || right) -> hex (hashPairV2 in verify.go), byte-identical
// to consistency.js hashChildrenV2, so it composes with the v2 inclusion proofs.
//
// HONESTY: a consistency proof shows append-only extension between two OBSERVED
// heads. It does NOT establish currency or split-view honesty by itself.
package emiliaverify

import "strings"

// ConsistencyAlg identifies the branch construction used.
const ConsistencyAlg = "EP-MERKLE-v2"

func consistencyHexOf(h string) string {
	return strings.ToLower(strings.TrimPrefix(strings.ToLower(h), "sha256:"))
}

func isPowerOfTwo(n int) bool {
	return n > 0 && (n&(n-1)) == 0
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less than n
// (RFC 6962 helper). n >= 2.
func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// MerkleRootV2 computes an EP-MERKLE-v2 root over the given leaf hashes (hex).
// Reference helper for tests/tooling, byte-identical to consistency.js merkleRoot.
func MerkleRootV2(leaves []string) string {
	d := make([]string, len(leaves))
	for i, l := range leaves {
		d[i] = consistencyHexOf(l)
	}
	if len(d) == 1 {
		return d[0]
	}
	k := largestPowerOfTwoLessThan(len(d))
	return hashPairV2(MerkleRootV2(d[:k]), MerkleRootV2(d[k:]))
}

// BuildConsistencyProof builds the RFC 6962 consistency proof between sizes m and
// n of a log given at least n leaf hashes (hex). Reference helper for
// tests/tooling, byte-identical to consistency.js buildConsistencyProof.
func BuildConsistencyProof(m, n int, leaves []string) []string {
	if m == n {
		return []string{}
	}
	d := make([]string, n)
	for i := 0; i < n; i++ {
		d[i] = consistencyHexOf(leaves[i])
	}
	return subproof(m, d, true)
}

// subproof implements RFC 6962 §2.1.2 SUBPROOF(m, D[0:n], b).
func subproof(m int, d []string, b bool) []string {
	n := len(d)
	if m == n {
		if b {
			return []string{}
		}
		return []string{MerkleRootV2(d)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(subproof(m, d[:k], b), MerkleRootV2(d[k:n]))
	}
	return append(subproof(m-k, d[k:n], false), MerkleRootV2(d[:k]))
}

// VerifyCheckpointConsistency verifies an RFC 6962 §2.1.2 checkpoint consistency
// proof between two tree states of the SAME append-only log. Returns true iff the
// proof shows a prefix-preserving append-only extension. Faithful port of
// consistency.js verifyCheckpointConsistency (fail-closed on all malformed input).
func VerifyCheckpointConsistency(oldRoot string, oldSize int, newRoot string, newSize int, proof []string) bool {
	// Input validation (fail-closed).
	if oldSize < 0 || newSize < 0 || oldSize > newSize {
		return false
	}
	if len(proof) > 64 { // 2^64 leaves is far beyond any real log
		return false
	}
	oldR := consistencyHexOf(oldRoot)
	newR := consistencyHexOf(newRoot)
	if oldR == "" || newR == "" {
		return false
	}

	// Equal sizes: the only consistent proof is the empty one; roots must match.
	if oldSize == newSize {
		return len(proof) == 0 && oldR == newR
	}
	// EP checkpoints never start below size 1; treat oldSize 0 as fail-closed.
	if oldSize == 0 {
		return false
	}
	if len(proof) == 0 {
		return false
	}

	path := make([]string, len(proof))
	for i, h := range proof {
		hx := consistencyHexOf(h)
		if hx == "" {
			return false
		}
		path[i] = hx
	}

	// RFC 6962 §2.1.2 verification algorithm. If oldSize is an exact power of two,
	// the reference algorithm seeds both hash chains with the old root; otherwise
	// the first proof node is the shared seed.
	node := path
	var seed string
	if isPowerOfTwo(oldSize) {
		seed = oldR
	} else {
		seed = node[0]
		node = node[1:]
	}

	fn := oldSize - 1
	sn := newSize - 1
	// Shift out the common lower bits (identical right-spine structure).
	for fn%2 == 1 {
		fn = fn / 2
		sn = sn / 2
	}

	fr := seed // running hash toward oldRoot
	sr := seed // running hash toward newRoot

	for _, c := range node {
		if sn == 0 {
			return false // proof longer than the tree geometry allows
		}
		if fn%2 == 1 || fn == sn {
			fr = hashPairV2(c, fr)
			sr = hashPairV2(c, sr)
			for fn%2 == 0 && fn != 0 {
				fn = fn / 2
				sn = sn / 2
			}
		} else {
			sr = hashPairV2(sr, c)
		}
		fn = fn / 2
		sn = sn / 2
	}

	// Both reconstructed roots must match their claimed values, and the proof must
	// have exactly consumed the tree (sn drained to 0).
	return sn == 0 && fr == oldR && sr == newR
}
