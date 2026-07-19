// SPDX-License-Identifier: Apache-2.0
//
// Third-party-verifiable one-time CONSUMPTION proofs (sparse-Merkle-over-nonce,
// EP-SMT-CONSUME-v1). Faithful port of packages/verify/consumption-proof.js.
// EXPERIMENTAL / additive.
//
// THE PROBLEM THIS CLOSES: a trust receipt's consumption block is today an
// OPERATOR ASSERTION. This profile replaces the assertion with a proof: the
// operator maintains a sparse Merkle tree keyed by nonce and produces, at commit
// time, a proof that the nonce transitioned ABSENT -> PRESENT exactly once
// between two WITNESSED log heads. A second commit of the same nonce cannot also
// exhibit a valid absent-at-h1 proof under the same append-only log, so
// double-consumption becomes offline-detectable by any third party.
//
// WHAT A BUNDLE PROVES (all three, conjunctively, fail-closed):
//
//	(a) NON-INCLUSION at head h1: the nonce leaf held the DEFAULT value at h1.
//	(b) INCLUSION at head h2: the same nonce leaf holds the PRESENT marker at h2.
//	(c) APPEND-ONLY h1 -> h2: h2 is a consistency-proven extension of h1 (reuses
//	    VerifyCheckpointConsistency — the SAME EP-MERKLE-v2 branch construction;
//	    this module does NOT invent a second Merkle scheme).
//
// DOMAIN SEPARATION (reuses EP-MERKLE-v2 branch bytes; adds distinct LEAF bytes):
//   - Branch  = SHA-256(0x01 || leftHex || rightHex)   [SAME as EP-MERKLE-v2]
//   - PRESENT leaf = SHA-256(0x02 || keyHex || valueHex)
//   - DEFAULT leaf = SHA-256(0x03)
//
// HONESTY: this is the VERIFIER and WIRE FORMAT only; the reference prover below
// is for tests/tooling, not a production consumption ledger. Offline verification
// establishes append-only consistency between two OBSERVED heads; it does not
// establish currency and does not by itself defeat split-view equivocation.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// ConsumptionProfile / ConsumptionLeafDomain identify the profile.
const ConsumptionProfile = "EP-SMT-CONSUME-v1"
const ConsumptionLeafDomain = "EP-SMT-CONSUME-v1"

// SMTDepth is the fixed sparse-tree depth (bits of SHA-256(nonce) consumed as the
// key path).
const SMTDepth = 32

var consumptionHexRe = regexp.MustCompile(`^[0-9a-f]+$`)

func consumptionHexOf(h string) string {
	return strings.ToLower(strings.TrimPrefix(strings.ToLower(h), "sha256:"))
}

func isHex64(h string) bool {
	return len(h) == 64 && consumptionHexRe.MatchString(h)
}

// presentLeaf = SHA-256(0x02 || keyHex || valueHex) -> hex.
func presentLeaf(keyHex, valueHex string) string {
	buf := make([]byte, 0, 1+len(keyHex)+len(valueHex))
	buf = append(buf, 0x02)
	buf = append(buf, keyHex...)
	buf = append(buf, valueHex...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// defaultLeaf = SHA-256(0x03) -> hex (the absent/empty marker).
func defaultLeaf() string {
	sum := sha256.Sum256([]byte{0x03})
	return hex.EncodeToString(sum[:])
}

// nonceKeyHex = SHA-256(nonce) as hex; the top SMTDepth bits form the tree path.
func nonceKeyHex(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

// pathBit returns bit i (MSB-first) of a hex string.
func pathBit(keyHex string, i int) int {
	byteIndex := i >> 3
	b, err := strconv.ParseInt(keyHex[byteIndex*2:byteIndex*2+2], 16, 32)
	if err != nil {
		return 0
	}
	return int((b >> (7 - (i & 7))) & 1)
}

// foldToRoot folds a leaf hash up depth sibling levels to a claimed root using
// the key bits to decide sibling side at each level. siblings is root-to-leaf.
// Returns the reconstructed root hex, or ("", false) on any malformed input.
func foldToRoot(leafHex string, siblings []string, keyHex string, depth int) (string, bool) {
	if !isHex64(leafHex) {
		return "", false
	}
	if len(siblings) != depth {
		return "", false
	}
	node := leafHex
	for level := depth - 1; level >= 0; level-- {
		sib := consumptionHexOf(siblings[level])
		if !isHex64(sib) {
			return "", false
		}
		bit := pathBit(keyHex, level)
		if bit == 0 {
			node = hashPairV2(node, sib)
		} else {
			node = hashPairV2(sib, node)
		}
	}
	return node, true
}

// smtSubProof is a decoded sparse-tree membership/non-membership sub-proof.
type smtSubProof struct {
	Root       string
	Siblings   []string
	Present    bool
	PresentSet bool
	Value      string
	ValueSet   bool
}

// smtSubFromMap decodes a sub-proof from a JSON object, preserving the
// present/absent flag distinction (JS refuses if present is not an explicit bool).
func smtSubFromMap(m map[string]any) (smtSubProof, bool) {
	if m == nil {
		return smtSubProof{}, false
	}
	sub := smtSubProof{}
	if v, ok := m["root"].(string); ok {
		sub.Root = v
	}
	if raw, ok := m["siblings"].([]any); ok {
		sub.Siblings = make([]string, len(raw))
		for i, s := range raw {
			sub.Siblings[i], _ = s.(string)
		}
	} else {
		sub.Siblings = nil
	}
	if v, ok := m["present"]; ok {
		if b, ok := v.(bool); ok {
			sub.Present = b
			sub.PresentSet = true
		}
	}
	if v, ok := m["value"].(string); ok {
		sub.Value = v
		sub.ValueSet = true
	}
	return sub, true
}

// checkSub validates one sparse-tree sub-proof against its root. Returns ("") on
// success or a distinct reason string on failure. Mirrors consumption-proof.js
// checkSub.
func checkSub(sub smtSubProof, keyHex, label string) string {
	root := consumptionHexOf(sub.Root)
	if !isHex64(root) {
		return label + "_root_malformed"
	}
	if len(sub.Siblings) != SMTDepth {
		return label + "_siblings_wrong_length"
	}
	var leaf string
	if sub.PresentSet && sub.Present {
		value := consumptionHexOf(sub.Value)
		if !isHex64(value) {
			return label + "_present_value_malformed"
		}
		leaf = presentLeaf(keyHex, value)
	} else if sub.PresentSet && !sub.Present {
		leaf = defaultLeaf()
	} else {
		return label + "_present_flag_missing"
	}
	reconstructed, ok := foldToRoot(leaf, sub.Siblings, keyHex, SMTDepth)
	if !ok {
		return label + "_sibling_malformed"
	}
	if reconstructed != root {
		return label + "_does_not_reconstruct_root"
	}
	return ""
}

// ConsumptionChecks is the per-leg pass/fail of a consumption bundle.
type ConsumptionChecks struct {
	NonInclusion bool `json:"non_inclusion"`
	Inclusion    bool `json:"inclusion"`
	Consistency  bool `json:"consistency"`
}

// ConsumptionResult is the verifyConsumptionProof result.
type ConsumptionResult struct {
	Valid  bool              `json:"valid"`
	Checks ConsumptionChecks `json:"checks"`
	Reason string            `json:"reason"` // "" when valid (JS null)
}

// jsonInt extracts an integer from a JSON-decoded value (json.Number / float64 /
// int), reporting whether it was an integer.
func jsonInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
		return 0, false
	case interface {
		Int64() (int64, error)
		Float64() (float64, error)
	}: // json.Number
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
		// Integral-valued decimal ("3.0"): Int64() rejects it, but it equals 3.
		// Accept via Float64 to match the float64 branch and the JS/Python ports.
		if f, err := n.Float64(); err == nil && f == float64(int(f)) {
			return int(f), true
		}
		return 0, false
	}
	return 0, false
}

// VerifyConsumptionProof verifies a third-party CONSUMPTION proof bundle supplied
// as a decoded JSON object. Faithful port of consumption-proof.js
// verifyConsumptionProof — same accept/refuse decisions, same distinct reason
// strings. Fail-closed: any missing/malformed/invalid sub-proof, a non-append-only
// h1->h2, a present-at-h1, or an absent-at-h2 refuses with a DISTINCT reason.
func VerifyConsumptionProof(bundle map[string]any) ConsumptionResult {
	checks := ConsumptionChecks{}
	fail := func(reason string) ConsumptionResult {
		return ConsumptionResult{Valid: false, Checks: checks, Reason: reason}
	}

	if bundle == nil {
		return fail("bundle_missing")
	}
	nonce, ok := bundle["nonce"].(string)
	if !ok || nonce == "" {
		return fail("nonce_missing")
	}
	keyHex := nonceKeyHex(nonce)

	// (a) NON-INCLUSION @ h1: the nonce leaf held the DEFAULT value at h1.
	niMap, niIsMap := bundle["non_inclusion_proof"].(map[string]any)
	if !niIsMap {
		return fail("non_inclusion_proof_missing")
	}
	ni, _ := smtSubFromMap(niMap)
	if !(ni.PresentSet && !ni.Present) {
		return fail("non_inclusion_proof_must_assert_absent")
	}
	if reason := checkSub(ni, keyHex, "non_inclusion"); reason != "" {
		return fail(reason)
	}
	checks.NonInclusion = true

	// (b) INCLUSION @ h2: the SAME nonce leaf holds the PRESENT marker at h2.
	incMap, incIsMap := bundle["inclusion_proof"].(map[string]any)
	if !incIsMap {
		return fail("inclusion_proof_missing")
	}
	inc, _ := smtSubFromMap(incMap)
	if !(inc.PresentSet && inc.Present) {
		return fail("inclusion_proof_must_assert_present")
	}
	if reason := checkSub(inc, keyHex, "inclusion"); reason != "" {
		return fail(reason)
	}
	checks.Inclusion = true

	// The two SMT roots must differ; an identical root means nothing changed.
	if consumptionHexOf(ni.Root) == consumptionHexOf(inc.Root) {
		return fail("smt_root_unchanged_no_transition")
	}

	// (c) APPEND-ONLY h1 -> h2 over the DENSE log (reuse the consistency verifier).
	cps, cpsIsMap := bundle["checkpoints"].(map[string]any)
	if !cpsIsMap {
		return fail("checkpoints_missing")
	}
	h1, h1IsMap := cps["h1"].(map[string]any)
	h2, h2IsMap := cps["h2"].(map[string]any)
	if !h1IsMap || !h2IsMap {
		return fail("checkpoints_missing")
	}
	h1Size, h1SizeOK := jsonInt(h1["tree_size"])
	h2Size, h2SizeOK := jsonInt(h2["tree_size"])
	h1RootStr, _ := h1["root_hash"].(string)
	h2RootStr, _ := h2["root_hash"].(string)
	h1Root := consumptionHexOf(h1RootStr)
	h2Root := consumptionHexOf(h2RootStr)
	if !h1SizeOK || h1Size < 1 || !isHex64(h1Root) {
		return fail("checkpoint_h1_malformed")
	}
	if !h2SizeOK || h2Size < 1 || !isHex64(h2Root) {
		return fail("checkpoint_h2_malformed")
	}
	if !(h1Size < h2Size) {
		return fail("checkpoint_h1_not_before_h2")
	}
	cpRaw, isArr := bundle["consistency_proof"].([]any)
	if !isArr {
		return fail("consistency_proof_missing")
	}
	cp := make([]string, len(cpRaw))
	for i, v := range cpRaw {
		cp[i], _ = v.(string)
	}
	if !VerifyCheckpointConsistency(h1Root, h1Size, h2Root, h2Size, cp) {
		return fail("consistency_proof_not_append_only")
	}
	checks.Consistency = true

	return ConsumptionResult{Valid: true, Checks: checks, Reason: ""}
}

// =============================================================================
// REFERENCE PROVER (test/tooling ONLY — NOT a production consumption ledger)
// =============================================================================
// A minimal, spec-faithful sparse Merkle tree over SMTDepth bits, mirroring
// ReferenceConsumptionTree in consumption-proof.js. Exists so the VERIFIER above
// (and the conformance vector) can be built against a real absent->present
// transition, byte-identical to the JS prover.

// ReferenceConsumptionTree is the reference sparse tree (tests/tooling only).
type ReferenceConsumptionTree struct {
	depth   int
	empty   []string
	present map[string]string // keyHex -> valueHex for present leaves
}

// NewReferenceConsumptionTree builds an empty reference tree of the given depth.
func NewReferenceConsumptionTree(depth int) *ReferenceConsumptionTree {
	empty := make([]string, depth+1)
	empty[depth] = defaultLeaf()
	for level := depth - 1; level >= 0; level-- {
		empty[level] = hashPairV2(empty[level+1], empty[level+1])
	}
	return &ReferenceConsumptionTree{depth: depth, empty: empty, present: map[string]string{}}
}

// Insert consumes a nonce with an optional value (empty value derives one from
// the nonce, matching the JS `value ?? nonce` default).
func (t *ReferenceConsumptionTree) Insert(nonce, value string) {
	keyHex := nonceKeyHex(nonce)
	var valueHex string
	if v := consumptionHexOf(value); v != "" && isHex64(v) {
		valueHex = v
	} else {
		content := value
		if content == "" {
			content = nonce
		}
		sum := sha256.Sum256([]byte(content))
		valueHex = hex.EncodeToString(sum[:])
	}
	t.present[keyHex] = valueHex
}

func (t *ReferenceConsumptionTree) bitsOf(keyHex string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(byte('0' + pathBit(keyHex, i)))
	}
	return b.String()
}

func (t *ReferenceConsumptionTree) rootRec(level int, prefixBits string) string {
	if level == t.depth {
		for keyHex, valueHex := range t.present {
			if t.bitsOf(keyHex, t.depth) == prefixBits {
				return presentLeaf(keyHex, valueHex)
			}
		}
		return t.empty[t.depth]
	}
	any := false
	for keyHex := range t.present {
		if prefixBits == "" || strings.HasPrefix(t.bitsOf(keyHex, level), prefixBits) {
			any = true
			break
		}
	}
	if !any {
		return t.empty[level]
	}
	left := t.rootRec(level+1, prefixBits+"0")
	right := t.rootRec(level+1, prefixBits+"1")
	return hashPairV2(left, right)
}

// Root computes the current root over the sparse present set.
func (t *ReferenceConsumptionTree) Root() string {
	return t.rootRec(0, "")
}

// Prove produces a proof for nonce: the sibling path root-to-leaf, plus whether
// the leaf is present and its value. Returns a map matching the JS proof shape.
func (t *ReferenceConsumptionTree) Prove(nonce string) map[string]any {
	keyHex := nonceKeyHex(nonce)
	siblings := make([]any, t.depth)
	for level := 0; level < t.depth; level++ {
		bit := pathBit(keyHex, level)
		prefix := t.bitsOf(keyHex, level)
		var siblingPrefix string
		if bit == 0 {
			siblingPrefix = prefix + "1"
		} else {
			siblingPrefix = prefix + "0"
		}
		siblings[level] = t.rootRec(level+1, siblingPrefix)
	}
	valueHex, isPresent := t.present[keyHex]
	proof := map[string]any{
		"root":     t.Root(),
		"siblings": siblings,
	}
	if isPresent {
		proof["present"] = true
		proof["value"] = valueHex
	} else {
		proof["present"] = false
	}
	return proof
}
