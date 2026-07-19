// SPDX-License-Identifier: Apache-2.0
//
// EP-SMT-CONSUME-v1 Go parity tests. Mirror
// packages/verify/consumption-proof.test.js: build a real sparse consumption tree,
// produce a genuine ABSENT -> PRESENT transition of a nonce between two
// append-only-linked heads, assert ACCEPT; plus reject vectors (present-at-h1,
// absent-at-h2, non-append-only h1->h2) and fail-closed input validation. The
// consistency (h1->h2) leg reuses the dense RFC 6962 reference prover so h1/h2 are
// a real append-only pair, byte-identical to the JS bundle.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func denseLeaf(content string) string {
	sum := sha256.Sum256(append([]byte{0x00}, []byte(content)...))
	return hex.EncodeToString(sum[:])
}

func denseLeaves(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = denseLeaf(fmt.Sprintf("log-entry-%d", i))
	}
	return out
}

// makeBundle builds a full bundle for a real absent->present transition of nonce,
// with a genuine append-only dense-log pair h1 (size m) -> h2 (size n).
func makeBundle(nonce string, otherNonces []string, m, n int) map[string]any {
	treeBefore := NewReferenceConsumptionTree(SMTDepth)
	for _, o := range otherNonces {
		treeBefore.Insert(o, "")
	}
	niProof := treeBefore.Prove(nonce) // absent

	treeAfter := NewReferenceConsumptionTree(SMTDepth)
	for _, o := range otherNonces {
		treeAfter.Insert(o, "")
	}
	treeAfter.Insert(nonce, "")
	incProof := treeAfter.Prove(nonce) // present

	logLeaves := denseLeaves(n)
	h1Root := MerkleRootV2(logLeaves[:m])
	h2Root := MerkleRootV2(logLeaves)
	consistency := BuildConsistencyProof(m, n, logLeaves)
	cp := make([]any, len(consistency))
	for i, c := range consistency {
		cp[i] = c
	}

	return map[string]any{
		"nonce":               nonce,
		"non_inclusion_proof": niProof,
		"inclusion_proof":     incProof,
		"consistency_proof":   cp,
		"checkpoints": map[string]any{
			"h1": map[string]any{"tree_size": float64(m), "root_hash": h1Root},
			"h2": map[string]any{"tree_size": float64(n), "root_hash": h2Root},
		},
	}
}

func baseBundle() map[string]any {
	return makeBundle("nonce-A", []string{"nonce-B", "nonce-C"}, 3, 6)
}

func TestConsumptionConstants(t *testing.T) {
	if ConsumptionProfile != "EP-SMT-CONSUME-v1" || ConsumptionLeafDomain != "EP-SMT-CONSUME-v1" || SMTDepth != 32 {
		t.Fatalf("constants wrong")
	}
}

func TestConsumptionAcceptTransition(t *testing.T) {
	res := VerifyConsumptionProof(baseBundle())
	if !res.Valid {
		t.Fatalf("expected valid, got %+v", res)
	}
	if !res.Checks.NonInclusion || !res.Checks.Inclusion || !res.Checks.Consistency {
		t.Fatalf("checks=%+v", res.Checks)
	}
	if res.Reason != "" {
		t.Fatalf("reason=%q", res.Reason)
	}
}

func TestConsumptionAcceptSha256Prefixes(t *testing.T) {
	b := baseBundle()
	pfx := func(h string) string { return "sha256:" + h }
	ni := b["non_inclusion_proof"].(map[string]any)
	ni["root"] = pfx(ni["root"].(string))
	ni["siblings"] = mapSiblings(ni["siblings"].([]any), pfx)
	inc := b["inclusion_proof"].(map[string]any)
	inc["root"] = pfx(inc["root"].(string))
	inc["siblings"] = mapSiblings(inc["siblings"].([]any), pfx)
	inc["value"] = pfx(inc["value"].(string))
	cps := b["checkpoints"].(map[string]any)
	cps["h1"].(map[string]any)["root_hash"] = pfx(cps["h1"].(map[string]any)["root_hash"].(string))
	cps["h2"].(map[string]any)["root_hash"] = pfx(cps["h2"].(map[string]any)["root_hash"].(string))
	cp := b["consistency_proof"].([]any)
	for i := range cp {
		cp[i] = pfx(cp[i].(string))
	}
	if !VerifyConsumptionProof(b).Valid {
		t.Fatal("prefixed bundle should verify")
	}
}

func mapSiblings(sibs []any, f func(string) string) []any {
	out := make([]any, len(sibs))
	for i, s := range sibs {
		out[i] = f(s.(string))
	}
	return out
}

func TestConsumptionAcceptRange(t *testing.T) {
	for _, mn := range [][2]int{{1, 2}, {2, 5}, {4, 9}, {5, 8}, {7, 16}} {
		m, n := mn[0], mn[1]
		others := make([]string, 5)
		for i := range others {
			others[i] = fmt.Sprintf("other-%d-%d-%d", m, n, i)
		}
		res := VerifyConsumptionProof(makeBundle("nonce-A", others, m, n))
		if !res.Valid {
			t.Fatalf("m=%d n=%d: %+v", m, n, res)
		}
	}
}

func TestConsumptionRejectPresentAtH1(t *testing.T) {
	b := baseBundle()
	tree := NewReferenceConsumptionTree(SMTDepth)
	tree.Insert("nonce-A", "")
	b["non_inclusion_proof"] = tree.Prove("nonce-A") // present:true where absent required
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "non_inclusion_proof_must_assert_absent" || res.Checks.NonInclusion {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectNonInclusionBadRoot(t *testing.T) {
	b := baseBundle()
	ni := b["non_inclusion_proof"].(map[string]any)
	sibs := ni["siblings"].([]any)
	sibs[SMTDepth-1] = repeat("ff", 32)
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "non_inclusion_does_not_reconstruct_root" {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectAbsentAtH2(t *testing.T) {
	b := baseBundle()
	tree := NewReferenceConsumptionTree(SMTDepth)
	tree.Insert("nonce-B", "")
	tree.Insert("nonce-C", "")
	b["inclusion_proof"] = tree.Prove("nonce-A") // present:false
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "inclusion_proof_must_assert_present" || res.Checks.Inclusion {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectInclusionBadRoot(t *testing.T) {
	b := baseBundle()
	inc := b["inclusion_proof"].(map[string]any)
	inc["siblings"].([]any)[0] = repeat("ab", 32)
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "inclusion_does_not_reconstruct_root" {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectTamperedValue(t *testing.T) {
	b := baseBundle()
	inc := b["inclusion_proof"].(map[string]any)
	sum := sha256.Sum256([]byte("forged"))
	inc["value"] = hex.EncodeToString(sum[:])
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "inclusion_does_not_reconstruct_root" {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectNonAppendOnly(t *testing.T) {
	b := baseBundle()
	forked := denseLeaves(6)
	forked[0] = denseLeaf("rewritten-log-entry-0")
	forkedH1 := MerkleRootV2(forked[:3])
	b["checkpoints"].(map[string]any)["h1"].(map[string]any)["root_hash"] = forkedH1
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "consistency_proof_not_append_only" || res.Checks.Consistency {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectTamperedConsistencyNode(t *testing.T) {
	b := baseBundle()
	cp := b["consistency_proof"].([]any)
	cp[0] = denseLeaf("not-the-node")
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "consistency_proof_not_append_only" {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectH1NotBeforeH2(t *testing.T) {
	b := baseBundle()
	h2Root := b["checkpoints"].(map[string]any)["h2"].(map[string]any)["root_hash"].(string)
	b["checkpoints"].(map[string]any)["h1"] = map[string]any{"tree_size": float64(5), "root_hash": h2Root}
	b["checkpoints"].(map[string]any)["h2"] = map[string]any{"tree_size": float64(5), "root_hash": h2Root}
	b["consistency_proof"] = []any{}
	res := VerifyConsumptionProof(b)
	if res.Valid || res.Reason != "checkpoint_h1_not_before_h2" {
		t.Fatalf("got %+v", res)
	}
}

func TestConsumptionRejectIdenticalSMTRoots(t *testing.T) {
	b := baseBundle()
	ni := b["non_inclusion_proof"].(map[string]any)
	b["inclusion_proof"].(map[string]any)["root"] = ni["root"]
	res := VerifyConsumptionProof(b)
	if res.Valid {
		t.Fatal("identical SMT roots must not pass")
	}
	if res.Reason != "smt_root_unchanged_no_transition" && res.Reason != "inclusion_does_not_reconstruct_root" {
		t.Fatalf("reason=%q", res.Reason)
	}
}

func TestConsumptionFailClosedShape(t *testing.T) {
	if VerifyConsumptionProof(nil).Reason != "bundle_missing" {
		t.Fatal("nil bundle")
	}
	if VerifyConsumptionProof(map[string]any{}).Reason != "nonce_missing" {
		t.Fatal("missing nonce")
	}
	if VerifyConsumptionProof(map[string]any{"nonce": ""}).Reason != "nonce_missing" {
		t.Fatal("empty nonce")
	}
	if VerifyConsumptionProof(map[string]any{"nonce": "n"}).Reason != "non_inclusion_proof_missing" {
		t.Fatal("missing non-inclusion")
	}

	// present flag must be an explicit boolean, never inferred.
	b1 := baseBundle()
	delete(b1["non_inclusion_proof"].(map[string]any), "present")
	if VerifyConsumptionProof(b1).Reason != "non_inclusion_proof_must_assert_absent" {
		t.Fatalf("missing present flag: %+v", VerifyConsumptionProof(b1))
	}

	// wrong siblings length.
	b2 := baseBundle()
	ni2 := b2["non_inclusion_proof"].(map[string]any)
	ni2["siblings"] = ni2["siblings"].([]any)[:5]
	if VerifyConsumptionProof(b2).Reason != "non_inclusion_siblings_wrong_length" {
		t.Fatal("siblings length")
	}

	// malformed SMT root.
	b3 := baseBundle()
	b3["non_inclusion_proof"].(map[string]any)["root"] = "not-hex"
	if VerifyConsumptionProof(b3).Reason != "non_inclusion_root_malformed" {
		t.Fatal("malformed root")
	}

	// present inclusion missing value.
	b4 := baseBundle()
	delete(b4["inclusion_proof"].(map[string]any), "value")
	if VerifyConsumptionProof(b4).Reason != "inclusion_present_value_malformed" {
		t.Fatal("missing value")
	}

	// missing checkpoints.
	b5 := baseBundle()
	delete(b5, "checkpoints")
	if VerifyConsumptionProof(b5).Reason != "checkpoints_missing" {
		t.Fatal("missing checkpoints")
	}

	// malformed checkpoint h1.
	b6 := baseBundle()
	b6["checkpoints"].(map[string]any)["h1"].(map[string]any)["tree_size"] = float64(0)
	if VerifyConsumptionProof(b6).Reason != "checkpoint_h1_malformed" {
		t.Fatal("malformed h1")
	}

	// missing consistency proof array.
	b7 := baseBundle()
	b7["consistency_proof"] = "nope"
	if VerifyConsumptionProof(b7).Reason != "consistency_proof_missing" {
		t.Fatal("missing consistency proof")
	}

	// sanity: base bundle still verifies.
	if !VerifyConsumptionProof(baseBundle()).Valid {
		t.Fatal("base bundle should verify")
	}
}

func TestConsumptionReferenceTreeSelfConsistency(t *testing.T) {
	tree := NewReferenceConsumptionTree(SMTDepth)
	tree.Insert("alpha", "")
	tree.Insert("beta", "")
	root := tree.Root()
	incl := tree.Prove("alpha")
	nonIncl := tree.Prove("gamma")
	if incl["root"].(string) != root || nonIncl["root"].(string) != root {
		t.Fatal("proofs must carry the tree root")
	}
	if incl["present"].(bool) != true || nonIncl["present"].(bool) != false {
		t.Fatal("present flags wrong")
	}
	if len(incl["siblings"].([]any)) != SMTDepth {
		t.Fatal("siblings length")
	}
}
