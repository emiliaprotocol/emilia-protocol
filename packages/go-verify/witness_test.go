// SPDX-License-Identifier: Apache-2.0
//
// EP-WITNESS-v1 Go parity tests. Mirror packages/verify/witness.test.js: a
// genuine cosign verifies; a wrong/unpinned key refuses; a tampered checkpoint
// refuses; a cosignature echoed for a DIFFERENT head refuses; the domain tag
// keeps a witness cosignature and a log signature disjoint; and the k-of-n quorum
// helper accepts k DISTINCT pinned witnesses and refuses k-1, duplicates, or
// unpinned witnesses. A cosignature produced HERE is byte-identical to one
// produced by witness.js over the same committed checkpoint bytes.
package emiliaverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
)

type wkeys struct {
	priv ed25519.PrivateKey
	pub  string // base64url SPKI DER
}

func newEd25519(t *testing.T) wkeys {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return wkeys{priv: priv, pub: base64.RawURLEncoding.EncodeToString(der)}
}

func makeCheckpoint(overrides map[string]any) map[string]any {
	cp := map[string]any{
		"tree_size":  json.Number("42"),
		"root_hash":  "sha256:" + repeat("a1", 32),
		"log_key_id": "ep:log:test#1",
		"merkle_alg": "EP-MERKLE-v2",
	}
	for k, v := range overrides {
		cp[k] = v
	}
	return cp
}

// cosign produces a witness cosignature exactly as witness/server.mjs / witness.js
// does: Ed25519 over WitnessSigningDigest(checkpoint), base64url.
func cosign(cp map[string]any, witnessID string, keys wkeys, extra map[string]any) map[string]any {
	digest := WitnessSigningDigest(cp)
	sig := ed25519.Sign(keys.priv, digest)
	out := map[string]any{
		"alg":        WitnessVersion,
		"witness_id": witnessID,
		"tree_size":  cp["tree_size"],
		"root_hash":  cp["root_hash"],
		"log_key_id": cp["log_key_id"],
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
	}
	for k, v := range extra {
		if v == nil {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

func TestWitnessGenuineVerifies(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(nil)
	cosig := cosignatureFromMap(cosign(cp, "witness-a", w, nil))
	r := VerifyWitnessCosignature(cp, cosig, PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub})
	if !r.Verified || r.WitnessID != "witness-a" || r.Reason != "" {
		t.Fatalf("got %+v", r)
	}
}

func TestWitnessWithLogSignatureStillVerifies(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(nil)
	cosig := cosignatureFromMap(cosign(cp, "witness-a", w, nil))
	withLogSig := makeCheckpoint(map[string]any{"log_signature": "b64u:deadbeef"})
	r := VerifyWitnessCosignature(withLogSig, cosig, PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub})
	if !r.Verified {
		t.Fatalf("log_signature must be stripped before hashing: %+v", r)
	}
}

func TestWitnessWrongKeyRefuses(t *testing.T) {
	signer := newEd25519(t)
	other := newEd25519(t)
	cp := makeCheckpoint(nil)
	cosig := cosignatureFromMap(cosign(cp, "witness-a", signer, nil))
	r := VerifyWitnessCosignature(cp, cosig, PinnedWitnessKey{WitnessID: "witness-a", PublicKey: other.pub})
	if r.Verified {
		t.Fatal("wrong key must refuse")
	}
}

func TestWitnessUnpinnedRefuses(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(nil)
	cosig := cosignatureFromMap(cosign(cp, "witness-stranger", w, nil))
	r := VerifyWitnessCosignature(cp, cosig, PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub})
	if r.Verified {
		t.Fatal("unpinned must refuse")
	}
}

func TestWitnessTamperedCheckpointRefuses(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(nil)
	cosig := cosign(cp, "witness-a", w, map[string]any{"root_hash": nil}) // drop echoed root_hash
	tampered := makeCheckpoint(map[string]any{"root_hash": "sha256:" + repeat("ff", 32)})
	r := VerifyWitnessCosignature(tampered, cosignatureFromMap(cosig), PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub})
	if r.Verified {
		t.Fatal("tampered checkpoint must refuse")
	}
}

func TestWitnessEchoDifferentHeadRefuses(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(map[string]any{"tree_size": json.Number("42")})
	cosig := cosignatureFromMap(cosign(cp, "witness-a", w, nil)) // echoes tree_size 42
	otherHead := makeCheckpoint(map[string]any{"tree_size": json.Number("100")})
	r := VerifyWitnessCosignature(otherHead, cosig, PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub})
	if r.Verified {
		t.Fatal("cosignature for a different head must refuse")
	}
}

func TestWitnessEchoDifferentLogRefuses(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(map[string]any{"log_key_id": "ep:log:test#1"})
	cosig := cosignatureFromMap(cosign(cp, "witness-a", w, nil))
	otherLog := makeCheckpoint(map[string]any{"log_key_id": "ep:log:evil#9"})
	r := VerifyWitnessCosignature(otherLog, cosig, PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub})
	if r.Verified {
		t.Fatal("cosignature for a different log must refuse")
	}
}

func TestWitnessDomainSeparation(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(nil)
	// Sign exactly as the LOG does: SHA-256(canonicalize(checkpoint)) with NO tag.
	signed := committedCheckpoint(cp)
	logDigest := sha256.Sum256([]byte(Canonicalize(signed)))
	logSig := ed25519.Sign(w.priv, logDigest[:])
	forged := map[string]any{
		"alg":        WitnessVersion,
		"witness_id": "witness-a",
		"tree_size":  cp["tree_size"],
		"root_hash":  cp["root_hash"],
		"log_key_id": cp["log_key_id"],
		"signature":  base64.RawURLEncoding.EncodeToString(logSig),
	}
	r := VerifyWitnessCosignature(cp, cosignatureFromMap(forged), PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub})
	if r.Verified {
		t.Fatal("a log signature must not be replayable as a witness cosignature")
	}
}

func TestWitnessSigningDigestIncludesDomainTag(t *testing.T) {
	cp := makeCheckpoint(nil)
	signed := committedCheckpoint(cp)
	witnessPre := append([]byte(WitnessDomainTag), []byte(Canonicalize(signed))...)
	expected := sha256.Sum256(witnessPre)
	got := WitnessSigningDigest(cp)
	if len(got) != 32 {
		t.Fatalf("digest len=%d", len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatal("witness digest mismatch")
		}
	}
	logDigest := sha256.Sum256([]byte(Canonicalize(signed)))
	same := true
	for i := range logDigest {
		if got[i] != logDigest[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("witness digest must differ from the log's tag-less digest")
	}
}

func TestWitnessMalformedInputsRefuse(t *testing.T) {
	w := newEd25519(t)
	cp := makeCheckpoint(nil)
	good := cosign(cp, "witness-a", w, nil)
	pin := PinnedWitnessKey{WitnessID: "witness-a", PublicKey: w.pub}

	if VerifyWitnessCosignature(nil, cosignatureFromMap(good), pin).Verified {
		t.Fatal("nil checkpoint")
	}
	if VerifyWitnessCosignature(cp, cosignatureFromMap(good), PinnedWitnessKey{WitnessID: "witness-a"}).Verified {
		t.Fatal("missing pinned pubkey")
	}
	if VerifyWitnessCosignature(cp, cosignatureFromMap(good), PinnedWitnessKey{PublicKey: w.pub}).Verified {
		t.Fatal("missing pinned id")
	}
	if VerifyWitnessCosignature(cp, cosignatureFromMap(cosign(cp, "witness-a", w, map[string]any{"signature": nil})), pin).Verified {
		t.Fatal("missing signature")
	}
	if VerifyWitnessCosignature(cp, cosignatureFromMap(cosign(cp, "witness-a", w, map[string]any{"witness_id": nil})), pin).Verified {
		t.Fatal("missing witness_id")
	}
	if VerifyWitnessCosignature(cp, cosignatureFromMap(cosign(cp, "witness-a", w, map[string]any{"alg": "WRONG"})), pin).Verified {
		t.Fatal("wrong alg")
	}
}

// ── k-of-n quorum ────────────────────────────────────────────────────────────

func TestWitnessQuorumAcceptsKDistinct(t *testing.T) {
	wA, wB, wC := newEd25519(t), newEd25519(t), newEd25519(t)
	cp := makeCheckpoint(nil)
	pinned := []PinnedWitnessKey{
		{WitnessID: "a", PublicKey: wA.pub},
		{WitnessID: "b", PublicKey: wB.pub},
		{WitnessID: "c", PublicKey: wC.pub},
	}
	cosigs := []map[string]any{cosign(cp, "a", wA, nil), cosign(cp, "b", wB, nil), cosign(cp, "c", wC, nil)}
	r := RequireWitnessQuorum(cp, cosigs, pinned, 2, true)
	if !r.OK || r.Met != 3 || r.Required != 2 {
		t.Fatalf("got %+v", r)
	}
	if len(r.WitnessIDs) != 3 || r.WitnessIDs[0] != "a" || r.WitnessIDs[2] != "c" {
		t.Fatalf("witness_ids=%v", r.WitnessIDs)
	}
}

func TestWitnessQuorumRefusesKMinus1(t *testing.T) {
	wA, wB, wC := newEd25519(t), newEd25519(t), newEd25519(t)
	cp := makeCheckpoint(nil)
	pinned := []PinnedWitnessKey{
		{WitnessID: "a", PublicKey: wA.pub},
		{WitnessID: "b", PublicKey: wB.pub},
		{WitnessID: "c", PublicKey: wC.pub},
	}
	cosigs := []map[string]any{cosign(cp, "a", wA, nil), cosign(cp, "b", wB, nil)}
	r := RequireWitnessQuorum(cp, cosigs, pinned, 3, true)
	if r.OK || r.Met != 2 || r.Required != 3 {
		t.Fatalf("got %+v", r)
	}
}

func TestWitnessQuorumDuplicateCountedOnce(t *testing.T) {
	wA, wB := newEd25519(t), newEd25519(t)
	cp := makeCheckpoint(nil)
	pinned := []PinnedWitnessKey{{WitnessID: "a", PublicKey: wA.pub}, {WitnessID: "b", PublicKey: wB.pub}}
	cosigs := []map[string]any{cosign(cp, "a", wA, nil), cosign(cp, "a", wA, nil)}
	r := RequireWitnessQuorum(cp, cosigs, pinned, 2, true)
	if r.OK || r.Met != 1 {
		t.Fatalf("got %+v", r)
	}
	if len(r.WitnessIDs) != 1 || r.WitnessIDs[0] != "a" {
		t.Fatalf("witness_ids=%v", r.WitnessIDs)
	}
	if !containsReason(r.Reasons, `duplicate cosignature from witness "a"`) {
		t.Fatalf("reasons=%v", r.Reasons)
	}
}

func TestWitnessQuorumIgnoresUnpinned(t *testing.T) {
	wA, wB, wStranger := newEd25519(t), newEd25519(t), newEd25519(t)
	cp := makeCheckpoint(nil)
	pinned := []PinnedWitnessKey{{WitnessID: "a", PublicKey: wA.pub}, {WitnessID: "b", PublicKey: wB.pub}}
	cosigs := []map[string]any{cosign(cp, "a", wA, nil), cosign(cp, "stranger", wStranger, nil)}
	r := RequireWitnessQuorum(cp, cosigs, pinned, 2, true)
	if r.OK || r.Met != 1 {
		t.Fatalf("got %+v", r)
	}
	if !containsReason(r.Reasons, `unpinned witness "stranger"`) {
		t.Fatalf("reasons=%v", r.Reasons)
	}
}

func TestWitnessQuorumIgnoresDifferentHead(t *testing.T) {
	wA, wB := newEd25519(t), newEd25519(t)
	cp := makeCheckpoint(map[string]any{"tree_size": json.Number("42")})
	otherHead := makeCheckpoint(map[string]any{"tree_size": json.Number("99")})
	pinned := []PinnedWitnessKey{{WitnessID: "a", PublicKey: wA.pub}, {WitnessID: "b", PublicKey: wB.pub}}
	cosigs := []map[string]any{cosign(cp, "a", wA, nil), cosign(otherHead, "b", wB, nil)}
	r := RequireWitnessQuorum(cp, cosigs, pinned, 2, true)
	if r.OK || r.Met != 1 {
		t.Fatalf("got %+v", r)
	}
	if len(r.WitnessIDs) != 1 || r.WitnessIDs[0] != "a" {
		t.Fatalf("witness_ids=%v", r.WitnessIDs)
	}
}

func TestWitnessQuorumDropsAmbiguousPinned(t *testing.T) {
	wA1, wA2, wB := newEd25519(t), newEd25519(t), newEd25519(t)
	cp := makeCheckpoint(nil)
	pinned := []PinnedWitnessKey{
		{WitnessID: "a", PublicKey: wA1.pub},
		{WitnessID: "a", PublicKey: wA2.pub},
		{WitnessID: "b", PublicKey: wB.pub},
	}
	cosigs := []map[string]any{cosign(cp, "a", wA1, nil), cosign(cp, "b", wB, nil)}
	r := RequireWitnessQuorum(cp, cosigs, pinned, 2, true)
	if r.OK || r.Met != 1 {
		t.Fatalf("got %+v", r)
	}
	if !containsReason(r.Reasons, "appears more than once") {
		t.Fatalf("reasons=%v", r.Reasons)
	}
}

func TestWitnessQuorumFailClosedBadInputs(t *testing.T) {
	cp := makeCheckpoint(nil)
	if RequireWitnessQuorum(cp, []map[string]any{}, []PinnedWitnessKey{}, 0, true).OK {
		t.Fatal("k=0")
	}
	if RequireWitnessQuorum(cp, []map[string]any{}, []PinnedWitnessKey{}, 0, false).OK {
		t.Fatal("k invalid (e.g. non-integer)")
	}
	if RequireWitnessQuorum(nil, []map[string]any{}, []PinnedWitnessKey{}, 1, true).OK {
		t.Fatal("nil checkpoint")
	}
	if RequireWitnessQuorum(cp, nil, []PinnedWitnessKey{}, 1, true).OK {
		t.Fatal("nil cosignatures")
	}
	if RequireWitnessQuorum(cp, []map[string]any{}, nil, 1, true).OK {
		t.Fatal("nil pinned keys")
	}
}

func containsReason(reasons []string, substr string) bool {
	for _, r := range reasons {
		if len(substr) == 0 {
			return true
		}
		if indexOf(r, substr) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
