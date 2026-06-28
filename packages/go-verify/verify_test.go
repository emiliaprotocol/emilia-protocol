// SPDX-License-Identifier: Apache-2.0

package emiliaverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// load returns the JS-signed receipt fixture and its base64url public key.
// These are byte-identical to packages/python-verify/tests/fixtures — the same
// receipt the Python verifier checks — so a pass here proves Go, JS, and
// Python agree on the canonical bytes.
func load(t *testing.T) ([]byte, string) {
	t.Helper()
	receipt, err := os.ReadFile(filepath.Join("testdata", "receipt.json"))
	if err != nil {
		t.Fatalf("read receipt fixture: %v", err)
	}
	pub, err := os.ReadFile(filepath.Join("testdata", "pubkey.txt"))
	if err != nil {
		t.Fatalf("read pubkey fixture: %v", err)
	}
	return receipt, strings.TrimSpace(string(pub))
}

func decodeT(t *testing.T, data []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

func randomPubKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// TestValidReceiptFromJS verifies a receipt signed on the JavaScript side.
func TestValidReceiptFromJS(t *testing.T) {
	data, pub := load(t)
	// Shared cross-language fixture carries an EP-MERKLE-v2 (domain-separated,
	// payload-bound) anchor, so it verifies by default — no legacy opt-in needed.
	r := VerifyReceiptJSON(data, pub)
	if !r.Valid {
		t.Fatalf("expected valid receipt, got %+v (err=%q)", r.Checks, r.Error)
	}
	if !r.Checks.Version || !r.Checks.Signature {
		t.Fatalf("version/signature failed: %+v", r.Checks)
	}
	if r.Checks.Anchor == nil || !*r.Checks.Anchor {
		t.Fatalf("anchor check failed: %+v", r.Checks)
	}
}

// TestTamperedPayloadFails proves a single changed field breaks the signature.
func TestTamperedPayloadFails(t *testing.T) {
	data, pub := load(t)
	doc := decodeT(t, data)
	ctx := doc["payload"].(map[string]any)["claim"].(map[string]any)["context"].(map[string]any)
	ctx["amount"] = json.Number("1") // was 50000, changed after signing
	r := VerifyReceipt(doc, pub)
	if r.Valid {
		t.Fatal("expected invalid after payload tamper")
	}
	if r.Checks.Signature {
		t.Fatal("expected signature=false after payload tamper")
	}
}

// TestWrongKeyFails proves an unrelated key does not verify the signature.
func TestWrongKeyFails(t *testing.T) {
	data, _ := load(t)
	r := VerifyReceiptJSON(data, randomPubKey(t))
	if r.Valid {
		t.Fatal("expected invalid with wrong key")
	}
	if r.Checks.Signature {
		t.Fatal("expected signature=false with wrong key")
	}
}

// TestTamperedAnchorFails proves a broken Merkle root is rejected.
func TestTamperedAnchorFails(t *testing.T) {
	data, pub := load(t)
	doc := decodeT(t, data)
	doc["anchor"].(map[string]any)["merkle_root"] = strings.Repeat("0", 64)
	r := VerifyReceipt(doc, pub)
	if r.Valid {
		t.Fatal("expected invalid after anchor tamper")
	}
	if r.Checks.Anchor == nil || *r.Checks.Anchor {
		t.Fatalf("expected anchor=false after tamper: %+v", r.Checks)
	}
}

// TestCanonicalizeVectors locks the canonical-JSON encoding (depth-first key
// sort, order-preserved arrays, JSON.stringify-compatible scalars).
func TestCanonicalizeVectors(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"z":[3,1,2],"a":{"y":true,"x":null},"s":"hi"}`, `{"a":{"x":null,"y":true},"s":"hi","z":[3,1,2]}`},
		{`{"amount":50000,"ok":false}`, `{"amount":50000,"ok":false}`},
		{`{"nested":{"b":1,"a":2}}`, `{"nested":{"a":2,"b":1}}`},
		{`{"@version":"EP-RECEIPT-v1","action":{"action_type":"payment.release","amount_usd":1.0,"risk_score":-0.0},"context":{"�":"replacement_char","🙂":"slight_smile"},"entity_id":"ep_entity_poc_test","signoffs":[]}`, `{"@version":"EP-RECEIPT-v1","action":{"action_type":"payment.release","amount_usd":1,"risk_score":0},"context":{"🙂":"slight_smile","�":"replacement_char"},"entity_id":"ep_entity_poc_test","signoffs":[]}`},
	}
	for _, c := range cases {
		got := Canonicalize(decodeT(t, []byte(c.in)))
		if got != c.want {
			t.Errorf("Canonicalize(%s)\n  got  %s\n  want %s", c.in, got, c.want)
		}
	}
	// String escaping matches JSON.stringify: quote, backslash, newline, tab.
	if got := encodeString("a\"b\\c\n\t"); got != `"a\"b\\c\n\t"` {
		t.Errorf("encodeString escaping wrong: %s", got)
	}
	edge := Canonicalize(decodeT(t, []byte(cases[3].in)))
	sum := sha256.Sum256([]byte(edge))
	if got := hex.EncodeToString(sum[:]); got != "49c642930186d4ed0324c6099f077c38a16cac19e327c2f58bb76f19a33351b2" {
		t.Fatalf("edge vector hash mismatch: %s", got)
	}
	if IsCanonicalizable(decodeT(t, []byte(`{"unsafe":1e20}`))) {
		t.Fatal("unsafe non-safe integer must be outside canonicalization profile")
	}
	if IsCanonicalizable(decodeT(t, []byte(`{"fractional":1.25}`))) {
		t.Fatal("fractional number must be outside canonicalization profile")
	}
}

// TestMerkleAnchorDirect exercises the proof folder independently of a receipt.
func TestMerkleAnchorDirect(t *testing.T) {
	// leaf folded with one right sibling: root = sha256(sorted(leaf+sib)).
	leaf := "778cca54937b133e6c71ed13ea953a2579588c641782e0e15ab3339a84560609"
	sib := "c91e40cb06ad90f0a4556fcc54d9489f7f59cca27494ae05ffe411ee9fdaaed7"
	root := "78be6a4b21e0e3280d6bf9f7d0aa2226ba9926f35cf4c298500c545e27ae5ead"
	proof := []any{map[string]any{"hash": sib, "position": "right"}}
	if !VerifyMerkleAnchor(leaf, proof, root) {
		t.Fatal("expected valid Merkle proof")
	}
	if VerifyMerkleAnchor(leaf, proof, strings.Repeat("f", 64)) {
		t.Fatal("expected invalid against wrong root")
	}
}
