// SPDX-License-Identifier: Apache-2.0
//
// Cross-language conformance + unit coverage for the RFC 3161 timestamp-proof Go
// port. Runs the SHARED conformance/vectors/timestamp-proof.v1.json (the same
// file the JS and Python lanes consume, produced by
// conformance/vectors/generate-timestamp-proof.mjs) through VerifyTimestampProof
// and asserts every vector's expect.valid. A pass proves the Go verifier agrees
// with the JS reference on each accept/refuse decision over identical token
// bytes. The reason-string assertions below additionally pin that the Go port
// refuses along the SAME distinct path as the JS/Python references.
package emiliaverify

import (
	"testing"
)

// tspPinnedKeysFromAny normalizes the polymorphic `pinned_tsa_keys` vector field
// (a single string, a []any of strings, or a map[string]any {id: key}) into the
// []string the Go verifier takes. Mirrors the JS pinnedList assembly.
func tspPinnedKeysFromAny(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func TestTimestampProofVectors(t *testing.T) {
	suite := loadSuite(t, "timestamp-proof.v1.json")
	vectors := suiteVectors(t, suite, "timestamp-proof.v1.json")
	if len(vectors) == 0 {
		t.Fatal("no timestamp-proof vectors")
	}
	for _, v := range vectors {
		id := vecID(v)
		tp, _ := v["timestamp_proof"].(string)
		ed, _ := v["expected_digest"].(string)
		keys := tspPinnedKeysFromAny(v["pinned_tsa_keys"])
		got := VerifyTimestampProof(tp, ed, keys).Verified
		want := expectValid(v)
		if got != want {
			t.Errorf("%s: Verified=%v want %v", id, got, want)
		}
	}
}

// TestTimestampProofReasons pins the DISTINCT refusal path for each reject
// vector, so the Go port refuses for the same reason as the JS reference (not
// merely "some" refusal). It re-reads the shared suite and asserts per-id.
func TestTimestampProofReasons(t *testing.T) {
	suite := loadSuite(t, "timestamp-proof.v1.json")
	vectors := suiteVectors(t, suite, "timestamp-proof.v1.json")
	byID := map[string]map[string]any{}
	for _, v := range vectors {
		byID[vecID(v)] = v
	}
	run := func(id string) TimestampProofResult {
		v := byID[id]
		if v == nil {
			t.Fatalf("vector %s missing from suite", id)
		}
		tp, _ := v["timestamp_proof"].(string)
		ed, _ := v["expected_digest"].(string)
		return VerifyTimestampProof(tp, ed, tspPinnedKeysFromAny(v["pinned_tsa_keys"]))
	}

	// Accept: tsa_key_id is the SHA-256 fingerprint of the pinned SPKI; gen_time
	// is a well-formed RFC 3339 UTC instant ending in Z.
	acc := run("accept_authentic_pinned_rsa_sha256")
	if !acc.Verified {
		t.Fatalf("accept vector refused: %s", acc.Reason)
	}
	if len(acc.TSAKeyID) != len("sha256:")+64 || acc.TSAKeyID[:7] != "sha256:" {
		t.Errorf("tsa_key_id malformed: %q", acc.TSAKeyID)
	}
	if len(acc.GenTime) == 0 || acc.GenTime[len(acc.GenTime)-1] != 'Z' {
		t.Errorf("gen_time not a UTC instant: %q", acc.GenTime)
	}

	cases := map[string]string{
		"reject_missing_token":             "missing_token",
		"reject_malformed_expected_digest": "missing_or_malformed_expected_digest",
		"reject_unpinned_tsa_empty":        "unpinned_tsa",
		"reject_unloadable_pinned_key":     "unpinned_tsa",
		"reject_digest_mismatch":           "digest_mismatch",
		"reject_wrong_pinned_key":          "bad_signature",
		"reject_tampered_signature":        "bad_signature",
		"reject_unparseable_garbage":       "unparseable_token",
		"reject_not_signed_data":           "not_signed_data",
	}
	for id, wantReason := range cases {
		r := run(id)
		if r.Verified {
			t.Errorf("%s: expected refusal, got verified", id)
			continue
		}
		if r.Reason != wantReason {
			t.Errorf("%s: reason=%q want %q", id, r.Reason, wantReason)
		}
	}
}

// TestTimestampProofDigestBindsBeforeSignature checks the JS invariant that a
// wrong expected digest refuses with digest_mismatch even when the pinned key is
// the correct signer (never leaking a signature-based verdict first).
func TestTimestampProofDigestBindsBeforeSignature(t *testing.T) {
	suite := loadSuite(t, "timestamp-proof.v1.json")
	vectors := suiteVectors(t, suite, "timestamp-proof.v1.json")
	var token, correctDigest string
	var keys []string
	for _, v := range vectors {
		if vecID(v) == "accept_authentic_pinned_rsa_sha256" {
			token, _ = v["timestamp_proof"].(string)
			correctDigest, _ = v["expected_digest"].(string)
			keys = tspPinnedKeysFromAny(v["pinned_tsa_keys"])
		}
	}
	if token == "" {
		t.Fatal("could not find accept vector")
	}
	// Flip the expected digest to a different (but well-formed) 64-hex value.
	wrong := "sha256:" + repeatHex("a", 64)
	if wrong[7:] == correctDigest[len(correctDigest)-64:] {
		wrong = "sha256:" + repeatHex("b", 64)
	}
	r := VerifyTimestampProof(token, wrong, keys)
	if r.Verified || r.Reason != "digest_mismatch" {
		t.Errorf("expected digest_mismatch, got verified=%v reason=%q", r.Verified, r.Reason)
	}
}

func repeatHex(c string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = c[0]
	}
	return string(out)
}
