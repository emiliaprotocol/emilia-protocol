// SPDX-License-Identifier: Apache-2.0

package emiliaverify

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type trustReceiptVector struct {
	ID           string         `json:"id"`
	TrustReceipt map[string]any `json:"trust_receipt"`
	Verification map[string]any `json:"verification"`
}

func loadTrustReceiptVector(t *testing.T, vectorID string) trustReceiptVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "trust-receipt.exec.v1.json"))
	if err != nil {
		t.Fatalf("read trust receipt vectors: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var corpus struct {
		Vectors []trustReceiptVector `json:"vectors"`
	}
	if err := dec.Decode(&corpus); err != nil {
		t.Fatalf("decode trust receipt vectors: %v", err)
	}
	for _, vector := range corpus.Vectors {
		if vector.ID == vectorID {
			return vector
		}
	}
	t.Fatalf("trust receipt vector %q not found", vectorID)
	return trustReceiptVector{}
}

func TestContextAuthorizesOnlyApprovedOrLegacyDecisions(t *testing.T) {
	if !contextAuthorizes(map[string]any{}) {
		t.Fatal("legacy context without a decision must remain compatible")
	}
	if !contextAuthorizes(map[string]any{"decision": "approved"}) {
		t.Fatal("approved decision must authorize")
	}
	for _, decision := range []any{"denied", "pending", nil, json.Number("1"), map[string]any{"outcome": "approved"}} {
		if contextAuthorizes(map[string]any{"decision": decision}) {
			t.Fatalf("non-approved decision %#v must not authorize", decision)
		}
	}
}

func TestCryptographicallyValidSignedDenialDoesNotAuthorize(t *testing.T) {
	vector := loadTrustReceiptVector(t, "reject_signed_denial_as_authorization")
	result := VerifyTrustReceipt(vector.TrustReceipt, map[string]any{
		"approverKeys": vector.Verification["approver_keys"],
		"logPublicKey": vector.Verification["log_public_key"],
	})

	if !result.Checks["context_commitments"] || !result.Checks["signoff_signatures"] || !result.Checks["windows"] {
		t.Fatalf("signed denial must remain valid decision evidence: %+v", result.Checks)
	}
	if result.Checks["sod"] || result.Valid {
		t.Fatalf("signed denial must not satisfy approval quorum or authorization: %+v", result.Checks)
	}
}
