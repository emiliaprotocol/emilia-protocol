// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Regression (P0 fail-open, found by the surface audit): VerifyProvenanceOffline
// read opts["now"] with a bare .(float64), so when `now` arrived as json.Number
// from the UseNumber decode path (the documented entry point) the assertion failed,
// hasNow stayed false, and the delegations_not_expired gate was SKIPPED entirely —
// an expired delegation verified as not-expired. JS defaults now to Date.now() and
// always enforces expiry; this brings the Go port to parity.
//
// The test loads a real accept vector and drives execution FAR past every delegation
// expiry via a json.Number `now`; the chain must then fail delegations_not_expired.
// Before the fix, the json.Number path disabled the gate and the doc stayed valid.

type provAcceptVector struct {
	doc            map[string]any
	delegationKeys any
	nowMs          *float64
}

func loadFirstProvenanceAccept(t *testing.T) *provAcceptVector {
	t.Helper()
	raw, err := os.ReadFile("../../conformance/vectors/provenance.exec.v1.json")
	if err != nil {
		t.Skipf("vector file unavailable: %v", err)
	}
	var suite struct {
		Vectors []struct {
			Expect          map[string]any `json:"expect"`
			ProvenanceChain map[string]any `json:"provenance_chain"`
			DelegationKeys  any            `json:"delegation_keys"`
			NowMs           *float64       `json:"now_ms"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("decode suite: %v", err)
	}
	for _, v := range suite.Vectors {
		if valid, _ := v.Expect["valid"].(bool); valid {
			return &provAcceptVector{doc: v.ProvenanceChain, delegationKeys: v.DelegationKeys, nowMs: v.NowMs}
		}
	}
	t.Skip("no accept vector present")
	return nil
}

func TestProvenanceExpiryGateNotSkippedUnderJSONNumberNow(t *testing.T) {
	vec := loadFirstProvenanceAccept(t)
	if vec == nil {
		return
	}

	// Baseline: at the vector's own `now`, the accept vector verifies.
	if vec.nowMs != nil {
		base := VerifyProvenanceOffline(vec.doc, map[string]any{"delegationKeys": vec.delegationKeys, "now": *vec.nowMs})
		if !base.Valid {
			t.Fatalf("baseline accept vector did not verify at its own now")
		}
	}

	// Fail-open trigger: `now` in the year 2100, decoded as json.Number (the
	// documented UseNumber path). Every delegation is long expired, so the gate
	// MUST fire. Before the fix, json.Number failed the .(float64) assertion and
	// the gate was skipped, leaving the doc valid.
	var nowJN any
	dec := json.NewDecoder(strings.NewReader("4102444800000")) // 2100-01-01
	dec.UseNumber()
	if err := dec.Decode(&nowJN); err != nil {
		t.Fatalf("decode json.Number now: %v", err)
	}
	res := VerifyProvenanceOffline(vec.doc, map[string]any{"delegationKeys": vec.delegationKeys, "now": nowJN})
	if res.Checks["delegations_not_expired"] {
		t.Fatalf("fail-open: delegations_not_expired stayed true under a year-2100 json.Number now; the expiry gate was skipped")
	}
	if res.Valid {
		t.Fatalf("fail-open: an expired chain verified as valid under a json.Number now")
	}
}
