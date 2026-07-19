// SPDX-License-Identifier: Apache-2.0
//
// Cross-language conformance for the opt-in verify profiles. Runs the SHARED
// conformance/vectors/{currency,initiator-attestation,consumption-proof,witness}.v1.json
// (the same files the JS and Python lanes consume, produced by
// conformance/vectors/generate-optin-profiles.mjs) through the Go ports and
// asserts every vector's expect.valid. A pass proves the Go verifier agrees with
// the JS reference on each profile's accept/refuse decision over identical bytes:
//
//   - EP-CURRENCY-v1              evaluateCurrency  -> currency_at_T.status
//   - EP-INITIATOR-ATTESTATION-v1 validateInitiatorAttestation -> ok
//   - EP-SMT-CONSUME-v1           verifyConsumptionProof -> valid
//   - EP-WITNESS-v1               requireWitnessQuorum   -> ok
package emiliaverify

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadSuite(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var suite map[string]any
	if err := dec.Decode(&suite); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return suite
}

func suiteVectors(t *testing.T, suite map[string]any, name string) []map[string]any {
	t.Helper()
	raw, ok := suite["vectors"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("%s: no vectors", name)
	}
	out := make([]map[string]any, len(raw))
	for i, v := range raw {
		out[i], _ = v.(map[string]any)
	}
	return out
}

func expectValid(v map[string]any) bool {
	exp, _ := v["expect"].(map[string]any)
	b, _ := exp["valid"].(bool)
	return b
}

func vecID(v map[string]any) string {
	id, _ := v["id"].(string)
	return id
}

// ── EP-CURRENCY-v1 ────────────────────────────────────────────────────────────

func TestCurrencyVectors(t *testing.T) {
	suite := loadSuite(t, "currency.v1.json")
	for _, v := range suiteVectors(t, suite, "currency") {
		cur, _ := v["currency"].(map[string]any)
		args, _ := cur["args"].(map[string]any)
		expectStatus, _ := cur["expect_status"].(string)

		ca := currencyArgsFromMap(args)
		got := EvaluateCurrency(ca).CurrencyAtT.Status
		// The vector's expect.valid is (status === expect_status).
		gotValid := got == expectStatus
		if gotValid != expectValid(v) {
			t.Errorf("%s: status=%q expect_status=%q valid=%v want %v", vecID(v), got, expectStatus, gotValid, expectValid(v))
		}
	}
}

func currencyArgsFromMap(args map[string]any) CurrencyArgs {
	ca := CurrencyArgs{}
	if r, ok := args["receipt"].(map[string]any); ok {
		ah, _ := r["action_hash"].(string)
		ca.Receipt = &CurrencyReceipt{ActionHash: ah}
	}
	if b, ok := args["authentic_as_of_commit"].(bool); ok {
		ca.AuthenticAsOfCommit = b
	}
	if now, ok := args["now"].(string); ok {
		ca.Now = &now
	}
	if v, present := args["maxStalenessSeconds"]; present {
		if f, ok := jsonFloat(v); ok {
			ca.MaxStalenessSeconds = &f
		} else {
			// Present but non-numeric: model as an invalid bound (negative) so the
			// verifier fails closed exactly as JS does for a non-finite bound.
			neg := -1.0
			ca.MaxStalenessSeconds = &neg
		}
	}
	if b, ok := args["freshHeadRequired"].(bool); ok {
		ca.FreshHeadRequired = b
	}
	if fh, present := args["freshHead"]; present && fh != nil {
		if fhm, ok := fh.(map[string]any); ok {
			head := &FreshHead{}
			head.ObservedAt, _ = fhm["observed_at"].(string)
			head.IssuedAt, _ = fhm["issued_at"].(string)
			if b, ok := fhm["revoked"].(bool); ok {
				head.Revoked = b
			}
			head.TargetHash, _ = fhm["target_hash"].(string)
			if rl, ok := fhm["revoked_target_hashes"].([]any); ok {
				for _, h := range rl {
					if hs, ok := h.(string); ok {
						head.RevokedTargetHashes = append(head.RevokedTargetHashes, hs)
					}
				}
			}
			ca.FreshHead = head
		}
	}
	return ca
}

func jsonFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	if jn, ok := v.(interface{ Float64() (float64, error) }); ok { // json.Number
		f, err := jn.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// ── EP-INITIATOR-ATTESTATION-v1 ───────────────────────────────────────────────

func TestInitiatorVectors(t *testing.T) {
	suite := loadSuite(t, "initiator-attestation.v1.json")
	for _, v := range suiteVectors(t, suite, "initiator-attestation") {
		att, _ := v["initiator_attestation"].(map[string]any)
		got := ValidateInitiatorAttestation(att).OK
		if got != expectValid(v) {
			t.Errorf("%s: ok=%v want %v", vecID(v), got, expectValid(v))
		}
	}
}

// ── EP-SMT-CONSUME-v1 ─────────────────────────────────────────────────────────

func TestConsumptionProofVectors(t *testing.T) {
	suite := loadSuite(t, "consumption-proof.v1.json")
	for _, v := range suiteVectors(t, suite, "consumption-proof") {
		bundle, _ := v["consumption_proof"].(map[string]any)
		got := VerifyConsumptionProof(bundle).Valid
		if got != expectValid(v) {
			res := VerifyConsumptionProof(bundle)
			t.Errorf("%s: valid=%v want %v (reason=%q)", vecID(v), got, expectValid(v), res.Reason)
		}
	}
}

// ── EP-WITNESS-v1 (k-of-n quorum) ─────────────────────────────────────────────

func TestWitnessQuorumVectors(t *testing.T) {
	suite := loadSuite(t, "witness.v1.json")
	for _, v := range suiteVectors(t, suite, "witness") {
		wq, _ := v["witness_quorum"].(map[string]any)
		checkpoint, _ := wq["checkpoint"].(map[string]any)

		var cosigs []map[string]any
		if raw, ok := wq["cosignatures"].([]any); ok {
			for _, c := range raw {
				if cm, ok := c.(map[string]any); ok {
					cosigs = append(cosigs, cm)
				}
			}
		}
		if cosigs == nil {
			cosigs = []map[string]any{}
		}

		var pinned []PinnedWitnessKey
		if raw, ok := wq["pinned"].([]any); ok {
			for _, p := range raw {
				if pm, ok := p.(map[string]any); ok {
					id, _ := pm["witness_id"].(string)
					pk, _ := pm["public_key"].(string)
					pinned = append(pinned, PinnedWitnessKey{WitnessID: id, PublicKey: pk})
				}
			}
		}
		if pinned == nil {
			pinned = []PinnedWitnessKey{}
		}

		k, kValid := jsonIntStrict(wq["k"])
		got := RequireWitnessQuorum(checkpoint, cosigs, pinned, k, kValid).OK
		if got != expectValid(v) {
			t.Errorf("%s: quorum ok=%v want %v", vecID(v), got, expectValid(v))
		}
	}
}

func jsonIntStrict(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
		return 0, false
	}
	if jn, ok := v.(interface{ Int64() (int64, error) }); ok { // json.Number
		i, err := jn.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}
