// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadOutcomeSuite(t *testing.T, name string) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "conformance", "vectors", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var suite map[string]any
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	return suite
}

func outcomeVectors(t *testing.T, suite map[string]any) []any {
	t.Helper()
	vectors, ok := suite["vectors"].([]any)
	if !ok {
		t.Fatal("suite vectors missing")
	}
	return vectors
}

func runOutcomeExecVector(t *testing.T, suite, vector map[string]any) OutcomeBindingResult {
	t.Helper()
	common := getMap(suite["common"])
	options := map[string]any{
		"receiptOptions": common["receipt_options"],
		"executorKeys":   common["executor_keys"],
		"now":            common["now"],
	}
	if executorKeys, present := vector["executor_keys"]; present {
		options["executorKeys"] = executorKeys
	}
	if policy, present := vector["policy_predicted_effects"]; present {
		options["policyPredictedEffects"] = policy
	}
	return VerifyOutcomeBinding(
		getMap(common["receipt"]),
		getMap(vector["attestation"]),
		options,
	)
}

func TestOutcomeExistingPredicateVectors(t *testing.T) {
	suite := loadOutcomeSuite(t, "outcome-binding.v1.json")
	count := 0
	for _, raw := range outcomeVectors(t, suite) {
		vector := getMap(raw)
		if getStr(vector, "kind") != "predicate" {
			continue
		}
		count++
		result := EvaluatePredictedEffects(vector["predicted_effects"], vector["observed_effects"])
		expect := getMap(vector["expect"])
		if result.Outcome != getStr(expect, "outcome") {
			t.Fatalf("%s outcome=%s want=%s reasons=%v", getStr(vector, "id"), result.Outcome, getStr(expect, "outcome"), result.Reasons)
		}
		if containsReason := getStr(expect, "reason_contains"); containsReason != "" &&
			!strings.Contains(strings.Join(result.Reasons, " "), containsReason) {
			t.Fatalf("%s reasons=%v missing %q", getStr(vector, "id"), result.Reasons, containsReason)
		}
	}
	if count != 24 {
		t.Fatalf("predicate vector count=%d want=24", count)
	}
}

func TestOutcomeExistingRealCryptoVectorsMatchJSDigests(t *testing.T) {
	suite := loadOutcomeSuite(t, "outcome-binding.exec.v1.json")
	vectors := outcomeVectors(t, suite)
	if len(vectors) != 10 {
		t.Fatalf("exec vector count=%d want=10", len(vectors))
	}
	for _, raw := range vectors {
		vector := getMap(raw)
		id := getStr(vector, "id")
		first := runOutcomeExecVector(t, suite, vector)
		second := runOutcomeExecVector(t, suite, vector)
		expectedOutcome := getStr(getMap(vector["expect"]), "outcome")
		if first.Valid != (expectedOutcome == "in_bounds") {
			t.Fatalf("%s valid=%v outcome=%s errors=%v", id, first.Valid, first.OutcomeBinding.Outcome, first.Errors)
		}
		if first.OutcomeBinding.Outcome != expectedOutcome {
			t.Fatalf("%s outcome=%s want=%s errors=%v", id, first.OutcomeBinding.Outcome, expectedOutcome, first.Errors)
		}
		expectedDigest := getStr(getMap(vector["expect"]), "result_digest")
		if first.ResultDigest != expectedDigest {
			t.Fatalf("%s digest=%s want=%s", id, first.ResultDigest, expectedDigest)
		}
		if second.ResultDigest != first.ResultDigest {
			t.Fatalf("%s result digest is not deterministic", id)
		}
	}
}

func TestOutcomeReceiptActionNonceAndKeyBindings(t *testing.T) {
	suite := loadOutcomeSuite(t, "outcome-binding.exec.v1.json")
	expected := map[string][2]string{
		"reject_resigned_receipt_id_swap":        {"receipt_bound", "receipt_id_mismatch"},
		"reject_resigned_receipt_bytes_swap":     {"receipt_digest_bound", "receipt_digest_mismatch"},
		"reject_resigned_action_swap":            {"action_bound", "action_hash_mismatch"},
		"reject_resigned_consumption_nonce_swap": {"consumption_bound", "consumption_nonce_mismatch"},
		"reject_unpinned_executor":               {"attestation_verified", "executor_key_not_pinned"},
	}
	for _, raw := range outcomeVectors(t, suite) {
		vector := getMap(raw)
		id := getStr(vector, "id")
		want, relevant := expected[id]
		if !relevant {
			continue
		}
		result := runOutcomeExecVector(t, suite, vector)
		if result.Checks[want[0]] {
			t.Fatalf("%s check %s unexpectedly passed", id, want[0])
		}
		if !contains(result.Errors, want[1]) {
			t.Fatalf("%s errors=%v missing %s", id, result.Errors, want[1])
		}
	}
}

func TestOutcomePolicyOnlyTightens(t *testing.T) {
	suite := loadOutcomeSuite(t, "outcome-binding.exec.v1.json")
	for _, raw := range outcomeVectors(t, suite) {
		vector := getMap(raw)
		switch getStr(vector, "id") {
		case "reject_signed_effect_divergence":
			result := runOutcomeExecVector(t, suite, vector)
			evaluation := result.OutcomeBinding.Evaluations[0]
			if evaluation.Source != "signed_receipt" || evaluation.Outcome != "divergent" {
				t.Fatalf("signed baseline was not independently enforced: %+v", evaluation)
			}
		case "reject_policy_tightening_divergence":
			result := runOutcomeExecVector(t, suite, vector)
			evaluations := result.OutcomeBinding.Evaluations
			if len(evaluations) != 2 ||
				evaluations[0].Source != "signed_receipt" ||
				evaluations[0].Outcome != "in_bounds" ||
				evaluations[1].Source != "relying_party_policy" ||
				evaluations[1].Outcome != "divergent" {
				t.Fatalf("policy did not behave as an additive refusal: %+v", evaluations)
			}
		}
	}
}

func TestOutcomeExactDecimals(t *testing.T) {
	cases := []struct {
		left, right string
		want        int
		ok          bool
	}{
		{"9007199254740993", "9007199254740992", 1, true},
		{"0.1", "0.10", 0, true},
		{"-2", "-1.99", -1, true},
		{"-0", "0.000", 0, true},
		{"01", "1", 0, false},
		{"1e3", "1000", 0, false},
	}
	for _, tc := range cases {
		got, ok := CompareDecimalStrings(tc.left, tc.right)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("CompareDecimalStrings(%q,%q)=(%d,%v) want=(%d,%v)", tc.left, tc.right, got, ok, tc.want, tc.ok)
		}
	}
}

func TestOutcomeClosedMembersAndLimits(t *testing.T) {
	suite := loadOutcomeSuite(t, "outcome-binding.exec.v1.json")
	common := getMap(suite["common"])
	first := getMap(outcomeVectors(t, suite)[0])
	base := getMap(first["attestation"])
	opts := map[string]any{"executorKeys": common["executor_keys"], "now": common["now"]}

	hostileTop := cloneOutcomeMap(t, base)
	hostileTop["predicted_effects"] = []any{}
	result := VerifyOutcomeAttestation(hostileTop, opts)
	if result.Valid || !contains(result.Errors, "malformed_outcome_attestation") {
		t.Fatalf("unknown top member was not refused: %+v", result)
	}

	hostileObserved := cloneOutcomeMap(t, base)
	observed, _ := outcomeAnySlice(hostileObserved["observed_effects"])
	getMap(observed[0])["ignored_limit"] = "999999.00"
	result = VerifyOutcomeAttestation(hostileObserved, opts)
	if result.Valid || !strings.Contains(strings.Join(result.Errors, " "), "not an exact observed-effect object") {
		t.Fatalf("unknown observed member was not refused: %+v", result)
	}

	oversizedObserved := cloneOutcomeMap(t, base)
	items := make([]any, MaxObservedEffects+1)
	for i := range items {
		items[i] = map[string]any{"effect_type": "payment", "target": "acct:x", "value": "1.00"}
	}
	oversizedObserved["observed_effects"] = items
	result = VerifyOutcomeAttestation(oversizedObserved, opts)
	if !strings.Contains(strings.Join(result.Errors, " "), "256-entry limit") {
		t.Fatalf("oversized observations were not refused: %+v", result)
	}

	tooManyPredictions := make([]any, MaxPredictedEffects+1)
	for i := range tooManyPredictions {
		tooManyPredictions[i] = map[string]any{
			"effect_type": "payment",
			"target":      "acct:x",
			"predicate":   map[string]any{"op": "absent"},
		}
	}
	validation := ValidatePredictedEffects(tooManyPredictions)
	if validation.OK || !strings.Contains(strings.Join(validation.Reasons, " "), "64-entry limit") {
		t.Fatalf("oversized predictions were not refused: %+v", validation)
	}
}

func TestOutcomeUnknownMembersAreNeverIgnored(t *testing.T) {
	prediction := []any{map[string]any{
		"effect_type": "payment",
		"target":      "acct:a",
		"predicate": map[string]any{
			"op": "lte", "value": "1", "tolerance": "0.1",
		},
	}}
	if ValidatePredictedEffects(prediction).OK {
		t.Fatal("unknown predicate member was ignored")
	}
	result := EvaluatePredictedEffects(
		[]any{map[string]any{
			"effect_type": "payment", "target": "acct:a",
			"predicate": map[string]any{"op": "lte", "value": "1"},
		}},
		[]any{map[string]any{
			"effect_type": "payment", "target": "acct:a", "value": "1", "ignored": "2",
		}},
	)
	if result.Outcome != "incomparable" || !strings.Contains(strings.Join(result.Reasons, " "), "unknown member") {
		t.Fatalf("unknown observation member was ignored: %+v", result)
	}
}

func cloneOutcomeMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
