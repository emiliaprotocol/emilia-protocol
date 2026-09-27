// SPDX-License-Identifier: Apache-2.0
// Published -02 verifier must not silently accept an unpublished -04 option.
package emiliaverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolutionSourceVersionGate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "resolution.v1.json"))
	if err != nil {
		t.Fatalf("read resolution vectors: %v", err)
	}
	var suite struct {
		Vectors []struct {
			ID                     string                       `json:"id"`
			Receipt                map[string]any               `json:"resolution_receipt"`
			BindingMoment          map[string]any               `json:"binding_moment"`
			ExpectedActionHash     string                       `json:"expected_action_hash"`
			ExpectedSelectedOption int                          `json:"expected_selected_option"`
			ExpectedNonce          string                       `json:"expected_nonce"`
			ExpectedInitiator      string                       `json:"expected_initiator"`
			EvaluationTime         string                       `json:"evaluation_time"`
			RPID                   string                       `json:"rp_id"`
			AllowedOrigins         []string                     `json:"allowed_origins"`
			PrincipalKeys          map[string]map[string]string `json:"principal_keys"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("parse resolution vectors: %v", err)
	}
	for _, vector := range suite.Vectors {
		if vector.ID != "accept_approved" {
			continue
		}
		opts := ResolutionOptions{
			BindingMoment: vector.BindingMoment, ExpectedActionHash: vector.ExpectedActionHash,
			ExpectedSelectedOption: &vector.ExpectedSelectedOption, ExpectedNonce: vector.ExpectedNonce,
			ExpectedInitiator: vector.ExpectedInitiator, EvaluationTime: vector.EvaluationTime,
			PrincipalKeys: vector.PrincipalKeys, RPID: vector.RPID, AllowedOrigins: vector.AllowedOrigins,
		}
		if result := VerifyResolutionReceipt(vector.Receipt, opts); !result.AuthorizesAction {
			t.Fatalf("control vector does not authorize: %+v", result)
		}
		vector.Receipt["profile"] = "EP-RESOLUTION-BME04-CANDIDATE-v1"
		if result := VerifyResolutionReceipt(vector.Receipt, opts); result.Valid || result.Reason != "malformed_resolution_receipt" {
			t.Fatalf("candidate profile relabel accepted: %+v", result)
		}
		vector.Receipt["profile"] = ResolutionVersion
		options, ok := getMap(vector.BindingMoment["question"])["options"].([]any)
		if !ok || len(options) != 2 {
			t.Fatal("unexpected published -02 option fixture")
		}
		getMap(options[0])["action_digest"] = vector.ExpectedActionHash
		getMap(options[1])["action_digest"] = "sha256:" + strings.Repeat("b", 64)
		if result := VerifyResolutionReceipt(vector.Receipt, opts); result.Valid || result.AuthorizesAction || result.Reason != "malformed_binding_moment" {
			t.Fatalf("unpublished option member accepted by v1: %+v", result)
		}
		return
	}
	t.Fatal("accept_approved vector not found")
}
