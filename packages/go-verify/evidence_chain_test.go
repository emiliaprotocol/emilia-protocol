// SPDX-License-Identifier: Apache-2.0
// EP-AEC composition conformance — Go runner over the shared conformance/vectors/aec.json
// (the same file the JS and Python runners use), proving cross-language agreement.
package emiliaverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAECVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "aec.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var suite struct {
		Action    map[string]any `json:"action"`
		StubTypes []string       `json:"stub_types"`
		Vectors   []struct {
			Name          string         `json:"name"`
			Chain         map[string]any `json:"chain"`
			ExpectAllow   bool           `json:"expect_allow"`
			RPRequirement string         `json:"relying_party_requirement"`
			ExpectSource  string         `json:"expect_requirement_source"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	digest := ActionDigest(suite.Action)
	other := "sha256:" + strings.Repeat("f", 64)
	subst := func(x any) any {
		s, ok := x.(string)
		if !ok {
			return x
		}
		switch s {
		case "SAME":
			return "sha256:" + digest
		case "OTHER":
			return other
		default:
			return x
		}
	}
	stub := func(ev any, ctx map[string]any) ComponentResult {
		m, _ := ev.(map[string]any)
		valid := true
		if v, ok := m["valid"].(bool); ok {
			valid = v
		}
		ad, _ := m["action_digest"].(string)
		return ComponentResult{Valid: valid, ActionDigest: ad}
	}
	verifiers := map[string]ComponentVerifier{}
	for _, ty := range suite.StubTypes {
		verifiers[ty] = stub
	}

	for _, v := range suite.Vectors {
		chain := v.Chain
		if _, ok := chain["action"]; !ok {
			chain["action"] = suite.Action
		}
		if _, ok := chain["action_digest"]; ok {
			chain["action_digest"] = subst(chain["action_digest"])
		}
		if comps, ok := chain["components"].([]any); ok {
			for _, ci := range comps {
				if c, ok := ci.(map[string]any); ok {
					if ev, ok := c["evidence"].(map[string]any); ok {
						if _, ok := ev["action_digest"]; ok {
							ev["action_digest"] = subst(ev["action_digest"])
						}
					}
				}
			}
		}
		var res AECResult
		if v.RPRequirement != "" {
			res = VerifyAuthorizationChain(chain, verifiers, v.RPRequirement)
		} else {
			res = VerifyAuthorizationChain(chain, verifiers)
		}
		if res.Allow != v.ExpectAllow {
			t.Errorf("%s: allow=%v want %v; reasons=%v", v.Name, res.Allow, v.ExpectAllow, res.Reasons)
		}
		if v.ExpectSource != "" && res.RequirementSource != v.ExpectSource {
			t.Errorf("%s: requirement_source=%q want %q", v.Name, res.RequirementSource, v.ExpectSource)
		}
	}
}
