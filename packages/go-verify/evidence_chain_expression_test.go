// SPDX-License-Identifier: Apache-2.0
// AEC -08 requirement expressions over the frozen corpus
// conformance/vectors/aec-expression.v1.json (the file the JS and Python tests
// run). This covers requirement-expression evaluation and the legacy
// VerifyAuthorizationChain wrapper only; this package does not implement the
// structured -07/-08 requirement and replay contract.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type aecExpressionCorpus struct {
	EvaluatorRevision string `json:"evaluator_revision"`
	Vectors           []struct {
		ID            string `json:"id"`
		AECExpression struct {
			Expression    string   `json:"expression"`
			EligibleTypes []string `json:"eligible_types"`
		} `json:"aec_expression"`
		Expect map[string]any `json:"expect"`
	} `json:"vectors"`
}

func loadAECExpressionCorpus(t *testing.T) ([]byte, aecExpressionCorpus) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "aec-expression.v1.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var corpus aecExpressionCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return raw, corpus
}

func TestAECExpressionCorpusFrozen(t *testing.T) {
	raw, corpus := loadAECExpressionCorpus(t)
	sums, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "aec-expression.v1.SHA256SUMS"))
	if err != nil {
		t.Fatalf("read sums: %v", err)
	}
	sum := sha256.Sum256(raw)
	if string(sums) != hex.EncodeToString(sum[:])+"  aec-expression.v1.json\n" {
		t.Fatalf("SHA256SUMS does not match the corpus")
	}
	if corpus.EvaluatorRevision != "EP-AEC-EVALUATOR-08-v1" {
		t.Fatalf("unexpected evaluator revision %q", corpus.EvaluatorRevision)
	}
}

func TestAECExpressionEachAssertion(t *testing.T) {
	_, corpus := loadAECExpressionCorpus(t)
	for _, v := range corpus.Vectors {
		got := EvaluateAECRequirementExpression(v.AECExpression.Expression, v.AECExpression.EligibleTypes)
		encoded, _ := json.Marshal(got)
		var row map[string]any
		_ = json.Unmarshal(encoded, &row)
		for _, key := range []string{"syntax", "invalid_class", "value", "result", "canonical_parse", "parse_identity"} {
			if !reflect.DeepEqual(row[key], v.Expect[key]) {
				t.Errorf("%s.%s: got %v want %v", v.ID, key, row[key], v.Expect[key])
			}
		}
	}
}

func TestAECExpressionLegacyWrapper(t *testing.T) {
	_, corpus := loadAECExpressionCorpus(t)
	action := map[string]any{"action_type": "payment.release", "amount": float64(100)}
	digest := ActionDigest(action)
	stub := func(ev any, _ map[string]any) ComponentResult {
		m, _ := ev.(map[string]any)
		ad, _ := m["action_digest"].(string)
		return ComponentResult{Valid: true, ActionDigest: ad}
	}
	for _, v := range corpus.Vectors {
		eligible := v.AECExpression.EligibleTypes
		skip := len(eligible) > 64
		for _, typ := range eligible {
			skip = skip || len(typ) > 128
		}
		if skip {
			continue // the legacy wrapper caps components and type length
		}
		verifiers := map[string]ComponentVerifier{"unrelated": stub}
		comps := []any{}
		for _, typ := range eligible {
			verifiers[typ] = stub
			comps = append(comps, map[string]any{"type": typ, "evidence": map[string]any{"action_digest": "sha256:" + digest}})
		}
		if len(comps) == 0 {
			comps = append(comps, map[string]any{"type": "unrelated", "evidence": map[string]any{"action_digest": "sha256:" + digest}})
		}
		chain := map[string]any{"@version": AECVersion, "action": action, "components": comps}
		res := VerifyAuthorizationChainWithOptions(chain, verifiers, nil, AECOptions{Requirement: v.AECExpression.Expression, ExpectedActionDigest: "sha256:" + digest})
		want := v.Expect["value"] == true
		if res.Satisfied != want {
			t.Errorf("%s: satisfied=%v want %v (%v)", v.ID, res.Satisfied, want, res.Reasons)
		}
	}
}

// Go once trimmed the pinned requirement with strings.TrimSpace, which strips
// Unicode spaces, so "\u00a0a" evaluated as "a" where JS and Python refused it.
func TestAECExpressionPinnedRequirementNotTrimmed(t *testing.T) {
	action := map[string]any{"action_type": "payment.release"}
	digest := "sha256:" + ActionDigest(action)
	stub := func(ev any, _ map[string]any) ComponentResult {
		return ComponentResult{Valid: true, ActionDigest: digest}
	}
	chain := map[string]any{"@version": AECVersion, "action": action,
		"components": []any{map[string]any{"type": "a", "evidence": map[string]any{}}}}
	run := func(req string) AECResult {
		return VerifyAuthorizationChainWithOptions(chain, map[string]ComponentVerifier{"a": stub}, nil, AECOptions{Requirement: req, ExpectedActionDigest: digest})
	}
	if !run(" \ta\r\n").Satisfied {
		t.Fatalf("ASCII whitespace around a valid expression must be accepted")
	}
	for _, padded := range []string{"\u00a0a", "a\u00a0", "\u2028a", "\ufeffa", "a\v", "\fa"} {
		res := run(padded)
		if res.Satisfied || res.RequirementSource != "relying_party" {
			t.Errorf("%q: satisfied=%v source=%s", padded, res.Satisfied, res.RequirementSource)
		}
	}
	over := run(strings.Repeat("a", 4095) + "\u00a0")
	if over.Satisfied || !strings.Contains(strings.Join(over.Reasons, "|"), "requirement expression exceeds size limit") {
		t.Errorf("4097-octet requirement must exceed the size limit: %v", over.Reasons)
	}
}

func TestAECExpressionCompiledTreeReused(t *testing.T) {
	c := CompileAECRequirementExpression("a OR b AND c")
	if !c.Valid || c.CanonicalParse != "((a OR b) AND c)" || c.TokenCount != 5 {
		t.Fatalf("unexpected compilation %+v", c)
	}
	if *c.Evaluate(map[string]bool{"a": true}).Value {
		t.Fatalf("a OR b AND c with only a eligible must be false")
	}
	bad := CompileAECRequirementExpression("a OR (b AND)")
	if bad.Valid || bad.InvalidClass != "syntax" || bad.ParseIdentity != "" {
		t.Fatalf("unexpected refusal %+v", bad)
	}
}
