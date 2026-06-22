// SPDX-License-Identifier: Apache-2.0
//
// EP-AEC-v1 — Authorization Evidence Chain (composition verifier).
// Mirrors packages/verify/evidence-chain.js and the Python verify_authorization_chain.
// Composes heterogeneous agent-authorization receipts that all bind ONE canonical
// action into a single offline, fail-closed ALLOW/DENY. Introduces no receipt type.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const AECVersion = "EP-AEC-v1"

// ComponentResult is what a component verifier reports: validity + the action
// digest the component itself attests it authorized.
type ComponentResult struct {
	Valid        bool
	ActionDigest string
}

// ComponentVerifier verifies one component's evidence within a context.
type ComponentVerifier func(evidence any, ctx map[string]any) ComponentResult

// AECComponentRow is a per-component audit row.
type AECComponentRow struct {
	Type   string
	Label  string
	Valid  bool
	Bound  bool
	Reason string
}

// AECResult is the chain verification result.
type AECResult struct {
	Allow        bool
	ActionDigest string
	Components   []AECComponentRow
	Reasons      []string
}

// ActionDigest returns the canonical action digest (hex) = sha256(JCS(action)).
func ActionDigest(action any) string {
	sum := sha256.Sum256([]byte(Canonicalize(action)))
	return hex.EncodeToString(sum[:])
}

func aecNormDigest(d any) string {
	s, ok := d.(string)
	if !ok {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(s), "sha256:")
}

func builtinAECVerifiers() map[string]ComponentVerifier {
	return map[string]ComponentVerifier{
		"ep-quorum": func(ev any, ctx map[string]any) ComponentResult {
			m, _ := ev.(map[string]any)
			r := VerifyQuorum(m, "")
			ad, _ := m["action_hash"].(string)
			return ComponentResult{Valid: r.Valid, ActionDigest: ad}
		},
		"ep-receipt": func(ev any, ctx map[string]any) ComponentResult {
			m, _ := ev.(map[string]any)
			key, _ := m["operator_public_key"].(string)
			r := VerifyReceipt(m, key)
			ad, _ := m["action_hash"].(string)
			return ComponentResult{Valid: r.Valid, ActionDigest: ad}
		},
	}
}

func aecTokenize(s string) []string {
	var toks []string
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '(' || c == ')' {
			toks = append(toks, string(c))
			i++
			continue
		}
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] != '(' && s[j] != ')' && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		toks = append(toks, s[i:j])
		i = j
	}
	return toks
}

func aecEvalRequirement(expr string, satisfied map[string]bool) bool {
	toks := aecTokenize(expr)
	i := 0
	peek := func() string {
		if i < len(toks) {
			return toks[i]
		}
		return ""
	}
	eat := func() string {
		t := peek()
		if i < len(toks) {
			i++
		}
		return t
	}
	var parseExpr func() bool
	parseTerm := func() bool {
		if peek() == "(" {
			eat()
			v := parseExpr()
			if peek() == ")" {
				eat()
			}
			return v
		}
		id := eat()
		if id == "" {
			return false
		}
		return satisfied[id]
	}
	parseExpr = func() bool {
		v := parseTerm()
		for {
			p := peek()
			if p == "AND" || p == "&&" || p == "OR" || p == "||" {
				eat()
				r := parseTerm()
				if p == "AND" || p == "&&" {
					v = v && r
				} else {
					v = v || r
				}
			} else {
				break
			}
		}
		return v
	}
	v := parseExpr()
	if i != len(toks) {
		return false
	}
	return v
}

// VerifyAuthorizationChain verifies an EP-AEC chain offline, fail-closed.
func VerifyAuthorizationChain(aec map[string]any, verifiers map[string]ComponentVerifier) AECResult {
	res := AECResult{}
	fail := func(why string) AECResult {
		res.Allow = false
		res.Reasons = append(res.Reasons, why)
		return res
	}
	if aec == nil {
		return fail("chain is not an object")
	}
	if v, _ := aec["@version"].(string); v != AECVersion {
		return fail("unexpected @version")
	}
	action, ok := aec["action"].(map[string]any)
	if !ok {
		return fail("missing action object")
	}
	compsIn, ok := aec["components"].([]any)
	if !ok || len(compsIn) == 0 {
		return fail("no components")
	}
	req, ok := aec["requirement"].(string)
	if !ok || strings.TrimSpace(req) == "" {
		return fail("missing requirement expression")
	}
	chainDigest := ActionDigest(action)
	res.ActionDigest = chainDigest
	if ad, present := aec["action_digest"]; present && ad != nil {
		if aecNormDigest(ad) != chainDigest {
			return fail("declared action_digest does not match canonical digest of the action")
		}
	}
	vmap := builtinAECVerifiers()
	for k, v := range verifiers {
		vmap[k] = v
	}
	satisfied := map[string]bool{}
	for idx, ci := range compsIn {
		c, _ := ci.(map[string]any)
		typ, _ := c["type"].(string)
		label, _ := c["label"].(string)
		if label == "" {
			if typ != "" {
				label = typ
			} else {
				label = fmt.Sprintf("#%d", idx)
			}
		}
		row := AECComponentRow{Type: typ, Label: label}
		v, has := vmap[typ]
		if !has {
			row.Reason = fmt.Sprintf("no verifier registered for type %q", typ)
			res.Components = append(res.Components, row)
			continue
		}
		cr := v(c["evidence"], map[string]any{"action": action})
		row.Valid = cr.Valid
		row.Bound = aecNormDigest(cr.ActionDigest) == chainDigest
		if !row.Valid {
			row.Reason = "component evidence did not verify"
		} else if !row.Bound {
			row.Reason = "component binds a DIFFERENT action than the chain"
		}
		if row.Valid && row.Bound {
			satisfied[typ] = true
			if label != "" {
				satisfied[label] = true
			}
		}
		res.Components = append(res.Components, row)
	}
	res.Allow = aecEvalRequirement(req, satisfied)
	if !res.Allow {
		res.Reasons = append(res.Reasons, fmt.Sprintf("requirement not satisfied: %q", req))
	}
	return res
}
