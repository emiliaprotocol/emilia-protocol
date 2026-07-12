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
	// RequirementSource records whose sufficiency bar was evaluated:
	// "relying_party" when pinned via the variadic requirement argument,
	// "presenter" when the chain document's own requirement was used.
	RequirementSource string
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
			// Every counted approver key MUST be pinned for the ep-quorum role.
			// VerifyQuorum checks only INTERNAL consistency against the quorum's OWN
			// declared keys and policy; without pinning an attacker forges an entire
			// distinct-human quorum under device keys it generated. Require every
			// member key pinned under keysByType["ep-quorum"]; fail closed otherwise.
			byType, _ := ctx["keysByType"].(map[string]map[string]string)
			scoped := byType["ep-quorum"]
			membersRaw, _ := m["members"].([]any)
			if scoped == nil || len(membersRaw) == 0 {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			for _, mr := range membersRaw {
				mm, _ := mr.(map[string]any)
				k, _ := mm["approver_public_key"].(string)
				if k == "" || scoped[k] == "" {
					return ComponentResult{Valid: false, ActionDigest: ""}
				}
			}
			r := VerifyQuorum(m, "")
			if !r.Valid {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			ad, _ := m["action_hash"].(string)
			return ComponentResult{Valid: true, ActionDigest: ad}
		},
		"ep-receipt": func(ev any, ctx map[string]any) ComponentResult {
			m, _ := ev.(map[string]any)
			// The signing key MUST be pinned FOR THE ep-receipt ROLE. A globally
			// pinned key is not enough: a relying party that also pins its policy
			// engine's key would otherwise let that machine relabel its own signed
			// object EP-RECEIPT-v1, name its own (pinned) key, and fill the human
			// role (cross-role key confusion). Trust anchors are role-scoped:
			// keysByType maps a component type to the keys accepted FOR THAT ROLE
			// ONLY. No key pinned for ep-receipt => fail closed.
			named, _ := m["operator_public_key"].(string)
			byType, _ := ctx["keysByType"].(map[string]map[string]string)
			pinned, ok := byType["ep-receipt"][named]
			if named == "" || !ok || pinned == "" {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			r := VerifyReceipt(m, pinned)
			if !r.Valid {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			// Bind from the SIGNED payload only, never the unsigned top-level
			// action_hash (attacker-malleable: a receipt signed over a DIFFERENT
			// action could otherwise pass as binding this one).
			var bound string
			if payload, ok := m["payload"].(map[string]any); ok {
				if s, ok := payload["action_digest"].(string); ok {
					bound = s
				} else if s, ok := payload["action_hash"].(string); ok {
					bound = s
				}
			}
			return ComponentResult{Valid: true, ActionDigest: bound}
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
//
// TRUST BOUNDARY: the chain document's "requirement" is PRESENTER-supplied — a
// claim of what the bundle satisfies, never the relying party's bar. Pass an
// optional relying-party requirement as the trailing argument to pin it; it
// takes precedence and RequirementSource records which was used.
// keysByType is the relying party's ROLE-SCOPED pinned key set for built-in
// verifiers that require pinning (ep-receipt): keysByType["ep-receipt"] maps a
// signer's SPKI (base64url) to the trusted SPKI the relying party accepts FOR THAT
// ROLE. A key pinned for one role cannot satisfy another (no cross-role key
// confusion). Pass nil when only custom/stub verifiers are used.
func VerifyAuthorizationChain(aec map[string]any, verifiers map[string]ComponentVerifier, keysByType map[string]map[string]string, relyingPartyRequirement ...string) AECResult {
	pinned := ""
	if len(relyingPartyRequirement) > 0 {
		pinned = strings.TrimSpace(relyingPartyRequirement[0])
	}
	res := AECResult{RequirementSource: "presenter"}
	if pinned != "" {
		res.RequirementSource = "relying_party"
	}
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
	req, reqOk := aec["requirement"].(string)
	if pinned != "" {
		req = pinned
	} else if !reqOk || strings.TrimSpace(req) == "" {
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
		cr := v(c["evidence"], map[string]any{"action": action, "keysByType": keysByType})
		row.Valid = cr.Valid
		row.Bound = aecNormDigest(cr.ActionDigest) == chainDigest
		if !row.Valid {
			row.Reason = "component evidence did not verify"
		} else if !row.Bound {
			row.Reason = "component binds a DIFFERENT action than the chain"
		}
		if row.Valid && row.Bound {
			satisfied[typ] = true
			// A presenter-controlled label must never satisfy a requirement token
			// that names a registered verifier type (that would let a policy leg
			// labeled 'ep-receipt' fill the human role). Use the RAW label and skip
			// it when it collides with a registered type.
			rawLabel, _ := c["label"].(string)
			if rawLabel != "" {
				if _, isType := vmap[rawLabel]; !isType {
					satisfied[rawLabel] = true
				}
			}
		}
		res.Components = append(res.Components, row)
	}
	res.Allow = aecEvalRequirement(req, satisfied)
	if !res.Allow {
		res.Reasons = append(res.Reasons, fmt.Sprintf("requirement not satisfied: %q", req))
	}
	if pinned != "" && reqOk {
		if presenter := strings.TrimSpace(aec["requirement"].(string)); presenter != "" && presenter != pinned {
			res.Reasons = append(res.Reasons, fmt.Sprintf("presenter requirement ignored in favor of relying-party requirement (presenter claimed: %q)", presenter))
		}
	}
	return res
}
