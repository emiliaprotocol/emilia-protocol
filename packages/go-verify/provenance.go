// SPDX-License-Identifier: Apache-2.0
// EP-PROVENANCE-CHAIN-v1 offline verifier — Go parity with packages/verify/
// provenance.js and python-verify verify_provenance_offline. Composes
// VerifyTrustReceipt + delegation-chain / scope-containment checks. Fail-closed.
package emiliaverify

import (
	"sort"
	"strings"
	"time"
)

const ProvenanceVersion = "EP-PROVENANCE-CHAIN-v1"

var provenanceProofFields = []string{"delegation_id", "delegator", "delegatee", "scope", "max_value_usd", "expires_at", "constraints"}

// ProvenanceResult mirrors the JS { valid, checks } shape (advisory blocks omitted).
type ProvenanceResult struct {
	Valid  bool            `json:"valid"`
	Checks map[string]bool `json:"checks"`
}

func provHasHumanSignoff(receipt map[string]any, humanClasses map[string]bool) bool {
	sos, _ := receipt["signoffs"].([]any)
	for _, so := range sos {
		if humanClasses[getStr(getMap(so), "key_class")] {
			return true
		}
	}
	return false
}

func provReceiptApprovers(receipt map[string]any) map[string]bool {
	ids := map[string]bool{}
	if receipt == nil {
		return ids
	}
	ctxs, _ := receipt["contexts"].([]any)
	for _, c := range ctxs {
		if a := getStr(getMap(c), "approver"); a != "" {
			ids[a] = true
		}
	}
	sos, _ := receipt["signoffs"].([]any)
	for _, s := range sos {
		if a := getStr(getMap(s), "approver_key_id"); a != "" {
			ids[a] = true
		}
	}
	return ids
}

func provLatestContextExpiry(receipt map[string]any) (int64, bool) {
	var mx int64
	found := false
	if receipt == nil {
		return 0, false
	}
	ctxs, _ := receipt["contexts"].([]any)
	for _, c := range ctxs {
		if t, ok := parseMillis(getStr(getMap(c), "expires_at")); ok && (!found || t > mx) {
			mx, found = t, true
		}
	}
	return mx, found
}

func provScopePermits(scope []any, actionType string) bool {
	if actionType == "" {
		return false
	}
	for _, g := range scope {
		grant, _ := g.(string)
		if grant == "*" || grant == actionType {
			return true
		}
		if strings.HasSuffix(grant, ".*") {
			prefix := grant[:len(grant)-2]
			if actionType == prefix || strings.HasPrefix(actionType, prefix+".") {
				return true
			}
		}
	}
	return false
}

func provScopeAsSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func provScopeContained(parent, child map[string]any) bool {
	for _, token := range provScopeAsSlice(child["scope"]) {
		probe, _ := token.(string)
		if strings.HasSuffix(probe, ".*") {
			probe = probe[:len(probe)-2]
		}
		if !provScopePermits(provScopeAsSlice(parent["scope"]), probe) {
			return false
		}
	}
	parentCap, parentHas := toFloat(parent["max_value_usd"])
	childCap, childHas := toFloat(child["max_value_usd"])
	if !childHas {
		childCap, childHas = parentCap, parentHas
	}
	if parentHas {
		if !childHas || childCap > parentCap {
			return false
		}
	}
	if pExp, ok := parseMillis(getStr(parent, "expires_at")); ok {
		if cExp, ok2 := parseMillis(getStr(child, "expires_at")); ok2 && cExp > pExp {
			return false
		}
	}
	return true
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

func provVerifyDetached(att map[string]any) bool {
	if att == nil {
		return false
	}
	sp := getStr(att, "signed_payload_b64u")
	sig := getStr(att, "signature_b64u")
	pub := getStr(att, "public_key")
	if sp == "" || sig == "" || pub == "" {
		return false
	}
	if alg := getStr(att, "algorithm"); alg != "" && alg != "Ed25519" {
		return false
	}
	data, err := b64urlDecode(sp)
	if err != nil {
		return false
	}
	return ed25519VerifyBytes(data, pub, sig)
}

func provDelegationProofBytes(link map[string]any) string {
	subset := map[string]any{}
	for _, f := range provenanceProofFields {
		subset[f] = link[f]
	}
	return Canonicalize(subset)
}

// VerifyProvenanceOffline verifies an EP-PROVENANCE-CHAIN-v1 document. opts keys:
// humanKeyClasses ([]any), delegationKeys (map), now (RFC3339), allowUnsignedDelegations
// (bool), requireActionApprovalAlways (bool).
func VerifyProvenanceOffline(doc map[string]any, opts map[string]any) ProvenanceResult {
	checks := map[string]bool{
		"version": false, "root_receipt_valid": false, "root_human_signoff": false,
		"per_action_required": true, "action_receipt_valid": true, "action_human_signoff": true,
		"execution_binding": true, "chain_anchored": true, "chain_links_bound": true,
		"delegations_signed": true, "proof_key_bound": true, "delegations_not_expired": true,
		"scope_containment": true, "leaf_permits_action": true, "temporal_containment": true,
	}
	fail := func(k string) { checks[k] = false }

	if doc == nil || getStr(doc, "@version") != ProvenanceVersion {
		return ProvenanceResult{false, checks}
	}
	checks["version"] = true

	humanClasses := map[string]bool{"A": true}
	if hc, ok := opts["humanKeyClasses"].([]any); ok && len(hc) > 0 {
		humanClasses = map[string]bool{}
		for _, c := range hc {
			if s, ok := c.(string); ok {
				humanClasses[s] = true
			}
		}
	}
	allowUnsigned, _ := opts["allowUnsignedDelegations"].(bool)
	requireAlways, _ := opts["requireActionApprovalAlways"].(bool)
	now := float64(0)
	hasNow := false
	if nowMs, ok := opts["now"].(float64); ok {
		now, hasNow = nowMs, true
	}

	root := getMap(doc["root_signoff"])
	if root == nil || getMap(root["receipt"]) == nil || getMap(root["verification"]) == nil {
		fail("root_receipt_valid")
	} else {
		ver := getMap(root["verification"])
		r0 := VerifyTrustReceipt(getMap(root["receipt"]), map[string]any{"approverKeys": ver["approver_keys"], "logPublicKey": ver["log_public_key"]})
		checks["root_receipt_valid"] = r0.Valid
		checks["root_human_signoff"] = provHasHumanSignoff(getMap(root["receipt"]), humanClasses)
	}

	exec := getMap(doc["execution"])
	// opts.reversibilityAsserted is a predicate (not serializable); absent here,
	// so reversibility is never asserted and approval is required by default.
	reversibilityAsserted := false
	needApproval := requireAlways || !reversibilityAsserted
	approval := getMap(doc["action_approval"])
	if needApproval && getMap(approval["receipt"]) == nil {
		fail("per_action_required")
	}
	if ar := getMap(approval["receipt"]); ar != nil {
		ver := getMap(approval["verification"])
		ra := VerifyTrustReceipt(ar, map[string]any{"approverKeys": ver["approver_keys"], "logPublicKey": ver["log_public_key"]})
		checks["action_receipt_valid"] = ra.Valid
		if irr, _ := exec["irreversible"].(bool); irr {
			checks["action_human_signoff"] = provHasHumanSignoff(ar, humanClasses)
		}
		checks["execution_binding"] = hexStrip(exec["action_hash"]) == hexStrip(ar["action_hash"])
	}

	chainAny, _ := doc["delegation_chain"].([]any)
	chain := make([]map[string]any, 0, len(chainAny))
	for _, c := range chainAny {
		chain = append(chain, getMap(c))
	}
	sort.SliceStable(chain, func(i, j int) bool {
		si, _ := toFloat(chain[i]["sequence"])
		sj, _ := toFloat(chain[j]["sequence"])
		return si < sj
	})
	delegationKeys := getMap(opts["delegationKeys"])
	rootApprovers := provReceiptApprovers(getMap(root["receipt"]))
	rootScope := []any{}
	if at := getStr(getMap(getMap(root["receipt"])["action"]), "action_type"); at != "" {
		rootScope = []any{at}
	}
	parent := map[string]any{"scope": rootScope, "max_value_usd": nil}
	if rExp, ok := provLatestContextExpiry(getMap(root["receipt"])); ok {
		parent["expires_at"] = time.UnixMilli(rExp).UTC().Format("2006-01-02T15:04:05.000Z")
	}

	if len(chain) > 0 {
		head := chain[0]
		checks["chain_anchored"] = rootApprovers[getStr(head, "parent_ref")] || rootApprovers[getStr(head, "delegator")]
	}

	prevDelegatee := ""
	havePrev := false
	for _, link := range chain {
		if havePrev {
			if getStr(link, "parent_ref") != prevDelegatee || getStr(link, "delegator") != prevDelegatee {
				fail("chain_links_bound")
			}
		}
		if exp, ok := parseMillis(getStr(link, "expires_at")); !ok || (hasNow && float64(exp) < now) {
			fail("delegations_not_expired")
		}
		if proof := getMap(link["proof"]); proof != nil {
			sigOK := provVerifyDetached(proof)
			presented, _ := b64urlDecode(getStr(proof, "signed_payload_b64u"))
			if !sigOK || string(presented) != provDelegationProofBytes(link) {
				fail("delegations_signed")
			}
			boundKey := getStr(getMap(delegationKeys[getStr(link, "delegator")]), "public_key")
			if boundKey == "" {
				fail("proof_key_bound")
			} else if boundKey != getStr(proof, "public_key") {
				fail("proof_key_bound")
			}
		} else if !allowUnsigned {
			fail("delegations_signed")
		}
		if !provScopeContained(parent, link) {
			fail("scope_containment")
		}
		// narrow effective cap forward
		linkCap, linkHas := toFloat(link["max_value_usd"])
		parentCap, parentHas := toFloat(parent["max_value_usd"])
		var eff any
		if !linkHas {
			eff = parent["max_value_usd"]
		} else if !parentHas {
			eff = linkCap
		} else if linkCap < parentCap {
			eff = linkCap
		} else {
			eff = parentCap
		}
		next := map[string]any{}
		for k, v := range link {
			next[k] = v
		}
		next["max_value_usd"] = eff
		parent = next
		prevDelegatee = getStr(link, "delegatee")
		havePrev = true
	}

	actionType := getStr(getMap(getMap(approval["receipt"])["action"]), "action_type")
	if actionType == "" {
		fail("leaf_permits_action")
	} else if !provScopePermits(provScopeAsSlice(parent["scope"]), actionType) {
		fail("leaf_permits_action")
	}

	if ar := getMap(approval["receipt"]); ar != nil {
		if commit, ok := parseMillis(getStr(getMap(ar["consumption"]), "committed_at")); ok {
			if leafExp, ok2 := parseMillis(getStr(parent, "expires_at")); ok2 && commit > leafExp {
				fail("temporal_containment")
			}
		}
	}

	return ProvenanceResult{allTrue(checks), checks}
}
