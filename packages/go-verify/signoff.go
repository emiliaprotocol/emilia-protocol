// SPDX-License-Identifier: Apache-2.0
// EP-SIGNOFF-v1 (WebAuthn ECDSA P-256 device signoff) + EP-QUORUM-v1 (multi-party
// M-of-N / ordered approval). Cross-language parity with packages/verify
// (quorum.js) and python-verify — same canonicalization, same fail-closed
// predicates, so the SAME conformance vectors verify identically in all three.
package emiliaverify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"
)

const flagUP = 0x01
const flagUV = 0x04

// SignoffResult mirrors the JS verifyWebAuthnSignoff return.
type SignoffResult struct {
	Valid  bool            `json:"valid"`
	Checks map[string]bool `json:"checks"`
}

func getMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
func getStr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// VerifyWebAuthnSignoff verifies a Class-A device signoff. rpID "" skips the
// audience check (matches JS opts.rpId absent). Never panics.
func VerifyWebAuthnSignoff(signoff map[string]any, approverPubKeyB64u string, rpID string) SignoffResult {
	checks := map[string]bool{
		"challenge_binding": false, "client_data_type": false, "user_present": false,
		"user_verified": false, "signature": false,
	}
	rpChecked := false
	rpOK := true
	if signoff == nil {
		return SignoffResult{false, checks}
	}
	ctx := signoff["context"]
	wa := getMap(signoff["webauthn"])
	if ctx == nil || wa == nil {
		return SignoffResult{false, checks}
	}
	adB64, cdB64, sigB64 := getStr(wa, "authenticator_data"), getStr(wa, "client_data_json"), getStr(wa, "signature")
	if adB64 == "" || cdB64 == "" || sigB64 == "" {
		return SignoffResult{false, checks}
	}
	cdBytes, err := b64urlDecode(cdB64)
	if err != nil {
		return SignoffResult{false, checks}
	}
	var client map[string]any
	if json.Unmarshal(cdBytes, &client) != nil {
		return SignoffResult{false, checks}
	}
	sum := sha256.Sum256([]byte(Canonicalize(ctx)))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	checks["challenge_binding"] = getStr(client, "challenge") == expected
	checks["client_data_type"] = getStr(client, "type") == "webauthn.get"

	ad, err := b64urlDecode(adB64)
	if err != nil || len(ad) < 37 {
		return SignoffResult{false, checks}
	}
	flags := ad[32]
	checks["user_present"] = flags&flagUP == flagUP
	checks["user_verified"] = flags&flagUV == flagUV
	if rpID != "" {
		h := sha256.Sum256([]byte(rpID))
		rpOK = subtle.ConstantTimeCompare(h[:], ad[:32]) == 1
		rpChecked = true
		checks["rp_id_hash"] = rpOK
	}
	signed := append(append([]byte{}, ad...), func() []byte { s := sha256.Sum256(cdBytes); return s[:] }()...)
	der, err := base64.RawURLEncoding.DecodeString(b64urlPad(approverPubKeyB64u))
	if err == nil {
		if pubAny, e := x509.ParsePKIXPublicKey(der); e == nil {
			if pub, ok := pubAny.(*ecdsa.PublicKey); ok {
				sig, e2 := b64urlDecode(sigB64)
				if e2 == nil {
					h := sha256.Sum256(signed)
					checks["signature"] = ecdsa.VerifyASN1(pub, h[:], sig)
				}
			}
		}
	}
	valid := checks["challenge_binding"] && checks["client_data_type"] && checks["user_present"] &&
		checks["user_verified"] && checks["signature"] && (!rpChecked || rpOK)
	return SignoffResult{valid, checks}
}

// b64urlPad normalizes a base64url string (RawURLEncoding handles no-pad; this
// strips any padding so both forms decode).
func b64urlPad(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

// QuorumResult mirrors the JS verifyQuorum return.
type QuorumResult struct {
	Valid  bool            `json:"valid"`
	Checks map[string]bool `json:"checks"`
}

func parseMillis(ts string) (int64, bool) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, false
	}
	return t.UnixMilli(), true
}

// VerifyQuorum verifies an EP-QUORUM-v1 document. Fail-closed; composes
// VerifyWebAuthnSignoff per member. Mirrors quorum.js.
func VerifyQuorum(quorum map[string]any, rpID string) QuorumResult {
	checks := map[string]bool{
		"all_signatures_valid": false, "action_binding": false, "distinct_humans": false,
		"distinct_keys": false, "initiator_excluded": false, "roles_admitted": false,
		"threshold_met": false, "order_satisfied": false, "chain_linked": false,
		"within_window": false,
	}
	if quorum == nil {
		return QuorumResult{false, checks}
	}
	policy := getMap(quorum["policy"])
	membersAny, _ := quorum["members"].([]any)
	actionHash := getStr(quorum, "action_hash")
	if policy == nil || len(membersAny) == 0 || actionHash == "" {
		return QuorumResult{false, checks}
	}
	members := make([]map[string]any, len(membersAny))
	for i, m := range membersAny {
		members[i] = getMap(m)
	}
	mode := "threshold"
	if getStr(policy, "mode") == "ordered" {
		mode = "ordered"
	}
	distinctHumans := true
	if v, ok := policy["distinct_humans"].(bool); ok {
		distinctHumans = v
	}
	windowSec := 900.0
	if v, ok := toFloat(policy["window_sec"]); ok {
		windowSec = v
	}
	eligAny, _ := policy["approvers"].([]any)
	eligible := make([]map[string]any, len(eligAny))
	for i, e := range eligAny {
		eligible[i] = getMap(e)
	}
	var required int
	if mode == "ordered" {
		required = len(eligible)
	} else if v, ok := toFloat(policy["required"]); ok && int(v) > 0 {
		required = int(v)
	}
	if required <= 0 || len(eligible) == 0 {
		return QuorumResult{false, checks}
	}

	ctxOf := func(m map[string]any) map[string]any { return getMap(getMap(m["signoff"])["context"]) }
	allSigs, allBound := true, true
	issued := make([]int64, len(members))
	issuedOK := make([]bool, len(members))
	memberValid := make([]bool, len(members))
	for i, m := range members {
		r := VerifyWebAuthnSignoff(getMap(m["signoff"]), getStr(m, "approver_public_key"), rpID)
		memberValid[i] = r.Valid
		if !r.Valid {
			allSigs = false
		}
		if getStr(ctxOf(m), "action_hash") != actionHash {
			allBound = false
		}
		issued[i], issuedOK[i] = parseMillis(getStr(ctxOf(m), "issued_at"))
	}
	checks["all_signatures_valid"] = allSigs
	checks["action_binding"] = allBound

	type idxMember struct {
		i int
		m map[string]any
	}
	counted := []idxMember{}
	for i, m := range members {
		if memberValid[i] && getStr(ctxOf(m), "action_hash") == actionHash {
			counted = append(counted, idxMember{i, m})
		}
	}
	seen := map[string]int{}
	for _, c := range counted {
		seen[getStr(ctxOf(c.m), "approver")]++
	}
	dh := len(seen) == len(counted)
	checks["distinct_humans"] = !distinctHumans || dh

	// Distinct device keys: no single public key may fill two counted slots.
	// Key-uniqueness is a cryptographic floor, NOT a separation-of-duties
	// preference: it holds UNCONDITIONALLY, even when distinct_humans is disabled.
	// One key in two counted seats is one signer, never a quorum. Mirrors quorum.js.
	countedKeys := map[string]int{}
	for _, c := range counted {
		countedKeys[getStr(c.m, "approver_public_key")]++
	}
	checks["distinct_keys"] = len(countedKeys) == len(counted)

	// Initiator excluded (separation of duties): the human/agent that INITIATED
	// the action must never also approve it. Require context.initiator to be
	// present, the SAME across all counted members, and to differ from every
	// counted member's own approver identity. Mirrors quorum.js and
	// verifyTrustReceipt's initiator SoD check.
	initiatorExcluded := len(counted) > 0
	quorumInitiator := ""
	if len(counted) > 0 {
		quorumInitiator = getStr(ctxOf(counted[0].m), "initiator")
	}
	if quorumInitiator == "" {
		initiatorExcluded = false
	}
	for _, c := range counted {
		if getStr(ctxOf(c.m), "initiator") != quorumInitiator {
			initiatorExcluded = false
		}
		if getStr(ctxOf(c.m), "approver") == quorumInitiator {
			initiatorExcluded = false
		}
	}
	checks["initiator_excluded"] = initiatorExcluded

	eligibleSet := map[string]bool{}
	for _, e := range eligible {
		eligibleSet[getStr(e, "role")+" "+getStr(e, "approver")] = true
	}
	rolesOK := len(counted) > 0
	for _, c := range counted {
		if !eligibleSet[getStr(c.m, "role")+" "+getStr(ctxOf(c.m), "approver")] {
			rolesOK = false
		}
	}
	checks["roles_admitted"] = rolesOK

	distinctElig := map[string]bool{}
	for _, c := range counted {
		if eligibleSet[getStr(c.m, "role")+" "+getStr(ctxOf(c.m), "approver")] {
			distinctElig[getStr(ctxOf(c.m), "approver")] = true
		}
	}
	checks["threshold_met"] = len(distinctElig) >= required

	if mode == "ordered" {
		seqOK := len(members) >= len(eligible)
		for idx, e := range eligible {
			if idx >= len(members) || getStr(members[idx], "role") != getStr(e, "role") ||
				getStr(ctxOf(members[idx]), "approver") != getStr(e, "approver") {
				seqOK = false
			}
		}
		timesOK := true
		for idx := 0; idx < len(eligible) && idx < len(members); idx++ {
			if !issuedOK[idx] || (idx > 0 && !(issued[idx] > issued[idx-1])) {
				timesOK = false
			}
		}
		checks["order_satisfied"] = seqOK && timesOK
	} else {
		checks["order_satisfied"] = true
	}

	orderedChain, _ := policy["ordered_chain"].(bool)
	if mode == "ordered" && orderedChain {
		linked := len(members) >= len(eligible)
		for idx := 0; idx < len(eligible) && idx < len(members); idx++ {
			prev := getStr(ctxOf(members[idx]), "prev_context_hash")
			if idx == 0 {
				if prev != "" {
					linked = false
				}
			} else {
				sum := sha256.Sum256([]byte(Canonicalize(ctxOf(members[idx-1]))))
				if prev != hex.EncodeToString(sum[:]) {
					linked = false
				}
			}
		}
		checks["chain_linked"] = linked
	} else {
		checks["chain_linked"] = true
	}

	if len(counted) > 0 {
		var mn, mx int64
		first := true
		ok := true
		for _, c := range counted {
			if !issuedOK[c.i] {
				ok = false
				break
			}
			if first {
				mn, mx, first = issued[c.i], issued[c.i], false
			}
			if issued[c.i] < mn {
				mn = issued[c.i]
			}
			if issued[c.i] > mx {
				mx = issued[c.i]
			}
		}
		checks["within_window"] = ok && float64(mx-mn) <= windowSec*1000
	}

	valid := checks["all_signatures_valid"] && checks["action_binding"] && checks["distinct_humans"] &&
		checks["distinct_keys"] && checks["initiator_excluded"] && checks["roles_admitted"] &&
		checks["threshold_met"] && checks["order_satisfied"] && checks["chain_linked"] &&
		checks["within_window"]
	return QuorumResult{valid, checks}
}
