// SPDX-License-Identifier: Apache-2.0
// Role non-substitution across the Go AEC verifier — mirror of the JS
// tests/role-non-substitution.test.js. A trusted machine policy decision must
// not satisfy a human-authorization requirement; each substitution attempt
// (label collision, version relabel, unsigned binding) fails closed.
package emiliaverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func roleKeyB64u(pub ed25519.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return base64.RawURLEncoding.EncodeToString(der)
}

func roleSign(payload any, priv ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(Canonicalize(payload))))
}

func TestRoleNonSubstitution(t *testing.T) {
	action := map[string]any{"action_type": "wire.release", "target": "treasury.example/wire/8841",
		"amount": "25000.00", "currency": "USD"}
	digest := "sha256:" + ActionDigest(action)

	machinePub, machinePriv, _ := ed25519.GenerateKey(rand.Reader)
	humanPub, humanPriv, _ := ed25519.GenerateKey(rand.Reader)
	machineKey := roleKeyB64u(machinePub)
	humanKey := roleKeyB64u(humanPub)

	policyPayload := map[string]any{"decision_id": "d1", "decision": "allow", "decision_maker": "policy-engine:gw7",
		"tool": "wire.release", "approval_state": "granted", "action_digest": digest, "issued_at": "2026-07-11T12:00:00Z"}
	policyDoc := map[string]any{"@version": "ACCESS-DECISION-RECORD-v1", "payload": policyPayload,
		"signature": map[string]any{"algorithm": "Ed25519", "value": roleSign(policyPayload, machinePriv)}}

	policyVerifier := func(ev any, ctx map[string]any) ComponentResult {
		m, _ := ev.(map[string]any)
		if v, _ := m["@version"].(string); v != "ACCESS-DECISION-RECORD-v1" {
			return ComponentResult{Valid: false}
		}
		pl, _ := m["payload"].(map[string]any)
		sig, _ := m["signature"].(map[string]any)
		sigVal, _ := sig["value"].(string)
		raw, _ := base64.RawURLEncoding.DecodeString(sigVal)
		ok := ed25519.Verify(machinePub, []byte(Canonicalize(pl)), raw) && pl["decision"] == "allow"
		ad, _ := pl["action_digest"].(string)
		return ComponentResult{Valid: ok, ActionDigest: ad}
	}
	verifiers := map[string]ComponentVerifier{"policy_decision": policyVerifier}
	keys := map[string]string{humanKey: humanKey} // only the human key is pinned for ep-receipt
	bar := "policy_decision AND ep-receipt"

	// POSITIVE: the machine decision verifies in its own role.
	r := VerifyAuthorizationChain(map[string]any{"@version": AECVersion, "action": action, "requirement": "policy_decision",
		"components": []any{map[string]any{"type": "policy_decision", "evidence": policyDoc}}}, verifiers, keys)
	if !r.Allow {
		t.Errorf("POSITIVE: want allow; reasons=%v", r.Reasons)
	}

	// NEGATIVE: presenter label 'ep-receipt' on a policy leg must not fill the human token.
	r = VerifyAuthorizationChain(map[string]any{"@version": AECVersion, "action": action, "requirement": "policy_decision",
		"components": []any{map[string]any{"type": "policy_decision", "label": "ep-receipt", "evidence": policyDoc}}}, verifiers, keys, bar)
	if r.Allow {
		t.Errorf("NEGATIVE label: substitution allowed")
	}
	if !r.Components[0].Valid || !r.Components[0].Bound {
		t.Errorf("NEGATIVE label: policy leg should still verify in its own role")
	}

	// NEGATIVE: machine object relabeled EP-RECEIPT-v1 with its own (unpinned) key.
	smuggled := map[string]any{}
	for k, v := range policyDoc {
		smuggled[k] = v
	}
	smuggled["@version"] = "EP-RECEIPT-v1"
	smuggled["operator_public_key"] = machineKey
	smuggled["action_hash"] = digest
	r = VerifyAuthorizationChain(map[string]any{"@version": AECVersion, "action": action, "requirement": "ep-receipt",
		"components": []any{map[string]any{"type": "ep-receipt", "evidence": smuggled}}}, verifiers, keys)
	if r.Allow || r.Components[0].Valid {
		t.Errorf("NEGATIVE relabel: unpinned machine key accepted as ep-receipt")
	}

	// NEGATIVE: a human receipt signed over a DIFFERENT action, unsigned top-level spoof.
	other := map[string]any{"action_type": "wire.release", "target": "treasury.example/wire/8841",
		"amount": "999999.00", "currency": "USD"}
	otherPayload := map[string]any{"receipt_id": "evil", "issuer": "ep:approver:cfo", "subject": "x",
		"action_digest": "sha256:" + ActionDigest(other), "created_at": "2026-07-11T12:00:00Z"}
	spoofed := map[string]any{"@version": "EP-RECEIPT-v1", "payload": otherPayload,
		"signature":           map[string]any{"algorithm": "Ed25519", "value": roleSign(otherPayload, humanPriv)},
		"operator_public_key": humanKey, "action_hash": digest}
	r = VerifyAuthorizationChain(map[string]any{"@version": AECVersion, "action": action, "requirement": "ep-receipt",
		"components": []any{map[string]any{"type": "ep-receipt", "evidence": spoofed}}}, verifiers, keys)
	if r.Allow || r.Components[0].Bound {
		t.Errorf("NEGATIVE unsigned binding: receipt over a different action bound to this one")
	}

	// CONTROL: a genuine human receipt with a pinned key satisfies the same bar.
	receiptPayload := map[string]any{"receipt_id": "r1", "issuer": "ep:approver:cfo", "subject": "wire-8841",
		"action_digest": digest, "created_at": "2026-07-11T12:00:02Z"}
	receipt := map[string]any{"@version": "EP-RECEIPT-v1", "payload": receiptPayload,
		"signature":           map[string]any{"algorithm": "Ed25519", "value": roleSign(receiptPayload, humanPriv)},
		"operator_public_key": humanKey}
	r = VerifyAuthorizationChain(map[string]any{"@version": AECVersion, "action": action, "requirement": "policy_decision",
		"components": []any{map[string]any{"type": "policy_decision", "evidence": policyDoc},
			map[string]any{"type": "ep-receipt", "evidence": receipt}}}, verifiers, keys, bar)
	if !r.Allow {
		t.Errorf("CONTROL: pinned human receipt should satisfy the bar; reasons=%v", r.Reasons)
	}
}
