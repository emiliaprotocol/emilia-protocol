// SPDX-License-Identifier: Apache-2.0
// EP-REVOCATION-v1 + EP-TIME-ATTESTATION-v1 — Go parity with packages/verify
// (revocation.js, time-attestation.js) and python-verify. Same canonicalization,
// same Ed25519 (asymmetric, key-pinned), same fail-closed predicates, so the
// SAME conformance vectors verify identically in all three languages.
package emiliaverify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"math"
	"strings"
	"time"
)

const RevocationVersion = "EP-REVOCATION-v1"
const TimeAttestationVersion = "EP-TIME-ATTESTATION-v1"

var revocationTargetTypes = map[string]bool{"receipt": true, "commit": true, "delegation": true}

// CheckResult mirrors the JS { valid, checks } shape for the portable statements.
type CheckResult struct {
	Valid  bool            `json:"valid"`
	Checks map[string]bool `json:"checks"`
}

func hexStrip(h any) string {
	s, ok := h.(string)
	if !ok {
		return ""
	}
	s = strings.ToLower(strings.TrimPrefix(s, "sha256:"))
	if len(s) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

func ed25519VerifyBytes(data []byte, pubB64u, sigB64u string) bool {
	if len(data) == 0 || pubB64u == "" || sigB64u == "" {
		return false
	}
	der, err := b64urlDecode(pubB64u)
	if err != nil {
		return false
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return false
	}
	sig, err := b64urlDecode(sigB64u)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, data, sig)
}

func allTrue(checks map[string]bool) bool {
	for _, v := range checks {
		if !v {
			return false
		}
	}
	return true
}

func revocationSignedPayload(stmt map[string]any) []byte {
	return []byte(Canonicalize(map[string]any{
		"@version":    RevocationVersion,
		"action_hash": stmt["action_hash"],
		"reason":      stmt["reason"],
		"revoked_at":  stmt["revoked_at"],
		"revoker_id":  stmt["revoker_id"],
		"target_id":   stmt["target_id"],
		"target_type": stmt["target_type"],
	}))
}

// VerifyRevocation mirrors packages/verify/revocation.js. opts keys: revokerKeys
// (map of revoker_id -> {public_key}) and now (RFC3339). maxAgeSeconds is
// accepted for API compatibility but ignored: terminal revocations do not age out.
func VerifyRevocation(target, statement, opts map[string]any) CheckResult {
	checks := map[string]bool{
		"version": true, "target_bound": true, "revoker_key_pinned": true,
		"revoked_at_present": true, "revoker_signature_valid": true,
		"effective_at_or_before_T": true, "signature_binds_statement": true,
	}
	fail := func(k string) { checks[k] = false }
	revokerKeys := getMap(opts["revokerKeys"])

	if statement == nil {
		checks["signature_binds_statement"] = false
		checks["revoker_signature_valid"] = false
		return CheckResult{false, checks}
	}
	if getStr(statement, "@version") != RevocationVersion {
		fail("version")
	}
	if target == nil {
		fail("target_bound")
	} else {
		tt := getStr(target, "target_type")
		targetID := getStr(target, "target_id")
		heldHash := hexStrip(target["action_hash"])
		statementType := getStr(statement, "target_type")
		statementID := getStr(statement, "target_id")
		statementHash := hexStrip(statement["action_hash"])
		if !revocationTargetTypes[tt] || targetID == "" || heldHash == "" {
			fail("target_bound")
		}
		if !revocationTargetTypes[statementType] || statementID == "" || statementHash == "" {
			fail("target_bound")
		} else if statementType != tt {
			fail("target_bound")
		} else if statementID != targetID {
			fail("target_bound")
		} else if statementHash != heldHash {
			fail("target_bound")
		}
	}

	proof := getMap(statement["proof"])
	revokerID := getStr(statement, "revoker_id")
	pinned := getStr(getMap(revokerKeys[revokerID]), "public_key")
	presented := getStr(proof, "public_key")
	if pinned == "" {
		fail("revoker_key_pinned")
	} else if presented != "" && pinned != presented {
		fail("revoker_key_pinned")
	}
	if getStr(proof, "algorithm") != "Ed25519" {
		fail("revoker_signature_valid")
	}
	if reason, present := statement["reason"]; present && reason != nil {
		if _, ok := reason.(string); !ok {
			fail("signature_binds_statement")
		}
	}

	revokedMs, revokedOK := parseMillis(getStr(statement, "revoked_at"))
	if !revokedOK {
		fail("revoked_at_present")
	}
	nowMs := time.Now().UnixMilli()
	nowOK := true
	if rawNow, present := opts["now"]; present {
		switch value := rawNow.(type) {
		case string:
			nowMs, nowOK = parseMillis(value)
		case float64:
			if math.IsNaN(value) || math.IsInf(value, 0) {
				nowOK = false
			} else {
				nowMs = int64(value)
			}
		case int:
			nowMs = int64(value)
		case int64:
			nowMs = value
		default:
			nowOK = false
		}
	}
	if !revokedOK || !nowOK || revokedMs > nowMs {
		fail("effective_at_or_before_T")
	}

	recomputed := revocationSignedPayload(statement)
	sig := getStr(proof, "signature_b64u")
	if !(pinned != "" && ed25519VerifyBytes(recomputed, pinned, sig)) {
		verifyKey := pinned
		if verifyKey == "" {
			verifyKey = presented
		}
		sigOverRecomputed := verifyKey != "" && ed25519VerifyBytes(recomputed, verifyKey, sig)
		if sig == "" || verifyKey == "" {
			fail("revoker_signature_valid")
		} else if !sigOverRecomputed {
			fail("signature_binds_statement")
			fail("revoker_signature_valid")
		}
	}

	return CheckResult{allTrue(checks), checks}
}

// IsRevoked reports whether any presented statement validly revokes target.
func IsRevoked(target map[string]any, statements []map[string]any, opts map[string]any) bool {
	for _, s := range statements {
		if VerifyRevocation(target, s, opts).Valid {
			return true
		}
	}
	return false
}

func timeSignedPayload(att map[string]any) []byte {
	return []byte(Canonicalize(map[string]any{
		"@version":        TimeAttestationVersion,
		"hashed":          att["hashed"],
		"time":            att["time"],
		"ts_authority_id": att["ts_authority_id"],
	}))
}

// VerifyTimeAttestation mirrors packages/verify/time-attestation.js. opts keys:
// tsaKeys, expectedHash (string), notBefore/notAfter (RFC3339 strings).
func VerifyTimeAttestation(att, opts map[string]any) CheckResult {
	checks := map[string]bool{
		"version": true, "tsa_key_pinned": true, "time_present": true,
		"signature_valid": true, "hash_bound": true, "within_bounds": true,
	}
	fail := func(k string) { checks[k] = false }
	if att == nil {
		checks["signature_valid"] = false
		return CheckResult{false, checks}
	}
	if getStr(att, "@version") != TimeAttestationVersion {
		fail("version")
	}
	tsaKeys := getMap(opts["tsaKeys"])
	proof := getMap(att["proof"])
	pinned := getStr(getMap(tsaKeys[getStr(att, "ts_authority_id")]), "public_key")
	presented := getStr(proof, "public_key")
	if pinned == "" {
		fail("tsa_key_pinned")
	} else if presented != "" && pinned != presented {
		fail("tsa_key_pinned")
	}
	ms, msOK := parseMillis(getStr(att, "time"))
	if !msOK {
		fail("time_present")
	}
	if !(pinned != "" && ed25519VerifyBytes(timeSignedPayload(att), pinned, getStr(proof, "signature_b64u"))) {
		fail("signature_valid")
	}
	if eh, ok := opts["expectedHash"].(string); ok {
		if hexStrip(att["hashed"]) != hexStrip(eh) {
			fail("hash_bound")
		}
	}
	if msOK {
		if nb, ok := parseMillis(getStr(opts, "notBefore")); ok && ms < nb {
			fail("within_bounds")
		}
		if na, ok := parseMillis(getStr(opts, "notAfter")); ok && ms > na {
			fail("within_bounds")
		}
	}
	return CheckResult{allTrue(checks), checks}
}
