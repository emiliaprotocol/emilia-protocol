// SPDX-License-Identifier: Apache-2.0
// EP-EVIDENCE-RECORD-v1 — Go parity with packages/verify/evidence-record.js and
// python-verify verify_evidence_record. Long-term, crypto-agile preservation
// (RFC 4998-style renewal chain): each renewal re-timestamps the previous
// attestation under a possibly-stronger hash. Composes VerifyTimeAttestation.
package emiliaverify

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
)

const EvidenceRecordVersion = "EP-EVIDENCE-RECORD-v1"

func algOf(hashed any) (string, string) {
	s, _ := hashed.(string)
	i := strings.Index(s, ":")
	if i < 0 {
		return "sha256", strings.ToLower(s)
	}
	return strings.ToLower(s[:i]), strings.ToLower(s[i+1:])
}

func hashHexWith(alg string, b []byte) (string, bool) {
	switch alg {
	case "sha256":
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]), true
	case "sha384":
		sum := sha512.Sum384(b)
		return hex.EncodeToString(sum[:]), true
	case "sha512":
		sum := sha512.Sum512(b)
		return hex.EncodeToString(sum[:]), true
	default:
		return "", false
	}
}

// EvidenceRecordResult mirrors the JS { valid, checks } shape.
type EvidenceRecordResult struct {
	Valid  bool            `json:"valid"`
	Checks map[string]bool `json:"checks"`
}

// VerifyEvidenceRecord verifies an EP-EVIDENCE-RECORD-v1 chain. opts keys:
// tsaKeys (map of ts_authority_id -> {public_key}), protectedHash (string).
func VerifyEvidenceRecord(record map[string]any, opts map[string]any) EvidenceRecordResult {
	checks := map[string]bool{
		"version": false, "protected_bound": true, "chain_nonempty": false,
		"all_timestamps_valid": true, "chain_linked": true, "monotonic_time": true,
	}
	fail := func(k string) { checks[k] = false }
	if record == nil || getStr(record, "@version") != EvidenceRecordVersion {
		return EvidenceRecordResult{false, checks}
	}
	checks["version"] = true
	atsAny, _ := record["archive_timestamps"].([]any)
	checks["chain_nonempty"] = len(atsAny) > 0
	if !checks["chain_nonempty"] {
		return EvidenceRecordResult{false, checks}
	}
	tsaKeys := getMap(opts["tsaKeys"])
	if ph, ok := opts["protectedHash"].(string); ok {
		_, a := algOf(record["protected_hash"])
		_, b := algOf(ph)
		if a != b {
			fail("protected_bound")
		}
	}
	var prevTime int64
	havePrev := false
	for i, atAny := range atsAny {
		ta := getMap(getMap(atAny)["time_attestation"])
		if !VerifyTimeAttestation(ta, map[string]any{"tsaKeys": tsaKeys}).Valid {
			fail("all_timestamps_valid")
		}
		alg, hx := algOf(ta["hashed"])
		if i == 0 {
			if _, ph := algOf(record["protected_hash"]); hx != ph {
				fail("chain_linked")
			}
		} else {
			prevTA := getMap(getMap(atsAny[i-1])["time_attestation"])
			expected, ok := hashHexWith(alg, []byte(Canonicalize(prevTA)))
			if !ok || hx != expected {
				fail("chain_linked")
			}
		}
		if t, ok := parseMillis(getStr(ta, "time")); ok {
			if havePrev && !(t > prevTime) {
				fail("monotonic_time")
			}
			prevTime = t
			havePrev = true
		} else {
			fail("monotonic_time")
		}
	}
	return EvidenceRecordResult{allTrue(checks), checks}
}
