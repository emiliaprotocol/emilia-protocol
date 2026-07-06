// SPDX-License-Identifier: Apache-2.0
//
// EP-INITIATOR-ATTESTATION-v1 Go parity tests. Mirror
// packages/verify/initiator-attestation.test.js: happy-path normalization,
// fail-closed rejections, hostile-text neutralization (bidi + C0/C1 controls +
// zero-width/BOM escaped, homoglyph flag, codepoint truncation), and BindInitiatorInto
// composition with the frozen action hash. Hostile codepoints are constructed
// from rune values so the SOURCE stays pure ASCII.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validAtt() map[string]any {
	return map[string]any{
		"model_id":          "anthropic/claude-opus",
		"model_version":     "2026-01-05",
		"tool_chain_digest": digestOf("tool-context"),
	}
}

const (
	rRLO  = '\u202e' // right-to-left override (bidi)
	rNUL  = '\u0000' // C0 control
	rBEL  = '\u0007' // C0 control
	rNEL  = '\u0085' // C1 control
	rZWSP = '\u200b' // zero-width space
	rBOM  = '\ufeff' // BOM / ZWNBSP
	rCYRA = '\u0430' // Cyrillic homoglyph of Latin a
)

func TestInitiatorValidNormalizes(t *testing.T) {
	r := ValidateInitiatorAttestation(validAtt())
	if !r.OK {
		t.Fatalf("expected ok, errors=%v", r.Errors)
	}
	if r.Normalized.Version != InitiatorAttestationVersion {
		t.Fatalf("version=%q", r.Normalized.Version)
	}
	if r.Normalized.ModelID != "anthropic/claude-opus" || r.Normalized.ModelVersion != "2026-01-05" {
		t.Fatalf("model fields wrong: %+v", r.Normalized)
	}
	if r.Normalized.ToolChainDigest != strings.ToLower(digestOf("tool-context")) {
		t.Fatalf("digest=%q", r.Normalized.ToolChainDigest)
	}
	if r.Normalized.HasStatement {
		t.Fatal("statement should be absent")
	}
}

func TestInitiatorBareUppercaseDigestNormalizes(t *testing.T) {
	bare := hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("ctx")); return s[:] }())
	att := validAtt()
	att["tool_chain_digest"] = strings.ToUpper(bare)
	r := ValidateInitiatorAttestation(att)
	if !r.OK {
		t.Fatalf("expected ok, errors=%v", r.Errors)
	}
	if r.Normalized.ToolChainDigest != "sha256:"+bare {
		t.Fatalf("digest=%q want sha256:%s", r.Normalized.ToolChainDigest, bare)
	}
}

func TestInitiatorMissingModelIDRejected(t *testing.T) {
	att := validAtt()
	delete(att, "model_id")
	r := ValidateInitiatorAttestation(att)
	if r.OK || r.Normalized != nil {
		t.Fatal("expected reject with nil normalized")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "model_id is required") {
		t.Fatalf("errors=%v", r.Errors)
	}
}

func TestInitiatorEmptyModelVersionRejected(t *testing.T) {
	att := validAtt()
	att["model_version"] = ""
	r := ValidateInitiatorAttestation(att)
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "model_version is required") {
		t.Fatalf("errors=%v", r.Errors)
	}
}

func TestInitiatorMalformedDigestRejected(t *testing.T) {
	bads := []any{"sha256:xyz", "deadbeef", "sha256:" + repeat("a", 63), 123, nil}
	for _, bad := range bads {
		att := validAtt()
		att["tool_chain_digest"] = bad
		r := ValidateInitiatorAttestation(att)
		if r.OK || r.Normalized != nil {
			t.Fatalf("expected reject for %v", bad)
		}
	}
}

func TestInitiatorMissingDigestRejected(t *testing.T) {
	att := validAtt()
	delete(att, "tool_chain_digest")
	r := ValidateInitiatorAttestation(att)
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "tool_chain_digest is required") {
		t.Fatalf("errors=%v", r.Errors)
	}
}

func TestInitiatorUnknownMemberRejected(t *testing.T) {
	att := validAtt()
	att["evil"] = "x"
	r := ValidateInitiatorAttestation(att)
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), `unknown member "evil"`) {
		t.Fatalf("errors=%v", r.Errors)
	}
}

func TestInitiatorWrongVersionRejected(t *testing.T) {
	att := validAtt()
	att["@version"] = "EP-OTHER-v9"
	r := ValidateInitiatorAttestation(att)
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "@version must be") {
		t.Fatalf("errors=%v", r.Errors)
	}
}

func TestInitiatorNonObjectRejected(t *testing.T) {
	r := ValidateInitiatorAttestation(nil)
	if r.OK || r.Normalized != nil {
		t.Fatal("nil attestation must reject fail-closed")
	}
}

func TestInitiatorStatementWrongTypeRejected(t *testing.T) {
	att := validAtt()
	att["statement"] = map[string]any{"not": "a string"}
	r := ValidateInitiatorAttestation(att)
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "statement, when present, must be a string") {
		t.Fatalf("errors=%v", r.Errors)
	}
}

func TestInitiatorStatementOverCapRejected(t *testing.T) {
	att := validAtt()
	att["statement"] = repeat("a", InitiatorStatementMax+1)
	r := ValidateInitiatorAttestation(att)
	if r.OK {
		t.Fatal("expected reject")
	}
	if !strings.Contains(strings.Join(r.Errors, " "), "exceeds the") {
		t.Fatalf("errors=%v", r.Errors)
	}
}

func TestInitiatorNeutralizeBidiAndControls(t *testing.T) {
	hostile := "send " + string(rRLO) + string(rNUL) + "000,1$" + string(rBEL) + " pay" + string(rNEL) + " now"
	att := validAtt()
	att["statement"] = hostile
	r := ValidateInitiatorAttestation(att)
	if !r.OK {
		t.Fatalf("expected ok, errors=%v", r.Errors)
	}
	safe := r.Normalized.Statement
	for _, cp := range []rune{rRLO, rNUL, rBEL, rNEL} {
		if strings.ContainsRune(safe, cp) {
			t.Fatalf("codepoint U+%04X survived", cp)
		}
	}
	for _, marker := range []string{"<U+202E>", "<U+0000>", "<U+0007>", "<U+0085>"} {
		if !strings.Contains(safe, marker) {
			t.Fatalf("missing escape marker %s in %q", marker, safe)
		}
	}
	if r.StatementReport == nil || !r.StatementReport.Changed {
		t.Fatal("report.changed should be true")
	}
	want := map[int]bool{0x0000: true, 0x0007: true, 0x0085: true, 0x202e: true}
	if len(r.StatementReport.EscapedCodepoints) != len(want) {
		t.Fatalf("escaped=%v", r.StatementReport.EscapedCodepoints)
	}
	for _, cp := range r.StatementReport.EscapedCodepoints {
		if !want[cp] {
			t.Fatalf("unexpected escaped codepoint %d", cp)
		}
	}
}

func TestInitiatorNeutralizePreservesWhitespace(t *testing.T) {
	r := NeutralizeStatement("line1\n\tline2\r ok")
	if r.Safe != "line1\n\tline2\r ok" {
		t.Fatalf("safe=%q", r.Safe)
	}
	if r.Changed || r.HomoglyphRisk {
		t.Fatal("plain text should not change or flag homoglyph")
	}
}

func TestInitiatorNeutralizeZeroWidthAndBOM(t *testing.T) {
	r := NeutralizeStatement("a" + string(rZWSP) + "b" + string(rBOM) + "c")
	if strings.ContainsRune(r.Safe, rZWSP) || strings.ContainsRune(r.Safe, rBOM) {
		t.Fatal("zero-width/BOM survived")
	}
	if !strings.Contains(r.Safe, "<U+200B>") || !strings.Contains(r.Safe, "<U+FEFF>") {
		t.Fatalf("missing markers: %q", r.Safe)
	}
	if !r.Changed {
		t.Fatal("changed should be true")
	}
}

func TestInitiatorNeutralizeHomoglyphFlag(t *testing.T) {
	r := NeutralizeStatement("p" + string(rCYRA) + "y now")
	if !r.HomoglyphRisk {
		t.Fatal("homoglyph_risk should be true")
	}
}

func TestInitiatorNeutralizeTruncation(t *testing.T) {
	r := NeutralizeStatement(repeat("x", InitiatorStatementMax+50))
	if len([]rune(r.Safe)) != InitiatorStatementMax {
		t.Fatalf("len=%d want %d", len([]rune(r.Safe)), InitiatorStatementMax)
	}
	if !r.Truncated {
		t.Fatal("truncated should be true")
	}
}

func TestInitiatorNormalizeDigest(t *testing.T) {
	if NormalizeDigest("sha256:zz") != "" {
		t.Fatal("malformed should be empty")
	}
	good := repeat("a", 64)
	if NormalizeDigest("SHA256:"+strings.ToUpper(good)) != good {
		t.Fatal("uppercase prefixed should normalize")
	}
}

func TestInitiatorBindIntoChangesDigest(t *testing.T) {
	action := map[string]any{"action_type": "wire.transfer", "amount": 100, "initiator": "ep:entity:agent-7"}
	baselineSum := sha256.Sum256([]byte(Canonicalize(action)))
	baseline := "sha256:" + hex.EncodeToString(baselineSum[:])

	att := validAtt()
	att["statement"] = "ok " + string(rRLO) + "spoof"
	res, err := BindInitiatorInto(action, att)
	if err != nil {
		t.Fatalf("bind error: %v", err)
	}
	bound := res.Action[InitiatorAttestationField].(map[string]any)
	if bound["@version"] != InitiatorAttestationVersion {
		t.Fatalf("bound version=%v", bound["@version"])
	}
	stmt, _ := bound["statement"].(string)
	if strings.ContainsRune(stmt, rRLO) {
		t.Fatal("bound statement still carries RLO")
	}
	if !strings.Contains(stmt, "<U+202E>") {
		t.Fatalf("bound statement not neutralized: %q", stmt)
	}
	if res.DigestPreview == baseline {
		t.Fatal("digest should differ from baseline")
	}
	// digest_preview matches the frozen definition.
	boundSum := sha256.Sum256([]byte(Canonicalize(res.Action)))
	want := "sha256:" + hex.EncodeToString(boundSum[:])
	if res.DigestPreview != want {
		t.Fatalf("digest_preview=%q want %q", res.DigestPreview, want)
	}
}

func TestInitiatorBindIntoInvalidThrows(t *testing.T) {
	_, err := BindInitiatorInto(map[string]any{"action_type": "wire.transfer"}, map[string]any{"model_id": "x"})
	if err == nil || !strings.Contains(err.Error(), "invalid initiator attestation") {
		t.Fatalf("expected invalid-attestation error, got %v", err)
	}
}

func TestInitiatorBindIntoRefusesOverwrite(t *testing.T) {
	action := map[string]any{"action_type": "x", InitiatorAttestationField: map[string]any{"model_id": "other"}}
	_, err := BindInitiatorInto(action, validAtt())
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("expected overwrite refusal, got %v", err)
	}
}

func TestInitiatorBindIntoIdempotent(t *testing.T) {
	action := map[string]any{"action_type": "x"}
	once, err := BindInitiatorInto(action, validAtt())
	if err != nil {
		t.Fatalf("first bind: %v", err)
	}
	twice, err := BindInitiatorInto(once.Action, validAtt())
	if err != nil {
		t.Fatalf("second bind: %v", err)
	}
	if once.DigestPreview != twice.DigestPreview {
		t.Fatalf("not idempotent: %q vs %q", once.DigestPreview, twice.DigestPreview)
	}
}

func TestInitiatorBindIntoRequiresObject(t *testing.T) {
	_, err := BindInitiatorInto(nil, validAtt())
	if err == nil || !strings.Contains(err.Error(), "requires the canonical Action Object") {
		t.Fatalf("expected object-required error, got %v", err)
	}
}
