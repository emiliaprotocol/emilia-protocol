// SPDX-License-Identifier: Apache-2.0
//
// EP-INITIATOR-ATTESTATION-v1 — WHICH software asked (Step 6 knob). Faithful
// port of packages/verify/initiator-attestation.js.
//
// A receipt records that a human approved an action. It does not, on its own,
// record which agent/model composed the request the human was shown. This module
// defines a small, canonicalizable attestation naming the initiating software
// (model id + version) and pinning the tool/prompt context it ran, plus an
// OPTIONAL free-text statement the software offers to the human.
//
// HONEST BOUNDARY: an initiator attestation says WHICH software asked. It does
// NOT prove the software behaved. model_id/model_version are self-asserted labels.
// tool_chain_digest binds THIS attestation to a specific tool/prompt context so a
// verifier can detect a SWAPPED context; the digest is authentic-as-supplied, not
// a proof of correct execution.
//
// HOSTILE FREE TEXT: statement is attacker-influenceable and is rendered to a
// human about to approve an irreversible action. It is a presentation-attack
// surface (bidi overrides, C0/C1 controls, homoglyphs). NeutralizeStatement
// strips/escapes bidi + invisible + C0/C1 controls and FLAGS homoglyph risk.
//
// FAIL CLOSED: ValidateInitiatorAttestation refuses on any missing required
// field, any wrong type, any unknown member, and any malformed tool_chain_digest.
// It never repairs a malformed attestation into a passing one.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// InitiatorAttestationVersion is the attestation @version.
const InitiatorAttestationVersion = "EP-INITIATOR-ATTESTATION-v1"

// InitiatorAttestationField is the action-object member under which a bound
// attestation is placed (BindInitiatorInto).
const InitiatorAttestationField = "initiator_software"

// InitiatorStatementMax is the free-text statement hard cap in characters
// (codepoints), measured pre-escape.
const InitiatorStatementMax = 280

// attestationMembers is the closed set of members a valid attestation may carry.
// Unknown members => reject.
var attestationMembers = []string{
	"@version",
	"model_id",
	"model_version",
	"tool_chain_digest",
	"statement",
}

var attestationMemberSet = func() map[string]struct{} {
	m := map[string]struct{}{}
	for _, k := range attestationMembers {
		m[k] = struct{}{}
	}
	return m
}()

// requiredStringMembers MUST be present and non-empty strings.
var requiredStringMembers = []string{"model_id", "model_version"}

var initiatorHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func initiatorSha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NormalizeDigest normalizes a claimed SHA-256 digest to bare lowercase hex, or
// "" when malformed (the fail-closed convention). Accepts an optional "sha256:"
// prefix (any case). Mirrors initiator-attestation.js normalizeDigest.
func NormalizeDigest(h string) string {
	s := h
	if len(s) >= 7 && strings.EqualFold(s[:7], "sha256:") {
		s = s[7:]
	}
	s = strings.ToLower(s)
	if initiatorHex64.MatchString(s) {
		return s
	}
	return ""
}

// bidiCodepoints reorder the visible glyph run relative to logical order.
var bidiCodepoints = map[rune]struct{}{
	0x202a: {}, 0x202b: {}, 0x202c: {}, 0x202d: {}, 0x202e: {}, // LRE RLE PDF LRO RLO
	0x2066: {}, 0x2067: {}, 0x2068: {}, 0x2069: {}, // LRI RLI FSI PDI
	0x200e: {}, 0x200f: {}, 0x061c: {}, // LRM RLM ALM
}

// invisibleCodepoints hide or fuse content: ZWSP ZWNJ ZWJ, WORD JOINER, BOM.
var invisibleCodepoints = map[rune]struct{}{
	0x200b: {}, 0x200c: {}, 0x200d: {}, 0x2060: {}, 0xfeff: {},
}

func isCyrillic(r rune) bool { return r >= 0x0400 && r <= 0x04ff }
func isGreek(r rune) bool    { return r >= 0x0370 && r <= 0x03ff }
func isASCIILetter(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

// StatementReport is the result of NeutralizeStatement.
type StatementReport struct {
	Safe              string // render-safe statement (dangerous codepoints escaped)
	Changed           bool   // true iff any codepoint was escaped
	HomoglyphRisk     bool   // true iff mixed-script / Latin-confusable codepoints present
	EscapedCodepoints []int  // the codepoints that were escaped (forensics)
	Truncated         bool   // true iff the input exceeded InitiatorStatementMax
}

// NeutralizeStatement renders a HOSTILE free-text statement into a form safe to
// place in front of a human. Non-string inputs cannot occur in Go; callers pass
// the raw string. Dangerous codepoints are ESCAPED (visible <U+XXXX> markers),
// not silently deleted. C0/C1 controls (except tab/newline/CR), bidi, and
// zero-width/BOM codepoints are escaped; a homoglyph/mixed-script risk is FLAGGED.
// Length is capped by codepoints BEFORE escaping. Mirrors neutralizeStatement.
func NeutralizeStatement(statement string) StatementReport {
	cps := []rune(statement)
	truncated := len(cps) > InitiatorStatementMax
	bounded := cps
	if truncated {
		bounded = cps[:InitiatorStatementMax]
	}

	escaped := []int{}
	changed := false
	hasNonASCIILetter := false
	hasASCIILetter := false
	hasConfusableScript := false

	var out strings.Builder
	for _, ch := range bounded {
		cp := int(ch)

		if isASCIILetter(ch) {
			hasASCIILetter = true
		}
		if cp > 0x7f && unicode.IsLetter(ch) {
			hasNonASCIILetter = true
		}
		if isCyrillic(ch) || isGreek(ch) {
			hasConfusableScript = true
		}

		_, isBidi := bidiCodepoints[ch]
		_, isInvisible := invisibleCodepoints[ch]
		// C0 controls 0x00-0x1F and C1 controls 0x80-0x9F, minus tab/newline/CR.
		isControl := (cp <= 0x1f && cp != 0x09 && cp != 0x0a && cp != 0x0d) ||
			(cp >= 0x7f && cp <= 0x9f)

		if isBidi || isInvisible || isControl {
			changed = true
			escaped = append(escaped, cp)
			out.WriteString(fmt.Sprintf("<U+%04X>", cp))
			continue
		}
		out.WriteRune(ch)
	}

	homoglyphRisk := hasConfusableScript || (hasNonASCIILetter && hasASCIILetter)

	return StatementReport{
		Safe:              out.String(),
		Changed:           changed,
		HomoglyphRisk:     homoglyphRisk,
		EscapedCodepoints: escaped,
		Truncated:         truncated,
	}
}

// NormalizedAttestation is the canonical stored form of a validated attestation:
// a "sha256:"-prefixed lowercase digest and the NEUTRALIZED statement (never the
// raw hostile bytes). HasStatement distinguishes an absent statement from an
// empty-but-present one.
type NormalizedAttestation struct {
	Version         string
	ModelID         string
	ModelVersion    string
	ToolChainDigest string
	Statement       string
	HasStatement    bool
}

// asMap renders the normalized attestation exactly as the JS `normalized` object
// so Canonicalize/ActionDigest agree byte-for-byte with the JS path.
func (n NormalizedAttestation) asMap() map[string]any {
	m := map[string]any{
		"@version":          n.Version,
		"model_id":          n.ModelID,
		"model_version":     n.ModelVersion,
		"tool_chain_digest": n.ToolChainDigest,
	}
	if n.HasStatement {
		m["statement"] = n.Statement
	}
	return m
}

// InitiatorValidation is the ValidateInitiatorAttestation result.
type InitiatorValidation struct {
	OK              bool
	Normalized      *NormalizedAttestation
	Errors          []string
	StatementReport *StatementReport
}

// ValidateInitiatorAttestation performs FAIL-CLOSED structural validation of an
// attestation supplied as a decoded JSON object (map[string]any). Enforces:
// object shape; only the closed member set; model_id and model_version present
// and non-empty strings; @version, when present, equals the version;
// tool_chain_digest present and a well-formed SHA-256; statement, when present, a
// string within the cap. On any error, OK=false and Normalized=nil. Faithful port
// of validateInitiatorAttestation.
func ValidateInitiatorAttestation(att map[string]any) InitiatorValidation {
	errors := []string{}
	fail := func() InitiatorValidation {
		return InitiatorValidation{OK: false, Normalized: nil, Errors: errors, StatementReport: nil}
	}

	if att == nil {
		errors = append(errors, "initiator attestation must be a non-array object")
		return fail()
	}

	// Closed member set — unknown members are rejected, not ignored. Sort keys so
	// the error order is deterministic across runs (Go map iteration is random).
	keys := make([]string, 0, len(att))
	for k := range att {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, ok := attestationMemberSet[key]; !ok {
			errors = append(errors, fmt.Sprintf("unknown member %q (allowed: %s)", key, strings.Join(attestationMembers, ", ")))
		}
	}

	// Version, when present, must be exactly ours.
	if v, present := att["@version"]; present {
		if vs, ok := v.(string); !ok || vs != InitiatorAttestationVersion {
			errors = append(errors, fmt.Sprintf("@version must be %s when present", InitiatorAttestationVersion))
		}
	}

	// Required identity strings.
	for _, key := range requiredStringMembers {
		v, present := att[key]
		vs, ok := v.(string)
		if !present || !ok || vs == "" {
			errors = append(errors, fmt.Sprintf("%s is required and must be a non-empty string", key))
		}
	}

	// tool_chain_digest: required, well-formed SHA-256.
	tcd, tcdPresent := att["tool_chain_digest"]
	var digestHex string
	if tcds, ok := tcd.(string); ok {
		digestHex = NormalizeDigest(tcds)
	}
	if !tcdPresent || tcd == nil {
		errors = append(errors, "tool_chain_digest is required")
	} else if digestHex == "" {
		errors = append(errors, "tool_chain_digest must be a well-formed SHA-256 (optionally \"sha256:\"-prefixed 64-hex)")
	}

	// statement: optional; must be a string within the cap when present.
	stmt, stmtPresent := att["statement"]
	if stmtPresent {
		if ss, ok := stmt.(string); !ok {
			errors = append(errors, "statement, when present, must be a string")
		} else if len([]rune(ss)) > InitiatorStatementMax {
			errors = append(errors, fmt.Sprintf("statement exceeds the %d-character cap", InitiatorStatementMax))
		}
	}

	if len(errors) > 0 {
		return fail()
	}

	// Neutralize the (validated) statement for the normalized form.
	var statementReport *StatementReport
	if stmtPresent {
		ss, _ := stmt.(string)
		rep := NeutralizeStatement(ss)
		statementReport = &rep
	}

	modelID, _ := att["model_id"].(string)
	modelVersion, _ := att["model_version"].(string)
	normalized := &NormalizedAttestation{
		Version:         InitiatorAttestationVersion,
		ModelID:         modelID,
		ModelVersion:    modelVersion,
		ToolChainDigest: "sha256:" + digestHex,
	}
	if statementReport != nil {
		normalized.Statement = statementReport.Safe
		normalized.HasStatement = true
	}

	return InitiatorValidation{OK: true, Normalized: normalized, Errors: errors, StatementReport: statementReport}
}

// InitiatorBindResult is the BindInitiatorInto result.
type InitiatorBindResult struct {
	Action        map[string]any
	Attestation   *NormalizedAttestation
	DigestPreview string
}

// BindInitiatorInto binds a validated initiator attestation into the ACTION
// digest domain under the reserved member InitiatorAttestationField, so
// model_id/model_version/tool_chain_digest are covered by the human's signature.
// It mirrors the frozen actionHash() definition:
//
//	digest_preview = "sha256:" + sha256(Canonicalize(boundAction))
//
// FAIL CLOSED: returns an error if action is nil, if the attestation does not
// validate, or if the action already carries a DIFFERENT value under the reserved
// member. Faithful port of bindInto.
func BindInitiatorInto(action map[string]any, att map[string]any) (InitiatorBindResult, error) {
	if action == nil {
		return InitiatorBindResult{}, fmt.Errorf("bindInto requires the canonical Action Object")
	}
	v := ValidateInitiatorAttestation(att)
	if !v.OK {
		return InitiatorBindResult{}, fmt.Errorf("bindInto: invalid initiator attestation: %s", strings.Join(v.Errors, "; "))
	}
	normalizedMap := v.Normalized.asMap()
	if existing, present := action[InitiatorAttestationField]; present {
		if Canonicalize(existing) != Canonicalize(normalizedMap) {
			return InitiatorBindResult{}, fmt.Errorf("bindInto: action already carries a different %s; refusing to overwrite", InitiatorAttestationField)
		}
	}
	bound := map[string]any{}
	for k, val := range action {
		bound[k] = val
	}
	bound[InitiatorAttestationField] = normalizedMap
	digestPreview := "sha256:" + initiatorSha256Hex(Canonicalize(bound))
	return InitiatorBindResult{Action: bound, Attestation: v.Normalized, DigestPreview: digestPreview}, nil
}
