// caid.go - CAID v1 reference implementation (Go, stdlib only).
//
// Conforms to DESIGN.md (the normative core of this package).
// Suite support: jcs-sha256 only. cbor-sha256 is defined in the suite
// registry but is NOT implemented here; this implementation refuses it
// as unknown_suite. Say so honestly everywhere.
//
// Scope (from DESIGN.md section 5): CAID carries no trust semantics.
// It proves that artifacts reference the same typed content. It does not
// prove the action was authorized, executed, safe, or wise. Nothing in
// this package verifies signatures, identity, or authorization.
//
// Fail-closed: junk input returns refusals with reasons, never panics.
//
// Input model: action objects and definitions are generic decoded JSON
// values. Callers MUST decode JSON with json.Decoder.UseNumber() so
// numbers arrive as json.Number, never float64 (bare .(float64)
// assertions are the classic fail-open; none exist here). Numbers follow
// the value-based rule (DESIGN.md section 1): a number is accepted iff
// its IEEE 754 double value is an integer with magnitude at most 2^53-1,
// regardless of literal form, so "1e3" and "2.0" are the integers 1000
// and 2 exactly as ECMAScript's JSON.parse sees them; fractional, NaN,
// infinite, or out-of-range values refuse as unsupported_number in every
// conforming implementation.
package caid

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const caidVersion = "1"

// maxSafeInteger is 2^53-1, the largest integer every conforming
// implementation (including the ECMAScript reference) represents exactly.
const maxSafeInteger int64 = 1<<53 - 1

var supportedSuites = map[string]bool{"jcs-sha256": true}

// sha256Suites are the suites defined in the registry that use a SHA-256
// digest (43 unpadded base64url characters). Used for strict
// digest-length checking at parse time.
var sha256Suites = map[string]bool{"jcs-sha256": true, "cbor-sha256": true}

const sha256B64urlLen = 43

// Grammar (strict, per DESIGN.md sections 2 and 3).
var (
	typeSegmentRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	typeVersionRe = regexp.MustCompile(`^[1-9][0-9]*$`)
	suiteRe       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	b64urlRe      = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	amountRe      = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	digestFieldRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// RFC 3339, UTC, trailing Z required. Optional fractional seconds.
	timestampRe = regexp.MustCompile(
		`^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?Z$`)
)

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

// ComputeResult is the outcome of ComputeCaid. On success Caid and
// Digest are set and Refusals is empty; on any failure Refusals is
// non-empty and no caid is emitted.
type ComputeResult struct {
	Caid     string   `json:"caid,omitempty"`
	Digest   string   `json:"digest,omitempty"`
	Refusals []string `json:"refusals,omitempty"`
}

// VerifyResult is the outcome of VerifyCaid. Same inputs, same reasons,
// same order, replayable offline by any third party.
type VerifyResult struct {
	Valid   bool     `json:"valid"`
	Reasons []string `json:"reasons"`
}

// ParsedCaid holds the four components of a strict-parsed CAID string.
type ParsedCaid struct {
	Version    string `json:"version"`
	ActionType string `json:"action_type"`
	Suite      string `json:"suite"`
	Digest     string `json:"digest"`
}

// ParseResult is the outcome of ParseCaid.
type ParseResult struct {
	OK       bool        `json:"ok"`
	Caid     *ParsedCaid `json:"caid,omitempty"`
	Refusals []string    `json:"refusals,omitempty"`
}

// CanonicalizeResult is the outcome of Canonicalize.
type CanonicalizeResult struct {
	OK        bool     `json:"ok"`
	Canonical string   `json:"canonical,omitempty"`
	Refusals  []string `json:"refusals,omitempty"`
}

// ComputeOptions carries the suite and the type definitions ComputeCaid
// validates against. Definitions is a slice of decoded JSON objects in
// the registry entry schema (DESIGN.md section 3); a local definitions
// file in the same schema works identically.
type ComputeOptions struct {
	Suite       string
	Definitions []interface{}
}

// VerifyOptions carries the type definitions VerifyCaid validates
// against.
type VerifyOptions struct {
	Definitions []interface{}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func asObject(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

func isValidActionType(t string) bool {
	segments := strings.Split(t, ".")
	if len(segments) < 2 {
		return false
	}
	if !typeVersionRe.MatchString(segments[len(segments)-1]) {
		return false
	}
	for _, seg := range segments[:len(segments)-1] {
		if !typeSegmentRe.MatchString(seg) {
			return false
		}
	}
	return true
}

func daysInMonth(year, month int) int {
	// month is 1-12
	if month == 2 {
		leap := (year%4 == 0 && year%100 != 0) || year%400 == 0
		if leap {
			return 29
		}
		return 28
	}
	switch month {
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

func isValidTimestamp(s string) bool {
	m := timestampRe.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	// The regexp constrains these submatches to digits; Atoi cannot fail.
	year, _ := strconv.Atoi(m[1])
	month, _ := strconv.Atoi(m[2])
	day, _ := strconv.Atoi(m[3])
	return day <= daysInMonth(year, month)
}

func resolveDefinition(actionType string, definitions []interface{}) map[string]interface{} {
	for _, entry := range definitions {
		def, ok := asObject(entry)
		if !ok {
			continue
		}
		at, ok := def["action_type"].(string)
		if ok && at == actionType {
			return def
		}
	}
	return nil
}

// integerLiteral inspects a decoded JSON number and returns its
// canonical integer serialization under the value-based rule (DESIGN.md
// section 1): a number is accepted iff its IEEE 754 double value is an
// integer with magnitude at most 2^53-1. Literal form is irrelevant:
// "1e3" and "2.0" are the integers 1000 and 2, exactly as JavaScript
// sees them after JSON.parse. ok is false for fractional, NaN,
// infinite, or out-of-range values.
func integerLiteral(v interface{}) (string, bool) {
	switch n := v.(type) {
	case json.Number:
		s := string(n)
		if !strings.ContainsAny(s, ".eE") {
			i, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				// Plain-decimal literal too large for int64: its
				// double value is far outside the safe range.
				return "", false
			}
			if i > maxSafeInteger || i < -maxSafeInteger {
				return "", false
			}
			// JSON grammar allows "-0"; ECMAScript serializes it as "0".
			return strconv.FormatInt(i, 10), true
		}
		// Exponent or fractional form: evaluate the double value the
		// way every JSON parser in the other implementations does
		// (strconv.ParseFloat is correctly rounded, like JSON.parse).
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return "", false
		}
		return integerFromDouble(f)
	case float64:
		// Reachable when a caller decoded without UseNumber.
		return integerFromDouble(n)
	case int:
		return integerLiteral(json.Number(strconv.Itoa(n)))
	case int64:
		return integerLiteral(json.Number(strconv.FormatInt(n, 10)))
	}
	return "", false
}

// integerFromDouble applies the value-based rule to an IEEE 754 double.
func integerFromDouble(f float64) (string, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", false
	}
	if f != math.Trunc(f) {
		return "", false
	}
	if f > float64(maxSafeInteger) || f < -float64(maxSafeInteger) {
		return "", false
	}
	return strconv.FormatInt(int64(f), 10), true
}

func isJSONNumber(v interface{}) bool {
	switch v.(type) {
	case json.Number, float64, int, int64:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Canonicalization: RFC 8785 JCS, implemented inline.
//
// DESIGN.md section 1: a JSON number is accepted iff its IEEE 754
// double value is an integer with magnitude at most 2^53-1, so the only
// numbers this canonicalizer serializes are in-range integers, which
// serialize as plain decimal under the ECMAScript algorithm RFC 8785
// requires. Object keys are sorted by
// UTF-16 code units as RFC 8785 mandates; Go strings are UTF-8, so keys
// are explicitly re-encoded to UTF-16 for comparison (byte order of
// UTF-8 diverges from UTF-16 code unit order for non-BMP characters).
// String escaping is the minimal RFC 8785 form (short escapes, lowercase
// \u00xx for other control characters, literal UTF-8 otherwise); Go's
// json.Marshal escapes '<', '>', and '&', so a custom writer is used.
// ---------------------------------------------------------------------------

// Canonicalize serializes a decoded JSON value to its RFC 8785 JCS form.
//
// Refusals:
//
//	unsupported_number - a number whose IEEE 754 double value is not an
//	                     integer with magnitude at most 2^53-1
//	                     (fractional, NaN, infinite, or out of range)
//	unsupported_value  - a Go value with no JSON representation (a type
//	                     json.Decoder never produces). Cannot arise from
//	                     decoded JSON input; exists so junk Go input
//	                     fails closed instead of being silently dropped.
func Canonicalize(value interface{}) CanonicalizeResult {
	var refusals []string
	var sb strings.Builder
	serialize(&sb, value, &refusals)
	if len(refusals) > 0 {
		return CanonicalizeResult{OK: false, Refusals: dedupe(refusals)}
	}
	return CanonicalizeResult{OK: true, Canonical: sb.String()}
}

func serialize(sb *strings.Builder, v interface{}, refusals *[]string) {
	if v == nil {
		sb.WriteString("null")
		return
	}
	switch t := v.(type) {
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case json.Number, float64, int, int64:
		lit, ok := integerLiteral(t)
		if !ok {
			*refusals = append(*refusals, "unsupported_number")
			return
		}
		sb.WriteString(lit)
	case string:
		writeJCSString(sb, t)
	case []interface{}:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			serialize(sb, x, refusals)
		}
		sb.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeJCSString(sb, k)
			sb.WriteByte(':')
			serialize(sb, t[k], refusals)
		}
		sb.WriteByte('}')
	default:
		*refusals = append(*refusals, "unsupported_value")
	}
}

// writeJCSString writes s as an RFC 8785 JSON string: only '"', '\\',
// and control characters below 0x20 are escaped; the two-character short
// escapes are used where they exist, lowercase \u00xx otherwise; all
// other characters are literal UTF-8.
func writeJCSString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\t':
			sb.WriteString(`\t`)
		case '\n':
			sb.WriteString(`\n`)
		case '\f':
			sb.WriteString(`\f`)
		case '\r':
			sb.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// sortUTF16 sorts keys by their UTF-16 code unit sequences, the order
// RFC 8785 requires. Sorting UTF-8 bytes instead would misorder any key
// containing a supplementary-plane character relative to keys with
// characters in U+E000..U+FFFF.
func sortUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})
}

func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	n := len(ua)
	if len(ub) < n {
		n = len(ub)
	}
	for i := 0; i < n; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Material-field validation (DESIGN.md sections 3 and 4).
// Refusals are returned in deterministic order: all
// missing_material_field (definition order), then all mistyped_field /
// invalid_amount (definition order, required fields then optional
// fields).
// ---------------------------------------------------------------------------

func fieldList(def map[string]interface{}, key string) []map[string]interface{} {
	raw, ok := def[key].([]interface{})
	if !ok {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(raw))
	for _, e := range raw {
		if m, isObj := asObject(e); isObj {
			out = append(out, m)
		}
	}
	return out
}

func validateAgainstDefinition(obj map[string]interface{}, def map[string]interface{}) []string {
	var refusals []string
	required := fieldList(def, "required_fields")
	optional := fieldList(def, "optional_fields")
	for _, f := range required {
		name, ok := f["name"].(string)
		if !ok {
			continue
		}
		if _, present := obj[name]; !present {
			refusals = append(refusals, "missing_material_field:"+name)
		}
	}
	all := make([]map[string]interface{}, 0, len(required)+len(optional))
	all = append(all, required...)
	all = append(all, optional...)
	for _, f := range all {
		name, ok := f["name"].(string)
		if !ok {
			continue
		}
		value, present := obj[name]
		if !present {
			continue
		}
		if code := checkFieldType(value, f); code != "" {
			refusals = append(refusals, code+":"+name)
		}
	}
	return refusals
}

// checkFieldType returns "" when valid, else "mistyped_field" or
// "invalid_amount".
func checkFieldType(value interface{}, field map[string]interface{}) string {
	ftype, ok := field["type"].(string)
	if !ok {
		// A definition entry without a string type: fail closed.
		return "mistyped_field"
	}
	switch ftype {
	case "string":
		if _, isStr := value.(string); isStr {
			return ""
		}
		return "mistyped_field"
	case "amount-string":
		s, isStr := value.(string)
		if !isStr {
			return "mistyped_field"
		}
		if amountRe.MatchString(s) {
			return ""
		}
		return "invalid_amount"
	case "digest":
		s, isStr := value.(string)
		if !isStr || !digestFieldRe.MatchString(s) {
			return "mistyped_field"
		}
		return ""
	case "enum":
		s, isStr := value.(string)
		if !isStr {
			return "mistyped_field"
		}
		if values, hasValues := field["values"].([]interface{}); hasValues {
			for _, v := range values {
				if vs, isVStr := v.(string); isVStr && vs == s {
					return ""
				}
			}
			return "mistyped_field"
		}
		return ""
	case "timestamp":
		s, isStr := value.(string)
		if !isStr || !isValidTimestamp(s) {
			return "mistyped_field"
		}
		return ""
	case "integer":
		if !isJSONNumber(value) {
			return "mistyped_field"
		}
		if _, isInt := integerLiteral(value); !isInt {
			return "mistyped_field"
		}
		return ""
	case "boolean":
		if _, isBool := value.(bool); isBool {
			return ""
		}
		return "mistyped_field"
	case "object":
		if _, isObj := asObject(value); isObj {
			return ""
		}
		return "mistyped_field"
	case "array":
		if _, isArr := value.([]interface{}); isArr {
			return ""
		}
		return "mistyped_field"
	default:
		// Unknown declared field type in the definition: fail closed.
		return "mistyped_field"
	}
}

func sha256Digest(canonical string) []byte {
	sum := sha256.Sum256([]byte(canonical))
	return sum[:]
}

// ---------------------------------------------------------------------------
// ComputeCaid (DESIGN.md section 4, conforming issuer)
// ---------------------------------------------------------------------------

// ComputeCaid validates actionObject against its type definition,
// canonicalizes it under the requested suite, and emits the caid string
// plus a "sha256:" + lowercase hex digest. Any failure returns a
// non-empty Refusals list and no caid; it never panics on junk input.
//
// actionObject is a decoded JSON value (decode with UseNumber; see the
// package comment).
func ComputeCaid(actionObject interface{}, opts ComputeOptions) ComputeResult {
	// Step 1: action_type present and grammar-valid.
	obj, ok := asObject(actionObject)
	if !ok {
		return ComputeResult{Refusals: []string{"invalid_action_type"}}
	}
	actionType, ok := obj["action_type"].(string)
	if !ok || !isValidActionType(actionType) {
		return ComputeResult{Refusals: []string{"invalid_action_type"}}
	}

	// Step 2: type resolvable in the configured definitions.
	def := resolveDefinition(actionType, opts.Definitions)
	if def == nil {
		return ComputeResult{Refusals: []string{"unknown_action_type"}}
	}

	var refusals []string

	// Steps 3-4: material fields present and type-valid.
	refusals = append(refusals, validateAgainstDefinition(obj, def)...)

	// Step 5: suite known (and implemented here).
	if !supportedSuites[opts.Suite] {
		refusals = append(refusals, "unknown_suite")
	}

	// Step 6: no non-integer number anywhere in the object.
	canon := Canonicalize(actionObject)
	if !canon.OK {
		refusals = append(refusals, canon.Refusals...)
	}

	if len(refusals) > 0 {
		return ComputeResult{Refusals: refusals}
	}

	// Step 7: canonicalize, digest, emit.
	digestBytes := sha256Digest(canon.Canonical)
	b64 := base64.RawURLEncoding.EncodeToString(digestBytes)
	return ComputeResult{
		Caid:   "caid:" + caidVersion + ":" + actionType + ":" + opts.Suite + ":" + b64,
		Digest: "sha256:" + hex.EncodeToString(digestBytes),
	}
}

// ---------------------------------------------------------------------------
// ParseCaid (strict parser, DESIGN.md section 2)
// ---------------------------------------------------------------------------

// ParseCaid strict-parses a CAID string. It refuses padding, uppercase
// in type or suite, empty segments, trailing content, unknown version,
// and (for known sha256 suites) a digest of the wrong length. Unknown
// version is a refusal, never a guess.
func ParseCaid(input string) ParseResult {
	refuse := ParseResult{OK: false, Refusals: []string{"malformed_caid"}}
	parts := strings.Split(input, ":")
	if len(parts) != 5 {
		return refuse // trailing content adds parts
	}
	prefix, version, actionType, suite, digest := parts[0], parts[1], parts[2], parts[3], parts[4]
	if prefix != "caid" {
		return refuse
	}
	if version != caidVersion {
		return refuse
	}
	if !isValidActionType(actionType) {
		return refuse
	}
	if !suiteRe.MatchString(suite) {
		return refuse
	}
	if !b64urlRe.MatchString(digest) {
		return refuse // refuses padding and junk
	}
	if sha256Suites[suite] && len(digest) != sha256B64urlLen {
		return refuse
	}
	return ParseResult{
		OK: true,
		Caid: &ParsedCaid{
			Version:    version,
			ActionType: actionType,
			Suite:      suite,
			Digest:     digest,
		},
	}
}

// ---------------------------------------------------------------------------
// VerifyCaid (DESIGN.md section 4, conforming verifier)
// ---------------------------------------------------------------------------

// VerifyCaid checks that actionObject is the typed content caidString
// identifies. Same inputs, same reasons, same order, replayable offline.
// Reason order: malformed_caid (alone), else action_type_mismatch, then
// unknown_suite or digest_mismatch, then invalid_object.
//
// Note: a valid CAID proves only that this object is the typed content
// the identifier was computed over. It proves nothing about
// authorization, execution, or trust.
func VerifyCaid(actionObject interface{}, caidString string, opts VerifyOptions) VerifyResult {
	// Step 1: strict-parse the string.
	parsed := ParseCaid(caidString)
	if !parsed.OK {
		return VerifyResult{Valid: false, Reasons: []string{"malformed_caid"}}
	}

	// A non-object cannot carry an action_type or be recomputed: fail
	// closed as an invalid object.
	obj, isObj := asObject(actionObject)
	if !isObj {
		return VerifyResult{Valid: false, Reasons: []string{"invalid_object"}}
	}

	reasons := []string{}

	// Step 2: in-object action_type equals the CAID's type. This check
	// is where cross-context reinterpretation dies (no domain-separation
	// prefix exists by design); skipping it re-opens that attack.
	objType, objTypeIsString := obj["action_type"].(string)
	if !objTypeIsString || objType != parsed.Caid.ActionType {
		reasons = append(reasons, "action_type_mismatch")
	}

	// Step 3: recompute under the CAID's suite.
	canon := Canonicalize(actionObject)
	if !supportedSuites[parsed.Caid.Suite] {
		// cbor-sha256 is defined in the registry but not implemented
		// here.
		reasons = append(reasons, "unknown_suite")
	} else if canon.OK {
		b64 := base64.RawURLEncoding.EncodeToString(sha256Digest(canon.Canonical))
		if b64 != parsed.Caid.Digest {
			reasons = append(reasons, "digest_mismatch")
		}
	}
	// If canonicalization refused, the digest cannot be recomputed; the
	// material validation below reports the object as invalid.

	// Step 4: the SAME material validation as compute. A CAID whose
	// object fails validation is invalid_object, not merely mismatched.
	var validationRefusals []string
	if !objTypeIsString || !isValidActionType(objType) {
		validationRefusals = append(validationRefusals, "invalid_action_type")
	} else {
		def := resolveDefinition(objType, opts.Definitions)
		if def == nil {
			validationRefusals = append(validationRefusals, "unknown_action_type")
		} else {
			validationRefusals = append(validationRefusals, validateAgainstDefinition(obj, def)...)
		}
	}
	if !canon.OK {
		validationRefusals = append(validationRefusals, canon.Refusals...)
	}
	if len(validationRefusals) > 0 {
		reasons = append(reasons, "invalid_object")
	}

	return VerifyResult{Valid: len(reasons) == 0, Reasons: reasons}
}
