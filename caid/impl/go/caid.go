// SPDX-License-Identifier: Apache-2.0

// Package caid is the Go implementation of the Canonical Action Identifier,
// draft-schrock-canonical-action-identifier-04. It uses the standard library
// only.
//
// The draft is the normative text. The grammar, limits, reason codes, reason
// ranks, field types and verification details are constants generated from
// it (spec_gen.go, written by caid/spec/gen.mjs from caid/spec); this file
// implements the semantic checks around them.
//
// Suites: jcs-sha256 only. cbor-sha256 is registered and therefore parses,
// but it is not implemented here: computation and verification refuse it as
// unknown_suite.
//
// Scope: a CAID carries no trust semantics. It shows that two artifacts
// reference the same typed content. It does not show that the action was
// authorized, executed, safe or wise. Nothing in this package verifies a
// signature, an identity or an authorization.
//
// # Input
//
// JSON text received from anywhere MUST go through a JSON text entry point:
// ComputeCaidJSON, VerifyCaidJSON, or DecodeJSON followed by the host-value
// entry point. They apply draft -04 Section 2.4 (see DecodeJSON) and refuse
// any other text as malformed_json. Decoding received text with encoding/json
// and passing the result here is not conforming: encoding/json replaces an
// unpaired surrogate escape with U+FFFD and keeps the last of duplicate
// member names, which changes the content being identified.
//
// ComputeCaid, VerifyCaid, MapAction and Canonicalize take host values: the
// output of DecodeJSON, or a value the application built itself. The data
// model accepts exactly:
//
//   - map[string]interface{} (not nil) for an object;
//   - []interface{} (not nil) for an array;
//   - string, holding valid UTF-8 with no noncharacter;
//   - bool, and nil for null;
//   - json.Number holding one RFC 8259 number token, float64, int or int64
//     for a number.
//
// Any other host value is refused, never rewritten: a nil map or slice, a
// struct, another numeric type, a string that is not valid UTF-8 (the form an
// unpaired surrogate takes in a Go string), a value nested deeper than 64, or
// a cyclic value. The refusal is unsupported_value, plus mistyped_field when a
// declared field holds the value. A number is accepted when the IEEE 754
// binary64 value nearest to it (ties to even) is an integer of magnitude at
// most 2^53-1, whatever its literal form: "1e3" and "2.0" are the integers
// 1000 and 2, "1e-400" is the integer 0, and "1e400" overflows and is refused
// as unsupported_number. For every value DecodeJSON can produce, the host
// entry point returns exactly what the JSON text entry point returns for the
// text.
//
// Every entry point returns refusals with reasons. None panics on any input,
// including cyclic and very deep host values.
package caid

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"caid/internal/jsontext"
)

// implementedSuites are the registered suites this implementation computes.
var implementedSuites = map[string]bool{"jcs-sha256": true}

// hostVisitLimit bounds the number of host values one canonicalization
// visits. Every value DecodeJSON produces takes at least one octet of a text
// of at most specLimitJsonTextOctets octets, so no decoded value comes near
// it; it exists so that a host value which shares subvalues many times over
// (a DAG whose expansion is exponential) is refused in bounded time.
const hostVisitLimit = specLimitJsonTextOctets

// uncappedOutputLimit bounds the canonical output of a document that has no
// canonical-size limit (definitions, enum snapshots, mapping profiles and
// sources). The canonical form of a JSON text is at most four times its
// length (the token "1e15" becomes sixteen digits), so no value decoded from
// a text of at most specLimitJsonTextOctets octets reaches it.
const uncappedOutputLimit = 4 * specLimitJsonTextOctets

// ---------------------------------------------------------------------------
// Result and option types
// ---------------------------------------------------------------------------

// ComputeResult is the outcome of ComputeCaid. On success Caid, Digest and
// DefinitionSha256 are set and Refusals is empty; on failure Refusals is
// non-empty and nothing else is set.
type ComputeResult struct {
	Caid             string   `json:"caid,omitempty"`
	Digest           string   `json:"digest,omitempty"`
	DefinitionSha256 string   `json:"definition_sha256,omitempty"`
	Refusals         []string `json:"refusals,omitempty"`
}

// VerifyDetail is one verification detail: the reason, the field it names
// (nil for none), the rule it broke, and the JSON kind observed (nil for
// none). The shape is closed; draft -04 Appendix B and caid/spec/core.json
// define the values for each reason.
type VerifyDetail struct {
	Reason   string  `json:"reason"`
	Field    *string `json:"field"`
	Rule     string  `json:"rule"`
	Observed *string `json:"observed"`
}

// VerifyResult is the outcome of VerifyCaid. Details is never nil: one
// detail per reason, in order, except that invalid_object is replaced by one
// detail per underlying computation reason. DefinitionSha256 is set whenever
// a conforming definition resolved.
type VerifyResult struct {
	Valid            bool           `json:"valid"`
	Reasons          []string       `json:"reasons"`
	Details          []VerifyDetail `json:"details"`
	DefinitionSha256 string         `json:"definition_sha256,omitempty"`
}

// ParsedCaid holds the four components of a strict-parsed CAID string.
type ParsedCaid struct {
	Version    string `json:"version"`
	ActionType string `json:"action_type"`
	Suite      string `json:"suite"`
	Digest     string `json:"digest"`
}

// ParseResult is the outcome of ParseCaid: exactly one reason on refusal.
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

// DefinitionDigestResult is the outcome of DefinitionSha256.
type DefinitionDigestResult struct {
	DefinitionSha256 string   `json:"definition_sha256,omitempty"`
	Refusals         []string `json:"refusals,omitempty"`
}

// ComputeOptions carries the suite, the type definitions and the enum
// snapshots ComputeCaid validates against. Definitions and EnumSnapshots
// hold host values in the registry schemas; local definitions in the same
// schema work identically. The suite is never defaulted: an empty Suite is
// refused as unknown_suite.
type ComputeOptions struct {
	Suite         string
	Definitions   []interface{}
	EnumSnapshots []interface{}
}

// VerifyOptions carries the definitions and enum snapshots VerifyCaid
// validates against. ExpectedDefinitionSha256, when not nil, pins the
// definition_sha256 the resolved definition must have; a conforming
// definition with any other digest adds definition_mismatch.
type VerifyOptions struct {
	Definitions              []interface{}
	EnumSnapshots            []interface{}
	ExpectedDefinitionSha256 *string
}

// ---------------------------------------------------------------------------
// The data model
// ---------------------------------------------------------------------------

// asObject returns v as a data-model object: a non-nil map[string]interface{}.
func asObject(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok && m != nil
}

// asArray returns v as a data-model array: a non-nil []interface{}.
func asArray(v interface{}) ([]interface{}, bool) {
	a, ok := v.([]interface{})
	return a, ok && a != nil
}

// kindOf is the JSON kind of a host value, or "" for a value outside the data
// model's kinds. A string that is not a data-model string (invalid UTF-8, a
// noncharacter) and a number whose value is refused still have their kind.
func kindOf(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case json.Number, float64, int, int64:
		return "number"
	case string:
		return "string"
	case []interface{}:
		if t != nil {
			return "array"
		}
	case map[string]interface{}:
		if t != nil {
			return "object"
		}
	}
	return ""
}

// isDataModelString reports whether s is a sequence of Unicode scalar values
// with no noncharacter, the strings of an I-JSON message.
func isDataModelString(s string) bool {
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if jsontext.IsNoncharacter(r) {
			return false
		}
		i += size
	}
	return true
}

// numberValue returns the binary64 value of a host number: the value nearest
// to a json.Number token (ties to even), or the float64 itself. ok is false
// for a json.Number that is not an RFC 8259 number token. An int or int64 is
// reported through exact instead.
func numberValue(v interface{}) (f float64, exact int64, isExact bool, ok bool) {
	switch n := v.(type) {
	case json.Number:
		s := string(n)
		if !jsontext.IsNumberToken(s) {
			return 0, 0, false, false
		}
		parsed, err := strconv.ParseFloat(s, 64)
		if err != nil {
			if ne, isNumErr := err.(*strconv.NumError); !isNumErr || ne.Err != strconv.ErrRange {
				return 0, 0, false, false
			}
			// ErrRange: the token overflows binary64 and parsed is
			// +/-Inf, which the value rule refuses.
		}
		return parsed, 0, false, true
	case float64:
		return n, 0, false, true
	case int:
		return 0, int64(n), true, true
	case int64:
		return 0, n, true, true
	}
	return 0, 0, false, false
}

// integerLiteral applies the number rule: the value must be a finite integer
// of magnitude at most 2^53-1. It returns the canonical decimal form.
func integerLiteral(v interface{}) (string, bool) {
	f, exact, isExact, ok := numberValue(v)
	if !ok {
		return "", false
	}
	if isExact {
		if exact > specLimitMaxSafeInteger || exact < -specLimitMaxSafeInteger {
			return "", false
		}
		return strconv.FormatInt(exact, 10), true
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return "", false
	}
	if f > specLimitMaxSafeInteger || f < -specLimitMaxSafeInteger {
		return "", false
	}
	return strconv.FormatInt(int64(f), 10), true // -0 becomes "0"
}

// isIntegralNumber is the integer field type: the number's value is a finite
// integer, whatever its literal form. Magnitude is not checked here; an
// integer beyond 2^53-1 is type-valid and refused once, as
// unsupported_number.
func isIntegralNumber(v interface{}) bool {
	f, _, isExact, ok := numberValue(v)
	if !ok {
		return false
	}
	if isExact {
		return true
	}
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f)
}

// ---------------------------------------------------------------------------
// Canonicalization: RFC 8785 JCS over the data model
// ---------------------------------------------------------------------------

type canonicalizer struct {
	sb      strings.Builder
	maxOut  int
	over    bool
	number  bool
	other   bool
	stopped bool
	visits  int
}

func (c *canonicalizer) write(s string) {
	if c.over {
		return
	}
	if c.sb.Len()+len(s) > c.maxOut {
		c.over = true
		return
	}
	c.sb.WriteString(s)
}

func (c *canonicalizer) writeByte(b byte) {
	if c.over {
		return
	}
	if c.sb.Len()+1 > c.maxOut {
		c.over = true
		return
	}
	c.sb.WriteByte(b)
}

// walk serializes v. It descends at most specLimitNestingDepth levels, so a
// cyclic host value ends as unsupported_value instead of exhausting the
// stack, and it visits at most hostVisitLimit values.
func (c *canonicalizer) walk(v interface{}, depth int) {
	if c.stopped {
		return
	}
	c.visits++
	if c.visits > hostVisitLimit {
		c.other = true
		c.stopped = true
		return
	}
	switch t := v.(type) {
	case nil:
		c.write("null")
	case bool:
		if t {
			c.write("true")
		} else {
			c.write("false")
		}
	case json.Number, float64, int, int64:
		lit, ok := integerLiteral(t)
		if !ok {
			c.number = true
			return
		}
		c.write(lit)
	case string:
		if !isDataModelString(t) {
			c.other = true
			return
		}
		c.writeString(t)
	case []interface{}:
		if t == nil || depth+1 > specLimitNestingDepth {
			c.other = true
			return
		}
		c.writeByte('[')
		for i, x := range t {
			if i > 0 {
				c.writeByte(',')
			}
			c.walk(x, depth+1)
		}
		c.writeByte(']')
	case map[string]interface{}:
		if t == nil || depth+1 > specLimitNestingDepth {
			c.other = true
			return
		}
		keys := sortedKeys(t)
		c.writeByte('{')
		for i, k := range keys {
			if i > 0 {
				c.writeByte(',')
			}
			if !isDataModelString(k) {
				c.other = true
			} else {
				c.writeString(k)
			}
			c.writeByte(':')
			c.walk(t[k], depth+1)
		}
		c.writeByte('}')
	default:
		c.other = true
	}
}

// writeString writes s as an RFC 8785 string: '"', '\\' and the controls
// below U+0020 are escaped, with the two-character forms where they exist
// and lowercase \u00xx otherwise; everything else is literal UTF-8. (Go's
// json.Marshal would also escape '<', '>' and '&'.)
func (c *canonicalizer) writeString(s string) {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if ch < 0x20 {
				const hexDigits = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[ch>>4])
				b.WriteByte(hexDigits[ch&0xF])
			} else {
				b.WriteByte(ch)
			}
		}
	}
	b.WriteByte('"')
	c.write(b.String())
}

// utf16Units is the UTF-16 code unit sequence RFC 8785 sorts member names
// by. The generalized UTF-8 form of a surrogate (a lone surrogate in a Go
// string) is read as that code unit, and any other invalid byte as U+FFFD,
// so every key has a sequence; such keys are refused anyway.
func utf16Units(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			out = append(out, uint16(c))
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if c == 0xED && i+2 < len(s) && s[i+1]&0xE0 == 0xA0 && s[i+2]&0xC0 == 0x80 {
				out = append(out, uint16(0xD000|rune(s[i+1]&0x3F)<<6|rune(s[i+2]&0x3F)))
				i += 3
				continue
			}
			out = append(out, 0xFFFD)
			i++
			continue
		}
		if r >= 0x10000 {
			hi, lo := utf16.EncodeRune(r)
			out = append(out, uint16(hi), uint16(lo))
		} else {
			out = append(out, uint16(r))
		}
		i += size
	}
	return out
}

func compareUnits(a, b []uint16) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return len(a) - len(b)
}

// sortedKeys returns the member names of m in RFC 8785 order (UTF-16 code
// units), ties between distinct invalid names broken by their bytes, so the
// order is total and never depends on Go's map iteration order.
func sortedKeys(m map[string]interface{}) []string {
	type key struct {
		s     string
		units []uint16
	}
	keys := make([]key, 0, len(m))
	for k := range m {
		keys = append(keys, key{k, utf16Units(k)})
	}
	sort.Slice(keys, func(i, j int) bool {
		if c := compareUnits(keys[i].units, keys[j].units); c != 0 {
			return c < 0
		}
		return keys[i].s < keys[j].s
	})
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.s
	}
	return out
}

// canonicalize serializes value under the data model with an output bound.
// Refusals are unsupported_number, then unsupported_value; exceeding the
// bound is unsupported_value only when nothing else was refused.
func canonicalize(value interface{}, maxOut int) CanonicalizeResult {
	c := &canonicalizer{maxOut: maxOut}
	c.walk(value, 0)
	if !c.number && !c.other && c.over {
		c.other = true
	}
	if c.number || c.other {
		refusals := make([]string, 0, 2)
		if c.number {
			refusals = append(refusals, "unsupported_number")
		}
		if c.other {
			refusals = append(refusals, "unsupported_value")
		}
		return CanonicalizeResult{OK: false, Refusals: refusals}
	}
	return CanonicalizeResult{OK: true, Canonical: c.sb.String()}
}

// Canonicalize serializes a host value to its RFC 8785 form under the data
// model. It refuses unsupported_number for a number outside the number rule
// and unsupported_value for any other value outside the data model (see the
// package documentation), including nesting deeper than 64. It applies no
// canonical-size limit; ComputeCaid and VerifyCaid apply the action-object
// limit of 16777216 octets themselves.
func Canonicalize(value interface{}) CanonicalizeResult {
	return canonicalize(value, uncappedOutputLimit)
}

func canonicalizeAction(value interface{}) CanonicalizeResult {
	return canonicalize(value, specLimitCanonicalOctets)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hashJSON(value interface{}) string {
	c := Canonicalize(value)
	if !c.OK {
		return ""
	}
	return "sha256:" + sha256Hex(c.Canonical)
}

// ---------------------------------------------------------------------------
// Definitions: conformance, digest, resolution (draft -04 Section 4.2)
// ---------------------------------------------------------------------------

var fieldTypeRequiredMembers = func() map[string][][2]string {
	out := map[string][][2]string{}
	keys := make([]string, 0, len(specFieldTypeRequiredMembers))
	for k := range specFieldTypeRequiredMembers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		dot := strings.IndexByte(k, '.')
		out[k[:dot]] = append(out[k[:dot]], [2]string{k[dot+1:], specFieldTypeRequiredMembers[k]})
	}
	return out
}()

func stringIn(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// validFieldName is the field-name rule: a non-empty string of scalar values
// with no ":" that is not a reserved name.
func validFieldName(name string) bool {
	if len(name) < specFieldNameMinLength || !utf8.ValidString(name) {
		return false
	}
	for _, r := range specFieldNameForbiddenCodePoints {
		if strings.ContainsRune(name, r) {
			return false
		}
	}
	return !stringIn(specReservedFieldNames, name)
}

// projection is the validation projection of a definition: action_type and
// the two field lists (an absent optional_fields read as []), each object
// entry without its excluded members. ok is false when the definition has no
// action_type or a field list that is not an array.
func projection(d map[string]interface{}) (map[string]interface{}, bool) {
	at, present := d["action_type"]
	if !present {
		return nil, false
	}
	out := map[string]interface{}{"action_type": at}
	for _, list := range specDefinitionFieldLists {
		raw, present := d[list]
		if !present {
			raw = []interface{}{} // the only default: optional_fields
			if list != "optional_fields" {
				return nil, false
			}
		}
		entries, ok := asArray(raw)
		if !ok {
			return nil, false
		}
		projected := make([]interface{}, len(entries))
		for i, entry := range entries {
			m, isObj := asObject(entry)
			if !isObj {
				projected[i] = entry
				continue
			}
			kept := make(map[string]interface{}, len(m))
			for k, v := range m {
				if !stringIn(specProjectionFieldMembersExcluded, k) {
					kept[k] = v
				}
			}
			projected[i] = kept
		}
		out[list] = projected
	}
	return out, true
}

// definitionDigest is definition_sha256 of a definition, or "" when its
// projection is missing or outside the data model.
func definitionDigest(d map[string]interface{}) string {
	p, ok := projection(d)
	if !ok {
		return ""
	}
	c := Canonicalize(p)
	if !c.OK {
		return ""
	}
	return specDefinitionDigestPrefix + sha256Hex(c.Canonical)
}

func fieldEntries(d map[string]interface{}, list string) []interface{} {
	entries, _ := asArray(d[list])
	return entries
}

// definitionConforms is draft -04 definition conformance.
func definitionConforms(d map[string]interface{}) bool {
	at, ok := d["action_type"].(string)
	if !ok || !specPatternActionType.MatchString(at) {
		return false
	}
	required, ok := asArray(d["required_fields"])
	if !ok || len(required) < specRequiredFieldsMin {
		return false
	}
	if raw, present := d["optional_fields"]; present {
		if _, ok := asArray(raw); !ok {
			return false
		}
	}
	names := map[string]bool{}
	for _, list := range specDefinitionFieldLists {
		for _, e := range fieldEntries(d, list) {
			entry, ok := asObject(e)
			if !ok {
				return false
			}
			name, ok := entry["name"].(string)
			if !ok || !validFieldName(name) || names[name] {
				return false
			}
			names[name] = true
			ftype, ok := entry["type"].(string)
			if !ok {
				return false
			}
			members, known := specFieldTypeMembers[ftype]
			if !known {
				continue // an unregistered type refuses only when present
			}
			for k := range entry {
				if !stringIn(specFieldCommonMembers, k) && !stringIn(members, k) {
					return false
				}
			}
			for _, rm := range fieldTypeRequiredMembers[ftype] {
				s, ok := entry[rm[0]].(string)
				if !ok || !specPatterns[rm[1]].MatchString(s) {
					return false
				}
			}
		}
	}
	return definitionDigest(d) != ""
}

// DefinitionSha256 returns the definition_sha256 of a type definition:
// "sha256:" and the lowercase hexadecimal SHA-256 of the RFC 8785 encoding of
// its validation projection. A definition that does not conform is refused
// as invalid_definition.
func DefinitionSha256(definition interface{}) DefinitionDigestResult {
	d, ok := asObject(definition)
	if !ok || !definitionConforms(d) {
		return DefinitionDigestResult{Refusals: []string{specResolutionNonconforming}}
	}
	return DefinitionDigestResult{DefinitionSha256: definitionDigest(d)}
}

type resolution struct {
	definition map[string]interface{}
	digest     string
	reason     string
}

// resolveDefinition collects the definitions whose action_type is the
// object's. None is unknown_action_type; any nonconforming one, or two whose
// definition_sha256 differ, is invalid_definition. Equal projections count
// once. Status never matters.
func resolveDefinition(actionType string, definitions []interface{}) resolution {
	var candidates []map[string]interface{}
	for _, entry := range definitions {
		d, ok := asObject(entry)
		if !ok {
			continue
		}
		if at, ok := d["action_type"].(string); ok && at == actionType {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return resolution{reason: specResolutionNone}
	}
	digest := ""
	for _, d := range candidates {
		if !definitionConforms(d) {
			return resolution{reason: specResolutionNonconforming}
		}
	}
	for _, d := range candidates {
		dd := definitionDigest(d)
		if digest != "" && dd != digest {
			return resolution{reason: specResolutionConflict}
		}
		digest = dd
	}
	return resolution{definition: candidates[0], digest: digest}
}

// ---------------------------------------------------------------------------
// Field types (draft -04 Section 4.3) and enum resolution (Section 4.4)
// ---------------------------------------------------------------------------

func daysInMonth(year, month int) int {
	if month == 2 {
		if (year%4 == 0 && year%100 != 0) || year%400 == 0 {
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

func digitsValue(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func timestampDayWithinMonth(s string) bool {
	year := digitsValue(s[specTimestampYear[0]:specTimestampYear[1]])
	month := digitsValue(s[specTimestampMonth[0]:specTimestampMonth[1]])
	day := digitsValue(s[specTimestampDay[0]:specTimestampDay[1]])
	return day <= daysInMonth(year, month)
}

// resolveEnumValues resolves an enum field to its closed value list. The
// compact form values_ref "inline: a | b" splits on "|" and trims U+0020
// only; a values member beside it must equal the parsed list. A values array
// without values_ref is the inline form. An external reference resolves only
// when the definition names its snapshot and pins the RFC 8785 values array
// by SHA-256, from an embedded values member or, without one, from the first
// supplied snapshot whose three labels match exactly.
func resolveEnumValues(field map[string]interface{}, enumSnapshots []interface{}) ([]string, bool) {
	ref, hasRef := field["values_ref"]
	declaredRaw, hasDeclared := field["values"]

	if refString, ok := ref.(string); ok && strings.HasPrefix(refString, specEnumInlinePrefix) {
		parts := strings.Split(strings.TrimPrefix(refString, specEnumInlinePrefix), specEnumInlineSeparator)
		values := make([]string, 0, len(parts))
		seen := make(map[string]bool, len(parts))
		for _, part := range parts {
			value := part
			for _, t := range specEnumInlineTrim {
				value = strings.Trim(value, t)
			}
			if value == "" || seen[value] {
				return nil, false
			}
			seen[value] = true
			values = append(values, value)
		}
		if hasDeclared {
			declared, ok := validEnumValues(declaredRaw)
			if !ok || !sameStringSlice(declared, values) {
				return nil, false
			}
		}
		return values, true
	}

	if !hasRef {
		return validEnumValues(declaredRaw)
	}

	refString, refOK := ref.(string)
	snapshot, snapshotOK := field["values_snapshot"].(string)
	pin, pinOK := field["values_sha256"].(string)
	if !refOK || refString == "" || !snapshotOK || snapshot == "" || !pinOK || !specPatternDigestField.MatchString(pin) {
		return nil, false
	}
	var declared []string
	ok := false
	if hasDeclared {
		declared, ok = validEnumValues(declaredRaw)
	} else {
		for _, candidate := range enumSnapshots {
			s, isObject := asObject(candidate)
			if !isObject {
				continue
			}
			sRef, _ := s["values_ref"].(string)
			sSnap, _ := s["values_snapshot"].(string)
			sPin, _ := s["values_sha256"].(string)
			if !isString(s["values_ref"]) || !isString(s["values_snapshot"]) || !isString(s["values_sha256"]) ||
				sRef != refString || sSnap != snapshot || sPin != pin {
				continue
			}
			declaredRaw = s["values"]
			declared, ok = validEnumValues(declaredRaw)
			break
		}
	}
	if !ok {
		return nil, false
	}
	if hashJSON(declaredRaw) != pin {
		return nil, false
	}
	return declared, true
}

func isString(v interface{}) bool {
	_, ok := v.(string)
	return ok
}

func validEnumValues(raw interface{}) ([]string, bool) {
	items, ok := asArray(raw)
	if !ok || len(items) == 0 {
		return nil, false
	}
	values := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		value, ok := item.(string)
		if !ok || value == "" || seen[value] {
			return nil, false
		}
		seen[value] = true
		values = append(values, value)
	}
	return values, true
}

func sameStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// checkField returns "" when value satisfies the field entry, else the
// reason code: mistyped_field, invalid_amount or invalid_code.
func checkField(value interface{}, field map[string]interface{}, enumSnapshots []interface{}) string {
	ftype, _ := field["type"].(string)
	want, known := specFieldTypeJSON[ftype]
	if !known {
		return specUnknownFieldTypeRefusal
	}
	k := kindOf(value)
	if want == "number" {
		if k == "number" && isIntegralNumber(value) {
			return ""
		}
		return "mistyped_field"
	}
	if k != want {
		return "mistyped_field"
	}
	switch ftype {
	case "enum":
		s := value.(string)
		values, ok := resolveEnumValues(field, enumSnapshots)
		if !ok || !stringIn(values, s) {
			return "mistyped_field"
		}
		return ""
	case "code":
		format, _ := field["format"].(string)
		matcher, registered := specCodeFormats[format]
		if !registered {
			return specCodeUnregisteredFormatRefusal
		}
		if !matcher.MatchString(value.(string)) {
			return specCodeFormatRefusal
		}
		return ""
	}
	if matcher, hasPattern := specFieldTypePattern[ftype]; hasPattern {
		s := value.(string)
		if !matcher.MatchString(s) {
			return specFieldTypePatternRefusal[ftype]
		}
		if ftype == "timestamp" && !timestampDayWithinMonth(s) {
			return specFieldTypePatternRefusal[ftype]
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Computation (draft -04 Section 5)
// ---------------------------------------------------------------------------

type rankedReason struct {
	rank, position int
	reason         string
}

// orderReasons sorts by (rank, position), stable, and removes repeats.
func orderReasons(found []rankedReason) []string {
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].rank != found[j].rank {
			return found[i].rank < found[j].rank
		}
		return found[i].position < found[j].position
	})
	out := make([]string, 0, len(found))
	seen := make(map[string]bool, len(found))
	for _, f := range found {
		if !seen[f.reason] {
			seen[f.reason] = true
			out = append(out, f.reason)
		}
	}
	return out
}

type evaluation struct {
	refusals   []string
	actionType string
	resolved   bool
	digest     string
	canonical  *CanonicalizeResult
}

// evaluate runs the computation phases after the JSON text gate. The gates
// (invalid_action_type, then unknown_action_type or invalid_definition) each
// yield one reason and stop; every later check runs, and the reasons are
// ordered by rank and field position. With checkSuite false the suite phase
// is skipped: verification checks the suite of the CAID it is given.
func evaluate(object interface{}, definitions, enumSnapshots []interface{}, suite string, checkSuite bool) evaluation {
	obj, ok := asObject(object)
	if !ok {
		return evaluation{refusals: []string{"invalid_action_type"}}
	}
	actionType, ok := obj["action_type"].(string)
	if !ok || !specPatternActionType.MatchString(actionType) {
		return evaluation{refusals: []string{"invalid_action_type"}}
	}
	res := resolveDefinition(actionType, definitions)
	if res.reason != "" {
		return evaluation{refusals: []string{res.reason}, actionType: actionType}
	}
	var found []rankedReason
	required := fieldEntries(res.definition, "required_fields")
	all := append(append([]interface{}{}, required...), fieldEntries(res.definition, "optional_fields")...)
	for i, e := range required {
		f, _ := asObject(e)
		name, _ := f["name"].(string)
		if _, present := obj[name]; !present {
			found = append(found, rankedReason{specSortRankCompute["missing_material_field"], i, "missing_material_field:" + name})
		}
	}
	for i, e := range all {
		f, _ := asObject(e)
		name, _ := f["name"].(string)
		value, present := obj[name]
		if !present {
			continue
		}
		if code := checkField(value, f, enumSnapshots); code != "" {
			found = append(found, rankedReason{specSortRankCompute[code], i, code + ":" + name})
		}
	}
	if checkSuite && !implementedSuites[suite] {
		found = append(found, rankedReason{specSortRankCompute["unknown_suite"], 0, "unknown_suite"})
	}
	c := canonicalizeAction(obj)
	for _, r := range c.Refusals {
		found = append(found, rankedReason{specSortRankCompute[r], 0, r})
	}
	return evaluation{
		refusals:   orderReasons(found),
		actionType: actionType,
		resolved:   true,
		digest:     res.digest,
		canonical:  &c,
	}
}

func digestBytes(canonical string) []byte {
	sum := sha256.Sum256([]byte(canonical))
	return sum[:]
}

// ComputeCaid validates a host value against its type definition,
// canonicalizes it under the suite and returns the CAID, the "sha256:" +
// lowercase hex digest and the definition_sha256 of the definition used.
// Any failure returns the ordered refusals and nothing else.
func ComputeCaid(actionObject interface{}, opts ComputeOptions) ComputeResult {
	e := evaluate(actionObject, opts.Definitions, opts.EnumSnapshots, opts.Suite, true)
	if len(e.refusals) > 0 {
		return ComputeResult{Refusals: e.refusals}
	}
	sum := digestBytes(e.canonical.Canonical)
	sep := specIdentifierSeparator
	return ComputeResult{
		Caid:             specIdentifierScheme + sep + specIdentifierVersion + sep + e.actionType + sep + opts.Suite + sep + base64.RawURLEncoding.EncodeToString(sum),
		Digest:           "sha256:" + hex.EncodeToString(sum),
		DefinitionSha256: e.digest,
	}
}

// ComputeCaidJSON computes over an action object received as JSON text. A
// text DecodeJSON refuses yields exactly malformed_json; otherwise the result
// is ComputeCaid over the decoded value.
func ComputeCaidJSON(data []byte, opts ComputeOptions) ComputeResult {
	value, err := DecodeJSON(data)
	if err != nil {
		return ComputeResult{Refusals: []string{ReasonMalformedJSON}}
	}
	return ComputeCaid(value, opts)
}

// ---------------------------------------------------------------------------
// Parsing (draft -04 Section 3.4)
// ---------------------------------------------------------------------------

// ParseCaid strict-parses a CAID string and yields exactly one reason on
// refusal. The whole string must match the caid rule of Appendix A
// (malformed_caid); the suite must be registered (unknown_suite); the digest
// must match that suite's digest syntax: the exact length, and a final
// character whose unused low bits are zero (malformed_caid). It works on the
// exact code points: no trimming, case folding or normalization.
func ParseCaid(input string) ParseResult {
	if !specPatternCaid.MatchString(input) {
		return ParseResult{Refusals: []string{"malformed_caid"}}
	}
	parts := strings.Split(input, specIdentifierSeparator)
	if len(parts) != specIdentifierParts {
		return ParseResult{Refusals: []string{"malformed_caid"}}
	}
	suite, digest := parts[3], parts[4]
	digestPattern, registered := specSuiteDigestPatterns[suite]
	if !registered {
		return ParseResult{Refusals: []string{"unknown_suite"}}
	}
	if !digestPattern.MatchString(digest) {
		return ParseResult{Refusals: []string{"malformed_caid"}}
	}
	return ParseResult{OK: true, Caid: &ParsedCaid{Version: parts[1], ActionType: parts[2], Suite: suite, Digest: digest}}
}

// ---------------------------------------------------------------------------
// Verification (draft -04 Section 6)
// ---------------------------------------------------------------------------

func stringPtr(s string) *string { return &s }

// observedKind is the kind a detail observes: "unsupported" for a host value
// outside the data model's kinds.
func observedKind(v interface{}) string {
	if k := kindOf(v); k != "" {
		return k
	}
	return "unsupported"
}

// verifyDetail builds the closed detail of one reason. value is the
// presented action object.
func verifyDetail(reason string, value interface{}) VerifyDetail {
	code, param := reason, ""
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		code, param = reason[:i], reason[i+1:]
	}
	shape, ok := specVerifyDetails[code]
	if !ok {
		return VerifyDetail{Reason: reason}
	}
	var field *string
	switch shape.Field {
	case "":
	case "param":
		field = stringPtr(param)
	default:
		field = stringPtr(shape.Field)
	}
	var observed *string
	switch shape.Observed {
	case "":
	case "argument":
		// The CAID argument of VerifyCaid is always a Go string.
		observed = stringPtr("string")
	case "member":
		if obj, isObj := asObject(value); isObj {
			member, present := interface{}(nil), false
			if field != nil {
				member, present = obj[*field]
			}
			if present {
				observed = stringPtr(observedKind(member))
			} else {
				observed = stringPtr("absent")
			}
		} else {
			observed = stringPtr(observedKind(value))
		}
	}
	return VerifyDetail{Reason: reason, Field: field, Rule: shape.Rule, Observed: observed}
}

func refusedVerify(reasons []string, value interface{}) VerifyResult {
	details := make([]VerifyDetail, 0, len(reasons))
	for _, r := range reasons {
		details = append(details, verifyDetail(r, value))
	}
	return VerifyResult{Valid: false, Reasons: reasons, Details: details}
}

// verifySuiteChecked reports whether the invalid_object expansion keeps the
// computation's suite phase (core.json says it omits it).
var verifySuiteChecked = !stringIn(specVerifyDetailExpandOmit["invalid_object"], "unknown_suite")

func verifyParsed(actionObject interface{}, parsed *ParsedCaid, opts VerifyOptions) VerifyResult {
	obj, isObj := asObject(actionObject)
	if !isObj {
		e := evaluate(actionObject, opts.Definitions, opts.EnumSnapshots, "", verifySuiteChecked)
		details := make([]VerifyDetail, 0, len(e.refusals))
		for _, r := range e.refusals {
			details = append(details, verifyDetail(r, actionObject))
		}
		return VerifyResult{Valid: false, Reasons: []string{"invalid_object"}, Details: details}
	}
	reasons := []string{}
	details := []VerifyDetail{}
	add := func(r string) {
		reasons = append(reasons, r)
		details = append(details, verifyDetail(r, actionObject))
	}
	if at, ok := obj["action_type"].(string); !ok || at != parsed.ActionType {
		add("action_type_mismatch")
	}
	e := evaluate(actionObject, opts.Definitions, opts.EnumSnapshots, "", verifySuiteChecked)
	definitionSha256 := ""
	if e.resolved {
		definitionSha256 = e.digest
	}
	if opts.ExpectedDefinitionSha256 != nil && definitionSha256 != "" && *opts.ExpectedDefinitionSha256 != definitionSha256 {
		add("definition_mismatch")
	}
	c := e.canonical
	if c == nil {
		computed := canonicalizeAction(obj)
		c = &computed
	}
	if !implementedSuites[parsed.Suite] {
		add("unknown_suite")
	} else if c.OK && base64.RawURLEncoding.EncodeToString(digestBytes(c.Canonical)) != parsed.Digest {
		add("digest_mismatch")
	}
	if len(e.refusals) > 0 {
		reasons = append(reasons, "invalid_object")
		for _, r := range e.refusals {
			details = append(details, verifyDetail(r, actionObject))
		}
	}
	return VerifyResult{Valid: len(reasons) == 0, Reasons: reasons, Details: details, DefinitionSha256: definitionSha256}
}

// VerifyCaid checks that a host value is the typed content caidString
// identifies. Parsing is a gate (malformed_caid or unknown_suite, alone), as
// is a presented value that is not an object (invalid_object). After them,
// in order: action_type_mismatch; definition_mismatch when
// ExpectedDefinitionSha256 is set and differs; unknown_suite for a registered
// suite this implementation does not compute, else digest_mismatch when the
// object canonicalizes to another digest; invalid_object when computation
// refuses the object. Same inputs, same reasons, same order, replayable
// offline by any third party.
//
// A valid CAID shows only that this object is the typed content the
// identifier was computed over. It shows nothing about authorization,
// execution or trust.
func VerifyCaid(actionObject interface{}, caidString string, opts VerifyOptions) VerifyResult {
	parsed := ParseCaid(caidString)
	if !parsed.OK {
		return refusedVerify(parsed.Refusals, actionObject)
	}
	return verifyParsed(actionObject, parsed.Caid, opts)
}

// VerifyCaidJSON verifies an action object received as JSON text. Parsing
// the CAID comes first; then a text DecodeJSON refuses yields exactly
// malformed_json; otherwise the result is VerifyCaid over the decoded value.
func VerifyCaidJSON(data []byte, caidString string, opts VerifyOptions) VerifyResult {
	parsed := ParseCaid(caidString)
	if !parsed.OK {
		return refusedVerify(parsed.Refusals, nil)
	}
	value, err := DecodeJSON(data)
	if err != nil {
		return refusedVerify([]string{ReasonMalformedJSON}, nil)
	}
	return verifyParsed(value, parsed.Caid, opts)
}
