// SPDX-License-Identifier: Apache-2.0

// grammar-vectors checks the Go port's public API against the ABNF
// interpreter's verdicts in a grammar case list, the file
// `node caid/spec/abnf-check.mjs --out FILE` writes
// ({"@version": "CAID-GRAMMAR-CASES-v1", "cases": [{rule, input, match}]}).
//
// Usage: go run ./cmd/grammar-vectors [CASES.json] [--registry DIR]
//
// CASES.json defaults to ../../conformance/grammar-vectors.json (a curated
// subset committed with the corpus, if there is one).
//
// It never consults the generated matchers. Each rule is driven through the
// entry point that enforces it, with a one-field definition where a field
// type is involved:
//
//	pattern:caid              ParseCaid(input)
//	pattern:action_type       ComputeCaid and ParseCaid
//	pattern:suite             ParseCaid("caid:1:a.b.1:<input>:<digest>")
//	pattern:digest            ParseCaid("caid:1:a.b.1:jcs-sha256:<input>")
//	suite_digest:<suite>      ParseCaid("caid:1:a.b.1:<suite>:<input>")
//	pattern:amount_string     ComputeCaid, field type amount-string
//	pattern:digest_field      ComputeCaid, field type digest
//	pattern:timestamp         ComputeCaid, field type timestamp
//	pattern:format_name       ComputeCaid, a code field declaring the format
//	pattern:code_system       ComputeCaid, a code field declaring the system
//	pattern:array_index       MapAction, a source path ending in the index
//	pattern:hex_sha256        MapAction, transform sha256-hex-to-digest
//	code_format:<format>      ComputeCaid, a code field of that format
//
// Where the API's verdict depends on more than the grammar (a registered
// suite, the digest length, the day of the month, a pointer's octet limit),
// the runner computes that part independently of the port: suites from
// caid/registry/suites.json, digest octets with encoding/base64, the calendar
// by hand. A case with an unknown rule label fails the run.
//
// Inputs may hold unpaired surrogates (as JSON escapes) and, with input_b64,
// arbitrary octets; the case list is read with the host decoder profile so
// they reach the API unchanged.
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"caid"
	"caid/internal/jsontext"
)

type obj = map[string]interface{}

var registeredSuites = map[string]int{}

// maxOctets holds the length limits of draft -04 Section 2.6, read from
// caid/spec/core.json: each is checked before any pattern runs.
var maxOctets = map[string]int{}

const codeSystem = "http://example.test/code-system"

func main() {
	casesPath := filepath.Join("..", "..", "conformance", "grammar-vectors.json")
	registryDir := filepath.Join("..", "..", "registry")
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--registry" && i+1 < len(os.Args):
			i++
			registryDir = os.Args[i]
		case strings.HasPrefix(os.Args[i], "--"):
			fmt.Fprintln(os.Stderr, "usage: grammar-vectors [CASES.json] [--registry DIR]")
			os.Exit(2)
		default:
			casesPath = os.Args[i]
		}
	}
	loadSuites(filepath.Join(registryDir, "suites.json"))
	loadLimits(filepath.Join(registryDir, "..", "spec", "core.json"))
	data, err := os.ReadFile(casesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	decoded, derr := jsontext.Decode(data, jsontext.Options{MaxDepth: 64, Host: true})
	if derr != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot decode %s: %v\n", casesPath, derr)
		os.Exit(1)
	}
	doc, _ := decoded.(obj)
	cases, _ := doc["cases"].([]interface{})
	if len(cases) == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: no cases")
		os.Exit(1)
	}
	failures := 0
	perRule := map[string]int{}
	for i, raw := range cases {
		c, _ := raw.(obj)
		rule, _ := c["rule"].(string)
		input, ok := c["input"].(string)
		if b64, isB64 := c["input_b64"].(string); isB64 {
			b, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				failures++
				fmt.Printf("FAIL case %d: bad input_b64\n", i)
				continue
			}
			input, ok = string(b), true
		}
		match, isBool := c["match"].(bool)
		if !ok || !isBool {
			failures++
			fmt.Printf("FAIL case %d: malformed case\n", i)
			continue
		}
		perRule[rule]++
		if msg := check(rule, input, match); msg != "" {
			failures++
			if failures <= 40 {
				fmt.Printf("FAIL %s %q (grammar says match=%v): %s\n", rule, clip(input), match, msg)
			}
		}
	}
	if failures > 0 {
		fmt.Printf("FAIL: %d of %d grammar cases\n", failures, len(cases))
		os.Exit(1)
	}
	fmt.Printf("PASS: %d grammar cases over %d rules through the public API\n", len(cases), len(perRule))
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func loadSuites(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	v, err := caid.DecodeDocumentJSON(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	doc, _ := v.(obj)
	suites, _ := doc["suites"].([]interface{})
	for _, raw := range suites {
		s, _ := raw.(obj)
		name, _ := s["suite"].(string)
		octets, _ := s["digest_octets"].(fmt.Stringer)
		if name == "" || octets == nil {
			continue
		}
		n, _ := strconv.Atoi(octets.String())
		registeredSuites[name] = n
	}
	if len(registeredSuites) == 0 {
		fmt.Fprintln(os.Stderr, "no suites in", path)
		os.Exit(1)
	}
}

func loadLimits(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	v, err := caid.DecodeDocumentJSON(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	doc, _ := v.(obj)
	limits, _ := doc["limits"].([]interface{})
	for _, raw := range limits {
		l, _ := raw.(obj)
		id, _ := l["id"].(string)
		value, _ := l["value"].(fmt.Stringer)
		if value == nil {
			continue
		}
		n, _ := strconv.Atoi(value.String())
		maxOctets[id] = n
	}
	for _, id := range []string{"caid_octets", "action_type_octets", "code_system_octets"} {
		if maxOctets[id] == 0 {
			fmt.Fprintln(os.Stderr, "no limit", id, "in", path)
			os.Exit(1)
		}
	}
}

// digestFits is the independent oracle for a suite's digest syntax: strict
// unpadded base64url that decodes to exactly the suite's octets.
func digestFits(digest string, octets int) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(digest)
	return err == nil && len(raw) == octets && !strings.ContainsAny(digest, "\r\n")
}

var validDigest = strings.Repeat("A", 42) + "E"

func parseReasons(input string) []string {
	r := caid.ParseCaid(input)
	if r.OK {
		return nil
	}
	return r.Refusals
}

// expectParse compares ParseCaid with the grammar verdict for the CAID
// assembled around the rule's input.
func expectParse(caidString string, match bool, suite, digest string) string {
	got := parseReasons(caidString)
	var want []string
	parts := strings.Split(caidString, ":")
	switch {
	case !match || len(caidString) > maxOctets["caid_octets"] || len(parts) != 5 || len(parts[2]) > maxOctets["action_type_octets"]:
		want = []string{"malformed_caid"}
	case registeredSuites[suite] == 0:
		want = []string{"unknown_suite"}
	case !digestFits(digest, registeredSuites[suite]):
		want = []string{"malformed_caid"}
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("ParseCaid(%q) = %v, want %v", clip(caidString), got, want)
	}
	return ""
}

func computeField(fieldEntry obj, value interface{}) caid.ComputeResult {
	def := obj{"action_type": "grammar.field.1", "required_fields": []interface{}{fieldEntry}}
	return caid.ComputeCaid(obj{"action_type": "grammar.field.1", "v": value}, caid.ComputeOptions{Suite: "jcs-sha256", Definitions: []interface{}{def}})
}

// expectField: the value computes exactly when the grammar accepts it (and
// extra holds); otherwise the first refusal is refusal:v.
func expectField(fieldEntry obj, input string, accept bool, refusal string) string {
	got := computeField(fieldEntry, input)
	if accept {
		if got.Caid == "" {
			return fmt.Sprintf("refused %v", got.Refusals)
		}
		return ""
	}
	if got.Caid != "" || len(got.Refusals) == 0 || got.Refusals[0] != refusal+":v" {
		return fmt.Sprintf("got %v %q, want first refusal %s:v", got.Refusals, got.Caid, refusal)
	}
	return ""
}

func dayWithinMonth(s string) bool {
	y, _ := strconv.Atoi(s[0:4])
	m, _ := strconv.Atoi(s[5:7])
	d, _ := strconv.Atoi(s[8:10])
	days := [13]int{0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if (y%4 == 0 && y%100 != 0) || y%400 == 0 {
		days[2] = 29
	}
	return d <= days[m]
}

func mapOne(source obj, sourcePath, transform string, fieldType string) caid.MapActionResult {
	profile := obj{
		"@version":              caid.MappingProfileVersion,
		"profile_id":            "urn:test:grammar",
		"source_format":         obj{"media_type": "application/json", "schema": "urn:test:grammar", "version": "1"},
		"target_action_type":    "grammar.map.1",
		"loss_policy":           "no-material-field-loss",
		"material_source_paths": []interface{}{sourcePath},
		"rules":                 []interface{}{obj{"source_path": sourcePath, "target_field": "v", "transform": transform}},
	}
	def := obj{"action_type": "grammar.map.1", "required_fields": []interface{}{obj{"name": "v", "type": fieldType}}}
	return caid.MapAction(source, caid.MapActionOptions{
		Profile: profile, SourceDescriptor: profile["source_format"], ExpectedProfileHash: caid.MappingProfileHash(profile),
		NativeVerified: true, Definitions: []interface{}{def},
	})
}

func escapeToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func sameReasons(got []string, want ...string) bool { return reflect.DeepEqual(got, want) }

func check(rule, input string, match bool) string {
	switch {
	case rule == "pattern:caid":
		parts := strings.Split(input, ":")
		suite, digest := "", ""
		if len(parts) == 5 {
			suite, digest = parts[3], parts[4]
		}
		return expectParse(input, match, suite, digest)
	case rule == "pattern:action_type":
		def := obj{"action_type": input, "required_fields": []interface{}{obj{"name": "f", "type": "string"}}}
		got := caid.ComputeCaid(obj{"action_type": input, "f": "x"}, caid.ComputeOptions{Suite: "jcs-sha256", Definitions: []interface{}{def}})
		accepted := match && len(input) <= maxOctets["action_type_octets"]
		if accepted != (got.Caid != "") || (!accepted && !sameReasons(got.Refusals, "invalid_action_type")) {
			return fmt.Sprintf("ComputeCaid = %v %q", got.Refusals, got.Caid)
		}
		return expectParse("caid:1:"+input+":jcs-sha256:"+validDigest, match && !strings.Contains(input, ":"), "jcs-sha256", validDigest)
	case rule == "pattern:suite":
		return expectParse("caid:1:a.b.1:"+input+":"+validDigest, match, input, validDigest)
	case rule == "pattern:digest":
		return expectParse("caid:1:a.b.1:jcs-sha256:"+input, match, "jcs-sha256", input)
	case strings.HasPrefix(rule, "suite_digest:"):
		suite := strings.TrimPrefix(rule, "suite_digest:")
		got := parseReasons("caid:1:a.b.1:" + suite + ":" + input)
		if match != (got == nil) || (!match && !sameReasons(got, "malformed_caid")) {
			return fmt.Sprintf("ParseCaid = %v", got)
		}
		return ""
	case rule == "pattern:amount_string":
		return expectField(obj{"name": "v", "type": "amount-string"}, input, match, "invalid_amount")
	case rule == "pattern:digest_field":
		return expectField(obj{"name": "v", "type": "digest"}, input, match, "mistyped_field")
	case rule == "pattern:timestamp":
		return expectField(obj{"name": "v", "type": "timestamp"}, input, match && dayWithinMonth(input), "mistyped_field")
	case rule == "pattern:format_name":
		got := computeField(obj{"name": "v", "type": "code", "code_system": codeSystem, "format": input}, "X")
		isInvalid := sameReasons(got.Refusals, "invalid_definition")
		if match == isInvalid {
			return fmt.Sprintf("ComputeCaid = %v %q", got.Refusals, got.Caid)
		}
		return ""
	case rule == "pattern:code_system":
		got := computeField(obj{"name": "v", "type": "code", "code_system": input, "format": "nacha-sec"}, "PPD")
		accepted := match && len(input) <= maxOctets["code_system_octets"]
		if accepted != (got.Caid != "") || (!accepted && !sameReasons(got.Refusals, "invalid_definition")) {
			return fmt.Sprintf("ComputeCaid = %v %q", got.Refusals, got.Caid)
		}
		return ""
	case rule == "pattern:array_index":
		items := make([]interface{}, 12)
		for i := range items {
			items[i] = "item"
		}
		path := "/a/" + escapeToken(input)
		got := mapOne(obj{"a": items}, path, "copy", "string")
		// A path that breaks the source-path rule or its octet limit fails
		// the profile's shape; one outside the data model (an unpaired
		// surrogate, a noncharacter) also leaves the profile unhashable,
		// so it cannot be pinned.
		shapeFails := !utf8.ValidString(path) || len(path) > 2048
		unhashable := !caid.Canonicalize(path).OK
		switch {
		case shapeFails || unhashable:
			want := []string{"invalid_mapping_profile"}
			if unhashable {
				want = append(want, "mapping_profile_unpinned")
			}
			if !reflect.DeepEqual(got.Reasons, want) {
				return fmt.Sprintf("MapAction = %v, want %v", got.Reasons, want)
			}
		case !match:
			if !sameReasons(got.Reasons, "invalid_source_path:"+path) {
				return fmt.Sprintf("MapAction = %v, want invalid_source_path", got.Reasons)
			}
		default:
			n, err := strconv.Atoi(input)
			if err == nil && n < len(items) {
				if !got.OK {
					return fmt.Sprintf("MapAction = %v, want success", got.Reasons)
				}
			} else if !sameReasons(got.Reasons, "missing_source_field:"+path) {
				return fmt.Sprintf("MapAction = %v, want missing_source_field", got.Reasons)
			}
		}
		return ""
	case rule == "pattern:hex_sha256":
		got := mapOne(obj{"h": input}, "/h", "sha256-hex-to-digest", "digest")
		if match {
			if !got.OK {
				return fmt.Sprintf("MapAction = %v, want success", got.Reasons)
			}
			return ""
		}
		if !sameReasons(got.Reasons, "source_value_type_mismatch:/h") && !sameReasons(got.Reasons, "source_not_canonicalizable") {
			return fmt.Sprintf("MapAction = %v", got.Reasons)
		}
		return ""
	case strings.HasPrefix(rule, "code_format:"):
		format := strings.TrimPrefix(rule, "code_format:")
		return expectField(obj{"name": "v", "type": "code", "code_system": codeSystem, "format": format}, input, match, "invalid_code")
	}
	return "unknown rule label"
}
