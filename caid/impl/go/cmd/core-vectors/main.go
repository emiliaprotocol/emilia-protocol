// SPDX-License-Identifier: Apache-2.0

// core-vectors runs the shared CAID core conformance corpus against the Go
// implementation and exits nonzero on any failure.
//
// Usage: go run ./cmd/core-vectors [path/to/vectors.json]
//
// Default path: ../../conformance/vectors.json relative to the module root
// (impl/go), with fallbacks for other working directories.
//
// Input forms (one per vector):
//
//	input.json         a string; its UTF-8 octets are the JSON text
//	input.json_b64     the exact octets, base64 (invalid UTF-8, a BOM, UTF-16)
//	input.json_repeat  {prefix, unit, count, suffix}: prefix, unit repeated
//	                   count times, suffix (inputs of many MiB)
//	input.native_json  a JSON text decoded into a host value outside the data
//	                   model where the text says so (unpaired surrogate
//	                   escapes kept, noncharacters and deep nesting allowed);
//	                   the native entry point alone runs on it
//	input.object       corpus v4: a host value embedded in the corpus
//
// For a JSON text, compute and verify run through ComputeCaidJSON and
// VerifyCaidJSON. When DecodeJSON accepts the text, the runner also calls
// ComputeCaid or VerifyCaid on the decoded value and requires an identical
// result (draft -04 Section 2.5 parity).
//
// Kinds: decode, parse, compute, verify, definition.
//
// The corpus file is decoded by the package's own decoder, never by
// encoding/json. A corpus of version 5 or later must decode under the
// strict document profile; earlier versions carry unpaired surrogates in
// their embedded objects and are read with the host profile.
package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"caid"
	"caid/internal/jsontext"
)

type obj = map[string]interface{}

var failures, total int

func main() {
	path := findVectors()
	if path == "" {
		fmt.Fprintln(os.Stderr, "FAIL: vectors.json not found; pass its path as the first argument")
		os.Exit(1)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot read %s: %v\n", path, err)
		os.Exit(1)
	}
	decoded, derr := jsontext.Decode(data, jsontext.Options{MaxDepth: 1 << 12, Host: true})
	if derr != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot decode %s: %v\n", path, derr)
		os.Exit(1)
	}
	doc, isObject := decoded.(obj)
	if !isObject {
		fmt.Fprintf(os.Stderr, "FAIL: %s is not a JSON object\n", path)
		os.Exit(1)
	}
	if version := corpusVersion(doc); version >= 5 {
		if _, err := caid.DecodeDocumentJSON(data); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: corpus version %d must decode under the strict profile: %v\n", version, err)
			os.Exit(1)
		}
	}
	vectorsRaw, ok := doc["vectors"].([]interface{})
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL: vectors.json has no vectors array")
		os.Exit(1)
	}
	enumSnapshots, _ := doc["enum_snapshots"].([]interface{})

	computedCaids := map[string]string{}
	var relations []relation
	for _, raw := range vectorsRaw {
		vec, isObj := raw.(obj)
		if !isObj {
			fail("(non-object vector entry)", "vector entry is not an object")
			continue
		}
		total++
		id := str(vec, "id")
		kind := str(vec, "kind")
		definitions, _ := vec["definitions"].([]interface{})
		input, _ := vec["input"].(obj)
		expect, _ := vec["expect"].(obj)
		if input == nil || expect == nil {
			fail(id, "vector missing input or expect")
			continue
		}
		switch kind {
		case "decode":
			runDecode(id, input, expect)
		case "parse":
			runParse(id, input, expect)
		case "compute":
			if c := runCompute(id, input, expect, definitions, enumSnapshots); c != "" {
				computedCaids[id] = c
			}
			if rel, hasRel := vec["relation"].(obj); hasRel {
				relations = append(relations, relation{id: id, spec: rel})
			}
		case "verify":
			runVerify(id, input, expect, definitions, enumSnapshots)
		case "definition":
			runDefinition(id, input, expect)
		default:
			fail(id, "unknown vector kind: "+kind)
		}
	}

	for _, r := range relations {
		if other := str(r.spec, "same_caid_as"); other != "" {
			a, aOK := computedCaids[r.id]
			b, bOK := computedCaids[other]
			if aOK && bOK && a != b {
				fail(r.id, "same_caid_as "+other+" violated: "+a+" != "+b)
			}
		}
		if other := str(r.spec, "different_caid_from"); other != "" {
			a, aOK := computedCaids[r.id]
			b, bOK := computedCaids[other]
			if aOK && bOK && a == b {
				fail(r.id, "different_caid_from "+other+" violated: both "+a)
			}
		}
	}

	if failures > 0 {
		fmt.Printf("FAIL: %d failures across %d vectors (%s)\n", failures, total, path)
		os.Exit(1)
	}
	fmt.Printf("PASS: %d vectors, 0 failures (%s)\n", total, path)
}

type relation struct {
	id   string
	spec obj
}

// corpusVersion reads the corpus version member (a number token).
func corpusVersion(doc obj) int {
	if v, ok := doc["version"].(fmt.Stringer); ok {
		n, _ := strconv.Atoi(v.String())
		return n
	}
	return 0
}

func str(m obj, key string) string {
	s, _ := m[key].(string)
	return s
}

func fail(id, msg string) {
	failures++
	fmt.Printf("FAIL %s: %s\n", id, msg)
}

// textInput returns the JSON text octets of a vector, when it has one.
func textInput(input obj) ([]byte, bool, error) {
	if s, ok := input["json"].(string); ok {
		return []byte(s), true, nil
	}
	if s, ok := input["json_b64"].(string); ok {
		b, err := base64.StdEncoding.DecodeString(s)
		return b, true, err
	}
	if r, ok := input["json_repeat"].(obj); ok {
		unit := str(r, "unit")
		count := 0
		switch c := r["count"].(type) {
		case interface{ Int64() (int64, error) }:
			n, err := c.Int64()
			if err != nil {
				return nil, true, err
			}
			count = int(n)
		default:
			return nil, true, fmt.Errorf("json_repeat.count is not an integer")
		}
		var b strings.Builder
		b.Grow(len(str(r, "prefix")) + len(unit)*count + len(str(r, "suffix")))
		b.WriteString(str(r, "prefix"))
		for i := 0; i < count; i++ {
			b.WriteString(unit)
		}
		b.WriteString(str(r, "suffix"))
		return []byte(b.String()), true, nil
	}
	return nil, false, nil
}

// nativeInput returns the host value of a native-lane or corpus v4 vector.
func nativeInput(input obj) (interface{}, bool, error) {
	if s, ok := input["native_json"].(string); ok {
		v, err := jsontext.Decode([]byte(s), jsontext.Options{MaxDepth: 1 << 16, Host: true})
		if err != nil {
			return nil, true, err
		}
		return v, true, nil
	}
	if v, ok := input["object"]; ok {
		return v, true, nil
	}
	return nil, false, nil
}

func stringList(v interface{}) ([]string, bool) {
	raw, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func checkStrings(id, label string, got []string, want interface{}) {
	wantList, ok := stringList(want)
	if !ok {
		fail(id, label+": expectation is not a string list")
		return
	}
	if len(got) == 0 && len(wantList) == 0 {
		return
	}
	if !reflect.DeepEqual(got, wantList) {
		fail(id, fmt.Sprintf("%s: got %q, want %q", label, got, wantList))
	}
}

func checkString(id, label, got string, want interface{}) {
	w, _ := want.(string)
	if got != w {
		fail(id, fmt.Sprintf("%s: got %q, want %q", label, got, w))
	}
}

func runDecode(id string, input, expect obj) {
	data, isText, err := textInput(input)
	if !isText || err != nil {
		fail(id, fmt.Sprintf("decode vector without a usable JSON text: %v", err))
		return
	}
	got := caid.DecodeCaidJSON(data)
	wantOK, _ := expect["ok"].(bool)
	if got.OK != wantOK {
		fail(id, fmt.Sprintf("ok: got %v, want %v (refusals %v)", got.OK, wantOK, got.Refusals))
		return
	}
	if !wantOK {
		checkStrings(id, "refusals", got.Refusals, expect["refusals"])
		return
	}
	if want, has := expect["value"]; has && !sameValue(got.Value, want) {
		fail(id, "decoded value differs from the expected value")
	}
}

// sameValue compares decoded values, numbers by their binary64 value.
func sameValue(a, b interface{}) bool {
	switch x := a.(type) {
	case map[string]interface{}:
		y, ok := b.(map[string]interface{})
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			w, present := y[k]
			if !present || !sameValue(v, w) {
				return false
			}
		}
		return true
	case []interface{}:
		y, ok := b.([]interface{})
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameValue(x[i], y[i]) {
				return false
			}
		}
		return true
	case fmt.Stringer:
		y, ok := b.(fmt.Stringer)
		if !ok {
			return false
		}
		fx, errX := strconv.ParseFloat(x.String(), 64)
		fy, errY := strconv.ParseFloat(y.String(), 64)
		return errX == nil && errY == nil && fx == fy
	}
	return reflect.DeepEqual(a, b)
}

func runParse(id string, input, expect obj) {
	got := caid.ParseCaid(str(input, "caid"))
	wantOK, _ := expect["ok"].(bool)
	if got.OK != wantOK {
		fail(id, fmt.Sprintf("ok: got %v, want %v (refusals %v)", got.OK, wantOK, got.Refusals))
		return
	}
	if !wantOK {
		checkStrings(id, "refusals", got.Refusals, expect["refusals"])
		return
	}
	want, _ := expect["caid"].(obj)
	if want == nil || got.Caid == nil {
		fail(id, "missing parsed caid on one side")
		return
	}
	checkString(id, "version", got.Caid.Version, want["version"])
	checkString(id, "action_type", got.Caid.ActionType, want["action_type"])
	checkString(id, "suite", got.Caid.Suite, want["suite"])
	checkString(id, "digest", got.Caid.Digest, want["digest"])
}

func checkCompute(id string, got caid.ComputeResult, expect obj) string {
	if _, hasCaid := expect["caid"]; hasCaid {
		if len(got.Refusals) != 0 {
			fail(id, fmt.Sprintf("expected success, got refusals %q", got.Refusals))
			return ""
		}
		before := failures
		checkString(id, "caid", got.Caid, expect["caid"])
		checkString(id, "digest", got.Digest, expect["digest"])
		if want, has := expect["definition_sha256"]; has {
			checkString(id, "definition_sha256", got.DefinitionSha256, want)
		}
		if failures == before {
			return got.Caid
		}
		return ""
	}
	if got.Caid != "" {
		fail(id, fmt.Sprintf("expected refusals %v, got caid %s", expect["refusals"], got.Caid))
		return ""
	}
	checkStrings(id, "refusals", got.Refusals, expect["refusals"])
	return ""
}

func computeOptions(input obj, definitions, snapshots []interface{}) caid.ComputeOptions {
	suite, present := input["suite"]
	s, isString := suite.(string)
	if present && !isString {
		// The Go API cannot carry a non-string suite; no registered suite
		// is spelled like this, so it refuses as unknown_suite, as a
		// non-string suite does in every port.
		s = "\x00non-string"
	}
	return caid.ComputeOptions{Suite: s, Definitions: definitions, EnumSnapshots: snapshots}
}

func runCompute(id string, input, expect obj, definitions, snapshots []interface{}) string {
	opts := computeOptions(input, definitions, snapshots)
	if data, isText, err := textInput(input); isText {
		if err != nil {
			fail(id, "unusable JSON text input: "+err.Error())
			return ""
		}
		got := caid.ComputeCaidJSON(data, opts)
		if value, derr := caid.DecodeJSON(data); derr == nil {
			native := caid.ComputeCaid(value, opts)
			if !reflect.DeepEqual(native, got) {
				fail(id, fmt.Sprintf("native/JSON parity: native %+v, JSON text %+v", native, got))
			}
		}
		return checkCompute(id, got, expect)
	}
	value, isNative, err := nativeInput(input)
	if !isNative || err != nil {
		fail(id, fmt.Sprintf("compute vector without a usable input: %v", err))
		return ""
	}
	return checkCompute(id, caid.ComputeCaid(value, opts), expect)
}

func verifyOptions(input obj, definitions, snapshots []interface{}) caid.VerifyOptions {
	opts := caid.VerifyOptions{Definitions: definitions, EnumSnapshots: snapshots}
	if raw, present := input["expected_definition_sha256"]; present {
		s, isString := raw.(string)
		if !isString {
			s = "\x00non-string"
		}
		opts.ExpectedDefinitionSha256 = &s
	}
	return opts
}

func detailList(details []caid.VerifyDetail) []interface{} {
	out := make([]interface{}, 0, len(details))
	ptr := func(p *string) interface{} {
		if p == nil {
			return nil
		}
		return *p
	}
	for _, d := range details {
		out = append(out, obj{"reason": d.Reason, "field": ptr(d.Field), "rule": d.Rule, "observed": ptr(d.Observed)})
	}
	return out
}

func checkVerify(id string, got caid.VerifyResult, expect obj) {
	wantValid, _ := expect["valid"].(bool)
	if got.Valid != wantValid {
		fail(id, fmt.Sprintf("valid: got %v, want %v (reasons %q)", got.Valid, wantValid, got.Reasons))
	}
	checkStrings(id, "reasons", got.Reasons, expect["reasons"])
	if want, has := expect["details"]; has {
		if !sameValue(detailList(got.Details), want) {
			fail(id, fmt.Sprintf("details: got %v, want %v", detailList(got.Details), want))
		}
	}
	if want, has := expect["definition_sha256"]; has {
		checkString(id, "definition_sha256", got.DefinitionSha256, want)
	} else if _, has := expect["details"]; has && got.DefinitionSha256 != "" {
		fail(id, "definition_sha256 reported but not expected: "+got.DefinitionSha256)
	}
}

func runVerify(id string, input, expect obj, definitions, snapshots []interface{}) {
	opts := verifyOptions(input, definitions, snapshots)
	caidString := str(input, "caid")
	if data, isText, err := textInput(input); isText {
		if err != nil {
			fail(id, "unusable JSON text input: "+err.Error())
			return
		}
		got := caid.VerifyCaidJSON(data, caidString, opts)
		if value, derr := caid.DecodeJSON(data); derr == nil {
			native := caid.VerifyCaid(value, caidString, opts)
			if !reflect.DeepEqual(native, got) {
				fail(id, fmt.Sprintf("native/JSON parity: native %+v, JSON text %+v", native, got))
			}
		}
		checkVerify(id, got, expect)
		return
	}
	value, isNative, err := nativeInput(input)
	if !isNative || err != nil {
		fail(id, fmt.Sprintf("verify vector without a usable input: %v", err))
		return
	}
	checkVerify(id, caid.VerifyCaid(value, caidString, opts), expect)
}

func runDefinition(id string, input, expect obj) {
	got := caid.DefinitionSha256(input["definition"])
	if want, has := expect["definition_sha256"]; has {
		if len(got.Refusals) != 0 {
			fail(id, fmt.Sprintf("expected a digest, got refusals %q", got.Refusals))
			return
		}
		checkString(id, "definition_sha256", got.DefinitionSha256, want)
		return
	}
	checkStrings(id, "refusals", got.Refusals, expect["refusals"])
}

func findVectors() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	candidates := []string{
		filepath.Join("..", "..", "conformance", "vectors.json"),
		filepath.Join("conformance", "vectors.json"),
		filepath.Join("..", "..", "..", "..", "conformance", "vectors.json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
