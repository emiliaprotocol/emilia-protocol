// SPDX-License-Identifier: Apache-2.0

// mapping-vectors runs a CAID Action-Mapping conformance corpus against the
// Go implementation.
//
// Usage: go run ./cmd/mapping-vectors [--corpus PATH] [--json]
//
// The corpus is decoded by the package's strict document decoder and walked
// as generic values; nothing here decodes through encoding/json. With --json
// the runner prints [{id, pass, verdict, reasons, definition_sha256}] in
// corpus order (the output only is written with encoding/json), which
// caid/conformance/run.mjs compares across the three implementations;
// definition_sha256 holds both sides' digests, null for a failed side. A set
// mutation carries its value as "value", as "units", the UTF-16 code units
// of a string no strict JSON text can hold, built as the generalized UTF-8
// (WTF-8) a Go string holds for a lone surrogate, as "nest", {depth,
// container, leaf}: leaf inside depth nested slices (or maps whose only
// member is "a"), a value nested deeper than strict JSON text may be, or as
// "dag", {depth, leaf}: leaf inside depth nested two-element slices whose
// two elements are one shared slice, a value past the value count. Every
// mutation value is built fresh for the vector and set as built, never
// deep-copied, so a shared slice stays shared.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	caidlib "caid"
)

type obj = map[string]interface{}

type output struct {
	ID               string        `json:"id"`
	Pass             bool          `json:"pass"`
	Verdict          string        `json:"verdict"`
	Reasons          []string      `json:"reasons"`
	DefinitionSha256 []interface{} `json:"definition_sha256"`
}

// unitsString builds a string from UTF-16 code units: a well-formed pair is
// one code point, and a lone surrogate is its generalized UTF-8 bytes.
func unitsString(raw interface{}) string {
	list, _ := raw.([]interface{})
	units := make([]int, 0, len(list))
	for _, x := range list {
		n, _ := x.(fmt.Stringer)
		if n == nil {
			continue
		}
		v, _ := strconv.Atoi(n.String())
		units = append(units, v)
	}
	var b strings.Builder
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xD800 && u <= 0xDBFF && i+1 < len(units) && units[i+1] >= 0xDC00 && units[i+1] <= 0xDFFF {
			b.WriteRune(rune(0x10000 + ((u - 0xD800) << 10) + (units[i+1] - 0xDC00)))
			i++
			continue
		}
		if u >= 0xD800 && u <= 0xDFFF {
			b.WriteByte(byte(0xE0 | u>>12))
			b.WriteByte(byte(0x80 | (u>>6)&0x3F))
			b.WriteByte(byte(0x80 | u&0x3F))
			continue
		}
		b.WriteRune(rune(u))
	}
	return b.String()
}

// nestedValue builds a "nest" mutation value: leaf inside depth nested
// slices, or maps whose only member is "a".
func nestedValue(raw interface{}) interface{} {
	spec, _ := raw.(obj)
	depth := 0
	if n, ok := spec["depth"].(fmt.Stringer); ok {
		depth, _ = strconv.Atoi(n.String())
	}
	value := clone(spec["leaf"])
	for i := 0; i < depth; i++ {
		if str(spec, "container") == "object" {
			value = obj{"a": value}
		} else {
			value = []interface{}{value}
		}
	}
	return value
}

// sharedValue builds a "dag" mutation value: leaf inside depth nested
// two-element slices, both elements one shared slice.
func sharedValue(raw interface{}) interface{} {
	spec, _ := raw.(obj)
	depth := 0
	if n, ok := spec["depth"].(fmt.Stringer); ok {
		depth, _ = strconv.Atoi(n.String())
	}
	value := clone(spec["leaf"])
	for i := 0; i < depth; i++ {
		value = []interface{}{value, value}
	}
	return value
}

func sideDigest(r caidlib.MapActionResult) interface{} {
	if !r.OK {
		return nil
	}
	return r.DefinitionSha256
}

// clone deep-copies a decoded value so mutations never leak between vectors.
func clone(value interface{}) interface{} {
	switch t := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, v := range t {
			out[k] = clone(v)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, v := range t {
			out[i] = clone(v)
		}
		return out
	}
	return value
}

func str(m obj, key string) string {
	s, _ := m[key].(string)
	return s
}

func pointerSegments(pointer string) []string {
	raw := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		out = append(out, strings.ReplaceAll(strings.ReplaceAll(item, "~1", "/"), "~0", "~"))
	}
	return out
}

// mutate applies one corpus mutation ({op: set|delete, path, value}). The
// caller builds newValue fresh for the vector; it is set as given.
func mutate(value interface{}, segments []string, op string, newValue interface{}) interface{} {
	if len(segments) == 0 {
		if op == "set" {
			return newValue
		}
		return nil
	}
	head := segments[0]
	if len(segments) == 1 {
		switch typed := value.(type) {
		case map[string]interface{}:
			switch op {
			case "delete":
				delete(typed, head)
			case "set":
				typed[head] = newValue
			default:
				panic("unsupported vector mutation: " + op)
			}
			return typed
		case []interface{}:
			index, err := strconv.Atoi(head)
			if err != nil || index < 0 || index >= len(typed) {
				panic("invalid vector array mutation")
			}
			switch op {
			case "delete":
				return append(typed[:index], typed[index+1:]...)
			case "set":
				typed[index] = newValue
				return typed
			}
			panic("unsupported vector mutation: " + op)
		default:
			panic("invalid vector mutation target")
		}
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		typed[head] = mutate(typed[head], segments[1:], op, newValue)
		return typed
	case []interface{}:
		index, err := strconv.Atoi(head)
		if err != nil || index < 0 || index >= len(typed) {
			panic("invalid vector array path")
		}
		typed[index] = mutate(typed[index], segments[1:], op, newValue)
		return typed
	default:
		panic("invalid vector mutation path")
	}
}

func buildSide(corpus obj, descriptor obj) obj {
	profiles, _ := corpus["profiles"].(obj)
	sources, _ := corpus["sources"].(obj)
	profile := clone(profiles[str(descriptor, "profile")])
	source := clone(sources[str(descriptor, "source")])
	var sourceDescriptor interface{}
	if p, ok := profile.(obj); ok {
		sourceDescriptor = clone(p["source_format"])
	}
	pin := str(descriptor, "pin")
	if pin == "profile" {
		pin = caidlib.MappingProfileHash(profile)
	}
	nativeVerified := true
	if raw, present := descriptor["native_verified"]; present && raw != nil {
		nativeVerified, _ = raw.(bool)
	}
	return obj{
		"source":                source,
		"profile":               profile,
		"source_descriptor":     sourceDescriptor,
		"expected_profile_hash": pin,
		"native_verified":       nativeVerified,
	}
}

func stringList(v interface{}) []string {
	raw, _ := v.([]interface{})
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func equalStrings(left, right []string) bool {
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

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func main() {
	vectorPath := filepath.Clean(filepath.Join("..", "..", "conformance", "mapping-vectors.json"))
	jsonMode := false
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--corpus":
			if i+1 >= len(os.Args) {
				fmt.Fprintln(os.Stderr, "--corpus requires a path")
				os.Exit(2)
			}
			i++
			vectorPath = filepath.Clean(os.Args[i])
		case "--json":
			jsonMode = true
		}
	}
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	decoded, err := caidlib.DecodeDocumentJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot decode %s: %v\n", vectorPath, err)
		os.Exit(1)
	}
	corpus, ok := decoded.(obj)
	if !ok {
		fmt.Fprintf(os.Stderr, "FAIL: %s is not a JSON object\n", vectorPath)
		os.Exit(1)
	}
	definitions, _ := corpus["definitions"].([]interface{})
	enumSnapshots, _ := corpus["enum_snapshots"].([]interface{})
	corpusSuite := suiteOption(corpus)
	vectors, _ := corpus["vectors"].([]interface{})

	results := []output{}
	for _, raw := range vectors {
		vector, _ := raw.(obj)
		leftDescriptor, _ := vector["left"].(obj)
		rightDescriptor, _ := vector["right"].(obj)
		left := buildSide(corpus, leftDescriptor)
		right := buildSide(corpus, rightDescriptor)
		mutations, _ := vector["mutations"].([]interface{})
		for _, m := range mutations {
			operation, _ := m.(obj)
			side := left
			if str(operation, "side") == "right" {
				side = right
			}
			target := str(operation, "target")
			value := clone(operation["value"])
			if units, present := operation["units"]; present {
				value = unitsString(units)
			} else if nest, present := operation["nest"]; present {
				value = nestedValue(nest)
			} else if dag, present := operation["dag"]; present {
				value = sharedValue(dag)
			}
			side[target] = mutate(side[target], pointerSegments(str(operation, "path")), str(operation, "op"), value)
		}
		for _, sideName := range stringList(vector["repin_after_mutation"]) {
			side := left
			if sideName == "right" {
				side = right
			}
			side["expected_profile_hash"] = caidlib.MappingProfileHash(side["profile"])
		}
		// A vector's own suite, when present, replaces the corpus suite.
		suite := corpusSuite
		if _, present := vector["suite"]; present {
			suite = suiteOption(vector)
		}
		result := caidlib.CompareMappedActionsWithOptions(left, right, caidlib.CompareOptions{
			Definitions:   definitions,
			EnumSnapshots: enumSnapshots,
			Suite:         suite,
		})
		expect, _ := vector["expect"].(obj)
		verdictOK := result.Verdict == str(expect, "verdict")
		reasonsOK := equalStrings(result.Reasons, stringList(expect["reasons"]))
		if wanted := str(expect, "reason_contains"); wanted != "" {
			reasonsOK = contains(result.Reasons, wanted)
		}
		results = append(results, output{
			ID: str(vector, "id"), Pass: verdictOK && reasonsOK,
			Verdict: result.Verdict, Reasons: result.Reasons,
			DefinitionSha256: []interface{}{sideDigest(result.Left), sideDigest(result.Right)},
		})
	}

	failed := false
	for _, r := range results {
		if !r.Pass {
			failed = true
		}
	}
	if jsonMode {
		encoded, err := json.Marshal(results)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(encoded))
	} else {
		for _, r := range results {
			status := "PASS"
			if !r.Pass {
				status = "FAIL"
			}
			fmt.Println(status, r.ID, r.Verdict, strings.Join(r.Reasons, ","))
		}
	}
	if failed {
		os.Exit(1)
	}
}

// suiteOption reads the suite member of a corpus or a vector: nil when it is
// absent (the default suite), the string as given, or a value no suite
// matches when it is not a string.
func suiteOption(o obj) *string {
	raw, present := o["suite"]
	if !present {
		return nil
	}
	s, isString := raw.(string)
	if !isString {
		s = "\x00non-string"
	}
	return &s
}
