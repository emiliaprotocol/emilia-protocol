// SPDX-License-Identifier: Apache-2.0

// Command caidconformance is the Go conformance runner for the CAID core
// corpus (vectors.json, version 5) and the grammar boundary corpus
// (grammar-vectors.json). It drives the Go implementation (module caid,
// caid/impl/go) only through its public entry points, which port.go names.
//
//	cd caid/conformance/runners/go && go run . [-corpus core|grammar|all] [-json]
//
// Built with -tags legacy it measures a pre-04 implementation through
// DecodeJSON and the native entry points (port_legacy.go); that build never
// passes. Standard library only.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// opts carries the corpus options as given; port.go maps them onto the
// implementation's option types.
type opts struct {
	hasSuite      bool
	suite         interface{}
	definitions   interface{}
	enumSnapshots []interface{}
	hasExpected   bool
	expected      interface{}
}

type failure struct {
	Corpus string `json:"corpus"`
	ID     string `json:"id"`
	Detail string `json:"detail"`
}

type tally struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
}

var (
	failures  []failure
	perCorpus = map[string]*tally{}
	passCount int
	failCount int
)

func report(corpus, id string, ok bool, detail string) {
	t := perCorpus[corpus]
	if t == nil {
		t = &tally{}
		perCorpus[corpus] = t
	}
	if ok {
		passCount++
		t.Pass++
		return
	}
	failCount++
	t.Fail++
	failures = append(failures, failure{Corpus: corpus, ID: id, Detail: detail})
}

// guard turns a panic into a result the comparison reports; a conforming
// implementation never panics.
func guard(fn func() interface{}) (out interface{}) {
	defer func() {
		if r := recover(); r != nil {
			out = map[string]interface{}{"thrown": fmt.Sprint(r)}
		}
	}()
	return fn()
}

// ---------------------------------------------------------------- JSON helpers

// canonical renders a value as JSON with sorted keys, reading a Go result
// through its json tags. Nil result lists (refusals, reasons, details)
// compare equal to empty ones.
func canonical(v interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "<unmarshalable: " + err.Error() + ">"
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic interface{}
	if err := dec.Decode(&generic); err != nil {
		return "<undecodable>"
	}
	if m, ok := generic.(map[string]interface{}); ok {
		for _, k := range []string{"refusals", "reasons", "details"} {
			if val, present := m[k]; present && val == nil {
				m[k] = []interface{}{}
			}
		}
	}
	var b strings.Builder
	writeCanonical(&b, generic)
	return b.String()
}

func writeCanonical(b *strings.Builder, v interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			writeCanonical(b, x[k])
		}
		b.WriteByte('}')
	case []interface{}:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, e)
		}
		b.WriteByte(']')
	default:
		eb, _ := json.Marshal(x)
		b.Write(eb)
	}
}

func str(m map[string]interface{}, k string) string {
	s, _ := m[k].(string)
	return s
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- native lane

// wtf8 encodes UTF-16 code units, keeping a lone surrogate as its
// generalized UTF-8 bytes (not valid UTF-8, as the corpus intends).
func wtf8(units []interface{}) string {
	var out []byte
	for i := 0; i < len(units); i++ {
		u := toInt(units[i])
		if u >= 0xD800 && u <= 0xDBFF && i+1 < len(units) {
			if lo := toInt(units[i+1]); lo >= 0xDC00 && lo <= 0xDFFF {
				out = utf8.AppendRune(out, rune(0x10000+((u-0xD800)<<10)+(lo-0xDC00)))
				i++
				continue
			}
		}
		if u >= 0xD800 && u <= 0xDFFF {
			out = append(out, byte(0xE0|(u>>12)), byte(0x80|((u>>6)&0x3F)), byte(0x80|(u&0x3F)))
			continue
		}
		out = utf8.AppendRune(out, rune(u))
	}
	return string(out)
}

func tagOf(v interface{}) (string, interface{}) {
	m, ok := v.(map[string]interface{})
	if !ok || len(m) != 1 {
		return "", nil
	}
	for k, x := range m {
		if strings.HasPrefix(k, "$") {
			return k, x
		}
	}
	return "", nil
}

// buildNative builds the Go host value for a native-lane encoding.
func buildNative(encoded interface{}, enclosing interface{}) interface{} {
	tag, body := tagOf(encoded)
	switch tag {
	case "$units":
		units, _ := body.([]interface{})
		return wtf8(units)
	case "$object":
		out := map[string]interface{}{}
		pairs, _ := body.([]interface{})
		for _, p := range pairs {
			pair, _ := p.([]interface{})
			if len(pair) != 2 {
				continue
			}
			var key string
			if s, isString := pair[0].(string); isString {
				key = s
			} else {
				key, _ = buildNative(pair[0], enclosing).(string)
			}
			out[key] = buildNative(pair[1], out)
		}
		return out
	case "$nest":
		spec, _ := body.(map[string]interface{})
		value := buildNative(spec["leaf"], enclosing)
		for i := 0; i < toInt(spec["depth"]); i++ {
			if str(spec, "container") == "object" {
				value = map[string]interface{}{"a": value}
			} else {
				value = []interface{}{value}
			}
		}
		return value
	case "$host":
		switch body {
		case "nan":
			return math.NaN()
		case "infinity":
			return math.Inf(1)
		case "-infinity":
			return math.Inf(-1)
		case "negative_zero":
			return math.Copysign(0, -1)
		case "cyclic":
			return enclosing
		case "opaque":
			return struct{}{}
		}
		panic(fmt.Sprintf("unknown $host %v", body))
	}
	switch x := encoded.(type) {
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, e := range x {
			out[i] = buildNative(e, out)
		}
		return out
	case map[string]interface{}:
		out := map[string]interface{}{}
		for k, e := range x {
			out[k] = buildNative(e, out)
		}
		return out
	}
	return encoded
}

func inputBytes(in map[string]interface{}) []byte {
	if s, ok := in["json"].(string); ok {
		return []byte(s)
	}
	if s, ok := in["json_b64"].(string); ok {
		b, _ := base64.StdEncoding.DecodeString(s)
		return b
	}
	if r, ok := in["json_repeat"].(map[string]interface{}); ok {
		var b bytes.Buffer
		b.WriteString(str(r, "prefix"))
		unit := str(r, "unit")
		n := toInt(r["count"])
		b.Grow(len(unit)*n + len(str(r, "suffix")))
		for i := 0; i < n; i++ {
			b.WriteString(unit)
		}
		b.WriteString(str(r, "suffix"))
		return b.Bytes()
	}
	return nil
}

// ---------------------------------------------------------------- corpus files

func conformanceDir() string {
	for _, candidate := range []string{"../..", "caid/conformance", "."} {
		if _, err := os.Stat(filepath.Join(candidate, "vectors.json")); err == nil {
			return candidate
		}
	}
	return "../.."
}

func readCorpus(name string) map[string]interface{} {
	data, err := os.ReadFile(filepath.Join(conformanceDir(), name))
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL cannot read", name, err)
		os.Exit(1)
	}
	value, err := decodeCorpus(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL cannot decode", name, err)
		os.Exit(1)
	}
	m, _ := value.(map[string]interface{})
	return m
}

// ---------------------------------------------------------------- core corpus

func runCore() {
	corpus := readCorpus("vectors.json")
	if toInt(corpus["version"]) != 5 {
		report("core", "(corpus)", false, "expected corpus version 5")
		return
	}
	snapshots, _ := corpus["enum_snapshots"].([]interface{})
	vectors, _ := corpus["vectors"].([]interface{})
	caids := map[string]string{}
	for _, raw := range vectors {
		v, _ := raw.(map[string]interface{})
		id := str(v, "id")
		kind := str(v, "kind")
		in, _ := v["input"].(map[string]interface{})
		o := opts{definitions: v["definitions"], enumSnapshots: snapshots}
		if s, present := in["suite"]; present && kind == "compute" {
			o.hasSuite, o.suite = true, s
		}
		if e, present := in["expected_definition_sha256"]; present && kind == "verify" {
			o.hasExpected, o.expected = true, e
		}
		var actual interface{}
		parity := ""
		var elapsed time.Duration
		switch {
		case kind == "decode":
			actual = guard(func() interface{} {
				_, ok, refusals := decodeBytes(inputBytes(in))
				if ok {
					return map[string]interface{}{"ok": true}
				}
				return map[string]interface{}{"ok": false, "refusals": refusals}
			})
		case kind == "parse":
			actual = guard(func() interface{} { return parseString(str(in, "caid")) })
		case kind == "definition":
			actual = guard(func() interface{} { return definitionSha256(in["definition"]) })
		case in["native"] != nil && legacySkip(in["native"]):
			actual = map[string]interface{}{"skipped": "a pre-04 implementation recurses without bound on this value"}
		case in["native"] != nil:
			host := buildNative(in["native"], nil)
			if kind == "compute" {
				actual = guard(func() interface{} { return computeValue(host, o) })
			} else {
				actual = guard(func() interface{} { return verifyValue(host, str(in, "caid"), o) })
			}
		default:
			data := inputBytes(in)
			start := time.Now()
			if kind == "compute" {
				actual = guard(func() interface{} { return computeBytes(data, o) })
			} else {
				actual = guard(func() interface{} { return verifyBytes(data, str(in, "caid"), o) })
			}
			elapsed = time.Since(start)
			if value, ok, _ := decodeBytes(data); ok {
				var n interface{}
				if kind == "compute" {
					n = guard(func() interface{} { return computeValue(value, o) })
				} else {
					n = guard(func() interface{} { return verifyValue(value, str(in, "caid"), o) })
				}
				if canonical(n) != canonical(actual) {
					parity = "native entry point on the decoded value gave " + clip(canonical(n), 300)
				}
			}
		}
		got := canonical(actual)
		if kind == "compute" {
			var probe map[string]interface{}
			if json.Unmarshal([]byte(got), &probe) == nil {
				if c, ok := probe["caid"].(string); ok && c != "" {
					caids[id] = c
				}
			}
		}
		want := canonical(v["expect"])
		detail := parity
		if got != want {
			detail = "expected " + clip(want, 400) + " got " + clip(got, 400)
		}
		report("core", id, got == want && parity == "", detail)
		if budget := toInt(v["time_budget_ms"]); budget > 0 && elapsed > time.Duration(budget)*time.Millisecond {
			report("core", id+" (time)", false, fmt.Sprintf("%d ms exceeds the %d ms budget", elapsed.Milliseconds(), budget))
		}
	}
	for _, raw := range vectors {
		v, _ := raw.(map[string]interface{})
		rel, _ := v["relation"].(map[string]interface{})
		if rel == nil {
			continue
		}
		other := str(rel, "same_caid_as")
		same := other != ""
		if !same {
			other = str(rel, "different_caid_from")
		}
		a, aok := caids[str(v, "id")]
		b, bok := caids[other]
		ok := aok && bok && ((a == b) == same)
		report("core", str(v, "id")+" (relation "+other+")", ok, fmt.Sprintf("%s vs %s", a, b))
	}
}

// ---------------------------------------------------------------- grammar corpus

func substitute(template interface{}, value string) interface{} {
	switch x := template.(type) {
	case string:
		if x == "$CASE" {
			return value
		}
		return x
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, e := range x {
			out[i] = substitute(e, value)
		}
		return out
	case map[string]interface{}:
		out := map[string]interface{}{}
		// A "$CASE" member name replaces a member of the same name.
		for k, e := range x {
			if k != "$CASE" {
				out[k] = substitute(e, value)
			}
		}
		if e, present := x["$CASE"]; present {
			out[value] = substitute(e, value)
		}
		return out
	}
	return template
}

func caseString(c interface{}) string {
	if s, ok := c.(string); ok {
		return s
	}
	m, _ := c.(map[string]interface{})
	if units, ok := m["$units"].([]interface{}); ok {
		return wtf8(units)
	}
	if r, ok := m["repeat"].(map[string]interface{}); ok {
		return str(r, "prefix") + strings.Repeat(str(r, "unit"), toInt(r["count"])) + str(r, "suffix")
	}
	return ""
}

func marshalText(v interface{}) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

func runGrammar() {
	corpus := readCorpus("grammar-vectors.json")
	placeholder := str(corpus, "placeholder")
	drivers, _ := corpus["drivers"].(map[string]interface{})
	cases, _ := corpus["cases"].([]interface{})
	for index, raw := range cases {
		c, _ := raw.(map[string]interface{})
		d, _ := drivers[str(c, "driver")].(map[string]interface{})
		lane := str(c, "lane")
		id := fmt.Sprintf("grammar[%d] %s %s", index, str(c, "driver"), lane)
		var actual interface{}
		expect, _ := c["expect"].(map[string]interface{})
		if str(d, "operation") == "parse" {
			cs, _ := d["caid"].(map[string]interface{})
			actual = guard(func() interface{} { return parseString(str(cs, "prefix") + caseString(c["case"]) + str(cs, "suffix")) })
		} else {
			s := caseString(c["case"])
			if lane == "bytes" {
				s = placeholder
			}
			definition := substitute(d["definition"], s)
			object := substitute(d["object"], s)
			o := opts{hasSuite: true, suite: "jcs-sha256", definitions: []interface{}{definition}, enumSnapshots: []interface{}{}}
			if str(d, "suite") == "$CASE" {
				o.suite = s
			}
			if lane == "native" {
				actual = guard(func() interface{} { return computeValue(object, o) })
			} else {
				var data []byte
				if lane == "bytes" {
					cm, _ := c["case"].(map[string]interface{})
					rawCase, _ := base64.StdEncoding.DecodeString(str(cm, "b64"))
					data = bytes.Join(bytes.Split(marshalText(object), []byte(placeholder)), rawCase)
				} else {
					data = marshalText(object)
				}
				actual = guard(func() interface{} { return computeBytes(data, o) })
				if lane == "text" {
					if value, ok, _ := decodeBytes(data); ok {
						n := guard(func() interface{} { return computeValue(value, o) })
						if canonical(n) != canonical(actual) {
							report("grammar", id, false, "native parity: "+clip(canonical(n), 200)+" vs "+clip(canonical(actual), 200))
							continue
						}
					}
				}
			}
			if _, wantCaid := expect["caid"]; wantCaid {
				var probe map[string]interface{}
				if json.Unmarshal([]byte(canonical(actual)), &probe) == nil {
					if cv, ok := probe["caid"].(string); ok && cv != "" {
						actual = map[string]interface{}{"caid": cv}
					}
				}
			}
		}
		got, want := canonical(actual), canonical(c["expect"])
		report("grammar", id, got == want, "case "+clip(canonical(c["case"]), 80)+": expected "+clip(want, 200)+" got "+clip(got, 200))
	}
}

// ---------------------------------------------------------------- main

func main() {
	corpusChoice := flag.String("corpus", "all", "core, grammar or all")
	asJSON := flag.Bool("json", false, "print a JSON summary")
	flag.Parse()
	if *corpusChoice == "core" || *corpusChoice == "all" {
		runCore()
	}
	if *corpusChoice == "grammar" || *corpusChoice == "all" {
		runGrammar()
	}
	limit := failures
	if len(limit) > 500 {
		limit = limit[:500]
	}
	summary := map[string]interface{}{
		"runner": "go", "impl": "caid/impl/go", "corpus": *corpusChoice, "legacy_front_end": legacyFrontEnd(),
		"pass": passCount, "fail": failCount, "per_corpus": perCorpus, "failures": limit,
	}
	if *asJSON {
		out, _ := json.Marshal(summary)
		fmt.Println(string(out))
	} else {
		for i, f := range failures {
			if i == 60 {
				fmt.Printf("... %d more failures\n", len(failures)-60)
				break
			}
			fmt.Printf("FAIL %s %s\n     %s\n", f.Corpus, f.ID, f.Detail)
		}
		pc, _ := json.Marshal(perCorpus)
		legacy := ""
		if legacyFrontEnd() {
			legacy = ", legacy front end"
		}
		fmt.Printf("go caid/impl/go (%s%s): %d passed, %d failed %s\n", *corpusChoice, legacy, passCount, failCount, pc)
	}
	if failCount > 0 || legacyFrontEnd() {
		os.Exit(1)
	}
}
