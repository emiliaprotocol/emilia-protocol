// SPDX-License-Identifier: Apache-2.0

package main

// The native lane of the CAID conformance corpora (native.mjs describes the
// encoding), built as Go host values: a lone surrogate is its generalized
// UTF-8 (WTF-8) bytes, NaN and the infinities are float64, a cyclic value
// refers to its enclosing map or slice, and an opaque value is a struct.
// The conformance runner and the fuzz driver (caid/fuzz/run.mjs copies this
// file into the driver's scratch module) both build host values here, so
// the two can never disagree about a tag. An unknown tag panics: it is an
// error in the corpus, never a value.

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

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
	case "$repeat":
		spec, _ := body.(map[string]interface{})
		return strings.Repeat(str(spec, "unit"), toInt(spec["count"]))
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
