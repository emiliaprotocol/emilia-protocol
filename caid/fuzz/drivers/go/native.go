// SPDX-License-Identifier: Apache-2.0

package main

// The native-lane encoding of caid/conformance/runners/native.mjs, built
// as Go host values: a lone surrogate is its WTF-8 bytes, NaN and the
// infinities are float64, a cyclic value refers to its enclosing map or
// slice, and an opaque value is a struct.

import (
	"encoding/json"
	"math"
	"strings"
	"unicode/utf8"
)

type opts struct {
	hasSuite      bool
	suite         interface{}
	definitions   interface{}
	enumSnapshots []interface{}
	hasExpected   bool
	expected      interface{}
}

func toInt(v interface{}) int {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case float64:
		return int(n)
	}
	return 0
}

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

func buildNative(encoded interface{}, enclosing interface{}) interface{} {
	if m, ok := encoded.(map[string]interface{}); ok && len(m) == 1 {
		for tag, body := range m {
			if !strings.HasPrefix(tag, "$") {
				break
			}
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
					key, isString := pair[0].(string)
					if !isString {
						key, _ = buildNative(pair[0], enclosing).(string)
					}
					out[key] = buildNative(pair[1], out)
				}
				return out
			case "$nest":
				spec, _ := body.(map[string]interface{})
				value := buildNative(spec["leaf"], enclosing)
				for i := 0; i < toInt(spec["depth"]); i++ {
					if c, _ := spec["container"].(string); c == "object" {
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
				default:
					return struct{}{}
				}
			}
		}
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

func suiteString(o opts) string {
	if s, ok := o.suite.(string); ok && o.hasSuite {
		return s
	}
	return ""
}

func definitionList(o opts) []interface{} {
	d, _ := o.definitions.([]interface{})
	return d
}

func expectedString(o opts) string {
	if s, ok := o.expected.(string); ok && o.hasExpected {
		return s
	}
	return ""
}
