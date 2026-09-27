// SPDX-License-Identifier: Apache-2.0

// Command fuzzdriver is the CAID differential fuzz driver's Go lane.
//
// It reads JSON-lines cases on stdin and writes one JSON line per case on
// stdout: {"id": ..., "r": {"go": <outcome>}}.
//
// Objects under test ("obj", base64 octets) go to the JSON text entry
// points (port.go). When the octets decode, the native entry point also
// runs on the decoded value and a different result is reported as
// "parity". "native" cases go to the native entry points. Mapping sources
// in "src" are decoded with the implementation's decoder; a refusal is
// {"json_error": true}.
//
// Typed-API adaptations (the Go API cannot receive these JSON shapes): a
// compute suite that is absent or not a string is ""; a mapping suite that
// is absent is "jcs-sha256" and one that is not a string is "\x00"; a
// non-object profile, descriptor or side is a nil map; a non-string pin or
// expected digest is ""; native_verified is true only for JSON true.
//
// The output encoder is hand-written: encoding/json would rewrite invalid
// UTF-8 (the Go form of an unpaired surrogate) to U+FFFD and hide it.
//
// Built by caid/fuzz/run.mjs in a scratch module whose go.mod replaces
// caid with the tree under test; -tags legacy drives a pre-04 tree.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"unicode/utf8"
)

type obj = map[string]interface{}

func main() {
	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	writer := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer writer.Flush()
	tables := obj{}
	for i, a := range os.Args {
		if a == "--tables" && i+1 < len(os.Args) {
			data, err := os.ReadFile(os.Args[i+1])
			if err != nil {
				panic(err)
			}
			v, err := decodeTransport(data)
			if err != nil {
				panic(err)
			}
			tables = v.(obj)
		}
		if a == "--meta" && i+1 < len(os.Args) {
			meta := fmt.Sprintf(`{"lanes":{"go":{"legacy":%t}}}`, legacyFrontEnd())
			if err := os.WriteFile(os.Args[i+1], []byte(meta), 0o644); err != nil {
				panic(err)
			}
		}
	}
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 {
			v, derr := decodeTransport(line)
			if derr != nil {
				panic(derr)
			}
			c := v.(obj)
			writeJSON(writer, obj{"id": c["id"], "r": obj{"go": runCase(c, tables)}})
			writer.WriteByte('\n')
		}
		if err != nil {
			break
		}
	}
}

func resolve(c obj, inlineKey, refKey, table string, tables obj) interface{} {
	if ref, ok := c[refKey]; ok {
		t, _ := tables[table].(obj)
		key, _ := ref.(string)
		return t[key]
	}
	return c[inlineKey]
}

func asSlice(v interface{}) []interface{} {
	s, _ := v.([]interface{})
	return s
}

func asMap(v interface{}) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	return m
}

func strOrEmpty(v interface{}) string {
	s, _ := v.(string)
	return s
}

func computeSuite(c obj) string {
	s, _ := c["suite"].(string)
	return s
}

func mappingSuite(c obj) string {
	s, present := c["suite"]
	if !present {
		return "jcs-sha256"
	}
	if str, ok := s.(string); ok {
		return str
	}
	return "\x00"
}

// generic renders a Go result through its json tags as a generic value,
// so outcomes from any result type compare as JSON.
func generic(v interface{}) interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return obj{"driver_error": "marshal: " + err.Error()}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out interface{}
	if err := dec.Decode(&out); err != nil {
		return obj{"driver_error": "decode: " + err.Error()}
	}
	if m, ok := out.(map[string]interface{}); ok {
		for _, k := range []string{"refusals", "reasons", "details"} {
			if val, present := m[k]; present && val == nil {
				m[k] = []interface{}{}
			}
		}
	}
	return out
}

func sameJSON(a, b interface{}) bool {
	var x, y bytes.Buffer
	wx := bufio.NewWriter(&x)
	wy := bufio.NewWriter(&y)
	writeJSON(wx, a)
	writeJSON(wy, b)
	wx.Flush()
	wy.Flush()
	return bytes.Equal(x.Bytes(), y.Bytes())
}

func runCase(c obj, tables obj) (result interface{}) {
	defer func() {
		if p := recover(); p != nil {
			result = obj{"crash": "panic"}
		}
	}()
	defs := resolve(c, "defs", "defs_ref", "defs", tables)
	snaps := asSlice(resolve(c, "snaps", "snaps_ref", "snaps", tables))
	o := opts{definitions: defs, enumSnapshots: snaps}
	if s, present := c["suite"]; present {
		o.hasSuite, o.suite = true, s
	}
	if e, present := c["expected"]; present {
		o.hasExpected, o.expected = true, e
	}
	op, _ := c["op"].(string)
	switch op {
	case "compute", "verify":
		run := func(native bool, value interface{}) interface{} {
			if op == "compute" {
				if native {
					return generic(computeValue(value, o))
				}
				return generic(computeBytes(value.([]byte), o))
			}
			if native {
				return generic(verifyValue(value, strOrEmpty(c["caid"]), o))
			}
			return generic(verifyBytes(value.([]byte), strOrEmpty(c["caid"]), o))
		}
		if n, present := c["native"]; present {
			return run(true, buildNative(n, nil))
		}
		raw, err := base64.StdEncoding.DecodeString(strOrEmpty(c["obj"]))
		if err != nil {
			return obj{"driver_error": "base64"}
		}
		out := run(false, raw)
		if value, ok := decodeBytes(raw); ok {
			n := run(true, value)
			if !sameJSON(n, out) {
				m, isMap := out.(map[string]interface{})
				if !isMap {
					m = obj{"result": out}
				}
				m["parity"] = n
				return m
			}
		}
		return out
	case "parse":
		return generic(parseString(strOrEmpty(c["caid"])))
	case "map":
		source := c["source"]
		if b64, ok := c["src"].(string); ok {
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return obj{"driver_error": "base64"}
			}
			value, decoded := decodeBytes(raw)
			if !decoded {
				return obj{"json_error": true}
			}
			source = value
		}
		nv, _ := c["nv"].(bool)
		return mapOne(source, asMap(c["profile"]), asMap(c["desc"]), strOrEmpty(c["pin"]), nv, asSlice(defs), snaps, mappingSuite(c))
	case "compare":
		return compareSides(asMap(c["left"]), asMap(c["right"]), asSlice(defs), snaps, mappingSuite(c))
	}
	return obj{"driver_error": "unknown op " + op}
}

// writeJSON writes a generic value with sorted keys. Strings are written
// byte-faithfully: a WTF-8 surrogate (ED A0..BF xx) becomes its \uXXXX
// escape, and any other invalid byte becomes the text \xHH so it stays
// visible.
func writeJSON(w *bufio.Writer, v interface{}) {
	switch t := v.(type) {
	case nil:
		w.WriteString("null")
	case bool:
		if t {
			w.WriteString("true")
		} else {
			w.WriteString("false")
		}
	case json.Number:
		w.WriteString(string(t))
	case string:
		writeString(w, t)
	case []interface{}:
		w.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				w.WriteByte(',')
			}
			writeJSON(w, x)
		}
		w.WriteByte(']')
	case []string:
		w.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				w.WriteByte(',')
			}
			writeString(w, x)
		}
		w.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				w.WriteByte(',')
			}
			writeString(w, k)
			w.WriteByte(':')
			writeJSON(w, t[k])
		}
		w.WriteByte('}')
	default:
		writeJSON(w, generic(v))
	}
}

func writeString(w *bufio.Writer, s string) {
	w.WriteByte('"')
	for i := 0; i < len(s); {
		b := s[i]
		if b < 0x80 {
			switch {
			case b == '"':
				w.WriteString(`\"`)
			case b == '\\':
				w.WriteString(`\\`)
			case b < 0x20 || b == 0x7f:
				fmt.Fprintf(w, `\u%04x`, b)
			default:
				w.WriteByte(b)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			if b == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2] >= 0x80 && s[i+2] <= 0xBF {
				cp := (rune(b&0x0F) << 12) | (rune(s[i+1]&0x3F) << 6) | rune(s[i+2]&0x3F)
				w.WriteString(`\u` + strconv.FormatInt(int64(cp), 16))
				i += 3
				continue
			}
			fmt.Fprintf(w, `\\x%02X`, b)
			i++
			continue
		}
		if r > 0xFFFF {
			r -= 0x10000
			fmt.Fprintf(w, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		} else {
			fmt.Fprintf(w, `\u%04x`, r)
		}
		i += size
	}
	w.WriteByte('"')
}
