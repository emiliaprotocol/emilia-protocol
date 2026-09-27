// SPDX-License-Identifier: Apache-2.0

package main

// The fuzz case lines are the harness's own transport, not CAID input, so
// they are decoded here rather than by the implementation: numbers become
// json.Number, and an unpaired surrogate escape becomes its generalized
// UTF-8 bytes (WTF-8), the Go form of a string holding a lone surrogate,
// so a native-lane string reaches the implementation unchanged.

import (
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"
)

type transport struct {
	data []byte
	pos  int
}

func decodeTransport(data []byte) (interface{}, error) {
	t := &transport{data: data}
	t.ws()
	v, err := t.value()
	if err != nil {
		return nil, err
	}
	t.ws()
	if t.pos != len(t.data) {
		return nil, errors.New("transport: trailing content")
	}
	return v, nil
}

func (t *transport) ws() {
	for t.pos < len(t.data) && (t.data[t.pos] == ' ' || t.data[t.pos] == '\t' || t.data[t.pos] == '\n' || t.data[t.pos] == '\r') {
		t.pos++
	}
}

func (t *transport) value() (interface{}, error) {
	if t.pos >= len(t.data) {
		return nil, errors.New("transport: end of input")
	}
	switch c := t.data[t.pos]; {
	case c == '{':
		t.pos++
		out := map[string]interface{}{}
		t.ws()
		if t.pos < len(t.data) && t.data[t.pos] == '}' {
			t.pos++
			return out, nil
		}
		for {
			t.ws()
			k, err := t.str()
			if err != nil {
				return nil, err
			}
			t.ws()
			if t.pos >= len(t.data) || t.data[t.pos] != ':' {
				return nil, errors.New("transport: expected colon")
			}
			t.pos++
			t.ws()
			v, err := t.value()
			if err != nil {
				return nil, err
			}
			out[k] = v
			t.ws()
			if t.pos < len(t.data) && t.data[t.pos] == ',' {
				t.pos++
				continue
			}
			if t.pos < len(t.data) && t.data[t.pos] == '}' {
				t.pos++
				return out, nil
			}
			return nil, errors.New("transport: expected comma or brace")
		}
	case c == '[':
		t.pos++
		out := []interface{}{}
		t.ws()
		if t.pos < len(t.data) && t.data[t.pos] == ']' {
			t.pos++
			return out, nil
		}
		for {
			t.ws()
			v, err := t.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			t.ws()
			if t.pos < len(t.data) && t.data[t.pos] == ',' {
				t.pos++
				continue
			}
			if t.pos < len(t.data) && t.data[t.pos] == ']' {
				t.pos++
				return out, nil
			}
			return nil, errors.New("transport: expected comma or bracket")
		}
	case c == '"':
		return t.str()
	case c == 't' && len(t.data)-t.pos >= 4 && string(t.data[t.pos:t.pos+4]) == "true":
		t.pos += 4
		return true, nil
	case c == 'f' && len(t.data)-t.pos >= 5 && string(t.data[t.pos:t.pos+5]) == "false":
		t.pos += 5
		return false, nil
	case c == 'n' && len(t.data)-t.pos >= 4 && string(t.data[t.pos:t.pos+4]) == "null":
		t.pos += 4
		return nil, nil
	default:
		start := t.pos
		for t.pos < len(t.data) {
			b := t.data[t.pos]
			if (b >= '0' && b <= '9') || b == '-' || b == '+' || b == '.' || b == 'e' || b == 'E' {
				t.pos++
				continue
			}
			break
		}
		if start == t.pos {
			return nil, errors.New("transport: unexpected character")
		}
		return json.Number(string(t.data[start:t.pos])), nil
	}
}

func (t *transport) str() (string, error) {
	if t.pos >= len(t.data) || t.data[t.pos] != '"' {
		return "", errors.New("transport: expected string")
	}
	t.pos++
	var out []byte
	for t.pos < len(t.data) {
		b := t.data[t.pos]
		if b == '"' {
			t.pos++
			return string(out), nil
		}
		if b != '\\' {
			out = append(out, b)
			t.pos++
			continue
		}
		if t.pos+1 >= len(t.data) {
			break
		}
		e := t.data[t.pos+1]
		t.pos += 2
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			u, ok := t.hex4()
			if !ok {
				return "", errors.New("transport: bad escape")
			}
			if u >= 0xD800 && u <= 0xDBFF && t.pos+1 < len(t.data) && t.data[t.pos] == '\\' && t.data[t.pos+1] == 'u' {
				save := t.pos
				t.pos += 2
				if lo, ok2 := t.hex4(); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
					out = utf8.AppendRune(out, rune(0x10000+((u-0xD800)<<10)+(lo-0xDC00)))
					continue
				}
				t.pos = save
			}
			if u >= 0xD800 && u <= 0xDFFF {
				out = append(out, byte(0xE0|(u>>12)), byte(0x80|((u>>6)&0x3F)), byte(0x80|(u&0x3F)))
				continue
			}
			out = utf8.AppendRune(out, rune(u))
		default:
			return "", errors.New("transport: bad escape")
		}
	}
	return "", errors.New("transport: unterminated string")
}

func (t *transport) hex4() (int, bool) {
	if t.pos+4 > len(t.data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(t.data[t.pos:t.pos+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	t.pos += 4
	return int(n), true
}
