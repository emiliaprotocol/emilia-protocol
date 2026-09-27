// SPDX-License-Identifier: Apache-2.0

// Package jsontext is the one JSON text decoder of the CAID Go port.
//
// Package caid exposes it only in its strict form (caid.DecodeJSON and
// friends): the profile of draft-schrock-canonical-action-identifier-04
// Section 2.4, which is an I-JSON message [RFC7493] with no byte order mark,
// exactly one JSON text, and a nesting bound. The host form, which keeps
// unpaired surrogate escapes as generalized UTF-8 and permits noncharacters,
// exists for the conformance runners alone: it builds host values outside the
// data model so the native entry points can be tested on them. Being an
// internal package, it cannot be imported from outside this module.
//
// Values decode to map[string]interface{}, []interface{}, json.Number (the
// exact number token), string, bool and nil. encoding/json is imported for
// the json.Number type only; nothing here decodes through it.
package jsontext

import (
	"encoding/json"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// Options selects the decoder profile.
type Options struct {
	// MaxOctets refuses input longer than this many octets before parsing;
	// 0 means no size limit.
	MaxOctets int
	// MaxDepth bounds nesting: the outermost object or array is at depth 1.
	// It must be positive.
	MaxDepth int
	// Host keeps unpaired surrogate escapes (as generalized UTF-8, which is
	// not valid UTF-8 in a Go string) and permits noncharacters. It is for
	// conformance tooling only; the strict profile refuses both.
	Host bool
}

// Error reports why a text was refused. Offset is the byte offset where
// decoding stopped, or -1 for a check made before parsing.
type Error struct {
	Offset int
	Msg    string
}

func (e *Error) Error() string {
	if e.Offset < 0 {
		return e.Msg
	}
	return fmt.Sprintf("offset %d: %s", e.Offset, e.Msg)
}

var byteOrderMark = []byte{0xEF, 0xBB, 0xBF}

// Decode decodes exactly one JSON text under opts.
func Decode(data []byte, opts Options) (interface{}, *Error) {
	if opts.MaxOctets > 0 && len(data) > opts.MaxOctets {
		return nil, &Error{Offset: -1, Msg: fmt.Sprintf("input is %d octets, above the limit of %d", len(data), opts.MaxOctets)}
	}
	if !utf8.Valid(data) {
		return nil, &Error{Offset: -1, Msg: "input is not valid UTF-8"}
	}
	if len(data) >= 3 && data[0] == byteOrderMark[0] && data[1] == byteOrderMark[1] && data[2] == byteOrderMark[2] {
		return nil, &Error{Offset: 0, Msg: "input begins with a byte order mark"}
	}
	if opts.MaxDepth <= 0 {
		return nil, &Error{Offset: -1, Msg: "decoder misconfigured: MaxDepth must be positive"}
	}
	d := &decoder{data: data, opts: opts}
	d.skipWhitespace()
	value, err := d.value(0)
	if err != nil {
		return nil, err
	}
	d.skipWhitespace()
	if d.pos != len(d.data) {
		return nil, d.fail("content after the JSON text")
	}
	return value, nil
}

// IsNoncharacter reports whether r is a Unicode noncharacter: U+FDD0 through
// U+FDEF, or the last two code points of any plane.
func IsNoncharacter(r rune) bool {
	return (r >= 0xFDD0 && r <= 0xFDEF) || (r >= 0 && r <= utf8.MaxRune && r&0xFFFE == 0xFFFE)
}

type decoder struct {
	data []byte
	pos  int
	opts Options
}

func (d *decoder) fail(format string, args ...interface{}) *Error {
	return &Error{Offset: d.pos, Msg: fmt.Sprintf(format, args...)}
}

// skipWhitespace skips the four JSON whitespace octets of RFC 8259.
func (d *decoder) skipWhitespace() {
	for d.pos < len(d.data) {
		switch d.data[d.pos] {
		case ' ', '\t', '\n', '\r':
			d.pos++
		default:
			return
		}
	}
}

func (d *decoder) value(depth int) (interface{}, *Error) {
	if d.pos >= len(d.data) {
		return nil, d.fail("unexpected end of input")
	}
	switch c := d.data[d.pos]; {
	case c == '{':
		return d.object(depth + 1)
	case c == '[':
		return d.array(depth + 1)
	case c == '"':
		return d.string()
	case c == 't':
		return true, d.literal("true")
	case c == 'f':
		return false, d.literal("false")
	case c == 'n':
		return nil, d.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	default:
		return nil, d.fail("unexpected character %q", c)
	}
}

func (d *decoder) literal(word string) *Error {
	if len(d.data)-d.pos < len(word) || string(d.data[d.pos:d.pos+len(word)]) != word {
		return d.fail("invalid literal")
	}
	d.pos += len(word)
	return nil
}

func (d *decoder) object(depth int) (interface{}, *Error) {
	if depth > d.opts.MaxDepth {
		return nil, d.fail("nesting deeper than %d", d.opts.MaxDepth)
	}
	d.pos++ // '{'
	out := map[string]interface{}{}
	d.skipWhitespace()
	if d.pos < len(d.data) && d.data[d.pos] == '}' {
		d.pos++
		return out, nil
	}
	for {
		if d.pos >= len(d.data) || d.data[d.pos] != '"' {
			return nil, d.fail("expected a member name")
		}
		keyStart := d.pos
		key, err := d.string()
		if err != nil {
			return nil, err
		}
		if _, duplicate := out[key]; duplicate {
			d.pos = keyStart
			return nil, d.fail("duplicate member name")
		}
		d.skipWhitespace()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return nil, d.fail("expected ':' after a member name")
		}
		d.pos++
		d.skipWhitespace()
		member, err := d.value(depth)
		if err != nil {
			return nil, err
		}
		out[key] = member
		d.skipWhitespace()
		if d.pos >= len(d.data) {
			return nil, d.fail("unterminated object")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipWhitespace()
		case '}':
			d.pos++
			return out, nil
		default:
			return nil, d.fail("expected ',' or '}' in an object")
		}
	}
}

func (d *decoder) array(depth int) (interface{}, *Error) {
	if depth > d.opts.MaxDepth {
		return nil, d.fail("nesting deeper than %d", d.opts.MaxDepth)
	}
	d.pos++ // '['
	out := []interface{}{}
	d.skipWhitespace()
	if d.pos < len(d.data) && d.data[d.pos] == ']' {
		d.pos++
		return out, nil
	}
	for {
		item, err := d.value(depth)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
		d.skipWhitespace()
		if d.pos >= len(d.data) {
			return nil, d.fail("unterminated array")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipWhitespace()
		case ']':
			d.pos++
			return out, nil
		default:
			return nil, d.fail("expected ',' or ']' in an array")
		}
	}
}

func (d *decoder) hex4() (rune, bool) {
	if len(d.data)-d.pos < 4 {
		return 0, false
	}
	var r rune
	for _, c := range d.data[d.pos : d.pos+4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}
	d.pos += 4
	return r, true
}

// appendSurrogate appends the generalized UTF-8 bytes of an unpaired
// surrogate code point (host profile only). utf8.AppendRune would write
// U+FFFD instead.
func appendSurrogate(buf []byte, r rune) []byte {
	return append(buf, byte(0xE0|(r>>12)), byte(0x80|((r>>6)&0x3F)), byte(0x80|(r&0x3F)))
}

func (d *decoder) string() (string, *Error) {
	d.pos++ // opening quote
	start := d.pos
	var buf []byte
	escaped := false
	for {
		if d.pos >= len(d.data) {
			return "", d.fail("unterminated string")
		}
		c := d.data[d.pos]
		switch {
		case c == '"':
			d.pos++
			if !escaped {
				return string(d.data[start : d.pos-1]), nil
			}
			return string(buf), nil
		case c < 0x20:
			return "", d.fail("unescaped control character in a string")
		case c >= 0x80:
			// The input is valid UTF-8, so this is the first byte of a
			// complete multi-byte sequence.
			r, size := utf8.DecodeRune(d.data[d.pos:])
			if !d.opts.Host && IsNoncharacter(r) {
				return "", d.fail("noncharacter U+%04X in a string", r)
			}
			if escaped {
				buf = append(buf, d.data[d.pos:d.pos+size]...)
			}
			d.pos += size
			continue
		case c != '\\':
			if escaped {
				buf = append(buf, c)
			}
			d.pos++
			continue
		}
		if !escaped {
			escaped = true
			buf = append(buf, d.data[start:d.pos]...)
		}
		escapeAt := d.pos
		d.pos++ // backslash
		if d.pos >= len(d.data) {
			return "", d.fail("unterminated escape")
		}
		e := d.data[d.pos]
		d.pos++
		switch e {
		case '"', '\\', '/':
			buf = append(buf, e)
		case 'b':
			buf = append(buf, '\b')
		case 'f':
			buf = append(buf, '\f')
		case 'n':
			buf = append(buf, '\n')
		case 'r':
			buf = append(buf, '\r')
		case 't':
			buf = append(buf, '\t')
		case 'u':
			r, ok := d.hex4()
			if !ok {
				d.pos = escapeAt
				return "", d.fail("invalid \\u escape")
			}
			switch {
			case r >= 0xD800 && r <= 0xDBFF:
				// A high surrogate combines only with an immediately
				// following low-surrogate escape.
				if len(d.data)-d.pos >= 6 && d.data[d.pos] == '\\' && d.data[d.pos+1] == 'u' {
					save := d.pos
					d.pos += 2
					low, lowOK := d.hex4()
					if lowOK && low >= 0xDC00 && low <= 0xDFFF {
						scalar := utf16.DecodeRune(r, low)
						if !d.opts.Host && IsNoncharacter(scalar) {
							d.pos = escapeAt
							return "", d.fail("escape denotes the noncharacter U+%04X", scalar)
						}
						buf = utf8.AppendRune(buf, scalar)
						continue
					}
					d.pos = save
				}
				if !d.opts.Host {
					d.pos = escapeAt
					return "", d.fail("escape denotes an unpaired surrogate")
				}
				buf = appendSurrogate(buf, r)
			case r >= 0xDC00 && r <= 0xDFFF:
				if !d.opts.Host {
					d.pos = escapeAt
					return "", d.fail("escape denotes an unpaired surrogate")
				}
				buf = appendSurrogate(buf, r)
			default:
				if !d.opts.Host && IsNoncharacter(r) {
					d.pos = escapeAt
					return "", d.fail("escape denotes the noncharacter U+%04X", r)
				}
				buf = utf8.AppendRune(buf, r)
			}
		default:
			d.pos = escapeAt
			return "", d.fail("invalid escape")
		}
	}
}

// number scans one RFC 8259 number token and returns it unchanged. The
// decoder never refuses a number for its value; the data model decides.
func (d *decoder) number() (interface{}, *Error) {
	start := d.pos
	if d.data[d.pos] == '-' {
		d.pos++
	}
	digits := func() int {
		n := 0
		for d.pos < len(d.data) && d.data[d.pos] >= '0' && d.data[d.pos] <= '9' {
			d.pos++
			n++
		}
		return n
	}
	if d.pos >= len(d.data) {
		return nil, d.fail("invalid number")
	}
	if d.data[d.pos] == '0' {
		d.pos++
	} else if digits() == 0 {
		return nil, d.fail("invalid number")
	}
	if d.pos < len(d.data) && d.data[d.pos] == '.' {
		d.pos++
		if digits() == 0 {
			return nil, d.fail("invalid number fraction")
		}
	}
	if d.pos < len(d.data) && (d.data[d.pos] == 'e' || d.data[d.pos] == 'E') {
		d.pos++
		if d.pos < len(d.data) && (d.data[d.pos] == '+' || d.data[d.pos] == '-') {
			d.pos++
		}
		if digits() == 0 {
			return nil, d.fail("invalid number exponent")
		}
	}
	return json.Number(d.data[start:d.pos]), nil
}

// IsNumberToken reports whether s is exactly one RFC 8259 number token. A
// json.Number built by a caller must pass it before its value is read:
// strconv.ParseFloat also accepts forms such as "Inf", "0x1p4" and "1_0".
func IsNumberToken(s string) bool {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	digits := func() int {
		n := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
			n++
		}
		return n
	}
	if i >= len(s) {
		return false
	}
	if s[i] == '0' {
		i++
	} else if digits() == 0 {
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		if digits() == 0 {
			return false
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		if digits() == 0 {
			return false
		}
	}
	return i == len(s)
}
