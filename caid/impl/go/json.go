// json.go - strict JSON decoding into the generic value model this package
// takes.
//
// encoding/json is not a safe front end for CAID input. It replaces an
// unpaired surrogate escape such as "\ud800" with U+FFFD, which silently
// changes the content being identified and hides the refusal RFC 8785
// section 3.2.2.2 requires, and it keeps the last of duplicate member names,
// which RFC 8785 (through I-JSON, RFC 7493 section 2.3) and the CAID draft
// require a raw parser to reject. DecodeJSON is the decoder the Go vector
// runners use and the one Go callers should use for raw action objects,
// definitions, snapshots, and mapping sources.
package caid

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// maxDecodeDepth bounds object and array nesting, matching encoding/json.
const maxDecodeDepth = 10000

// DecodeJSON decodes exactly one JSON text (RFC 8259) into the value model
// ComputeCaid, VerifyCaid, and MapAction take: map[string]interface{},
// []interface{}, json.Number, string, bool, and nil.
//
// It returns an error for input that is not valid UTF-8, for any syntax
// error or trailing content, for an unescaped control character in a
// string, and for duplicate member names in one object (compared after
// unescaping, so "a" and "a" are duplicates).
//
// It does not replace an unpaired surrogate escape. The escape decodes to
// that code point's generalized UTF-8 bytes, so the resulting Go string is
// not valid UTF-8 and Canonicalize refuses it as unsupported_value. That is
// the same outcome the JavaScript and Python implementations reach, since
// their standard parsers preserve the lone surrogate for their canonicalizers
// to refuse.
func DecodeJSON(data []byte) (interface{}, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("caid: JSON text is not valid UTF-8")
	}
	d := &strictDecoder{data: data}
	d.skipWhitespace()
	value, err := d.value(0)
	if err != nil {
		return nil, err
	}
	d.skipWhitespace()
	if d.pos != len(d.data) {
		return nil, d.errorf("trailing content after the JSON value")
	}
	return value, nil
}

type strictDecoder struct {
	data []byte
	pos  int
}

func (d *strictDecoder) errorf(format string, args ...interface{}) error {
	return fmt.Errorf("caid: JSON offset %d: %s", d.pos, fmt.Sprintf(format, args...))
}

func (d *strictDecoder) skipWhitespace() {
	for d.pos < len(d.data) {
		switch d.data[d.pos] {
		case ' ', '\t', '\n', '\r':
			d.pos++
		default:
			return
		}
	}
}

func (d *strictDecoder) value(depth int) (interface{}, error) {
	if d.pos >= len(d.data) {
		return nil, d.errorf("unexpected end of input")
	}
	switch c := d.data[d.pos]; {
	case c == '{':
		return d.object(depth + 1)
	case c == '[':
		return d.array(depth + 1)
	case c == '"':
		s, err := d.string()
		return s, err
	case c == 't':
		return true, d.literal("true")
	case c == 'f':
		return false, d.literal("false")
	case c == 'n':
		return nil, d.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	default:
		return nil, d.errorf("unexpected character %q", c)
	}
}

func (d *strictDecoder) literal(word string) error {
	if len(d.data)-d.pos < len(word) || string(d.data[d.pos:d.pos+len(word)]) != word {
		return d.errorf("invalid literal")
	}
	d.pos += len(word)
	return nil
}

func (d *strictDecoder) object(depth int) (interface{}, error) {
	if depth > maxDecodeDepth {
		return nil, d.errorf("nesting deeper than %d", maxDecodeDepth)
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
			return nil, d.errorf("expected a member name")
		}
		key, err := d.string()
		if err != nil {
			return nil, err
		}
		d.skipWhitespace()
		if d.pos >= len(d.data) || d.data[d.pos] != ':' {
			return nil, d.errorf("expected ':' after a member name")
		}
		d.pos++
		d.skipWhitespace()
		member, err := d.value(depth)
		if err != nil {
			return nil, err
		}
		if _, duplicate := out[key]; duplicate {
			return nil, d.errorf("duplicate member name %q", key)
		}
		out[key] = member
		d.skipWhitespace()
		if d.pos >= len(d.data) {
			return nil, d.errorf("unterminated object")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipWhitespace()
		case '}':
			d.pos++
			return out, nil
		default:
			return nil, d.errorf("expected ',' or '}' in an object")
		}
	}
}

func (d *strictDecoder) array(depth int) (interface{}, error) {
	if depth > maxDecodeDepth {
		return nil, d.errorf("nesting deeper than %d", maxDecodeDepth)
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
			return nil, d.errorf("unterminated array")
		}
		switch d.data[d.pos] {
		case ',':
			d.pos++
			d.skipWhitespace()
		case ']':
			d.pos++
			return out, nil
		default:
			return nil, d.errorf("expected ',' or ']' in an array")
		}
	}
}

func (d *strictDecoder) hex4() (rune, bool) {
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

// appendSurrogate appends the generalized UTF-8 (WTF-8) bytes of an
// unpaired surrogate code point. utf8.AppendRune would write U+FFFD.
func appendSurrogate(buf []byte, r rune) []byte {
	return append(buf, byte(0xE0|(r>>12)), byte(0x80|((r>>6)&0x3F)), byte(0x80|(r&0x3F)))
}

func (d *strictDecoder) string() (string, error) {
	d.pos++ // opening quote
	var buf []byte
	for {
		if d.pos >= len(d.data) {
			return "", d.errorf("unterminated string")
		}
		c := d.data[d.pos]
		switch {
		case c == '"':
			d.pos++
			return string(buf), nil
		case c < 0x20:
			return "", d.errorf("unescaped control character in a string")
		case c != '\\':
			// The whole input was validated as UTF-8 up front, so
			// multi-byte sequences copy through byte by byte.
			buf = append(buf, c)
			d.pos++
			continue
		}
		d.pos++ // backslash
		if d.pos >= len(d.data) {
			return "", d.errorf("unterminated escape")
		}
		escape := d.data[d.pos]
		d.pos++
		switch escape {
		case '"', '\\', '/':
			buf = append(buf, escape)
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
				return "", d.errorf("invalid \\u escape")
			}
			switch {
			case r >= 0xD800 && r <= 0xDBFF:
				// A high surrogate combines only with an immediately
				// following low-surrogate escape. Otherwise it stays
				// unpaired and the next escape is decoded on its own,
				// as ECMAScript JSON.parse and Python json.loads do.
				if len(d.data)-d.pos >= 6 && d.data[d.pos] == '\\' && d.data[d.pos+1] == 'u' {
					save := d.pos
					d.pos += 2
					low, lowOK := d.hex4()
					if lowOK && low >= 0xDC00 && low <= 0xDFFF {
						buf = utf8.AppendRune(buf, utf16.DecodeRune(r, low))
						continue
					}
					d.pos = save
				}
				buf = appendSurrogate(buf, r)
			case r >= 0xDC00 && r <= 0xDFFF:
				buf = appendSurrogate(buf, r)
			default:
				buf = utf8.AppendRune(buf, r)
			}
		default:
			return "", d.errorf("invalid escape character %q", escape)
		}
	}
}

func (d *strictDecoder) number() (interface{}, error) {
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
		return nil, d.errorf("invalid number")
	}
	if d.data[d.pos] == '0' {
		d.pos++
	} else if digits() == 0 {
		return nil, d.errorf("invalid number")
	}
	if d.pos < len(d.data) && d.data[d.pos] == '.' {
		d.pos++
		if digits() == 0 {
			return nil, d.errorf("invalid number fraction")
		}
	}
	if d.pos < len(d.data) && (d.data[d.pos] == 'e' || d.data[d.pos] == 'E') {
		d.pos++
		if d.pos < len(d.data) && (d.data[d.pos] == '+' || d.data[d.pos] == '-') {
			d.pos++
		}
		if digits() == 0 {
			return nil, d.errorf("invalid number exponent")
		}
	}
	return json.Number(d.data[start:d.pos]), nil
}
