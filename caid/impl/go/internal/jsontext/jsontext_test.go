package jsontext

import (
	"strings"
	"testing"
)

func TestHostProfileKeepsWhatTheStrictProfileRefuses(t *testing.T) {
	strict := Options{MaxDepth: 64}
	host := Options{MaxDepth: 1 << 16, Host: true}
	for _, c := range []struct {
		text string
		want string
	}{
		{`"\ud800"`, "\xed\xa0\x80"},
		{`"x\udc00y"`, "x\xed\xb0\x80y"},
		{`"\ud800A"`, "\xed\xa0\x80A"},
		{`"\uffff"`, "\uffff"},
		{`"\ud83d\ude00"`, "\U0001F600"},
	} {
		v, err := Decode([]byte(c.text), host)
		if err != nil || v != c.want {
			t.Errorf("host %s = %q, %v; want %q", c.text, v, err, c.want)
		}
		if _, err := Decode([]byte(c.text), strict); (err == nil) != (c.text == `"\ud83d\ude00"`) {
			t.Errorf("strict %s: %v", c.text, err)
		}
	}
	deep := strings.Repeat("[", 1000) + strings.Repeat("]", 1000)
	if _, err := Decode([]byte(deep), host); err != nil {
		t.Errorf("host depth 1000: %v", err)
	}
	if _, err := Decode([]byte(deep), strict); err == nil {
		t.Error("strict depth 1000 accepted")
	}
	// Both profiles refuse duplicates, invalid UTF-8 and a byte order mark.
	for _, text := range []string{`{"a":1,"a":2}`, "\"\xff\"", "\xef\xbb\xbf1"} {
		if _, err := Decode([]byte(text), host); err == nil {
			t.Errorf("host accepted %q", text)
		}
	}
	if _, err := Decode([]byte("1"), Options{}); err == nil {
		t.Error("MaxDepth 0 accepted")
	}
	if _, err := Decode([]byte("[1]"), Options{MaxDepth: 1, MaxOctets: 2}); err == nil || err.Offset != -1 {
		t.Errorf("size limit: %v", err)
	}
}

func TestIsNumberToken(t *testing.T) {
	for _, s := range []string{"0", "-0", "12", "1.5", "1e5", "1E+5", "-1.5e-5", strings.Repeat("9", 400)} {
		if !IsNumberToken(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", "-", "01", "1.", ".5", "1e", "+1", "Inf", "NaN", "0x10", "1_0", " 1", "1 ", "1e+"} {
		if IsNumberToken(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestIsNoncharacter(t *testing.T) {
	for _, r := range []rune{0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF} {
		if !IsNoncharacter(r) {
			t.Errorf("U+%04X", r)
		}
	}
	for _, r := range []rune{0xFDCF, 0xFDF0, 0xFFFD, 0xFEFF, 0x1FFFD, 'a'} {
		if IsNoncharacter(r) {
			t.Errorf("U+%04X", r)
		}
	}
}
