package caid

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func decodeOrFail(t *testing.T, text string) interface{} {
	t.Helper()
	value, err := DecodeJSON([]byte(text))
	if err != nil {
		t.Fatalf("DecodeJSON(%q): %v", text, err)
	}
	return value
}

func TestDecodeJSONValueModel(t *testing.T) {
	got := decodeOrFail(t, ` {"a":[1,-2,3.5e2,0,true,false,null,{"b":"é🚀\n\t\"\\\/\u0041\ud83d\ude00"}],"c":{}, "d":[]} `)
	want := map[string]interface{}{
		"a": []interface{}{
			json.Number("1"), json.Number("-2"), json.Number("3.5e2"), json.Number("0"), true, false, nil,
			map[string]interface{}{"b": "é🚀\n\t\"\\/A😀"},
		},
		"c": map[string]interface{}{},
		"d": []interface{}{},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeJSON = %#v, want %#v", got, want)
	}
}

func TestDecodeJSONRefusalsAreTypedMalformedJSON(t *testing.T) {
	deep := strings.Repeat("[", 65) + strings.Repeat("]", 65)
	for name, text := range map[string]string{
		"empty":                      "",
		"whitespace only":            " \n",
		"unterminated object":        "{",
		"member without value":       `{"a"}`,
		"trailing comma":             `{"a":1,}`,
		"array trailing comma":       `[1,]`,
		"leading zero":               `01`,
		"bare fraction dot":          `1.`,
		"bare exponent":              `1e`,
		"lone minus":                 `-`,
		"bad literal":                `tru`,
		"control in string":          "\"\x01\"",
		"short unicode escape":       `"\u12"`,
		"unknown escape":             `"\q"`,
		"two texts":                  `{} {}`,
		"byte order mark":            "\xef\xbb\xbf{}",
		"invalid utf-8":              "\"\xff\"",
		"overlong utf-8":             "\"\xc0\xaf\"",
		"utf-16le":                   "{\x00}\x00",
		"encoded surrogate":          "\"\xed\xa0\x80\"",
		"NaN":                        `NaN`,
		"Infinity":                   `[Infinity]`,
		"plus sign":                  `+1`,
		"duplicate names":            `{"a":1,"a":2}`,
		"duplicate escaped name":     `{"a":1,"\u0061":2}`,
		"nested duplicate":           `{"outer":{"x":1,"x":1}}`,
		"lone high surrogate":        `"\ud800"`,
		"high then other escape":     `"\ud800\u0041"`,
		"high then literal":          `"\ud800A"`,
		"lone low surrogate":         `"x\udc00y"`,
		"surrogate member name":      `{"\ud800":1}`,
		"escaped noncharacter":       `"\uffff"`,
		"escaped FDD0":               `"\ufdd0"`,
		"escaped plane noncharacter": `"\ud83f\udffe"`,
		"literal noncharacter":       "\"\xef\xbf\xbf\"",
		"literal FDEF":               "\"\xef\xb7\xaf\"",
		"literal plane-16 U+10FFFF":  "\"\xf4\x8f\xbf\xbf\"",
		"noncharacter member name":   "{\"\xef\xbf\xbe\":1}",
		"nesting 65":                 deep,
		"vertical tab whitespace":    "\v{}",
		"nbsp whitespace":            " {}",
	} {
		_, err := DecodeJSON([]byte(text))
		var de *DecodeError
		if err == nil || !errors.As(err, &de) || de.Reason() != "malformed_json" {
			t.Errorf("%s: DecodeJSON(%q) error = %v, want a *DecodeError with reason malformed_json", name, text, err)
		}
		if got := DecodeCaidJSON([]byte(text)); got.OK || !reflect.DeepEqual(got.Refusals, []string{"malformed_json"}) {
			t.Errorf("%s: DecodeCaidJSON = %#v", name, got)
		}
	}
}

func TestDecodeJSONNestingBound(t *testing.T) {
	ok64 := strings.Repeat(`{"a":`, 63) + "[]" + strings.Repeat("}", 63)
	if _, err := DecodeJSON([]byte(ok64)); err != nil {
		t.Fatalf("depth 64 refused: %v", err)
	}
	if _, err := DecodeJSON([]byte(strings.Repeat("[", 64) + strings.Repeat("]", 64))); err != nil {
		t.Fatalf("depth 64 arrays refused: %v", err)
	}
	bad65 := strings.Repeat(`{"a":`, 64) + "[]" + strings.Repeat("}", 64)
	if _, err := DecodeJSON([]byte(bad65)); err == nil {
		t.Fatal("depth 65 accepted")
	}
	// A million levels are refused at level 65 without deep recursion.
	if _, err := DecodeJSON([]byte(strings.Repeat("[", 1000000))); err == nil {
		t.Fatal("deep text accepted")
	}
}

func TestDecodeJSONSizeLimitAppliesToActionObjectsOnly(t *testing.T) {
	// {"s":"xxx...x"} of exactly the limit, then one octet more.
	fill := specLimitJsonTextOctets - len(`{"s":""}`)
	exact := []byte(`{"s":"` + strings.Repeat("x", fill) + `"}`)
	if len(exact) != specLimitJsonTextOctets {
		t.Fatalf("test construction: %d octets", len(exact))
	}
	if _, err := DecodeJSON(exact); err != nil {
		t.Fatalf("text of exactly the limit refused: %v", err)
	}
	over := append([]byte(" "), exact...)
	if _, err := DecodeJSON(over); err == nil {
		t.Fatal("text one octet over the limit accepted")
	}
	if _, err := DecodeDocumentJSON(over); err != nil {
		t.Fatalf("DecodeDocumentJSON applied the action-object size limit: %v", err)
	}
	if got := ComputeCaidJSON(over, ComputeOptions{Suite: "jcs-sha256"}); !reflect.DeepEqual(got.Refusals, []string{"malformed_json"}) {
		t.Fatalf("ComputeCaidJSON over the limit = %#v", got.Refusals)
	}
}

func TestDecodeJSONAcceptsScalarsNumbersAndValidPairs(t *testing.T) {
	for _, text := range []string{
		`0`, `-0`, `1e-400`, `1E+400`, `12.5`, `"\ud83d\ude00"`, `"\uFFFD"`, `"\ufeff"`, `"\u0000"`,
		`null`, `true`, "\t[ ]\r\n", `"` + strings.Repeat("1", 5000) + `"`, strings.Repeat("9", 5000),
	} {
		if _, err := DecodeJSON([]byte(text)); err != nil {
			t.Errorf("DecodeJSON(%q) refused: %v", text, err)
		}
	}
	got := decodeOrFail(t, `[1e400, 1e-400, -0, 0.5]`)
	want := []interface{}{json.Number("1e400"), json.Number("1e-400"), json.Number("-0"), json.Number("0.5")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("number tokens were not kept exactly: %#v", got)
	}
}

func TestJSONTextEntryPointsGateOnMalformedJSON(t *testing.T) {
	defs := stringDefinition
	caidString := computeOK(t, map[string]interface{}{"action_type": "test.text.1", "c": "x"}, defs).Caid
	got := VerifyCaidJSON([]byte(`{"action_type":"test.text.1","c":"x","c":"y"}`), caidString, VerifyOptions{Definitions: defs})
	want := VerifyResult{Valid: false, Reasons: []string{"malformed_json"}, Details: []VerifyDetail{{Reason: "malformed_json", Rule: "json-text"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("VerifyCaidJSON duplicate = %#v", got)
	}
	// Parsing the CAID comes before decoding the text.
	got = VerifyCaidJSON([]byte(`{`), "canactid:1:test.text.1:jcs-sha256:!", VerifyOptions{Definitions: defs})
	if !reflect.DeepEqual(got.Reasons, []string{"malformed_caid"}) {
		t.Fatalf("VerifyCaidJSON parse gate = %#v", got)
	}
	ok := VerifyCaidJSON([]byte(`{"c":"x","action_type":"test.text.1"}`), caidString, VerifyOptions{Definitions: defs})
	if !ok.Valid || len(ok.Details) != 0 || ok.DefinitionSha256 == "" {
		t.Fatalf("VerifyCaidJSON valid = %#v", ok)
	}
	for _, text := range []string{`{"action_type":"test.text.1","c":"\ud800"}`, "\xef\xbb\xbf{}"} {
		if got := ComputeCaidJSON([]byte(text), ComputeOptions{Suite: "jcs-sha256", Definitions: defs}); !reflect.DeepEqual(got, ComputeResult{Refusals: []string{"malformed_json"}}) {
			t.Fatalf("ComputeCaidJSON(%q) = %#v", text, got)
		}
	}
}
