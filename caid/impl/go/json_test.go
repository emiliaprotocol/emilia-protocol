package caid

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

var stringDefinition = []interface{}{map[string]interface{}{
	"action_type":     "test.text.1",
	"required_fields": []interface{}{map[string]interface{}{"name": "c", "type": "string"}},
}}

func decodeOrFail(t *testing.T, text string) interface{} {
	t.Helper()
	value, err := DecodeJSON([]byte(text))
	if err != nil {
		t.Fatalf("DecodeJSON(%q): %v", text, err)
	}
	return value
}

func TestDecodeJSONMatchesEncodingJSONOnOrdinaryInput(t *testing.T) {
	text := `{"a":[1,-2,3.5e2,0,true,false,null,{"b":"é🚀\n\t\"\\\/"}],"c":{}, "d":[]}`
	got := decodeOrFail(t, text)
	var want interface{}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	if err := decoder.Decode(&want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeJSON = %#v, encoding/json = %#v", got, want)
	}
}

func TestDecodeJSONRefusesDuplicateMemberNames(t *testing.T) {
	for _, text := range []string{
		`{"currency":"ZZZ","currency":"USD"}`,
		`{"a":1,"a":2}`,
		`{"outer":{"x":1,"x":1}}`,
	} {
		if _, err := DecodeJSON([]byte(text)); err == nil || !strings.Contains(err.Error(), "duplicate member name") {
			t.Fatalf("DecodeJSON(%q) error = %v, want duplicate member name", text, err)
		}
	}
}

func TestDecodeJSONRefusesMalformedText(t *testing.T) {
	for _, text := range []string{
		"", "{", `{"a"}`, `{"a":1,}`, `[1,]`, `01`, `1.`, `1e`, `-`, `tru`, `"\x01"`,
		`"\u12"`, `"\q"`, `{} {}`, "\xef\xbb\xbf{}", "\"\xff\"", `nul`,
	} {
		if _, err := DecodeJSON([]byte(text)); err == nil {
			t.Fatalf("DecodeJSON(%q) accepted malformed input", text)
		}
	}
}

func TestDecodeJSONKeepsUnpairedSurrogatesForTheCanonicalizerToRefuse(t *testing.T) {
	for _, text := range []string{
		`{"action_type":"test.text.1","c":"\ud800"}`,
		`{"action_type":"test.text.1","c":"x\udc00y"}`,
		`{"action_type":"test.text.1","c":"\ud800A"}`,
		`{"action_type":"test.text.1","c":"ok","\ud800":1}`,
	} {
		object := decodeOrFail(t, text)
		got := ComputeCaid(object, ComputeOptions{Suite: "jcs-sha256", Definitions: stringDefinition})
		if got.Caid != "" || !reflect.DeepEqual(got.Refusals, []string{"unsupported_value"}) {
			t.Fatalf("%s: ComputeCaid = %#v, want refusal unsupported_value", text, got)
		}
	}
	// U+FFFD itself is an ordinary scalar value and still computes, so the
	// lone surrogate and U+FFFD can no longer collide on one CAID.
	replacement := decodeOrFail(t, `{"action_type":"test.text.1","c":"�"}`)
	if got := ComputeCaid(replacement, ComputeOptions{Suite: "jcs-sha256", Definitions: stringDefinition}); got.Caid == "" {
		t.Fatalf("U+FFFD refused: %#v", got)
	}
}

func TestCanonicalizeRefusesInvalidUTF8GoStrings(t *testing.T) {
	for _, value := range []interface{}{
		"\xff",
		map[string]interface{}{"\xed\xa0\x80": "x"},
		[]interface{}{"ok", "\xc3"},
	} {
		got := Canonicalize(value)
		if got.OK || !reflect.DeepEqual(got.Refusals, []string{"unsupported_value"}) {
			t.Fatalf("Canonicalize(%q) = %#v, want unsupported_value", value, got)
		}
	}
}
