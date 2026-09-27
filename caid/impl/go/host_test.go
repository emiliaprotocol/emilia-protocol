package caid

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

type obj = map[string]interface{}

var stringDefinition = []interface{}{obj{
	"action_type":     "test.text.1",
	"required_fields": []interface{}{obj{"name": "c", "type": "string"}},
}}

var anyDefinition = []interface{}{obj{
	"action_type":     "test.any.1",
	"required_fields": []interface{}{obj{"name": "o", "type": "object"}},
	"optional_fields": []interface{}{obj{"name": "extra", "type": "string"}},
}}

func computeOK(t *testing.T, object interface{}, definitions []interface{}) ComputeResult {
	t.Helper()
	got := ComputeCaid(object, ComputeOptions{Suite: "jcs-sha256", Definitions: definitions})
	if got.Caid == "" {
		t.Fatalf("ComputeCaid(%#v) refused: %v", object, got.Refusals)
	}
	return got
}

func refusals(object interface{}, definitions []interface{}) []string {
	return ComputeCaid(object, ComputeOptions{Suite: "jcs-sha256", Definitions: definitions}).Refusals
}

func withTimeout(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not return within %v", d)
	}
}

func TestCyclicHostValuesAreRefusedAndTheProcessSurvives(t *testing.T) {
	cyclic := obj{"action_type": "test.any.1"}
	inner := obj{}
	inner["self"] = inner
	cyclic["o"] = inner
	withTimeout(t, 10*time.Second, func() {
		if got := refusals(cyclic, anyDefinition); !reflect.DeepEqual(got, []string{"unsupported_value"}) {
			t.Errorf("cyclic map: %v", got)
		}
		if got := Canonicalize(inner); got.OK || !reflect.DeepEqual(got.Refusals, []string{"unsupported_value"}) {
			t.Errorf("Canonicalize cyclic map: %#v", got)
		}
		loop := []interface{}{nil}
		loop[0] = loop
		if got := refusals(obj{"action_type": "test.any.1", "o": obj{}, "extra2": loop}, anyDefinition); !reflect.DeepEqual(got, []string{"unsupported_value"}) {
			t.Errorf("cyclic slice: %v", got)
		}
		top := obj{"action_type": "test.any.1", "o": obj{}}
		top["o"].(obj)["up"] = top
		v := VerifyCaid(top, "caid:1:test.any.1:jcs-sha256:"+strings.Repeat("A", 43), VerifyOptions{Definitions: anyDefinition})
		if v.Valid || !reflect.DeepEqual(v.Reasons, []string{"invalid_object"}) || v.Details[0].Reason != "unsupported_value" {
			t.Errorf("VerifyCaid cyclic: %#v", v)
		}
	})
}

func nest(depth int) interface{} {
	var v interface{} = obj{}
	for i := 1; i < depth; i++ {
		v = obj{"n": v}
	}
	return v
}

func TestHostNestingBound(t *testing.T) {
	// The action object is depth 1, so "o" may nest 63 more levels.
	computeOK(t, obj{"action_type": "test.any.1", "o": nest(63)}, anyDefinition)
	if got := refusals(obj{"action_type": "test.any.1", "o": nest(64)}, anyDefinition); !reflect.DeepEqual(got, []string{"unsupported_value"}) {
		t.Fatalf("depth 65: %v", got)
	}
	if got := Canonicalize(nest(64)); !got.OK {
		t.Fatalf("Canonicalize depth 64: %#v", got)
	}
	if got := Canonicalize(nest(65)); got.OK {
		t.Fatal("Canonicalize depth 65 accepted")
	}
	withTimeout(t, 10*time.Second, func() {
		if got := Canonicalize(nest(200000)); got.OK {
			t.Error("very deep value accepted")
		}
	})
}

func TestSharedSubvaluesAreBounded(t *testing.T) {
	// 60 levels, each holding the next twice: 2^60 paths if expanded.
	var v interface{} = "leaf"
	for i := 0; i < 60; i++ {
		v = obj{"a": v, "b": v}
	}
	withTimeout(t, 60*time.Second, func() {
		if got := refusals(obj{"action_type": "test.any.1", "o": v}, anyDefinition); !reflect.DeepEqual(got, []string{"unsupported_value"}) {
			t.Errorf("exponential DAG: %v", got)
		}
	})
	// A small DAG is an ordinary tree value: it computes like its expansion.
	shared := obj{"k": "v"}
	a := computeOK(t, obj{"action_type": "test.any.1", "o": obj{"x": shared, "y": shared}}, anyDefinition)
	b := computeOK(t, obj{"action_type": "test.any.1", "o": obj{"x": obj{"k": "v"}, "y": obj{"k": "v"}}}, anyDefinition)
	if a.Caid != b.Caid {
		t.Fatalf("shared subvalue changed the CAID: %s vs %s", a.Caid, b.Caid)
	}
}

type hostStruct struct{ A int }

func TestHostValuesOutsideTheDataModelAreRefusedNeverRewritten(t *testing.T) {
	var nilMap map[string]interface{}
	var nilSlice []interface{}
	for name, value := range map[string]interface{}{
		"map[string]string":  map[string]string{"a": "b"},
		"[]string":           []string{"a"},
		"int32":              int32(1),
		"uint64":             uint64(1),
		"float32":            float32(1),
		"struct":             hostStruct{A: 1},
		"pointer":            &hostStruct{A: 1},
		"nil map":            nilMap,
		"nil slice":          nilSlice,
		"time":               time.Unix(0, 0),
		"lone surrogate":     "\xed\xa0\x80",
		"invalid utf-8":      "\xff",
		"noncharacter":       "\uffff",
		"FDD0 noncharacter":  "a\ufdd0",
		"plane noncharacter": "\U0010FFFE",
		"func":               func() {},
		"channel":            make(chan int),
	} {
		got := refusals(obj{"action_type": "test.any.1", "o": obj{}, "extra2": value}, anyDefinition)
		if !reflect.DeepEqual(got, []string{"unsupported_value"}) {
			t.Errorf("%s in an undeclared member: %v", name, got)
		}
		got = refusals(obj{"action_type": "test.any.1", "o": value}, anyDefinition)
		if len(got) == 0 || got[len(got)-1] != "unsupported_value" {
			t.Errorf("%s in a declared object field: %v", name, got)
		}
		key := obj{"action_type": "test.any.1", "o": obj{}}
		if s, ok := value.(string); ok {
			key[s] = "x"
			if got := refusals(key, anyDefinition); !reflect.DeepEqual(got, []string{"unsupported_value"}) {
				t.Errorf("%s as a member name: %v", name, got)
			}
		}
	}
	// A declared field of the wrong host type is mistyped as well.
	if got := refusals(obj{"action_type": "test.any.1", "o": map[string]string{}}, anyDefinition); !reflect.DeepEqual(got, []string{"mistyped_field:o", "unsupported_value"}) {
		t.Fatalf("map[string]string in an object field: %v", got)
	}
	// A nil map is not an object at the top level either.
	if got := refusals(nilMap, anyDefinition); !reflect.DeepEqual(got, []string{"invalid_action_type"}) {
		t.Fatalf("nil map action object: %v", got)
	}
}

func TestHostNumbersFollowTheValueRule(t *testing.T) {
	def := []interface{}{obj{"action_type": "test.num.1", "required_fields": []interface{}{obj{"name": "n", "type": "integer"}}}}
	base := computeOK(t, obj{"action_type": "test.num.1", "n": json.Number("1000")}, def)
	for _, v := range []interface{}{
		json.Number("1e3"), json.Number("1000.0"), json.Number("1E+3"), json.Number("10000e-1"),
		float64(1000), int(1000), int64(1000),
	} {
		if got := computeOK(t, obj{"action_type": "test.num.1", "n": v}, def); got.Caid != base.Caid {
			t.Errorf("%#v: %s, want %s", v, got.Caid, base.Caid)
		}
	}
	zero := computeOK(t, obj{"action_type": "test.num.1", "n": json.Number("0")}, def)
	for _, v := range []interface{}{json.Number("-0"), json.Number("1e-400"), json.Number("-1e-400"), math.Copysign(0, -1)} {
		if got := computeOK(t, obj{"action_type": "test.num.1", "n": v}, def); got.Caid != zero.Caid {
			t.Errorf("%#v is not the integer 0", v)
		}
	}
	for _, c := range []struct {
		value interface{}
		want  []string
	}{
		{json.Number("1e400"), []string{"mistyped_field:n", "unsupported_number"}},
		{json.Number(strings.Repeat("9", 5000)), []string{"mistyped_field:n", "unsupported_number"}},
		{json.Number("9007199254740992"), []string{"unsupported_number"}},
		{json.Number("-9007199254740992"), []string{"unsupported_number"}},
		{json.Number("12.5"), []string{"mistyped_field:n", "unsupported_number"}},
		{json.Number("1_0"), []string{"mistyped_field:n", "unsupported_number"}},
		{json.Number("Inf"), []string{"mistyped_field:n", "unsupported_number"}},
		{json.Number("0x10"), []string{"mistyped_field:n", "unsupported_number"}},
		{json.Number(" 1"), []string{"mistyped_field:n", "unsupported_number"}},
		{math.NaN(), []string{"mistyped_field:n", "unsupported_number"}},
		{math.Inf(-1), []string{"mistyped_field:n", "unsupported_number"}},
		{int64(1) << 53, []string{"unsupported_number"}},
		{float64(1 << 53), []string{"unsupported_number"}},
		{"12", []string{"mistyped_field:n"}},
	} {
		if got := refusals(obj{"action_type": "test.num.1", "n": c.value}, def); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%#v: %v, want %v", c.value, got, c.want)
		}
	}
	maxSafe := computeOK(t, obj{"action_type": "test.num.1", "n": json.Number("9007199254740991")}, def)
	if got := computeOK(t, obj{"action_type": "test.num.1", "n": int64(9007199254740991)}, def); got.Caid != maxSafe.Caid {
		t.Fatal("2^53-1 differs between json.Number and int64")
	}
}

// For every value DecodeJSON produces, the host entry point returns what the
// JSON text entry point returns (draft -04 Section 2.5).
func TestNativeAndJSONTextParity(t *testing.T) {
	defs := append(append([]interface{}{}, stringDefinition...), anyDefinition...)
	texts := []string{
		`{"action_type":"test.text.1","c":"x"}`,
		`{"action_type":"test.text.1","c":1.5,"z":"\ue000"}`,
		`{"action_type":"test.text.1"}`,
		`{"action_type":"test.any.1","o":{"a":[1e3,-0,null,true]},"extra":7}`,
		`{"action_type":"test.any.1","o":[]}`,
		`{"action_type":"nope.1"}`,
		`{"action_type":"Bad"}`,
		`[1,2]`,
		`"str"`,
		`null`,
		`{"action_type":"test.any.1","o":{"n":1e400,"m":0.5}}`,
	}
	for _, text := range texts {
		value := decodeOrFail(t, text)
		for _, suite := range []string{"jcs-sha256", "cbor-sha256", ""} {
			opts := ComputeOptions{Suite: suite, Definitions: defs}
			if a, b := ComputeCaid(value, opts), ComputeCaidJSON([]byte(text), opts); !reflect.DeepEqual(a, b) {
				t.Errorf("%s: native %#v, text %#v", text, a, b)
			}
		}
		for _, c := range []string{"caid:1:test.text.1:jcs-sha256:" + strings.Repeat("A", 43), "caid:1:test.any.1:cbor-sha256:" + strings.Repeat("A", 43), "nope"} {
			opts := VerifyOptions{Definitions: defs}
			if a, b := VerifyCaid(value, c, opts), VerifyCaidJSON([]byte(text), c, opts); !reflect.DeepEqual(a, b) {
				t.Errorf("%s / %s: native %#v, text %#v", text, c, a, b)
			}
		}
	}
}
