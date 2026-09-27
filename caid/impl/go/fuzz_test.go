package caid

import (
	"reflect"
	"testing"
)

var fuzzDefinitions = append(append(append([]interface{}{}, stringDefinition...), anyDefinition...), orderDefinition...)

// FuzzJSONTextEntryPoints: no input panics, every decode failure is exactly
// malformed_json, and the host entry points agree with the JSON text entry
// points on every decoded value. `go test` runs the seeds; `go test -fuzz`
// explores.
func FuzzJSONTextEntryPoints(f *testing.F) {
	for _, seed := range []string{
		`{"action_type":"test.text.1","c":"x"}`,
		`{"action_type":"test.order.1","a":"01","b":1,"c":1.5,"d":"sha256:x","e":"A01.1"}`,
		`{"action_type":"test.any.1","o":{"a":[1e400,-0,{"😀":null}]}}`,
		`{"action_type":"test.text.1","c":"\ud800"}`,
		"\xef\xbb\xbf{}", `[[[[[[[[]]]]]]]]`, `{"a":1,"a":2}`, `"￿"`, `1e-400`,
	} {
		f.Add([]byte(seed), "jcs-sha256")
	}
	f.Fuzz(func(t *testing.T, data []byte, suite string) {
		opts := ComputeOptions{Suite: suite, Definitions: fuzzDefinitions}
		got := ComputeCaidJSON(data, opts)
		value, err := DecodeJSON(data)
		if err != nil {
			if !reflect.DeepEqual(got, ComputeResult{Refusals: []string{"malformed_json"}}) {
				t.Fatalf("refused text: %#v", got)
			}
			return
		}
		if native := ComputeCaid(value, opts); !reflect.DeepEqual(native, got) {
			t.Fatalf("parity: native %#v, text %#v", native, got)
		}
		caidString := got.Caid
		if caidString == "" {
			caidString = "caid:1:test.text.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"
		}
		vopts := VerifyOptions{Definitions: fuzzDefinitions}
		v := VerifyCaidJSON(data, caidString, vopts)
		if native := VerifyCaid(value, caidString, vopts); !reflect.DeepEqual(native, v) {
			t.Fatalf("verify parity: native %#v, text %#v", native, v)
		}
		if got.Caid != "" && !v.Valid {
			t.Fatalf("a computed CAID does not verify: %#v", v)
		}
		MapAction(value, MapActionOptions{Profile: value, SourceDescriptor: value, Definitions: fuzzDefinitions})
		DefinitionSha256(value)
		Canonicalize(value)
	})
}
