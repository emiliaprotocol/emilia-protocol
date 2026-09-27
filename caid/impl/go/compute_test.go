package caid

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

var orderDefinition = []interface{}{obj{
	"action_type": "test.order.1",
	"required_fields": []interface{}{
		obj{"name": "a", "type": "amount-string"},
		obj{"name": "b", "type": "string"},
		obj{"name": "c", "type": "integer"},
	},
	"optional_fields": []interface{}{
		obj{"name": "d", "type": "digest"},
		obj{"name": "e", "type": "code", "code_system": "http://hl7.org/fhir/sid/icd-10-cm", "format": "icd-10-cm"},
	},
}}

func TestReasonOrderIsRankThenFieldPosition(t *testing.T) {
	// Every non-gate phase at once, presented in an order unlike the result.
	object := obj{
		"action_type":  "test.order.1",
		"zz":           json.Number("1.5"),
		"\xed\xa0\x80": "lone surrogate key",
		"e":            "a00",
		"d":            "sha256:XYZ",
		"a":            "01",
	}
	got := ComputeCaid(object, ComputeOptions{Suite: "sha512", Definitions: orderDefinition})
	want := []string{
		"missing_material_field:b", "missing_material_field:c",
		"invalid_amount:a", "mistyped_field:d", "invalid_code:e",
		"unknown_suite", "unsupported_number", "unsupported_value",
	}
	if !reflect.DeepEqual(got.Refusals, want) {
		t.Fatalf("refusals = %v, want %v", got.Refusals, want)
	}
	// D1: a lone-surrogate key beside a U+E000 key holding 1.5.
	d1 := obj{"action_type": "test.text.1", "c": "x", "\xed\xa0\x80": "v", "\ue000": json.Number("1.5")}
	if got := refusals(d1, stringDefinition); !reflect.DeepEqual(got, []string{"unsupported_number", "unsupported_value"}) {
		t.Fatalf("D1 order = %v", got)
	}
}

func TestGatesYieldExactlyOneReason(t *testing.T) {
	bad := obj{"action_type": "test.order.1", "zz": json.Number("1.5")}
	for name, c := range map[string]struct {
		object interface{}
		defs   []interface{}
		want   string
	}{
		"not an object":       {[]interface{}{1}, orderDefinition, "invalid_action_type"},
		"action_type absent":  {obj{"zz": json.Number("1.5")}, orderDefinition, "invalid_action_type"},
		"action_type number":  {obj{"action_type": json.Number("1")}, orderDefinition, "invalid_action_type"},
		"action_type grammar": {obj{"action_type": "Test.order.1"}, orderDefinition, "invalid_action_type"},
		"trailing newline":    {obj{"action_type": "test.order.1\n"}, orderDefinition, "invalid_action_type"},
		"unknown type":        {bad, stringDefinition, "unknown_action_type"},
		"no definitions":      {bad, nil, "unknown_action_type"},
		"invalid definition":  {bad, []interface{}{obj{"action_type": "test.order.1", "required_fields": "a"}}, "invalid_definition"},
	} {
		got := ComputeCaid(c.object, ComputeOptions{Suite: "nope", Definitions: c.defs})
		if !reflect.DeepEqual(got.Refusals, []string{c.want}) {
			t.Errorf("%s: %v, want [%s]", name, got.Refusals, c.want)
		}
	}
}

func TestMalformedDefinitionsAreInvalidDefinition(t *testing.T) {
	field := func(name string) obj { return obj{"name": name, "type": "string"} }
	object := obj{"action_type": "test.def.1", "amount": "1"}
	for name, def := range map[string]obj{
		"required_fields absent":    {"action_type": "test.def.1"},
		"required_fields a string":  {"action_type": "test.def.1", "required_fields": "amount"},
		"required_fields strings":   {"action_type": "test.def.1", "required_fields": []interface{}{"amount"}},
		"required_fields empty":     {"action_type": "test.def.1", "required_fields": []interface{}{}},
		"required_fields null":      {"action_type": "test.def.1", "required_fields": nil},
		"name typo":                 {"action_type": "test.def.1", "required_fields": []interface{}{obj{"nmae": "amount", "type": "string"}}},
		"numeric name":              {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": json.Number("1"), "type": "string"}}},
		"empty name":                {"action_type": "test.def.1", "required_fields": []interface{}{field("")}},
		"name with colon":           {"action_type": "test.def.1", "required_fields": []interface{}{field("a:b")}},
		"name action_type":          {"action_type": "test.def.1", "required_fields": []interface{}{field("action_type")}},
		"lone surrogate name":       {"action_type": "test.def.1", "required_fields": []interface{}{field("\xed\xa0\x80")}},
		"repeated name":             {"action_type": "test.def.1", "required_fields": []interface{}{field("amount")}, "optional_fields": []interface{}{field("amount")}},
		"type missing":              {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount"}}},
		"type not a string":         {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount", "type": json.Number("1")}}},
		"optional_fields null":      {"action_type": "test.def.1", "required_fields": []interface{}{field("amount")}, "optional_fields": nil},
		"optional_fields object":    {"action_type": "test.def.1", "required_fields": []interface{}{field("amount")}, "optional_fields": obj{}},
		"member outside the type":   {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount", "type": "string", "pattern": "x"}}},
		"enum member on string":     {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount", "type": "string", "values": []interface{}{"1"}}}},
		"code without code_system":  {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount", "type": "code", "format": "ndc-11"}}},
		"code with bad code_system": {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount", "type": "code", "code_system": "icd10", "format": "ndc-11"}}},
		"code with bad format name": {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount", "type": "code", "code_system": "urn:x:y", "format": "NDC_11"}}},
		"float in projection":       {"action_type": "test.def.1", "required_fields": []interface{}{obj{"name": "amount", "type": "enum", "values": []interface{}{"1"}, "values_ref": json.Number("1.5")}}},
	} {
		if got := refusals(object, []interface{}{def}); !reflect.DeepEqual(got, []string{"invalid_definition"}) {
			t.Errorf("%s: %v", name, got)
		}
		if got := DefinitionSha256(def); !reflect.DeepEqual(got.Refusals, []string{"invalid_definition"}) {
			t.Errorf("%s: DefinitionSha256 = %#v", name, got)
		}
	}
}

func TestDefinitionResolution(t *testing.T) {
	def := func(status, notes string, fieldType string) obj {
		return obj{
			"action_type": "test.res.1", "status": status, "summary": notes,
			"required_fields": []interface{}{obj{"name": "f", "type": fieldType, "notes": notes}},
		}
	}
	object := obj{"action_type": "test.res.1", "f": "x"}
	// Definitions that differ only outside the projection count once.
	a := computeOK(t, object, []interface{}{def("active", "one", "string"), def("deprecated", "two", "string")})
	b := computeOK(t, object, []interface{}{def("deprecated", "two", "string"), def("active", "one", "string")})
	if !reflect.DeepEqual(a, b) || a.DefinitionSha256 != DefinitionSha256(def("x", "y", "string")).DefinitionSha256 {
		t.Fatalf("equal projections resolved differently: %#v %#v", a, b)
	}
	// Conflicting definitions are refused whatever their order.
	for _, defs := range [][]interface{}{
		{def("active", "", "string"), def("active", "", "digest")},
		{def("active", "", "digest"), def("active", "", "string")},
		{def("active", "", "string"), obj{"action_type": "test.res.1", "required_fields": "broken"}},
	} {
		if got := refusals(object, defs); !reflect.DeepEqual(got, []string{"invalid_definition"}) {
			t.Errorf("conflict %v: %v", defs, got)
		}
	}
	// Status never affects computation: a deprecated type computes.
	computeOK(t, object, []interface{}{def("deprecated", "", "string")})
	// Non-object entries and other types are ignored.
	computeOK(t, object, []interface{}{"junk", nil, json.Number("1"), def("active", "", "string"), stringDefinition[0]})
}

func TestUnregisteredFieldTypesRefuseOnlyWhenPresent(t *testing.T) {
	defs := []interface{}{obj{
		"action_type":     "test.future.1",
		"required_fields": []interface{}{obj{"name": "a", "type": "string"}},
		"optional_fields": []interface{}{obj{"name": "g", "type": "geo-point", "precision": json.Number("7")}},
	}}
	computeOK(t, obj{"action_type": "test.future.1", "a": "x"}, defs)
	if got := refusals(obj{"action_type": "test.future.1", "a": "x", "g": "1,2"}, defs); !reflect.DeepEqual(got, []string{"mistyped_field:g"}) {
		t.Fatalf("present unregistered type: %v", got)
	}
}

func TestFieldNamesBeyondSnakeCase(t *testing.T) {
	defs := []interface{}{obj{
		"action_type":     "test.names.1",
		"required_fields": []interface{}{obj{"name": "@version", "type": "string"}, obj{"name": "café", "type": "string"}, obj{"name": "__proto__", "type": "string"}},
	}}
	computeOK(t, obj{"action_type": "test.names.1", "@version": "1", "café": "x", "__proto__": "y"}, defs)
	if got := refusals(obj{"action_type": "test.names.1", "@version": "1"}, defs); !reflect.DeepEqual(got, []string{"missing_material_field:café", "missing_material_field:__proto__"}) {
		t.Fatalf("missing names: %v", got)
	}
}

func TestCodeFieldType(t *testing.T) {
	base := func(v interface{}) obj {
		o := obj{"action_type": "test.order.1", "a": "1.00", "b": "x", "c": json.Number("1")}
		if v != nil {
			o["e"] = v
		}
		return o
	}
	computeOK(t, base("A01"), orderDefinition)
	computeOK(t, base("A01.1234"), orderDefinition)
	computeOK(t, base("A1B.X"), orderDefinition)
	for _, bad := range []string{"a01", "A01.", "A01.12345", "A0", " A01", "A01\n", "", "A01.1-", "Ａ01"} {
		if got := refusals(base(bad), orderDefinition); !reflect.DeepEqual(got, []string{"invalid_code:e"}) {
			t.Errorf("%q: %v", bad, got)
		}
	}
	if got := refusals(base(json.Number("1")), orderDefinition); !reflect.DeepEqual(got, []string{"mistyped_field:e"}) {
		t.Errorf("number in a code field: %v", got)
	}
	unregistered := []interface{}{obj{
		"action_type":     "test.order.1",
		"required_fields": []interface{}{obj{"name": "e", "type": "code", "code_system": "http://example.test/codes", "format": "not-registered"}},
	}}
	if got := refusals(obj{"action_type": "test.order.1", "e": "A01"}, unregistered); !reflect.DeepEqual(got, []string{"mistyped_field:e"}) {
		t.Errorf("unregistered format: %v", got)
	}
	// Code values are never normalized: case and spacing change the CAID or refuse.
	for format, good := range map[string]string{
		"icd-10-cm": "Z99.89", "ndc-11": "00002143380", "ndc-10-hyphenated": "0002-1433-80", "cpt": "99213",
		"hcpcs-level-ii": "J1234", "hcpcs": "0001U", "iso-3166-1-alpha-2": "US", "iso-3166-2": "US-CA",
		"iso20022-external-code": "AC01", "nacha-sec": "PPD",
	} {
		defs := []interface{}{obj{
			"action_type":     "test.code.1",
			"required_fields": []interface{}{obj{"name": "v", "type": "code", "code_system": "urn:example:codes", "format": format}},
		}}
		computeOK(t, obj{"action_type": "test.code.1", "v": good}, defs)
		if got := refusals(obj{"action_type": "test.code.1", "v": strings.ToLower(good) + "\n"}, defs); !reflect.DeepEqual(got, []string{"invalid_code:v"}) {
			t.Errorf("%s lowercase: %v", format, got)
		}
	}
}

func TestDefinitionSha256InResultsAndPins(t *testing.T) {
	object := obj{"action_type": "test.text.1", "c": "x"}
	got := computeOK(t, object, stringDefinition)
	digest := DefinitionSha256(stringDefinition[0])
	if digest.DefinitionSha256 == "" || got.DefinitionSha256 != digest.DefinitionSha256 {
		t.Fatalf("compute definition_sha256 %q, DefinitionSha256 %#v", got.DefinitionSha256, digest)
	}
	// The digest is over {action_type, required_fields, optional_fields: []}
	// with notes dropped: adding [] or a note does not change it.
	same := obj{"action_type": "test.text.1", "status": "deprecated", "optional_fields": []interface{}{},
		"required_fields": []interface{}{obj{"name": "c", "type": "string", "notes": "free text"}}}
	if DefinitionSha256(same).DefinitionSha256 != digest.DefinitionSha256 {
		t.Fatal("notes, status or an empty optional_fields changed definition_sha256")
	}
	want := "sha256:" + sha256Hex(`{"action_type":"test.text.1","optional_fields":[],"required_fields":[{"name":"c","type":"string"}]}`)
	if digest.DefinitionSha256 != want {
		t.Fatalf("definition_sha256 %s, want %s", digest.DefinitionSha256, want)
	}
	pin := digest.DefinitionSha256
	other := "sha256:" + strings.Repeat("0", 64)
	empty := ""
	if v := VerifyCaid(object, got.Caid, VerifyOptions{Definitions: stringDefinition, ExpectedDefinitionSha256: &pin}); !v.Valid || v.DefinitionSha256 != pin {
		t.Fatalf("matching pin: %#v", v)
	}
	for _, p := range []*string{&other, &empty} {
		v := VerifyCaid(object, got.Caid, VerifyOptions{Definitions: stringDefinition, ExpectedDefinitionSha256: p})
		want := VerifyResult{Valid: false, Reasons: []string{"definition_mismatch"}, DefinitionSha256: pin,
			Details: []VerifyDetail{{Reason: "definition_mismatch", Rule: "definition-sha256"}}}
		if !reflect.DeepEqual(v, want) {
			t.Fatalf("pin %q: %#v", *p, v)
		}
	}
	// No definition resolved: no definition_mismatch, and no digest reported.
	v := VerifyCaid(object, got.Caid, VerifyOptions{ExpectedDefinitionSha256: &other})
	if !reflect.DeepEqual(v.Reasons, []string{"invalid_object"}) || v.DefinitionSha256 != "" {
		t.Fatalf("unresolved with pin: %#v", v)
	}
}

func TestParseCaid(t *testing.T) {
	d := strings.Repeat("A", 42) + "E"
	for input, want := range map[string]string{
		"caid:1:a.b.1:jcs-sha256:" + d:                             "",
		"caid:1:a.b.1:cbor-sha256:" + d:                            "",
		"caid:1:a.b.1:jcs-sha512:" + d:                             "unknown_suite",
		"caid:1:a.b.1:foo:x":                                       "unknown_suite",
		"caid:1:a.b.1:jcs-sha256:" + strings.Repeat("A", 42) + "B": "malformed_caid",
		"caid:1:a.b.1:jcs-sha256:" + d + "=":                       "malformed_caid",
		"caid:1:a.b.1:jcs-sha256:" + d[:42]:                        "malformed_caid",
		"CAID:1:a.b.1:jcs-sha256:" + d:                             "malformed_caid",
		"caid:2:a.b.1:jcs-sha256:" + d:                             "malformed_caid",
		"caid:1:a.b.01:jcs-sha256:" + d:                            "malformed_caid",
		"caid:1:a.b.1:JCS-sha256:" + d:                             "malformed_caid",
		"caid:1:a.b.1:1x:" + d:                                     "malformed_caid",
		"caid:1:a.b.1:jcs-sha256:" + d + "\n":                      "malformed_caid",
		" caid:1:a.b.1:jcs-sha256:" + d:                            "malformed_caid",
		"caid:1:a.b.1:jcs-sha256:" + d + ":x":                      "malformed_caid",
		"caid:1:a.b.1:jcs-sha256:" + d[:41] + "\xed\xa0\x80":       "malformed_caid",
	} {
		got := ParseCaid(input)
		if want == "" {
			if !got.OK || got.Caid.Digest != d {
				t.Errorf("%q: %#v", input, got)
			}
			continue
		}
		if got.OK || !reflect.DeepEqual(got.Refusals, []string{want}) {
			t.Errorf("%q: %#v, want [%s]", input, got, want)
		}
	}
}

func TestVerifyReasonsAndDetails(t *testing.T) {
	object := obj{"action_type": "test.text.1", "c": "x"}
	good := computeOK(t, object, stringDefinition)
	opts := VerifyOptions{Definitions: stringDefinition}
	str := func(s string) *string { return &s }

	// malformed_caid observes the CAID argument.
	v := VerifyCaid(object, "caid:1:x", opts)
	if !reflect.DeepEqual(v, VerifyResult{Reasons: []string{"malformed_caid"}, Details: []VerifyDetail{{Reason: "malformed_caid", Rule: "caid", Observed: str("string")}}}) {
		t.Fatalf("malformed: %#v", v)
	}
	// Unregistered suite: unknown_suite from parsing.
	v = VerifyCaid(object, "caid:1:test.text.1:jcs-sha512:"+strings.Repeat("A", 43), opts)
	if !reflect.DeepEqual(v, VerifyResult{Reasons: []string{"unknown_suite"}, Details: []VerifyDetail{{Reason: "unknown_suite", Rule: "suite"}}}) {
		t.Fatalf("unregistered suite: %#v", v)
	}
	// A value that is not an object: invalid_object, detailed by the
	// computation's own gate reason.
	v = VerifyCaid([]interface{}{}, good.Caid, opts)
	if !reflect.DeepEqual(v, VerifyResult{Reasons: []string{"invalid_object"}, Details: []VerifyDetail{{Reason: "invalid_action_type", Field: str("action_type"), Rule: "action-type", Observed: str("array")}}}) {
		t.Fatalf("non-object: %#v", v)
	}
	// Registered but not implemented: unknown_suite after the mismatch.
	v = VerifyCaid(obj{"action_type": "test.other.1", "c": "x"}, strings.Replace(good.Caid, "jcs-sha256", "cbor-sha256", 1), opts)
	if !reflect.DeepEqual(v.Reasons, []string{"action_type_mismatch", "unknown_suite", "invalid_object"}) {
		t.Fatalf("cbor: %#v", v)
	}
	if v.Details[0] != (VerifyDetail{Reason: "action_type_mismatch", Field: v.Details[0].Field, Rule: "action-type-equal", Observed: v.Details[0].Observed}) ||
		*v.Details[0].Field != "action_type" || *v.Details[0].Observed != "string" || v.Details[2].Reason != "unknown_action_type" {
		t.Fatalf("cbor details: %#v", v.Details)
	}
	// Every reason at once: mismatch, digest, and the compute reasons in
	// compute order with their observed kinds.
	bad := obj{"action_type": "test.text.1", "c": json.Number("1"), "n": json.Number("0.5")}
	v = VerifyCaid(bad, good.Caid, opts)
	wantDetails := []VerifyDetail{
		{Reason: "mistyped_field:c", Field: str("c"), Rule: "field-type", Observed: str("number")},
		{Reason: "unsupported_number", Rule: "number"},
	}
	if v.Valid || !reflect.DeepEqual(v.Reasons, []string{"invalid_object"}) || !reflect.DeepEqual(v.Details, wantDetails) || v.DefinitionSha256 != good.DefinitionSha256 {
		t.Fatalf("invalid object: %#v", v)
	}
	missing := VerifyCaid(obj{"action_type": "test.text.1"}, good.Caid, opts)
	if !reflect.DeepEqual(missing.Reasons, []string{"digest_mismatch", "invalid_object"}) ||
		!reflect.DeepEqual(missing.Details, []VerifyDetail{{Reason: "digest_mismatch", Rule: "digest-equal"}, {Reason: "missing_material_field:c", Field: str("c"), Rule: "required-field", Observed: str("absent")}}) {
		t.Fatalf("missing field: %#v", missing)
	}
	host := VerifyCaid(obj{"action_type": "test.text.1", "c": int32(1)}, good.Caid, opts)
	if host.Details[len(host.Details)-2].Observed == nil || *host.Details[len(host.Details)-2].Observed != "unsupported" {
		t.Fatalf("host value observed kind: %#v", host.Details)
	}
	// Valid: empty reasons and details, digest reported.
	v = VerifyCaid(object, good.Caid, opts)
	if !reflect.DeepEqual(v, VerifyResult{Valid: true, Reasons: []string{}, Details: []VerifyDetail{}, DefinitionSha256: good.DefinitionSha256}) {
		t.Fatalf("valid: %#v", v)
	}
	// The details are closed-shape JSON with explicit nulls.
	encoded, err := json.Marshal(missing.Details)
	if err != nil || string(encoded) != `[{"reason":"digest_mismatch","field":null,"rule":"digest-equal","observed":null},{"reason":"missing_material_field:c","field":"c","rule":"required-field","observed":"absent"}]` {
		t.Fatalf("details JSON: %s %v", encoded, err)
	}
}

func TestTimestampField(t *testing.T) {
	defs := []interface{}{obj{"action_type": "test.time.1", "required_fields": []interface{}{obj{"name": "t", "type": "timestamp"}}}}
	for _, ok := range []string{"2024-02-29T00:00:00Z", "2026-12-31T23:59:59.999999Z", "0000-01-01T00:00:00Z"} {
		computeOK(t, obj{"action_type": "test.time.1", "t": ok}, defs)
	}
	for _, bad := range []string{"2026-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-01-01T00:00:60Z",
		"2026-01-01t00:00:00Z", "2026-01-01T00:00:00z", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00.Z", "2026-13-01T00:00:00Z"} {
		if got := refusals(obj{"action_type": "test.time.1", "t": bad}, defs); !reflect.DeepEqual(got, []string{"mistyped_field:t"}) {
			t.Errorf("%q: %v", bad, got)
		}
	}
	a := computeOK(t, obj{"action_type": "test.time.1", "t": "2026-01-01T00:00:00Z"}, defs)
	b := computeOK(t, obj{"action_type": "test.time.1", "t": "2026-01-01T00:00:00.000Z"}, defs)
	if a.Caid == b.Caid {
		t.Fatal("the fraction is lexical: .000Z and Z must differ")
	}
}

func TestCanonicalFormAndKeyOrder(t *testing.T) {
	value := obj{"\U0001F600": 1, "\ue000": 2, "b": []interface{}{"<&>", "\u007f", "\u001f", "é"}, "a": nil, "": true}
	got := Canonicalize(value)
	want := "{\"\":true,\"a\":null,\"b\":[\"<&>\",\"\u007f\",\"\\u001f\",\"é\"],\"\U0001F600\":1,\"\ue000\":2}"
	if !got.OK || got.Canonical != want {
		t.Fatalf("Canonicalize = %q, want %q", got.Canonical, want)
	}
	// Map iteration order never shows through.
	for i := 0; i < 50; i++ {
		if Canonicalize(value).Canonical != want {
			t.Fatal("canonical form is not deterministic")
		}
	}
}

func TestCanonicalSizeLimitAppliesToActionObjects(t *testing.T) {
	defs := []interface{}{obj{"action_type": "test.big.1", "required_fields": []interface{}{obj{"name": "s", "type": "string"}}}}
	prefix := len(`{"action_type":"test.big.1","s":""}`)
	exact := obj{"action_type": "test.big.1", "s": strings.Repeat("x", specLimitCanonicalOctets-prefix)}
	computeOK(t, exact, defs)
	over := obj{"action_type": "test.big.1", "s": strings.Repeat("x", specLimitCanonicalOctets-prefix+1)}
	if got := refusals(over, defs); !reflect.DeepEqual(got, []string{"unsupported_value"}) {
		t.Fatalf("canonical limit + 1: %v", got)
	}
	over["n"] = json.Number("0.5")
	if got := refusals(over, defs); !reflect.DeepEqual(got, []string{"unsupported_number"}) {
		t.Fatalf("size is reported only when nothing else is refused: %v", got)
	}
	if got := Canonicalize(obj{"s": strings.Repeat("x", specLimitCanonicalOctets)}); !got.OK {
		t.Fatal("Canonicalize applied the action-object limit")
	}
}
