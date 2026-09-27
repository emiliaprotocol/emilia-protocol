package caid

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

var mapDefinitions = []interface{}{obj{
	"action_type": "test.map.1",
	"required_fields": []interface{}{
		obj{"name": "a", "type": "string"},
		obj{"name": "b", "type": "amount-string"},
	},
	"optional_fields": []interface{}{obj{"name": "c", "type": "string"}},
}}

func mapProfile() obj {
	return obj{
		"@version":              MappingProfileVersion,
		"profile_id":            "urn:test:map:1",
		"source_format":         obj{"media_type": "application/test+json", "schema": "urn:test:src:1", "version": "1"},
		"target_action_type":    "test.map.1",
		"loss_policy":           "no-material-field-loss",
		"material_source_paths": []interface{}{"/x/a", "/x/b"},
		"rules": []interface{}{
			obj{"source_path": "/x/a", "target_field": "a", "transform": "copy"},
			obj{"source_path": "/x/b", "target_field": "b", "transform": "copy"},
		},
	}
}

func mapSource() obj { return obj{"x": obj{"a": "hello", "b": "1.00", "h": strings.Repeat("ab", 32)}} }

func mapWith(profile interface{}, source interface{}, suite *string) MapActionResult {
	var descriptor interface{}
	if p, ok := profile.(obj); ok {
		descriptor = p["source_format"]
	}
	return MapAction(source, MapActionOptions{
		Profile: profile, SourceDescriptor: descriptor, ExpectedProfileHash: MappingProfileHash(profile),
		NativeVerified: true, Definitions: mapDefinitions, Suite: suite,
	})
}

func mapReasons(mutate func(p obj)) []string {
	p := mapProfile()
	mutate(p)
	return mapWith(p, mapSource(), nil).Reasons
}

func TestMapActionHappyPath(t *testing.T) {
	got := mapWith(mapProfile(), mapSource(), nil)
	want := computeOK(t, obj{"action_type": "test.map.1", "a": "hello", "b": "1.00"}, mapDefinitions)
	if !got.OK || got.Caid != want.Caid || got.Suite != DefaultMappingSuite {
		t.Fatalf("MapAction = %#v", got)
	}
}

func TestMappingShapeGateYieldsExactlyInvalidMappingProfile(t *testing.T) {
	for name, mutate := range map[string]func(p obj){
		"wrong version":              func(p obj) { p["@version"] = "CAID-MAPPING-PROFILE-v2" },
		"unknown member":             func(p obj) { p["extra"] = true },
		"unknown source_format key":  func(p obj) { p["source_format"].(obj)["charset"] = "utf-8" },
		"unknown rule key":           func(p obj) { p["rules"].([]interface{})[0].(obj)["note"] = "x" },
		"omitted_source_fields null": func(p obj) { p["omitted_source_fields"] = nil },
		"profile_id empty":           func(p obj) { p["profile_id"] = "" },
		"profile_id 513 octets":      func(p obj) { p["profile_id"] = strings.Repeat("é", 256) + "x" },
		"rules empty":                func(p obj) { p["rules"] = []interface{}{} },
		"transform unregistered":     func(p obj) { p["rules"].([]interface{})[0].(obj)["transform"] = "sha512-utf8" },
		"transform not a string":     func(p obj) { p["rules"].([]interface{})[0].(obj)["transform"] = []interface{}{"copy"} },
		"loss policy unregistered":   func(p obj) { p["loss_policy"] = "best-effort" },
		"target_field reserved":      func(p obj) { p["rules"].([]interface{})[0].(obj)["target_field"] = "action_type" },
		"target_field with colon":    func(p obj) { p["rules"].([]interface{})[0].(obj)["target_field"] = "a:b" },
		"target_field not a string":  func(p obj) { p["rules"].([]interface{})[0].(obj)["target_field"] = []interface{}{"a"} },
		"source_path not a pointer":  func(p obj) { p["rules"].([]interface{})[0].(obj)["source_path"] = "x/a" },
		"source_path bad escape":     func(p obj) { p["rules"].([]interface{})[0].(obj)["source_path"] = "/x/a~2" },
		"source_path 2049 octets":    func(p obj) { p["rules"].([]interface{})[0].(obj)["source_path"] = "/" + strings.Repeat("a", 2048) },
		// D9: a non-string material path is a member-rule failure, so the
		// unknown target type is not reported beside it.
		"material path a number": func(p obj) {
			p["material_source_paths"] = []interface{}{json.Number("123")}
			p["target_action_type"] = "test.unknown.1"
		},
		// D4: target_action_type is bounded to 512 octets.
		"target_action_type 513 octets": func(p obj) { p["target_action_type"] = strings.Repeat("a", 513) },
	} {
		if got := mapReasons(mutate); !reflect.DeepEqual(got, []string{"invalid_mapping_profile"}) {
			t.Errorf("%s: %v", name, got)
		}
	}
	rules := make([]interface{}, 129)
	paths := make([]interface{}, 129)
	for i := range rules {
		path := "/x/" + strings.Repeat("a", i+1)
		rules[i] = obj{"source_path": path, "target_field": "f" + strings.Repeat("a", i), "transform": "copy"}
		paths[i] = path
	}
	if got := mapReasons(func(p obj) { p["rules"] = rules; p["material_source_paths"] = paths }); !reflect.DeepEqual(got, []string{"invalid_mapping_profile"}) {
		t.Errorf("129 rules: %v", got)
	}
}

func TestMappingProfileChecksAllRunAfterTheShapeGate(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(p obj)
		want   []string
	}{
		"two rules on one material path": {func(p obj) {
			p["rules"] = append(p["rules"].([]interface{}), obj{"source_path": "/x/a", "target_field": "c", "transform": "copy"})
		}, []string{"invalid_mapping_profile"}},
		"rule path outside material paths": {func(p obj) {
			p["material_source_paths"] = []interface{}{"/x/a"}
		}, []string{"invalid_mapping_profile"}},
		"repeated target": {func(p obj) {
			p["rules"].([]interface{})[1].(obj)["target_field"] = "a"
		}, []string{"invalid_mapping_profile", "unmapped_material_field:b"}},
		"repeated material path and unknown type": {func(p obj) {
			p["material_source_paths"] = []interface{}{"/x/a", "/x/b", "/x/a"}
			p["target_action_type"] = "test.unknown.1"
		}, []string{"invalid_mapping_profile", "unknown_action_type"}},
		"newline-joined coverage": {func(p obj) {
			p["rules"] = []interface{}{obj{"source_path": "/x/a\n/x/b", "target_field": "a", "transform": "copy"}}
		}, []string{"invalid_mapping_profile", "unmapped_material_field:b"}},
		"omission under no-material-field-loss": {func(p obj) {
			p["omitted_source_fields"] = []interface{}{obj{"source_path": "/x/z", "reason": "unused"}}
		}, []string{"invalid_mapping_profile"}},
		"omission overlapping a rule": {func(p obj) {
			p["loss_policy"] = "declared-source-semantic-loss"
			p["omitted_source_fields"] = []interface{}{obj{"source_path": "/x/a", "reason": "unused"}}
		}, []string{"invalid_mapping_profile", "declared_source_semantic_loss"}},
		"declared loss without omissions": {func(p obj) {
			p["loss_policy"] = "declared-source-semantic-loss"
		}, []string{"invalid_mapping_profile", "declared_source_semantic_loss"}},
		"unmapped required fields in order": {func(p obj) {
			p["rules"] = []interface{}{obj{"source_path": "/x/a", "target_field": "c", "transform": "copy"}}
			p["material_source_paths"] = []interface{}{"/x/a"}
		}, []string{"unmapped_material_field:a", "unmapped_material_field:b"}},
		"conflicting definitions": {func(p obj) {
			p["target_action_type"] = "test.conflict.1"
		}, []string{"invalid_definition"}},
	} {
		p := mapProfile()
		c.mutate(p)
		defs := append(append([]interface{}{}, mapDefinitions...),
			obj{"action_type": "test.conflict.1", "required_fields": []interface{}{obj{"name": "a", "type": "string"}}},
			obj{"action_type": "test.conflict.1", "required_fields": []interface{}{obj{"name": "a", "type": "digest"}}})
		got := MapAction(mapSource(), MapActionOptions{
			Profile: p, SourceDescriptor: p["source_format"], ExpectedProfileHash: MappingProfileHash(p),
			NativeVerified: true, Definitions: defs,
		})
		if !reflect.DeepEqual(got.Reasons, c.want) {
			t.Errorf("%s: %v, want %v", name, got.Reasons, c.want)
		}
	}
}

func TestMappingTargetFieldsBeyondSnakeCase(t *testing.T) {
	defs := []interface{}{obj{"action_type": "test.sci.1", "required_fields": []interface{}{obj{"name": "@version", "type": "string"}}}}
	p := mapProfile()
	p["target_action_type"] = "test.sci.1"
	p["rules"] = []interface{}{obj{"source_path": "/x/a", "target_field": "@version", "transform": "copy"}}
	p["material_source_paths"] = []interface{}{"/x/a"}
	got := MapAction(mapSource(), MapActionOptions{Profile: p, SourceDescriptor: p["source_format"], ExpectedProfileHash: MappingProfileHash(p), NativeVerified: true, Definitions: defs})
	if !got.OK {
		t.Fatalf("@version target: %v", got.Reasons)
	}
}

func TestMappingStageBOrderAndStop(t *testing.T) {
	p := mapProfile()
	got := MapAction(json.Number("1"), MapActionOptions{Profile: p, SourceDescriptor: obj{"media_type": "x"}, ExpectedProfileHash: "sha256:0"})
	want := []string{"unknown_action_type", "native_verification_required", "mapping_profile_unpinned", "source_format_mismatch", "source_not_object", "source_not_canonicalizable"}
	if !reflect.DeepEqual(got.Reasons, want) {
		t.Fatalf("stage A+B: %v, want %v", got.Reasons, want)
	}
	// A profile outside the data model: invalid_mapping_profile sorts first.
	p["profile_id"] = "\xed\xa0\x80"
	got = MapAction(mapSource(), MapActionOptions{Profile: p, SourceDescriptor: p["source_format"], ExpectedProfileHash: "x", Definitions: mapDefinitions})
	if !reflect.DeepEqual(got.Reasons, []string{"invalid_mapping_profile", "native_verification_required", "mapping_profile_unpinned"}) {
		t.Fatalf("unhashable profile: %v", got.Reasons)
	}
	// A source outside the data model.
	src := mapSource()
	src["bad"] = json.Number("0.5")
	if got := mapWith(mapProfile(), src, nil); !reflect.DeepEqual(got.Reasons, []string{"source_not_canonicalizable"}) {
		t.Fatalf("source: %v", got.Reasons)
	}
}

func TestMappingStagesCAndD(t *testing.T) {
	p := mapProfile()
	p["rules"] = []interface{}{
		obj{"source_path": "/x/missing", "target_field": "a", "transform": "copy"},
		obj{"source_path": "/x/a/0", "target_field": "b", "transform": "copy"},
		obj{"source_path": "/x/b", "target_field": "c", "transform": "sha256-hex-to-digest"},
	}
	p["material_source_paths"] = []interface{}{"/x/missing", "/x/a/0", "/x/b"}
	if got := mapWith(p, mapSource(), nil); !reflect.DeepEqual(got.Reasons, []string{"missing_source_field:/x/missing", "missing_source_field:/x/a/0", "source_value_type_mismatch:/x/b"}) {
		t.Fatalf("stage C: %v", got.Reasons)
	}
	src := obj{"x": obj{"a": []interface{}{"q"}, "b": "1.00"}}
	p["rules"] = []interface{}{
		obj{"source_path": "/x/a/01", "target_field": "a", "transform": "copy"},
		obj{"source_path": "/x/a/5", "target_field": "b", "transform": "copy"},
	}
	p["material_source_paths"] = []interface{}{"/x/a/01", "/x/a/5"}
	if got := mapWith(p, src, nil); !reflect.DeepEqual(got.Reasons, []string{"invalid_source_path:/x/a/01", "missing_source_field:/x/a/5"}) {
		t.Fatalf("array indexes: %v", got.Reasons)
	}
	// hex-to-digest accepts exactly 64 lowercase hex characters.
	p = mapProfile()
	p["rules"].([]interface{})[1] = obj{"source_path": "/x/h", "target_field": "b", "transform": "sha256-hex-to-digest"}
	p["material_source_paths"] = []interface{}{"/x/a", "/x/h"}
	if got := mapWith(p, mapSource(), nil); !reflect.DeepEqual(got.Reasons, []string{"mapped_action:invalid_amount:b"}) {
		t.Fatalf("stage D: %v", got.Reasons)
	}
	upper := mapSource()
	upper["x"].(obj)["h"] = strings.Repeat("AB", 32)
	if got := mapWith(p, upper, nil); !reflect.DeepEqual(got.Reasons, []string{"source_value_type_mismatch:/x/h"}) {
		t.Fatalf("uppercase hex: %v", got.Reasons)
	}
	// D10: an explicit empty suite is not defaulted.
	empty := ""
	if got := mapWith(mapProfile(), mapSource(), &empty); !reflect.DeepEqual(got.Reasons, []string{"mapped_action:unknown_suite"}) {
		t.Fatalf("empty suite: %v", got.Reasons)
	}
	cmp := CompareMappedActions(
		obj{"source": mapSource(), "profile": mapProfile(), "source_descriptor": mapProfile()["source_format"], "expected_profile_hash": MappingProfileHash(mapProfile()), "native_verified": true},
		obj{"source": mapSource(), "profile": mapProfile(), "source_descriptor": mapProfile()["source_format"], "expected_profile_hash": MappingProfileHash(mapProfile()), "native_verified": true},
		mapDefinitions, "")
	if cmp.Verdict != Indeterminate || !reflect.DeepEqual(cmp.Reasons, []string{"left:mapped_action:unknown_suite", "right:mapped_action:unknown_suite"}) {
		t.Fatalf("comparison with an empty suite: %#v", cmp)
	}
}

func TestCompareMappedActionsVerdicts(t *testing.T) {
	side := func(source obj, nativeVerified interface{}) obj {
		return obj{"source": source, "profile": mapProfile(), "source_descriptor": mapProfile()["source_format"], "expected_profile_hash": MappingProfileHash(mapProfile()), "native_verified": nativeVerified}
	}
	if got := CompareMappedActionsWithOptions(side(mapSource(), true), side(mapSource(), true), CompareOptions{Definitions: mapDefinitions}); got.Verdict != EquivalentUnderProfile || len(got.Reasons) != 0 {
		t.Fatalf("equivalent: %#v", got)
	}
	other := mapSource()
	other["x"].(obj)["a"] = "bye"
	if got := CompareMappedActionsWithOptions(side(mapSource(), true), side(other, true), CompareOptions{Definitions: mapDefinitions}); got.Verdict != NotEquivalent || !reflect.DeepEqual(got.Reasons, []string{"material_projection_mismatch"}) {
		t.Fatalf("not equivalent: %#v", got)
	}
	// native_verified must be the JSON value true.
	if got := CompareMappedActionsWithOptions(side(mapSource(), "true"), json.Number("1"), CompareOptions{Definitions: mapDefinitions}); got.Verdict != Indeterminate ||
		got.Reasons[0] != "left:native_verification_required" || !strings.HasPrefix(got.Reasons[1], "right:") {
		t.Fatalf("prefixes: %#v", got)
	}
}
