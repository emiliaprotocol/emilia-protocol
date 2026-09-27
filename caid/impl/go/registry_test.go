package caid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const registryDir = "../../registry"

func readDocument(t *testing.T, path string) interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := DecodeDocumentJSON(data)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

type registryFixture struct {
	types     []interface{}
	snapshots []interface{}
}

func loadRegistry(t *testing.T) registryFixture {
	t.Helper()
	registry := readDocument(t, filepath.Join(registryDir, "action-types.json")).(obj)
	var snapshots []interface{}
	for _, f := range registry["enum_snapshot_files"].([]interface{}) {
		snapshots = append(snapshots, readDocument(t, filepath.Join(registryDir, f.(obj)["path"].(string))))
	}
	return registryFixture{types: registry["types"].([]interface{}), snapshots: snapshots}
}

var codeSamples = map[string]string{
	"icd-10-cm": "E11.9", "ndc-11": "00002143380", "ndc-10-hyphenated": "0002-1433-80", "cpt": "99213",
	"hcpcs-level-ii": "J1234", "hcpcs": "J1234", "iso-3166-2": "US-CA",
	"iso20022-external-code": "AC01", "nacha-sec": "PPD",
}

func sampleValue(t *testing.T, field obj, snapshots []interface{}) interface{} {
	switch field["type"] {
	case "string":
		return "x"
	case "amount-string":
		return "1.00"
	case "digest":
		return "sha256:" + strings.Repeat("0", 64)
	case "timestamp":
		return "2026-02-28T00:00:00Z"
	case "integer":
		return json.Number("1")
	case "boolean":
		return true
	case "object":
		return obj{}
	case "array":
		return []interface{}{}
	case "code":
		s, ok := codeSamples[field["format"].(string)]
		if !ok {
			t.Fatalf("no sample for code format %v", field["format"])
		}
		return s
	case "enum":
		if values, ok := field["values"].([]interface{}); ok {
			return values[0]
		}
		if ref, ok := field["values_ref"].(string); ok && strings.HasPrefix(ref, "inline:") {
			return strings.Trim(strings.Split(strings.TrimPrefix(ref, "inline:"), "|")[0], " ")
		}
		for _, s := range snapshots {
			so := s.(obj)
			if so["values_ref"] == field["values_ref"] && so["values_snapshot"] == field["values_snapshot"] && so["values_sha256"] == field["values_sha256"] {
				return so["values"].([]interface{})[0]
			}
		}
		return "UNRESOLVED"
	}
	t.Fatalf("no sample for field type %v", field["type"])
	return nil
}

// Every registry v5 type resolves, conforms, reports the definition_sha256
// that caid/registry/digests.json lists, and computes: every active type with
// its required fields alone and with every optional field, every deprecated
// type unless a required enum is unresolved (then exactly those fields
// refuse as mistyped_field).
func TestRegistryV5TypesComputeInGo(t *testing.T) {
	reg := loadRegistry(t)
	digests := readDocument(t, filepath.Join(registryDir, "digests.json")).(obj)
	listed := map[string]string{}
	for _, e := range digests["types"].([]interface{}) {
		listed[e.(obj)["action_type"].(string)] = e.(obj)["definition_sha256"].(string)
	}
	registry := readDocument(t, filepath.Join(registryDir, "action-types.json")).(obj)
	unresolved := map[string]bool{}
	for _, u := range registry["unresolved_external_enums"].([]interface{}) {
		unresolved[u.(obj)["action_type"].(string)+"."+u.(obj)["field"].(string)] = true
	}
	active, deprecated, withCode := 0, 0, 0
	for _, raw := range reg.types {
		def := raw.(obj)
		at := def["action_type"].(string)
		if got := DefinitionSha256(def); got.DefinitionSha256 != listed[at] || listed[at] == "" {
			t.Errorf("%s: definition_sha256 %#v, digests.json %q", at, got, listed[at])
		}
		minimal := obj{"action_type": at}
		var expectRefusals []string
		for _, f := range def["required_fields"].([]interface{}) {
			fo := f.(obj)
			minimal[fo["name"].(string)] = sampleValue(t, fo, reg.snapshots)
			if unresolved[at+"."+fo["name"].(string)] {
				expectRefusals = append(expectRefusals, "mistyped_field:"+fo["name"].(string))
			}
			if fo["type"] == "code" {
				withCode++
			}
		}
		full := obj{}
		for k, v := range minimal {
			full[k] = v
		}
		if optional, ok := def["optional_fields"].([]interface{}); ok {
			for _, f := range optional {
				fo := f.(obj)
				full[fo["name"].(string)] = sampleValue(t, fo, reg.snapshots)
			}
		}
		opts := ComputeOptions{Suite: "jcs-sha256", Definitions: reg.types, EnumSnapshots: reg.snapshots}
		a, b := ComputeCaid(minimal, opts), ComputeCaid(full, opts)
		switch def["status"] {
		case "active":
			active++
			if a.Caid == "" || b.Caid == "" {
				t.Errorf("active %s does not compute: %v / %v", at, a.Refusals, b.Refusals)
				continue
			}
			if a.DefinitionSha256 != listed[at] {
				t.Errorf("%s: compute reports %s", at, a.DefinitionSha256)
			}
			v := VerifyCaid(full, b.Caid, VerifyOptions{Definitions: reg.types, EnumSnapshots: reg.snapshots, ExpectedDefinitionSha256: &b.DefinitionSha256})
			if !v.Valid {
				t.Errorf("%s: verify %#v", at, v)
			}
		case "deprecated":
			deprecated++
			if len(expectRefusals) == 0 && a.Caid == "" {
				t.Errorf("deprecated %s does not compute: %v", at, a.Refusals)
			}
			if len(expectRefusals) > 0 && !reflect.DeepEqual(a.Refusals, expectRefusals) {
				t.Errorf("deprecated %s: %v, want %v", at, a.Refusals, expectRefusals)
			}
		default:
			t.Errorf("%s: status %v", at, def["status"])
		}
	}
	if active != 53 || deprecated != 9 || withCode == 0 {
		t.Fatalf("registry v5: %d active, %d deprecated, %d required code fields", active, deprecated, withCode)
	}
}

// The frozen v4 registry still resolves: its definition digests are the
// v4 values digests.json records for the changed types.
func TestHistoryV4DigestsForChangedTypes(t *testing.T) {
	v4 := readDocument(t, filepath.Join(registryDir, "history", "action-types.v4.json")).(obj)
	byType := map[string]obj{}
	for _, raw := range v4["types"].([]interface{}) {
		byType[raw.(obj)["action_type"].(string)] = raw.(obj)
	}
	digests := readDocument(t, filepath.Join(registryDir, "digests.json")).(obj)
	for _, raw := range digests["changed_since_v4"].([]interface{}) {
		c := raw.(obj)
		want, ok := c["v4_definition_sha256"].(string)
		if !ok {
			continue
		}
		at := c["action_type"].(string)
		if got := DefinitionSha256(byType[at]).DefinitionSha256; got != want {
			t.Errorf("v4 %s: %s, want %s", at, got, want)
		}
	}
}
