// run_vectors.go - runs the shared CAID conformance vectors against the
// Go implementation. Exits nonzero on any failure.
//
// Usage: go run ./cmd/run_vectors [path/to/vectors.json]
// Default path: ../../conformance/vectors.json relative to the module
// root (impl/go), with fallbacks for other working directories.
//
// The vectors file is decoded with UseNumber so numbers reach the
// implementation as json.Number, exactly as a conforming Go caller
// would provide them.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"caid"
)

func main() {
	path := findVectors()
	if path == "" {
		fmt.Fprintln(os.Stderr, "FAIL: vectors.json not found; pass its path as the first argument")
		os.Exit(1)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot read %s: %v\n", path, err)
		os.Exit(1)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]interface{}
	if err := dec.Decode(&doc); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot decode %s: %v\n", path, err)
		os.Exit(1)
	}
	vectorsRaw, ok := doc["vectors"].([]interface{})
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL: vectors.json has no vectors array")
		os.Exit(1)
	}

	failures := 0
	total := 0
	computedCaids := map[string]string{}
	relations := []relation{}

	for _, raw := range vectorsRaw {
		vec, isObj := raw.(map[string]interface{})
		if !isObj {
			fail(&failures, "(non-object vector entry)", "vector entry is not an object")
			continue
		}
		id := str(vec, "id")
		kind := str(vec, "kind")
		total++

		definitions, _ := vec["definitions"].([]interface{})
		input, _ := vec["input"].(map[string]interface{})
		expect, _ := vec["expect"].(map[string]interface{})
		if input == nil || expect == nil {
			fail(&failures, id, "vector missing input or expect")
			continue
		}

		switch kind {
		case "compute":
			res := caid.ComputeCaid(input["object"], caid.ComputeOptions{
				Suite:       str(input, "suite"),
				Definitions: definitions,
			})
			if expCaid, hasCaid := expect["caid"]; hasCaid {
				if len(res.Refusals) != 0 {
					fail(&failures, id, fmt.Sprintf("expected success, got refusals %v", res.Refusals))
					continue
				}
				okC := checkEqual(&failures, id, "caid", res.Caid, expCaid)
				okD := checkEqual(&failures, id, "digest", res.Digest, expect["digest"])
				if okC && okD {
					computedCaids[id] = res.Caid
				}
			} else {
				checkStringList(&failures, id, "refusals", res.Refusals, expect["refusals"])
			}
			if rel, hasRel := vec["relation"].(map[string]interface{}); hasRel {
				relations = append(relations, relation{id: id, spec: rel})
			}
		case "verify":
			res := caid.VerifyCaid(input["object"], str(input, "caid"), caid.VerifyOptions{
				Definitions: definitions,
			})
			expValid, _ := expect["valid"].(bool)
			if res.Valid != expValid {
				fail(&failures, id, fmt.Sprintf("valid: got %v, want %v", res.Valid, expValid))
			}
			checkStringList(&failures, id, "reasons", res.Reasons, expect["reasons"])
		case "parse":
			res := caid.ParseCaid(str(input, "caid"))
			expOK, _ := expect["ok"].(bool)
			if res.OK != expOK {
				fail(&failures, id, fmt.Sprintf("ok: got %v, want %v", res.OK, expOK))
				continue
			}
			if expOK {
				expCaid, _ := expect["caid"].(map[string]interface{})
				if expCaid == nil || res.Caid == nil {
					fail(&failures, id, "missing parsed caid on one side")
					continue
				}
				checkEqual(&failures, id, "version", res.Caid.Version, expCaid["version"])
				checkEqual(&failures, id, "action_type", res.Caid.ActionType, expCaid["action_type"])
				checkEqual(&failures, id, "suite", res.Caid.Suite, expCaid["suite"])
				checkEqual(&failures, id, "digest", res.Caid.Digest, expCaid["digest"])
			} else {
				checkStringList(&failures, id, "refusals", res.Refusals, expect["refusals"])
			}
		default:
			fail(&failures, id, "unknown vector kind: "+kind)
		}
	}

	// Cross-vector relations: same_caid_as / different_caid_from.
	for _, r := range relations {
		if other := str(r.spec, "same_caid_as"); other != "" {
			a, aOK := computedCaids[r.id]
			b, bOK := computedCaids[other]
			if aOK && bOK && a != b {
				fail(&failures, r.id, "same_caid_as "+other+" violated: "+a+" != "+b)
			}
		}
		if other := str(r.spec, "different_caid_from"); other != "" {
			a, aOK := computedCaids[r.id]
			b, bOK := computedCaids[other]
			if aOK && bOK && a == b {
				fail(&failures, r.id, "different_caid_from "+other+" violated: both "+a)
			}
		}
	}

	if failures > 0 {
		fmt.Printf("FAIL: %d of %d vectors failed (%s)\n", failures, total, path)
		os.Exit(1)
	}
	fmt.Printf("PASS: %d vectors, 0 failures (%s)\n", total, path)
}

type relation struct {
	id   string
	spec map[string]interface{}
}

func str(m map[string]interface{}, key string) string {
	s, _ := m[key].(string)
	return s
}

func fail(failures *int, id, msg string) {
	*failures++
	fmt.Printf("FAIL %s: %s\n", id, msg)
}

func checkEqual(failures *int, id, label, got string, want interface{}) bool {
	w, _ := want.(string)
	if got != w {
		fail(failures, id, fmt.Sprintf("%s: got %q, want %q", label, got, w))
		return false
	}
	return true
}

func checkStringList(failures *int, id, label string, got []string, want interface{}) {
	wantRaw, _ := want.([]interface{})
	wantList := make([]string, 0, len(wantRaw))
	for _, w := range wantRaw {
		s, _ := w.(string)
		wantList = append(wantList, s)
	}
	equal := len(got) == len(wantList)
	if equal {
		for i := range got {
			if got[i] != wantList[i] {
				equal = false
				break
			}
		}
	}
	if !equal {
		fail(failures, id, fmt.Sprintf("%s: got %v, want %v", label, got, wantList))
	}
}

func findVectors() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	candidates := []string{
		filepath.Join("..", "..", "conformance", "vectors.json"),
		filepath.Join("conformance", "vectors.json"),
		filepath.Join("..", "..", "..", "..", "conformance", "vectors.json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
