// SPDX-License-Identifier: Apache-2.0

//go:build legacy

package main

// A pre-04 Go implementation driven through DecodeJSON and the native entry
// points. run.mjs never passes a run built this way.

import (
	"fmt"

	caidlib "caid"
)

func legacyFrontEnd() bool { return true }

func decodeBytes(data []byte) (interface{}, bool) {
	v, err := caidlib.DecodeJSON(data)
	return v, err == nil
}

func computeBytes(data []byte, o opts) interface{} {
	v, ok := decodeBytes(data)
	if !ok {
		return obj{"refusals": []interface{}{"malformed_json"}}
	}
	return computeValue(v, o)
}

func verifyBytes(data []byte, caidString string, o opts) interface{} {
	v, ok := decodeBytes(data)
	if !ok {
		return obj{"valid": false, "reasons": []interface{}{"malformed_json"}, "details": []interface{}{}}
	}
	return verifyValue(v, caidString, o)
}

func computeValue(v interface{}, o opts) interface{} {
	if cyclic(v) {
		return obj{"crash": "a pre-04 implementation recurses without bound on a cyclic value"}
	}
	return caidlib.ComputeCaid(v, caidlib.ComputeOptions{Suite: suiteString(o), Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots})
}

func verifyValue(v interface{}, caidString string, o opts) interface{} {
	if cyclic(v) {
		return obj{"crash": "a pre-04 implementation recurses without bound on a cyclic value"}
	}
	return caidlib.VerifyCaid(v, caidString, caidlib.VerifyOptions{Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots})
}

// cyclic reports a value whose walk revisits a container, which a pre-04
// Go implementation follows until the stack overflows (not recoverable).
func cyclic(v interface{}) bool {
	seen := map[interface{}]bool{}
	var walk func(x interface{}, depth int) bool
	walk = func(x interface{}, depth int) bool {
		if depth > 20000 {
			return true
		}
		switch t := x.(type) {
		case map[string]interface{}:
			key := fmt.Sprintf("%p", t)
			if seen[key] {
				return true
			}
			seen[key] = true
			for _, e := range t {
				if walk(e, depth+1) {
					return true
				}
			}
			delete(seen, key)
		case []interface{}:
			for _, e := range t {
				if walk(e, depth+1) {
					return true
				}
			}
		}
		return false
	}
	return walk(v, 0)
}

func parseString(s string) interface{} { return caidlib.ParseCaid(s) }

func normMap(r caidlib.MapActionResult) obj {
	if r.OK {
		return obj{"ok": true, "caid": r.Caid, "digest": r.Digest}
	}
	return obj{"ok": false, "reasons": stringList(r.Reasons)}
}

func mapOne(source interface{}, profile, desc map[string]interface{}, pin string, nv bool, defs, snaps []interface{}, suite string) interface{} {
	return normMap(caidlib.MapAction(source, caidlib.MapActionOptions{
		Profile: profile, SourceDescriptor: desc, ExpectedProfileHash: pin, NativeVerified: nv,
		Definitions: defs, EnumSnapshots: snaps, Suite: suite,
	}))
}

func compareSides(left, right map[string]interface{}, defs, snaps []interface{}, suite string) interface{} {
	r := caidlib.CompareMappedActionsWithEnumSnapshots(left, right, defs, snaps, suite)
	return obj{"verdict": r.Verdict, "reasons": stringList(r.Reasons), "left": normMap(r.Left), "right": normMap(r.Right)}
}

func stringList(in []string) []interface{} {
	out := make([]interface{}, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}
