// SPDX-License-Identifier: Apache-2.0

//go:build legacy

package main

// A pre-04 implementation measured through DecodeJSON and the native entry
// points. This build always exits nonzero.

import (
	"strings"

	"caid"
)

func legacyFrontEnd() bool { return true }

func decodeCorpus(data []byte) (interface{}, error) { return caid.DecodeJSON(data) }

func decodeBytes(data []byte) (interface{}, bool, []string) {
	v, err := caid.DecodeJSON(data)
	if err != nil {
		return nil, false, []string{"malformed_json"}
	}
	return v, true, nil
}

func computeBytes(data []byte, o opts) interface{} {
	v, ok, refusals := decodeBytes(data)
	if !ok {
		return map[string]interface{}{"refusals": refusals}
	}
	return computeValue(v, o)
}

func verifyBytes(data []byte, caidString string, o opts) interface{} {
	v, ok, _ := decodeBytes(data)
	if !ok {
		return map[string]interface{}{"valid": false, "reasons": []string{"malformed_json"}, "details": []interface{}{}}
	}
	return verifyValue(v, caidString, o)
}

func computeValue(v interface{}, o opts) interface{} {
	return caid.ComputeCaid(v, caid.ComputeOptions{Suite: suiteString(o), Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots})
}

func verifyValue(v interface{}, caidString string, o opts) interface{} {
	return caid.VerifyCaid(v, caidString, caid.VerifyOptions{Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots})
}

func parseString(s string) interface{} { return caid.ParseCaid(s) }

func definitionSha256(interface{}) interface{} {
	return map[string]interface{}{"refusals": []string{"definition_sha256 not implemented"}}
}

// legacySkip reports native values a pre-04 Go implementation cannot survive:
// a cyclic value overflows its stack, which no recover can catch.
func legacySkip(encoded interface{}) bool { return strings.Contains(canonical(encoded), `"cyclic"`) }
