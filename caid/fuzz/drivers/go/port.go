// SPDX-License-Identifier: Apache-2.0

//go:build !legacy

package main

// The -04 entry points of the Go implementation under test.

import caidlib "caid"

func legacyFrontEnd() bool { return false }

func decodeBytes(data []byte) (interface{}, bool) {
	r := caidlib.DecodeCaidJSON(data)
	return r.Value, r.OK
}

func computeBytes(data []byte, o opts) interface{} {
	return caidlib.ComputeCaidJSON(data, computeOptions(o))
}

func verifyBytes(data []byte, caidString string, o opts) interface{} {
	return caidlib.VerifyCaidJSON(data, caidString, verifyOptions(o))
}

func computeValue(v interface{}, o opts) interface{} {
	return caidlib.ComputeCaid(v, computeOptions(o))
}

func verifyValue(v interface{}, caidString string, o opts) interface{} {
	return caidlib.VerifyCaid(v, caidString, verifyOptions(o))
}

func parseString(s string) interface{} { return caidlib.ParseCaid(s) }

func computeOptions(o opts) caidlib.ComputeOptions {
	return caidlib.ComputeOptions{Suite: suiteString(o), Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots}
}

func verifyOptions(o opts) caidlib.VerifyOptions {
	return caidlib.VerifyOptions{Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots, ExpectedDefinitionSha256: expectedString(o)}
}

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
