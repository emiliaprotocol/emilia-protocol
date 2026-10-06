// SPDX-License-Identifier: Apache-2.0

package main

// The -05 entry points of the Go implementation under test.

import caidlib "caid"

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
	return caidlib.VerifyOptions{Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots, ExpectedDefinitionSha256: expectedPointer(o)}
}

// expectedPointer is the typed form of the expected digest option: nil
// when it is absent. A supplied pin is never absent (draft -05 Section 6):
// one that is not a string, null included, becomes a pin to "", which no
// definition_sha256 equals, so it fails closed as in the other ports.
func expectedPointer(o opts) *string {
	if !o.hasExpected {
		return nil
	}
	s, _ := o.expected.(string)
	return &s
}

func definitionDigest(d interface{}) interface{} { return caidlib.DefinitionSha256(d) }

func canonicalizeValue(v interface{}) interface{} { return caidlib.Canonicalize(v) }

// orNil passes a missing (nil) map as an untyped nil, so the port sees no
// value rather than a typed empty map.
func orNil(m map[string]interface{}) interface{} {
	if m == nil {
		return nil
	}
	return m
}

func normMap(r caidlib.MapActionResult) obj {
	if r.OK {
		return obj{"ok": true, "caid": r.Caid, "digest": r.Digest}
	}
	return obj{"ok": false, "reasons": stringList(r.Reasons)}
}

func mapOne(source interface{}, profile, desc map[string]interface{}, pin string, nv bool, defs, snaps []interface{}, suite string) interface{} {
	return normMap(caidlib.MapAction(source, caidlib.MapActionOptions{
		Profile: orNil(profile), SourceDescriptor: orNil(desc), ExpectedProfileHash: pin, NativeVerified: nv,
		Definitions: defs, EnumSnapshots: snaps, Suite: &suite,
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
