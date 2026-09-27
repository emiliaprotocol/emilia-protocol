// SPDX-License-Identifier: Apache-2.0

package main

// The corpus options as given; port.go maps them onto the implementation's
// option types. The native-lane builder is the conformance runner's
// (caid/conformance/runners/go/native.go), which run.mjs copies into this
// module.

type opts struct {
	hasSuite      bool
	suite         interface{}
	definitions   interface{}
	enumSnapshots []interface{}
	hasExpected   bool
	expected      interface{}
}

func suiteString(o opts) string {
	if s, ok := o.suite.(string); ok && o.hasSuite {
		return s
	}
	return ""
}

func definitionList(o opts) []interface{} {
	d, _ := o.definitions.([]interface{})
	return d
}
