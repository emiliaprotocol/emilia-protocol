// SPDX-License-Identifier: Apache-2.0

package main

// The typed Go options cannot carry every JSON type the corpus passes. A
// suite or definitions option of the wrong type counts as absent, and absent
// is the zero value: a suite that is not a string is "", which no suite
// matches; definitions that are not an array are nil. An expected definition
// digest is never absent once supplied (draft -05 Section 6): a supplied
// value that is not a string, null included, is passed as a pin to "", which
// no definition_sha256 equals, so the pin fails closed exactly as in the
// ports that can carry the value itself.

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

func expectedString(o opts) *string {
	if !o.hasExpected {
		return nil
	}
	s, _ := o.expected.(string)
	return &s
}
