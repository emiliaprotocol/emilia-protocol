// SPDX-License-Identifier: Apache-2.0

package main

// The typed Go options cannot carry every JSON type the corpus passes. An
// option of the wrong type counts as absent, and absent is the zero value:
// a suite that is not a string is "", which no suite matches; definitions
// that are not an array are nil; an expected definition digest that is not
// a string is "".

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

func expectedString(o opts) string {
	if s, ok := o.expected.(string); ok && o.hasExpected {
		return s
	}
	return ""
}
