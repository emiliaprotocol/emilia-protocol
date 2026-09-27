// SPDX-License-Identifier: Apache-2.0

//go:build !legacy

package main

// The -04 entry points of the Go implementation (package caid). This file
// is the only place the runner touches the implementation's API.

import "caid"

func legacyFrontEnd() bool { return false }

func decodeCorpus(data []byte) (interface{}, error) { return caid.DecodeJSON(data) }

func decodeBytes(data []byte) (interface{}, bool, []string) {
	r := caid.DecodeCaidJSON(data)
	return r.Value, r.OK, r.Refusals
}

func computeBytes(data []byte, o opts) interface{} {
	return caid.ComputeCaidJSON(data, computeOptions(o))
}

func verifyBytes(data []byte, caidString string, o opts) interface{} {
	return caid.VerifyCaidJSON(data, caidString, verifyOptions(o))
}

func computeValue(v interface{}, o opts) interface{} { return caid.ComputeCaid(v, computeOptions(o)) }

func verifyValue(v interface{}, caidString string, o opts) interface{} {
	return caid.VerifyCaid(v, caidString, verifyOptions(o))
}

func parseString(s string) interface{} { return caid.ParseCaid(s) }

func definitionSha256(d interface{}) interface{} { return caid.DefinitionSha256(d) }

func computeOptions(o opts) caid.ComputeOptions {
	return caid.ComputeOptions{Suite: suiteString(o), Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots}
}

func verifyOptions(o opts) caid.VerifyOptions {
	return caid.VerifyOptions{Definitions: definitionList(o), EnumSnapshots: o.enumSnapshots, ExpectedDefinitionSha256: expectedString(o)}
}

func legacySkip(interface{}) bool { return false }
