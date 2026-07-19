// SPDX-License-Identifier: Apache-2.0
package emiliaverify

// These assignments are the public v2 function-type contract. A variadic
// signature still accepts ordinary three-argument calls but breaks callers
// that store the verifier as a fixed function value, so compile that boundary.
var _ func(map[string]any, string, string) SignoffResult = VerifyWebAuthnSignoff
var _ func(map[string]any, string) QuorumResult = VerifyQuorum
