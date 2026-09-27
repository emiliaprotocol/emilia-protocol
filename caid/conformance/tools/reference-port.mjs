// SPDX-License-Identifier: Apache-2.0
//
// The spec oracle (./oracle.mjs) behind the JavaScript port's -04 entry
// point names, so the JavaScript runner can check the corpora against the
// oracle itself:
//
//   node caid/conformance/runners/run.mjs --impl caid/conformance/tools/reference-port.mjs
//
// Dev-time only; it ships in no package.

import * as oracle from './oracle.mjs';

const computeOptions = (o) => {
  const out = {};
  if (o && typeof o === 'object') {
    if ('suite' in o) out.suite = o.suite;
    out.definitions = o.definitions;
    out.enum_snapshots = o.enumSnapshots;
  }
  return out;
};
const verifyOptions = (o) => {
  const out = computeOptions(o);
  delete out.suite;
  if (o && typeof o === 'object' && 'expectedDefinitionSha256' in o) out.expected_definition_sha256 = o.expectedDefinitionSha256;
  return out;
};

export const decodeCaidJson = (bytes) => oracle.decode(bytes);
export const computeCaidJson = (bytes, o) => oracle.computeText(bytes, computeOptions(o));
export const verifyCaidJson = (bytes, caid, o) => oracle.verifyText(bytes, caid, verifyOptions(o));
export const computeCaid = (value, o) => oracle.compute(value, computeOptions(o));
export const verifyCaid = (value, caid, o) => oracle.verify(value, caid, verifyOptions(o));
export const parseCaid = (s) => oracle.parse(s);
export const definitionSha256 = (d) => oracle.definitionSha256(d);
// Canonicalization of a document: the document ceiling applies, as in the
// ports' canonicalize.
export const canonicalize = (value) => oracle.reference.canonicalizeDocument(value);
