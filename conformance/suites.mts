// SPDX-License-Identifier: Apache-2.0
// The current same-team cross-language corpus. The externally attested
// clean-room corpus is independently frozen by clean-room/bundle.v1.json.
export const LIVE_SUITE_FILES = Object.freeze([
  'receipts.v1.json',
  'signoffs.v1.json',
  'resolution.v1.json',
  'quorum.v1.json',
  'revocation.exec.v2.json',
  'outcome-binding.v1.json',
  'outcome-binding.exec.v1.json',
  'authority-document-proof-join.v1.json',
  'time-attestation.v2.json',
  'trust-receipt.exec.v1.json',
  'trust-receipt.timestamp-forms.v2.json',
  'provenance.exec.v1.json',
  'evidence-record.v1.json',
  'canonicalization.v1.json',
  'boundary.v1.json',
  'aec-role.v1.json',
  'currency.v2.json',
  'initiator-attestation.v1.json',
  'consumption-proof.v1.json',
  'witness.v1.json',
  'timestamp-proof.v1.json',
]);

// The Authority join's public v1 catalogue carries the official case ids and
// accepted/reason contract. Its deterministic exec companion carries the real
// proof, Authority Document, pin, and key bytes plus the complete typed result.
// Count the catalogue once while executing and comparing the pinned companion.
export const LIVE_SUITE_EXECUTION_FILES = Object.freeze({
  'authority-document-proof-join.v1.json': 'authority-document-proof-join.exec.v1.json',
});

// Mode-A external-verification suites whose result rows must reproduce the
// complete published expect object, not only the primary boolean/verdict.
export const EXACT_EXTERNAL_RESULT_KINDS = Object.freeze({
  'outcome-binding.exec.v1.json': 'outcome',
  'revocation.exec.v2.json': 'valid',
  'authority-document-proof-join.exec.v1.json': 'accepted',
});

// Cross-language profile suites. Every port runs them in conformance/run.mjs
// and the manifest writer records them under `profile_suites`, but they are
// not part of the live corpus totals above: the clean-room bundles pin that
// corpus, and a profile suite covers one narrow contract, stated in its scope.
export const PROFILE_SUITES = Object.freeze([
  Object.freeze({
    file: 'aec-expression.v1.json',
    claim_scope: 'AEC -08 requirement-expression evaluation (EP-AEC-EVALUATOR-08-v1 expression contract) only. '
      + 'JavaScript, Python and Go agreement here is not conformance to the structured -07/-08 requirement and replay contract, '
      + 'which only the JavaScript createAuthorizationChainEvaluator implements.',
  }),
]);
export const PROFILE_SUITE_FILES = Object.freeze(PROFILE_SUITES.map((suite) => suite.file));

export default LIVE_SUITE_FILES;
