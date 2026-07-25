// SPDX-License-Identifier: Apache-2.0

import {
  evaluateScopedAuthority,
  evaluateSignedDecision,
  scopeViolationCases,
  signedDenialFixture,
} from "./two-claim-assurance.model.mjs";

/**
 * Deliberately unsafe comparison: authentic signatures are treated as approval
 * without inspecting the signed decision outcome.
 */
export function unsafeIgnoreSignedDecision(input) {
  const unsafe = evaluateSignedDecision({
    ...structuredClone(input),
    decision: "approved",
  });
  return Object.freeze({
    ...unsafe,
    decision: input?.decision ?? null,
    unsafeRule: "signature-implies-approval",
  });
}

/**
 * Deliberately unsafe comparison: one requested scope gate is skipped.
 */
export function unsafeOmitScopedAuthorityCheck(
  proof,
  request,
  pin,
  omittedCheck,
) {
  const safe = evaluateScopedAuthority(proof, request, pin);
  const checks = { ...safe.checks, [omittedCheck]: true };
  return Object.freeze({
    checks: Object.freeze(checks),
    authorized: Object.values(checks).every(Boolean),
    unsafeRule: `omitted-${omittedCheck}`,
  });
}

export function findSignedDenialCounterexample() {
  const input = signedDenialFixture();
  const safe = evaluateSignedDecision(input);
  const unsafe = unsafeIgnoreSignedDecision(input);
  return Object.values(unsafe.authorizationOutputs).some(Boolean)
    ? { input, safe, unsafe }
    : null;
}

export function findScopedAuthorityCounterexamples() {
  return scopeViolationCases().map((scenario) => {
    const safe = evaluateScopedAuthority(
      scenario.proof,
      scenario.request,
      scenario.pin,
    );
    const unsafe = unsafeOmitScopedAuthorityCheck(
      scenario.proof,
      scenario.request,
      scenario.pin,
      scenario.violatedCheck,
    );
    if (safe.authorized || !unsafe.authorized) {
      throw new Error(
        `unsafe comparison did not expose ${scenario.violatedCheck}`,
      );
    }
    return {
      id: scenario.id,
      omittedCheck: scenario.violatedCheck,
      safe,
      unsafe,
    };
  });
}
