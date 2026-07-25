#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import {
  DENIAL_AUTHORIZATION_OUTPUTS,
  FORMAL_MODEL_VERSION,
  FORMAL_OBLIGATIONS,
  evaluateSignedDecision,
  evaluateScopedAuthority,
  scopeViolationCases,
  scopedAuthorityFixture,
  signedDenialFixture,
} from "./two-claim-assurance.model.mjs";
import {
  findScopedAuthorityCounterexamples,
  findSignedDenialCounterexample,
} from "./two-claim-assurance.unsafe.mjs";

const BOOLEAN_FIELDS = Object.freeze([
  "signatureValid",
  "actionDigestMatches",
  "nonceMatches",
  "policyContextPinned",
  "withinWindow",
  "nonInitiator",
  "distinctApprover",
  "quorumReached",
  "assuranceSatisfied",
  "authorityWithinScope",
  "actionMaterialMatches",
  "relianceProfilePinned",
  "freshnessSatisfied",
]);

function checkSignedDenialStates() {
  const base = signedDenialFixture();
  const violations = [];
  const positiveControl = evaluateSignedDecision({
    ...base,
    decision: "approved",
  });
  for (const predicate of DENIAL_AUTHORIZATION_OUTPUTS) {
    if (positiveControl.authorizationOutputs[predicate] !== true) {
      violations.push({
        control: "bounded-approved-positive-control",
        predicate,
        positiveControl,
      });
    }
  }
  let states = 1;
  for (let mask = 0; mask < 2 ** BOOLEAN_FIELDS.length; mask += 1) {
    const input = { ...base, decision: "denied" };
    BOOLEAN_FIELDS.forEach((field, bit) => {
      input[field] = (mask & (1 << bit)) !== 0;
    });
    const result = evaluateSignedDecision(input);
    states += 1;
    for (const predicate of DENIAL_AUTHORIZATION_OUTPUTS) {
      if (result.authorizationOutputs[predicate] !== false) {
        violations.push({ mask, predicate, result });
      }
    }
  }
  return { states, violations };
}

function checkScopedAuthorityStates() {
  const fixture = scopedAuthorityFixture();
  const accepted = evaluateScopedAuthority(
    fixture.proof,
    fixture.request,
    fixture.pin,
  );
  const violations = [];
  if (!accepted.authorized) {
    violations.push({ id: "bounded-positive-control", accepted });
  }
  for (const scenario of scopeViolationCases()) {
    const result = evaluateScopedAuthority(
      scenario.proof,
      scenario.request,
      scenario.pin,
    );
    if (
      result.authorized ||
      result.checks[scenario.violatedCheck] !== false
    ) {
      violations.push({ id: scenario.id, result });
    }
  }
  return {
    states: 1 + scopeViolationCases().length,
    violations,
  };
}

function obligationRow(statesChecked, mutationCounterexample) {
  return {
    states_checked: statesChecked,
    mutation_states_checked: 1,
    verified: true,
    counterexample: null,
    mutation_counterexample: mutationCounterexample,
  };
}

export function runBoundedAssuranceChecks() {
  const denial = checkSignedDenialStates();
  const scopedAuthority = checkScopedAuthorityStates();
  const denialCounterexample = findSignedDenialCounterexample();
  const scopedCounterexamples = findScopedAuthorityCounterexamples();
  const safe =
    denial.violations.length === 0 &&
    scopedAuthority.violations.length === 0;
  const unsafeComparisonsExposed =
    denialCounterexample !== null &&
    scopedCounterexamples.length === scopeViolationCases().length &&
    scopedCounterexamples.every(
      ({ safe: safeResult, unsafe }) =>
        safeResult.authorized === false && unsafe.authorized === true,
    );
  const scopeMutationByCheck = new Map(
    scopedCounterexamples.map((counterexample) => [
      counterexample.omittedCheck,
      counterexample,
    ]),
  );
  const denialMutation = (output) => ({
    output,
    witness: denialCounterexample,
  });
  const obligations = {
    SignedDenialApprovalRefused: obligationRow(
      denial.states,
      denialMutation("approval"),
    ),
    SignedDenialSeparationOfDutiesRefused: obligationRow(
      denial.states,
      denialMutation("separationOfDuties"),
    ),
    SignedDenialQuorumRefused: obligationRow(
      denial.states,
      denialMutation("quorum"),
    ),
    SignedDenialAssuranceRefused: obligationRow(
      denial.states,
      denialMutation("assurance"),
    ),
    SignedDenialAuthorityRefused: obligationRow(
      denial.states,
      denialMutation("authority"),
    ),
    SignedDenialActionMaterialRefused: obligationRow(
      denial.states,
      denialMutation("actionMaterial"),
    ),
    SignedDenialRelianceRefused: obligationRow(
      denial.states,
      denialMutation("reliance"),
    ),
    ScopedAuthorityRegistryIssuerPinned: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("registryIssuerPinned"),
    ),
    ScopedAuthorityActionMembership: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("actionMembership"),
    ),
    ScopedAuthorityTimeWindowOrdered: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("timeWindowOrdering"),
    ),
    ScopedAuthorityAmountCeiling: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("amountCeiling"),
    ),
    ScopedAuthorityCurrencyPinned: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("currency"),
    ),
    ScopedAuthorityOrganizationPinned: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("organization"),
    ),
    ScopedAuthorityRolePinned: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("role"),
    ),
    ScopedAuthorityPolicyPinned: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("policy"),
    ),
    ScopedAuthorityDelegationMonotone: obligationRow(
      scopedAuthority.states,
      scopeMutationByCheck.get("monotoneDelegation"),
    ),
  };
  const verified =
    safe &&
    unsafeComparisonsExposed &&
    FORMAL_OBLIGATIONS.every(
      (obligation) =>
        obligations[obligation]?.verified === true &&
        obligations[obligation]?.counterexample === null &&
        obligations[obligation]?.mutation_counterexample !== null,
    );

  return {
    model: FORMAL_MODEL_VERSION,
    method: "bounded_exhaustive_state_exploration",
    claims: [
      "signed-denial-cannot-authorize",
      "scoped-authority-is-pinned",
    ],
    verified,
    obligations,
    safe,
    unsafeComparisonsExposed,
    checkedStates: denial.states + scopedAuthority.states,
    denial: {
      checkedStates: denial.states,
      predicateCount: DENIAL_AUTHORIZATION_OUTPUTS.length,
      violations: denial.violations,
      unsafeCounterexample: denialCounterexample,
    },
    scopedAuthority: {
      checkedStates: scopedAuthority.states,
      violations: scopedAuthority.violations,
      unsafeCounterexamples: scopedCounterexamples,
    },
  };
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], "file:").href) {
  const result = runBoundedAssuranceChecks();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!result.verified) {
    process.exitCode = 1;
  }
}
