// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DENIAL_AUTHORIZATION_OUTPUTS,
  evaluateSignedDecision,
  evaluateScopedAuthority,
  scopeViolationCases,
  scopedAuthorityFixture,
  signedDenialFixture,
} from "../formal/two-claim-assurance.model.mjs";
import {
  findSignedDenialCounterexample,
  findScopedAuthorityCounterexamples,
} from "../formal/two-claim-assurance.unsafe.mjs";
import {
  createStandaloneChallengeProjection,
  runScopedAuthorityRuntimeScenarios,
  runSignedDenialRuntimeScenario,
} from "../conformance/refinement/adapters/two-claim-assurance.mts";

const TRUST_RECEIPT_SUITE = JSON.parse(
  fs.readFileSync(
    new URL(
      "../conformance/vectors/trust-receipt.exec.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

describe("bounded assurance closure for exactly two claims", () => {
  it("models every signed-denial authorization output independently", () => {
    const fixture = signedDenialFixture();
    const result = evaluateSignedDecision(fixture);

    expect(result.decisionEvidenceVerified).toBe(true);
    expect(result.decision).toBe("denied");
    expect(result.challengeContext).toEqual(fixture.challengeContext);
    expect(result.challengeAuthorizes).toBe(false);
    expect(result.challengeIsReceipt).toBe(false);
    expect(Object.keys(result.authorizationOutputs).sort()).toEqual(
      [...DENIAL_AUTHORIZATION_OUTPUTS].sort(),
    );
    for (const predicate of DENIAL_AUTHORIZATION_OUTPUTS) {
      expect(result.authorizationOutputs[predicate], predicate).toBe(false);
    }

    const approved = evaluateSignedDecision({
      ...fixture,
      decision: "approved",
    });
    for (const predicate of DENIAL_AUTHORIZATION_OUTPUTS) {
      expect(approved.authorizationOutputs[predicate], predicate).toBe(true);
    }
  });

  it("models every pinned-scope dimension and rejects each isolated violation", () => {
    const fixture = scopedAuthorityFixture();
    const accepted = evaluateScopedAuthority(
      fixture.proof,
      fixture.request,
      fixture.pin,
    );

    expect(accepted.authorized).toBe(true);
    expect(Object.values(accepted.checks).every(Boolean)).toBe(true);

    for (const scenario of scopeViolationCases()) {
      const result = evaluateScopedAuthority(
        scenario.proof,
        scenario.request,
        scenario.pin,
      );
      expect(result.authorized, scenario.id).toBe(false);
      expect(result.checks[scenario.violatedCheck], scenario.id).toBe(false);
    }
  });

  it("requires deliberate unsafe variants to produce concrete counterexamples", () => {
    const denialCounterexample = findSignedDenialCounterexample();
    expect(denialCounterexample).not.toBeNull();
    expect(denialCounterexample?.input.decision).toBe("denied");
    expect(
      Object.values(denialCounterexample?.unsafe.authorizationOutputs ?? {})
        .some(Boolean),
    ).toBe(true);

    const scopedCounterexamples = findScopedAuthorityCounterexamples();
    const expectedChecks = scopeViolationCases().map(
      (scenario) => scenario.violatedCheck,
    );
    expect(scopedCounterexamples.map((counterexample) => counterexample.omittedCheck))
      .toEqual(expectedChecks);
    for (const counterexample of scopedCounterexamples) {
      expect(counterexample.safe.authorized).toBe(false);
      expect(counterexample.unsafe.authorized).toBe(true);
    }
  });

  it("replays a signed denial through the public Trust Receipt verifier", () => {
    const vector = TRUST_RECEIPT_SUITE.vectors.find(
      (candidate: any) =>
        candidate.id === "reject_signed_denial_as_authorization",
    );
    const result = runSignedDenialRuntimeScenario(vector);

    expect(result.publicEntryPoint).toBe("verifyTrustReceipt");
    expect(result.decisionEvidenceVerified).toBe(true);
    expect(result.verifierResult.checks.signoff_signatures).toBe(true);
    expect(result.verifierResult.checks.sod).toBe(false);
    expect(result.verifierResult.valid).toBe(false);
    for (const predicate of DENIAL_AUTHORIZATION_OUTPUTS) {
      expect(result.authorizationOutputs[predicate], predicate).toBe(false);
    }
  });

  it("replays every pinned-scope refusal through public authority entry points", () => {
    const result = runScopedAuthorityRuntimeScenarios();

    expect(result.publicEntryPoints).toEqual([
      "verifyAuthorityProof",
      "evaluateAuthorityVerdict",
    ]);
    expect(result.acceptedProof.accepted).toBe(true);
    expect(result.unpinnedIssuer.accepted).toBe(false);
    expect(result.unpinnedIssuer.reason).toBe("pin_mismatched_issuer");
    expect(result.acceptedScope.authorized).toBe(true);

    const expected = {
      action_membership: "wrong_scope",
      time_before_window: "not_yet_valid",
      time_after_window: "expired_authority",
      amount_ceiling: "amount_exceeded",
      currency: "amount_exceeded",
      organization: "unknown_authority",
      role: "wrong_role",
      policy: "policy_mismatch",
      delegation_action_widening: "delegation_broken",
      delegation_time_widening: "delegation_broken",
      delegation_amount_widening: "delegation_broken",
      delegation_currency_widening: "delegation_broken",
      delegation_organization_widening: "delegation_broken",
      delegation_policy_widening: "delegation_broken",
    };
    expect(
      Object.fromEntries(
        Object.entries(result.refusals).map(([id, refusal]: [string, any]) => [
          id,
          refusal.verdict,
        ]),
      ),
    ).toEqual(expected);
    for (const refusal of Object.values(result.refusals) as any[]) {
      expect(refusal.authorized).toBe(false);
    }
  });

  it("preserves a standalone challenge without treating it as authorization or a receipt", () => {
    const action = {
      action_type: "wire.release",
      organization_id: "org-a",
      amount: "100.00",
      currency: "USD",
    };
    const policy = {
      policy_id: "policy:wire-release:v1",
      reliance_purpose: "authorize a bounded wire release",
      requirement: "authorization_receipt AND workload_identity",
      freshness_sec: {
        authorization_receipt: 300,
        workload_identity: 60,
      },
      profiles: {
        authorization_receipt: "EP-TRUST-RECEIPT-v1",
        workload_identity: "EP-WORKLOAD-IDENTITY-v1",
      },
    };
    const projection = createStandaloneChallengeProjection(action, policy, {
      challenge_id: "challenge-two-claim-boundary",
      expires_at: "2026-07-24T20:05:00.000Z",
      nonce: "challenge_nonce_123456",
      audience: "rp:bounded-assurance",
    });

    expect(projection.authorization).toBe(false);
    expect(projection.receipt).toBe(false);
    expect(projection.challenge.action_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(projection.challenge.required_evidence).toEqual([
      {
        type: "authorization_receipt",
        max_age_sec: 300,
        profile: "EP-TRUST-RECEIPT-v1",
      },
      {
        type: "workload_identity",
        max_age_sec: 60,
        profile: "EP-WORKLOAD-IDENTITY-v1",
      },
    ]);
    expect(projection.challenge.policy_id).toBe(policy.policy_id);
    expect(projection.challenge.policy_digest).toMatch(
      /^sha256:[0-9a-f]{64}$/,
    );
    expect(projection.challenge.reliance_purpose).toBe(
      policy.reliance_purpose,
    );
    expect(projection.challenge.expires_at).toBe(
      "2026-07-24T20:05:00.000Z",
    );
    expect(projection.challenge.nonce).toBe("challenge_nonce_123456");
    expect(projection.challenge.present_as).toEqual(["ep-aec-v1"]);
    expect(projection.preserved).toEqual(projection.challenge);
  });
});
