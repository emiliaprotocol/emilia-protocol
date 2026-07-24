// SPDX-License-Identifier: Apache-2.0

import {
  AEC_VERSION,
  actionDigest,
  verifyAuthorizationChain,
} from "../../../packages/verify/evidence-chain.js";
import type { RuntimeScenarioResult } from "../types.mjs";

const ACTION = Object.freeze({
  action_type: "wire.release",
  target: "treasury.example/wire/refinement-1",
  amount: "25000.00",
  currency: "USD",
});

const ACTION_DIGEST = `sha256:${actionDigest(ACTION)}`;

function boundVerifier() {
  return {
    valid: true,
    action_digest: ACTION_DIGEST,
  };
}

function exactRoleScenario(): RuntimeScenarioResult {
  const result = verifyAuthorizationChain(
    {
      "@version": AEC_VERSION,
      action: ACTION,
      requirement: "machine_policy AND human_authority",
      components: [
        { type: "machine_policy", evidence: { decision: "allow" } },
        { type: "human_authority", evidence: { decision: "approve" } },
      ],
    },
    {
      requirement: "machine_policy AND human_authority",
      expectedActionDigest: ACTION_DIGEST,
      verifiers: {
        machine_policy: boundVerifier,
        human_authority: boundVerifier,
      },
    },
  );

  if (
    result.allow !== true ||
    result.expected_action_bound !== true ||
    result.components?.length !== 2 ||
    result.components.some(
      (component) => component.valid !== true || component.bound !== true,
    )
  ) {
    throw new Error("AEC exact-role runtime verification did not authorize");
  }

  return {
    scenario: "aec-exact-role-map",
    steps: [
      {
        operator: "PresentExactAecRoles",
        accepted: true,
        projection: {
          aecState: "exact_roles_presented",
        },
      },
      {
        operator: "AcceptAec",
        accepted: true,
        projection: {
          aecState: "accepted",
        },
      },
    ],
  };
}

function substitutedRoleScenario(): RuntimeScenarioResult {
  const result = verifyAuthorizationChain(
    {
      "@version": AEC_VERSION,
      action: ACTION,
      requirement: "machine_policy AND operator_substitute",
      components: [
        { type: "machine_policy", evidence: { decision: "allow" } },
        { type: "operator_substitute", evidence: { decision: "approve" } },
      ],
    },
    {
      requirement: "machine_policy AND human_authority",
      expectedActionDigest: ACTION_DIGEST,
      verifiers: {
        machine_policy: boundVerifier,
        operator_substitute: boundVerifier,
      },
    },
  );

  const evidenceWasCryptographicallyAdmitted =
    result.components?.length === 2 &&
    result.components.every(
      (component) => component.valid === true && component.bound === true,
    );
  if (
    !evidenceWasCryptographicallyAdmitted ||
    result.allow !== false ||
    result.satisfied !== false
  ) {
    throw new Error(
      "AEC substituted-role runtime attempt was not refused at the requirement boundary",
    );
  }

  return {
    scenario: "aec-role-substitution-refused",
    steps: [
      {
        operator: "PresentSubstitutedAecRole",
        accepted: true,
        projection: {
          aecState: "substitution_presented",
        },
      },
      {
        operator: "RefuseAec",
        accepted: false,
        projection: {
          aecState: "refused",
        },
      },
    ],
  };
}

export async function runAecScenario(
  scenario: string,
): Promise<RuntimeScenarioResult> {
  if (scenario === "aec-exact-role-map") return exactRoleScenario();
  if (scenario === "aec-role-substitution-refused")
    return substitutedRoleScenario();
  throw new Error(`unknown AEC refinement scenario: ${scenario}`);
}
