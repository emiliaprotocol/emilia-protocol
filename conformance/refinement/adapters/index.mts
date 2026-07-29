// SPDX-License-Identifier: Apache-2.0

import type { RuntimeAdapter } from "../types.mjs";
import { runActionEscrowScenario } from "./action-escrow.mjs";
import { runAecScenario } from "./aec.mjs";
import { runAecExecutionFleetAssuranceScenario } from "./aec-execution-fleet-assurance.mjs";
import { runConsequenceLifecycleScenario } from "./consequence-lifecycle.mjs";
import { runComposedTrustLifecycleScenario } from "./composed-trust-lifecycle.mjs";
import { runCompleteMediationScenario } from "./complete-mediation.mjs";
import { runDurableConsumptionOwnerScenario } from "./durable-consumption-owner.mjs";
import {
  runAuthorityDocumentProofJoinScenario,
  runAuthorityProgramScenario,
  runConservationAuthorityScenario,
  runOutcomeBindingScenario,
  runOutcomeSourceScenario,
  runReceiptProgramScenario,
} from "./five-claim-bridge.mjs";
import { runGraceScenario } from "./grace-curtailment.mjs";
import { runMobileContinuityScenario } from "./mobile-continuity.mjs";
import { runMobileEnrollmentScenario } from "./mobile-enrollment.mjs";
import { runModelToMatterScenario } from "./model-to-matter.mjs";
import { runNetworkWitnessScenario } from "./network-witness.mjs";
import { runEvidenceChallengeLifecycleScenario } from "./evidence-challenge-lifecycle.mjs";
import { runReliancePinnedProfileScenario } from "./reliance-pinned-profile.mjs";
import { runRevocationScenario } from "./revocation.mjs";
import { runTwoClaimAssuranceScenario } from "./two-claim-assurance.mjs";

const adapters: Readonly<Record<string, RuntimeAdapter>> = Object.freeze({
  "action-escrow": runActionEscrowScenario,
  aec: runAecScenario,
  "aec-execution-fleet-assurance": runAecExecutionFleetAssuranceScenario,
  "consequence-lifecycle": runConsequenceLifecycleScenario,
  "composed-trust-lifecycle": runComposedTrustLifecycleScenario,
  "complete-mediation": runCompleteMediationScenario,
  "durable-consumption-owner": runDurableConsumptionOwnerScenario,
  "conservation-authority": runConservationAuthorityScenario,
  "outcome-binding": runOutcomeBindingScenario,
  "outcome-binding-sources": runOutcomeSourceScenario,
  "authority-document-proof-join": runAuthorityDocumentProofJoinScenario,
  "authority-program": runAuthorityProgramScenario,
  "receipt-program": runReceiptProgramScenario,
  grace: runGraceScenario,
  "mobile-continuity": runMobileContinuityScenario,
  "mobile-enrollment": runMobileEnrollmentScenario,
  "model-to-matter": runModelToMatterScenario,
  "network-witness": runNetworkWitnessScenario,
  "evidence-challenge-lifecycle": runEvidenceChallengeLifecycleScenario,
  "reliance-pinned-profile": runReliancePinnedProfileScenario,
  revocation: runRevocationScenario,
  "two-claim-assurance": runTwoClaimAssuranceScenario,
});

export function getRuntimeAdapter(name: string): RuntimeAdapter {
  const adapter = adapters[name];
  if (!adapter) throw new Error(`unknown refinement adapter: ${name}`);
  return adapter;
}

export const runtimeAdapterNames = Object.freeze(Object.keys(adapters).sort());
