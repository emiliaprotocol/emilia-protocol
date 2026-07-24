// SPDX-License-Identifier: Apache-2.0
// Generated from index.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { runActionEscrowScenario } from "./action-escrow.mjs";
import { runAecScenario } from "./aec.mjs";
import { runConsequenceLifecycleScenario } from "./consequence-lifecycle.mjs";
import { runGraceScenario } from "./grace-curtailment.mjs";
import { runMobileContinuityScenario } from "./mobile-continuity.mjs";
import { runMobileEnrollmentScenario } from "./mobile-enrollment.mjs";
import { runModelToMatterScenario } from "./model-to-matter.mjs";
import { runNetworkWitnessScenario } from "./network-witness.mjs";
import { runRevocationScenario } from "./revocation.mjs";
const adapters = Object.freeze({
    "action-escrow": runActionEscrowScenario,
    aec: runAecScenario,
    "consequence-lifecycle": runConsequenceLifecycleScenario,
    grace: runGraceScenario,
    "mobile-continuity": runMobileContinuityScenario,
    "mobile-enrollment": runMobileEnrollmentScenario,
    "model-to-matter": runModelToMatterScenario,
    "network-witness": runNetworkWitnessScenario,
    revocation: runRevocationScenario,
});
export function getRuntimeAdapter(name) {
    const adapter = adapters[name];
    if (!adapter)
        throw new Error(`unknown refinement adapter: ${name}`);
    return adapter;
}
export const runtimeAdapterNames = Object.freeze(Object.keys(adapters).sort());
