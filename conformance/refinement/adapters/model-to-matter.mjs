// SPDX-License-Identifier: Apache-2.0
// Generated from model-to-matter.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from "node:crypto";
import { M2M_EVIDENCE_TYPES, buildModelToMatterGraph, createModelToMatterAction, createModelToMatterExecutor, createModelToMatterProfile, modelToMatterActionDigest, modelToMatterCaid, signModelToMatterEvidence, } from "../../../lib/frontier/model-to-matter.js";
import { createDurableChallengeStore } from "../../../packages/gate/challenge-store.js";
import { createDurableConsumptionStore, createMemoryBackend, } from "../../../packages/gate/store.js";
const NOW = "2026-07-11T16:00:00Z";
const ISSUED_AT = "2026-07-11T15:59:00Z";
const EVIDENCE_EXPIRES = "2026-07-11T16:10:00Z";
const EXACT_CAID = "caid:exact-action";
const OTHER_CAID = "caid:other-action";
function digest(label) {
    return `sha256:${crypto.createHash("sha256").update(label).digest("hex")}`;
}
function deterministicPrivateKey(label) {
    const seed = crypto
        .createHash("sha256")
        .update(`emilia-formal-refinement:${label}`)
        .digest();
    const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
    return crypto.createPrivateKey({
        key: Buffer.concat([pkcs8Prefix, seed]),
        format: "der",
        type: "pkcs8",
    });
}
function publicKey(privateKey) {
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
    return crypto
        .createPublicKey(privatePem)
        .export({ type: "spki", format: "der" })
        .toString("base64url");
}
const evidenceKeys = Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [type, deterministicPrivateKey(type)]));
const ACTION_INPUT = Object.freeze({
    action_type: "science.bio.experiment.execute.1",
    model: {
        provider: "example-frontier-lab",
        model_id: "frontier-bio-model-refinement",
        manifest_digest: digest("model-manifest"),
        harness_digest: digest("agent-harness"),
        safeguards_digest: digest("deployment-safeguards"),
    },
    experiment: {
        protocol_digest: digest("benign-protocol"),
        materials_commitment: digest("opaque-materials"),
        expected_effects_digest: digest("approved-effect-criteria"),
    },
    principal: {
        organization_id: "org:example-university",
        principal_id: "researcher:alice",
    },
    executor: {
        executor_id: "cloud-lab:example",
        facility_id: "facility:safe-demo-01",
    },
    purpose: {
        code: "defensive-research",
        jurisdiction: "US",
    },
    destination_digest: digest("approved-destination"),
    requested_at: "2026-07-11T15:58:00Z",
    max_executions: 1,
});
function createAction(overrides = {}) {
    return createModelToMatterAction({
        ...structuredClone(ACTION_INPUT),
        ...structuredClone(overrides),
    });
}
function createProfile() {
    return createModelToMatterProfile({
        profile_id: "ep:m2m:formal-refinement:v1",
        accepted_issuers: Object.fromEntries(M2M_EVIDENCE_TYPES.map((type) => [
            type,
            [
                {
                    issuer_id: `issuer:${type}`,
                    public_key: publicKey(evidenceKeys[type]),
                },
            ],
        ])),
    });
}
function claimsFor(type, action) {
    if (type === "model_attestation") {
        return {
            provider: action.model.provider,
            model_id: action.model.model_id,
            manifest_digest: action.model.manifest_digest,
            harness_digest: action.model.harness_digest,
            safeguards_digest: action.model.safeguards_digest,
        };
    }
    if (type === "safety_case_attestation") {
        return {
            manifest_digest: action.model.manifest_digest,
            harness_digest: action.model.harness_digest,
            safeguards_digest: action.model.safeguards_digest,
            safety_case_digest: digest("frontier-safety-case"),
            assessment: "acceptable",
        };
    }
    if (type === "institutional_authority") {
        return {
            organization_id: action.principal.organization_id,
            principal_id: action.principal.principal_id,
            action_type: action.action_type,
            purpose_code: action.purpose.code,
            decision: "allow",
        };
    }
    if (type === "biosafety_review") {
        return {
            protocol_digest: action.experiment.protocol_digest,
            materials_commitment: action.experiment.materials_commitment,
            facility_id: action.executor.facility_id,
            decision: "approve",
        };
    }
    if (type === "domain_screening") {
        return {
            materials_commitment: action.experiment.materials_commitment,
            destination_digest: action.destination_digest,
            screening_profile_digest: digest("screening-profile"),
            decision: "pass",
        };
    }
    if (type === "human_authorization") {
        return {
            approver_id: "person:responsible-investigator",
            decision: "approve",
            assurance_class: "class_a",
        };
    }
    throw new Error(`unknown Model-to-Matter evidence type: ${type}`);
}
function signedEvidence(action, type) {
    return signModelToMatterEvidence({
        evidence_type: type,
        action_digest: modelToMatterActionDigest(action),
        issuer_id: `issuer:${type}`,
        issued_at: ISSUED_AT,
        expires_at: EVIDENCE_EXPIRES,
        claims: claimsFor(type, action),
    }, evidenceKeys[type]);
}
function evidenceSet(action, mismatchedType, otherAction) {
    return M2M_EVIDENCE_TYPES.map((type) => type === mismatchedType
        ? signedEvidence(otherAction, type)
        : signedEvidence(action, type));
}
function createExecutor() {
    return createModelToMatterExecutor({
        profile: createProfile(),
        challengeStore: createDurableChallengeStore(createMemoryBackend()),
        clearanceStore: createDurableConsumptionStore(createMemoryBackend()),
        revocationProvider: async () => new Set(),
        allowEphemeralState: true,
        now: () => Date.parse(NOW),
    });
}
async function clearanceOnceScenario() {
    const action = createAction();
    const gate = createExecutor();
    const challenge = await gate.issueChallenge(action, {
        nonce: "m2m-refinement-clearance-once",
    });
    const graph = buildModelToMatterGraph(action, evidenceSet(action));
    let effectCalls = 0;
    const first = await gate.run({ action, challenge, graph }, async () => {
        effectCalls += 1;
        return "executed";
    });
    const replay = await gate.run({ action, challenge, graph }, async () => {
        effectCalls += 1;
        return "unexpected-replay";
    });
    const actualCaid = modelToMatterCaid(action).caid;
    if (first.ok !== true ||
        first.clearance?.action_caid !== actualCaid ||
        replay.ok !== false ||
        replay.allow !== false ||
        effectCalls !== 1) {
        throw new Error("Model-to-Matter runtime did not enforce exact single-use clearance");
    }
    return {
        scenario: "model-to-matter-clearance-once",
        steps: [
            {
                operator: "PresentSixExactLegs",
                accepted: true,
                projection: {
                    m2mState: "ready",
                    m2mPresentedCaid: EXACT_CAID,
                    m2mConsumptionCount: 0,
                },
            },
            {
                operator: "ConsumeModelToMatterClearance",
                accepted: true,
                projection: {
                    m2mState: "consumed",
                    m2mPresentedCaid: EXACT_CAID,
                    m2mConsumptionCount: 1,
                },
            },
            {
                operator: "AttemptModelToMatterReplay",
                accepted: false,
                projection: {
                    m2mState: "replay_refused",
                    m2mPresentedCaid: EXACT_CAID,
                    m2mConsumptionCount: 1,
                },
            },
        ],
    };
}
async function mismatchRefusedScenario() {
    const action = createAction();
    const otherAction = createAction({
        destination_digest: digest("unapproved-destination"),
    });
    const gate = createExecutor();
    const challenge = await gate.issueChallenge(action, {
        nonce: "m2m-refinement-mismatch",
    });
    const graph = buildModelToMatterGraph(action, evidenceSet(action, "domain_screening", otherAction));
    let effectCalls = 0;
    const result = await gate.run({ action, challenge, graph }, async () => {
        effectCalls += 1;
        return "must-not-execute";
    });
    if (result.ok !== false ||
        result.allow !== false ||
        result.clearance?.clear_to_execute !== false ||
        effectCalls !== 0) {
        throw new Error("Model-to-Matter mismatched evidence runtime attempt was not refused");
    }
    return {
        scenario: "model-to-matter-mismatch-refused",
        steps: [
            {
                operator: "PresentMismatchedLeg",
                accepted: true,
                projection: {
                    m2mState: "mismatch_presented",
                    m2mPresentedCaid: OTHER_CAID,
                    m2mConsumptionCount: 0,
                },
            },
            {
                operator: "RefuseModelToMatterClearance",
                accepted: false,
                projection: {
                    m2mState: "refused",
                    m2mPresentedCaid: OTHER_CAID,
                    m2mConsumptionCount: 0,
                },
            },
        ],
    };
}
export async function runModelToMatterScenario(scenario) {
    if (scenario === "model-to-matter-clearance-once")
        return clearanceOnceScenario();
    if (scenario === "model-to-matter-mismatch-refused")
        return mismatchRefusedScenario();
    throw new Error(`unknown Model-to-Matter refinement scenario: ${scenario}`);
}
