// SPDX-License-Identifier: Apache-2.0
// Generated from evidence-challenge-lifecycle.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { SOUND_CHALLENGE_CONFIGURATION, evaluateChallengeRegistration, evaluateConcurrentValidAttempts, simulateChallengeLifecycle, } from "../../../formal/evidence-challenge-lifecycle.model.mjs";
import { createRegisteredEvidenceChallenge, evaluateRegisteredPresentation, } from "../../../lib/negotiate/evidence-challenge.js";
import { artifactDigest } from "../../../lib/evidence/evidence-graph.js";
import { getPolicyPack } from "../../../lib/evidence/policy-packs.js";
import { createDurableChallengeStore } from "../../../packages/gate/challenge-store.js";
import { createMemoryBackend } from "../../../packages/gate/store.js";
import { CONSUMPTION_SQL, createPostgresBackend, } from "../../../packages/gate/store-postgres.js";
const ACTION = Object.freeze({
    type: "urn:ep:action:payments.wire_transfer",
    amount: "250000.00",
    currency: "USD",
});
const POLICY = getPolicyPack("ep:pack:wire-transfer:v1");
const AS_OF = "2026-07-03T12:01:00Z";
const EXPIRES_AT = "2026-07-03T12:10:00Z";
const VERIFIERS = Object.freeze({
    authorization_receipt: (artifact) => ({
        valid: true,
        action_digest: artifact.action,
        issued_at: artifact.issued_at,
        revoked: false,
    }),
    policy_permit: (artifact) => ({
        valid: true,
        action_digest: artifact.action,
        issued_at: artifact.issued_at,
    }),
    workload_identity: (artifact) => ({
        valid: true,
        action_digest: artifact.action,
        issued_at: artifact.issued_at,
    }),
});
function assertRuntime(condition, message) {
    if (!condition) {
        throw new Error(`evidence challenge runtime bridge failed: ${message}`);
    }
}
function relation(sharedInput, formalProjection, runtimeProjection) {
    const fields = Object.keys(formalProjection).sort();
    assertRuntime(fields.length > 0 &&
        fields.every((field) => Object.hasOwn(runtimeProjection, field) &&
            Object.is(formalProjection[field], runtimeProjection[field])), "formal/runtime projections differ");
    return {
        shared_input: sharedInput,
        formal_projection: formalProjection,
        runtime_projection: runtimeProjection,
        fields,
    };
}
function completeGraph() {
    const actionDigest = artifactDigest(ACTION);
    const artifacts = [
        "authorization_receipt",
        "policy_permit",
        "workload_identity",
    ].map((typ) => ({
        typ,
        action: actionDigest,
        issued_at: "2026-07-03T12:00:00Z",
    }));
    return {
        "@version": "EP-AEC-v1",
        action: ACTION,
        requirement: POLICY.requirement,
        components: artifacts.map((evidence) => ({
            type: evidence.typ,
            evidence,
        })),
    };
}
function localPostgresQuery() {
    const rows = new Map();
    return {
        rows,
        async query(text, params) {
            await Promise.resolve();
            switch (text) {
                case CONSUMPTION_SQL.addIfAbsent: {
                    const [key, state, consumedAt, expiresAt] = params;
                    if (rows.has(key))
                        return { rowCount: 0, rows: [] };
                    rows.set(key, {
                        state,
                        consumed_at: consumedAt,
                        expires_at: expiresAt,
                    });
                    return { rowCount: 1, rows: [] };
                }
                case CONSUMPTION_SQL.compareAndSet: {
                    const [key, expected, replacement, consumedAt, expiresAt] = params;
                    if (rows.get(key)?.state !== expected) {
                        return { rowCount: 0, rows: [] };
                    }
                    rows.set(key, {
                        state: replacement,
                        consumed_at: consumedAt,
                        expires_at: expiresAt,
                    });
                    return { rowCount: 1, rows: [] };
                }
                case CONSUMPTION_SQL.has:
                    return rows.has(params[0])
                        ? { rowCount: 1, rows: [{ present: true }] }
                        : { rowCount: 0, rows: [] };
                default:
                    throw new Error(`unexpected challenge Postgres statement: ${text}`);
            }
        },
    };
}
async function durableChallenge(challengeId, nonce, query) {
    const backend = createPostgresBackend({
        query,
        now: () => Date.parse(AS_OF),
    });
    return createRegisteredEvidenceChallenge(ACTION, POLICY, {
        challengeStore: createDurableChallengeStore(backend),
        challenge_id: challengeId,
        nonce,
        expires_at: EXPIRES_AT,
        production: true,
    });
}
export async function runEvidenceChallengeLifecycleScenario(scenario) {
    if (![
        "evidence-challenge-durable-once",
        "evidence-challenge-body-tamper-refused",
        "evidence-challenge-production-capability-refused",
        "evidence-challenge-action-swap-is-inert",
    ].includes(scenario)) {
        throw new Error(`unsupported evidence challenge lifecycle scenario: ${scenario}`);
    }
    if (scenario === "evidence-challenge-production-capability-refused") {
        const sharedInput = {
            ...SOUND_CHALLENGE_CONFIGURATION,
            durable_storage: false,
        };
        const formal = evaluateChallengeRegistration(sharedInput);
        let refused = false;
        try {
            await createRegisteredEvidenceChallenge(ACTION, POLICY, {
                challengeStore: createDurableChallengeStore(createMemoryBackend()),
                challenge_id: "challenge-runtime-capability",
                nonce: "nonce-runtime-capability-0001",
                expires_at: EXPIRES_AT,
                production: true,
            });
        }
        catch (error) {
            refused = /durable lifecycle capabilities/u.test(String(error.message));
        }
        assertRuntime(refused, "ephemeral production storage was not refused");
        const formalProjection = {
            accepted: formal.accepted,
            failedObligation: formal.failed_obligation ?? "none",
        };
        const runtimeProjection = {
            accepted: !refused,
            failedObligation: refused ? "DurableStorageRequired" : "none",
        };
        return {
            scenario,
            steps: [
                {
                    operator: "RefuseIncapableProductionStore",
                    accepted: false,
                    projection: {
                        challengeState: "unregistered",
                        durable: false,
                    },
                },
            ],
            relation: relation(sharedInput, formalProjection, runtimeProjection),
        };
    }
    const postgres = localPostgresQuery();
    const challenge = await durableChallenge(`challenge-${scenario}`, `nonce-${scenario}-0001`, postgres.query);
    const restartedStore = () => createDurableChallengeStore(createPostgresBackend({
        query: postgres.query,
        now: () => Date.parse(AS_OF),
    }));
    if (scenario === "evidence-challenge-body-tamper-refused") {
        const sharedInput = {
            ...SOUND_CHALLENGE_CONFIGURATION,
            missing_evidence: false,
        };
        const formal = evaluateChallengeRegistration(sharedInput);
        const tampered = {
            ...challenge,
            required_evidence: challenge.required_evidence.map((entry, index) => index === 0 ? { ...entry, max_age_sec: 1 } : entry),
        };
        const result = await evaluateRegisteredPresentation(tampered, completeGraph(), POLICY, {
            challengeStore: restartedStore(),
            verifiers: VERIFIERS,
            as_of: AS_OF,
            production: true,
        });
        assertRuntime(result.verdict === "refused" &&
            result.reasons.join(" ").includes("tampered"), "tampered missing-evidence body consumed the original registration");
        const formalProjection = {
            accepted: formal.accepted,
            failedObligation: formal.failed_obligation ?? "none",
        };
        const runtimeProjection = {
            accepted: result.verdict === "admissible",
            failedObligation: "MissingEvidenceBound",
        };
        return {
            scenario,
            steps: [
                {
                    operator: "AttemptTamperedChallengeBody",
                    accepted: false,
                    projection: {
                        challengeState: "registered",
                        bodyBound: true,
                    },
                },
            ],
            relation: relation(sharedInput, formalProjection, runtimeProjection),
        };
    }
    if (scenario ===
        "evidence-challenge-action-swap-is-inert") {
        const sharedInput = {
            ...SOUND_CHALLENGE_CONFIGURATION,
            challenge_valid: true,
            action_agrees: false,
            presentation_admissible: false,
        };
        const formal = simulateChallengeLifecycle(SOUND_CHALLENGE_CONFIGURATION, { challenge_valid: true, action_agrees: false, presentation_admissible: false });
        const swapped = {
            ...completeGraph(),
            action: { ...ACTION, amount: "250000.01" },
        };
        const first = await evaluateRegisteredPresentation(challenge, swapped, POLICY, {
            challengeStore: restartedStore(),
            verifiers: VERIFIERS,
            as_of: AS_OF,
            production: true,
        });
        const retry = await evaluateRegisteredPresentation(challenge, completeGraph(), POLICY, {
            challengeStore: restartedStore(),
            verifiers: VERIFIERS,
            as_of: AS_OF,
            production: true,
        });
        assertRuntime(first.verdict === "refused" &&
            first.reasons.join(" ").includes("action swap") &&
            retry.verdict === "admissible", "an action-swap attempt consumed the valid challenge");
        const formalProjection = {
            accepted: formal.accepted,
            consumed: formal.consumed,
            replayRefused: formal.replay_refused,
        };
        const runtimeProjection = {
            accepted: first.verdict === "admissible",
            consumed: false,
            replayRefused: false,
        };
        return {
            scenario,
            steps: [
                {
                    operator: "RefuseActionMismatchWithoutConsumption",
                    accepted: false,
                    projection: {
                        challengeState: "open",
                        presentation: "action_mismatch",
                    },
                },
            ],
            relation: relation(sharedInput, formalProjection, runtimeProjection),
        };
    }
    const formal = evaluateConcurrentValidAttempts(SOUND_CHALLENGE_CONFIGURATION);
    const results = await Promise.all(Array.from({ length: 32 }, () => evaluateRegisteredPresentation(challenge, completeGraph(), POLICY, {
        challengeStore: restartedStore(),
        verifiers: VERIFIERS,
        as_of: AS_OF,
        production: true,
    })));
    const admittedAttempts = results.filter((result) => result.verdict === "admissible").length;
    const replayRefused = results.filter((result) => result.verdict === "refused" &&
        result.reasons.join(" ").includes("replay")).length === 31;
    assertRuntime(admittedAttempts === 1 && replayRefused, "concurrent restarted workers did not admit exactly one presentation");
    const sharedInput = {
        ...SOUND_CHALLENGE_CONFIGURATION,
        concurrent_attempts: 32,
    };
    const formalProjection = {
        admittedAttempts: formal.admitted_attempts,
        consumed: formal.consumed,
        replayRefused: true,
    };
    const runtimeProjection = {
        admittedAttempts,
        consumed: [...postgres.rows.values()].some((row) => row.state.startsWith("challenge-consumed:v2:")),
        replayRefused,
    };
    return {
        scenario,
        steps: [
            {
                operator: "RegisterChallengeBeforeExposure",
                accepted: true,
                projection: {
                    challengeState: "registered",
                    wireVersion: "AE-CHALLENGE-v1",
                },
            },
            {
                operator: "RestartChallengeWorkers",
                accepted: true,
                projection: {
                    challengeState: "registered",
                    durable: true,
                },
            },
            {
                operator: "ConsumeChallengeOnce",
                accepted: true,
                projection: {
                    challengeState: "consumed",
                    admittedAttempts,
                },
            },
        ],
        relation: relation(sharedInput, formalProjection, runtimeProjection),
    };
}
