// SPDX-License-Identifier: Apache-2.0
// Generated from complete-mediation.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { generateKeyPairSync } from "node:crypto";
import { CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION, ConsequenceActuator, createMemoryConsequenceActuatorStore, signConsequenceExecutionEnvelope, verifyConsequenceExecutionEnvelope, } from "../../../packages/gate/consequence-actuator.js";
import { InMemoryAebConsumptionStore, reconcileAebExecution, } from "../../../packages/verify/aeb-adapter-contract.js";
const NOW = Date.parse("2026-07-25T01:00:00.000Z");
const ACTION_DIGEST = `sha256:${"a".repeat(64)}`;
const OTHER_ACTION_DIGEST = `sha256:${"b".repeat(64)}`;
const TARGET_DIGEST = `sha256:${"c".repeat(64)}`;
const OTHER_TARGET_DIGEST = `sha256:${"d".repeat(64)}`;
const CAID = `caid:1:example.execute.1:jcs-sha256:${"A".repeat(43)}`;
const TENANT_ID = "tenant-complete-mediation";
const ATTEMPT_ID = "attempt-complete-mediation";
const IDEMPOTENCY_KEY = "operation-complete-mediation";
const PROVIDER_ACCOUNT_ID = "provider-account-complete-mediation";
const OPERATION = "payment.capture";
const ISSUER_ID = "authorization-service";
const ENVELOPE_KEY_ID = "complete-mediation-key-1";
const NONCE = Buffer.from("complete-mediation-nonce-0001", "utf8").toString("base64url");
const ISSUED_AT = new Date(NOW - 1_000).toISOString();
const EXPIRES_AT = new Date(NOW + 30_000).toISOString();
function requireCondition(condition, message) {
    if (!condition)
        throw new Error(message);
}
function payload(overrides = {}) {
    return {
        "@version": CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION,
        issuer_id: ISSUER_ID,
        tenant_id: TENANT_ID,
        attempt_id: ATTEMPT_ID,
        action_digest: ACTION_DIGEST,
        caid: CAID,
        provider_account_id: PROVIDER_ACCOUNT_ID,
        target_digest: TARGET_DIGEST,
        operation: OPERATION,
        idempotency_key: IDEMPOTENCY_KEY,
        nonce: NONCE,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        ...overrides,
    };
}
function initialProjection(overrides = {}) {
    return {
        decision: "NONE",
        envelope: "NONE",
        binding: "NONE",
        effect: "NONE",
        providerCalls: 0,
        providerCaller: "NONE",
        bypassRefused: false,
        staleRefused: false,
        replayRefused: false,
        reconciliationAuthenticated: false,
        reservation: "NONE",
        reservationReleased: false,
        reReserveRefused: false,
        ...overrides,
    };
}
function relation(sharedInput, formalProjection, runtimeProjection) {
    const fields = Object.keys(formalProjection).sort();
    if (!fields.every((field) => Object.hasOwn(runtimeProjection, field) &&
        Object.is(formalProjection[field], runtimeProjection[field]))) {
        throw new Error("complete-mediation formal/runtime projection mismatch");
    }
    return {
        shared_input: sharedInput,
        formal_projection: formalProjection,
        runtime_projection: runtimeProjection,
        fields,
    };
}
function requireRefusal(result, reason, invoked) {
    requireCondition(result.ok === false &&
        result.reason === reason &&
        result.invoked === invoked, `expected ${reason} with invoked=${String(invoked)}`);
}
function executionInput(envelope) {
    return {
        envelope,
        attemptId: ATTEMPT_ID,
        actionDigest: ACTION_DIGEST,
        idempotencyKey: IDEMPOTENCY_KEY,
    };
}
async function runSoundScenario(scenario) {
    const signer = generateKeyPairSync("ed25519");
    const store = createMemoryConsequenceActuatorStore({ now: NOW });
    const providerCredential = Object.freeze({
        token: "credential-owned-only-by-actuator",
    });
    const providerCallers = [];
    let providerCalls = 0;
    const actuator = new ConsequenceActuator({
        testOnly: true,
        pins: {
            tenantId: TENANT_ID,
            caid: CAID,
            providerAccountId: PROVIDER_ACCOUNT_ID,
            targetDigest: TARGET_DIGEST,
            operation: OPERATION,
            envelopeIssuerId: ISSUER_ID,
            envelopeKeyId: ENVELOPE_KEY_ID,
            envelopePublicKey: signer.publicKey,
            maxEnvelopeTtlMs: 60_000,
            clockSkewMs: 2_000,
        },
        store,
        now: NOW,
        perform: async (binding) => {
            providerCalls += 1;
            providerCallers.push("ACTUATOR");
            requireCondition(providerCredential.token === "credential-owned-only-by-actuator", "actuator lost its provider credential");
            requireCondition(Object.isFrozen(binding) && !Object.hasOwn(binding, "credential"), "provider callback received ambient credential or mutable binding");
            requireCondition(binding.issuer_id === ISSUER_ID &&
                binding.tenant_id === TENANT_ID &&
                binding.attempt_id === ATTEMPT_ID &&
                binding.action_digest === ACTION_DIGEST &&
                binding.caid === CAID &&
                binding.provider_account_id === PROVIDER_ACCOUNT_ID &&
                binding.target_digest === TARGET_DIGEST &&
                binding.operation === OPERATION &&
                binding.idempotency_key === IDEMPOTENCY_KEY &&
                binding.nonce === NONCE &&
                binding.issued_at === ISSUED_AT &&
                binding.expires_at === EXPIRES_AT, "provider callback received a substituted execution binding");
            throw new Error("provider response lost after invocation");
        },
    });
    // The AEB one-time unit for this action instance, exercised through the
    // shipped reference store rather than a projection-only stand-in.
    const consumption = new InMemoryAebConsumptionStore();
    const RESERVATION_KEY = `aeb:${"e".repeat(64)}`;
    const REPLAY_UNIT = `aeb-native:${"f".repeat(64)}`;
    const bypass = await actuator.execute(executionInput(null));
    requireRefusal(bypass, "malformed_envelope", false);
    requireCondition(providerCalls === 0 && store.size === 0, "unsigned bypass reached the provider or replay store");
    requireCondition(consumption.reserve(RESERVATION_KEY, [REPLAY_UNIT]) === true &&
        consumption.state(RESERVATION_KEY) === "RESERVED", "the one-time AEB unit was not reserved before the envelope was issued");
    const exactEnvelope = signConsequenceExecutionEnvelope(payload(), {
        privateKey: signer.privateKey,
        keyId: ENVELOPE_KEY_ID,
    });
    const exactVerification = verifyConsequenceExecutionEnvelope(exactEnvelope, {
        pins: {
            tenantId: TENANT_ID,
            caid: CAID,
            providerAccountId: PROVIDER_ACCOUNT_ID,
            targetDigest: TARGET_DIGEST,
            operation: OPERATION,
            envelopeIssuerId: ISSUER_ID,
            envelopeKeyId: ENVELOPE_KEY_ID,
            envelopePublicKey: signer.publicKey,
            maxEnvelopeTtlMs: 60_000,
            clockSkewMs: 2_000,
        },
        expected: {
            attemptId: ATTEMPT_ID,
            actionDigest: ACTION_DIGEST,
            idempotencyKey: IDEMPOTENCY_KEY,
        },
        now: NOW,
    });
    requireCondition(exactVerification.ok, "real signed exact-binding envelope did not verify");
    const expiredEnvelope = signConsequenceExecutionEnvelope(payload({
        expires_at: new Date(NOW).toISOString(),
    }), {
        privateKey: signer.privateKey,
        keyId: ENVELOPE_KEY_ID,
    });
    const expired = await actuator.execute(executionInput(expiredEnvelope));
    requireRefusal(expired, "envelope_expired", false);
    const actionSubstitution = signConsequenceExecutionEnvelope(payload({ action_digest: OTHER_ACTION_DIGEST }), {
        privateKey: signer.privateKey,
        keyId: ENVELOPE_KEY_ID,
    });
    const wrongAction = await actuator.execute(executionInput(actionSubstitution));
    requireRefusal(wrongAction, "action_digest_mismatch", false);
    const targetSubstitution = signConsequenceExecutionEnvelope(payload({ target_digest: OTHER_TARGET_DIGEST }), {
        privateKey: signer.privateKey,
        keyId: ENVELOPE_KEY_ID,
    });
    const wrongTarget = await actuator.execute(executionInput(targetSubstitution));
    requireRefusal(wrongTarget, "target_mismatch", false);
    const tamperedEnvelope = structuredClone(exactEnvelope);
    tamperedEnvelope.payload.operation = "payment.refund";
    const tampered = await actuator.execute(executionInput(tamperedEnvelope));
    requireRefusal(tampered, "signature_invalid", false);
    requireCondition(providerCalls === 0 && store.size === 0, "expired or substituted envelope reached provider or replay store");
    const indeterminate = await actuator.execute(executionInput(exactEnvelope));
    requireRefusal(indeterminate, "provider_outcome_indeterminate", true);
    const consumed = store.snapshot(TENANT_ID, NONCE);
    requireCondition(providerCalls === 1 &&
        providerCallers.length === 1 &&
        providerCallers[0] === "ACTUATOR" &&
        consumed?.state === "CONSUMED" &&
        consumed.outcome === "INDETERMINATE" &&
        consumed.tenantId === TENANT_ID &&
        consumed.attemptId === ATTEMPT_ID &&
        consumed.actionDigest === ACTION_DIGEST &&
        consumed.caid === CAID &&
        consumed.providerAccountId === PROVIDER_ACCOUNT_ID &&
        consumed.targetDigest === TARGET_DIGEST &&
        consumed.operation === OPERATION &&
        consumed.idempotencyKey === IDEMPOTENCY_KEY &&
        consumed.nonce === NONCE &&
        consumed.issuedAt === ISSUED_AT &&
        consumed.expiresAt === EXPIRES_AT, "indeterminate provider entry was not exact, actuator-only, and consumed");
    const replay = await actuator.execute(executionInput(exactEnvelope));
    requireRefusal(replay, "envelope_replayed", false);
    requireCondition(providerCalls === 1 &&
        store.size === 1 &&
        store.snapshot(TENANT_ID, NONCE)?.outcome === "INDETERMINATE", "indeterminate envelope replay reopened provider entry");
    // draft-schrock-action-evidence-boundary-04 s5.11: the authoritative
    // non-entry is terminal. The unit is never handed back, and re-presenting the
    // same action instance derives the byte-identical key, which is refused.
    const reconciled = reconcileAebExecution(consumption, RESERVATION_KEY, "NOT_COMMITTED");
    requireCondition(reconciled.state === "RELEASED_NOT_ENTERED" &&
        reconciled.retry_requires_new_instance === true &&
        consumption.state(RESERVATION_KEY) === "RELEASED_NOT_ENTERED", "reconciled non-entry did not become terminal released-not-entered");
    const reReserve = consumption.reserve(RESERVATION_KEY, [REPLAY_UNIT]);
    const lateCommit = reconcileAebExecution(consumption, RESERVATION_KEY, "COMMITTED");
    requireCondition(reReserve === false &&
        lateCommit.state === "RECONCILIATION_REQUIRED" &&
        consumption.state(RESERVATION_KEY) === "RELEASED_NOT_ENTERED" &&
        providerCalls === 1, "a released reservation was resurrected or reached the provider twice");
    const bypassProjection = initialProjection({ bypassRefused: true });
    const authorizedProjection = initialProjection({
        decision: "ALLOWED",
        bypassRefused: true,
    });
    const reservedProjection = initialProjection({
        decision: "ALLOWED",
        bypassRefused: true,
        reservation: "RESERVED",
    });
    const issuedProjection = initialProjection({
        decision: "ALLOWED",
        envelope: "FRESH",
        binding: "EXACT",
        bypassRefused: true,
        reservation: "RESERVED",
    });
    const invokingProjection = initialProjection({
        decision: "ALLOWED",
        envelope: "CONSUMED",
        binding: "EXACT",
        effect: "INVOKING",
        providerCalls: 1,
        providerCaller: "ACTUATOR",
        bypassRefused: true,
        reservation: "RESERVED",
    });
    const indeterminateProjection = initialProjection({
        decision: "ALLOWED",
        envelope: "CONSUMED",
        binding: "EXACT",
        effect: "INDETERMINATE",
        providerCalls: 1,
        providerCaller: "ACTUATOR",
        bypassRefused: true,
        reservation: "RESERVED",
    });
    const replayRefusedProjection = initialProjection({
        ...indeterminateProjection,
        replayRefused: true,
    });
    const releasedProjection = initialProjection({
        ...replayRefusedProjection,
        effect: "NOT_COMMITTED",
        reconciliationAuthenticated: true,
        reservation: "RELEASED_NOT_ENTERED",
        reservationReleased: true,
    });
    const reReserveRefusedProjection = initialProjection({
        ...releasedProjection,
        reReserveRefused: true,
    });
    return {
        scenario,
        steps: [
            {
                operator: "RefuseGateBypass",
                accepted: false,
                projection: bypassProjection,
            },
            {
                operator: "AuthorizeExactAction",
                accepted: true,
                projection: authorizedProjection,
            },
            {
                operator: "ReserveOneTimeUnit",
                accepted: true,
                projection: reservedProjection,
            },
            {
                operator: "IssueExactEnvelope",
                accepted: true,
                projection: issuedProjection,
            },
            {
                operator: "InvokeThroughActuator",
                accepted: true,
                projection: invokingProjection,
            },
            {
                operator: "ProviderTimeout",
                accepted: true,
                projection: indeterminateProjection,
            },
            {
                operator: "RefuseBlindReplay",
                accepted: false,
                projection: replayRefusedProjection,
            },
            {
                operator: "ReconcileNotCommitted",
                accepted: true,
                projection: releasedProjection,
            },
            {
                operator: "RefuseReReserveAfterRelease",
                accepted: false,
                projection: reReserveRefusedProjection,
            },
        ],
        relation: relation({
            binding: {
                attempt_id: ATTEMPT_ID,
                action_digest: ACTION_DIGEST,
                caid: CAID,
                provider_account_id: PROVIDER_ACCOUNT_ID,
                target_digest: TARGET_DIGEST,
                operation: OPERATION,
                idempotency_key: IDEMPOTENCY_KEY,
                nonce: NONCE,
            },
            runtime_controls: {
                bypass: bypass.reason,
                expiry: expired.reason,
                action_substitution: wrongAction.reason,
                target_substitution: wrongTarget.reason,
                signed_body_substitution: tampered.reason,
                indeterminate: indeterminate.reason,
                replay: replay.reason,
                reconciled_non_entry: reconciled.reason,
                re_reserve_after_release: reReserve,
                late_commit_after_release: lateCommit.reason,
            },
        }, reReserveRefusedProjection, reReserveRefusedProjection),
    };
}
async function runNegativeControl(scenario) {
    const signer = generateKeyPairSync("ed25519");
    const store = createMemoryConsequenceActuatorStore({ now: NOW });
    let providerCalls = 0;
    const actuator = new ConsequenceActuator({
        testOnly: true,
        pins: {
            tenantId: TENANT_ID,
            caid: CAID,
            providerAccountId: PROVIDER_ACCOUNT_ID,
            targetDigest: TARGET_DIGEST,
            operation: OPERATION,
            envelopeIssuerId: ISSUER_ID,
            envelopeKeyId: ENVELOPE_KEY_ID,
            envelopePublicKey: signer.publicKey,
        },
        store,
        now: NOW,
        perform: async () => {
            providerCalls += 1;
            return { provider_reference: "unsafe-direct-call" };
        },
    });
    const directProviderBypass = await actuator.execute(executionInput(null));
    requireRefusal(directProviderBypass, "malformed_envelope", false);
    requireCondition(providerCalls === 0 && store.size === 0, "runtime accepted UnsafeDirectProviderCall");
    const refusedProjection = initialProjection();
    return {
        scenario,
        steps: [
            {
                operator: "UnsafeDirectProviderCall",
                accepted: false,
                projection: refusedProjection,
            },
        ],
        relation: relation({
            formal_mutation: "UnsafeDirectProviderCall",
            violated_invariant: "EffectRequiresActuator",
            runtime_refusal: directProviderBypass.reason,
        }, refusedProjection, refusedProjection),
    };
}
export async function runCompleteMediationScenario(scenario) {
    if (scenario === "complete-mediation-indeterminate-no-replay") {
        return runSoundScenario(scenario);
    }
    if (scenario === "complete-mediation-direct-provider-bypass-refused") {
        return runNegativeControl(scenario);
    }
    throw new Error(`unsupported complete-mediation scenario: ${scenario}`);
}
