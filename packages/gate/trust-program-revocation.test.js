// SPDX-License-Identifier: Apache-2.0
// Generated from trust-program-revocation.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, } from 'node:crypto';
import { canonicalize } from '@emilia-protocol/verify';
import { TRUST_PROGRAM_REVOCATION_TARGET_VERSION, applyTrustProgramRevocation, deriveTrustProgramRevocationTarget, deriveTrustProgramRevocationTargetObject, verifyTrustProgramRevocation, } from './trust-program-revocation.js';
import { TRUST_PROGRAM_VERSION, createMemoryTrustProgramStore, createTrustProgramKernel, } from './trust-program.js';
const NOW = Date.parse('2026-07-21T23:30:00.000Z');
const DIGEST = (character) => `sha256:${character.repeat(64)}`;
const ROOT_CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
const RECEIPT_CONTEXT = Object.freeze({
    issuer: 'emilia-test',
    tenant: 'tenant-a',
    environment: 'test',
    audience: 'trust-program-test',
    key_id: 'trust-program-test-key',
});
const OTHER_RECEIPT_CONTEXT = Object.freeze({
    ...RECEIPT_CONTEXT,
    tenant: 'tenant-b',
});
function canonicalDigest(value) {
    return `sha256:${createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}
function authorizationBinding(receiptContext = RECEIPT_CONTEXT, overrides = {}) {
    return {
        instance_id: 'program-instance-123',
        operation_id: 'provider-operation-123',
        program_digest: DIGEST('1'),
        root_caid: ROOT_CAID,
        action_digest: DIGEST('2'),
        receipt_context_digest: canonicalDigest(receiptContext),
        terminal_stage_receipt_digests: [DIGEST('3'), DIGEST('4')],
        consequence_mode: 'receipt-program',
        capability_template_digest: DIGEST('5'),
        escrow_profile_digest: null,
        ...overrides,
    };
}
function derivationInput(receiptContext = RECEIPT_CONTEXT, binding = authorizationBinding(receiptContext)) {
    return {
        authorizationBinding: binding,
        programVersion: 7,
        receiptContext,
    };
}
function revokerFixture() {
    const keys = generateKeyPairSync('ed25519');
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const keyId = `ep:revoker-key:sha256:${createHash('sha256')
        .update(Buffer.from(publicKey, 'base64url')).digest('hex')}`;
    const revokerId = 'ep:key:trust-program-revoker#1';
    function statement(target) {
        const signedFields = {
            '@version': 'EP-REVOCATION-v1',
            action_hash: target.action_hash,
            reason: 'compromised trust-program authority',
            revoked_at: '2026-07-21T23:29:00Z',
            revoker_id: revokerId,
            target_id: target.target_id,
            target_type: target.target_type,
        };
        return {
            ...signedFields,
            proof: {
                algorithm: 'Ed25519',
                revoker_key_id: keyId,
                signature_b64u: sign(null, Buffer.from(canonicalize(signedFields), 'utf8'), keys.privateKey).toString('base64url'),
                public_key: publicKey,
            },
        };
    }
    return {
        statement,
        revokerKeys: {
            [revokerId]: { public_key: publicKey, key_id: keyId },
        },
    };
}
test('derives the closed Trust Program target object and portable commit target from RP-owned bindings', () => {
    const targetObject = deriveTrustProgramRevocationTargetObject(derivationInput());
    assert.deepEqual(targetObject, {
        '@version': TRUST_PROGRAM_REVOCATION_TARGET_VERSION,
        instance_id: 'program-instance-123',
        program_digest: DIGEST('1'),
        program_version: 7,
        root_caid: ROOT_CAID,
        action_digest: DIGEST('2'),
        operation_id: 'provider-operation-123',
        receipt_context_digest: canonicalDigest(RECEIPT_CONTEXT),
        terminal_stage_receipt_digests: [DIGEST('3'), DIGEST('4')],
        consequence_mode: 'receipt-program',
        capability_template_digest: DIGEST('5'),
        escrow_profile_digest: null,
    });
    assert.equal(Object.isFrozen(targetObject), true);
    assert.equal(Object.isFrozen(targetObject.terminal_stage_receipt_digests), true);
    const target = deriveTrustProgramRevocationTarget(derivationInput());
    assert.deepEqual(target, {
        target_type: 'commit',
        target_id: 'provider-operation-123',
        action_hash: canonicalDigest(targetObject),
    });
    assert.equal(Object.isFrozen(target), true);
});
test('target derivation refuses malformed, open, prototype-bearing, unsorted, cross-context, and mixed-owner bindings', () => {
    assert.throws(() => deriveTrustProgramRevocationTarget(derivationInput(RECEIPT_CONTEXT, authorizationBinding(RECEIPT_CONTEXT, { unexpected: true }))), /closed execution authorization binding/);
    const inherited = Object.assign(Object.create({ inherited_target: 'attacker-controlled' }), authorizationBinding());
    assert.throws(() => deriveTrustProgramRevocationTarget(derivationInput(RECEIPT_CONTEXT, inherited)), /closed execution authorization binding/);
    const prototypeNamed = authorizationBinding();
    Object.defineProperty(prototypeNamed, '__proto__', {
        value: DIGEST('9'), enumerable: true, writable: true, configurable: true,
    });
    assert.throws(() => deriveTrustProgramRevocationTarget(derivationInput(RECEIPT_CONTEXT, prototypeNamed)), /prototype-named field|closed execution authorization binding/);
    assert.throws(() => deriveTrustProgramRevocationTarget(derivationInput(RECEIPT_CONTEXT, authorizationBinding(RECEIPT_CONTEXT, {
        terminal_stage_receipt_digests: [DIGEST('4'), DIGEST('3')],
    }))), /sorted terminal receipt digests/);
    assert.throws(() => deriveTrustProgramRevocationTarget(derivationInput(RECEIPT_CONTEXT, authorizationBinding(RECEIPT_CONTEXT, { escrow_profile_digest: DIGEST('6') }))), /exactly one consequence owner/);
    assert.throws(() => deriveTrustProgramRevocationTarget(derivationInput(OTHER_RECEIPT_CONTEXT, authorizationBinding(RECEIPT_CONTEXT))), /receipt context digest mismatch/);
    assert.throws(() => deriveTrustProgramRevocationTarget({
        ...derivationInput(),
        target_id: 'statement-controlled-target',
    }), /closed derivation input/);
});
test('verifies a real Ed25519 statement with the actual portable verifier and rejects target or tenant substitution', () => {
    const revoker = revokerFixture();
    const targetA = deriveTrustProgramRevocationTarget(derivationInput());
    const validStatement = revoker.statement(targetA);
    const verified = verifyTrustProgramRevocation({
        ...derivationInput(),
        statement: validStatement,
        revokerKeys: revoker.revokerKeys,
        now: NOW,
    });
    assert.equal(verified.valid, true, verified.errors.join('; '));
    assert.deepEqual(verified.target, targetA);
    assert.equal(verified.checks.target_derived, true);
    assert.equal(verified.checks.portable_verifier_completed, true);
    const substitute = revoker.statement({
        ...targetA,
        target_id: 'provider-operation-substitute',
    });
    const refusedSubstitution = verifyTrustProgramRevocation({
        ...derivationInput(),
        statement: substitute,
        revokerKeys: revoker.revokerKeys,
        now: NOW,
    });
    assert.equal(refusedSubstitution.valid, false);
    assert.equal(refusedSubstitution.checks.target_bound, false);
    const bindingB = authorizationBinding(OTHER_RECEIPT_CONTEXT);
    const targetB = deriveTrustProgramRevocationTarget(derivationInput(OTHER_RECEIPT_CONTEXT, bindingB));
    assert.notEqual(targetA.action_hash, targetB.action_hash);
    const refusedCrossTenant = verifyTrustProgramRevocation({
        ...derivationInput(OTHER_RECEIPT_CONTEXT, bindingB),
        statement: validStatement,
        revokerKeys: revoker.revokerKeys,
        now: NOW,
    });
    assert.equal(refusedCrossTenant.valid, false);
    assert.equal(refusedCrossTenant.checks.target_bound, false);
});
test('verification rejects open or prototype-bearing statements and fails closed if the portable verifier throws', () => {
    const revoker = revokerFixture();
    const target = deriveTrustProgramRevocationTarget(derivationInput());
    const statement = revoker.statement(target);
    const openStatement = { ...statement, unsigned_scope: 'all-tenants' };
    const openResult = verifyTrustProgramRevocation({
        ...derivationInput(), statement: openStatement, revokerKeys: revoker.revokerKeys, now: NOW,
    });
    assert.equal(openResult.valid, false);
    assert.equal(openResult.checks.statement_structure, false);
    const inherited = Object.assign(Object.create({ target_id: 'inherited' }), statement);
    const inheritedResult = verifyTrustProgramRevocation({
        ...derivationInput(), statement: inherited, revokerKeys: revoker.revokerKeys, now: NOW,
    });
    assert.equal(inheritedResult.valid, false);
    assert.equal(inheritedResult.checks.statement_structure, false);
    const throwingStatement = new Proxy(statement, {
        get() {
            throw new Error('hostile verifier input');
        },
    });
    const exception = verifyTrustProgramRevocation({
        ...derivationInput(),
        statement: throwingStatement,
        revokerKeys: revoker.revokerKeys,
        now: NOW,
    });
    assert.equal(exception.valid, false);
    assert.equal(exception.checks.portable_verifier_completed, false);
    assert.match(exception.errors.join('; '), /portable revocation verifier threw/);
});
test('apply verifies first, never invalidates on refusal, and classifies a stale already-claimed revision as late', async () => {
    const revoker = revokerFixture();
    const target = deriveTrustProgramRevocationTarget(derivationInput());
    const validStatement = revoker.statement(target);
    let statusCalls = 0;
    let invalidateCalls = 0;
    const kernel = {
        async status() {
            statusCalls += 1;
            return {
                ok: true,
                state: {
                    status: 'active',
                    revision: 6,
                    execution: { status: 'claimed' },
                },
            };
        },
        async invalidate() {
            invalidateCalls += 1;
            throw new Error('must not be called');
        },
    };
    const substitutedStatement = revoker.statement({ ...target, action_hash: DIGEST('f') });
    const refused = await applyTrustProgramRevocation({
        ...derivationInput(),
        statement: substitutedStatement,
        revokerKeys: revoker.revokerKeys,
        now: NOW,
        expectedRevision: 5,
        kernel,
    });
    assert.equal(refused.verified, false);
    assert.equal(refused.disposition, 'refused');
    assert.equal(refused.must_fail_closed, false);
    assert.equal(refused.claim_permitted, false);
    assert.equal(statusCalls, 0);
    assert.equal(invalidateCalls, 0);
    const stale = await applyTrustProgramRevocation({
        ...derivationInput(),
        statement: validStatement,
        revokerKeys: revoker.revokerKeys,
        now: NOW,
        expectedRevision: 5,
        kernel,
    });
    assert.equal(stale.verified, true);
    assert.equal(stale.applied, false);
    assert.equal(stale.disposition, 'late_future_authority_only');
    assert.equal(stale.reason, 'stale_expected_revision_claim_already_linearized');
    assert.equal(stale.claim_permitted, false);
    assert.equal(statusCalls, 1);
    assert.equal(invalidateCalls, 0);
});
function oneStageProgram() {
    return {
        '@version': TRUST_PROGRAM_VERSION,
        program_id: 'tp_revocation_race_1',
        version: 1,
        root_caid: ROOT_CAID,
        action_digest: DIGEST('a'),
        valid_from: new Date(NOW - 60_000).toISOString(),
        expires_at: new Date(NOW + 60_000).toISOString(),
        stages: [{
                stage_id: 'approval',
                depends_on: [],
                rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
                requirements: [{
                        requirement_id: 'approver',
                        evidence_type: 'ep-signoff',
                        verifier_profile: 'ep-signoff',
                        policy_digest: DIGEST('b'),
                        max_age_sec: 900,
                        revocation_required: true,
                    }],
            }],
        execution: {
            depends_on: ['approval'],
            consequence_mode: 'receipt-program',
            capability_template_digest: DIGEST('c'),
            escrow_profile_digest: null,
        },
    };
}
async function createReadyKernel(store, instanceId) {
    const receiptKeys = generateKeyPairSync('ed25519');
    const program = oneStageProgram();
    const kernel = createTrustProgramKernel({
        program,
        store,
        verifiers: {
            'ep-signoff': async ({ artifact }) => ({
                valid: true,
                binding_digest: artifact.binding_digest,
                policy_digest: DIGEST('b'),
                subjects: ['alice'],
                key_fingerprints: ['key-alice'],
                issued_at: new Date(NOW - 5_000).toISOString(),
                expires_at: new Date(NOW + 30_000).toISOString(),
                revocation_checked_at: new Date(NOW - 1_000).toISOString(),
            }),
        },
        receiptPrivateKey: receiptKeys.privateKey,
        receiptContext: RECEIPT_CONTEXT,
        allowEphemeralState: true,
        now: () => NOW,
    });
    assert.equal((await kernel.start({ instanceId })).ok, true);
    const challenge = await kernel.challenge({
        instanceId, stageId: 'approval', requirementId: 'approver',
    });
    const admitted = await kernel.admit({
        instanceId,
        stageId: 'approval',
        requirementId: 'approver',
        artifact: {
            evidence_id: `ev-${instanceId}-approval`,
            binding_digest: challenge.binding_digest,
        },
    });
    assert.equal(admitted.ok, true);
    assert.equal(admitted.state.execution.status, 'ready');
    const binding = {
        instance_id: instanceId,
        operation_id: `provider-operation-${instanceId}`,
        program_digest: kernel.program_digest,
        root_caid: program.root_caid,
        action_digest: program.action_digest,
        receipt_context_digest: canonicalDigest(RECEIPT_CONTEXT),
        terminal_stage_receipt_digests: [admitted.stage_receipt.receipt_digest],
        consequence_mode: program.execution.consequence_mode,
        capability_template_digest: program.execution.capability_template_digest,
        escrow_profile_digest: program.execution.escrow_profile_digest,
    };
    return { kernel, program, admitted, binding };
}
test('a verified stale revision on an unclaimed ready instance retries CAS and cannot leave it claimable', async () => {
    const store = createMemoryTrustProgramStore();
    const instanceId = 'program-instance-stale-ready';
    const { kernel, program, admitted, binding } = await createReadyKernel(store, instanceId);
    const staleRevision = admitted.state.revision;
    const stored = await store.get({ tenantId: RECEIPT_CONTEXT.tenant, instanceId });
    const unrelatedTransition = structuredClone(stored.state);
    unrelatedTransition.revision += 1;
    assert.equal((await store.compareAndSwap({
        tenantId: RECEIPT_CONTEXT.tenant,
        instanceId,
        expectedRevision: staleRevision,
        state: unrelatedTransition,
    })).ok, true);
    const revoker = revokerFixture();
    const derivation = {
        authorizationBinding: binding,
        programVersion: program.version,
        receiptContext: RECEIPT_CONTEXT,
    };
    const application = await applyTrustProgramRevocation({
        ...derivation,
        statement: revoker.statement(deriveTrustProgramRevocationTarget(derivation)),
        revokerKeys: revoker.revokerKeys,
        now: NOW,
        expectedRevision: staleRevision,
        kernel,
    });
    assert.equal(application.disposition, 'invalidated_before_claim');
    assert.equal(application.applied, true);
    assert.equal(application.blocks_claim, true);
    assert.equal(application.claim_permitted, false);
    assert.equal((await kernel.claimExecution({
        instanceId,
        operationId: binding.operation_id,
        claimToken: 'claim-token-that-is-at-least-32-bytes',
    })).reason, 'program_instance_invalidated');
});
test('repeated unrelated conflicts are indeterminate and require caller-side fail-closed retry', async () => {
    const revoker = revokerFixture();
    const derivation = derivationInput();
    let revision = 10;
    let invalidateCalls = 0;
    const kernel = {
        async status() {
            return {
                ok: true,
                state: {
                    status: 'active',
                    revision,
                    execution: { status: 'ready' },
                },
            };
        },
        async invalidate(input) {
            invalidateCalls += 1;
            assert.equal(input.expectedRevision, revision);
            revision += 1;
            return { ok: false, reason: 'revision_conflict' };
        },
    };
    const result = await applyTrustProgramRevocation({
        ...derivation,
        statement: revoker.statement(deriveTrustProgramRevocationTarget(derivation)),
        revokerKeys: revoker.revokerKeys,
        now: NOW,
        expectedRevision: 9,
        kernel,
    });
    assert.equal(invalidateCalls, 3);
    assert.equal(result.disposition, 'indeterminate_retry_required');
    assert.equal(result.reason, 'invalidation_conflict_retry_exhausted');
    assert.equal(result.applied, false);
    assert.equal(result.blocks_claim, false);
    assert.equal(result.future_authority_only, false);
    assert.equal(result.claim_permitted, false);
    assert.equal(result.retry_required, true);
    assert.equal(result.must_fail_closed, true);
});
test('a barrier race proves exactly one of claim or revocation invalidation linearizes first', async () => {
    const baseStore = createMemoryTrustProgramStore();
    let raceEnabled = false;
    let arrivals = 0;
    let releaseBarrier;
    const barrier = new Promise((resolve) => { releaseBarrier = resolve; });
    const awaitRace = async () => {
        if (!raceEnabled)
            return;
        arrivals += 1;
        if (arrivals === 2)
            releaseBarrier();
        await barrier;
    };
    const store = {
        durable: baseStore.durable,
        create: baseStore.create.bind(baseStore),
        get: baseStore.get.bind(baseStore),
        async compareAndSwap(input) {
            await awaitRace();
            return baseStore.compareAndSwap(input);
        },
        async invalidate(input) {
            await awaitRace();
            return baseStore.invalidate(input);
        },
    };
    const instanceId = 'program-instance-race';
    const { kernel, program, admitted, binding } = await createReadyKernel(store, instanceId);
    const revoker = revokerFixture();
    const derivation = {
        authorizationBinding: binding,
        programVersion: program.version,
        receiptContext: RECEIPT_CONTEXT,
    };
    const statement = revoker.statement(deriveTrustProgramRevocationTarget(derivation));
    raceEnabled = true;
    const [claim, application] = await Promise.all([
        kernel.claimExecution({
            instanceId,
            operationId: binding.operation_id,
            claimToken: 'claim-token-that-is-at-least-32-bytes',
        }),
        applyTrustProgramRevocation({
            ...derivation,
            statement,
            revokerKeys: revoker.revokerKeys,
            now: NOW,
            expectedRevision: admitted.state.revision,
            kernel,
        }),
    ]);
    assert.equal(arrivals, 2);
    assert.equal(claim.ok === true, application.blocks_claim !== true);
    const final = await kernel.status(instanceId);
    if (application.blocks_claim) {
        assert.equal(application.disposition, 'invalidated_before_claim');
        assert.equal(claim.ok, false);
        assert.equal(final.state.status, 'invalidated');
        assert.equal((await kernel.claimExecution({ instanceId })).reason, 'program_instance_invalidated');
    }
    else {
        assert.equal(claim.ok, true);
        assert.equal(application.disposition, 'late_future_authority_only');
        assert.equal(final.state.execution.status, 'claimed');
    }
});
