// SPDX-License-Identifier: Apache-2.0
// Generated from receipt-program.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import { CAPABILITY_CAID_SCOPE_PROFILE, createDefaultActionRiskManifest, createEg1Harness, createGate, createMemoryCapabilityStore, createRuntimeMonitor, mintCapabilityReceipt, } from './index.js';
import { RECEIPT_PROGRAM_CERTIFICATE_VERSION, RECEIPT_PROGRAM_SIGNATURE_ALGORITHM, RECEIPT_PROGRAM_VERSION, createReceiptProgramKernel, verifyReceiptProgramCertificate, } from './receipt-program.js';
import { canonicalize } from './execution-binding.js';
import { canonicalEvidenceJson } from './evidence.js';
const NOW = Date.parse('2026-07-20T22:00:00.000Z');
const CERTIFICATE_CONTEXT = Object.freeze({
    issuer: 'emilia-reference-operator',
    tenant: 'tenant_receipt_program_test',
    environment: 'test',
    audience: 'receipt-program-verifier',
    key_id: 'local-dev',
});
const SELECTOR = Object.freeze({ protocol: 'mcp', tool: 'release_payment' });
const BENEFICIARY = `sha256:${'a'.repeat(64)}`;
const OBSERVED_ACTION = Object.freeze({
    action_type: 'payment.release',
    amount: '40.00',
    amount_usd: 40,
    currency: 'USD',
    beneficiary_account: BENEFICIARY,
    beneficiary_account_hash: BENEFICIARY,
    payment_instruction_id: 'pi_receipt_program_1',
});
const CAID_DEFINITIONS = Object.freeze([{
        action_type: 'payment.release.1',
        required_fields: [
            { name: 'amount', type: 'amount-string' },
            { name: 'currency', type: 'enum', values_ref: 'ISO 4217 alpha-3' },
            { name: 'beneficiary_account', type: 'digest' },
            { name: 'payment_instruction_id', type: 'string' },
        ],
        optional_fields: [],
    }]);
function caidAction(action) {
    return {
        action_type: 'payment.release.1',
        amount: action.amount,
        currency: action.currency,
        beneficiary_account: action.beneficiary_account,
        payment_instruction_id: action.payment_instruction_id,
    };
}
function resolveCaid(action) {
    const result = computeCaid(caidAction(action), {
        suite: 'jcs-sha256',
        definitions: CAID_DEFINITIONS,
    });
    if (!result.caid)
        throw new Error(result.refusals.join(','));
    return result.caid;
}
function fixture({ budget = 100, action = OBSERVED_ACTION, effectTimeoutMs = 1000, projectResult = null, trustBaseReceipt = true, } = {}) {
    const harness = createEg1Harness({ action, now: () => NOW, idPrefix: 'receipt-program' });
    const capabilityIssuer = generateKeyPairSync('ed25519');
    const capabilityIssuerPublicKey = capabilityIssuer.publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const certificateSigner = generateKeyPairSync('ed25519');
    const certificateSignerPublicKey = certificateSigner.publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const caid = resolveCaid(action);
    const baseReceipt = harness.mint({ outcome: 'allow_with_signoff', extra: { capability_only: true } });
    const capability = mintCapabilityReceipt(baseReceipt, {
        issuerPrivateKey: capabilityIssuer.privateKey,
        budget: { amount: budget, currency: 'USD' },
        expiry: NOW + 60_000,
        secret: Buffer.alloc(32, 9),
        capabilityId: `cap_receipt_program_${budget}`,
        scope: {
            profile: CAPABILITY_CAID_SCOPE_PROFILE,
            operation_id_field: 'payment_instruction_id',
            caids: [caid],
        },
    });
    const capabilityStore = createMemoryCapabilityStore();
    assert.equal(capabilityStore.registerCapability(capability.capabilityReceipt), true);
    const runtimeMonitor = createRuntimeMonitor({ now: () => NOW });
    const gate = createGate({
        manifest: createDefaultActionRiskManifest(),
        trustedKeys: trustBaseReceipt ? [harness.publicKey] : [],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        capabilityStore,
        capabilityTrustedIssuerKeys: [capabilityIssuerPublicKey],
        capabilityCaidResolver: resolveCaid,
        runtimeMonitor,
        allowEphemeralStore: true,
        now: () => NOW,
    });
    const kernel = createReceiptProgramKernel({
        gate,
        resolveCaid,
        operationIdField: 'payment_instruction_id',
        certificatePrivateKey: certificateSigner.privateKey,
        certificateContext: CERTIFICATE_CONTEXT,
        projectResult,
        effectTimeoutMs,
        allowEphemeralState: true,
        now: () => NOW,
    });
    return {
        harness,
        gate,
        kernel,
        caid,
        capability,
        capabilityStore,
        certificateSignerPublicKey,
        certificateSignerPrivateKey: certificateSigner.privateKey,
        certificateContext: CERTIFICATE_CONTEXT,
        runtimeMonitor,
        action,
    };
}
function request(f, overrides = {}) {
    return {
        programId: 'delegated-payment-reference',
        instructionId: 'release-milestone-1',
        caid: f.caid,
        selector: SELECTOR,
        observedAction: f.action,
        capability: {
            capabilityReceipt: f.capability.capabilityReceipt,
            secret: f.capability.secret,
            action: { amount: f.action.amount_usd, currency: f.action.currency },
            operationId: f.action.payment_instruction_id,
        },
        ...overrides,
    };
}
function verifyCertificate(f, certificate, certificateEvidence = null) {
    return verifyReceiptProgramCertificate(certificate, {
        trustedCertificateKeys: {
            [f.certificateContext.key_id]: f.certificateSignerPublicKey,
        },
        resolveCaid,
        expectedContext: f.certificateContext,
        certificateEvidence,
        ...(certificateEvidence === null ? {} : {
            verifyCertificateInclusion: (candidate) => f.gate.evidence.all().some((record) => canonicalEvidenceJson(record) === canonicalEvidenceJson(candidate)),
        }),
    });
}
function digest(value) {
    return `sha256:${createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}
function resignCertificate(certificate, privateKey, publicKey = certificate.signature.public_key) {
    const changed = structuredClone(certificate);
    changed.program_digest = digest(changed.program);
    delete changed.signature;
    delete changed.state_root;
    changed.state_root = digest(changed);
    changed.signature = {
        algorithm: RECEIPT_PROGRAM_SIGNATURE_ALGORITHM,
        public_key: publicKey,
        value: cryptoSign(null, Buffer.from(canonicalize(changed), 'utf8'), privateKey).toString('base64url'),
    };
    return changed;
}
test('receipt program executes one CAID-bound capability and emits a trusted certificate', async () => {
    const f = fixture();
    let effects = 0;
    const out = await f.kernel.run(request(f), async (_authorization, operation) => {
        effects += 1;
        return {
            provider: 'simulated-custodian',
            provider_operation_id: operation.providerIdempotencyKey,
            status: 'settled',
        };
    });
    assert.equal(out.ok, true, `${out.reason}: ${JSON.stringify(out.certificate)}`);
    assert.equal(out.outcome, 'executed');
    assert.equal(out.certificate['@version'], RECEIPT_PROGRAM_CERTIFICATE_VERSION);
    assert.equal(out.certificate.program['@version'], RECEIPT_PROGRAM_VERSION);
    assert.deepEqual(out.certificate.steps.map((step) => step.opcode), [
        'RECEIPT', 'MATCH', 'RESERVE', 'EXECUTE', 'COMMIT', 'CERTIFY',
    ]);
    assert.equal(out.certificate.result.status, 'settled');
    const certificateCheck = verifyCertificate(f, out.certificate, out.certificate_evidence);
    assert.equal(certificateCheck.ok, true, `${certificateCheck.reason}: ${JSON.stringify(out.certificate)}`);
    assert.equal(certificateCheck.certificate_persisted, true);
    assert.equal(effects, 1);
    assert.equal(f.capabilityStore.getState('cap_receipt_program_100').consumed_amount, 40);
    assert.equal(f.capabilityStore.getOperation(f.action.payment_instruction_id).outcome, 'executed');
    const recovered = await f.kernel.recoverCertificates(out.certificate.program_digest);
    assert.equal(recovered.ok, true);
    assert.equal(recovered.certificates.length, 1);
    assert.equal(recovered.certificates[0].certificate.state_root, out.certificate.state_root);
});
test('receipt program refuses a CAID substitution before reservation or effect', async () => {
    const f = fixture();
    let effects = 0;
    const substituted = `${f.caid.slice(0, -1)}${f.caid.endsWith('A') ? 'B' : 'A'}`;
    const out = await f.kernel.run(request(f, { caid: substituted }), async () => {
        effects += 1;
        return { status: 'must-not-run' };
    });
    assert.equal(out.ok, false);
    assert.equal(out.outcome, 'refused');
    assert.equal(out.reason, 'caid_mismatch');
    assert.deepEqual(out.certificate.steps.map((step) => step.opcode), ['RECEIPT', 'REFUSE', 'CERTIFY']);
    assert.equal(verifyCertificate(f, out.certificate).ok, true);
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getState('cap_receipt_program_100').consumed_amount, 0);
    assert.equal(f.capabilityStore.getOperation(f.action.payment_instruction_id), null);
});
test('provider timeout becomes signed indeterminate state and replay stays refused', async () => {
    const f = fixture({ effectTimeoutMs: 15 });
    let effects = 0;
    let providerSignal;
    const out = await f.kernel.run(request(f), async (_authorization, operation) => {
        effects += 1;
        providerSignal = operation.signal;
        return new Promise(() => { });
    });
    assert.equal(out.ok, false);
    assert.equal(out.outcome, 'indeterminate', `${out.reason}: ${JSON.stringify(out.certificate)}`);
    assert.equal(out.reason, 'effect_indeterminate');
    assert.deepEqual(out.certificate.steps.map((step) => step.opcode), [
        'RECEIPT', 'MATCH', 'RESERVE', 'EXECUTE', 'COMMIT_INDETERMINATE', 'HALT', 'CERTIFY',
    ]);
    assert.equal(providerSignal.aborted, true);
    assert.equal(verifyCertificate(f, out.certificate).ok, true);
    assert.equal(f.capabilityStore.getState('cap_receipt_program_100').consumed_amount, 40);
    assert.equal(f.capabilityStore.getOperation(f.action.payment_instruction_id).outcome, 'indeterminate');
    const replay = await f.kernel.run(request(f), async () => {
        effects += 1;
        return { status: 'must-not-run' };
    });
    assert.equal(replay.outcome, 'refused');
    assert.equal(replay.reason, 'operation_already_committed');
    assert.equal(effects, 1);
});
test('non-canonical provider output is treated as indeterminate after provider entry', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f), async () => ({ amount: 1.5 }));
    assert.equal(out.ok, false);
    assert.equal(out.outcome, 'indeterminate', `${out.reason}: ${JSON.stringify(out.certificate)}`);
    assert.equal(out.reason, 'effect_indeterminate');
    assert.equal(out.certificate.result, null);
    assert.equal(verifyCertificate(f, out.certificate).ok, true);
    assert.equal(f.capabilityStore.getOperation(f.action.payment_instruction_id).outcome, 'indeterminate');
});
test('null provider output is indeterminate instead of issuing an unverifiable success', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f), async () => null);
    assert.equal(out.ok, false);
    assert.equal(out.outcome, 'indeterminate');
    assert.equal(out.reason, 'effect_indeterminate');
    assert.equal(verifyCertificate(f, out.certificate).ok, true);
    assert.equal(f.capabilityStore.getOperation(f.action.payment_instruction_id).outcome, 'indeterminate');
});
test('oversized canonical input is refused before reservation or effect', async () => {
    const f = fixture();
    let effects = 0;
    const out = await f.kernel.run(request(f, {
        observedAction: { ...f.action, padding: 'x'.repeat(1024 * 1024) },
    }), async () => {
        effects += 1;
        return { status: 'must-not-run' };
    });
    assert.equal(out.outcome, 'refused');
    assert.equal(out.reason, 'program_invalid');
    assert.equal(effects, 0);
    assert.equal(f.capabilityStore.getState('cap_receipt_program_100').consumed_amount, 0);
});
test('accessor-backed input and certificates refuse without invoking accessors', async () => {
    const f = fixture();
    let accessorCalls = 0;
    const observedAction = { ...f.action };
    Object.defineProperty(observedAction, 'hidden', {
        enumerable: true,
        get() {
            accessorCalls += 1;
            return 'must-not-run';
        },
    });
    const out = await f.kernel.run(request(f, { observedAction }), async () => ({ status: 'must-not-run' }));
    assert.equal(out.outcome, 'refused');
    assert.equal(out.reason, 'program_invalid');
    assert.equal(accessorCalls, 0);
    const certificate = {};
    Object.defineProperty(certificate, '@version', {
        enumerable: true,
        get() {
            accessorCalls += 1;
            return RECEIPT_PROGRAM_CERTIFICATE_VERSION;
        },
    });
    assert.equal(verifyCertificate(f, certificate).reason, 'certificate_version_invalid');
    assert.equal(accessorCalls, 0);
});
test('provider cannot mutate Gate authorization before execution evidence is committed', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f), async (authorization) => {
        assert.equal(Object.isFrozen(authorization), true);
        assert.equal(Object.isFrozen(authorization.evidence), true);
        assert.throws(() => {
            authorization.evidence.hash = 'f'.repeat(64);
        }, TypeError);
        return { status: 'settled' };
    });
    assert.equal(out.outcome, 'executed');
    const checked = verifyCertificate(f, out.certificate, out.certificate_evidence);
    assert.equal(checked.ok, true, `${checked.reason}: ${JSON.stringify(out.certificate)}`);
    assert.notEqual(out.certificate.authorization_ref.hash, 'f'.repeat(64));
});
test('post-commit evidence failure never becomes a contradictory indeterminate certificate', async () => {
    const f = fixture();
    const record = f.gate.evidence.record.bind(f.gate.evidence);
    f.gate.evidence.record = async (entry) => {
        if (entry.kind === 'execution')
            throw new Error('simulated execution evidence outage');
        return record(entry);
    };
    const out = await f.kernel.run(request(f), async () => ({ status: 'settled' }));
    assert.equal(out.ok, false);
    assert.equal(out.outcome, 'executed');
    assert.equal(out.reason, 'execution_evidence_unavailable');
    assert.equal(out.certificate, null);
    assert.equal(f.capabilityStore.getOperation(f.action.payment_instruction_id).outcome, 'executed');
});
test('indeterminate execution-evidence failure never emits or persists an unverifiable certificate', async () => {
    const f = fixture();
    const record = f.gate.evidence.record.bind(f.gate.evidence);
    f.gate.evidence.record = async (entry) => {
        if (entry.kind === 'execution')
            throw new Error('simulated indeterminate evidence outage');
        return record(entry);
    };
    const out = await f.kernel.run(request(f), async () => {
        throw new Error('provider response lost');
    });
    assert.equal(out.ok, false);
    assert.equal(out.outcome, 'indeterminate');
    assert.equal(out.reason, 'execution_evidence_unavailable');
    assert.equal(out.certificate, null);
    assert.equal(out.certificate_evidence, null);
    assert.equal(f.capabilityStore.getOperation(f.action.payment_instruction_id).outcome, 'indeterminate');
    assert.equal(f.gate.evidence.all().some((entry) => entry.kind === 'receipt_program_certificate'), false);
});
test('ordinary Gate preserves executed after a post-commit evidence failure', async () => {
    const f = fixture();
    const record = f.gate.evidence.record.bind(f.gate.evidence);
    f.gate.evidence.record = async (entry) => {
        if (entry.kind === 'execution')
            throw new Error('simulated execution evidence outage');
        return record(entry);
    };
    const receipt = f.harness.mint({ outcome: 'allow_with_signoff' });
    await assert.rejects(f.gate.run({ selector: SELECTOR, receipt, observedAction: f.action }, async () => ({ status: 'settled' })), (error) => {
        assert.equal(error.emiliaGateOutcome.outcome, 'executed');
        assert.equal(error.emiliaGateOutcome.reason, 'execution_evidence_unavailable');
        assert.deepEqual(error.emiliaGateOutcome.result, { status: 'settled' });
        return true;
    });
    assert.equal(f.gate.evidence.all().some((entry) => entry.kind === 'execution'), false);
});
test('Gate denial emits a verifiable refused certificate', async () => {
    const f = fixture({ trustBaseReceipt: false });
    const out = await f.kernel.run(request(f), async () => ({ status: 'must-not-run' }));
    assert.equal(out.outcome, 'refused');
    assert.equal(out.reason, 'base_receipt_rejected');
    assert.equal(out.certificate.authorization_ref.allow, false);
    const checked = verifyCertificate(f, out.certificate, out.certificate_evidence);
    assert.equal(checked.ok, true, `${checked.reason}: ${JSON.stringify(out.certificate)}`);
});
test('constructor-pinned result projection prevents successful provider secret disclosure', async () => {
    const f = fixture({ projectResult: (result) => ({ status: result.status }) });
    const out = await f.kernel.run(request(f), async () => ({
        status: 'settled',
        access_token: 'must-not-be-certified',
    }));
    assert.equal(out.outcome, 'executed');
    assert.deepEqual(out.certificate.result, { status: 'settled' });
    assert.equal(JSON.stringify(out.certificate).includes('must-not-be-certified'), false);
});
test('signer and certificate-log failures preserve the terminal Gate outcome without false proof', async () => {
    const signingFailure = fixture();
    const failedSignerKey = generateKeyPairSync('ed25519');
    const failedSignerPublic = failedSignerKey.publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const signingKernel = createReceiptProgramKernel({
        gate: signingFailure.gate,
        resolveCaid,
        operationIdField: 'payment_instruction_id',
        certificateSigner: {
            keyId: 'failed-local-signer',
            custody: 'local-dev',
            publicKey: failedSignerPublic,
            sign: async () => { throw new Error('signer unavailable secret=hidden'); },
        },
        certificateContext: {
            ...CERTIFICATE_CONTEXT,
            key_id: 'failed-local-signer',
        },
        allowEphemeralState: true,
        now: () => NOW,
    });
    const unsigned = await signingKernel.run(request(signingFailure), async () => ({ status: 'settled' }));
    assert.equal(unsigned.outcome, 'executed');
    assert.equal(unsigned.reason, 'certificate_signing_failed');
    assert.equal(unsigned.certificate, null);
    assert.equal(signingFailure.capabilityStore.getOperation(signingFailure.action.payment_instruction_id).outcome, 'executed');
    const persistenceFailure = fixture();
    const record = persistenceFailure.gate.evidence.record.bind(persistenceFailure.gate.evidence);
    persistenceFailure.gate.evidence.record = async (entry) => {
        if (entry.kind === 'receipt_program_certificate')
            throw new Error('certificate log unavailable');
        return record(entry);
    };
    const unpersisted = await persistenceFailure.kernel.run(request(persistenceFailure), async () => ({ status: 'settled' }));
    assert.equal(unpersisted.outcome, 'executed');
    assert.equal(unpersisted.reason, 'certificate_persistence_failed');
    assert.ok(unpersisted.certificate);
    assert.equal(unpersisted.certificate_evidence, null);
    assert.equal(persistenceFailure.capabilityStore.getOperation(persistenceFailure.action.payment_instruction_id).outcome, 'executed');
});
test('verifier rejects re-signed structural, context, time, and evidence-kind contradictions', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f), async () => ({ status: 'settled' }));
    assert.equal(out.outcome, 'executed');
    const missingSelector = structuredClone(out.certificate);
    delete missingSelector.program.selector;
    const resignedMissing = resignCertificate(missingSelector, f.certificateSignerPrivateKey);
    assert.equal(verifyCertificate(f, resignedMissing).reason, 'certificate_program_invalid');
    const badTime = structuredClone(out.certificate);
    badTime.completed_at = 'not-an-instant';
    const resignedTime = resignCertificate(badTime, f.certificateSignerPrivateKey);
    assert.equal(verifyCertificate(f, resignedTime).reason, 'certificate_time_invalid');
    const badKind = structuredClone(out.certificate);
    badKind.execution_ref.kind = 'decision';
    const resignedKind = resignCertificate(badKind, f.certificateSignerPrivateKey);
    assert.equal(verifyCertificate(f, resignedKind).reason, 'certificate_execution_ref_invalid');
    const signatureMalleability = structuredClone(out.certificate);
    signatureMalleability.signature.untrusted_hint = 'not-signed';
    assert.equal(verifyCertificate(f, signatureMalleability).reason, 'certificate_signature_invalid');
    const extraStepField = structuredClone(out.certificate);
    extraStepField.steps[0].untrusted_hint = 'signed-but-unsupported';
    const resignedStep = resignCertificate(extraStepField, f.certificateSignerPrivateKey);
    assert.equal(verifyCertificate(f, resignedStep).reason, 'certificate_steps_invalid');
    const oversizedProgram = structuredClone(out.certificate);
    oversizedProgram.program.selector.padding = 'x'.repeat(513 * 1024);
    const resignedOversized = resignCertificate(oversizedProgram, f.certificateSignerPrivateKey);
    assert.equal(verifyCertificate(f, resignedOversized).reason, 'certificate_program_invalid');
    assert.equal(verifyReceiptProgramCertificate(out.certificate, {
        trustedCertificateKeys: { [f.certificateContext.key_id]: f.certificateSignerPublicKey },
        resolveCaid,
        expectedContext: { ...f.certificateContext, environment: 'production' },
    }).reason, 'certificate_context_mismatch');
});
test('certificate key identity maps the context key id to exactly one trusted public key', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f), async () => ({ status: 'settled' }));
    const alternate = generateKeyPairSync('ed25519');
    const alternatePublic = alternate.publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const substituted = resignCertificate(out.certificate, alternate.privateKey, alternatePublic);
    const checked = verifyReceiptProgramCertificate(substituted, {
        trustedCertificateKeys: {
            [f.certificateContext.key_id]: f.certificateSignerPublicKey,
            alternate: alternatePublic,
        },
        resolveCaid,
        expectedContext: f.certificateContext,
    });
    assert.equal(checked.reason, 'certificate_signer_not_trusted');
});
test('a locally rehashed evidence wrapper cannot prove durable certificate inclusion', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f), async () => ({ status: 'settled' }));
    const forged = structuredClone(out.certificate_evidence);
    forged.seq = 987654;
    forged.prev_hash = 'genesis';
    delete forged.hash;
    forged.hash = createHash('sha256').update(canonicalEvidenceJson(forged)).digest('hex');
    const options = {
        trustedCertificateKeys: { [f.certificateContext.key_id]: f.certificateSignerPublicKey },
        resolveCaid,
        expectedContext: f.certificateContext,
        certificateEvidence: forged,
    };
    assert.equal(verifyReceiptProgramCertificate(out.certificate, options).reason, 'certificate_evidence_inclusion_verifier_required');
    assert.equal(verifyReceiptProgramCertificate(out.certificate, {
        ...options,
        verifyCertificateInclusion: () => false,
    }).reason, 'certificate_evidence_not_included');
});
test('expected program digest mismatch emits a verifiable recoverable refusal', async () => {
    const f = fixture();
    const out = await f.kernel.run({
        ...request(f),
        expectedProgramDigest: `sha256:${'0'.repeat(64)}`,
    }, async () => ({ status: 'must-not-run' }));
    assert.equal(out.outcome, 'refused');
    assert.equal(out.reason, 'program_digest_mismatch');
    assert.deepEqual(out.certificate.steps.map((step) => step.opcode), [
        'RECEIPT', 'MATCH', 'REFUSE', 'CERTIFY',
    ]);
    assert.equal(verifyCertificate(f, out.certificate, out.certificate_evidence).ok, true);
    const recovered = await f.kernel.recoverCertificates(out.certificate.program_digest);
    assert.equal(recovered.ok, true);
    assert.equal(recovered.certificates.length, 1);
});
test('Gate wraps reused provider errors with request-local minimal terminal metadata', async () => {
    const shared = new Error('provider response lost');
    const caught = [];
    for (const f of [fixture(), fixture()]) {
        try {
            await f.gate.run({
                selector: SELECTOR,
                observedAction: f.action,
                capability: request(f).capability,
            }, async () => { throw shared; });
        }
        catch (error) {
            caught.push(error);
        }
    }
    assert.equal(caught.length, 2);
    assert.notEqual(caught[0], shared);
    assert.notEqual(caught[1], shared);
    assert.notEqual(caught[0], caught[1]);
    assert.equal(caught[0].emiliaGateOutcome.outcome, 'indeterminate');
    assert.equal(Object.hasOwn(caught[0].emiliaGateOutcome, 'authorization'), false);
    assert.ok(caught[0].emiliaGateOutcome.authorizationEvidence);
});
test('indeterminate certification does not scan the complete evidence history', async () => {
    const f = fixture();
    f.gate.evidence.all = () => {
        throw new Error('full evidence history must not be read on the execution path');
    };
    const out = await f.kernel.run(request(f), async () => {
        throw new Error('provider response lost');
    });
    assert.equal(out.outcome, 'indeterminate');
    assert.equal(out.reason, 'effect_indeterminate');
    assert.equal(verifyCertificate(f, out.certificate).ok, true);
});
test('certificate verification rejects untrusted signers and internally consistent tampering', async () => {
    const f = fixture();
    const out = await f.kernel.run(request(f), async () => ({ status: 'settled' }));
    assert.equal(out.ok, true, `${out.reason}: ${JSON.stringify(out.certificate)}`);
    assert.equal(verifyReceiptProgramCertificate(out.certificate).reason, 'certificate_signer_not_trusted');
    const attacker = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    assert.equal(verifyReceiptProgramCertificate(out.certificate, {
        trustedCertificateKeys: { [f.certificateContext.key_id]: attacker },
    }).reason, 'certificate_signer_not_trusted');
    assert.equal(verifyReceiptProgramCertificate(out.certificate, {
        trustedCertificateKeys: { [f.certificateContext.key_id]: f.certificateSignerPublicKey },
        expectedContext: f.certificateContext,
    }).reason, 'certificate_caid_resolver_required');
    const tampered = structuredClone(out.certificate);
    tampered.result.status = 'reversed';
    assert.equal(verifyCertificate(f, tampered).ok, false);
});
test('receipt program requires durable fleet state unless a caller explicitly chooses a test kernel', () => {
    const f = fixture();
    const signer = generateKeyPairSync('ed25519');
    assert.throws(() => createReceiptProgramKernel({
        gate: f.gate,
        resolveCaid,
        operationIdField: 'payment_instruction_id',
        certificatePrivateKey: signer.privateKey,
        certificateContext: CERTIFICATE_CONTEXT,
        now: () => NOW,
    }), /durable atomic evidence log and durable capability store/);
});
test('production construction requires external signer custody and a disclosure projection', () => {
    const signer = generateKeyPairSync('ed25519');
    const publicKey = signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const gate = {
        run: async () => { throw new Error('not used'); },
        evidence: {
            durable: true,
            strict: true,
            forkAware: true,
            atomicAppend: true,
            record: async () => { throw new Error('not used'); },
        },
        capabilityStore: { durable: true },
    };
    assert.throws(() => createReceiptProgramKernel({
        gate,
        resolveCaid,
        operationIdField: 'payment_instruction_id',
        certificatePrivateKey: signer.privateKey,
        certificateContext: CERTIFICATE_CONTEXT,
        projectResult: (result) => result,
    }), /external KMS\/HSM certificate signer/);
    const kernel = createReceiptProgramKernel({
        gate,
        resolveCaid,
        operationIdField: 'payment_instruction_id',
        certificateSigner: {
            keyId: 'kms-receipt-program-1',
            custody: 'kms',
            publicKey,
            sign: async (bytes) => cryptoSign(null, bytes, signer.privateKey),
        },
        certificateContext: {
            ...CERTIFICATE_CONTEXT,
            environment: 'production',
            key_id: 'kms-receipt-program-1',
        },
        projectResult: (result) => result,
    });
    assert.equal(kernel.signer_public_key, publicKey);
    assert.throws(() => createReceiptProgramKernel({
        gate,
        resolveCaid,
        operationIdField: 'payment_instruction_id',
        certificateSigner: {
            keyId: 'kms-receipt-program-1',
            custody: 'kms',
            publicKey,
            sign: async (bytes) => cryptoSign(null, bytes, signer.privateKey),
        },
        certificateContext: {
            ...CERTIFICATE_CONTEXT,
            environment: 'production',
            key_id: 'kms-receipt-program-1',
            attacker_extension: true,
        },
        projectResult: (result) => result,
    }), /certificateContext must contain exactly/);
});
test('receipt program refuses runtime trust configuration and operation relabeling', async () => {
    const f = fixture();
    let effects = 0;
    const relabelled = await f.kernel.run(request(f, {
        capability: {
            capabilityReceipt: f.capability.capabilityReceipt,
            secret: f.capability.secret,
            action: { amount: f.action.amount_usd, currency: f.action.currency },
            operationId: 'attacker-operation-id',
        },
    }), async () => {
        effects += 1;
        return { status: 'must-not-run' };
    });
    assert.equal(relabelled.outcome, 'refused');
    assert.equal(relabelled.reason, 'program_operation_binding_failed');
    assert.equal(verifyCertificate(f, relabelled.certificate).ok, true);
    assert.equal(effects, 0);
    const runtimeTrust = await f.kernel.run({
        ...request(f),
        resolveCaid: () => f.caid,
    }, async () => ({ status: 'must-not-run' }));
    assert.equal(runtimeTrust.outcome, 'refused');
    assert.equal(runtimeTrust.reason, 'runtime_trust_configuration_refused');
    assert.equal(verifyCertificate(f, runtimeTrust.certificate).ok, true);
    assert.equal(effects, 0);
});
