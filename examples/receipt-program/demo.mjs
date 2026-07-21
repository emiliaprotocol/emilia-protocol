// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { generateKeyPairSync } from 'node:crypto';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import { CAPABILITY_CAID_SCOPE_PROFILE, createDefaultActionRiskManifest, createEg1Harness, createGate, createMemoryCapabilityStore, createReceiptProgramKernel, createRuntimeMonitor, delegateCapabilityReceipt, mintCapabilityReceipt, verifyReceiptProgramCertificate, } from '../../packages/gate/index.js';
const now = Date.parse('2026-07-20T22:00:00.000Z');
const operationId = 'pi_receipt_program_demo';
const beneficiary = `sha256:${'a'.repeat(64)}`;
const action = Object.freeze({
    action_type: 'payment.release',
    amount: '50.00',
    amount_usd: 50,
    currency: 'USD',
    beneficiary_account: beneficiary,
    beneficiary_account_hash: beneficiary,
    payment_instruction_id: operationId,
});
const definitions = [{
        action_type: 'payment.release.1',
        required_fields: [
            { name: 'amount', type: 'amount-string' },
            { name: 'currency', type: 'enum', values_ref: 'ISO 4217 alpha-3' },
            { name: 'beneficiary_account', type: 'digest' },
            { name: 'payment_instruction_id', type: 'string' },
        ],
        optional_fields: [],
    }];
function resolveCaid(observed) {
    const materialAction = {
        action_type: 'payment.release.1',
        amount: observed.amount,
        currency: observed.currency,
        beneficiary_account: observed.beneficiary_account,
        payment_instruction_id: observed.payment_instruction_id,
    };
    const computed = computeCaid(materialAction, { suite: 'jcs-sha256', definitions });
    if (!computed.caid)
        throw new Error(`CAID refused: ${computed.refusals?.join(',') ?? 'unknown reason'}`);
    return computed.caid;
}
const caid = resolveCaid(action);
const receiptHarness = createEg1Harness({ action, now: () => now, idPrefix: 'receipt-program-demo' });
const capabilityIssuer = generateKeyPairSync('ed25519');
const capabilityIssuerKey = capabilityIssuer.publicKey
    .export({ type: 'spki', format: 'der' }).toString('base64url');
const certificateOperator = generateKeyPairSync('ed25519');
const certificateOperatorKey = certificateOperator.publicKey
    .export({ type: 'spki', format: 'der' }).toString('base64url');
const baseReceipt = receiptHarness.mint({
    outcome: 'allow_with_signoff',
    extra: { capability_only: true },
});
const parent = mintCapabilityReceipt(baseReceipt, {
    issuerPrivateKey: capabilityIssuer.privateKey,
    budget: { amount: 1000, currency: 'USD' },
    expiry: now + 30 * 24 * 60 * 60 * 1000,
    capabilityId: 'cap_demo_parent',
    secret: Buffer.alloc(32, 7),
    scope: {
        profile: CAPABILITY_CAID_SCOPE_PROFILE,
        operation_id_field: 'payment_instruction_id',
        caids: [caid],
    },
});
const capabilityStore = createMemoryCapabilityStore();
if (!parent.secret)
    throw new Error('parent capability secret missing');
if (!capabilityStore.registerCapability(parent.capabilityReceipt)) {
    throw new Error('parent capability registration failed');
}
const child = await delegateCapabilityReceipt({
    parentCapabilityReceipt: parent.capabilityReceipt,
    parentSecret: parent.secret,
    issuerPrivateKey: capabilityIssuer.privateKey,
    budget: { amount: 100, currency: 'USD' },
    expiry: now + 30 * 24 * 60 * 60 * 1000,
    delegateId: 'payment-agent-demo',
    capabilityId: 'cap_demo_child',
    secret: Buffer.alloc(32, 8),
    operationId: 'delegation:cap_demo_child',
    store: capabilityStore,
    trustedIssuerKeys: [capabilityIssuerKey],
    now: () => now,
});
if (!child.ok)
    throw new Error(`delegation refused: ${child.reason}`);
if (!child.secret)
    throw new Error('child capability secret missing');
const gate = createGate({
    manifest: createDefaultActionRiskManifest(),
    trustedKeys: [receiptHarness.publicKey],
    approverKeys: receiptHarness.approverKeys,
    quorumPolicy: receiptHarness.quorumPolicy,
    rpId: receiptHarness.rpId,
    allowedOrigins: receiptHarness.allowedOrigins,
    capabilityStore,
    capabilityTrustedIssuerKeys: [capabilityIssuerKey],
    capabilityCaidResolver: resolveCaid,
    runtimeMonitor: createRuntimeMonitor({ now: () => now }),
    allowEphemeralStore: true,
    now: () => now,
});
const kernel = createReceiptProgramKernel({
    gate,
    resolveCaid,
    operationIdField: 'payment_instruction_id',
    certificatePrivateKey: certificateOperator.privateKey,
    certificateContext: {
        issuer: 'emilia-receipt-program-demo',
        tenant: 'demo',
        environment: 'local-demo',
        audience: 'demo-verifier',
        key_id: 'local-dev',
    },
    projectResult: (result) => ({
        provider: result.provider,
        provider_operation_id: result.provider_operation_id,
        status: result.status,
    }),
    allowEphemeralState: true,
    now: () => now,
});
const run = await kernel.run({
    programId: 'delegated-payment-reference',
    instructionId: 'release-50-usd',
    caid,
    selector: { protocol: 'mcp', tool: 'release_payment' },
    observedAction: action,
    capability: {
        capabilityReceipt: child.capabilityReceipt,
        secret: child.secret,
        action: { amount: 50, currency: 'USD' },
        operationId,
    },
}, async (_authorization, operation) => ({
    provider: 'simulated-custodian',
    provider_operation_id: operation.providerIdempotencyKey,
    status: 'settled',
}));
const verified = verifyReceiptProgramCertificate(run.certificate, {
    trustedCertificateKeys: {
        [kernel.certificate_context.key_id]: certificateOperatorKey,
    },
    resolveCaid,
    expectedContext: kernel.certificate_context,
    certificateEvidence: run.certificate_evidence,
    verifyCertificateInclusion: (candidate) => gate.evidence.all().some((record) => JSON.stringify(record) === JSON.stringify(candidate)),
});
if (!run.ok || !verified.ok)
    throw new Error(`receipt program failed: ${run.reason || verified.reason}`);
console.log('EMILIA RECEIPT PROGRAM');
console.log(`Parent capability: 1000 USD -> delegated 100 USD (remaining ${child.remaining} USD)`);
console.log(`CAID: ${caid}`);
for (const step of run.certificate.steps)
    console.log(`Step ${step.sequence}: ${step.opcode}`);
console.log(`Child capability remaining: ${capabilityStore.getState('cap_demo_child').budget_amount - capabilityStore.getState('cap_demo_child').consumed_amount} USD`);
console.log(`State root: ${run.certificate.state_root}`);
console.log('Certificate: trusted and internally consistent');
