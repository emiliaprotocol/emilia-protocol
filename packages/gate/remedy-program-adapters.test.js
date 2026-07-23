// SPDX-License-Identifier: Apache-2.0
// Generated from remedy-program-adapters.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { canonicalize } from './execution-binding.js';
import { createRemedyMemoryStore, createRemedyProgramKernel, } from './remedy-program.js';
import { signActionEscrowStateStatement } from './action-escrow-state.js';
import { REMEDY_PROGRAM_EVIDENCE_VERSION, createRemedyProgramAdapters, remedyProgramEvidenceDigest, remedyProgramEvidenceSigningBytes, } from './remedy-program-adapters.js';
const NOW = Date.parse('2026-07-22T19:00:00.000Z');
const HASH = (char) => `sha256:${char.repeat(64)}`;
const CAID = (char, action = 'payments.refund') => (`caid:1:${action}.1:jcs-sha256:${char.repeat(43)}`);
function keyPair() {
    const pair = crypto.generateKeyPairSync('ed25519');
    return {
        ...pair,
        publicKeyB64u: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
function digest(value) {
    return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}
function signingIdentity(authorityId, keyId) {
    return { ...keyPair(), authorityId, keyId };
}
function signEvidence(kind, payload, signer) {
    const unsigned = {
        version: REMEDY_PROGRAM_EVIDENCE_VERSION,
        kind,
        issuer: { authority_id: signer.authorityId, key_id: signer.keyId },
        payload,
    };
    const body = { ...unsigned, content_digest: digest(unsigned) };
    const signature = crypto.sign(null, remedyProgramEvidenceSigningBytes(body), signer.privateKey).toString('base64url');
    return {
        ...body,
        signature: { algorithm: 'Ed25519', value: signature },
    };
}
function signRevocation({ operationId, actionDigest, signer, }) {
    const publicKey = signer.publicKeyB64u;
    const statement = {
        '@version': 'EP-REVOCATION-v1',
        target_type: 'commit',
        target_id: operationId,
        action_hash: actionDigest,
        revoker_id: signer.authorityId,
        revoked_at: '2026-07-22T18:20:00.000Z',
        reason: 'future authority withdrawn',
        proof: {
            algorithm: 'Ed25519',
            revoker_key_id: signer.keyId,
            signature_b64u: '',
            public_key: publicKey,
        },
    };
    const signedPayload = {
        '@version': statement['@version'],
        action_hash: statement.action_hash,
        reason: statement.reason,
        revoked_at: statement.revoked_at,
        revoker_id: statement.revoker_id,
        target_id: statement.target_id,
        target_type: statement.target_type,
    };
    statement.proof.signature_b64u = crypto.sign(null, Buffer.from(canonicalize(signedPayload), 'utf8'), signer.privateKey).toString('base64url');
    return statement;
}
class EvidenceSource {
    records = new Map();
    put(tenantId, evidenceId, evidence) {
        const evidenceDigest = remedyProgramEvidenceDigest(evidence);
        this.records.set(`${tenantId}\0${evidenceId}\0${evidenceDigest}`, structuredClone(evidence));
        return { evidenceId, evidenceDigest };
    }
    async get({ tenantId, evidenceId, evidenceDigest }) {
        return structuredClone(this.records.get(`${tenantId}\0${evidenceId}\0${evidenceDigest}`));
    }
}
function harness({ stateSigner = signingIdentity('operator:gate', 'state-key-1') } = {}) {
    const dispute = signingIdentity('authority:disputes', 'dispute-key-1');
    const remedy = signingIdentity('authority:remedies', 'remedy-key-1');
    const provider = signingIdentity('provider:payments', 'provider-key-1');
    const revoker = signingIdentity('authority:revoker', 'revoker-key-1');
    const source = new EvidenceSource();
    const tenantId = 'tenant-1';
    const instanceId = 'remedy-case-1';
    const operationId = 'purchase-release-1';
    const actionDigest = HASH('a');
    const bindingDigest = HASH('b');
    const profileDigest = HASH('c');
    const remedyProfileDigest = HASH('d');
    const destinationBindingDigest = HASH('e');
    const originalCaid = CAID('A', 'commerce.purchase');
    const remedyCaid = CAID('B');
    const remedyActionDigest = HASH('f');
    const capabilityTemplateDigest = HASH('1');
    const agreementId = 'agreement-1';
    const snapshot = {
        '@version': 'EP-ACTION-ESCROW-STATE-v1',
        state: 'released',
        revision: 7,
        release_action_digest: actionDigest,
        document_action_binding_digest: bindingDigest,
        profile_digest: profileDigest,
        release: { operation_idempotency_key: operationId },
    };
    const stateStatement = signActionEscrowStateStatement({
        statementId: 'state-statement-1',
        agreementId,
        bindingDigest,
        actionDigest,
        profileDigest,
        state: 'released',
        revision: 7,
        amendmentDigests: [],
        stateRecord: snapshot,
        previousStatementDigest: null,
        occurredAt: '2026-07-22T18:00:00.000Z',
    }, {
        operatorId: stateSigner.authorityId,
        keyId: stateSigner.keyId,
        privateKey: stateSigner.privateKey,
    });
    const original = {
        caid: originalCaid,
        action_digest: actionDigest,
        operation_id: operationId,
        consequence_mode: 'action-escrow',
        consequence_digest: bindingDigest,
        terminal_evidence_digest: stateStatement.statement_digest,
        outcome: 'executed',
        occurred_at: '2026-07-22T18:00:00.000Z',
    };
    const adapters = createRemedyProgramAdapters({
        tenantId,
        environment: 'production',
        audience: 'merchant-1',
        evidenceSource: source,
        actionEscrow: {
            trustedKeys: {
                [stateSigner.keyId]: {
                    operator_id: stateSigner.authorityId,
                    public_key: stateSigner.publicKeyB64u,
                },
            },
            originalEffects: {
                [operationId]: {
                    agreementId,
                    caid: originalCaid,
                    bindingDigest,
                    profileDigest,
                    amendmentDigests: [],
                },
            },
        },
        revokerKeys: {
            [revoker.authorityId]: {
                public_key: revoker.publicKeyB64u,
                key_id: revoker.keyId,
            },
        },
        disputeAuthority: {
            authorityId: dispute.authorityId,
            trustedKeys: { [dispute.keyId]: dispute.publicKeyB64u },
        },
        remedyAuthority: {
            authorityId: remedy.authorityId,
            trustedKeys: { [remedy.keyId]: remedy.publicKeyB64u },
        },
        providerAuthority: {
            authorityId: provider.authorityId,
            trustedKeys: { [provider.keyId]: provider.publicKeyB64u },
        },
        now: () => NOW,
    });
    const subject = createRemedyProgramKernel({
        store: createRemedyMemoryStore(),
        ...adapters,
        now: () => NOW,
    });
    const createInput = {
        instanceId,
        tenantId,
        environment: 'production',
        audience: 'merchant-1',
        original,
        remedyProfileDigest,
        destinationBindingDigest,
        maxRemedyUnits: 10_000,
        unit: 'USD-cent',
        evidence: { snapshot, statement: stateStatement },
    };
    return {
        subject,
        source,
        signers: { dispute, remedy, provider, revoker, stateSigner },
        values: {
            tenantId,
            instanceId,
            operationId,
            actionDigest,
            remedyCaid,
            remedyActionDigest,
            destinationBindingDigest,
            capabilityTemplateDigest,
            createInput,
        },
    };
}
function disputePayload(h, overrides = {}) {
    const { values } = h;
    return {
        evidence_id: 'dispute-evidence-1',
        tenant_id: values.tenantId,
        instance_id: values.instanceId,
        dispute_id: 'dispute-1',
        challenger_id: 'buyer-1',
        requested_units: 10_000,
        opened_at: '2026-07-22T18:25:00.000Z',
        original_operation_id: values.operationId,
        original_action_digest: values.actionDigest,
        ...overrides,
    };
}
async function createAndDispute(h, artifact) {
    assert.equal((await h.subject.create(h.values.createInput)).ok, true);
    const evidence = artifact ?? signEvidence('dispute', disputePayload(h), h.signers.dispute);
    const ref = h.source.put(h.values.tenantId, 'dispute-evidence-1', evidence);
    return h.subject.openDispute({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        dispute: {
            dispute_id: 'dispute-1',
            evidence_id: ref.evidenceId,
            evidence_digest: ref.evidenceDigest,
            challenger_id: 'buyer-1',
            requested_units: 10_000,
            opened_at: '2026-07-22T18:25:00.000Z',
        },
    });
}
function authorizationPayload(h, overrides = {}) {
    const { values } = h;
    return {
        evidence_id: 'authorization-evidence-1',
        tenant_id: values.tenantId,
        instance_id: values.instanceId,
        dispute_id: 'dispute-1',
        original_operation_id: values.operationId,
        original_action_digest: values.actionDigest,
        remedy_operation_id: 'refund-operation-1',
        remedy_caid: values.remedyCaid,
        remedy_action_digest: values.remedyActionDigest,
        destination_binding_digest: values.destinationBindingDigest,
        consequence_mode: 'receipt-program',
        capability_template_digest: values.capabilityTemplateDigest,
        escrow_profile_digest: null,
        units: 10_000,
        unit: 'USD-cent',
        authorized_at: '2026-07-22T18:30:00.000Z',
        ...overrides,
    };
}
async function authorize(h, artifact) {
    const payload = authorizationPayload(h);
    const evidence = artifact ?? signEvidence('remedy_authorization', payload, h.signers.remedy);
    const ref = h.source.put(h.values.tenantId, payload.evidence_id, evidence);
    return h.subject.authorizeRemedy({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        authorization: {
            evidence_id: ref.evidenceId,
            evidence_digest: ref.evidenceDigest,
            remedy_operation_id: payload.remedy_operation_id,
            remedy_caid: payload.remedy_caid,
            remedy_action_digest: payload.remedy_action_digest,
            consequence_mode: payload.consequence_mode,
            capability_template_digest: payload.capability_template_digest,
            escrow_profile_digest: payload.escrow_profile_digest,
            units: payload.units,
            authorized_at: payload.authorized_at,
        },
    });
}
function providerPayload(h, { evidenceId, outcome, observedAt, reconciliation, }) {
    return {
        evidence_id: evidenceId,
        tenant_id: h.values.tenantId,
        instance_id: h.values.instanceId,
        remedy_operation_id: 'refund-operation-1',
        remedy_action_digest: h.values.remedyActionDigest,
        destination_binding_digest: h.values.destinationBindingDigest,
        units: 10_000,
        unit: 'USD-cent',
        outcome,
        observed_at: observedAt,
        reconciliation,
    };
}
test('real adapters preserve original effect across late revocation and reconcile a signed provider timeout', async () => {
    const h = harness();
    const created = await h.subject.create(h.values.createInput);
    assert.equal(created.ok, true, created.reason);
    const revocation = signRevocation({
        operationId: h.values.operationId,
        actionDigest: h.values.actionDigest,
        signer: h.signers.revoker,
    });
    const revocationRef = h.source.put(h.values.tenantId, 'revocation-evidence-1', revocation);
    const revoked = await h.subject.recordRevocation({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        evidence: { id: revocationRef.evidenceId, digest: revocationRef.evidenceDigest },
    });
    assert.equal(revoked.ok, true, revoked.reason);
    assert.equal(revoked.state.original.outcome, 'executed');
    assert.equal(revoked.state.status, 'effect_executed');
    assert.equal(revoked.state.revocation.effect, 'future_authority_only');
    assert.equal((await createAndDispute(h)).ok, true);
    assert.equal((await authorize(h)).ok, true);
    assert.equal((await h.subject.claimRemedy({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        remedyOperationId: 'refund-operation-1',
        claimToken: 'worker-A',
    })).ok, true);
    const timeoutPayload = providerPayload(h, {
        evidenceId: 'provider-timeout-1',
        outcome: 'indeterminate',
        observedAt: '2026-07-22T18:35:00.000Z',
        reconciliation: false,
    });
    const timeoutRef = h.source.put(h.values.tenantId, timeoutPayload.evidence_id, signEvidence('provider_outcome', timeoutPayload, h.signers.provider));
    const uncertain = await h.subject.finalizeRemedy({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        remedyOperationId: 'refund-operation-1',
        claimToken: 'worker-A',
        outcome: 'indeterminate',
        evidence: {
            evidence_id: timeoutRef.evidenceId,
            evidence_digest: timeoutRef.evidenceDigest,
            observed_at: timeoutPayload.observed_at,
        },
    });
    assert.equal(uncertain.ok, true, uncertain.reason);
    assert.equal(uncertain.state.status, 'remedy_indeterminate');
    const replay = await h.subject.reconcileRemedy({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        remedyOperationId: 'refund-operation-1',
        outcome: 'executed',
        evidence: {
            evidence_id: timeoutRef.evidenceId,
            evidence_digest: timeoutRef.evidenceDigest,
            observed_at: timeoutPayload.observed_at,
        },
    });
    assert.equal(replay.ok, false);
    assert.equal(replay.reason, 'evidence_replayed');
    const executedPayload = providerPayload(h, {
        evidenceId: 'provider-reconciliation-1',
        outcome: 'executed',
        observedAt: '2026-07-22T18:40:00.000Z',
        reconciliation: true,
    });
    const executedRef = h.source.put(h.values.tenantId, executedPayload.evidence_id, signEvidence('provider_outcome', executedPayload, h.signers.provider));
    const reconciled = await h.subject.reconcileRemedy({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        remedyOperationId: 'refund-operation-1',
        outcome: 'executed',
        evidence: {
            evidence_id: executedRef.evidenceId,
            evidence_digest: executedRef.evidenceDigest,
            observed_at: executedPayload.observed_at,
        },
    });
    assert.equal(reconciled.ok, true, reconciled.reason);
    assert.equal(reconciled.state.status, 'remedied');
});
test('tenant, authority key, and exact action substitutions fail closed', async (t) => {
    await t.test('wrong tenant', async () => {
        const h = harness();
        const artifact = signEvidence('dispute', disputePayload(h, { tenant_id: 'tenant-attacker' }), h.signers.dispute);
        const result = await createAndDispute(h, artifact);
        assert.equal(result.ok, false);
        assert.equal(result.reason, 'dispute_invalid');
    });
    await t.test('wrong pinned key', async () => {
        const h = harness();
        const attacker = signingIdentity(h.signers.dispute.authorityId, h.signers.dispute.keyId);
        const artifact = signEvidence('dispute', disputePayload(h), attacker);
        const result = await createAndDispute(h, artifact);
        assert.equal(result.ok, false);
        assert.equal(result.reason, 'dispute_invalid');
    });
    await t.test('wrong remedy action', async () => {
        const h = harness();
        assert.equal((await createAndDispute(h)).ok, true);
        const artifact = signEvidence('remedy_authorization', authorizationPayload(h, { remedy_action_digest: HASH('9') }), h.signers.remedy);
        const result = await authorize(h, artifact);
        assert.equal(result.ok, false);
        assert.equal(result.reason, 'remedy_authorization_invalid');
    });
});
test('exact retries are idempotent but evidence cannot be replayed into another transition', async () => {
    const h = harness();
    const artifact = signEvidence('dispute', disputePayload(h), h.signers.dispute);
    const first = await createAndDispute(h, artifact);
    assert.equal(first.ok, true, first.reason);
    const ref = h.source.put(h.values.tenantId, 'dispute-evidence-1', artifact);
    const retry = await h.subject.openDispute({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        dispute: {
            dispute_id: 'dispute-1',
            evidence_id: ref.evidenceId,
            evidence_digest: ref.evidenceDigest,
            challenger_id: 'buyer-1',
            requested_units: 10_000,
            opened_at: '2026-07-22T18:25:00.000Z',
        },
    });
    assert.equal(retry.ok, true);
    assert.equal(retry.idempotent, true);
    const result = await h.subject.recordRevocation({
        tenantId: h.values.tenantId,
        instanceId: h.values.instanceId,
        evidence: { id: ref.evidenceId, digest: ref.evidenceDigest },
    });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'evidence_replayed');
});
