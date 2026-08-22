#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { generateKeyPairSync } from 'node:crypto';
import { verifyMemoryProjectionRecordV1, } from '@emilia-protocol/verify/memory-projection';
import { canonicalContextBindingDigest, canonicalContextRecordDigest, createTrustedContextEvaluator, signTrustedContextBinding, trustedContextPolicyDigest, } from '@emilia-protocol/gate/trusted-context';
import { SHEESH_PROVIDER_ID, SHEESH_SOURCE_PROFILE, SHEESH_CONTEXT_FRAME_PROFILE, createSheeshContextProvider, createSheeshMemoryProjection, } from '@emilia-protocol/gate/trusted-context/sheesh';
import { ZEP_PROVIDER_ID, ZEP_SOURCE_PROFILE, ZEP_CONTEXT_FRAME_PROFILE, createZepContextProvider, createZepMemoryProjection, } from '@emilia-protocol/gate/trusted-context/zep';
const CREATED_AT = '2026-08-21T16:00:00.000Z';
const STATUS_AT = '2026-08-21T16:00:10.000Z';
const VERIFY_AT = '2026-08-21T16:00:30.000Z';
const VALID_FROM = '2026-08-21T00:00:00.000Z';
const VALID_TO = '2027-08-21T00:00:00.000Z';
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
export function runTrustedContextMultiProviderDemo() {
    const adapter = generateKeyPairSync('ed25519');
    const binder = generateKeyPairSync('ed25519');
    const adapterKeyId = 'demo-adapter-2026-08';
    const binderKeyId = 'demo-binder-2026-08';
    const adapterKeys = {
        [adapterKeyId]: {
            public_key_spki_b64u: spki(adapter.publicKey),
            status: 'active',
            valid_from: VALID_FROM,
            valid_to: VALID_TO,
            revoked_at: null,
        },
    };
    const selectionContext = {
        recallRequestBytes: Buffer.from('{"workflow":"vendor-bank-detail-change"}'),
        selectionPolicyBytes: Buffer.from('{"max_sources":1,"native_trust":"unverified"}'),
        trustSnapshotBytes: Buffer.from('{"checked_at":"2026-08-21T16:00:00.000Z"}'),
        trustEvaluatedAt: CREATED_AT,
    };
    const sheesh = createSheeshMemoryProjection({
        projectionId: 'urn:uuid:81000000-0000-4000-8000-000000000001',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://demo.example/adapters/sheesh',
            keyId: adapterKeyId,
            privateKey: adapter.privateKey,
        },
        selectionContext,
        sources: [{
                repositoryUri: 'https://github.com/example/continuum',
                revision: '0123456789abcdef0123456789abcdef01234567',
                path: 'continuum/domains/finance.cogobj',
                sourceBytes: Buffer.from('{"vendor_id":"vendor-42","known_account":"1111"}'),
                contextFragmentBytes: Buffer.from('vendor-42 known account is 1111'),
            }],
    });
    const zep = createZepMemoryProjection({
        projectionId: 'urn:uuid:81000000-0000-4000-8000-000000000002',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://demo.example/adapters/zep',
            keyId: adapterKeyId,
            privateKey: adapter.privateKey,
        },
        selectionContext,
        sources: [{
                projectId: 'demo-project',
                graphId: 'finance-operations',
                episodeUuid: 'episode-vendor-42',
                sourceBytes: Buffer.from('{"uuid":"episode-vendor-42","content":"known account is 1111"}'),
                contextFragmentBytes: Buffer.from('vendor-42 known account is 1111'),
            }],
    });
    const fullPolicy = (sourceProfile, contextFrameProfile) => ({
        adapterKeys,
        verificationTime: VERIFY_AT,
        maxProjectionAgeSec: 300,
        maxTrustAgeSec: 300,
        expectedSourceProfile: sourceProfile,
        expectedContextFrameProfile: contextFrameProfile,
    });
    const sheeshFull = verifyMemoryProjectionRecordV1(sheesh.record, sheesh.verificationMaterial, fullPolicy(SHEESH_SOURCE_PROFILE, SHEESH_CONTEXT_FRAME_PROFILE));
    const zepFull = verifyMemoryProjectionRecordV1(zep.record, zep.verificationMaterial, fullPolicy(ZEP_SOURCE_PROFILE, ZEP_CONTEXT_FRAME_PROFILE));
    const policy = {
        policy_id: 'trusted-context/vendor-bank-detail/v1',
        provider_id: ZEP_PROVIDER_ID,
        provider_profile: ZEP_SOURCE_PROFILE,
        max_projection_age_sec: 300,
        max_keyring_age_sec: 300,
        max_signer_status_age_sec: 300,
        allowed_trust: ['unverified'],
        allowed_exclusion_reasons: [
            'authentication_failed',
            'schema_invalid',
            'policy_filtered',
            'context_limit',
        ],
        max_excluded_objects: 0,
        require_current_signer_status: true,
    };
    const actionSubject = {
        action_type: 'vendor.bank_detail.change',
        vendor_id: 'vendor-42',
        proposed_account: '9999',
    };
    const binding = signTrustedContextBinding({
        providerId: ZEP_PROVIDER_ID,
        providerProfile: ZEP_SOURCE_PROFILE,
        projectionRecord: zep.record,
        action: actionSubject,
        policyDigest: trustedContextPolicyDigest(policy),
        nonce: 'demo-admission-1',
        issuedAt: CREATED_AT,
        expiresAt: '2026-08-21T16:05:00.000Z',
        binderId: 'https://demo.example/gate',
        keyId: binderKeyId,
        privateKey: binder.privateKey,
    });
    const action = {
        ...actionSubject,
        trusted_context: {
            provider_id: ZEP_PROVIDER_ID,
            provider_profile: ZEP_SOURCE_PROFILE,
            projection_record_digest: canonicalContextRecordDigest(zep.record),
            projection_digest: zep.record.projection.digest,
            context_binding_digest: canonicalContextBindingDigest(binding),
        },
    };
    const evidence = {
        provider_id: ZEP_PROVIDER_ID,
        provider_profile: ZEP_SOURCE_PROFILE,
        projection_record: zep.record,
        context_binding: binding,
    };
    const evaluate = createTrustedContextEvaluator({
        providers: [
            createZepContextProvider({ adapterKeys, statusCheckedAt: STATUS_AT }),
            createSheeshContextProvider({ adapterKeys, statusCheckedAt: STATUS_AT }),
        ],
        policy,
        bindingKeys: {
            [binderKeyId]: {
                public_key_spki_b64u: spki(binder.publicKey),
                status: 'active',
                valid_from: VALID_FROM,
                valid_to: VALID_TO,
                revoked_at: null,
            },
        },
        bindingStatusCheckedAt: STATUS_AT,
        expectedBindingNonce: 'demo-admission-1',
        verificationTime: VERIFY_AT,
    });
    const exact = evaluate({ evidence, action });
    const substituted = evaluate({
        evidence,
        action: { ...action, proposed_account: '0000' },
    });
    const stale = createZepContextProvider({
        adapterKeys,
        statusCheckedAt: '2026-08-21T15:00:00.000Z',
    }).verifyProjection(zep.record, {
        verificationTime: VERIFY_AT,
        maxSignerStatusAgeSec: 300,
        maxProjectionAgeSec: 300,
        maxTrustAgeSec: 300,
    });
    const wrongProfile = createSheeshContextProvider({
        adapterKeys,
        statusCheckedAt: STATUS_AT,
    }).verifyProjection(zep.record, {
        verificationTime: VERIFY_AT,
        maxSignerStatusAgeSec: 300,
        maxProjectionAgeSec: 300,
        maxTrustAgeSec: 300,
    });
    let tamperObserved = 'accepted';
    try {
        const tampered = {
            ...zep.verificationMaterial,
            sourceObjectBytesByPosition: [Buffer.from('{"tampered":true}')],
        };
        verifyMemoryProjectionRecordV1(zep.record, tampered, fullPolicy(ZEP_SOURCE_PROFILE, ZEP_CONTEXT_FRAME_PROFILE));
    }
    catch {
        tamperObserved = 'refused';
    }
    const cases = [
        {
            case_id: 'TCM-01-sheesh-exact-source-and-projection-verified',
            passed: sheeshFull.valid && sheesh.record.delivered[0].derived_trust === 'unverified',
            observed: sheeshFull.verification_scope,
        },
        {
            case_id: 'TCM-02-zep-exact-source-and-projection-verified',
            passed: zepFull.valid && zep.record.delivered[0].derived_trust === 'unverified',
            observed: zepFull.verification_scope,
        },
        {
            case_id: 'TCM-03-exact-action-context-verified-not-authorized',
            passed: exact.state === 'VERIFIED' && exact.authorizes === false,
            observed: `${exact.state}:authorizes=${String(exact.authorizes)}`,
        },
        {
            case_id: 'TCM-04-action-substitution-refused',
            passed: substituted.state === 'NOT_VERIFIED'
                && substituted.reason === 'action_context_binding_mismatch',
            observed: `${substituted.state}:${substituted.reason}`,
        },
        {
            case_id: 'TCM-05-provider-profile-substitution-refused',
            passed: wrongProfile.state === 'NOT_VERIFIED',
            observed: `${wrongProfile.state}:${wrongProfile.reason}`,
        },
        {
            case_id: 'TCM-06-stale-status-remains-indeterminate',
            passed: stale.state === 'INDETERMINATE' && stale.reason === 'adapter_status_stale',
            observed: `${stale.state}:${stale.reason}`,
        },
        {
            case_id: 'TCM-07-source-byte-tamper-refused',
            passed: tamperObserved === 'refused',
            observed: tamperObserved,
        },
    ];
    return {
        '@version': 'EMILIA-TRUSTED-CONTEXT-MULTI-PROVIDER-REPORT-v1',
        generated_at: CREATED_AT,
        providers: [SHEESH_PROVIDER_ID, ZEP_PROVIDER_ID],
        claim_boundary: 'This local reference run verifies EMILIA-owned interop profiles over synthetic SHEESH-shaped and Zep-shaped source bytes, exact projection commitments, and one action binding. It is not a native provider conformance result, provider endorsement, live service connection, production deployment, source-truth proof, or authorization decision.',
        passed: cases.every((entry) => entry.passed),
        checks_passed: cases.filter((entry) => entry.passed).length,
        checks_total: cases.length,
        cases,
    };
}
if (import.meta.url === `file://${process.argv[1]}`) {
    console.log(JSON.stringify(runTrustedContextMultiProviderDemo(), null, 2));
}
