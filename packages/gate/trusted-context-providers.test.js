// SPDX-License-Identifier: Apache-2.0
// Generated from trusted-context-providers.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { verifyMemoryProjectionRecordV1, } from '@emilia-protocol/verify/memory-projection';
import { canonicalContextBindingDigest, canonicalContextRecordDigest, createTrustedContextEvaluator, signTrustedContextBinding, trustedContextPolicyDigest, } from './trusted-context.js';
import { SHEESH_CONTEXT_FRAME_PROFILE, SHEESH_PROVIDER_ID, SHEESH_SOURCE_PROFILE, createSheeshContextProvider, createSheeshMemoryProjection, } from './sheesh-context.js';
import { ZEP_CONTEXT_FRAME_PROFILE, ZEP_PROVIDER_ID, ZEP_SOURCE_PROFILE, createZepContextProvider, createZepMemoryProjection, } from './zep-context.js';
const CREATED_AT = '2026-08-21T16:00:00.000Z';
const STATUS_AT = '2026-08-21T16:00:10.000Z';
const VERIFY_AT = '2026-08-21T16:00:30.000Z';
const VALID_FROM = '2026-08-21T00:00:00.000Z';
const VALID_TO = '2027-08-21T00:00:00.000Z';
const ADAPTER = generateKeyPairSync('ed25519');
const BINDER = generateKeyPairSync('ed25519');
const ADAPTER_KEY_ID = 'adapter-2026-08';
const BINDER_KEY_ID = 'binder-2026-08';
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function adapterKeys() {
    return {
        [ADAPTER_KEY_ID]: {
            public_key_spki_b64u: spki(ADAPTER.publicKey),
            status: 'active',
            valid_from: VALID_FROM,
            valid_to: VALID_TO,
            revoked_at: null,
        },
    };
}
function selectionContext() {
    return {
        recallRequestBytes: Buffer.from('{"task":"summarize one bounded domain"}'),
        selectionPolicyBytes: Buffer.from('{"max_sources":1}'),
        trustSnapshotBytes: Buffer.from('{"source_status":"unverified"}'),
        trustEvaluatedAt: CREATED_AT,
    };
}
function verifyFull(output, expectedSourceProfile, expectedContextFrameProfile) {
    return verifyMemoryProjectionRecordV1(output.record, output.verificationMaterial, {
        adapterKeys: adapterKeys(),
        verificationTime: VERIFY_AT,
        maxProjectionAgeSec: 300,
        maxTrustAgeSec: 300,
        expectedSourceProfile,
        expectedContextFrameProfile,
    });
}
test('SHEESH adapter commits the exact repo revision, path, source bytes, and projection bytes', () => {
    const output = createSheeshMemoryProjection({
        projectionId: 'urn:uuid:11111111-1111-4111-8111-111111111111',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://operator.example/adapters/sheesh',
            keyId: ADAPTER_KEY_ID,
            privateKey: ADAPTER.privateKey,
        },
        selectionContext: selectionContext(),
        sources: [{
                repositoryUri: 'https://github.com/example/continuum',
                revision: '0123456789abcdef0123456789abcdef01234567',
                path: 'continuum/domains/finance.cogobj',
                sourceBytes: Buffer.from('{"domain":"finance","fact":"approved limit is 1000"}'),
                contextFragmentBytes: Buffer.from('approved limit is 1000'),
            }],
    });
    const verified = verifyFull(output, SHEESH_SOURCE_PROFILE, SHEESH_CONTEXT_FRAME_PROFILE);
    assert.equal(verified.valid, true);
    assert.equal(verified.delivered_count, 1);
    assert.equal(output.record.delivered[0].derived_trust, 'unverified');
    assert.equal(output.record.delivered[0].authorship, 'unknown');
});
test('SHEESH adapter refuses traversal paths and detects changed source bytes', () => {
    assert.throws(() => createSheeshMemoryProjection({
        projectionId: 'urn:uuid:22222222-2222-4222-8222-222222222222',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://operator.example/adapters/sheesh',
            keyId: ADAPTER_KEY_ID,
            privateKey: ADAPTER.privateKey,
        },
        selectionContext: selectionContext(),
        sources: [{
                repositoryUri: 'https://github.com/example/continuum',
                revision: 'main',
                path: '../secrets.cogobj',
                sourceBytes: Buffer.from('{}'),
                contextFragmentBytes: Buffer.from('x'),
            }],
    }), /source path invalid/);
    const output = createSheeshMemoryProjection({
        projectionId: 'urn:uuid:33333333-3333-4333-8333-333333333333',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://operator.example/adapters/sheesh',
            keyId: ADAPTER_KEY_ID,
            privateKey: ADAPTER.privateKey,
        },
        selectionContext: selectionContext(),
        sources: [{
                repositoryUri: 'https://github.com/example/continuum',
                revision: 'main',
                path: 'continuum/somatic_index.json',
                sourceBytes: Buffer.from('{"domains":[]}'),
                contextFragmentBytes: Buffer.from('no domains selected'),
            }],
    });
    output.verificationMaterial.sourceObjectBytesByPosition[0] = Buffer.from('{"tampered":true}');
    assert.throws(() => verifyFull(output, SHEESH_SOURCE_PROFILE, SHEESH_CONTEXT_FRAME_PROFILE), /source object 0 does not match its commitment/);
});
test('a deployment-owned SHEESH verifier can make a bounded trust assertion and is rerun by full verification', () => {
    let verifierRuns = 0;
    const trustedSource = ({ sealedObjectDigest }) => {
        verifierRuns += 1;
        return {
            valid: true,
            formatVersion: 1,
            sealedObjectDigest,
            derivedTrust: 'trusted',
            authorship: 'attested',
            authorKeyIdB64u: Buffer.from('author01').toString('base64url'),
            custodyPresent: true,
        };
    };
    const output = createSheeshMemoryProjection({
        projectionId: 'urn:uuid:44444444-4444-4444-8444-444444444444',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://operator.example/adapters/sheesh',
            keyId: ADAPTER_KEY_ID,
            privateKey: ADAPTER.privateKey,
        },
        selectionContext: selectionContext(),
        verifyNativeSource: trustedSource,
        sources: [{
                repositoryUri: 'https://github.com/example/continuum',
                revision: 'v1.0.0',
                path: 'continuum/domains/finance.cogobj.enc',
                sourceBytes: Buffer.from('ciphertext'),
                contextFragmentBytes: Buffer.from('approved limit is 1000'),
            }],
    });
    verifyFull(output, SHEESH_SOURCE_PROFILE, SHEESH_CONTEXT_FRAME_PROFILE);
    assert.equal(output.record.delivered[0].derived_trust, 'trusted');
    assert.equal(verifierRuns, 2);
});
test('Zep adapter binds graph identity, episode identity, raw result bytes, and projection bytes', () => {
    const output = createZepMemoryProjection({
        projectionId: 'urn:uuid:55555555-5555-4555-8555-555555555555',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://operator.example/adapters/zep',
            keyId: ADAPTER_KEY_ID,
            privateKey: ADAPTER.privateKey,
        },
        selectionContext: selectionContext(),
        sources: [{
                projectId: 'proj_123',
                graphId: 'finance-operations',
                episodeUuid: 'episode-456',
                sourceBytes: Buffer.from('{"uuid":"episode-456","content":"supplier account 1111"}'),
                contextFragmentBytes: Buffer.from('supplier account 1111'),
            }],
    });
    const verified = verifyFull(output, ZEP_SOURCE_PROFILE, ZEP_CONTEXT_FRAME_PROFILE);
    assert.equal(verified.valid, true);
    assert.equal(output.record.delivered[0].derived_trust, 'unverified');
    output.verificationMaterial.fragmentBytesByPosition[0] = Buffer.from('supplier account 9999');
    assert.throws(() => verifyFull(output, ZEP_SOURCE_PROFILE, ZEP_CONTEXT_FRAME_PROFILE), /fragment 0 does not match its commitment/);
});
test('Gate pins provider and profile, binds one exact action, and never treats context as authorization', () => {
    const output = createZepMemoryProjection({
        projectionId: 'urn:uuid:66666666-6666-4666-8666-666666666666',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://operator.example/adapters/zep',
            keyId: ADAPTER_KEY_ID,
            privateKey: ADAPTER.privateKey,
        },
        selectionContext: selectionContext(),
        sources: [{
                projectId: 'proj_123',
                graphId: 'finance-operations',
                episodeUuid: 'episode-789',
                sourceBytes: Buffer.from('{"uuid":"episode-789","content":"known payee is 1111"}'),
                contextFragmentBytes: Buffer.from('known payee is 1111'),
            }],
    });
    const actionSubject = {
        action_type: 'vendor.bank_detail.change',
        vendor_id: 'vendor-42',
        proposed_account: '9999',
    };
    const policy = {
        policy_id: 'trusted-context/vendor-bank-detail/v1',
        provider_id: ZEP_PROVIDER_ID,
        provider_profile: ZEP_SOURCE_PROFILE,
        max_projection_age_sec: 300,
        max_keyring_age_sec: 300,
        max_signer_status_age_sec: 300,
        allowed_trust: ['unverified'],
        allowed_exclusion_reasons: ['authentication_failed', 'schema_invalid', 'policy_filtered', 'context_limit'],
        max_excluded_objects: 0,
        require_current_signer_status: true,
    };
    const binding = signTrustedContextBinding({
        providerId: ZEP_PROVIDER_ID,
        providerProfile: ZEP_SOURCE_PROFILE,
        projectionRecord: output.record,
        action: actionSubject,
        policyDigest: trustedContextPolicyDigest(policy),
        nonce: 'admission-nonce-1',
        issuedAt: CREATED_AT,
        expiresAt: '2026-08-21T16:05:00.000Z',
        binderId: 'https://operator.example/gate',
        keyId: BINDER_KEY_ID,
        privateKey: BINDER.privateKey,
    });
    const action = {
        ...actionSubject,
        trusted_context: {
            provider_id: ZEP_PROVIDER_ID,
            provider_profile: ZEP_SOURCE_PROFILE,
            projection_record_digest: canonicalContextRecordDigest(output.record),
            projection_digest: output.record.projection.digest,
            context_binding_digest: canonicalContextBindingDigest(binding),
        },
    };
    const evidence = {
        provider_id: ZEP_PROVIDER_ID,
        provider_profile: ZEP_SOURCE_PROFILE,
        projection_record: output.record,
        context_binding: binding,
    };
    const evaluate = createTrustedContextEvaluator({
        providers: [createZepContextProvider({
                adapterKeys: adapterKeys(),
                statusCheckedAt: STATUS_AT,
            })],
        policy,
        bindingKeys: {
            [BINDER_KEY_ID]: {
                public_key_spki_b64u: spki(BINDER.publicKey),
                status: 'active',
                valid_from: VALID_FROM,
                valid_to: VALID_TO,
                revoked_at: null,
            },
        },
        bindingStatusCheckedAt: STATUS_AT,
        expectedBindingNonce: 'admission-nonce-1',
        verificationTime: VERIFY_AT,
    });
    const accepted = evaluate({ evidence, action });
    assert.equal(accepted.state, 'VERIFIED');
    assert.equal(accepted.authorizes, false);
    const substituted = evaluate({
        evidence,
        action: { ...action, proposed_account: '0000' },
    });
    assert.equal(substituted.state, 'NOT_VERIFIED');
    assert.equal(substituted.reason, 'action_context_binding_mismatch');
    const wrongProvider = createSheeshContextProvider({
        adapterKeys: adapterKeys(),
        statusCheckedAt: STATUS_AT,
    });
    assert.equal(wrongProvider.providerId, SHEESH_PROVIDER_ID);
    assert.equal(wrongProvider.profileId, SHEESH_SOURCE_PROFILE);
    assert.equal(wrongProvider.verifyProjection(output.record, {
        verificationTime: VERIFY_AT,
        maxSignerStatusAgeSec: 300,
        maxProjectionAgeSec: 300,
        maxTrustAgeSec: 300,
    }).state, 'NOT_VERIFIED');
});
test('stale adapter status remains INDETERMINATE instead of becoming a negative fact', () => {
    const provider = createZepContextProvider({
        adapterKeys: adapterKeys(),
        statusCheckedAt: '2026-08-21T15:00:00.000Z',
    });
    const output = createZepMemoryProjection({
        projectionId: 'urn:uuid:77777777-7777-4777-8777-777777777777',
        createdAt: CREATED_AT,
        adapter: {
            id: 'https://operator.example/adapters/zep',
            keyId: ADAPTER_KEY_ID,
            privateKey: ADAPTER.privateKey,
        },
        selectionContext: selectionContext(),
        sources: [{
                projectId: 'proj_123',
                graphId: 'finance-operations',
                episodeUuid: 'episode-000',
                sourceBytes: Buffer.from('{}'),
                contextFragmentBytes: Buffer.from('unknown'),
            }],
    });
    assert.deepEqual(provider.verifyProjection(output.record, {
        verificationTime: VERIFY_AT,
        maxSignerStatusAgeSec: 300,
        maxProjectionAgeSec: 300,
        maxTrustAgeSec: 300,
    }), {
        state: 'INDETERMINATE',
        reason: 'adapter_status_stale',
    });
});
