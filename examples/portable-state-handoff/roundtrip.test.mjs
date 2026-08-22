// SPDX-License-Identifier: Apache-2.0
// Generated from roundtrip.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { InMemoryRecipientStateBoundary, PORTABLE_STATE_ACTIONS, PORTABLE_STATE_SIGNATURE_PROFILE, importPortableState, stateActionExpectation, stateHandoffDigest, verifyPortableStateImportReceipt, verifyPortableStateImportReceiptForManifest, } from '../../packages/verify/src/portable-state-handoff.js';
import { somaCogobjPayloadAdapter } from '../../packages/verify/src/soma-cogobj-profile.js';
import { exportPortableSomaState, independentDigest } from './continuum-exporter.mjs';
function key(label) {
    const privateKey = crypto.createPrivateKey({
        key: Buffer.concat([
            Buffer.from('302e020100300506032b657004220420', 'hex'),
            crypto.createHash('sha256').update(label).digest(),
        ]),
        format: 'der',
        type: 'pkcs8',
    });
    return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}
const source = key('continuum-independent-source');
const importer = key('emilia-independent-importer');
const sourceId = 'urn:agent:continuum:smith';
const sourceBoundaryId = 'urn:ep:aeb:continuum:state-export';
const recipientId = 'urn:agent:emilia:receiver';
const recipientBoundaryId = 'urn:ep:aeb:emilia:state-import';
const objects = [{
        object_id: 'urn:cogobj:operations:curtailment',
        domain: 'operations',
        schema_uri: 'urn:soma:schema:curtailment:v1',
        snapshot: {
            asserted_at: '2026-08-21T17:55:00Z',
            source_mutability: 'MUTABLE',
            observed_at: null,
            freshness_basis_digest: null,
        },
        sensitivity: 'PROTECTED',
        protection: { mode: 'PLAINTEXT', profile: null, key_reference_digest: null },
        disposition: 'ACTIVE',
        origin: {
            assertion_class: 'agent-generated',
            issuer: sourceId,
            asserted_at: '2026-08-21T17:55:00Z',
            source_digest: null,
            transform_id: 'continuum:session-close:v1',
        },
        lineage: { generation: 0, predecessor_digest: null },
        authority_semantics: 'NONE',
        content: {
            note: 'Portable context is not permission to curtail power.',
            jcs_negative_zero_alias: -0,
        },
    }];
async function build() {
    return exportPortableSomaState({
        handoff_id: 'urn:ep:state-handoff:roundtrip:1',
        source_agent: sourceId,
        source_boundary_id: sourceBoundaryId,
        recipient_agent: recipientId,
        recipient_boundary_id: recipientBoundaryId,
        relying_party_id: 'urn:org:example',
        created_at: '2026-08-21T17:56:00Z',
        snapshot_at: '2026-08-21T17:55:00Z',
        expires_at: '2026-08-21T19:00:00Z',
        nonce: 'independent-roundtrip-0001',
        objects,
        optional_object_ids: [],
        signer: { key_id: 'continuum-source-1', private_key: source.privateKey },
    });
}
test('independent Continuum producer and EMILIA recipient agree on bytes, bindings, and terminal receipt', async () => {
    const one = await build();
    const two = await build();
    assert.equal(independentDigest(one), independentDigest(two));
    assert.equal(independentDigest(one.manifest), stateHandoffDigest(one.manifest));
    for (const action of one.manifest.authority.source_actions) {
        const expected = stateActionExpectation(one.manifest, action);
        one.source_authority_evidence[action] = { caid: expected.caid, consumed: true };
    }
    const importExpected = stateActionExpectation(one.manifest, PORTABLE_STATE_ACTIONS.IMPORT);
    const boundary = new InMemoryRecipientStateBoundary({
        authorizeImport(expected, evidence) {
            if (evidence?.caid !== expected.caid) {
                return { status: 'REFUSED', reasons: ['import_authority_invalid'] };
            }
            return {
                status: 'AUTHORIZED',
                receipt_digest: stateHandoffDigest({ recipient: expected.caid }),
            };
        },
    });
    const importerPolicy = {
        profile: PORTABLE_STATE_SIGNATURE_PROFILE,
        required_algorithms: ['Ed25519'],
    };
    const receipt = await importPortableState(one, {
        now: '2026-08-21T18:00:00Z',
        expected_recipient_agent: recipientId,
        expected_recipient_boundary_id: recipientBoundaryId,
        expected_relying_party_id: 'urn:org:example',
        source_signer_pins: [{
                alg: 'Ed25519',
                key_id: 'continuum-source-1',
                public_key: source.publicKey,
                status: 'active',
                principals: [sourceId],
                valid_from: '2026-01-01T00:00:00Z',
                valid_until: '2027-01-01T00:00:00Z',
            }],
        payload_adapters: [somaCogobjPayloadAdapter],
        source_authority_verifier: {
            async verify(expected, evidence) {
                if (evidence?.caid !== expected.caid
                    || evidence?.consumed !== true) {
                    return { status: 'REFUSED', reasons: ['source_release_invalid'] };
                }
                return {
                    status: 'VERIFIED',
                    consumption: 'CONSUMED',
                    receipt_digest: stateHandoffDigest({ source: expected.caid }),
                };
            },
        },
        recipient_boundary: boundary,
        import_authority_evidence: { caid: importExpected.caid },
        importer_signer: {
            principal_id: recipientBoundaryId,
            policy: importerPolicy,
            keys: [{ alg: 'Ed25519', key_id: 'emilia-importer-1', private_key: importer.privateKey }],
        },
    });
    assert.equal(receipt.result, 'ACCEPTED');
    assert.deepEqual(receipt.accepted_object_ids, [objects[0].object_id]);
    const pins = [{
            alg: 'Ed25519',
            key_id: 'emilia-importer-1',
            public_key: importer.publicKey,
            status: 'active',
            principals: [recipientBoundaryId],
            valid_from: '2026-01-01T00:00:00Z',
            valid_until: '2027-01-01T00:00:00Z',
        }];
    assert.deepEqual(await verifyPortableStateImportReceipt(receipt, pins), { valid: true, reasons: [] });
    assert.deepEqual(await verifyPortableStateImportReceiptForManifest(receipt, one.manifest, pins), { valid: true, reasons: [] });
});
test('independent producer rejects Unicode member names the recipient canonicalizer cannot represent', async () => {
    const hostile = structuredClone(objects[0]);
    hostile.content = { ['bad\ud800key']: 'must refuse before signing' };
    await assert.rejects(exportPortableSomaState({
        handoff_id: 'urn:ep:state-handoff:roundtrip:unicode-hostile',
        source_agent: sourceId,
        source_boundary_id: sourceBoundaryId,
        recipient_agent: recipientId,
        recipient_boundary_id: recipientBoundaryId,
        relying_party_id: 'urn:org:example',
        created_at: '2026-08-21T17:56:00Z',
        snapshot_at: '2026-08-21T17:55:00Z',
        expires_at: '2026-08-21T19:00:00Z',
        nonce: 'independent-roundtrip-unicode-hostile-0001',
        objects: [hostile],
        optional_object_ids: [],
        signer: { key_id: 'continuum-source-1', private_key: source.privateKey },
    }), /unpaired surrogate/);
});
