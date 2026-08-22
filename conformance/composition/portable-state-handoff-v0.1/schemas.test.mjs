// SPDX-License-Identifier: Apache-2.0
// Generated from schemas.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { exportPortableSomaState } from '../../../examples/portable-state-handoff/continuum-exporter.mjs';
import { stateHandoffDigest } from '../../../packages/verify/src/portable-state-handoff.js';
const root = new URL('../../../', import.meta.url);
function key() {
    const privateKey = crypto.createPrivateKey({
        key: Buffer.concat([
            Buffer.from('302e020100300506032b657004220420', 'hex'),
            crypto.createHash('sha256').update('schema-artifact').digest(),
        ]),
        format: 'der',
        type: 'pkcs8',
    });
    return privateKey;
}
async function schema(name) {
    return JSON.parse(await readFile(new URL(`conformance/schemas/${name}`, root), 'utf8'));
}
async function bundle() {
    return exportPortableSomaState({
        handoff_id: 'urn:ep:state-handoff:schema:1',
        source_agent: 'urn:agent:source',
        source_boundary_id: 'urn:ep:aeb:source:state-export',
        recipient_agent: 'urn:agent:recipient',
        recipient_boundary_id: 'urn:ep:aeb:recipient:state-import',
        relying_party_id: 'urn:org:example',
        created_at: '2026-08-21T17:56:00Z',
        snapshot_at: '2026-08-21T17:55:00Z',
        expires_at: '2026-08-21T19:00:00Z',
        nonce: 'schema-artifact-1',
        objects: [{
                object_id: 'urn:cogobj:schema:1',
                domain: 'test',
                schema_uri: 'urn:soma:schema:test:v1',
                snapshot: {
                    asserted_at: '2026-08-21T17:55:00Z',
                    source_mutability: 'UNKNOWN',
                    observed_at: null,
                    freshness_basis_digest: null,
                },
                sensitivity: 'OPEN',
                protection: { mode: 'PLAINTEXT', profile: null, key_reference_digest: null },
                disposition: 'ACTIVE',
                origin: {
                    assertion_class: 'agent-generated',
                    issuer: 'urn:agent:source',
                    asserted_at: '2026-08-21T17:55:00Z',
                    source_digest: null,
                    transform_id: null,
                },
                lineage: { generation: 0, predecessor_digest: null },
                authority_semantics: 'NONE',
                content: { value: 'portable state, not authority' },
            }],
        optional_object_ids: [],
        signer: { key_id: 'source-key', private_key: key() },
    });
}
test('published schemas compile, accept reference artifacts, and reject unknown members', async () => {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    const manifestValidator = ajv.compile(await schema('state-handoff-manifest.v0.1.schema.json'));
    const cogobjValidator = ajv.compile(await schema('soma-cogobj.v0.1.schema.json'));
    const receiptValidator = ajv.compile(await schema('state-handoff-import-receipt.v0.1.schema.json'));
    const created = await bundle();
    assert.equal(manifestValidator(created.manifest), true, JSON.stringify(manifestValidator.errors));
    assert.equal(cogobjValidator(created.objects[0]), true, JSON.stringify(cogobjValidator.errors));
    const receipt = {
        '@version': 'EP-STATE-HANDOFF-IMPORT-RECEIPT-v0.1',
        receipt_kind: 'INITIAL',
        handoff_id: created.manifest.handoff_id,
        manifest_digest: stateHandoffDigest(created.manifest),
        payload_profile: created.manifest.payload_profile,
        importer_boundary_id: 'urn:ep:aeb:recipient:state-import',
        result: 'ACCEPTED',
        accepted_object_ids: [created.objects[0].object_id],
        unavailable_objects: [],
        reasons: [],
        authority_evidence: [
            {
                stage: 'SOURCE_RELEASE',
                action: 'agent.state.export.1',
                caid: 'caid:1:agent.state.export.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                receipt_digest: `sha256:${'1'.repeat(64)}`,
            },
            {
                stage: 'RECIPIENT_COMMIT',
                action: 'agent.state.import.1',
                caid: 'caid:1:agent.state.import.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                receipt_digest: `sha256:${'2'.repeat(64)}`,
            },
        ],
        admission_record_digest: `sha256:${'3'.repeat(64)}`,
        completed_at: '2026-08-21T18:00:00Z',
        issued_at: '2026-08-21T18:00:00Z',
        nonclaims: created.manifest.nonclaims,
        signature_policy: { profile: 'EP-SIG-AGILITY-v1', required_algorithms: ['Ed25519'] },
        signatures: [{
                alg: 'Ed25519',
                sig: Buffer.alloc(64, 7).toString('base64url'),
                key_id: 'recipient-key',
            }],
    };
    assert.equal(receiptValidator(receipt), true, JSON.stringify(receiptValidator.errors));
    const hostileManifest = { ...created.manifest, unrecognized_critical_member: true };
    const hostileObject = { ...created.objects[0], embedded_authority: true };
    const hostileReceipt = { ...receipt, unsigned_claim: 'smuggled' };
    assert.equal(manifestValidator(hostileManifest), false);
    assert.equal(cogobjValidator(hostileObject), false);
    assert.equal(receiptValidator(hostileReceipt), false);
});
