// SPDX-License-Identifier: Apache-2.0
// Generated from generate-trusted-context.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { canonicalContextBindingDigest, canonicalContextRecordDigest, signTrustedContextBinding, trustedContextPolicyDigest, } from '../../packages/gate/trusted-context.js';
const OUTPUT = fileURLToPath(new URL('./trusted-context.v1.json', import.meta.url));
const AMEM = fileURLToPath(new URL('../../interop/apertomemory-emilia/apertomemory-emilia.v1.json', import.meta.url));
const source = JSON.parse(readFileSync(AMEM, 'utf8'));
const projectionRecord = source.projection.record;
const HASH = (character) => `sha256:${character.repeat(64)}`;
function deterministicEd25519(label) {
    const privateKey = crypto.createPrivateKey({
        key: Buffer.concat([
            Buffer.from('302e020100300506032b657004220420', 'hex'),
            crypto.createHash('sha256').update(label).digest(),
        ]),
        format: 'der',
        type: 'pkcs8',
    });
    // Node accepts a private KeyObject here and derives its public half. The
    // ambient @types/node version lacks that runtime overload.
    const publicKey = crypto.createPublicKey(privateKey);
    return { privateKey, publicKey };
}
const binder = deterministicEd25519('emilia/trusted-context/v1/binder');
const binderKeyId = 'gate-context-binder-vector-01';
const policy = {
    policy_id: 'trusted-context/software-remediation/v1',
    provider_id: 'apertomemory',
    provider_profile: 'draft-ferro-apertomemory-02',
    max_projection_age_sec: 300,
    max_keyring_age_sec: 300,
    max_signer_status_age_sec: 300,
    allowed_trust: ['self', 'trusted'],
    allowed_exclusion_reasons: [
        'authentication_failed',
        'schema_invalid',
        'policy_filtered',
        'context_limit',
    ],
    max_excluded_objects: 2,
    require_current_signer_status: true,
};
const actionSubject = {
    action_type: 'software.merge',
    repository: 'emiliaprotocol/example',
    target_ref: 'refs/heads/main',
    diff_digest: HASH('d'),
};
const contextBinding = signTrustedContextBinding({
    providerId: 'apertomemory',
    providerProfile: 'draft-ferro-apertomemory-02',
    projectionRecord,
    action: actionSubject,
    policyDigest: trustedContextPolicyDigest(policy),
    nonce: 'ctx_vector_nonce_01',
    issuedAt: '2026-07-29T17:00:01.000Z',
    expiresAt: '2026-07-29T17:05:01.000Z',
    binderId: 'urn:emilia:gate:context-binder:vector-01',
    keyId: binderKeyId,
    privateKey: binder.privateKey,
});
const trustedContext = {
    provider_id: 'apertomemory',
    provider_profile: 'draft-ferro-apertomemory-02',
    projection_record_digest: canonicalContextRecordDigest(projectionRecord),
    projection_digest: projectionRecord.projection.digest,
    context_binding_digest: canonicalContextBindingDigest(contextBinding),
};
const vector = {
    '@version': 'EP-TRUSTED-CONTEXT-CONFORMANCE-v1',
    profile: 'Provider-neutral context projection admission with ApertoMemory as the first provider',
    claim_boundary: {
        establishes: 'A signed projection satisfied one relying-party evidence role for one exact action.',
        does_not_establish: [
            'that the model ingested, weighted, or used the projected bytes',
            'local action authorization',
            'execution or outcome',
            'independent conformance with the raw ApertoMemory CBOR/COSE format',
        ],
    },
    environment: {
        verification_time: '2026-07-29T17:01:00.000Z',
        expected_binding_nonce: 'ctx_vector_nonce_01',
        projection_adapter_status_checked_at: '2026-07-29T17:00:30.000Z',
        binding_signer_status_checked_at: '2026-07-29T17:00:30.000Z',
        projection_adapter_pin: {
            key_id: source.adapter_pin.key_id,
            public_key_spki_b64u: source.adapter_pin.public_key_spki_b64u,
            status: 'active',
            valid_from: '2026-07-29T00:00:00.000Z',
            valid_to: '2027-07-29T00:00:00.000Z',
            revoked_at: null,
        },
        binding_signer_pin: {
            key_id: binderKeyId,
            public_key_spki_b64u: binder.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            status: 'active',
            valid_from: '2026-07-29T00:00:00.000Z',
            valid_to: '2027-07-29T00:00:00.000Z',
            revoked_at: null,
        },
        policy,
    },
    fixture: {
        evidence: {
            provider_id: 'apertomemory',
            provider_profile: 'draft-ferro-apertomemory-02',
            projection_record: projectionRecord,
            context_binding: contextBinding,
        },
        action: { ...actionSubject, trusted_context: trustedContext },
    },
    cases: [
        { id: 'valid_exact_action', mutation: null, expect: { state: 'VERIFIED', reason: null } },
        { id: 'refuse_action_substitution', mutation: 'action_diff_digest', expect: { state: 'NOT_VERIFIED', reason: 'action_context_binding_mismatch' } },
        { id: 'refuse_projection_mutation', mutation: 'projection_byte_length', expect: { state: 'NOT_VERIFIED', reason: 'projection_signature_invalid' } },
        { id: 'refuse_binding_signature_substitution', mutation: 'binding_signature', expect: { state: 'NOT_VERIFIED', reason: 'context_binding_signature_invalid' } },
        { id: 'indeterminate_stale_adapter_status', mutation: 'adapter_status_stale', expect: { state: 'INDETERMINATE', reason: 'adapter_status_stale' } },
        { id: 'refuse_revoked_adapter', mutation: 'adapter_revoked', expect: { state: 'NOT_VERIFIED', reason: 'adapter_key_revoked' } },
        { id: 'refuse_forbidden_exclusion', mutation: 'forbid_authentication_exclusion', expect: { state: 'NOT_VERIFIED', reason: 'projection_exclusion_policy_mismatch' } },
        { id: 'refuse_action_binding_digest_substitution', mutation: 'action_binding_digest', expect: { state: 'NOT_VERIFIED', reason: 'action_context_binding_mismatch' } },
        { id: 'refuse_binding_nonce_replay', mutation: 'binding_nonce', expect: { state: 'NOT_VERIFIED', reason: 'context_binding_nonce_mismatch' } },
    ],
};
const serialized = `${JSON.stringify(vector, null, 2)}\n`;
if (process.argv.includes('--check')) {
    const current = readFileSync(OUTPUT, 'utf8');
    if (current !== serialized) {
        console.error('trusted-context.v1.json is stale; regenerate it');
        process.exit(1);
    }
    console.log('Trusted Context Pack vector is current');
}
else {
    writeFileSync(OUTPUT, serialized);
    console.log(`wrote ${OUTPUT}`);
}
