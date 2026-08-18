// SPDX-License-Identifier: Apache-2.0
// Generated from discovery-permit-contract-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v2 hybrid verifier test: the
// reference hybrid migration for this surface. Builds a REAL Ed25519 +
// ML-DSA-65 signed resolver attestation over a real resolution, then asserts
// the fail-closed predicate: leg stripping, set narrowing, a wrong-length
// signature, an Ed448 masquerade, and a v1 verifier refusing a v2 attestation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION, DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION, DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS, DISCOVERY_PERMIT_DISCOVERY_VERSION, DISCOVERY_PERMIT_BINDING_VERSION, pinDiscoveryPermitTrust, digestDiscoveryPermit, evaluateDiscoveryPermitContinuity, signDiscoveryPermitResolverAttestationV2, verifyDiscoveryPermitResolverAttestationSignature, verifyDiscoveryPermitResolverAttestationSignatureV2, verifyDiscoveryPermitResolverAttestationStatement, } from './discovery-permit-contract.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const ed = crypto.generateKeyPairSync('ed25519');
const edPubB64u = ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pq = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
const PINS = pinDiscoveryPermitTrust({
    origin: 'https://example.com',
    discovery_url: 'https://example.com/.well-known/ep-discovery.json',
    permit_url: 'https://example.com/.well-known/ep-permit-binding.json',
    discovery_schema_digest: `sha256:${'a'.repeat(64)}`,
    permit_schema_digest: `sha256:${'b'.repeat(64)}`,
    mapping_digest: `sha256:${'c'.repeat(64)}`,
    max_age_seconds: 3600,
    redirect_map: {},
});
function buildResolution() {
    const discovery = {
        '@type': DISCOVERY_PERMIT_DISCOVERY_VERSION,
        source: { origin: PINS.origin, discovery_url: PINS.discovery_url, permit_url: PINS.permit_url },
        schema_digests: { discovery: PINS.discovery_schema_digest, permit_binding: PINS.permit_schema_digest },
        mapping_digest: PINS.mapping_digest,
        status: 'active',
        issued_at: '2026-06-01T00:00:00Z',
    };
    const caid = `caid:1:example.com.1:jcs-sha256:${'A'.repeat(43)}`;
    const action = { op: 'transfer' };
    const actionDigest = digestDiscoveryPermit(action);
    const binding = { ...discovery, '@type': DISCOVERY_PERMIT_BINDING_VERSION, caid, action_digest: actionDigest };
    const provRec = (role, url, canonicalDigest) => ({
        role, requested_url: url, resolved_url: url, connected_address: '93.184.216.34',
        media_type: 'application/json', byte_length: 10, raw_digest: `sha256:${'d'.repeat(64)}`,
        canonical_digest: canonicalDigest, redirect_chain: [url],
    });
    const provenance = {
        discovery: provRec('discovery', PINS.discovery_url, digestDiscoveryPermit(discovery)),
        permit: provRec('permit', PINS.permit_url, digestDiscoveryPermit(binding)),
    };
    return evaluateDiscoveryPermitContinuity({
        pins: PINS, discovery, binding, caid, action, now: '2026-06-01T00:10:00Z', provenance,
    });
}
async function buildV2Attestation() {
    return signDiscoveryPermitResolverAttestationV2({
        resolver_id: 'resolver1',
        evaluated_at: '2026-06-01T00:10:00Z',
        expires_at: '2026-06-01T01:10:00Z',
        configuration_digest: `sha256:${'e'.repeat(64)}`,
        resolution: buildResolution(),
    }, { key_id: 'rk1', private_key: ed.privateKey, pq_key_id: 'pqrk1', pq_private_key: Buffer.from(pq.secretKey).toString('base64url') });
}
const PIN = { resolver_id: 'resolver1', key_id: 'rk1', public_key: edPubB64u, pq_key_id: 'pqrk1', pq_public_key: pqPubB64u };
test('real ML-DSA-65 backend is available for this suite', () => {
    assert.ok(typeof ml_dsa65?.sign === 'function');
});
test('a real hybrid resolver attestation verifies under both pinned keys', async () => {
    const attestation = await buildV2Attestation();
    const ok = await verifyDiscoveryPermitResolverAttestationSignatureV2(attestation, PIN);
    assert.equal(ok, true);
});
test('the v1 verifier refuses a v2 attestation cleanly, without crashing', async () => {
    const attestation = await buildV2Attestation();
    const ok = verifyDiscoveryPermitResolverAttestationSignature(attestation, PIN);
    assert.equal(ok, false);
});
test('verifyDiscoveryPermitResolverAttestationStatement routes each @type to its own verifier', async () => {
    const v2 = await buildV2Attestation();
    assert.equal(await verifyDiscoveryPermitResolverAttestationStatement(v2, PIN), true);
});
test('LEG STRIPPING: removing the ML-DSA leg refuses', async () => {
    const attestation = await buildV2Attestation();
    const tampered = { ...attestation, signatures: attestation.signatures.filter((s) => s.alg === 'Ed25519') };
    const ok = await verifyDiscoveryPermitResolverAttestationSignatureV2(tampered, PIN);
    assert.equal(ok, false);
});
test('LEG STRIPPING: removing the Ed25519 leg refuses too', async () => {
    const attestation = await buildV2Attestation();
    const tampered = { ...attestation, signatures: attestation.signatures.filter((s) => s.alg === 'ML-DSA-65') };
    const ok = await verifyDiscoveryPermitResolverAttestationSignatureV2(tampered, PIN);
    assert.equal(ok, false);
});
test('SET NARROWING: a narrowed required_algorithms fails structurally', async () => {
    const attestation = await buildV2Attestation();
    const tampered = { ...attestation, required_algorithms: ['Ed25519'] };
    const ok = await verifyDiscoveryPermitResolverAttestationSignatureV2(tampered, PIN);
    assert.equal(ok, false);
});
test('WRONG-LENGTH SIGNATURE: a truncated leg refuses', async () => {
    const attestation = await buildV2Attestation();
    const edSig = attestation.signatures.find((s) => s.alg === 'Ed25519');
    const tampered = {
        ...attestation,
        signatures: attestation.signatures.map((s) => (s === edSig ? { ...s, sig: s.sig.slice(0, -4) } : s)),
    };
    const ok = await verifyDiscoveryPermitResolverAttestationSignatureV2(tampered, PIN);
    assert.equal(ok, false);
});
test('ED448 MASQUERADE: an Ed448 key pinned as the Ed25519 half refuses', async () => {
    const attestation = await buildV2Attestation();
    const ed448 = crypto.generateKeyPairSync('ed448');
    const ed448PubB64u = ed448.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const ok = await verifyDiscoveryPermitResolverAttestationSignatureV2(attestation, {
        ...PIN, public_key: ed448PubB64u,
    });
    assert.equal(ok, false);
});
test('NO ML-DSA BACKEND is a refusal, never a pass on the classical leg', async () => {
    const attestation = await buildV2Attestation();
    const ok = await verifyDiscoveryPermitResolverAttestationSignatureV2(attestation, PIN, {
        mldsaBackendLoader: async () => null,
    });
    assert.equal(ok, false);
});
test('the registered required algorithm set is fixed and Ed25519-first', () => {
    assert.deepEqual([...DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
    assert.equal(DISCOVERY_PERMIT_RESOLVER_ATTESTATION_VERSION, 'EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v1');
    assert.equal(DISCOVERY_PERMIT_RESOLVER_ATTESTATION_V2_VERSION, 'EP-DISCOVERY-PERMIT-RESOLVER-ATTESTATION-v2');
});
