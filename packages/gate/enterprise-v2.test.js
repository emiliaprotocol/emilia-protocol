// SPDX-License-Identifier: Apache-2.0
// Generated from enterprise-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-GATE-ENTITLEMENT-v2 -- hostile matrix for the hybrid entitlement.
// Package-root node:test file importing the compatibility shim
// './enterprise.js' (which re-exports ./dist/enterprise.js), matching this
// package's convention; packages/gate/enterprise.test.js keeps covering v1 and
// is untouched.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import { ENTITLEMENT_VERSION, ENTITLEMENT_V2_VERSION, ENTITLEMENT_V2_REQUIRED_ALGORITHMS, mintEntitlement, mintEntitlementV2, verifyEntitlement, verifyEntitlementV2, verifyEntitlementStatement, } from './enterprise.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = Date.parse('2026-08-17T12:00:00Z');
const KID = 'lic-v2-2026-1';
function fields(over = {}) {
    return {
        org: 'org:acme',
        tier: 'enterprise',
        features: ['sso', 'managed_control_plane', 'byoc'],
        limits: { protected_actions_per_year: 1_000_000 },
        not_before: '2026-01-01T00:00:00Z',
        expires_at: '2027-01-01T00:00:00Z',
        kid: KID,
        ...over,
    };
}
function issuerFixture() {
    const ed = crypto.generateKeyPairSync('ed25519');
    const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const pq = ml_dsa65.keygen(crypto.randomBytes(32));
    const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
    return {
        keys: { ed: { privateKey: ed.privateKey }, pq: { secretKey: pq.secretKey } },
        hybridPin: { [KID]: { public_key: edPubB64u, pq_public_key: pqPubB64u } },
        classicalOnlyPin: { [KID]: edPubB64u },
    };
}
describe('EP-GATE-ENTITLEMENT-v2 hybrid entitlement', () => {
    it('valid v2 roundtrip: verifies and yields the tier/features/limits', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        assert.equal(ent['@version'], ENTITLEMENT_V2_VERSION);
        assert.deepEqual(ent.proof.required_algorithms, [...ENTITLEMENT_V2_REQUIRED_ALGORITHMS]);
        assert.deepEqual(ent.proof.signatures.map((s) => s.alg), [...ENTITLEMENT_V2_REQUIRED_ALGORITHMS]);
        const v = await verifyEntitlementV2(ent, { issuerKeys: issuer.hybridPin, now: NOW });
        assert.equal(v.valid, true);
        assert.equal(v.tier, 'enterprise');
        assert.deepEqual(v.features, ['sso', 'managed_control_plane', 'byoc']);
        assert.equal(v.reason, 'entitlement_verified');
    });
    it('the router accepts a v1 entitlement unchanged, and a v2 one via the hybrid path', async () => {
        const issuer = issuerFixture();
        const ed = crypto.generateKeyPairSync('ed25519');
        const v1 = mintEntitlement(ed.privateKey, fields({ kid: 'lic-v1' }));
        const v1Pub = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
        const v1Result = await verifyEntitlementStatement(v1, { issuerKeys: { 'lic-v1': v1Pub }, now: NOW });
        assert.equal(v1Result.valid, true);
        const v2 = await mintEntitlementV2(issuer.keys, fields());
        const v2Result = await verifyEntitlementStatement(v2, { issuerKeys: issuer.hybridPin, now: NOW });
        assert.equal(v2Result.valid, true);
    });
    it('v1-refuses-v2: the existing SYNC verifier refuses a v2 document cleanly, community fallback, never a crash', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        // No await: verifyEntitlement remains synchronous and untouched.
        const result = verifyEntitlement(ent, { issuerKeys: { [KID]: 'unused' }, now: NOW });
        assert.equal(result.valid, false);
        assert.equal(result.tier, 'community');
        assert.equal(result.reason, 'unsupported_version');
    });
    it('a v2 document from a kid pinned WITHOUT the ML-DSA half refuses to community (never partial credit)', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        const result = await verifyEntitlementV2(ent, { issuerKeys: issuer.classicalOnlyPin, now: NOW });
        assert.equal(result.valid, false);
        assert.equal(result.tier, 'community');
        assert.equal(result.reason, 'unknown_kid');
    });
    it('stripped leg: dropping the ML-DSA signature refuses, never a classical-only pass', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        const stripped = {
            ...ent,
            proof: { ...ent.proof, signatures: ent.proof.signatures.filter((s) => s.alg !== 'ML-DSA-65') },
        };
        const result = await verifyEntitlementV2(stripped, { issuerKeys: issuer.hybridPin, now: NOW });
        assert.equal(result.valid, false);
        assert.equal(result.tier, 'community');
    });
    it('narrowed set: claiming required_algorithms=["Ed25519"] only is refused structurally', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        const narrowed = {
            ...ent,
            proof: {
                required_algorithms: ['Ed25519'],
                signatures: ent.proof.signatures.filter((s) => s.alg === 'Ed25519'),
            },
        };
        const result = await verifyEntitlementV2(narrowed, { issuerKeys: issuer.hybridPin, now: NOW });
        assert.equal(result.valid, false);
        assert.equal(result.tier, 'community');
        assert.equal(result.reason, 'unsupported_algorithm_set');
    });
    it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        const tampered = {
            ...ent,
            proof: {
                ...ent.proof,
                signatures: ent.proof.signatures.map((s) => (s.alg === 'ML-DSA-65' ? { ...s, sig: Buffer.from(crypto.randomBytes(16)).toString('base64url') } : s)),
            },
        };
        const tamperedResult = await verifyEntitlementV2(tampered, { issuerKeys: issuer.hybridPin, now: NOW });
        assert.equal(tamperedResult.valid, false);
        assert.equal(tamperedResult.tier, 'community');
    });
    it('Ed448-masquerade: a non-Ed25519 SPKI presented as the classical half refuses, never verified under the wrong curve', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        const ed448 = crypto.generateKeyPairSync('ed448');
        const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
        const pin = { [KID]: { ...issuer.hybridPin[KID], public_key: ed448PubB64u } };
        const result = await verifyEntitlementV2(ent, { issuerKeys: pin, now: NOW });
        assert.equal(result.valid, false);
        assert.equal(result.tier, 'community');
    });
    it('an expired v2 entitlement still refuses AFTER the hybrid signature check passes', async () => {
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields({
            not_before: '2020-01-01T00:00:00Z', expires_at: '2020-06-01T00:00:00Z',
        }));
        const result = await verifyEntitlementV2(ent, { issuerKeys: issuer.hybridPin, now: NOW });
        assert.equal(result.valid, false);
        assert.equal(result.tier, 'community');
        assert.equal(result.reason, 'expired');
    });
    it('never throws on hostile input (absent, malformed JSON, prototype-bearing document)', async () => {
        for (const bad of [null, undefined, '', '{not json', 42, []]) {
            const result = await verifyEntitlementV2(bad, { issuerKeys: {}, now: NOW });
            assert.equal(result.valid, false);
            assert.equal(result.tier, 'community');
        }
        const issuer = issuerFixture();
        const ent = await mintEntitlementV2(issuer.keys, fields());
        const inherited = Object.assign(Object.create({ tier: 'enterprise' }), ent);
        // Never throws; the canonicalize() round-trip drops non-own-enumerable
        // inherited fields before any check runs, so this is not a bypass either
        // way -- the point of this assertion is only that it resolves cleanly.
        const inheritedResult = await verifyEntitlementV2(inherited, { issuerKeys: issuer.hybridPin, now: NOW });
        assert.ok('valid' in inheritedResult);
    });
});
