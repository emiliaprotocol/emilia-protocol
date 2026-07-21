// Generated from enterprise.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/gate enterprise entitlement tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mintEntitlement, verifyEntitlement, requireFeature, ENTITLEMENT_VERSION, ENTITLEMENT_TIERS, } from './enterprise.js';
function makeKey() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
// Deterministic clock: every test passes `now` explicitly; nothing reads the wall clock.
const NOW = Date.parse('2026-07-04T12:00:00Z');
const issuer = makeKey();
const ISSUER_KEYS = { 'lic-2026-1': issuer.pub };
function fields(over = {}) {
    return {
        org: 'org:acme',
        tier: 'enterprise',
        features: ['sso', 'managed_control_plane', 'byoc'],
        limits: { protected_actions_per_year: 1_000_000 },
        not_before: '2026-01-01T00:00:00Z',
        expires_at: '2027-01-01T00:00:00Z',
        kid: 'lic-2026-1',
        ...over,
    };
}
function mint(over = {}, key = issuer.privateKey) {
    return mintEntitlement(key, fields(over));
}
test('mint + verify: valid entitlement yields its tier, features, limits', () => {
    const ent = mint();
    assert.equal(ent['@version'], ENTITLEMENT_VERSION);
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, true);
    assert.equal(v.tier, 'enterprise');
    assert.deepEqual(v.features, ['sso', 'managed_control_plane', 'byoc']);
    assert.equal(v.limits.protected_actions_per_year, 1_000_000);
    assert.equal(v.org, 'org:acme');
    assert.equal(v.reason, 'entitlement_verified');
});
test('verify accepts the artifact as a JSON string', () => {
    const v = verifyEntitlement(JSON.stringify(mint()), { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, true);
    assert.equal(v.tier, 'enterprise');
});
test('duplicate-member entitlement JSON resolves to community', () => {
    const ent = mint();
    const raw = `{"@version":"${ENTITLEMENT_VERSION}","payload":${JSON.stringify(ent.payload)},"payload":${JSON.stringify(ent.payload)},"signature":${JSON.stringify(ent.signature)}}`;
    const v = verifyEntitlement(raw, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'entitlement_unparseable');
});
test('absence of an entitlement -> community, never an error', () => {
    for (const absent of [null, undefined, '']) {
        const v = verifyEntitlement(absent, { issuerKeys: ISSUER_KEYS, now: NOW });
        assert.equal(v.valid, false);
        assert.equal(v.tier, 'community');
        assert.equal(v.reason, 'no_entitlement');
    }
});
test('tampered payload (tier upgrade) -> community with bad_signature', () => {
    const ent = mint({ tier: 'team' });
    ent.payload.tier = 'regulated'; // self-upgrade attempt
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'bad_signature');
});
test('tampered payload (features injection) -> community with bad_signature', () => {
    const ent = mint({ features: ['sso'] });
    ent.payload.features.push('managed_control_plane');
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'bad_signature');
    assert.equal(requireFeature(v, 'managed_control_plane'), false);
});
test('signed by the wrong key -> community with bad_signature', () => {
    const rogue = makeKey();
    const ent = mint({}, rogue.privateKey); // same kid, wrong private key
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'bad_signature');
});
test('unknown kid -> community, entitlement cannot nominate its own key', () => {
    const ent = mint({ kid: 'lic-unknown' });
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'unknown_kid');
});
test('no pinned issuer keys at all -> community (fail closed)', () => {
    const v = verifyEntitlement(mint(), { now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'unknown_kid');
});
test('expired -> community with expired, using the injected clock', () => {
    const ent = mint();
    const after = Date.parse('2027-06-01T00:00:00Z');
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: after });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'expired');
});
test('not yet valid -> community with not_yet_valid', () => {
    const ent = mint({ not_before: '2026-12-01T00:00:00Z' });
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'not_yet_valid');
});
test('same artifact flips valid/expired purely by the explicit clock', () => {
    const ent = mint();
    const inside = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: () => NOW });
    const outside = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: () => Date.parse('2030-01-01T00:00:00Z') });
    assert.equal(inside.valid, true);
    assert.equal(outside.valid, false);
    assert.equal(outside.reason, 'expired');
});
test('unsupported version -> community', () => {
    const ent = mint();
    ent['@version'] = 'EP-GATE-ENTITLEMENT-v0';
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'unsupported_version');
});
test('unknown tier in a (re-signed) payload -> community', () => {
    const ent = mintEntitlement(issuer.privateKey, fields()); // start valid
    ent.payload.tier = 'platinum';
    // Re-sign so ONLY the tier check can refuse it.
    const canon = (v) => (v === null || v === undefined) ? JSON.stringify(v)
        : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
            : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
                : JSON.stringify(v);
    ent.signature.value = crypto.sign(null, Buffer.from(canon(ent.payload), 'utf8'), issuer.privateKey).toString('base64url');
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.tier, 'community');
    assert.equal(v.reason, 'unknown_tier');
});
test('malformed artifacts -> community, never a throw', () => {
    const cases = [
        ['not json {', 'entitlement_unparseable'],
        [{ '@version': ENTITLEMENT_VERSION }, 'entitlement_malformed'],
        [{ '@version': ENTITLEMENT_VERSION, payload: fields() }, 'entitlement_malformed'],
        [42, 'entitlement_malformed'],
    ];
    for (const [artifact, reason] of cases) {
        const v = verifyEntitlement(artifact, { issuerKeys: ISSUER_KEYS, now: NOW });
        assert.equal(v.valid, false);
        assert.equal(v.tier, 'community');
        assert.equal(v.reason, reason);
    }
});
test('non-Ed25519 algorithm -> community (fail closed)', () => {
    const ent = mint();
    ent.signature.algorithm = 'RS256';
    const v = verifyEntitlement(ent, { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, false);
    assert.equal(v.reason, 'unsupported_algorithm');
});
test('every refusal resolves to community — the core gate is never bricked', () => {
    const refusals = [
        verifyEntitlement(null, { issuerKeys: ISSUER_KEYS, now: NOW }),
        verifyEntitlement('garbage', { issuerKeys: ISSUER_KEYS, now: NOW }),
        verifyEntitlement(mint({ kid: 'nope' }), { issuerKeys: ISSUER_KEYS, now: NOW }),
        verifyEntitlement(mint(), { issuerKeys: ISSUER_KEYS, now: Date.parse('2031-01-01T00:00:00Z') }),
        verifyEntitlement(mint({}, makeKey().privateKey), { issuerKeys: ISSUER_KEYS, now: NOW }),
    ];
    for (const v of refusals) {
        assert.equal(v.valid, false);
        assert.equal(v.tier, 'community');
        assert.equal(typeof v.reason, 'string');
        assert.ok(v.reason.length > 0);
    }
});
test('requireFeature: true only for a valid entitlement listing the feature', () => {
    const v = verifyEntitlement(mint({ features: ['sso', 'byoc'] }), { issuerKeys: ISSUER_KEYS, now: NOW });
    assert.equal(v.valid, true);
    assert.equal(requireFeature(v, 'sso'), true);
    assert.equal(requireFeature(v, 'byoc'), true);
    assert.equal(requireFeature(v, 'managed_control_plane'), false); // not listed
    assert.equal(requireFeature(v, ''), false);
    assert.equal(requireFeature(v, undefined), false);
});
test('requireFeature fails closed on invalid/absent verification results', () => {
    const expired = verifyEntitlement(mint(), { issuerKeys: ISSUER_KEYS, now: Date.parse('2031-01-01T00:00:00Z') });
    assert.equal(requireFeature(expired, 'sso'), false);
    assert.equal(requireFeature(null, 'sso'), false);
    assert.equal(requireFeature(undefined, 'sso'), false);
    assert.equal(requireFeature({ valid: 'true', features: ['sso'] }, 'sso'), false); // non-boolean valid
    assert.equal(requireFeature({ valid: true, features: 'sso' }, 'sso'), false); // features not an array
});
test('issuerKeys as an entry list [{kid,key}] also verifies', () => {
    const v = verifyEntitlement(mint(), { issuerKeys: [{ kid: 'lic-2026-1', key: issuer.pub }], now: NOW });
    assert.equal(v.valid, true);
});
test('mintEntitlement rejects invalid fields (never issue a malformed license)', () => {
    assert.throws(() => mintEntitlement(issuer.privateKey, fields({ tier: 'platinum' })), /unknown tier/);
    assert.throws(() => mintEntitlement(issuer.privateKey, fields({ kid: undefined })), /kid is required/);
    assert.throws(() => mintEntitlement(issuer.privateKey, fields({ org: '' })), /org is required/);
    assert.throws(() => mintEntitlement(issuer.privateKey, fields({ expires_at: 'not-a-date' })), /expires_at/);
    assert.throws(() => mintEntitlement(issuer.privateKey, fields({ features: [42] })), /features/);
});
test('all five tiers mint and verify', () => {
    for (const tier of ENTITLEMENT_TIERS) {
        const v = verifyEntitlement(mint({ tier }), { issuerKeys: ISSUER_KEYS, now: NOW });
        assert.equal(v.valid, true, tier);
        assert.equal(v.tier, tier);
    }
});
