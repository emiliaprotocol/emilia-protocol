// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-oasnt-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import { digestAeb, } from './aeb-adapter-contract.js';
import { OASNT_AEB_ADAPTER_ID, OASNT_AEB_ADAPTER_VERSION, OASNT_AEB_CONFIG_VERSION, OASNT_CAID_DRAFT_REVISION, OASNT_CAID_DRAFT_TXT_SHA256, OASNT_CAID_MAPPER_ID, OASNT_CAID_MAPPING_VERSION, OASNT_DRAFT_REVISION, OASNT_DRAFT_TXT_SHA256, OASNT_TRUST_ROOT_VERSION, computeOasntActionDigest, computeOasntCaid, computeOasntDisplayDigest, computeOasntRequestFingerprint, createOasntActionDefinition, createOasntAebAdapter, } from './aeb-oasnt-adapter.js';
const oasntCaidVectors = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/oasnt-caid-aeb.v1.json', import.meta.url), 'utf8'));
const NOW = new Date(1_800_000_000 * 1000).toISOString();
const ACTION_TYPE = 'payment.transfer.1';
const OASNT_ACTION_TYPE = 'payment.transfer';
const TOKEN = [
    'eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hc250K2p3dCJ9',
    'eyJzdWIiOiJhZ2VudC0xIiwiYWRnIjoiWWxIcDNNNEpJV0ZQUFpJVkF3QW1ZT0JPTWZVeWIyYmpFNnZlM0FEMmlhUSIsImRzcCI6InVTRWdPRzlVQzFJV0d4ekJhbEp2NWNJYmZ4RThreG1vS0YyNXlyUmwxZnMiLCJycWYiOiIxR0w3Q0lnMUprS0dhR2ZIZ2RGNV85M3JWeDRGcWZqb1kwbFlaNnhialEwIiwiaW50IjoiY2xlYW4iLCJqdGkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImlhdCI6MTgwMDAwMDAwMCwiZXhwIjoxODAwMDAwMDYwLCJjbmYiOnsiamt0IjoieGNEYmMyLU1zUklFTlF5bkFZR3RKMFZjMHhQVEJkZmpfMWlBZUk5TU1GbyJ9fQ',
    '1rS6k1Yz9ZsYWpk51vTv0GDJX4VJ9vp3Qb9v4ZNG1VjQQwvVvUpUjNao7ZA0hxmBqEOHPLv8NY5C_Jqjl-SJzA',
].join('.');
const request = Object.freeze({
    method: 'POST',
    path: '/v1/transfers',
    org_id: 'org_acme',
    scope: 'payments:write',
    body_sha256: '05be0ab936cd56cf971cc8b57f7132a690d4ed3bf63b37ac3cb81d6e289f847a',
});
const expectedAction = Object.freeze({
    action_type: ACTION_TYPE,
    native_action: {
        type: OASNT_ACTION_TYPE,
        parameters: { amount: '100.00', payee: 'acct_9' },
    },
    request,
});
const config = Object.freeze({
    '@version': OASNT_AEB_CONFIG_VERSION,
    evidence_role: 'human-authorization',
    subject: { id: 'human:agent-1', kind: 'human', native_id: 'agent-1' },
    action_type: ACTION_TYPE,
    require_request_binding: true,
    clock_skew_seconds: 5,
    max_token_lifetime_seconds: 120,
    max_status_age_seconds: 120,
    required_assurance_level: null,
});
const trustRoot = Object.freeze({
    '@version': OASNT_TRUST_ROOT_VERSION,
    use: 'enrolled-oasnt-signing-key',
    native_subject: 'agent-1',
    public_jwk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'P7Vp3OZi4XYii2VHo4T08zkjKrKhCt-gY-oAATkXaao',
        y: 'QNEaWqPG2EI5-2AdT8oX-S4odj8TH9wj_JW2I2ILBoc',
    },
    jwk_thumbprint: 'xcDbc2-MsRIENQynAYGtJ0Vc0xPTBdfj_1iAeI9MMFo',
    enrollment: {
        hardware_attested: true,
        evidence_digest: `sha256:${'a'.repeat(64)}`,
    },
});
function profile() {
    return {
        version: OASNT_CAID_MAPPING_VERSION,
        definition: createOasntActionDefinition(ACTION_TYPE, true),
        registry_entry_ref: 'mapping:oasnt-payment-transfer',
        mapper_id: OASNT_CAID_MAPPER_ID,
        resolver: {
            id: OASNT_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: OASNT_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'token.int',
                'token.cnf.jkt',
                'token.jti',
                'token.iat',
                'token.exp',
            ],
        },
        profile_digest: digestAeb(null),
    };
}
function input(overrides = {}) {
    return {
        artifact: TOKEN,
        artifact_ref: 'oasnt:published-v5',
        status: {
            checked_at: NOW,
            expires_at: new Date(Date.parse(NOW) + 60_000).toISOString(),
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        trust_roots: [trustRoot],
        adapter_config: config,
        expected_action: expectedAction,
        now: NOW,
        ...overrides,
    };
}
function mappedIdentifiers(action) {
    const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
    const nativeInput = input({ expected_action: action });
    const native = adapter.verifyNative(nativeInput);
    if (native.native_verification !== 'VERIFIED' || native.acceptance !== 'ACCEPTED')
        return null;
    const mapped = adapter.mapAction({ ...nativeInput, profile: profile(), native });
    if (mapped.mapping !== 'MATCH' || mapped.caid === null || mapped.action_digest === null)
        return null;
    return {
        oasnt_caid: computeOasntCaid(action.native_action.type, action.native_action.parameters),
        emilia_caid: mapped.caid,
        local_action_digest: mapped.action_digest,
    };
}
function joinProfilesOnExecutorAction(action, presented) {
    const derived = mappedIdentifiers(action);
    if (derived === null
        || presented.oasnt_caid !== derived.oasnt_caid
        || presented.emilia_caid !== derived.emilia_caid)
        return null;
    return derived;
}
test('OASNT -02 published canonicalization vectors match byte-for-byte (unchanged from -01)', () => {
    assert.equal(computeOasntActionDigest(OASNT_ACTION_TYPE, expectedAction.native_action.parameters), 'YlHp3M4JIWFPPZIVAwAmYOBOMfUyb2bjE6ve3AD2iaQ');
    assert.equal(computeOasntDisplayDigest(OASNT_ACTION_TYPE, expectedAction.native_action.parameters), 'uSEgOG9UC1IWGxzBalJv5cIbfxE8kxmoKF25yrRl1fs');
    assert.equal(computeOasntRequestFingerprint(request), '1GL7CIg1JkKGaGfHgdF5_93rVx4FqfjoY0lYZ6xbjQ0');
});
test('OASNT -02 published compact token (Appendix A.6 V5, no asl) verifies and maps to one EMILIA CAID', () => {
    const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
    assert.equal(adapter.id, OASNT_AEB_ADAPTER_ID);
    assert.equal(adapter.version, OASNT_AEB_ADAPTER_VERSION);
    const native = adapter.verifyNative(input());
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
    assert.deepEqual(native.reasons, []);
    assert.match(native.replay_unit, /^sha256:[0-9a-f]{64}$/);
    const mapped = adapter.mapAction({ ...input(), profile: profile(), native });
    assert.equal(mapped.mapping, 'MATCH');
    assert.match(mapped.caid ?? '', /^caid:1:payment\.transfer\.1:jcs-sha256:/);
    assert.equal(mapped.action_digest, digestAeb(expectedAction));
});
test('OASNT adapter refuses an exact-action mismatch and never maps it', () => {
    const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
    const changed = structuredClone(expectedAction);
    changed.native_action.parameters.amount = '1000.00';
    const changedInput = input({ expected_action: changed });
    const native = adapter.verifyNative(changedInput);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.ok(native.reasons.includes('oasnt:action_digest_mismatch'));
    assert.equal(adapter.mapAction({ ...changedInput, profile: profile(), native }).mapping, 'INDETERMINATE');
});
test('OASNT adapter fails closed on missing request binding and consumed status', () => {
    const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
    const noRequest = structuredClone(expectedAction);
    delete noRequest.request;
    const missing = adapter.verifyNative(input({ expected_action: noRequest }));
    assert.equal(missing.acceptance, 'INDETERMINATE');
    assert.ok(missing.reasons.includes('oasnt:concrete_request_required'));
    const consumed = adapter.verifyNative(input({
        status: { ...input().status, consumed: true },
    }));
    assert.equal(consumed.native_verification, 'VERIFIED');
    assert.equal(consumed.acceptance, 'REJECTED');
    assert.ok(consumed.reasons.includes('evidence_consumed'));
});
test('OASNT constructor pins cannot be replaced by presenter-selected roots', () => {
    const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
    const swapped = structuredClone(trustRoot);
    swapped.public_jwk.x = `A${swapped.public_jwk.x.slice(1)}`;
    const result = adapter.verifyNative(input({ trust_roots: [swapped] }));
    assert.equal(result.native_verification, 'FAILED');
    assert.equal(result.acceptance, 'REJECTED');
    assert.deepEqual(result.reasons, ['oasnt:constructor_pin_mismatch']);
});
test('OASNT source lock is the current reviewed draft', () => {
    assert.equal(OASNT_DRAFT_REVISION, 'draft-thallapelly-oasnt-02');
    assert.equal(OASNT_DRAFT_TXT_SHA256, 'sha256:3a134b635d5101cd91ac885fb4867bf1a7fd37bc52fc4f8405467ed66c397603');
    assert.equal(OASNT_CAID_DRAFT_REVISION, 'draft-thallapelly-oasnt-caid-01');
    assert.equal(OASNT_CAID_DRAFT_TXT_SHA256, 'sha256:75dfecb65e56accc5b55aa66a570e6fae52d3fe417631482eb8172d50e771963');
    assert.equal(oasntCaidVectors.source_locks.oasnt.revision, OASNT_DRAFT_REVISION);
    assert.equal(oasntCaidVectors.source_locks.oasnt.txt_sha256, OASNT_DRAFT_TXT_SHA256);
    assert.equal(oasntCaidVectors.source_locks.oasnt_caid.revision, OASNT_CAID_DRAFT_REVISION);
    assert.equal(oasntCaidVectors.source_locks.oasnt_caid.txt_sha256, OASNT_CAID_DRAFT_TXT_SHA256);
    assert.deepEqual(oasntCaidVectors.source_locks.oasnt_caid.sections, ['4.1', '6.4']);
    assert.equal(oasntCaidVectors.claim_limits.length, 3);
    assert.ok(oasntCaidVectors.claim_limits.some((claim) => claim.includes('do not claim that a revised OASNT-CAID profile has been published for OASNT-02')));
    assert.ok(oasntCaidVectors.claim_limits.some((claim) => claim.includes('not external interoperability, adoption, or endorsement')));
    assert.ok(oasntCaidVectors.claim_limits.some((claim) => claim.includes('direct cross-profile join key')));
});
const joinVectorHandlers = {
    profile_specific_identifiers_are_not_direct_join_keys() {
        const derived = mappedIdentifiers(expectedAction);
        assert.ok(derived);
        assert.match(derived.oasnt_caid, /^oasnt:caid:1:[A-Za-z0-9_-]{43}$/);
        assert.match(derived.emilia_caid, /^caid:1:/);
        assert.notEqual(derived.oasnt_caid, derived.emilia_caid);
    },
    executor_owned_mapping_joins_one_material_action() {
        const derived = mappedIdentifiers(expectedAction);
        assert.ok(derived);
        const joined = joinProfilesOnExecutorAction(expectedAction, derived);
        assert.ok(joined);
        assert.equal(joined.local_action_digest, digestAeb(expectedAction));
    },
    namespace_collision_refuses() {
        const derived = mappedIdentifiers(expectedAction);
        assert.ok(derived);
        assert.equal(joinProfilesOnExecutorAction(expectedAction, {
            oasnt_caid: derived.emilia_caid,
            emilia_caid: derived.emilia_caid,
        }), null);
    },
    profile_identifier_mismatch_refuses() {
        const derived = mappedIdentifiers(expectedAction);
        assert.ok(derived);
        const changedEmilia = `${derived.emilia_caid.slice(0, -1)}${derived.emilia_caid.endsWith('A') ? 'B' : 'A'}`;
        const changedOasnt = `${derived.oasnt_caid.slice(0, -1)}${derived.oasnt_caid.endsWith('A') ? 'B' : 'A'}`;
        assert.equal(joinProfilesOnExecutorAction(expectedAction, {
            oasnt_caid: derived.oasnt_caid,
            emilia_caid: changedEmilia,
        }), null);
        assert.equal(joinProfilesOnExecutorAction(expectedAction, {
            oasnt_caid: changedOasnt,
            emilia_caid: derived.emilia_caid,
        }), null);
    },
    changed_material_action_refuses() {
        const derived = mappedIdentifiers(expectedAction);
        assert.ok(derived);
        const changed = structuredClone(expectedAction);
        changed.native_action.parameters.amount = '1000.00';
        assert.equal(joinProfilesOnExecutorAction(changed, derived), null);
    },
};
for (const vector of oasntCaidVectors.vectors.filter((candidate) => candidate.section === '6.4')) {
    test(`OASNT-CAID-01 section 6.4 under OASNT-02 source lock: ${vector.id}`, () => {
        assert.equal(oasntCaidVectors['@version'], 'OASNT-CAID-AEB-VECTORS-v1');
        const run = joinVectorHandlers[vector.id];
        assert.equal(typeof run, 'function', `missing executable handler for ${vector.id}`);
        run();
    });
}
// ---------------------------------------------------------------------------
// -02 sec 5.4 assurance. Tokens below are minted locally with the draft's
// published Appendix A.1 key (its private component is published exactly so
// implementers can reproduce signatures; the draft forbids any other use).
// ---------------------------------------------------------------------------
const PUBLISHED_PRIVATE_JWK = {
    kty: 'EC',
    crv: 'P-256',
    x: 'P7Vp3OZi4XYii2VHo4T08zkjKrKhCt-gY-oAATkXaao',
    y: 'QNEaWqPG2EI5-2AdT8oX-S4odj8TH9wj_JW2I2ILBoc',
    d: 'Y2j9oKoLsw3p24brNicuYCjBxv0LVUWLHSYc9Wzvy5A',
};
function mintToken(extraClaims) {
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'oasnt+jwt' }), 'utf8')
        .toString('base64url');
    const payload = Buffer.from(JSON.stringify({
        sub: 'agent-1',
        adg: 'YlHp3M4JIWFPPZIVAwAmYOBOMfUyb2bjE6ve3AD2iaQ',
        dsp: 'uSEgOG9UC1IWGxzBalJv5cIbfxE8kxmoKF25yrRl1fs',
        rqf: '1GL7CIg1JkKGaGfHgdF5_93rVx4FqfjoY0lYZ6xbjQ0',
        int: 'clean',
        jti: `jti-${JSON.stringify(extraClaims)}`,
        iat: 1_800_000_000,
        exp: 1_800_000_060,
        cnf: { jkt: 'xcDbc2-MsRIENQynAYGtJ0Vc0xPTBdfj_1iAeI9MMFo' },
        ...extraClaims,
    }), 'utf8').toString('base64url');
    const signingInput = `${header}.${payload}`;
    const key = crypto.createPrivateKey({ key: PUBLISHED_PRIVATE_JWK, format: 'jwk' });
    const signature = crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), {
        key,
        dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    return `${signingInput}.${signature}`;
}
function withFloor(level) {
    return Object.freeze({ ...config, required_assurance_level: level });
}
test('asl absent with a pinned floor refuses as an absent assurance statement', () => {
    const adapter = createOasntAebAdapter({ config: withFloor('platform-key'), trust_roots: [trustRoot] });
    const native = adapter.verifyNative(input({
        artifact: mintToken({}),
        adapter_config: withFloor('platform-key'),
    }));
    assert.equal(native.acceptance, 'REJECTED');
    assert.deepEqual(native.reasons, ['oasnt:assurance_statement_absent']);
});
test('unrecognized asl decides like absent but reports its own reason (sec 5.4.2)', () => {
    const adapter = createOasntAebAdapter({ config: withFloor('platform-key'), trust_roots: [trustRoot] });
    const native = adapter.verifyNative(input({
        artifact: mintToken({ asl: 'quantum-oracle' }),
        adapter_config: withFloor('platform-key'),
    }));
    assert.equal(native.acceptance, 'REJECTED');
    assert.deepEqual(native.reasons, ['oasnt:assurance_level_unrecognized']);
});
test('an over-claim buys nothing: effective level is the enrollment ceiling (sec 5.4.1)', () => {
    // Token claims attested-display; this root version attests hardware but not
    // a display path, so the ceiling is platform-key and the effective level is
    // platform-key. A floor of attested-display refuses...
    const strict = createOasntAebAdapter({ config: withFloor('attested-display'), trust_roots: [trustRoot] });
    const refused = strict.verifyNative(input({
        artifact: mintToken({ asl: 'attested-display' }),
        adapter_config: withFloor('attested-display'),
    }));
    assert.equal(refused.acceptance, 'REJECTED');
    assert.deepEqual(refused.reasons, ['oasnt:assurance_below_requirement']);
    // ...while a floor of platform-key admits the same token, because the
    // ceiling genuinely satisfies it (the lesser rule, not outright refusal).
    const lenient = createOasntAebAdapter({ config: withFloor('platform-key'), trust_roots: [trustRoot] });
    const admitted = lenient.verifyNative(input({
        artifact: mintToken({ asl: 'attested-display' }),
        adapter_config: withFloor('platform-key'),
    }));
    assert.equal(admitted.native_verification, 'VERIFIED');
    assert.equal(admitted.acceptance, 'ACCEPTED');
});
test('with a null floor no assurance evaluation runs, even for unrecognized asl', () => {
    const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
    const native = adapter.verifyNative(input({ artifact: mintToken({ asl: 'quantum-oracle' }) }));
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
});
test('asl that violates registry syntax is a malformed claim set', () => {
    const adapter = createOasntAebAdapter({ config, trust_roots: [trustRoot] });
    const native = adapter.verifyNative(input({ artifact: mintToken({ asl: 'Attested-Display' }) }));
    assert.equal(native.acceptance, 'REJECTED');
    assert.deepEqual(native.reasons, ['oasnt:claims_invalid']);
});
test('a v1 config without the assurance key is refused at the constructor pin', () => {
    const legacy = { ...config };
    delete legacy.required_assurance_level;
    assert.throws(() => createOasntAebAdapter({
        config: legacy,
        trust_roots: [trustRoot],
    }));
});
