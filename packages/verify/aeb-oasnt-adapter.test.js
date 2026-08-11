// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-oasnt-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { digestAeb, } from './aeb-adapter-contract.js';
import { OASNT_AEB_ADAPTER_ID, OASNT_AEB_ADAPTER_VERSION, OASNT_AEB_CONFIG_VERSION, OASNT_CAID_DRAFT_REVISION, OASNT_CAID_MAPPER_ID, OASNT_CAID_MAPPING_VERSION, OASNT_DRAFT_REVISION, OASNT_TRUST_ROOT_VERSION, computeOasntActionDigest, computeOasntCaid, computeOasntDisplayDigest, computeOasntRequestFingerprint, createOasntActionDefinition, createOasntAebAdapter, } from './aeb-oasnt-adapter.js';
const vectors = JSON.parse(fs.readFileSync(new URL('../../conformance/vectors/oasnt-caid-aeb.v1.json', import.meta.url), 'utf8'));
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
test('OASNT -01 published canonicalization vectors match byte-for-byte', () => {
    assert.equal(computeOasntActionDigest(OASNT_ACTION_TYPE, expectedAction.native_action.parameters), 'YlHp3M4JIWFPPZIVAwAmYOBOMfUyb2bjE6ve3AD2iaQ');
    assert.equal(computeOasntDisplayDigest(OASNT_ACTION_TYPE, expectedAction.native_action.parameters), 'uSEgOG9UC1IWGxzBalJv5cIbfxE8kxmoKF25yrRl1fs');
    assert.equal(computeOasntRequestFingerprint(request), '1GL7CIg1JkKGaGfHgdF5_93rVx4FqfjoY0lYZ6xbjQ0');
});
test('OASNT -01 published compact token verifies and maps to one EMILIA CAID', () => {
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
    assert.equal(OASNT_DRAFT_REVISION, 'draft-thallapelly-oasnt-01');
    assert.equal(OASNT_CAID_DRAFT_REVISION, 'draft-thallapelly-oasnt-caid-01');
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
for (const vector of vectors.vectors.filter((candidate) => candidate.section === '6.4')) {
    test(`OASNT-CAID-01 section 6.4: ${vector.id}`, () => {
        assert.equal(vectors['@version'], 'OASNT-CAID-AEB-VECTORS-v1');
        assert.equal(vectors.source, 'draft-thallapelly-oasnt-caid-01');
        const run = joinVectorHandlers[vector.id];
        assert.equal(typeof run, 'function', `missing executable handler for ${vector.id}`);
        run();
    });
}
