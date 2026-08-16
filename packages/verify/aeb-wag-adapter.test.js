// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-wag-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto, {} from 'node:crypto';
import test from 'node:test';
import { digestAeb, } from './aeb-adapter-contract.js';
import { WAG_AEB_ADAPTER_ID, WAG_AEB_ADAPTER_VERSION, WAG_AEB_CONFIG_VERSION, WAG_CAID_MAPPER_ID, WAG_CAID_MAPPING_VERSION, WAG_DRAFT_REVISION, WAG_DRAFT_SOURCE_COMMIT, WAG_DRAFT_SOURCE_SHA256, WAG_DRAFT_TXT_SHA256, WAG_GRANT_TYPE, WAG_TRUST_ROOT_VERSION, createWagActionDefinition, createWagAebAdapter, } from './aeb-wag-adapter.js';
const NOW_SECONDS = 1_800_000_000;
const NOW = new Date(NOW_SECONDS * 1000).toISOString();
const ISSUER = 'https://acme.agents.platform.example';
const OTHER_ISSUER = 'https://other.agents.platform.example';
const SUBJECT = 'wimse://acme.agents.platform.example/agent/7f3d9a2e';
const CHILD_SUBJECT = 'wimse://acme.agents.platform.example/agent/child';
const AS_ISSUER = 'https://as.saas.example';
const TOKEN_ENDPOINT = 'https://as.saas.example/token';
const RESOURCE = 'https://api.saas.example/';
const ACTION_TYPE = 'oauth.access-token.issue.1';
const signingKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const otherKeys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
function publicJwk(key) {
    const jwk = key.export({ format: 'jwk' });
    assert.equal(jwk.kty, 'EC');
    assert.equal(jwk.crv, 'P-256');
    assert.ok(jwk.x);
    assert.ok(jwk.y);
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
const config = Object.freeze({
    '@version': WAG_AEB_CONFIG_VERSION,
    evidence_role: 'workload-authorization-grant',
    issuer: ISSUER,
    tenancy: 'acme',
    wimse_authority: 'acme.agents.platform.example',
    authorization_server_issuer: AS_ISSUER,
    token_endpoint: TOKEN_ENDPOINT,
    resource: RESOURCE,
    action_type: ACTION_TYPE,
    property_claims: ['ctx', 'groups', 'namespace', 'roles'],
    require_wimse_identifier: true,
    clock_skew_seconds: 5,
    max_grant_lifetime_seconds: 300,
    max_status_age_seconds: 120,
});
const trustRoot = Object.freeze({
    '@version': WAG_TRUST_ROOT_VERSION,
    use: 'wag-per-tenancy-issuer-key',
    issuer: ISSUER,
    tenancy: 'acme',
    key_id: '2026-07-14',
    algorithm: 'ES256',
    public_jwk: publicJwk(signingKeys.publicKey),
});
function mintGrant(claims = {}, header = {}, privateKey = signingKeys.privateKey) {
    const completeHeader = { alg: 'ES256', kid: trustRoot.key_id, typ: 'JWT', ...header };
    const completeClaims = {
        iss: ISSUER,
        sub: SUBJECT,
        aud: [AS_ISSUER, TOKEN_ENDPOINT],
        exp: NOW_SECONDS + 300,
        iat: NOW_SECONDS,
        jti: '7d0f5a2b-93c8-4f0e-9c33-1b6a0e6d5f10',
        name: 'Support Triage Agent',
        namespace: 'acme/support',
        groups: ['support-eng'],
        roles: ['responder'],
        ctx: 'channel:C0123456789',
        ...claims,
    };
    const signingInput = [completeHeader, completeClaims]
        .map((value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url'))
        .join('.');
    const signature = crypto.sign('sha256', Buffer.from(signingInput, 'ascii'), {
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    return `${signingInput}.${signature}`;
}
function artifact(overrides = {}) {
    return {
        grant_type: WAG_GRANT_TYPE,
        assertion: mintGrant(),
        resource: RESOURCE,
        ...overrides,
    };
}
function action(grant = artifact()) {
    const claims = JSON.parse(Buffer.from(grant.assertion.split('.')[1], 'base64url').toString('utf8'));
    return {
        action_type: ACTION_TYPE,
        authorization_server: { issuer: AS_ISSUER, token_endpoint: TOKEN_ENDPOINT },
        grant: {
            issuer: claims.iss,
            subject: claims.sub,
            jti: claims.jti,
            assertion_digest: digestAeb(grant.assertion),
        },
        resource: grant.resource,
        properties: {
            ctx: claims.ctx,
            groups: claims.groups,
            namespace: claims.namespace,
            roles: claims.roles,
        },
    };
}
function profile() {
    return {
        version: WAG_CAID_MAPPING_VERSION,
        definition: createWagActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:wag-token-issuance-v1',
        mapper_id: WAG_CAID_MAPPER_ID,
        resolver: {
            id: WAG_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({ implementation: WAG_CAID_MAPPER_ID, version: '1' }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: ['grant.aud', 'grant.exp', 'grant.iat', 'grant.name'],
        },
        profile_digest: digestAeb(null),
    };
}
function input(currentArtifact = artifact(), overrides = {}) {
    const expectedAction = overrides.expected_action === undefined
        ? action(currentArtifact)
        : overrides.expected_action;
    return {
        artifact: currentArtifact,
        artifact_ref: 'wag:test-fixture-1',
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
test('WAG -00 source revision and exact reviewed bytes are pinned', () => {
    assert.equal(WAG_DRAFT_REVISION, 'draft-carleton-workload-authz-grant-00');
    assert.equal(WAG_DRAFT_SOURCE_COMMIT, '13f516a5e458b89ca30f7ea47a802091dd9d4154');
    assert.equal(WAG_DRAFT_TXT_SHA256, 'sha256:4b92283fefdce2093e11f70bbfce5aa00af9191f7b278d498f30f2b34a78f798');
    assert.equal(WAG_DRAFT_SOURCE_SHA256, 'sha256:195fa249380052324d78c8dbfbdeb4ff7b7c5b3bd5d9a9f4d9abf110e944e4e2');
});
test('a valid WAG grant verifies and maps the exact token-issuance request to one CAID', () => {
    const currentArtifact = artifact();
    const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
    assert.equal(adapter.id, WAG_AEB_ADAPTER_ID);
    assert.equal(adapter.version, WAG_AEB_ADAPTER_VERSION);
    const native = adapter.verifyNative(input(currentArtifact));
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'ACCEPTED');
    assert.equal(native.evidence_role, 'workload-authorization-grant');
    assert.deepEqual(native.subject, { id: SUBJECT, kind: 'workload' });
    const mapped = adapter.mapAction({ ...input(currentArtifact), profile: profile(), native });
    assert.equal(mapped.mapping, 'MATCH');
    assert.match(mapped.caid ?? '', /^caid:1:oauth\.access-token\.issue\.1:jcs-sha256:/);
    assert.equal(mapped.action_digest, digestAeb(action(currentArtifact)));
});
test('issuer, tenant key, audience, resource, and exact grant substitutions fail closed', () => {
    const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
    const cases = [
        ['issuer', artifact({ assertion: mintGrant({ iss: OTHER_ISSUER }) }), 'wag:issuer_mismatch'],
        ['audience', artifact({ assertion: mintGrant({ aud: ['https://evil.example'] }) }), 'wag:audience_mismatch'],
        ['resource', artifact({ resource: 'https://other.saas.example/' }), 'wag:resource_mismatch'],
        ['key', artifact({ assertion: mintGrant({}, {}, otherKeys.privateKey) }), 'wag:signature_invalid'],
    ];
    for (const [name, changed, reason] of cases) {
        const result = adapter.verifyNative(input(changed, { expected_action: action(artifact()) }));
        assert.equal(result.acceptance, 'REJECTED', name);
        assert.ok(result.reasons.includes(reason), `${name}: ${JSON.stringify(result.reasons)}`);
    }
    const swappedRoot = { ...trustRoot, tenancy: 'other' };
    const pinMismatch = adapter.verifyNative(input(artifact(), { trust_roots: [swappedRoot] }));
    assert.deepEqual(pinMismatch.reasons, ['wag:constructor_pin_mismatch']);
});
test('a newly seen subject is accepted but cannot substitute for another subject action', () => {
    const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
    const parentArtifact = artifact();
    const parentNative = adapter.verifyNative(input(parentArtifact));
    const parentMapping = adapter.mapAction({ ...input(parentArtifact), profile: profile(), native: parentNative });
    const childArtifact = artifact({ assertion: mintGrant({ sub: CHILD_SUBJECT, jti: 'child-jti' }) });
    const childNative = adapter.verifyNative(input(childArtifact));
    assert.equal(childNative.acceptance, 'ACCEPTED');
    assert.deepEqual(childNative.subject, { id: CHILD_SUBJECT, kind: 'workload' });
    const childMapping = adapter.mapAction({ ...input(childArtifact), profile: profile(), native: childNative });
    assert.equal(childMapping.mapping, 'MATCH');
    assert.notEqual(childMapping.caid, parentMapping.caid);
    const substitution = adapter.verifyNative(input(childArtifact, {
        expected_action: action(parentArtifact),
    }));
    assert.equal(substitution.acceptance, 'REJECTED');
    assert.ok(substitution.reasons.includes('wag:token_request_projection_mismatch'));
});
test('the profile treats WAG properties as evidence, never as automatic authorization', () => {
    const currentArtifact = artifact({ assertion: mintGrant({ roles: ['admin'] }) });
    const expected = action(currentArtifact);
    expected.properties.roles = ['responder'];
    const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
    const native = adapter.verifyNative(input(currentArtifact, { expected_action: expected }));
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.ok(native.reasons.includes('wag:token_request_projection_mismatch'));
});
test('grant time, status freshness, retirement, and native replay identity are enforced', () => {
    const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
    const expired = artifact({ assertion: mintGrant({ exp: NOW_SECONDS - 10 }) });
    assert.ok(adapter.verifyNative(input(expired)).reasons.includes('wag:grant_expired'));
    const future = artifact({ assertion: mintGrant({ iat: NOW_SECONDS + 60, exp: NOW_SECONDS + 120 }) });
    assert.ok(adapter.verifyNative(input(future)).reasons.includes('wag:grant_not_yet_valid'));
    const unavailable = adapter.verifyNative(input(artifact(), {
        status: { ...input().status, unavailable: true },
    }));
    assert.equal(unavailable.acceptance, 'INDETERMINATE');
    const revoked = adapter.verifyNative(input(artifact(), {
        status: { ...input().status, revoked: true },
    }));
    assert.equal(revoked.acceptance, 'REJECTED');
    const first = adapter.verifyNative(input(artifact(), { artifact_ref: 'wrapper:a' }));
    const second = adapter.verifyNative(input(artifact(), { artifact_ref: 'wrapper:b' }));
    assert.equal(first.replay_unit, second.replay_unit);
    const newJti = artifact({ assertion: mintGrant({ jti: 'new-jti' }) });
    assert.notEqual(first.replay_unit, adapter.verifyNative(input(newJti)).replay_unit);
});
test('WAG alone cannot be substituted for human approval or downstream action authority', () => {
    const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
    const currentArtifact = artifact();
    const downstream = {
        action_type: 'tool.invoke.1',
        tool: 'payments.transfer',
        parameters: { amount: '100.00', payee: 'acct_9' },
    };
    const native = adapter.verifyNative(input(currentArtifact, { expected_action: downstream }));
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.acceptance, 'INDETERMINATE');
    assert.ok(native.reasons.includes('wag:does_not_bind_downstream_action'));
    const mapped = adapter.mapAction({
        ...input(currentArtifact, { expected_action: downstream }),
        profile: profile(),
        native,
    });
    assert.equal(mapped.mapping, 'INDETERMINATE');
});
test('malformed, unsigned, unknown-key, and ambiguous WIMSE identifier grants are refused', () => {
    const adapter = createWagAebAdapter({ config, trust_roots: [trustRoot] });
    const cases = [
        ['malformed', artifact({ assertion: 'not-a-jwt' }), 'wag:malformed_grant'],
        ['none', artifact({ assertion: mintGrant({}, { alg: 'none' }) }), 'wag:unsupported_or_unpinned_key'],
        ['kid', artifact({ assertion: mintGrant({}, { kid: 'unknown' }) }), 'wag:unsupported_or_unpinned_key'],
    ];
    for (const [name, changed, reason] of cases) {
        const result = adapter.verifyNative(input(changed, { expected_action: action(artifact()) }));
        assert.equal(result.acceptance, 'REJECTED', name);
        assert.ok(result.reasons.includes(reason), `${name}: ${JSON.stringify(result.reasons)}`);
    }
    const bareConfig = { ...config };
    const bareAdapter = createWagAebAdapter({ config: bareConfig, trust_roots: [trustRoot] });
    const bare = artifact({ assertion: mintGrant({ sub: 'opaque-agent-id' }) });
    const bareInput = input(bare, {
        adapter_config: bareConfig,
        expected_action: action(bare),
    });
    const bareResult = bareAdapter.verifyNative(bareInput);
    assert.equal(bareResult.acceptance, 'REJECTED');
    assert.ok(bareResult.reasons.includes('wag:wimse_identifier_required'));
});
