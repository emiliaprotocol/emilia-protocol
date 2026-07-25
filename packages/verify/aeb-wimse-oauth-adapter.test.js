// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-wimse-oauth-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto, {} from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
// The CAID reference implementation intentionally has no TypeScript surface.
// @ts-expect-error -- exercised as the independent CAID recomputation.
import { computeCaid } from './vendor/caid.mjs';
import { InMemoryAebConsumptionStore, canonicalizeAeb, digestAeb, } from './aeb-adapter-contract.js';
import { OAUTH_TRANSACTION_TOKENS_REVISION, WIMSE_OAUTH_SPT_AEB_ADAPTER_ID, WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION, WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION, WIMSE_OAUTH_SPT_CAID_MAPPER_ID, WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION, WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION, createWimseOAuthSptAebAdapter, createWimseOAuthSptActionDefinition, } from './aeb-wimse-oauth-adapter.js';
const NOW = '2026-07-24T12:00:00Z';
const NOW_SECONDS = Math.floor(Date.parse(NOW) / 1000);
const WORKLOAD_SUBJECT = 'wimse://payments.example/workloads/release-agent';
const WIMSE_AUDIENCE = 'https://payments.example/commit';
const OAUTH_AUDIENCE = 'payments.example';
const OAUTH_SUBJECT = 'principal:customer-42';
const OAUTH_SCOPE = 'payment.release';
const SPT_AUDIENCE = 'https://payments.example/pep';
const ACTION_TYPE = 'payment.release.1';
function spki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function compactJws(header, claims, privateKey) {
    const protectedHeader = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payload = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
    const signingInput = `${protectedHeader}.${payload}`;
    const signature = crypto.sign(null, Buffer.from(signingInput, 'ascii'), privateKey).toString('base64url');
    return `${signingInput}.${signature}`;
}
function sha256Base64url(value) {
    return crypto.createHash('sha256').update(Buffer.from(value, 'ascii')).digest('base64url');
}
function contentDigest(body) {
    return `sha-256=:${crypto.createHash('sha256').update(Buffer.from(body, 'utf8')).digest('base64')}:`;
}
function sptIntentDigest(intent) {
    return crypto.createHash('sha256')
        .update(Buffer.from('spt-txn-intent-v1', 'utf8'))
        .update(Buffer.from([0]))
        .update(Buffer.from(canonicalizeAeb(intent), 'utf8'))
        .digest('base64url');
}
function mappingProfile() {
    return {
        version: WIMSE_OAUTH_SPT_CAID_MAPPING_VERSION,
        definition: createWimseOAuthSptActionDefinition(ACTION_TYPE),
        registry_entry_ref: 'mapping:wimse-oauth-spt-payment-release',
        mapper_id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
        resolver: {
            id: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
            version: '1',
            implementation_digest: digestAeb({
                implementation: WIMSE_OAUTH_SPT_CAID_MAPPER_ID,
                version: '1',
            }),
        },
        semantic_equivalence: {
            assertion: 'EQUIVALENT_UNDER_PROFILE',
            loss_policy: 'NO_MATERIAL_FIELD_LOSS',
            omitted_material_fields: [],
            omitted_nonmaterial_fields: [
                'wit.iss',
                'wit.sub',
                'oauth.iss',
                'oauth.aud',
                'oauth.sub',
                'oauth.txn',
                'oauth.req_wl',
                'spt.human_anchor',
                'spt.jti',
            ],
        },
        profile_digest: digestAeb(null),
    };
}
function signatureBase(components, signatureParams, method, requestTarget, headers) {
    const normalized = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), String(value).trim()]));
    const lines = components.map((component) => {
        const value = component === '@method'
            ? method
            : component === '@request-target'
                ? requestTarget
                : normalized.get(component);
        assert.notEqual(value, undefined, `test signer cannot resolve ${component}`);
        return `${JSON.stringify(component)}: ${value}`;
    });
    lines.push(`"@signature-params": ${signatureParams}`);
    return lines.join('\n');
}
function makeFixture(options = {}) {
    const witIssuer = crypto.generateKeyPairSync('ed25519');
    const oauthIssuer = crypto.generateKeyPairSync('ed25519');
    const sptIssuer = crypto.generateKeyPairSync('ed25519');
    const holder = crypto.generateKeyPairSync('ed25519');
    const attacker = crypto.generateKeyPairSync('ed25519');
    const holderJwk = holder.publicKey.export({ format: 'jwk' });
    assert.equal(holderJwk.kty, 'OKP');
    assert.equal(holderJwk.crv, 'Ed25519');
    assert.equal(typeof holderJwk.x, 'string');
    const holderKeyId = 'workload-ed25519-2026-07';
    const holderKeyPin = `holder:${holderJwk.x}`;
    const config = {
        '@version': WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION,
        evidence_role: 'delegated-workload',
        subject: {
            id: 'workload:payment-release-agent',
            kind: 'workload',
            native_id: WORKLOAD_SUBJECT,
        },
        trust_domain: 'payments.example',
        wimse_audience: WIMSE_AUDIENCE,
        oauth_audience: OAUTH_AUDIENCE,
        oauth_subject: OAUTH_SUBJECT,
        oauth_scope: OAUTH_SCOPE,
        spt_audience: SPT_AUDIENCE,
        spt_subject: WORKLOAD_SUBJECT,
        spt_holder_key: holderKeyPin,
        action_type: ACTION_TYPE,
        clock_skew_seconds: 2,
        max_age_seconds: {
            wit: 3_600,
            wpt: 300,
            oauth_txn: 600,
            spt_txn: 180,
            http_signature: 120,
            status: 120,
        },
    };
    const trustRoots = [
        {
            '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
            use: 'wit-issuer',
            issuer: 'https://identity.payments.example',
            key_id: 'wit-issuer-ed25519-1',
            algorithm: 'EdDSA',
            public_key: spki(witIssuer.publicKey),
        },
        {
            '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
            use: 'oauth-transaction-token-issuer',
            issuer: 'https://tts.payments.example',
            key_id: 'tts-ed25519-1',
            algorithm: 'EdDSA',
            public_key: spki(oauthIssuer.publicKey),
        },
        {
            '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
            use: 'spt-transaction-token-issuer',
            issuer: 'https://spt.payments.example',
            key_id: 'spt-ed25519-1',
            algorithm: 'EdDSA',
            public_key: spki(sptIssuer.publicKey),
        },
        {
            '@version': WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION,
            use: 'workload-holder',
            subject: WORKLOAD_SUBJECT,
            key_id: holderKeyId,
            algorithm: 'EdDSA',
            public_key: spki(holder.publicKey),
        },
    ];
    const witClaims = {
        iss: trustRoots[0].use === 'wit-issuer' ? trustRoots[0].issuer : '',
        sub: options.witSubject ?? WORKLOAD_SUBJECT,
        iat: NOW_SECONDS - 30,
        nbf: NOW_SECONDS - 30,
        exp: NOW_SECONDS + 1_800,
        jti: 'wit-2026-07-24-0001',
        cnf: {
            jwk: {
                kty: 'OKP',
                crv: 'Ed25519',
                alg: 'EdDSA',
                kid: holderKeyId,
                x: holderJwk.x,
            },
        },
    };
    const wit = compactJws({
        alg: options.witAlg ?? 'EdDSA',
        typ: 'wit+jwt',
        kid: 'wit-issuer-ed25519-1',
    }, witClaims, options.witSigner === 'attacker' ? attacker.privateKey : witIssuer.privateKey);
    const transactionContext = {
        effect: 'payment.release',
        target_id: 'escrow_4821',
        amount_minor: '50000',
        currency: 'USD',
    };
    const oauthTimes = options.oauthTimes ?? {
        iat: NOW_SECONDS - 10,
        nbf: NOW_SECONDS - 10,
        exp: NOW_SECONDS + 300,
    };
    const oauthClaims = {
        iss: 'https://tts.payments.example',
        sub: OAUTH_SUBJECT,
        aud: options.oauthAudience ?? OAUTH_AUDIENCE,
        ...oauthTimes,
        txn: 'txn-payment-release-0001',
        scope: OAUTH_SCOPE,
        req_wl: WORKLOAD_SUBJECT,
        tctx: transactionContext,
    };
    const txnToken = compactJws({
        alg: 'EdDSA',
        typ: 'txntoken+jwt',
        kid: 'tts-ed25519-1',
    }, oauthClaims, oauthIssuer.privateKey);
    const sptIntent = {
        tool: 'payment.release',
        params: {
            amount_minor: '50000',
            currency: 'USD',
            escrow_id: 'escrow_4821',
        },
        target: 'payments.example/escrow_4821',
    };
    const sptClaims = {
        iss: 'https://spt.payments.example',
        sub: WORKLOAD_SUBJECT,
        aud: SPT_AUDIENCE,
        iat: NOW_SECONDS - 5,
        nbf: NOW_SECONDS - 5,
        exp: NOW_SECONDS + 90,
        jti: 'spt-txn-payment-release-0001',
        txn_token_type: 'TXN',
        human_anchor: 'opaque-anchor-not-a-human-authorization-role',
        holder_key: holderKeyPin,
        spt_intent_digest: options.sptIntentDigest ?? sptIntentDigest(sptIntent),
    };
    const sptTxn = compactJws({
        alg: 'EdDSA',
        kid: 'spt-ed25519-1',
    }, sptClaims, sptIssuer.privateKey);
    const wptTimes = options.wptTimes ?? {
        iat: NOW_SECONDS - 5,
        nbf: NOW_SECONDS - 5,
        exp: NOW_SECONDS + 90,
    };
    const wptClaims = {
        aud: options.wptAudience ?? WIMSE_AUDIENCE,
        ...wptTimes,
        jti: 'wpt-payment-release-0001',
        wth: sha256Base64url(wit),
        tth: options.wptTth ?? sha256Base64url(txnToken),
    };
    const wpt = compactJws({
        alg: 'EdDSA',
        typ: 'wpt+jwt',
    }, wptClaims, holder.privateKey);
    const body = '{"amount_minor":"50000","currency":"USD","escrow_id":"escrow_4821"}';
    const method = 'POST';
    const targetUri = 'https://payments.example/commit?mode=atomic';
    const requestTarget = '/commit?mode=atomic';
    const components = options.signatureComponents ?? [
        '@method',
        '@request-target',
        'content-type',
        'content-digest',
        'txn-token',
        'workload-identity-token',
    ];
    const signatureParams = `(${components.map((component) => JSON.stringify(component)).join(' ')})`
        + `;created=${NOW_SECONDS - 3};expires=${NOW_SECONDS + 57}`
        + ';nonce="wimse-nonce-payment-release-0001"'
        + ';tag="wimse-workload-to-workload"'
        + `;wimse-aud="${options.signatureAudience ?? WIMSE_AUDIENCE}"`;
    const headers = {
        'Content-Type': 'application/json',
        'Content-Digest': contentDigest(body),
        'Txn-Token': txnToken,
        'Workload-Identity-Token': wit,
        'Workload-Proof-Token': wpt,
        'Signature-Input': `wimse=${signatureParams}`,
    };
    const requestSignature = crypto.sign(null, Buffer.from(signatureBase(components, signatureParams, method, requestTarget, headers), 'utf8'), holder.privateKey).toString('base64');
    headers.Signature = `wimse=:${requestSignature}:`;
    const includeSpt = options.includeSpt !== false;
    const artifact = {
        wit,
        wpt,
        txn_token: txnToken,
        request: {
            method,
            target_uri: targetUri,
            headers,
            body,
        },
    };
    if (includeSpt) {
        artifact.spt_txn = sptTxn;
        artifact.spt_intent = sptIntent;
    }
    const expectedAction = {
        action_type: ACTION_TYPE,
        http: {
            method,
            request_target: requestTarget,
            content_digest: headers['Content-Digest'],
            wimse_audience: options.signatureAudience ?? WIMSE_AUDIENCE,
        },
        transaction: {
            scope: OAUTH_SCOPE,
            context: transactionContext,
        },
    };
    if (includeSpt)
        expectedAction.spt_intent = sptIntent;
    const profile = mappingProfile();
    const adapter = createWimseOAuthSptAebAdapter({
        config,
        trust_roots: trustRoots,
    });
    const input = {
        artifact,
        artifact_ref: 'artifact:wimse-oauth-spt-1',
        status: {
            checked_at: '2026-07-24T11:59:30Z',
            expires_at: '2026-07-24T12:01:00Z',
            revocation_checked: true,
            revoked: false,
            consumed: false,
        },
        trust_roots: trustRoots,
        adapter_config: config,
        expected_action: expectedAction,
        now: NOW,
    };
    return { adapter, artifact, config, trustRoots, expectedAction, profile, input };
}
function verifyFixture(fixture) {
    return fixture.adapter.verifyNative(fixture.input);
}
test('real Ed25519 WIT, WPT, OAuth Txn, SPT intent, and HTTP signature map to one recomputed CAID', () => {
    const fixture = makeFixture();
    assert.equal(fixture.adapter.id, WIMSE_OAUTH_SPT_AEB_ADAPTER_ID);
    assert.equal(fixture.adapter.version, WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION);
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
    assert.equal(native.acceptance, 'ACCEPTED', native.reasons.join('; '));
    assert.equal(native.evidence_role, 'delegated-workload');
    assert.deepEqual(native.subject, {
        id: 'workload:payment-release-agent',
        kind: 'workload',
    });
    assert.match(native.replay_unit, /^sha256:[0-9a-f]{64}$/);
    const mapped = fixture.adapter.mapAction({
        ...fixture.input,
        profile: fixture.profile,
        native,
    });
    assert.equal(mapped.mapping, 'MATCH', mapped.reasons.join('; '));
    assert.equal(mapped.action_digest, digestAeb(fixture.expectedAction));
    const definition = fixture.profile.definition;
    const independentlyComputed = computeCaid(fixture.expectedAction, {
        suite: 'jcs-sha256',
        definitions: definition.definitions,
    });
    assert.equal(mapped.caid, independentlyComputed.caid);
    assert.match(mapped.caid ?? '', /^caid:1:payment\.release\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/);
});
test('SPT is optional, but its intent binding is mandatory whenever the token is present', () => {
    const withoutSpt = makeFixture({ includeSpt: false });
    const native = verifyFixture(withoutSpt);
    assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
    assert.equal(native.acceptance, 'ACCEPTED');
    const mapped = withoutSpt.adapter.mapAction({
        ...withoutSpt.input,
        profile: withoutSpt.profile,
        native,
    });
    assert.equal(mapped.mapping, 'MATCH', mapped.reasons.join('; '));
    assert.equal(Object.hasOwn(withoutSpt.expectedAction, 'spt_intent'), false);
    const incomplete = makeFixture();
    delete incomplete.artifact.spt_intent;
    const incompleteResult = verifyFixture(incomplete);
    assert.equal(incompleteResult.native_verification, 'FAILED');
    assert.equal(incompleteResult.acceptance, 'INDETERMINATE');
});
test('malformed, unexpected-algorithm, and wrong-key compact JWS inputs fail closed', () => {
    const malformed = makeFixture();
    malformed.artifact.wit = 'malformed.compact-jws';
    malformed.artifact.request.headers['Workload-Identity-Token'] = malformed.artifact.wit;
    const badAlg = makeFixture({ witAlg: 'ES256' });
    const wrongKey = makeFixture({ witSigner: 'attacker' });
    for (const fixture of [malformed, badAlg, wrongKey]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
    }
});
test('constructor-pinned audiences, trust domain, and workload subject cannot be substituted', () => {
    const wrongWptAudience = makeFixture({ wptAudience: 'https://attacker.example/commit' });
    const wrongOauthAudience = makeFixture({ oauthAudience: 'attacker.example' });
    const wrongSubject = makeFixture({ witSubject: 'wimse://attacker.example/workloads/release-agent' });
    const wrongSignatureAudience = makeFixture({ signatureAudience: 'https://attacker.example/commit' });
    for (const fixture of [
        wrongWptAudience,
        wrongOauthAudience,
        wrongSubject,
        wrongSignatureAudience,
    ]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
    }
});
test('iat, nbf, exp, and constructor-pinned maximum ages are all enforced', () => {
    const expired = makeFixture({
        wptTimes: {
            iat: NOW_SECONDS - 100,
            nbf: NOW_SECONDS - 100,
            exp: NOW_SECONDS - 10,
        },
    });
    const notYetValid = makeFixture({
        wptTimes: {
            iat: NOW_SECONDS - 1,
            nbf: NOW_SECONDS + 60,
            exp: NOW_SECONDS + 120,
        },
    });
    const stale = makeFixture({
        oauthTimes: {
            iat: NOW_SECONDS - 700,
            nbf: NOW_SECONDS - 700,
            exp: NOW_SECONDS + 10,
        },
    });
    for (const fixture of [expired, notYetValid, stale]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
    }
});
test('HTTP method, target, content digest, wimse-aud, and Txn-Token coverage fail closed', () => {
    const complete = [
        '@method',
        '@request-target',
        'content-type',
        'content-digest',
        'txn-token',
        'workload-identity-token',
    ];
    const missingCoverage = complete.map((omitted) => makeFixture({
        signatureComponents: complete.filter((component) => component !== omitted),
    }));
    const changedBody = makeFixture();
    changedBody.artifact.request.body = '{"amount_minor":"90000"}';
    for (const fixture of [...missingCoverage, changedBody]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
    }
});
test('WPT tth and optional SPT intent transaction binding reject signed mismatches', () => {
    const wrongTth = makeFixture({ wptTth: sha256Base64url('different-transaction-token') });
    const wrongSptIntent = makeFixture({ sptIntentDigest: sha256Base64url('different-intent') });
    for (const fixture of [wrongTth, wrongSptIntent]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
    }
});
test('missing exact action is INDETERMINATE and a different exact action is MISMATCH', () => {
    const fixture = makeFixture();
    const native = verifyFixture(fixture);
    assert.equal(native.acceptance, 'ACCEPTED');
    const missing = fixture.adapter.mapAction({
        ...fixture.input,
        expected_action: undefined,
        profile: fixture.profile,
        native,
    });
    assert.equal(missing.mapping, 'INDETERMINATE');
    assert.equal(missing.caid, null);
    assert.ok(missing.reasons.includes('missing_or_ambiguous_exact_action'));
    const changedAction = structuredClone(fixture.expectedAction);
    changedAction.transaction.context.amount_minor = '90000';
    const mismatch = fixture.adapter.mapAction({
        ...fixture.input,
        expected_action: changedAction,
        profile: fixture.profile,
        native,
    });
    assert.equal(mismatch.mapping, 'MISMATCH');
    assert.equal(mismatch.caid, null);
    assert.ok(mismatch.reasons.includes('exact_action_projection_mismatch'));
});
test('OAuth txn creates a stable native replay ID across AEB wrappers and is fenced', () => {
    const fixture = makeFixture();
    const first = verifyFixture(fixture);
    const second = fixture.adapter.verifyNative({
        ...fixture.input,
        artifact_ref: 'artifact:wimse-oauth-spt-second-wrapper',
    });
    assert.equal(first.native_verification, 'VERIFIED');
    assert.equal(second.native_verification, 'VERIFIED');
    assert.equal(first.replay_unit, second.replay_unit);
    assert.equal(first.replay_unit, digestAeb({
        native_protocol: OAUTH_TRANSACTION_TOKENS_REVISION,
        trust_domain: OAUTH_AUDIENCE,
        txn: 'txn-payment-release-0001',
    }));
    const store = new InMemoryAebConsumptionStore();
    assert.equal(store.reserve('aeb:operation:first', [first.replay_unit]), true);
    assert.equal(store.reserve('aeb:operation:second', [second.replay_unit]), false);
});
test('identity, possession, OAuth context, and SPT human_anchor cannot substitute a human authorization role', () => {
    const fixture = makeFixture();
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED');
    assert.equal(native.evidence_role, 'delegated-workload');
    assert.equal(native.subject.kind, 'workload');
    const substitutedConfig = structuredClone(fixture.config);
    substitutedConfig.evidence_role = 'human-authorization';
    const substituted = fixture.adapter.verifyNative({
        ...fixture.input,
        adapter_config: substitutedConfig,
    });
    assert.equal(substituted.native_verification, 'FAILED');
    assert.equal(substituted.acceptance, 'INDETERMINATE');
    assert.ok(substituted.reasons.includes('wimse-oauth-spt:constructor_pin_mismatch'));
    assert.throws(() => createWimseOAuthSptAebAdapter({
        config: substitutedConfig,
        trust_roots: fixture.trustRoots,
    }), /constructor config/);
});
test('checked-in vector enumerates the positive and required hostile classes', () => {
    const vectorPath = new URL('../../conformance/vectors/wimse-oauth-spt-aeb.v1.json', import.meta.url);
    const vector = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));
    const ids = new Set(vector.vectors.map((entry) => entry.id));
    for (const id of [
        'accept_real_ed25519_native_bundle',
        'reject_malformed_compact_jws',
        'reject_unexpected_algorithm',
        'reject_wrong_constructor_key',
        'reject_wrong_audience',
        'reject_wrong_workload_subject',
        'reject_expired_or_stale_token',
        'reject_tth_mismatch',
        'reject_spt_intent_mismatch',
        'indeterminate_missing_exact_action',
        'reject_native_replay_across_aeb_wrappers',
        'reject_human_role_substitution',
    ]) {
        assert.ok(ids.has(id), `missing vector ${id}`);
    }
});
