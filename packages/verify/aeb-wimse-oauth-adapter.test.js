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
import { OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE, OAUTH_TRANSACTION_TOKENS_REVISION, WIMSE_OAUTH_SPT_AEB_ADAPTER_ID, WIMSE_OAUTH_SPT_AEB_ADAPTER_VERSION, WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION, WIMSE_OAUTH_SPT_TRUST_ROOT_VERSION, WIMSE_HTTP_SIGNATURE_REVISION, WIMSE_WORKLOAD_CREDS_REVISION, WIMSE_WORKLOAD_IDENTIFIER_REVISION, WIMSE_WPT_REVISION, createWimseOAuthSptAebAdapter, createWimseOAuthSptMappingProfile, deriveOAuthTransactionTokenReplayUnit, verifyWimseWpt02TokenBindingClaims, } from './aeb-wimse-oauth-adapter.js';
const NOW = '2026-07-24T12:00:00Z';
const NOW_SECONDS = Math.floor(Date.parse(NOW) / 1000);
const WORKLOAD_SUBJECT = 'wimse://payments.example/workloads/release-agent';
const RECEIVING_WORKLOAD = 'wimse://payments.example/workloads/payment-executor';
const SECOND_RECEIVING_WORKLOAD = 'wimse://payments.example/workloads/ledger-writer';
const WIMSE_AUDIENCE = 'https://payments.example/commit';
const OAUTH_AUDIENCE = 'payments.example';
const OAUTH_SUBJECT = 'principal:customer-42';
const OAUTH_SCOPE = 'payment.release';
const SPT_AUDIENCE = 'https://payments.example/pep';
const ACTION_TYPE = 'payment.release.1';
const OAUTH_CHALLENGE_HEADER = 'oauth-transaction-challenge';
const OAUTH_ACCESS_TOKEN_HEADER = 'oauth-transaction-access-token';
const OAUTH_CHALLENGE_TOKEN = 'challenge.jwt.static-test-value';
const OAUTH_ACCESS_TOKEN = 'access.jwt.static-test-value';
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
    // OAuth token-binding test commitment, not password or credential storage.
    // codeql[js/insufficient-password-hash]
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
    return createWimseOAuthSptMappingProfile(ACTION_TYPE);
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
    const oauthIssuer = options.oauthIssuer ?? crypto.generateKeyPairSync('ed25519');
    const sptIssuer = crypto.generateKeyPairSync('ed25519');
    const holder = crypto.generateKeyPairSync('ed25519');
    const attacker = crypto.generateKeyPairSync('ed25519');
    const holderJwk = holder.publicKey.export({ format: 'jwk' });
    const attackerJwk = attacker.publicKey.export({ format: 'jwk' });
    assert.equal(holderJwk.kty, 'OKP');
    assert.equal(holderJwk.crv, 'Ed25519');
    assert.equal(typeof holderJwk.x, 'string');
    assert.equal(attackerJwk.kty, 'OKP');
    assert.equal(attackerJwk.crv, 'Ed25519');
    assert.equal(typeof attackerJwk.x, 'string');
    const holderKeyId = 'workload-ed25519-2026-07';
    const holderKeyPin = `holder:${holderJwk.x}`;
    const workloadSubject = options.workloadSubject ?? WORKLOAD_SUBJECT;
    const oauthRequestingWorkload = options.oauthRequestingWorkload ?? workloadSubject;
    const oauthIssuerUrl = options.oauthIssuerUrl ?? 'https://tts.payments.example';
    const oauthIssuerKeyId = options.oauthIssuerKeyId ?? 'tts-ed25519-1';
    const config = {
        '@version': WIMSE_OAUTH_SPT_AEB_CONFIG_VERSION,
        evidence_role: 'delegated-workload',
        subject: {
            id: options.subjectId ?? 'workload:payment-release-agent',
            kind: 'workload',
            native_id: workloadSubject,
        },
        trust_domain: 'payments.example',
        receiving_workload: options.receivingWorkload ?? RECEIVING_WORKLOAD,
        oauth_requesting_workload: oauthRequestingWorkload,
        wimse_audience: WIMSE_AUDIENCE,
        oauth_audience: OAUTH_AUDIENCE,
        oauth_subject: OAUTH_SUBJECT,
        oauth_scope: OAUTH_SCOPE,
        spt_audience: SPT_AUDIENCE,
        spt_subject: workloadSubject,
        spt_holder_key: holderKeyPin,
        other_token_headers: [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_CHALLENGE_HEADER],
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
            issuer: oauthIssuerUrl,
            key_id: oauthIssuerKeyId,
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
            subject: workloadSubject,
            key_id: holderKeyId,
            algorithm: 'EdDSA',
            public_key: spki(holder.publicKey),
        },
    ];
    const witClaims = {
        iss: trustRoots[0].use === 'wit-issuer' ? trustRoots[0].issuer : '',
        sub: options.witSubject ?? workloadSubject,
        iat: NOW_SECONDS - 30,
        nbf: NOW_SECONDS - 30,
        exp: NOW_SECONDS + 1_800,
        jti: options.witJti ?? 'wit-2026-07-24-0001',
        cnf: {
            jwk: {
                kty: 'OKP',
                crv: 'Ed25519',
                alg: 'EdDSA',
                kid: holderKeyId,
                x: options.witHolder === 'attacker' ? attackerJwk.x : holderJwk.x,
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
        iss: oauthIssuerUrl,
        sub: OAUTH_SUBJECT,
        aud: options.oauthAudience ?? OAUTH_AUDIENCE,
        ...oauthTimes,
        txn: 'txn-payment-release-0001',
        scope: OAUTH_SCOPE,
        req_wl: options.oauthClaimRequestingWorkload ?? oauthRequestingWorkload,
        tctx: transactionContext,
    };
    if (options.oauthRctx !== undefined)
        oauthClaims.rctx = options.oauthRctx;
    const txnToken = compactJws({
        alg: 'EdDSA',
        typ: 'txntoken+jwt',
        kid: oauthIssuerKeyId,
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
        sub: workloadSubject,
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
        jti: options.wptJti ?? 'wpt-payment-release-0001',
        wth: sha256Base64url(wit),
        oth: options.wptOth ?? {
            [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_CHALLENGE_TOKEN),
            [OAUTH_ACCESS_TOKEN_HEADER]: sha256Base64url(OAUTH_ACCESS_TOKEN),
        },
    };
    if (!options.omitWptTth) {
        wptClaims.tth = options.wptTth ?? sha256Base64url(txnToken);
    }
    if (options.omitWptIatNbf) {
        delete wptClaims.iat;
        delete wptClaims.nbf;
    }
    const wpt = compactJws({
        alg: 'EdDSA',
        typ: 'wpt+jwt',
    }, wptClaims, holder.privateKey);
    const body = options.body
        ?? '{"amount_minor":"50000","currency":"USD","escrow_id":"escrow_4821"}';
    const method = 'POST';
    const targetUri = options.targetUri ?? 'https://payments.example/commit?mode=atomic';
    const parsedTarget = new URL(targetUri);
    const requestTarget = `${parsedTarget.pathname}${parsedTarget.search}`;
    const components = options.signatureComponents ?? [
        '@method',
        '@request-target',
        'content-type',
        'content-digest',
        'txn-token',
        'workload-identity-token',
        'authorization',
    ];
    const signatureParams = `(${components.map((component) => JSON.stringify(component)).join(' ')})`
        + `;created=${NOW_SECONDS - 3};expires=${NOW_SECONDS + 57}`
        + `;nonce="${options.signatureNonce ?? 'wimse-nonce-payment-release-0001'}"`
        + ';tag="wimse-workload-to-workload"'
        + `;wimse-aud="${options.signatureAudience ?? WIMSE_AUDIENCE}"`
        + (options.requestSignedResponse ? ';wimse-sign-response' : '');
    const headers = {
        'Content-Type': options.contentType ?? 'application/json',
        'Content-Digest': contentDigest(body),
        'Txn-Token': txnToken,
        'Workload-Identity-Token': wit,
        'OAuth-Transaction-Challenge': OAUTH_CHALLENGE_TOKEN,
        'OAuth-Transaction-Access-Token': OAUTH_ACCESS_TOKEN,
        Authorization: `WPT ${wpt}`,
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
            content_type: headers['Content-Type'],
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
    assert.equal(native.evidence_digest, digestAeb(fixture.artifact));
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
    assert.equal(WIMSE_WPT_REVISION, 'draft-ietf-wimse-wpt-02');
    assert.equal(WIMSE_HTTP_SIGNATURE_REVISION, 'draft-ietf-wimse-http-signature-06');
    assert.equal(WIMSE_WORKLOAD_CREDS_REVISION, 'draft-ietf-wimse-workload-creds-02');
    assert.equal(WIMSE_WORKLOAD_IDENTIFIER_REVISION, 'draft-ietf-wimse-identifier-02');
    assert.equal(OAUTH_TRANSACTION_TOKENS_REVISION, 'draft-ietf-oauth-transaction-tokens-11');
});
test('WPT-02 uses the Authorization scheme and accepts exp without nonstandard iat or nbf requirements', () => {
    const fixture = makeFixture({ omitWptIatNbf: true });
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
    assert.equal(native.acceptance, 'ACCEPTED');
    const legacyHeader = makeFixture();
    legacyHeader.artifact.request.headers['Workload-Proof-Token'] = legacyHeader.artifact.wpt;
    delete legacyHeader.artifact.request.headers.Authorization;
    const rejected = verifyFixture(legacyHeader);
    assert.equal(rejected.native_verification, 'FAILED');
    assert.equal(rejected.acceptance, 'REJECTED');
    assert.deepEqual(rejected.reasons, ['wimse-oauth-spt:native_header_value_mismatch']);
    const tabSeparatedScheme = makeFixture();
    tabSeparatedScheme.artifact.request.headers.Authorization = `WPT\t${tabSeparatedScheme.artifact.wpt}`;
    const tabRejected = verifyFixture(tabSeparatedScheme);
    assert.equal(tabRejected.native_verification, 'FAILED');
    assert.equal(tabRejected.acceptance, 'REJECTED');
});
test('mapping requires the exact canonical profile, resolver, omissions, and profile digest', () => {
    const fixture = makeFixture();
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED');
    const profiles = [
        (() => {
            const profile = structuredClone(fixture.profile);
            profile.registry_entry_ref = 'mapping:attacker';
            return profile;
        })(),
        (() => {
            const profile = structuredClone(fixture.profile);
            profile.resolver.implementation_digest = `sha256:${'0'.repeat(64)}`;
            return profile;
        })(),
        (() => {
            const profile = structuredClone(fixture.profile);
            profile.semantic_equivalence.omitted_nonmaterial_fields = [];
            return profile;
        })(),
        (() => {
            const profile = structuredClone(fixture.profile);
            profile.profile_digest = `sha256:${'0'.repeat(64)}`;
            return profile;
        })(),
    ];
    for (const profile of profiles) {
        const mapped = fixture.adapter.mapAction({
            ...fixture.input,
            profile,
            native,
        });
        assert.equal(mapped.mapping, 'INDETERMINATE');
        assert.deepEqual(mapped.reasons, ['mapping_profile_invalid']);
    }
});
test('the request-only -06 profile rejects signed-response negotiation it cannot enforce', () => {
    const fixture = makeFixture({ requestSignedResponse: true });
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.deepEqual(native.reasons, ['wimse-oauth-spt:http_signature_invalid_or_incomplete']);
});
test('WPT-02 oth binds the exact understood header set and trimmed ASCII token bytes', () => {
    const reversedOrder = makeFixture({
        wptOth: {
            [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_CHALLENGE_TOKEN),
            [OAUTH_ACCESS_TOKEN_HEADER]: sha256Base64url(OAUTH_ACCESS_TOKEN),
        },
    });
    assert.equal(verifyFixture(reversedOrder).native_verification, 'VERIFIED');
    const missingEntry = makeFixture({
        wptOth: {
            [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_CHALLENGE_TOKEN),
        },
    });
    const unknownEntry = makeFixture({
        wptOth: {
            [OAUTH_ACCESS_TOKEN_HEADER]: sha256Base64url(OAUTH_ACCESS_TOKEN),
            [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_CHALLENGE_TOKEN),
            'unknown-context-token': sha256Base64url('unknown'),
        },
    });
    const substitutedToken = makeFixture();
    substitutedToken.artifact.request.headers['OAuth-Transaction-Access-Token'] = 'substituted.access.token';
    const missingHeader = makeFixture();
    delete missingHeader.artifact.request.headers['OAuth-Transaction-Challenge'];
    for (const fixture of [missingEntry, unknownEntry, substitutedToken, missingHeader]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
        assert.match(native.reasons[0] ?? '', /wpt_token_binding_failed/);
    }
});
test('claim-level WPT-02 binding requires tth exactly when a Txn-Token is present', () => {
    const headersWithoutTxn = {
        'OAuth-Transaction-Access-Token': `  ${OAUTH_ACCESS_TOKEN}  `,
        'OAuth-Transaction-Challenge': OAUTH_CHALLENGE_TOKEN,
    };
    const oth = {
        [OAUTH_ACCESS_TOKEN_HEADER]: sha256Base64url(OAUTH_ACCESS_TOKEN),
        [OAUTH_CHALLENGE_HEADER]: sha256Base64url(OAUTH_CHALLENGE_TOKEN),
    };
    assert.deepEqual(verifyWimseWpt02TokenBindingClaims({ oth }, headersWithoutTxn, [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_CHALLENGE_HEADER]), {
        verification: 'VERIFIED',
        transaction_token: 'ABSENT',
        other_token_headers: [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_CHALLENGE_HEADER],
        reason: null,
    });
    assert.equal(verifyWimseWpt02TokenBindingClaims({ tth: sha256Base64url('orphan'), oth }, headersWithoutTxn, [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_CHALLENGE_HEADER]).reason, 'unexpected_tth_without_txn_token');
    assert.equal(verifyWimseWpt02TokenBindingClaims({ oth }, { ...headersWithoutTxn, 'Txn-Token': 'present' }, [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_CHALLENGE_HEADER]).reason, 'tth_missing_or_mismatch');
});
test('the canonical workload-subject profile remains scheme-generic', () => {
    const fixture = makeFixture({
        workloadSubject: 'spiffe://payments.example/workloads/release-agent',
    });
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
    assert.equal(native.acceptance, 'ACCEPTED', native.reasons.join('; '));
});
test('constructor rejects workload subjects with comparison ambiguity', () => {
    const fixture = makeFixture();
    const ambiguous = [
        'WIMSE://payments.example/workloads/release-agent',
        'wimse://Payments.example/workloads/release-agent',
        'wimse://payments.example/workloads/%72elease-agent',
        'wimse://payments.example/workloads/./release-agent',
        'wimse://payments.example/workloads//release-agent',
        'wimse://payments.example/workloads/release-agent/',
        'wimse://payments.example:443/workloads/release-agent',
        'wimse://payments.example/workloads/release-agent?tenant=other',
    ];
    for (const subject of ambiguous) {
        const config = structuredClone(fixture.config);
        config.subject.native_id = subject;
        config.spt_subject = subject;
        const trustRoots = structuredClone(fixture.trustRoots);
        const holder = trustRoots.find((root) => root.use === 'workload-holder');
        assert.ok(holder && holder.use === 'workload-holder');
        holder.subject = subject;
        assert.throws(() => createWimseOAuthSptAebAdapter({
            config,
            trust_roots: trustRoots,
        }), /constructor config/);
    }
});
test('constructor pins only the exact two sorted candidate token headers', () => {
    const fixture = makeFixture();
    for (const otherTokenHeaders of [
        [OAUTH_CHALLENGE_HEADER, OAUTH_ACCESS_TOKEN_HEADER],
        ['OAuth-Transaction-Access-Token'],
        ['txn-token'],
        [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_CHALLENGE_HEADER, 'if-match'],
        [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_CHALLENGE_HEADER, 'x-http-method-override'],
        [OAUTH_ACCESS_TOKEN_HEADER, OAUTH_ACCESS_TOKEN_HEADER],
    ]) {
        const config = structuredClone(fixture.config);
        config.other_token_headers = otherTokenHeaders;
        assert.throws(() => createWimseOAuthSptAebAdapter({
            config,
            trust_roots: fixture.trustRoots,
        }), /constructor config/);
    }
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
    const wrongScheme = makeFixture({
        witSubject: 'spiffe://payments.example/workloads/release-agent',
    });
    const siblingSubject = makeFixture({
        witSubject: 'wimse://payments.example/workloads/release-agent-admin',
    });
    const wrongSignatureAudience = makeFixture({ signatureAudience: 'https://attacker.example/commit' });
    for (const fixture of [
        wrongWptAudience,
        wrongOauthAudience,
        wrongSubject,
        wrongScheme,
        siblingSubject,
        wrongSignatureAudience,
    ]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
    }
});
test('WPT audience is bound to the exact canonical target authority and path after removing query', () => {
    const validDifferentQuery = makeFixture({
        targetUri: 'https://payments.example/commit?mode=serial',
    });
    assert.equal(verifyFixture(validDifferentQuery).native_verification, 'VERIFIED');
    const wrongAuthority = makeFixture({
        targetUri: 'https://attacker.example/commit?mode=atomic',
    });
    const wrongPath = makeFixture({
        targetUri: 'https://payments.example/admin?mode=atomic',
    });
    for (const fixture of [wrongAuthority, wrongPath]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
        assert.deepEqual(native.reasons, ['wimse-oauth-spt:request_target_audience_mismatch']);
    }
});
test('request targets are canonical HTTPS values projected to origin-form path and query', () => {
    for (const targetUri of [
        'https://payments.example/a/../commit?mode=atomic',
        'https://payments.example:443/commit?mode=atomic',
        'https://payments.example/commit?mode=atomic#fragment',
    ]) {
        const fixture = makeFixture({ targetUri });
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
        assert.deepEqual(native.reasons, ['wimse-oauth-spt:request_malformed']);
    }
});
test('WPT audience configuration rejects aliases and noncanonical URI spellings', () => {
    const fixture = makeFixture();
    for (const audience of [
        'https://payments.example/commit?mode=atomic',
        'https://payments.example:443/commit',
        'https://PAYMENTS.example/commit',
        'https://payments.example/a/../commit',
    ]) {
        const config = structuredClone(fixture.config);
        config.wimse_audience = audience;
        assert.throws(() => createWimseOAuthSptAebAdapter({
            config,
            trust_roots: fixture.trustRoots,
        }), /constructor config/);
    }
});
test('a signed Txn-Token twin with rctx fails before a lossy action mapping', () => {
    const withoutRequestContext = makeFixture();
    const withRequestContext = makeFixture({
        oauthRctx: {
            request_ip: '192.0.2.10',
            risk_tier: 'elevated',
        },
    });
    const accepted = verifyFixture(withoutRequestContext);
    const refused = verifyFixture(withRequestContext);
    assert.equal(accepted.native_verification, 'VERIFIED');
    assert.equal(accepted.acceptance, 'ACCEPTED');
    assert.equal(refused.native_verification, 'FAILED');
    assert.equal(refused.acceptance, 'REJECTED');
    assert.deepEqual(refused.reasons, ['wimse-oauth-spt:oauth_txn_rctx_unsupported']);
});
test('case-folded duplicate object headers fail, without claiming raw-wire cardinality', () => {
    const fixture = makeFixture();
    fixture.artifact.request.headers['txn-token'] = fixture.artifact.txn_token;
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.deepEqual(native.reasons, ['wimse-oauth-spt:request_malformed']);
});
test('issuer-signed WIT cannot rebind possession to an unpinned holder key', () => {
    const fixture = makeFixture({ witHolder: 'attacker' });
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.deepEqual(native.reasons, ['wimse-oauth-spt:wit_confirmation_key_mismatch']);
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
        'authorization',
    ];
    const missingCoverage = complete.map((omitted) => makeFixture({
        signatureComponents: complete.filter((component) => component !== omitted),
    }));
    const changedBody = makeFixture();
    changedBody.artifact.request.body = '{"amount_minor":"90000"}';
    const tooManySignatureComponents = makeFixture({
        signatureComponents: [
            ...complete,
            OAUTH_ACCESS_TOKEN_HEADER,
            OAUTH_CHALLENGE_HEADER,
            'signature-input',
        ],
    });
    for (const fixture of [...missingCoverage, changedBody, tooManySignatureComponents]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
    }
});
test('the exact request profile rejects unknown headers and keeps signed Content-Type material', () => {
    const extraHeader = makeFixture();
    extraHeader.artifact.request.headers['X-HTTP-Method-Override'] = 'DELETE';
    const extraHeaderNative = verifyFixture(extraHeader);
    assert.equal(extraHeaderNative.native_verification, 'FAILED');
    assert.equal(extraHeaderNative.acceptance, 'REJECTED');
    assert.deepEqual(extraHeaderNative.reasons, [
        'wimse-oauth-spt:request_header_set_mismatch',
    ]);
    const substitutedContentType = makeFixture({ contentType: 'application/cbor' });
    const substitutedNative = verifyFixture(substitutedContentType);
    assert.equal(substitutedNative.native_verification, 'VERIFIED');
    assert.equal(substitutedNative.acceptance, 'ACCEPTED');
    substitutedContentType.input.expected_action = structuredClone(substitutedContentType.expectedAction);
    substitutedContentType.input.expected_action.http.content_type = 'application/json';
    const mapped = substitutedContentType.adapter.mapAction({
        ...substitutedContentType.input,
        profile: substitutedContentType.profile,
        native: substitutedNative,
    });
    assert.equal(mapped.mapping, 'MISMATCH');
    assert.deepEqual(mapped.reasons, ['exact_action_projection_mismatch']);
});
test('request strings have scalar and byte limits before native verification', () => {
    const maxBody = makeFixture({ body: 'a'.repeat(262_144) });
    const maxBodyNative = verifyFixture(maxBody);
    assert.equal(maxBodyNative.native_verification, 'VERIFIED', maxBodyNative.reasons.join('; '));
    assert.equal(maxBodyNative.acceptance, 'ACCEPTED');
    assert.equal(maxBodyNative.evidence_digest, digestAeb(maxBody.artifact));
    const tooLargeBody = makeFixture({ body: 'a'.repeat(262_145) });
    const tooLargeHeader = makeFixture({ contentType: 'a'.repeat(131_073) });
    const tooLargeTarget = makeFixture({
        targetUri: `https://payments.example/${'a'.repeat(8_193)}`,
    });
    const invalidEvidenceDigest = digestAeb({ invalid_wimse_oauth_spt_value: true });
    const validStatusDigest = digestAeb({
        ...tooLargeBody.input.status,
        unavailable: false,
    });
    for (const fixture of [tooLargeBody, tooLargeHeader, tooLargeTarget]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
        assert.equal(native.evidence_digest, invalidEvidenceDigest);
        assert.equal(native.status_digest, validStatusDigest);
        assert.deepEqual(native.reasons, [
            'wimse-oauth-spt:artifact_resource_or_shape_invalid',
        ]);
    }
    const firstSurrogate = makeFixture({ body: '\ud800' });
    const secondSurrogate = makeFixture({ body: '\ud801' });
    assert.equal(firstSurrogate.artifact.request.headers['Content-Digest'], secondSurrogate.artifact.request.headers['Content-Digest']);
    for (const fixture of [firstSurrogate, secondSurrogate]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'REJECTED');
        assert.equal(native.evidence_digest, invalidEvidenceDigest);
        assert.equal(native.status_digest, validStatusDigest);
        assert.deepEqual(native.reasons, [
            'wimse-oauth-spt:artifact_resource_or_shape_invalid',
        ]);
    }
});
test('mapping refuses a forged accepted result before hashing an oversized changed artifact', () => {
    const fixture = makeFixture();
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'VERIFIED');
    fixture.artifact.request.body = 'a'.repeat(262_145);
    const mapped = fixture.adapter.mapAction({
        ...fixture.input,
        profile: fixture.profile,
        native,
    });
    assert.equal(mapped.mapping, 'INDETERMINATE');
    assert.deepEqual(mapped.reasons, ['native_evidence_digest_mismatch']);
});
test('mapping rebinds status and re-evaluates its current acceptance', () => {
    const fixture = makeFixture();
    const acceptedNative = verifyFixture(fixture);
    assert.equal(acceptedNative.acceptance, 'ACCEPTED');
    const statuses = [
        { ...fixture.input.status, revoked: true },
        { ...fixture.input.status, consumed: true },
        { ...fixture.input.status, unavailable: true },
        { ...fixture.input.status, checked_at: '2026-07-24T11:56:00Z' },
    ];
    for (const status of statuses) {
        const rebound = fixture.adapter.mapAction({
            ...fixture.input,
            status,
            profile: fixture.profile,
            native: acceptedNative,
        });
        assert.equal(rebound.mapping, 'INDETERMINATE');
        assert.deepEqual(rebound.reasons, ['native_status_digest_mismatch']);
    }
    const revokedInput = { ...fixture.input, status: statuses[0] };
    const revokedNative = fixture.adapter.verifyNative(revokedInput);
    assert.equal(revokedNative.acceptance, 'REJECTED');
    const forgedAcceptance = fixture.adapter.mapAction({
        ...revokedInput,
        profile: fixture.profile,
        native: {
            ...revokedNative,
            native_verification: 'VERIFIED',
            acceptance: 'ACCEPTED',
        },
    });
    assert.equal(forgedAcceptance.mapping, 'INDETERMINATE');
    assert.ok(forgedAcceptance.reasons.includes('native_status_not_accepted'));
    assert.ok(forgedAcceptance.reasons.includes('evidence_revoked'));
});
test('WPT tth and optional SPT intent transaction binding reject signed mismatches', () => {
    const wrongTth = makeFixture({ wptTth: sha256Base64url('different-transaction-token') });
    const missingTth = makeFixture({ omitWptTth: true });
    const wrongSptIntent = makeFixture({ sptIntentDigest: sha256Base64url('different-intent') });
    for (const fixture of [wrongTth, missingTth, wrongSptIntent]) {
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
test('OAuth txn creates a stable receiver-scoped replay ID across AEB wrappers and is fenced', () => {
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
        native_namespace: OAUTH_TRANSACTION_TOKEN_REPLAY_NAMESPACE,
        trust_domain: OAUTH_AUDIENCE,
        receiving_workload: RECEIVING_WORKLOAD,
        txn: 'txn-payment-release-0001',
    }));
    const store = new InMemoryAebConsumptionStore();
    assert.equal(store.reserve('aeb:operation:first', [first.replay_unit]), true);
    assert.equal(store.reserve('aeb:operation:second', [second.replay_unit]), false);
});
test('receiver-scoped replay identity has a compatibility-frozen golden value', () => {
    assert.equal(deriveOAuthTransactionTokenReplayUnit(OAUTH_AUDIENCE, RECEIVING_WORKLOAD, 'txn-payment-release-0001'), 'sha256:bfd653e378a0c0c6185b413e06d772f616bf4e43cd7f1c95032f6548dcc1ade6');
});
test('full adapter verification refuses replay at one workload and permits the unchanged txn at the next hop', () => {
    const oauthIssuer = crypto.generateKeyPairSync('ed25519');
    const firstHop = makeFixture({ oauthIssuer });
    const nextHop = makeFixture({
        oauthIssuer,
        subjectId: 'workload:payment-executor',
        workloadSubject: RECEIVING_WORKLOAD,
        receivingWorkload: SECOND_RECEIVING_WORKLOAD,
        oauthRequestingWorkload: WORKLOAD_SUBJECT,
        witJti: 'wit-2026-07-24-hop2-0001',
        wptJti: 'wpt-payment-release-hop2-0001',
        signatureNonce: 'wimse-nonce-payment-release-hop2-0001',
    });
    const first = verifyFixture(firstHop);
    const sameReceiverAgain = firstHop.adapter.verifyNative({
        ...firstHop.input,
        artifact_ref: 'artifact:wimse-oauth-spt-same-receiver-replay',
    });
    const downstream = verifyFixture(nextHop);
    assert.equal(first.native_verification, 'VERIFIED');
    assert.equal(sameReceiverAgain.native_verification, 'VERIFIED');
    assert.equal(downstream.native_verification, 'VERIFIED');
    assert.equal(downstream.acceptance, 'ACCEPTED');
    assert.equal(firstHop.artifact.txn_token, nextHop.artifact.txn_token);
    assert.notEqual(nextHop.config.subject.native_id, nextHop.config.oauth_requesting_workload);
    assert.equal(first.replay_unit, sameReceiverAgain.replay_unit);
    assert.notEqual(first.replay_unit, downstream.replay_unit);
    const store = new InMemoryAebConsumptionStore();
    assert.equal(store.reserve('aeb:operation:first-workload-use', [first.replay_unit]), true);
    assert.equal(store.reserve('aeb:operation:same-workload-replay', [sameReceiverAgain.replay_unit]), false);
    assert.equal(store.reserve('aeb:operation:different-workload-use', [downstream.replay_unit]), true);
});
test('receiving workload is constructor-pinned and must be canonical within the trust domain', () => {
    const fixture = makeFixture();
    for (const receivingWorkload of [
        '',
        'wimse://attacker.example/workloads/payment-executor',
        'wimse://payments.example/workloads/../payment-executor',
        'wimse://Payments.example/workloads/payment-executor',
    ]) {
        const config = structuredClone(fixture.config);
        config.receiving_workload = receivingWorkload;
        assert.throws(() => createWimseOAuthSptAebAdapter({
            config,
            trust_roots: fixture.trustRoots,
        }), /constructor config/);
    }
});
test('original OAuth requesting workload is constructor-pinned and canonical within the trust domain', () => {
    const fixture = makeFixture();
    const missing = structuredClone(fixture.config);
    delete missing.oauth_requesting_workload;
    assert.throws(() => createWimseOAuthSptAebAdapter({
        config: missing,
        trust_roots: fixture.trustRoots,
    }), /constructor config/);
    for (const requestingWorkload of [
        '',
        'wimse://attacker.example/workloads/release-agent',
        'wimse://payments.example/workloads/../release-agent',
        'wimse://Payments.example/workloads/release-agent',
    ]) {
        const config = structuredClone(fixture.config);
        config.oauth_requesting_workload = requestingWorkload;
        assert.throws(() => createWimseOAuthSptAebAdapter({
            config,
            trust_roots: fixture.trustRoots,
        }), /constructor config/);
    }
});
test('a validly signed Txn-Token cannot substitute the pinned original requesting workload', () => {
    const fixture = makeFixture({
        oauthClaimRequestingWorkload: SECOND_RECEIVING_WORKLOAD,
    });
    const native = verifyFixture(fixture);
    assert.equal(native.native_verification, 'FAILED');
    assert.equal(native.acceptance, 'REJECTED');
    assert.deepEqual(native.reasons, ['wimse-oauth-spt:oauth_txn_claims_mismatch']);
});
test('OAuth audience must equal the trust domain used by the receiver replay scope', () => {
    const fixture = makeFixture();
    const config = structuredClone(fixture.config);
    config.oauth_audience = 'other-trust-domain.example';
    assert.throws(() => createWimseOAuthSptAebAdapter({
        config,
        trust_roots: fixture.trustRoots,
    }), /constructor config/);
});
test('valid token reissuance and issuer migration cannot rekey the same native spend', () => {
    const currentFixture = makeFixture({
        oauthIssuer: crypto.generateKeyPairSync('ed25519'),
    });
    const migratedFixture = makeFixture({
        oauthIssuer: crypto.generateKeyPairSync('ed25519'),
        oauthIssuerUrl: 'https://tts-v2.payments.example',
        oauthIssuerKeyId: 'tts-v2-ed25519-1',
        witJti: 'wit-2026-07-24-migrated-0001',
        wptJti: 'wpt-payment-release-migrated-0001',
        signatureNonce: 'wimse-nonce-payment-release-migrated-0001',
    });
    const currentNative = verifyFixture(currentFixture);
    const migratedNative = verifyFixture(migratedFixture);
    assert.equal(currentNative.native_verification, 'VERIFIED');
    assert.equal(migratedNative.native_verification, 'VERIFIED');
    assert.notEqual(currentFixture.artifact.txn_token, migratedFixture.artifact.txn_token);
    const verifiedUnder = [
        {
            source_revision: OAUTH_TRANSACTION_TOKENS_REVISION,
            replay_unit: currentNative.replay_unit,
        },
        {
            source_revision: 'draft-ietf-oauth-transaction-tokens-next-review-label',
            replay_unit: migratedNative.replay_unit,
        },
    ];
    assert.notEqual(verifiedUnder[0].source_revision, verifiedUnder[1].source_revision);
    assert.equal(verifiedUnder[0].replay_unit, verifiedUnder[1].replay_unit);
    assert.notEqual(verifiedUnder[0].replay_unit, deriveOAuthTransactionTokenReplayUnit('other-trust-domain.example', 'wimse://other-trust-domain.example/workloads/payment-executor', 'txn-payment-release-0001'));
    const store = new InMemoryAebConsumptionStore();
    assert.equal(store.reserve('aeb:operation:current-revision', [verifiedUnder[0].replay_unit]), true);
    assert.equal(store.reserve('aeb:operation:next-revision', [verifiedUnder[1].replay_unit]), false);
});
test('unavailable or stale lifecycle status cannot authorize identifier reuse', () => {
    const unavailable = makeFixture();
    unavailable.input.status = {
        ...unavailable.input.status,
        unavailable: true,
    };
    const stale = makeFixture();
    stale.input.status = {
        ...stale.input.status,
        checked_at: '2026-07-24T11:56:00Z',
    };
    for (const fixture of [unavailable, stale]) {
        const native = verifyFixture(fixture);
        assert.equal(native.native_verification, 'VERIFIED', native.reasons.join('; '));
        assert.equal(native.acceptance, 'INDETERMINATE');
    }
    assert.deepEqual(unavailable.adapter.verifyNative(unavailable.input).reasons, ['status_unavailable']);
    assert.deepEqual(stale.adapter.verifyNative(stale.input).reasons, ['status_too_old']);
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
test('the v3 adapter invokes only the WPT-02 and Txn-Tokens-11 vector profile', () => {
    const vectorPath = new URL('../../conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/vectors.json', import.meta.url);
    const vector = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));
    assert.equal(vector['@version'], 'WIMSE-WPT02-OAUTH-TXN-AEB-VECTORS-v0.1');
    const ids = new Set(vector.cases.map((entry) => entry.id));
    for (const id of [
        'candidate_wrapper_bytes_bound_not_native_oauth_presentation',
        'missing_tth_with_txn_refused',
        'mismatched_tth_refused',
        'target_authority_substitution_refused',
        'target_path_substitution_refused',
        'noncanonical_target_uri_refused',
        'response_signature_negotiation_refused',
        'txn_rctx_present_refused_before_mapping',
        'case_variant_duplicate_header_refused',
        'unsigned_semantic_header_refused',
        'signed_content_type_substitution_changes_action',
        'configured_semantic_other_header_refused',
        'draft_revision_migration_does_not_rekey_spend',
        'direct_http_authorization_scheme_collision',
    ]) {
        assert.ok(ids.has(id), `missing vector ${id}`);
    }
});
