// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-aic-crossing-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { digestAebTyped } from './dist/aeb-adapter-contract.js';
import { AIC_CROSSING_MAX_STATUS_AGE_SECONDS, AIC_JWT_JKT_CROSSING_MAPPING_PROFILE, AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE, AIC_JWT_SVID_PROJECTION_VERSION, AIC_X509_SPKI_CROSSING_MAPPING_PROFILE, AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE, AIC_X509_CREDENTIAL_BUNDLE_DIGEST_VERSION, mapAicJwtJktCrossingAuthority, mapAicJwtJktBoundCrossingAuthority, mapAicX509SpkiCrossingAuthority, mapAicX509SpkiBoundCrossingAuthority, projectAicJwtToStrictJwtSvid, } from './dist/aeb-aic-crossing-adapter.js';
const NOW = '2026-09-01T07:00:00Z';
const DIGEST = (octet) => `sha256:${octet.repeat(32)}`;
const TRUST_ANCHOR = DIGEST('11');
const JWT_VERIFIER = {
    id: 'varwof:aic-jwt-validate.gateway-verify-bearer',
    version: 'source-lock-v0.2',
    implementation_digest: DIGEST('dd'),
};
const X509_VERIFIER = {
    id: 'varwof:gateway-verify-credential-bundle',
    version: 'source-lock-v0.2',
    implementation_digest: DIGEST('ee'),
};
const AGENT_CERTIFICATE_DER = 'MIIBczCCASWgAwIBAgICEIcwBQYDK2VwMDgxGTAXBgNVBAMMEGFnZW50LWFjY291bnRpbmcxGzAZBgNVBAoMEkVNSUxJQSBBSUMgRml4dHVyZTAeFw0yNjA5MDEwNjM1MTRaFw0zNjA4MjkwNjM1MTRaMDgxGTAXBgNVBAMMEGFnZW50LWFjY291bnRpbmcxGzAZBgNVBAoMEkVNSUxJQSBBSUMgRml4dHVyZTAqMAUGAytlcAMhABlRhmmMT_c3eHf39WJ53gjQ-XsXrkk2JjbOst7y2iG6o1MwUTAdBgNVHQ4EFgQUYRN3QUuM-4WfrO9gw0jrbCge6WkwHwYDVR0jBBgwFoAUYRN3QUuM-4WfrO9gw0jrbCge6WkwDwYDVR0TAQH_BAUwAwEB_zAFBgMrZXADQQAMwAAYlEzDMMFWXJomesb1_O7QypjsRF3DGHQLhuoBh2op5s9xTo7aiF1BAfW2O82QCy9LOCZsX1ymKcLUEJYL';
const PRINCIPAL_CERTIFICATE_DER = 'MIIBezCCAS2gAwIBAgICEIgwBQYDK2VwMDwxHTAbBgNVBAMMFHByaW5jaXBhbC1hY2NvdW50aW5nMRswGQYDVQQKDBJFTUlMSUEgQUlDIEZpeHR1cmUwHhcNMjYwOTAxMDYzNTE0WhcNMzYwODI5MDYzNTE0WjA8MR0wGwYDVQQDDBRwcmluY2lwYWwtYWNjb3VudGluZzEbMBkGA1UECgwSRU1JTElBIEFJQyBGaXh0dXJlMCowBQYDK2VwAyEAWP6IT_BCkU9xUCVQR2MePkJ_zYdkFYqAFp0jSzW6Re6jUzBRMB0GA1UdDgQWBBRZkhmqaCLhEEtolUAUZLVa7eBfejAfBgNVHSMEGDAWgBRZkhmqaCLhEEtolUAUZLVa7eBfejAPBgNVHRMBAf8EBTADAQH_MAUGAytlcANBAL-e_CxbdYdZRTB86m3ldvMg_dCpJHAtMl26I-T40QR2JFbG3xWhJTKfEMuZooI2jjHbjLsE1qHQ6s5v3EtphQ0';
const X509_SPKI = 'HHZknPZ96UejPrdBkR8uVScD38l0C-CydQ-8aWJ1iFo';
const PRINCIPAL_JWK = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'c_kUSHs4ymdA65GF3OV8C3PDWhelodqfOvCmFe-6oUI',
};
const JKT = crypto.createHash('sha256')
    .update(JSON.stringify({ crv: PRINCIPAL_JWK.crv, kty: PRINCIPAL_JWK.kty, x: PRINCIPAL_JWK.x }))
    .digest('base64url');
function jwtCompactToken(typ = 'aic+jwt', audience = 'erp:vendor-master') {
    const segment = (value) => Buffer.from(JSON.stringify(value), 'utf8')
        .toString('base64url');
    return [
        segment({ alg: 'EdDSA', typ, kid: 'issuer-key-1' }),
        segment({
            iss: 'https://issuer.varwof.example',
            sub: 'spiffe://agents.example/agent/release-bot',
            aud: audience,
            iat: 1788245700,
            exp: 1788246300,
            jti: 'aic-artifact-0001',
            cnf: { jkt: JKT },
            aic: {
                ver: 1,
                principal: {
                    realm: 'agents.example',
                    id: 'principal:release-owner',
                    key_hash: JKT,
                    hash_alg: 'jkt',
                },
                delegation_mode: 'authorized',
                capabilities: [{
                        scheme: 'varwof/core',
                        id: 'finance.vendor-account-change',
                        params: {
                            vendor_id: 'vendor-0042',
                            account_fingerprint: 'acct:7e8c',
                        },
                    }],
            },
        }),
        Buffer.from('fixture-signature', 'utf8').toString('base64url'),
    ].join('.');
}
const JWT_COMPACT_TOKEN = jwtCompactToken();
const JWT_ARTIFACT_DIGEST = `sha256:${crypto.createHash('sha256')
    .update(JWT_COMPACT_TOKEN, 'utf8')
    .digest('hex')}`;
const X509_ARTIFACT_DIGEST = digestAebTyped({
    agent_certificate_der: AGENT_CERTIFICATE_DER,
    principal_certificate_der: PRINCIPAL_CERTIFICATE_DER,
}, AIC_X509_CREDENTIAL_BUNDLE_DIGEST_VERSION);
const ACTION = {
    caid: 'caid:1:finance.vendor-account-change.1:jcs-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    action_digest: DIGEST('77'),
};
const ADMISSION_DOMAIN = {
    relying_party_id: 'rp:example-finance',
    audience: 'erp:vendor-master',
    executor_id: 'executor:erp-production',
    state_domain_id: 'state-domain:finance-primary',
};
function common(nativeVerifier = JWT_VERIFIER) {
    return {
        native_verification: 'VERIFIED',
        native_verifier: nativeVerifier,
        native_verification_evidence_digest: DIGEST('de'),
        issuer: 'https://issuer.varwof.example',
        subject: 'spiffe://agents.example/agent/release-bot',
        artifact_id: 'aic-artifact-0001',
        artifact_digest: JWT_ARTIFACT_DIGEST,
        issuer_trust_anchor_digest: TRUST_ANCHOR,
        constraints_digest: DIGEST('44'),
        status: {
            value: 'CURRENT',
            checked_at: NOW,
            source_head_digest: DIGEST('55'),
        },
        validity: {
            not_before: '2026-09-01T06:55:00Z',
            not_after: '2026-09-01T07:05:00Z',
        },
    };
}
function jwtPolicy(bound = false) {
    return {
        mapping_profile_id: bound
            ? AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE
            : AIC_JWT_JKT_CROSSING_MAPPING_PROFILE,
        mapping_profile_digest: DIGEST('33'),
        action_projection_profile_id: 'AIC-EXACT-ACTION-PROJECTION-v1',
        action_projection_profile_digest: DIGEST('88'),
        trusted_issuer_trust_anchor_digests: [TRUST_ANCHOR],
        native_verifier: JWT_VERIFIER,
    };
}
function x509Policy(bound = false) {
    return {
        mapping_profile_id: bound
            ? AIC_X509_SPKI_BOUND_CROSSING_MAPPING_PROFILE
            : AIC_X509_SPKI_CROSSING_MAPPING_PROFILE,
        mapping_profile_digest: DIGEST('33'),
        action_projection_profile_id: 'AIC-EXACT-ACTION-PROJECTION-v1',
        action_projection_profile_digest: DIGEST('88'),
        trusted_issuer_trust_anchor_digests: [TRUST_ANCHOR],
        native_verifier: X509_VERIFIER,
    };
}
function projectionContext() {
    return {
        relying_party_policy: jwtPolicy(),
        evaluated_at: NOW,
        max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
    };
}
function temporalContext() {
    return {
        evaluated_at: NOW,
        max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
    };
}
function jwtInput() {
    return {
        ...common(),
        carrier_provenance: {
            source_carrier: 'AIC-JWT-COMPACT',
            compact_token: JWT_COMPACT_TOKEN,
            presented_principal_jwk: PRINCIPAL_JWK,
            downstream_representation: 'DIRECT',
        },
        principal_binding: {
            kind: 'RFC7638_JKT',
            hash_alg: 'jkt',
            claimed_key_hash: JKT,
            presented_key_hash: JKT,
        },
    };
}
function x509Input() {
    return {
        ...common(X509_VERIFIER),
        artifact_digest: X509_ARTIFACT_DIGEST,
        carrier_provenance: {
            source_carrier: 'AIC-X509-CREDENTIAL-BUNDLE',
            agent_certificate_der: AGENT_CERTIFICATE_DER,
            principal_certificate_der: PRINCIPAL_CERTIFICATE_DER,
        },
        principal_binding: {
            kind: 'X509_SPKI',
            hash_alg: 'sha-256',
            claimed_key_hash: X509_SPKI,
            presented_key_hash: X509_SPKI,
        },
    };
}
function boundContext(policy = jwtPolicy(true)) {
    return {
        action: ACTION,
        admission_domain: ADMISSION_DOMAIN,
        requested_capability_digest: DIGEST('99'),
        evaluated_at: NOW,
        max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
        policy,
    };
}
function boundX509Input() {
    return {
        ...x509Input(),
        request_binding: boundJwtInput().request_binding,
    };
}
function boundJwtInput() {
    return {
        ...jwtInput(),
        request_binding: {
            action_projection_profile_id: 'AIC-EXACT-ACTION-PROJECTION-v1',
            action_projection_profile_digest: DIGEST('88'),
            requested_capability_digest: DIGEST('99'),
            projected_action: ACTION,
            projected_admission_domain_digest: digestAebTyped(ADMISSION_DOMAIN, 'EP-AIC-ADMISSION-DOMAIN-v1'),
        },
    };
}
test('bound mapping requires the same exact action and relying-party admission domain', () => {
    const result = mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), boundContext());
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok)
        return;
    assert.equal(result.authority.mapping_profile_id, AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE);
    const substitutedAction = mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), {
        ...boundContext(),
        action: { ...ACTION, action_digest: DIGEST('aa') },
    });
    assert.deepEqual(substitutedAction, {
        ok: false,
        reason: 'aic_action_projection_mismatch',
    });
    const substitutedDomain = mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), {
        ...boundContext(),
        admission_domain: {
            ...ADMISSION_DOMAIN,
            relying_party_id: 'rp:attacker-controlled',
        },
    });
    assert.deepEqual(substitutedDomain, {
        ok: false,
        reason: 'aic_admission_domain_mismatch',
    });
    const substitutedMappingPolicy = mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), {
        ...boundContext(),
        policy: {
            ...jwtPolicy(true),
            mapping_profile_id: 'attacker-selected-mapping-v1',
        },
    });
    assert.deepEqual(substitutedMappingPolicy, {
        ok: false,
        reason: 'aic_mapping_profile_unpinned',
    });
    const selfPinnedProjection = mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        request_binding: {
            ...boundJwtInput().request_binding,
            action_projection_profile_id: 'attacker-selected-projection-v1',
            action_projection_profile_digest: DIGEST('af'),
        },
    }, boundContext());
    assert.deepEqual(selfPinnedProjection, {
        ok: false,
        reason: 'aic_action_projection_profile_unpinned',
    });
    const substitutedCapability = mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        request_binding: {
            ...boundJwtInput().request_binding,
            requested_capability_digest: DIGEST('af'),
        },
    }, boundContext());
    assert.deepEqual(substitutedCapability, {
        ok: false,
        reason: 'aic_requested_capability_mismatch',
    });
});
test('bound mapping fails closed on non-current, stale, future, or out-of-window source status', () => {
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        status: { ...boundJwtInput().status, value: 'REVOKED' },
    }, boundContext()), { ok: false, reason: 'aic_status_not_current' });
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        status: { ...boundJwtInput().status, checked_at: '2026-09-01T06:58:00Z' },
    }, boundContext()), { ok: false, reason: 'aic_status_observation_stale' });
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        status: { ...boundJwtInput().status, checked_at: '2026-09-01T07:00:01Z' },
    }, boundContext()), { ok: false, reason: 'aic_status_observation_future' });
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        status: { ...boundJwtInput().status, checked_at: '2026-09-01T07:06:00Z' },
    }, {
        ...boundContext(),
        evaluated_at: '2026-09-01T07:06:00Z',
        max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
    }), { ok: false, reason: 'aic_validity_window_mismatch' });
});
test('unbound mappings require relying-party evaluation time and freshness', () => {
    assert.deepEqual(mapAicJwtJktCrossingAuthority(jwtInput(), jwtPolicy()), { ok: false, reason: 'aic_relying_party_temporal_context_required' });
    assert.deepEqual(mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        status: { ...x509Input().status, checked_at: '2026-09-01T06:58:00Z' },
    }, x509Policy(), temporalContext()), { ok: false, reason: 'aic_status_observation_stale' });
    assert.deepEqual(mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        status: { ...jwtInput().status, checked_at: '2026-09-01T07:06:00Z' },
    }, jwtPolicy(), {
        evaluated_at: '2026-09-01T07:06:00Z',
        max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
    }), { ok: false, reason: 'aic_validity_window_mismatch' });
});
test('the fixed source-status freshness profile cannot be widened by a caller', () => {
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), {
        ...boundContext(),
        max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS - 1,
    }), { ok: false, reason: 'aic_status_freshness_profile_mismatch' });
    const widened = {
        evaluated_at: NOW,
        max_status_age_seconds: 86_400,
    };
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), {
        ...boundContext(),
        ...widened,
    }), { ok: false, reason: 'aic_status_freshness_profile_mismatch' });
    assert.deepEqual(mapAicX509SpkiBoundCrossingAuthority(boundX509Input(), {
        ...boundContext(x509Policy(true)),
        ...widened,
    }), { ok: false, reason: 'aic_status_freshness_profile_mismatch' });
    assert.deepEqual(mapAicJwtJktCrossingAuthority(jwtInput(), jwtPolicy(), widened), { ok: false, reason: 'aic_status_freshness_profile_mismatch' });
    assert.deepEqual(mapAicX509SpkiCrossingAuthority(x509Input(), x509Policy(), widened), { ok: false, reason: 'aic_status_freshness_profile_mismatch' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        source: jwtInput(),
        purpose: 'WORKLOAD_IDENTITY_ONLY',
        audience: ['spiffe://services.example/payment-gate'],
        issued_at: 1788246000,
        not_before: 1788245940,
        expires_at: 1788246240,
        token_id: 'jwt-svid-projection-freshness-widening',
        projected_algorithm: 'ES256',
        projected_key_id: 'jwt-svid-key-2026-08',
    }, {
        ...projectionContext(),
        max_status_age_seconds: widened.max_status_age_seconds,
    }), { ok: false, reason: 'aic_status_freshness_profile_mismatch' });
});
test('bound JWT validity must equal the signed compact-token temporal envelope', () => {
    const result = mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        validity: {
            not_before: '2026-09-01T06:54:00Z',
            not_after: '2026-09-01T07:06:00Z',
        },
    }, boundContext());
    assert.deepEqual(result, { ok: false, reason: 'aic_jwt_validity_mismatch' });
});
test('pure-JSON RFC 7638 jkt and X.509 SPKI remain distinct native mappings', () => {
    const jwt = mapAicJwtJktCrossingAuthority(jwtInput(), jwtPolicy(), temporalContext());
    const x509 = mapAicX509SpkiCrossingAuthority(x509Input(), x509Policy(), temporalContext());
    assert.equal(jwt.ok, true, JSON.stringify(jwt));
    assert.equal(x509.ok, true, JSON.stringify(x509));
    if (!jwt.ok || !x509.ok)
        return;
    assert.equal(jwt.authority.mapping_profile_id, AIC_JWT_JKT_CROSSING_MAPPING_PROFILE);
    assert.equal(x509.authority.mapping_profile_id, AIC_X509_SPKI_CROSSING_MAPPING_PROFILE);
    assert.equal(jwt.authority.native_profile, 'AIC-JWT-RFC7638-JKT');
    assert.equal(x509.authority.native_profile, 'AIC-X509-SPKI');
    assert.notEqual(jwt.authority.authority_instance_digest, x509.authority.authority_instance_digest);
    assert.notEqual(jwt.authority.replay_unit, x509.authority.replay_unit);
    assert.equal(jwt.authority.rp_acceptance, 'ACCEPTED');
    assert.equal(x509.authority.rp_acceptance, 'ACCEPTED');
});
test('X.509 replay identity comes from exact DER rather than free wrapper labels', () => {
    const context = boundContext(x509Policy(true));
    const original = mapAicX509SpkiBoundCrossingAuthority(boundX509Input(), context);
    const relabeledArtifact = mapAicX509SpkiBoundCrossingAuthority({
        ...boundX509Input(),
        artifact_id: 'attacker-selected-artifact-label',
    }, context);
    const relabeledIssuer = mapAicX509SpkiBoundCrossingAuthority({
        ...boundX509Input(),
        issuer: 'https://other-wrapper-label.example',
    }, context);
    assert.equal(original.ok, true, JSON.stringify(original));
    assert.equal(relabeledArtifact.ok, true, JSON.stringify(relabeledArtifact));
    assert.equal(relabeledIssuer.ok, true, JSON.stringify(relabeledIssuer));
    if (!original.ok || !relabeledArtifact.ok || !relabeledIssuer.ok)
        return;
    assert.equal(original.authority.replay_unit, relabeledArtifact.authority.replay_unit);
    assert.equal(original.authority.replay_unit, relabeledIssuer.authority.replay_unit);
    assert.notEqual(original.authority.authority_instance_digest, relabeledArtifact.authority.authority_instance_digest);
    assert.notEqual(original.authority.authority_instance_digest, relabeledIssuer.authority.authority_instance_digest);
});
test('JWT replay identity follows issuer and jti across a re-signed compact token', () => {
    const segments = JWT_COMPACT_TOKEN.split('.');
    const resignedToken = [
        segments[0],
        segments[1],
        Buffer.from('different-fixture-signature', 'utf8').toString('base64url'),
    ].join('.');
    const original = mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), boundContext());
    const resigned = mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        artifact_digest: `sha256:${crypto.createHash('sha256')
            .update(resignedToken, 'utf8')
            .digest('hex')}`,
        carrier_provenance: {
            ...boundJwtInput().carrier_provenance,
            compact_token: resignedToken,
        },
    }, boundContext());
    assert.equal(original.ok, true, JSON.stringify(original));
    assert.equal(resigned.ok, true, JSON.stringify(resigned));
    if (!original.ok || !resigned.ok)
        return;
    assert.equal(original.authority.replay_unit, resigned.authority.replay_unit);
    assert.notEqual(original.authority.authority_instance_digest, resigned.authority.authority_instance_digest);
});
test('principal binding mismatch refuses before a crossing authority is emitted', () => {
    const jwt = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        principal_binding: {
            ...jwtInput().principal_binding,
            presented_key_hash: 'C'.repeat(43),
        },
    }, jwtPolicy(), temporalContext());
    const x509 = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        principal_binding: {
            ...x509Input().principal_binding,
            presented_key_hash: 'D'.repeat(43),
        },
    }, x509Policy(), temporalContext());
    assert.deepEqual(jwt, { ok: false, reason: 'aic_principal_binding_mismatch' });
    assert.deepEqual(x509, { ok: false, reason: 'aic_principal_binding_mismatch' });
});
test('native results cannot self-pin relying-party trust or verifier policy', () => {
    const untrusted = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        issuer_trust_anchor_digest: DIGEST('66'),
    }, jwtPolicy(), temporalContext());
    const selfPinned = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        issuer_trust_anchor_digest: DIGEST('66'),
        trusted_issuer_trust_anchor_digests: [DIGEST('66')],
    }, jwtPolicy(), temporalContext());
    const emptyPolicy = mapAicJwtJktCrossingAuthority(jwtInput(), { ...jwtPolicy(), trusted_issuer_trust_anchor_digests: [] }, temporalContext());
    const verifierSelfPin = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        native_verifier: {
            ...JWT_VERIFIER,
            implementation_digest: DIGEST('fe'),
        },
    }, jwtPolicy(), temporalContext());
    assert.deepEqual(untrusted, { ok: false, reason: 'aic_issuer_untrusted' });
    assert.deepEqual(selfPinned, { ok: false, reason: 'mapping_input_invalid' });
    assert.deepEqual(emptyPolicy, {
        ok: false,
        reason: 'aic_relying_party_policy_invalid',
    });
    assert.deepEqual(verifierSelfPin, {
        ok: false,
        reason: 'aic_native_verifier_unpinned',
    });
});
test('raw carrier provenance refuses synthesized-certificate relabeling and type confusion', () => {
    const wrongJwtCarrier = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        carrier_provenance: x509Input().carrier_provenance,
    }, jwtPolicy(), temporalContext());
    const wrongTypToken = jwtCompactToken('JWT');
    const jwtTyp = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        artifact_digest: `sha256:${crypto.createHash('sha256')
            .update(wrongTypToken, 'utf8')
            .digest('hex')}`,
        carrier_provenance: {
            ...jwtInput().carrier_provenance,
            compact_token: wrongTypToken,
        },
    }, jwtPolicy(), temporalContext());
    const claimAsPresentedKey = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        carrier_provenance: {
            source_carrier: 'AIC-JWT-COMPACT',
            compact_token: JWT_COMPACT_TOKEN,
            downstream_representation: 'DIRECT',
        },
    }, jwtPolicy(), temporalContext());
    const jktAsX509 = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        principal_binding: jwtInput().principal_binding,
    }, x509Policy(), temporalContext());
    const synthesizedJwtAsX509 = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        artifact_digest: JWT_ARTIFACT_DIGEST,
        carrier_provenance: {
            ...jwtInput().carrier_provenance,
            downstream_representation: 'SYNTHESIZED-X509',
        },
    }, x509Policy(), temporalContext());
    const synthesizedJwtAsJwt = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        carrier_provenance: {
            ...jwtInput().carrier_provenance,
            downstream_representation: 'SYNTHESIZED-X509',
        },
    }, jwtPolicy(), temporalContext());
    const missingNativeDer = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        carrier_provenance: {
            ...x509Input().carrier_provenance,
            agent_certificate_der: '',
        },
    }, x509Policy(), temporalContext());
    const changedBundleDigest = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        artifact_digest: DIGEST('ab'),
    }, x509Policy(), temporalContext());
    const unsupportedSpkiHash = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        principal_binding: {
            kind: 'X509_SPKI',
            hash_alg: 'sha-384',
            claimed_key_hash: 'A'.repeat(64),
            presented_key_hash: 'A'.repeat(64),
        },
    }, x509Policy(), temporalContext());
    assert.deepEqual(wrongJwtCarrier, {
        ok: false,
        reason: 'aic_carrier_provenance_unverifiable',
    });
    assert.deepEqual(jwtTyp, {
        ok: false,
        reason: 'aic_carrier_provenance_unverifiable',
    });
    assert.deepEqual(claimAsPresentedKey, {
        ok: false,
        reason: 'aic_carrier_provenance_unverifiable',
    });
    assert.deepEqual(jktAsX509, { ok: false, reason: 'aic_native_type_confusion' });
    assert.deepEqual(synthesizedJwtAsX509, {
        ok: false,
        reason: 'aic_carrier_provenance_unverifiable',
    });
    assert.equal(synthesizedJwtAsJwt.ok, true, JSON.stringify(synthesizedJwtAsJwt));
    assert.deepEqual(missingNativeDer, {
        ok: false,
        reason: 'aic_carrier_provenance_unverifiable',
    });
    assert.deepEqual(changedBundleDigest, {
        ok: false,
        reason: 'aic_carrier_artifact_digest_mismatch',
    });
    assert.deepEqual(unsupportedSpkiHash, {
        ok: false,
        reason: 'aic_native_type_confusion',
    });
});
test('bound JWT mapping derives and pins the compact-token audience', () => {
    const wrongAudienceToken = jwtCompactToken('aic+jwt', 'erp:other-system');
    const result = mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        artifact_digest: `sha256:${crypto.createHash('sha256')
            .update(wrongAudienceToken, 'utf8')
            .digest('hex')}`,
        carrier_provenance: {
            ...boundJwtInput().carrier_provenance,
            compact_token: wrongAudienceToken,
        },
    }, boundContext());
    assert.deepEqual(result, { ok: false, reason: 'aic_audience_mismatch' });
});
test('strict JWT-SVID projection creates new typ=JWT TBS bytes and never passes aic+jwt through', () => {
    const result = projectAicJwtToStrictJwtSvid({
        source: jwtInput(),
        purpose: 'WORKLOAD_IDENTITY_ONLY',
        audience: ['spiffe://services.example/payment-gate'],
        issued_at: 1788246000,
        not_before: 1788245940,
        expires_at: 1788246240,
        token_id: 'jwt-svid-projection-0001',
        projected_algorithm: 'ES256',
        projected_key_id: 'jwt-svid-key-2026-08',
    }, projectionContext());
    assert.equal(result.ok, true, JSON.stringify(result));
    if (!result.ok)
        return;
    assert.equal(result.projection['@version'], AIC_JWT_SVID_PROJECTION_VERSION);
    assert.deepEqual(result.projection.protected_header, {
        alg: 'ES256',
        kid: 'jwt-svid-key-2026-08',
        typ: 'JWT',
    });
    assert.equal(result.projection.payload.aud, 'spiffe://services.example/payment-gate');
    assert.equal(result.projection.payload.sub, jwtInput().subject);
    assert.equal('scope' in result.projection.payload, false);
    assert.equal(result.projection.source.typ, 'aic+jwt');
    assert.equal(result.projection.source.token_digest, jwtInput().artifact_digest);
    assert.equal(result.projection.new_signature_required, true);
    assert.equal(result.projection.compact_token, null);
    assert.equal(result.projection.authorization_decision, false);
    assert.equal(result.projection.authority_semantics_preserved, false);
    assert.deepEqual(result.projection.omitted_source_members, [
        'iss',
        'aic.principal',
        'aic.capabilities',
        'aic.delegation_mode',
        'cnf',
    ]);
    assert.equal(result.projection.projection_digest, digestAebTyped({
        protected_header: result.projection.protected_header,
        payload: result.projection.payload,
        source: result.projection.source,
        purpose: result.projection.purpose,
        omitted_source_members: result.projection.omitted_source_members,
        authority_semantics_preserved: false,
        new_signature_required: true,
    }, `${AIC_JWT_SVID_PROJECTION_VERSION}:projection`));
});
test('JWT-SVID projection refuses type confusion, multiple audiences, and authority-semantic loss', () => {
    const base = {
        source: jwtInput(),
        purpose: 'WORKLOAD_IDENTITY_ONLY',
        audience: ['spiffe://services.example/payment-gate'],
        issued_at: 1788246000,
        not_before: null,
        expires_at: 1788246240,
        token_id: 'jwt-svid-projection-0001',
        projected_algorithm: 'ES256',
        projected_key_id: 'jwt-svid-key-2026-08',
    };
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        source: {
            ...jwtInput(),
            artifact_digest: `sha256:${crypto.createHash('sha256')
                .update(jwtCompactToken('JWT'), 'utf8')
                .digest('hex')}`,
            carrier_provenance: {
                ...jwtInput().carrier_provenance,
                compact_token: jwtCompactToken('JWT'),
            },
        },
    }, projectionContext()), { ok: false, reason: 'aic_carrier_provenance_unverifiable' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        audience: [...base.audience, 'spiffe://services.example/other'],
    }, projectionContext()), { ok: false, reason: 'jwt_svid_single_audience_required' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        purpose: 'AIC_AUTHORITY',
    }, projectionContext()), { ok: false, reason: 'aic_jwt_svid_semantic_loss' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        source: {
            ...jwtInput(),
            status: { ...jwtInput().status, value: 'REVOKED' },
        },
    }, projectionContext()), { ok: false, reason: 'aic_status_not_current' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        source: {
            ...jwtInput(),
            status: { ...jwtInput().status, checked_at: '2026-09-01T06:58:00Z' },
        },
    }, projectionContext()), { ok: false, reason: 'jwt_svid_source_status_stale' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        expires_at: 2099520000,
    }, projectionContext()), { ok: false, reason: 'jwt_svid_source_validity_mismatch' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        has_constraints: true,
    }, projectionContext()), { ok: false, reason: 'jwt_svid_projection_input_invalid' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid(base, {
        ...projectionContext(),
        max_status_age_seconds: AIC_CROSSING_MAX_STATUS_AGE_SECONDS,
        attacker_selected: true,
    }), { ok: false, reason: 'jwt_svid_projection_input_invalid' });
});
