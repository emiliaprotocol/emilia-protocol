// SPDX-License-Identifier: Apache-2.0
// Generated from aeb-aic-crossing-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import test from 'node:test';
import { digestAebTyped } from './dist/aeb-adapter-contract.js';
import { AIC_JWT_JKT_CROSSING_MAPPING_PROFILE, AIC_JWT_JKT_BOUND_CROSSING_MAPPING_PROFILE, AIC_JWT_SVID_PROJECTION_VERSION, AIC_X509_SPKI_CROSSING_MAPPING_PROFILE, mapAicJwtJktCrossingAuthority, mapAicJwtJktBoundCrossingAuthority, mapAicX509SpkiCrossingAuthority, projectAicJwtToStrictJwtSvid, } from './dist/aeb-aic-crossing-adapter.js';
const NOW = '2026-08-26T18:00:00Z';
const DIGEST = (octet) => `sha256:${octet.repeat(32)}`;
const TRUST_ANCHOR = DIGEST('11');
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
function common() {
    return {
        native_verification: 'VERIFIED',
        issuer: 'https://issuer.varwof.example',
        subject: 'spiffe://agents.example/agent/release-bot',
        artifact_id: 'aic-artifact-0001',
        artifact_digest: DIGEST('22'),
        issuer_trust_anchor_digest: TRUST_ANCHOR,
        trusted_issuer_trust_anchor_digests: [TRUST_ANCHOR],
        mapping_profile_digest: DIGEST('33'),
        constraints_digest: DIGEST('44'),
        status: {
            value: 'CURRENT',
            checked_at: NOW,
            source_head_digest: DIGEST('55'),
        },
        validity: {
            not_before: '2026-08-26T17:55:00Z',
            not_after: '2026-08-26T18:05:00Z',
        },
    };
}
function jwtInput() {
    return {
        ...common(),
        native_typ: 'aic+jwt',
        principal_binding: {
            kind: 'RFC7638_JKT',
            hash_alg: 'jkt',
            claimed_key_hash: 'A'.repeat(43),
            presented_key_hash: 'A'.repeat(43),
        },
    };
}
function x509Input() {
    return {
        ...common(),
        native_type: 'AIC-X509',
        certificate_serial: '01A5F0',
        principal_binding: {
            kind: 'X509_SPKI',
            hash_alg: 'sha-256',
            claimed_key_hash: 'B'.repeat(43),
            presented_key_hash: 'B'.repeat(43),
        },
    };
}
function boundContext() {
    return {
        action: ACTION,
        admission_domain: ADMISSION_DOMAIN,
        evaluated_at: NOW,
        max_status_age_seconds: 60,
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
});
test('bound mapping fails closed on non-current, stale, future, or out-of-window source status', () => {
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        status: { ...boundJwtInput().status, value: 'REVOKED' },
    }, boundContext()), { ok: false, reason: 'aic_status_not_current' });
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        status: { ...boundJwtInput().status, checked_at: '2026-08-26T17:58:00Z' },
    }, boundContext()), { ok: false, reason: 'aic_status_observation_stale' });
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority({
        ...boundJwtInput(),
        status: { ...boundJwtInput().status, checked_at: '2026-08-26T18:00:01Z' },
    }, boundContext()), { ok: false, reason: 'aic_status_observation_future' });
    assert.deepEqual(mapAicJwtJktBoundCrossingAuthority(boundJwtInput(), {
        ...boundContext(),
        evaluated_at: '2026-08-26T18:06:00Z',
        max_status_age_seconds: 600,
    }), { ok: false, reason: 'aic_validity_window_mismatch' });
});
test('pure-JSON RFC 7638 jkt and X.509 SPKI remain distinct native mappings', () => {
    const jwt = mapAicJwtJktCrossingAuthority(jwtInput());
    const x509 = mapAicX509SpkiCrossingAuthority(x509Input());
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
test('principal binding mismatch refuses before a crossing authority is emitted', () => {
    const jwt = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        principal_binding: {
            ...jwtInput().principal_binding,
            presented_key_hash: 'C'.repeat(43),
        },
    });
    const x509 = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        principal_binding: {
            ...x509Input().principal_binding,
            presented_key_hash: 'D'.repeat(43),
        },
    });
    assert.deepEqual(jwt, { ok: false, reason: 'aic_principal_binding_mismatch' });
    assert.deepEqual(x509, { ok: false, reason: 'aic_principal_binding_mismatch' });
});
test('an issuer-selected or empty trust set cannot establish relying-party acceptance', () => {
    const untrusted = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        issuer_trust_anchor_digest: DIGEST('66'),
    });
    const empty = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        trusted_issuer_trust_anchor_digests: [],
    });
    assert.deepEqual(untrusted, { ok: false, reason: 'aic_issuer_untrusted' });
    assert.deepEqual(empty, { ok: false, reason: 'aic_issuer_untrusted' });
});
test('native carrier and key-binding type confusion refuses', () => {
    const jwtTyp = mapAicJwtJktCrossingAuthority({
        ...jwtInput(),
        native_typ: 'JWT',
    });
    const jktAsX509 = mapAicX509SpkiCrossingAuthority({
        ...x509Input(),
        principal_binding: jwtInput().principal_binding,
    });
    assert.deepEqual(jwtTyp, { ok: false, reason: 'aic_native_type_confusion' });
    assert.deepEqual(jktAsX509, { ok: false, reason: 'aic_native_type_confusion' });
});
test('strict JWT-SVID projection creates new typ=JWT TBS bytes and never passes aic+jwt through', () => {
    const result = projectAicJwtToStrictJwtSvid({
        source: jwtInput(),
        purpose: 'WORKLOAD_IDENTITY_ONLY',
        audience: ['spiffe://services.example/payment-gate'],
        issued_at: 1787767200,
        not_before: 1787767140,
        expires_at: 1787767500,
        token_id: 'jwt-svid-projection-0001',
        projected_algorithm: 'ES256',
        projected_key_id: 'jwt-svid-key-2026-08',
        has_constraints: true,
        delegation_mode: 'representative',
        has_delegation_assertion: true,
        confirmation_key_present: true,
    });
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
        'aic.constraints',
        'da',
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
        issued_at: 1787767200,
        not_before: null,
        expires_at: 1787767500,
        token_id: 'jwt-svid-projection-0001',
        projected_algorithm: 'ES256',
        projected_key_id: 'jwt-svid-key-2026-08',
        has_constraints: false,
        delegation_mode: 'authorized',
        has_delegation_assertion: false,
        confirmation_key_present: false,
    };
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        source: { ...jwtInput(), native_typ: 'JWT' },
    }), { ok: false, reason: 'aic_native_type_confusion' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        audience: [...base.audience, 'spiffe://services.example/other'],
    }), { ok: false, reason: 'jwt_svid_single_audience_required' });
    assert.deepEqual(projectAicJwtToStrictJwtSvid({
        ...base,
        purpose: 'AIC_AUTHORITY',
        has_constraints: true,
    }), { ok: false, reason: 'aic_jwt_svid_semantic_loss' });
});
