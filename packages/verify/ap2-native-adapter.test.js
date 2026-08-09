// SPDX-License-Identifier: Apache-2.0
// Generated from ap2-native-adapter.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { AP2_NATIVE_AEB_ADAPTER_ID, AP2_NATIVE_AEB_CONFIG_VERSION, createAp2NativeAebAdapter, } from './ap2-native-adapter.js';
import { digestAeb } from './aeb-adapter-contract.js';
const NOW = '2026-08-09T17:00:00.000Z';
const CAID = 'caid:1:payment.release.1:jcs-sha256:Riz3t86C4OB-fE_5XB_yUQDIoi1tOSZUPgAd_inMBnc';
const ACTION = Object.freeze({
    action_type: 'payment.release.1',
    payment_instruction_id: 'pi-ap2-1',
    amount: '184.00',
    currency: 'USD',
    beneficiary_account: `sha256:${'a'.repeat(64)}`,
});
const ACTION_DEFINITIONS = Object.freeze([{
        action_type: 'payment.release.1',
        required_fields: [
            { name: 'amount', type: 'amount-string' },
            { name: 'currency', type: 'enum' },
            { name: 'beneficiary_account', type: 'digest' },
            { name: 'payment_instruction_id', type: 'string' },
        ],
        optional_fields: [],
    }]);
const MANDATE = Object.freeze({
    vct: 'mandate.payment.1',
    serialized: 'native-ap2-sd-jwt-token',
});
function status(overrides = {}) {
    return {
        checked_at: '2026-08-09T16:59:30.000Z',
        expires_at: '2026-08-09T17:05:00.000Z',
        revocation_checked: true,
        revoked: false,
        consumed: false,
        ...overrides,
    };
}
function verifier() {
    return {
        id: 'external:ap2-reference',
        version: '0.2-test',
        implementation_digest: digestAeb({ implementation: 'external-ap2-reference', version: '0.2-test' }),
        verify(input) {
            assert.equal(input.artifact, MANDATE, 'the native mandate must reach its verifier without an EMILIA wrapper');
            return {
                verified: true,
                accepted: true,
                native_artifact_digest: digestAeb(MANDATE),
                replay_unit: digestAeb({ protocol: 'AP2', native_id: MANDATE.serialized }),
                evidence_role: 'ap2-native-authorization',
                subject: { id: 'human:alice', kind: 'human' },
                normalized_action: ACTION,
                action_digest: digestAeb(ACTION),
                reasons: [],
            };
        },
    };
}
function input(overrides = {}) {
    const nativeVerifier = verifier();
    return {
        artifact: MANDATE,
        artifact_ref: 'urn:ap2:mandate:payment:1',
        status: status(),
        trust_roots: [{ issuer: 'https://wallet.example', key_id: 'wallet-1' }],
        adapter_config: {
            '@version': AP2_NATIVE_AEB_CONFIG_VERSION,
            source_revision: 'ap2-agent-authorization-v0.2',
            evidence_role: 'ap2-native-authorization',
            subject: { id: 'human:alice', kind: 'human' },
            max_status_age_seconds: 300,
            verifier: {
                id: nativeVerifier.id,
                version: nativeVerifier.version,
                implementation_digest: nativeVerifier.implementation_digest,
            },
        },
        expected_action: ACTION,
        now: NOW,
        ...overrides,
    };
}
describe('native AP2 AEB adapter', () => {
    it('preserves the AP2 mandate as native evidence and maps its exact action', () => {
        let nativeVerificationCalls = 0;
        const pinnedVerifier = verifier();
        const verifyNative = pinnedVerifier.verify.bind(pinnedVerifier);
        pinnedVerifier.verify = (candidate) => {
            nativeVerificationCalls += 1;
            return verifyNative(candidate);
        };
        const adapter = createAp2NativeAebAdapter(pinnedVerifier);
        assert.equal(adapter.id, AP2_NATIVE_AEB_ADAPTER_ID);
        const native = adapter.verifyNative(input());
        assert.equal(native.native_verification, 'VERIFIED');
        assert.equal(native.acceptance, 'ACCEPTED');
        assert.equal(native.evidence_digest, digestAeb(MANDATE));
        assert.equal(native.replay_unit, digestAeb({ protocol: 'AP2', native_id: MANDATE.serialized }));
        const mapping = adapter.mapAction({
            ...input(),
            profile: {
                version: 'test',
                definition: { suite: 'jcs-sha256', definitions: ACTION_DEFINITIONS },
                registry_entry_ref: 'mapping:ap2:test',
                mapper_id: 'mapper:ap2:test',
                resolver: { id: 'resolver:ap2:test', version: '1', implementation_digest: digestAeb({ resolver: 'ap2' }) },
                semantic_equivalence: {
                    assertion: 'EQUIVALENT_UNDER_PROFILE',
                    loss_policy: 'NO_MATERIAL_FIELD_LOSS',
                    omitted_material_fields: [],
                    omitted_nonmaterial_fields: [],
                },
                profile_digest: digestAeb({ profile: 'ap2-test' }),
            },
            native,
        });
        assert.deepEqual(mapping, {
            mapping: 'MATCH',
            caid: CAID,
            action_digest: digestAeb(ACTION),
            reasons: [],
        });
        assert.equal(nativeVerificationCalls, 1, 'mapAction must consume the exact native result instead of verifying twice');
    });
    it('refuses revoked native evidence and makes unavailable status indeterminate', () => {
        const adapter = createAp2NativeAebAdapter(verifier());
        const revoked = adapter.verifyNative(input({ status: status({ revoked: true }) }));
        assert.equal(revoked.native_verification, 'VERIFIED');
        assert.equal(revoked.acceptance, 'REJECTED');
        assert.ok(revoked.reasons.includes('evidence_revoked'));
        const unavailable = adapter.verifyNative(input({ status: status({ unavailable: true }) }));
        assert.equal(unavailable.acceptance, 'INDETERMINATE');
        assert.ok(unavailable.reasons.includes('status_unavailable'));
    });
    it('fails closed when the pinned verifier descriptor is substituted', () => {
        const adapter = createAp2NativeAebAdapter(verifier());
        const candidate = input();
        candidate.adapter_config.verifier.id = 'attacker:verifier';
        const native = adapter.verifyNative(candidate);
        assert.equal(native.native_verification, 'FAILED');
        assert.equal(native.acceptance, 'INDETERMINATE');
        assert.ok(native.reasons.includes('ap2:pinned_verifier_mismatch'));
    });
});
