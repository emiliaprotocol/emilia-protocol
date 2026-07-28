// SPDX-License-Identifier: Apache-2.0
// Generated from reliance-program.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { RELIANCE_PROGRAM_SOURCE_VERSION, RELIANCE_PROGRAM_VERSION, RelianceProgramValidationError, compileRelianceProgram, createAdmissibilityProfileTrustAdapter, relianceProgramSourceDigest, signRelianceProgram, verifyRelianceProgram, } from './reliance-program.js';
import { hashCanonical } from './execution-binding.js';
import { trustProgramDigest, validateTrustProgram } from './trust-program.js';
const D = (character) => `sha256:${character.repeat(64)}`;
const C = (character) => `caid:1:health.prior-authorization-determination.1:jcs-sha256:${character.repeat(43)}`;
function profile(id = 'rp:admissibility:human-review:v1', evidence = 'human_authorization') {
    const body = {
        id,
        version: 1,
        authored_by: 'Example Health Plan',
        requires: [{ evidence, max_staleness_sec: 900 }],
        verdicts: ['unverifiable', 'conflicted', 'stale', 'missing_evidence', 'admissible'],
    };
    return { ...body, profile_hash: `sha256:${hashCanonical(body)}` };
}
const PROFILE_HASH = profile().profile_hash;
function source(profileHash = PROFILE_HASH) {
    return {
        '@version': RELIANCE_PROGRAM_SOURCE_VERSION,
        program_id: 'rp.payer.pas-adverse-determination.1',
        version: 1,
        relying_party: { id: 'payer:example-health-plan', key_id: 'rp-key-1' },
        root_caid: C('A'),
        action_digest: D('1'),
        valid_from: '2026-07-28T12:00:00Z',
        expires_at: '2026-07-29T12:00:00Z',
        stages: [
            {
                stage_id: 'licensed-review',
                depends_on: [],
                rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
                profiles: [{
                        profile_id: 'rp:admissibility:human-review:v1',
                        profile_hash: profileHash,
                        evaluation_max_age_sec: 300,
                        revocation_required: true,
                    }],
            },
        ],
        execution: {
            depends_on: ['licensed-review'],
            consequence_mode: 'action-escrow',
            capability_template_digest: null,
            escrow_profile_digest: D('e'),
        },
    };
}
function harness() {
    const keys = generateKeyPairSync('ed25519');
    const signed = signRelianceProgram(source(), keys.privateKey);
    const trustedKeys = {
        'rp-key-1': {
            relying_party_id: 'payer:example-health-plan',
            public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        },
    };
    return { keys, signed, trustedKeys, profiles: [profile()] };
}
function code(run) {
    try {
        run();
        return undefined;
    }
    catch (error) {
        assert.ok(error instanceof RelianceProgramValidationError);
        return error.code;
    }
}
test('signs and verifies the exact canonical relying-party source', () => {
    const { signed, trustedKeys } = harness();
    assert.equal(signed['@version'], RELIANCE_PROGRAM_VERSION);
    assert.equal(signed.source_digest, relianceProgramSourceDigest(signed.source));
    assert.equal(Object.isFrozen(signed.source.stages[0]), true);
    assert.deepEqual(verifyRelianceProgram(signed, { trustedKeys }), {
        valid: true,
        reason: null,
        source_digest: signed.source_digest,
        relying_party_id: 'payer:example-health-plan',
        key_id: 'rp-key-1',
    });
    const tampered = structuredClone(signed);
    tampered.source.action_digest = D('9');
    assert.equal(verifyRelianceProgram(tampered, { trustedKeys }).reason, 'source_digest_mismatch');
});
test('compiles pinned Admissibility Profile fragments into the existing Trust Program wire format', () => {
    const { signed, trustedKeys, profiles } = harness();
    const compiled = compileRelianceProgram(signed, { trustedKeys, profiles });
    assert.equal(compiled.version, RELIANCE_PROGRAM_VERSION);
    assert.equal(compiled.source_digest, signed.source_digest);
    assert.equal(compiled.program['@version'], 'EP-GATE-TRUST-PROGRAM-PROFILE-v1');
    assert.equal(compiled.program.stages[0].requirements[0].policy_digest, PROFILE_HASH);
    assert.equal(compiled.program.stages[0].requirements[0].evidence_type, 'ep-admissibility-evaluation');
    assert.equal(compiled.program.stages[0].requirements[0].verifier_profile, 'ep-admissibility-profile:v1');
    assert.equal(compiled.program_digest, trustProgramDigest(compiled.program));
    assert.equal(validateTrustProgram(compiled.program).valid, true);
    assert.deepEqual(compiled.trace, [{
            stage_id: 'licensed-review',
            requirement_id: 'admissibility-01',
            profile_id: 'rp:admissibility:human-review:v1',
            profile_hash: PROFILE_HASH,
        }]);
});
test('refuses unsigned, unknown-key, profile-substitution, and malformed source inputs', () => {
    const { signed, trustedKeys, profiles } = harness();
    const unsigned = structuredClone(signed);
    delete unsigned.signature;
    assert.equal(verifyRelianceProgram(unsigned, { trustedKeys }).reason, 'envelope_schema_invalid');
    assert.equal(verifyRelianceProgram(signed, { trustedKeys: {} }).reason, 'relying_party_key_untrusted');
    assert.equal(verifyRelianceProgram(signed, { trustedKeys: {
            'rp-key-1': { ...trustedKeys['rp-key-1'], relying_party_id: 'payer:other' },
        } }).reason, 'relying_party_identity_mismatch');
    const substituted = [profile(profiles[0].id, 'organization_attestation')];
    assert.equal(code(() => compileRelianceProgram(signed, { trustedKeys, profiles: substituted })), 'profile_pin_mismatch');
    const lyingHash = [{ ...profiles[0], authored_by: 'Attacker' }];
    assert.equal(code(() => compileRelianceProgram(signed, { trustedKeys, profiles: lyingHash })), 'profile_integrity_invalid');
    const extra = source();
    extra.surprise = true;
    assert.equal(code(() => signRelianceProgram(extra, harness().keys.privateKey)), 'source_schema_invalid');
});
test('refuses disconnected stages and CAID or action drift before authority can compile', () => {
    const { keys, trustedKeys, profiles } = harness();
    const disconnected = source();
    disconnected.stages.push({
        stage_id: 'decorative', depends_on: [],
        rule: { mode: 'all', distinct_subjects: false, distinct_keys: false },
        profiles: [{ profile_id: profile().id, profile_hash: PROFILE_HASH, evaluation_max_age_sec: 300, revocation_required: true }],
    });
    const signedDisconnected = signRelianceProgram(disconnected, keys.privateKey);
    assert.equal(code(() => compileRelianceProgram(signedDisconnected, { trustedKeys, profiles })), 'compiled_program_invalid');
    const invalidCaid = source();
    invalidCaid.root_caid = 'caid:not-valid';
    assert.equal(code(() => signRelianceProgram(invalidCaid, keys.privateKey)), 'source_binding_invalid');
    const invalidAction = source();
    invalidAction.action_digest = 'sha256:nope';
    assert.equal(code(() => signRelianceProgram(invalidAction, keys.privateKey)), 'source_binding_invalid');
});
test('runs the pinned Admissibility Profile as a Trust Program verifier without presenter-selected policy', async () => {
    const { signed, trustedKeys, profiles } = harness();
    const compiled = compileRelianceProgram(signed, { trustedKeys, profiles });
    const requirement = compiled.program.stages[0].requirements[0];
    const binding = {
        instance_id: 'instance:pas-001',
        program_digest: compiled.program_digest,
        program_version: compiled.program.version,
        root_caid: compiled.program.root_caid,
        action_digest: compiled.program.action_digest,
        stage_id: 'licensed-review',
        requirement_id: requirement.requirement_id,
        policy_digest: PROFILE_HASH,
        predecessor_receipt_digests: [],
    };
    const adapter = createAdmissibilityProfileTrustAdapter({
        profile: profiles[0],
        evaluate: (p, bundle) => ({
            profile_hash: p.profile_hash,
            verdict: bundle?.items?.length ? 'admissible' : 'missing_evidence',
        }),
        now: '2026-07-28T12:10:00Z',
        project: () => ({
            subjects: ['reviewer:licensed-001'],
            key_fingerprints: [D('f')],
            issued_at: '2026-07-28T12:09:00Z',
            expires_at: '2026-07-28T12:20:00Z',
            revocation_checked_at: '2026-07-28T12:09:30Z',
        }),
    });
    const artifact = {
        evidence_id: 'evidence:licensed-review-001',
        binding,
        evidence: {
            bundle: { items: [{
                        evidence: 'human_authorization',
                        digest: D('c'),
                        signature_valid: true,
                        issued_at: '2026-07-28T12:09:00Z',
                        revoked: false,
                        action_digest: compiled.program.action_digest,
                    }] },
        },
    };
    const accepted = await adapter({ artifact, requirement, program: compiled.program });
    assert.equal(accepted.valid, true);
    assert.equal(accepted.policy_digest, PROFILE_HASH);
    assert.equal(accepted.binding_digest, `sha256:${hashCanonical(binding)}`);
    const missing = structuredClone(artifact);
    missing.evidence.bundle.items = [];
    assert.equal((await adapter({ artifact: missing, requirement, program: compiled.program })).reason, 'admissibility_missing_evidence');
    const substituted = structuredClone(artifact);
    substituted.evidence.profile = profile('attacker:bar:v1');
    assert.equal((await adapter({ artifact: substituted, requirement, program: compiled.program })).reason, 'admissibility_evidence_schema_invalid');
});
