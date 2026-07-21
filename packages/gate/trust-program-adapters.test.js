// SPDX-License-Identifier: Apache-2.0
// Generated from trust-program-adapters.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { canonicalKeyFingerprint, createActionEscrowExecutionOutcomeVerifier, createActionEscrowTerminalOutcomeVerifier, createAecTrustProgramAdapter, createPinnedEvidenceAdapter, createQuorumTrustProgramAdapter, createReceiptProgramExecutionOutcomeVerifier, createReceiptProgramTerminalOutcomeVerifier, } from './src/trust-program-adapters.ts';
import { TRUST_PROGRAM_VERSION, trustProgramDigest } from './trust-program.js';
const HASH = (character) => `sha256:${character.repeat(64)}`;
const POLICY_DIGEST = HASH('a');
const NOW = '2026-07-21T18:00:00.000Z';
const ROOT_CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
function requirement(overrides = {}) {
    return {
        requirement_id: 'approval',
        evidence_type: 'ep-aec',
        verifier_profile: 'ep-aec',
        policy_digest: POLICY_DIGEST,
        max_age_sec: 900,
        revocation_required: true,
        ...overrides,
    };
}
function program() {
    return {
        '@version': TRUST_PROGRAM_VERSION,
        program_id: 'tp_adapter_test',
        version: 1,
        root_caid: ROOT_CAID,
        action_digest: HASH('b'),
        valid_from: '2026-07-21T17:00:00.000Z',
        expires_at: '2026-07-21T19:00:00.000Z',
        stages: [{
                stage_id: 'approval',
                depends_on: [],
                rule: { mode: 'all', distinct_subjects: true, distinct_keys: true },
                requirements: [requirement()],
            }],
        execution: {
            depends_on: ['approval'],
            consequence_mode: 'receipt-program',
            capability_template_digest: HASH('c'),
            escrow_profile_digest: null,
        },
    };
}
function binding(overrides = {}) {
    const definition = program();
    return {
        instance_id: 'tpi_adapter_test',
        program_digest: trustProgramDigest(definition),
        program_version: definition.version,
        root_caid: definition.root_caid,
        action_digest: definition.action_digest,
        stage_id: 'approval',
        requirement_id: 'approval',
        policy_digest: POLICY_DIGEST,
        predecessor_receipt_digests: [],
        ...overrides,
    };
}
const metadata = {
    subjects: ['zoe', 'alice', 'alice'],
    key_fingerprints: [HASH('2'), HASH('1'), HASH('1')],
    issued_at: '2026-07-21T17:59:00Z',
    expires_at: '2026-07-21T18:05:00.000Z',
    revocation_checked_at: '2026-07-21T17:59:30+00:00',
};
test('generic adapter refuses presenter trust configuration and normalizes authenticated claims', async () => {
    let trustedSeen;
    const adapter = createPinnedEvidenceAdapter({
        policyDigest: POLICY_DIGEST,
        trustedConfiguration: { trustedKeys: { signer: 'server-owned' } },
        verify: async (_evidence, context) => {
            trustedSeen = context.trustedConfiguration;
            return {
                valid: true,
                binding_digest: context.expectedBindingDigest,
                policy_digest: context.expectedPolicyDigest,
                ...metadata,
            };
        },
    });
    const accepted = await adapter({
        artifact: { evidence_id: 'ev_generic', binding: binding(), evidence: { signed: true } },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(accepted.valid, true);
    assert.deepEqual(trustedSeen, { trustedKeys: { signer: 'server-owned' } });
    assert.deepEqual(accepted.subjects, ['alice', 'zoe']);
    assert.deepEqual(accepted.key_fingerprints, [HASH('1'), HASH('2')]);
    assert.equal(accepted.issued_at, '2026-07-21T17:59:00.000Z');
    assert.equal(accepted.revocation_checked_at, '2026-07-21T17:59:30.000Z');
    const injected = await adapter({
        artifact: {
            evidence_id: 'ev_injected',
            binding: binding(),
            evidence: { signed: true },
            trustedKeys: { signer: 'attacker' },
        },
        requirement: requirement(),
        program: program(),
    });
    assert.deepEqual(injected, { valid: false, reason: 'artifact_schema_invalid' });
    const nestedInjection = await adapter({
        artifact: {
            evidence_id: 'ev_nested_injection',
            binding: binding(),
            evidence: { signed: true, trustedKeys: { signer: 'attacker' } },
        },
        requirement: requirement(),
        program: program(),
    });
    assert.deepEqual(nestedInjection, {
        valid: false, reason: 'artifact_trust_configuration_forbidden',
    });
});
test('generic adapter fails closed on exact binding and policy mismatches', async () => {
    const make = (mutation) => createPinnedEvidenceAdapter({
        policyDigest: POLICY_DIGEST,
        verify: async (_evidence, context) => ({
            valid: true,
            binding_digest: context.expectedBindingDigest,
            policy_digest: context.expectedPolicyDigest,
            ...metadata,
            ...mutation,
        }),
    });
    const input = {
        artifact: { evidence_id: 'ev_mismatch', binding: binding(), evidence: {} },
        requirement: requirement(),
        program: program(),
    };
    assert.equal((await make({ binding_digest: HASH('e') })(input)).reason, 'evidence_binding_mismatch');
    assert.equal((await make({ policy_digest: HASH('f') })(input)).reason, 'evidence_policy_mismatch');
    assert.equal((await make({})({ ...input, requirement: requirement({ policy_digest: HASH('0') }) })).reason, 'requirement_policy_mismatch');
});
test('quorum adapter injects the pinned policy and enrolled keys into real-verifier input', async () => {
    const alice = generateKeyPairSync('ed25519').publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const bob = generateKeyPairSync('ed25519').publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const policy = {
        mode: 'threshold',
        required: 2,
        approvers: [
            { role: 'controller', approver: 'alice' },
            { role: 'cfo', approver: 'bob' },
        ],
        distinct_humans: true,
        window_sec: 300,
    };
    let verifierInput;
    const adapter = createQuorumTrustProgramAdapter({
        policy,
        policyDigest: POLICY_DIGEST,
        approverKeys: { alice, bob },
        verificationOptions: { rpId: 'rp.example', allowedOrigins: ['https://rp.example'] },
        revocationCheckedAt: NOW,
        verifyQuorum: (quorum, options) => {
            verifierInput = { quorum, options };
            return {
                valid: true,
                members: quorum.members.map((member) => ({
                    approver: member.signoff.context.approver,
                    role: member.role,
                    valid: true,
                })),
                checks: {},
            };
        },
    });
    const members = [
        {
            role: 'controller',
            signoff: { context: { approver: 'alice', issued_at: '2026-07-21T17:58:00.000Z', expires_at: '2026-07-21T18:05:00.000Z' } },
        },
        {
            role: 'cfo',
            signoff: { context: { approver: 'bob', issued_at: '2026-07-21T17:59:00.000Z', expires_at: '2026-07-21T18:04:00.000Z' } },
        },
    ];
    const accepted = await adapter({
        artifact: { evidence_id: 'ev_quorum', binding: binding(), evidence: { members } },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(accepted.valid, true);
    assert.deepEqual(verifierInput.quorum.policy, policy);
    assert.equal(verifierInput.quorum.members[0].approver_public_key, alice);
    assert.equal(verifierInput.quorum.members[1].approver_public_key, bob);
    assert.equal(verifierInput.quorum.action_hash, accepted.binding_digest);
    assert.deepEqual(verifierInput.options, {
        rpId: 'rp.example', allowedOrigins: ['https://rp.example'],
    });
    assert.deepEqual(accepted.subjects, ['alice', 'bob']);
    assert.deepEqual(accepted.key_fingerprints, [
        canonicalKeyFingerprint(alice),
        canonicalKeyFingerprint(bob),
    ].sort());
    const suppliedPolicy = await adapter({
        artifact: {
            evidence_id: 'ev_quorum_injected',
            binding: binding(),
            evidence: { policy: { mode: 'threshold', required: 1 }, members },
        },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(suppliedPolicy.reason, 'quorum_evidence_schema_invalid');
});
test('quorum adapter admits corrected ordered M-of-N and refuses thresholds above the roster', async () => {
    const keys = Object.fromEntries(['alice', 'bob', 'carol'].map((approver) => [
        approver,
        generateKeyPairSync('ed25519').publicKey
            .export({ type: 'spki', format: 'der' }).toString('base64url'),
    ]));
    let called = false;
    const adapter = createQuorumTrustProgramAdapter({
        policy: {
            mode: 'ordered',
            required: 2,
            approvers: [
                { role: 'controller', approver: 'alice' },
                { role: 'cfo', approver: 'bob' },
                { role: 'director', approver: 'carol' },
            ],
        },
        policyDigest: POLICY_DIGEST,
        approverKeys: keys,
        revocationCheckedAt: NOW,
        verifyQuorum: (quorum) => {
            called = true;
            assert.equal(quorum.policy.required, 2);
            assert.equal(quorum.policy.approvers.length, 3);
            return {
                valid: true,
                members: quorum.members.map((member) => ({
                    approver: member.signoff.context.approver,
                    role: member.role,
                    valid: true,
                })),
            };
        },
    });
    const members = ['alice', 'bob'].map((approver, index) => ({
        role: index === 0 ? 'controller' : 'cfo',
        signoff: {
            context: {
                approver,
                issued_at: `2026-07-21T17:5${8 + index}:00.000Z`,
                expires_at: '2026-07-21T18:05:00.000Z',
            },
        },
    }));
    const result = await adapter({
        artifact: { evidence_id: 'ev_ordered', binding: binding(), evidence: { members } },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(result.valid, true);
    assert.equal(called, true);
    let invalidCalled = false;
    const invalid = createQuorumTrustProgramAdapter({
        policy: {
            mode: 'ordered', required: 4,
            approvers: [
                { role: 'controller', approver: 'alice' },
                { role: 'cfo', approver: 'bob' },
                { role: 'director', approver: 'carol' },
            ],
        },
        policyDigest: POLICY_DIGEST,
        approverKeys: keys,
        revocationCheckedAt: NOW,
        verifyQuorum: () => { invalidCalled = true; return { valid: true }; },
    });
    assert.equal((await invalid({
        artifact: { evidence_id: 'ev_invalid_ordered', binding: binding(), evidence: { members } },
        requirement: requirement(), program: program(),
    })).reason, 'quorum_policy_invalid');
    assert.equal(invalidCalled, false);
});
test('AEC adapter supplies only RP-owned requirement, action, policies, keys, and custom verifiers', async () => {
    const keysByType = { permit: { issuer: 'server-key' } };
    const policiesByType = { permit: { issuer: 'server-policy' } };
    const customVerifier = () => ({ valid: false, action_digest: null });
    let verifierOptions;
    const adapter = createAecTrustProgramAdapter({
        policyDigest: POLICY_DIGEST,
        requirement: 'permit AND ep-quorum',
        keysByType,
        policiesByType,
        verifiers: { permit: customVerifier },
        verificationTime: NOW,
        verifyAuthorizationChain: (_chain, options) => {
            verifierOptions = options;
            return {
                satisfied: true,
                expected_action_bound: true,
                action_digest: options.expectedActionDigest,
                components: [],
                reasons: [],
                ...metadata,
            };
        },
    });
    const chain = {
        '@version': 'EP-AEC-v1',
        action: binding(),
        components: [{ type: 'permit', evidence: { signed: true } }],
        requirement: 'permit',
    };
    const result = await adapter({
        artifact: { evidence_id: 'ev_aec', binding: binding(), evidence: chain },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(result.valid, true);
    assert.equal(verifierOptions.requirement, 'permit AND ep-quorum');
    assert.deepEqual(verifierOptions.expectedAction, binding());
    assert.equal(verifierOptions.expectedActionDigest, result.binding_digest);
    assert.deepEqual(verifierOptions.keysByType, keysByType);
    assert.deepEqual(verifierOptions.policiesByType, policiesByType);
    assert.equal(verifierOptions.verifiers.permit, customVerifier);
    assert.equal(verifierOptions.verificationTime, NOW);
    const injected = await adapter({
        artifact: {
            evidence_id: 'ev_aec_injected',
            binding: binding(),
            evidence: chain,
            keysByType: { permit: { issuer: 'attacker-key' } },
        },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(injected.reason, 'artifact_schema_invalid');
    const nestedInjection = await adapter({
        artifact: {
            evidence_id: 'ev_aec_nested_injected',
            binding: binding(),
            evidence: { ...chain, keysByType: { permit: { issuer: 'attacker-key' } } },
        },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(nestedInjection.reason, 'artifact_trust_configuration_forbidden');
});
test('Quorum and AEC defaults resolve the repository verifiers and fail closed', async () => {
    const publicKey = generateKeyPairSync('ed25519').publicKey
        .export({ type: 'spki', format: 'der' }).toString('base64url');
    const quorum = createQuorumTrustProgramAdapter({
        policy: {
            mode: 'threshold', required: 1,
            approvers: [{ role: 'controller', approver: 'alice' }],
        },
        policyDigest: POLICY_DIGEST,
        approverKeys: { alice: publicKey },
        revocationCheckedAt: NOW,
    });
    const quorumResult = await quorum({
        artifact: {
            evidence_id: 'ev_real_quorum_refusal',
            binding: binding(),
            evidence: {
                members: [{
                        role: 'controller',
                        signoff: {
                            context: {
                                approver: 'alice',
                                issued_at: '2026-07-21T17:59:00.000Z',
                                expires_at: '2026-07-21T18:05:00.000Z',
                            },
                        },
                    }],
            },
        },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(quorumResult.reason, 'quorum_verification_failed');
    const aec = createAecTrustProgramAdapter({
        policyDigest: POLICY_DIGEST,
        requirement: 'external-permit',
        keysByType: {},
        policiesByType: {},
        verificationTime: NOW,
    });
    const aecResult = await aec({
        artifact: {
            evidence_id: 'ev_real_aec_refusal',
            binding: binding(),
            evidence: {
                '@version': 'EP-AEC-v1',
                action: binding(),
                components: [{ type: 'external-permit', evidence: { signed: false } }],
                requirement: 'external-permit',
            },
        },
        requirement: requirement(),
        program: program(),
    });
    assert.equal(aecResult.reason, 'aec_verification_failed');
});
function authorizationBinding(overrides = {}) {
    return {
        instance_id: 'tpi_adapter_test',
        operation_id: 'provider_operation_123',
        program_digest: HASH('3'),
        root_caid: ROOT_CAID,
        action_digest: HASH('4'),
        terminal_stage_receipt_digests: [HASH('5')],
        consequence_mode: 'receipt-program',
        capability_template_digest: HASH('6'),
        escrow_profile_digest: null,
        ...overrides,
    };
}
function actionEscrowAuthorizationBinding(overrides = {}) {
    return authorizationBinding({
        consequence_mode: 'action-escrow',
        capability_template_digest: null,
        escrow_profile_digest: HASH('7'),
        ...overrides,
    });
}
test('Receipt Program terminal verifier binds program, operation, action, CAID, and consequence digest', async () => {
    const certificate = {
        program: {
            program_id: 'rp_release_v1',
            operation_id: 'provider_operation_123',
            action_digest: HASH('4'),
            caid: ROOT_CAID,
            observed_action: { action_type: 'payment.release' },
        },
        outcome: 'executed',
    };
    let verifierOptions;
    const terminal = createReceiptProgramTerminalOutcomeVerifier({
        programId: 'rp_release_v1',
        trustedCertificateKeys: { operator: 'server-owned-key' },
        expectedContext: { issuer: 'gate', key_id: 'operator' },
        resolveCaid: () => ROOT_CAID,
        verifyReceiptProgramCertificate: (_certificate, options) => {
            verifierOptions = options;
            return { ok: true, outcome: 'executed', program_digest: HASH('8') };
        },
    });
    const result = await terminal({ evidence: { certificate }, authorizationBinding: authorizationBinding() });
    assert.equal(result.valid, true);
    assert.equal(result.outcome, 'executed');
    assert.match(result.evidence_digest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(verifierOptions.trustedCertificateKeys, { operator: 'server-owned-key' });
    assert.deepEqual(verifierOptions.expectedContext, { issuer: 'gate', key_id: 'operator' });
    const executionVerifier = createReceiptProgramExecutionOutcomeVerifier({
        programId: 'rp_release_v1',
        trustedCertificateKeys: { operator: 'server-owned-key' },
        expectedContext: { issuer: 'gate', key_id: 'operator' },
        resolveCaid: () => ROOT_CAID,
        verifyReceiptProgramCertificate: () => ({ ok: true, outcome: 'executed', program_digest: HASH('8') }),
    });
    assert.equal(await executionVerifier({
        outcome: result.outcome,
        evidenceDigest: result.evidence_digest,
        evidence: { certificate },
        authorizationBinding: authorizationBinding(),
    }), true);
    assert.equal(await executionVerifier({
        outcome: result.outcome,
        evidenceDigest: result.evidence_digest,
        evidence: { certificate },
        authorizationBinding: authorizationBinding({ action_digest: HASH('9') }),
    }), false);
});
test('Receipt Program explicitly refuses Action Escrow nesting and runtime trust injection', async () => {
    let called = false;
    const terminal = createReceiptProgramTerminalOutcomeVerifier({
        programId: 'rp_release_v1',
        trustedCertificateKeys: { operator: 'server-owned-key' },
        expectedContext: { issuer: 'gate', key_id: 'operator' },
        resolveCaid: () => ROOT_CAID,
        verifyReceiptProgramCertificate: () => { called = true; return { ok: true, outcome: 'executed' }; },
    });
    const certificate = {
        program: {
            program_id: 'rp_release_v1', operation_id: 'provider_operation_123',
            action_digest: HASH('4'), caid: ROOT_CAID,
            observed_action: { '@version': 'EP-ACTION-ESCROW-STATE-v1' },
        },
        outcome: 'executed',
    };
    assert.equal((await terminal({
        evidence: { certificate }, authorizationBinding: authorizationBinding(),
    })).reason, 'action_escrow_receipt_program_nesting_refused');
    assert.equal(called, false);
    assert.equal((await terminal({
        evidence: { certificate: { ...certificate, program: { ...certificate.program, observed_action: {} } }, trustedCertificateKeys: { operator: 'attacker' } },
        authorizationBinding: authorizationBinding(),
    })).reason, 'receipt_program_evidence_schema_invalid');
});
test('Action Escrow maps only authenticated terminal states and binds the claim authorization', async () => {
    const packageDigest = HASH('8');
    const releaseActionDigest = HASH('4');
    const profileDigest = HASH('7');
    const pkg = { agreement_id: 'agreement_1', stage: 'released', package_digest: packageDigest };
    let verifierOptions;
    const terminal = createActionEscrowTerminalOutcomeVerifier({
        agreementId: 'agreement_1',
        releaseActionDigest,
        profileDigest,
        componentVerifiers: {
            verifyBinding: () => true,
            verifyProfile: () => true,
            verifyState: () => true,
            verifyRelease: () => true,
        },
        now: NOW,
        verifyActionEscrowEvidencePackage: async (_pkg, options) => {
            verifierOptions = options;
            return {
                valid: true,
                package_digest: packageDigest,
                agreement_id: 'agreement_1',
                action_digest: releaseActionDigest,
                profile_digest: profileDigest,
            };
        },
    });
    const result = await terminal({
        evidence: { package: pkg, document_bytes: new Uint8Array([1, 2, 3]) },
        authorizationBinding: actionEscrowAuthorizationBinding(),
    });
    assert.deepEqual(result, {
        valid: true, reason: null, outcome: 'executed', evidence_digest: packageDigest,
    });
    assert.equal(verifierOptions.expectedAgreementId, 'agreement_1');
    assert.equal(verifierOptions.verifyBinding, terminal.options.componentVerifiers.verifyBinding);
    assert.deepEqual([...verifierOptions.documentBytes], [1, 2, 3]);
    const executionVerifier = createActionEscrowExecutionOutcomeVerifier({
        agreementId: 'agreement_1', releaseActionDigest, profileDigest,
        componentVerifiers: {},
        verifyActionEscrowEvidencePackage: async () => ({
            valid: true, package_digest: packageDigest, agreement_id: 'agreement_1',
            action_digest: releaseActionDigest, profile_digest: profileDigest,
        }),
    });
    assert.equal(await executionVerifier({
        outcome: 'executed', evidenceDigest: packageDigest,
        evidence: { package: pkg, document_bytes: new Uint8Array([1]) },
        authorizationBinding: actionEscrowAuthorizationBinding(),
    }), true);
    assert.equal(await executionVerifier({
        outcome: 'executed', evidenceDigest: packageDigest,
        evidence: { package: pkg, document_bytes: new Uint8Array([1]) },
        authorizationBinding: actionEscrowAuthorizationBinding({ escrow_profile_digest: HASH('0') }),
    }), false);
    assert.equal((await terminal({
        evidence: { package: { ...pkg, stage: 'funded' }, document_bytes: new Uint8Array([1]) },
        authorizationBinding: actionEscrowAuthorizationBinding(),
    })).reason, 'action_escrow_state_not_terminal');
    assert.equal((await terminal({
        evidence: {
            package: pkg,
            document_bytes: new Uint8Array([1]),
            verifyRelease: () => true,
        },
        authorizationBinding: actionEscrowAuthorizationBinding(),
    })).reason, 'action_escrow_evidence_schema_invalid');
});
test('terminal adapters refuse mixed or wrong consequence ownership before verification', async () => {
    let receiptCalled = false;
    const receipt = createReceiptProgramTerminalOutcomeVerifier({
        programId: 'rp_release_v1',
        trustedCertificateKeys: { operator: 'server-owned-key' },
        expectedContext: { issuer: 'gate', key_id: 'operator' },
        resolveCaid: () => ROOT_CAID,
        verifyReceiptProgramCertificate: () => {
            receiptCalled = true;
            return { ok: true, outcome: 'executed' };
        },
    });
    const certificate = {
        program: {
            program_id: 'rp_release_v1', operation_id: 'provider_operation_123',
            action_digest: HASH('4'), caid: ROOT_CAID, observed_action: {},
        },
        outcome: 'executed',
    };
    assert.equal((await receipt({
        evidence: { certificate },
        authorizationBinding: authorizationBinding({ escrow_profile_digest: HASH('7') }),
    })).reason, 'consequence_ownership_invalid');
    assert.equal(receiptCalled, false);
    let escrowCalled = false;
    const escrow = createActionEscrowTerminalOutcomeVerifier({
        agreementId: 'agreement_1', releaseActionDigest: HASH('4'), profileDigest: HASH('7'),
        componentVerifiers: {},
        verifyActionEscrowEvidencePackage: async () => {
            escrowCalled = true;
            return { valid: true };
        },
    });
    assert.equal((await escrow({
        evidence: {
            package: { agreement_id: 'agreement_1', stage: 'released', package_digest: HASH('8') },
            document_bytes: new Uint8Array([1]),
        },
        authorizationBinding: actionEscrowAuthorizationBinding({ capability_template_digest: HASH('6') }),
    })).reason, 'consequence_ownership_invalid');
    assert.equal(escrowCalled, false);
});
