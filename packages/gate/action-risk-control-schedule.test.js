// SPDX-License-Identifier: Apache-2.0
// Generated from action-risk-control-schedule.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY, ACTION_RISK_CONTROL_SCHEDULE_VERSION, ACTION_RISK_DIVERGENT_HANDLING, ACTION_RISK_INDETERMINATE_HANDLING, ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY, actionRiskControlScheduleDigest, actionRiskHybridTrustPinDigest, actionRiskQualificationStatusDigest, evaluateActionRiskControlSchedule, signActionRiskControlSchedule, signActionRiskQualificationStatus, } from './action-risk-control-schedule.js';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const D = (character) => `sha256:${character.repeat(64)}`;
const NOW = '2026-09-04T12:04:00Z';
const SCHEDULE_ID = 'schedule:finance-payment-release:v1';
const SCHEDULE_ISSUER = 'issuer:risk-control-committee';
const SCHEDULE_KEY_ID = 'key:schedule:1';
const STATUS_AUTHORITY = 'authority:qualification:acme';
const STATUS_KEY_ID = 'key:qualification:1';
const RELYING_PARTY = 'enterprise:acme';
const TENANT = 'tenant:acme';
function keyMaterial(seed, issuerId, keyId) {
    const ed = generateKeyPairSync('ed25519');
    const pq = ml_dsa65.keygen(new Uint8Array(32).fill(seed));
    const pin = {
        issuer_id: issuerId,
        public_key: ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
        pq_public_key: Buffer.from(pq.publicKey).toString('base64url'),
    };
    return {
        signer: {
            issuer_id: issuerId,
            key_id: keyId,
            private_key: ed.privateKey,
            pq_private_key: Buffer.from(pq.secretKey).toString('base64url'),
        },
        pins: { [keyId]: pin },
        pin,
    };
}
const scheduleKeys = keyMaterial(9, SCHEDULE_ISSUER, SCHEDULE_KEY_ID);
const statusKeys = keyMaterial(17, STATUS_AUTHORITY, STATUS_KEY_ID);
function scheduleSource() {
    return {
        schedule_id: SCHEDULE_ID,
        relying_party_id: RELYING_PARTY,
        tenant_id: TENANT,
        issued_at: '2026-09-04T12:00:00Z',
        valid_from: '2026-09-04T12:00:00Z',
        expires_at: '2026-10-04T12:00:00Z',
        action: {
            action_class: 'payment.release',
            caid_profile_id: 'caid-profile:payment-release:1',
            caid_profile_digest: D('1'),
        },
        provider_binding: {
            provider_id: 'provider:stripe',
            account_id: 'account:acme-production',
            environment: 'production',
            adapter_digest: D('2'),
        },
        qualification: {
            requirements_digest: D('3'),
            status_authority_id: STATUS_AUTHORITY,
            status_key_id: STATUS_KEY_ID,
            min_sequence: 7,
            max_observation_age_sec: 300,
        },
        control_bindings: {
            aeb_digest: D('4'),
            aec_digest: D('5'),
            local_policy_digest: D('6'),
        },
        complete_mediation: {
            surface_inventory_digest: D('7'),
            refusal_probe_evidence_digest: D('8'),
        },
        loss_allocation: {
            program_digest: D('9'),
        },
        open_exposure: {
            program_id: 'oel:finance:1',
            program_digest: D('a'),
            currency: 'USD',
            per_action_ceiling_minor: '1000000',
            aggregate_ceiling_minor: '5000000',
            reconciler_id: 'reconciler:finance-independent',
            reconciliation_deadline_sec: 3600,
        },
        outcome_binding: {
            required_sources: [
                { role: 'independent_observer', source_class: 'bank-settlement-feed' },
                { role: 'system_of_record', source_class: 'erp-payment-ledger' },
            ],
            quorum: 2,
            observation_window: {
                opens_before_provider_entry_sec: 0,
                closes_after_provider_entry_sec: 3600,
                max_observation_age_sec: 300,
            },
            require_control_domain_independence: true,
        },
        handling: {
            indeterminate: ACTION_RISK_INDETERMINATE_HANDLING,
            divergent: ACTION_RISK_DIVERGENT_HANDLING,
        },
        trust_pin_references: [
            {
                purpose: 'QUALIFICATION_STATUS',
                authority_id: STATUS_AUTHORITY,
                key_id: STATUS_KEY_ID,
                key_digest: actionRiskHybridTrustPinDigest(STATUS_KEY_ID, statusKeys.pin),
            },
            {
                purpose: 'SCHEDULE_ISSUER',
                authority_id: SCHEDULE_ISSUER,
                key_id: SCHEDULE_KEY_ID,
                key_digest: actionRiskHybridTrustPinDigest(SCHEDULE_KEY_ID, scheduleKeys.pin),
            },
        ],
        claim_boundary: ACTION_RISK_CONTROL_SCHEDULE_CLAIM_BOUNDARY,
    };
}
function observedControls(source = scheduleSource()) {
    return {
        action: structuredClone(source.action),
        provider_binding: structuredClone(source.provider_binding),
        qualification_requirements_digest: source.qualification.requirements_digest,
        control_bindings: structuredClone(source.control_bindings),
        complete_mediation: structuredClone(source.complete_mediation),
        loss_allocation: structuredClone(source.loss_allocation),
        open_exposure: structuredClone(source.open_exposure),
        outcome_binding: structuredClone(source.outcome_binding),
        handling: structuredClone(source.handling),
        trust_pin_references: structuredClone(source.trust_pin_references),
    };
}
const scheduleArtifact = await signActionRiskControlSchedule(scheduleSource(), scheduleKeys.signer);
async function qualificationStatus(schedule = scheduleArtifact, overrides = {}, keys = statusKeys) {
    return signActionRiskQualificationStatus({
        status_id: 'qualification-status:acme:7',
        schedule_id: SCHEDULE_ID,
        schedule_digest: actionRiskControlScheduleDigest(schedule),
        tenant_id: TENANT,
        requirements_digest: D('3'),
        sequence: 7,
        observed_at: '2026-09-04T12:03:00Z',
        outcome: 'ELIGIBLE',
        evidence_digest: D('d'),
        claim_boundary: ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY,
        ...overrides,
    }, keys.signer);
}
function qualificationStatusHead(status, overrides = {}) {
    return {
        schedule_id: status.schedule_id,
        schedule_digest: status.schedule_digest,
        tenant_id: status.tenant_id,
        status_authority_id: status.issuer.id,
        status_key_id: status.issuer.key_id,
        sequence: status.sequence,
        status_digest: actionRiskQualificationStatusDigest(status),
        recorded_at: '2026-09-04T12:03:30Z',
        ...overrides,
    };
}
async function evaluationOptions(overrides = {}) {
    const status = await qualificationStatus();
    return {
        trusted_schedule_keys: scheduleKeys.pins,
        trusted_status_keys: statusKeys.pins,
        expected_schedule_id: SCHEDULE_ID,
        expected_issuer_id: SCHEDULE_ISSUER,
        expected_relying_party_id: RELYING_PARTY,
        expected_tenant_id: TENANT,
        observed_controls: observedControls(),
        qualification_status: status,
        qualification_status_head: qualificationStatusHead(status),
        now: NOW,
        ...overrides,
    };
}
function mutable(value) {
    return JSON.parse(JSON.stringify(value));
}
test('real Ed25519 and ML-DSA-65 schedule plus independent current status evaluate ELIGIBLE', async () => {
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions());
    assert.equal(scheduleArtifact['@version'], ACTION_RISK_CONTROL_SCHEDULE_VERSION);
    assert.deepEqual(scheduleArtifact.proof.required_algorithms, ['Ed25519', 'ML-DSA-65']);
    assert.equal(result.outcome, 'ELIGIBLE', result.reason);
    assert.equal(result.reason, 'technical_requirements_observed');
    assert.equal(result.schedule_verified, true);
    assert.equal(result.qualification_status_verified, true);
    assert.equal(result.authorizes_action, false);
    assert.equal(result.establishes_policy, false);
    assert.equal(result.establishes_coverage, false);
    assert.equal(result.sets_premium, false);
    assert.equal(result.allocates_liability, false);
    assert.equal(result.proves_provider_effect, false);
    assert.equal(Object.isFrozen(result), true);
});
test('published JSON Schema accepts the signed artifact and refuses unknown members', () => {
    const schema = JSON.parse(readFileSync(new URL('../../public/schemas/ep-action-risk-control-schedule.schema.json', import.meta.url), 'utf8'));
    const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
    const validate = ajv.compile(schema);
    assert.equal(validate(scheduleArtifact), true, JSON.stringify(validate.errors));
    const unknown = mutable(scheduleArtifact);
    unknown.provider_binding.shadow_account = 'attacker';
    assert.equal(validate(unknown), false);
    const missingLegKeyId = mutable(scheduleArtifact);
    delete missingLegKeyId.proof.signatures[0].key_id;
    assert.equal(validate(missingLegKeyId), false);
    const decorativePin = mutable(scheduleArtifact);
    decorativePin.trust_pin_references.unshift({
        purpose: 'AEB',
        authority_id: 'authority:aeb:acme',
        key_id: 'key:aeb:1',
        key_digest: D('b'),
    });
    assert.equal(validate(decorativePin), false);
});
test('published qualification-status JSON Schema matches the signed artifact shape', async () => {
    const schema = JSON.parse(readFileSync(new URL('../../public/schemas/ep-action-risk-qualification-status.schema.json', import.meta.url), 'utf8'));
    const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false });
    const validate = ajv.compile(schema);
    const status = await qualificationStatus();
    assert.equal(validate(status), true, JSON.stringify(validate.errors));
    const unknown = mutable(status);
    unknown.coverage = true;
    assert.equal(validate(unknown), false);
    const missingLeg = mutable(status);
    missingLeg.proof.signatures.pop();
    assert.equal(validate(missingLeg), false);
});
test('tampering any signed schedule field fails before control evaluation', async () => {
    const tampered = mutable(scheduleArtifact);
    tampered.provider_binding.account_id = 'account:attacker';
    const result = await evaluateActionRiskControlSchedule(tampered, await evaluationOptions());
    assert.equal(result.outcome, 'NOT_ELIGIBLE');
    assert.equal(result.reason, 'digest_mismatch');
    assert.equal(result.schedule_verified, false);
});
test('removing either hybrid signature never leaves a valid schedule', async () => {
    for (const kept of ['Ed25519', 'ML-DSA-65']) {
        const stripped = mutable(scheduleArtifact);
        stripped.proof.signatures = stripped.proof.signatures.filter((signature) => signature.alg === kept);
        const result = await evaluateActionRiskControlSchedule(stripped, await evaluationOptions());
        assert.equal(result.outcome, 'NOT_ELIGIBLE');
        assert.equal(result.reason, 'signature_set_incomplete');
    }
});
test('every schedule signature key id is required and must equal proof and issuer key ids', async () => {
    const missing = mutable(scheduleArtifact);
    delete missing.proof.signatures[0].key_id;
    const missingResult = await evaluateActionRiskControlSchedule(missing, await evaluationOptions());
    assert.equal(missingResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(missingResult.reason, 'signature_key_id_required');
    const mismatch = mutable(scheduleArtifact);
    mismatch.proof.signatures[1].key_id = 'key:attacker';
    const mismatchResult = await evaluateActionRiskControlSchedule(mismatch, await evaluationOptions());
    assert.equal(mismatchResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(mismatchResult.reason, 'signature_key_id_mismatch');
    const reordered = mutable(scheduleArtifact);
    reordered.proof.signatures.reverse();
    const reorderedResult = await evaluateActionRiskControlSchedule(reordered, await evaluationOptions());
    assert.equal(reorderedResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(reorderedResult.reason, 'signature_set_invalid');
});
test('wrong or absent externally supplied schedule pins fail closed', async () => {
    const wrong = keyMaterial(31, SCHEDULE_ISSUER, SCHEDULE_KEY_ID);
    const wrongResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ trusted_schedule_keys: wrong.pins }));
    assert.equal(wrongResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(wrongResult.reason, 'signature_invalid');
    const absentResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ trusted_schedule_keys: undefined }));
    assert.equal(absentResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(absentResult.reason, 'issuer_untrusted');
});
test('a signed trust reference cannot substitute for the caller trust root', async () => {
    const source = scheduleSource();
    source.trust_pin_references = source.trust_pin_references.map((reference) => (reference.purpose === 'SCHEDULE_ISSUER' ? { ...reference, key_digest: D('e') } : reference));
    const artifact = await signActionRiskControlSchedule(source, scheduleKeys.signer);
    const result = await evaluateActionRiskControlSchedule(artifact, {
        ...(await evaluationOptions()),
        qualification_status: undefined,
        observed_controls: observedControls(source),
    });
    assert.equal(result.outcome, 'NOT_ELIGIBLE');
    assert.equal(result.reason, 'schedule_trust_pin_reference_mismatch');
});
test('all schedule context identities are required and exact', async () => {
    const cases = [
        ['missing', { expected_schedule_id: undefined }, 'context_binding_required'],
        ['schedule', { expected_schedule_id: 'schedule:other' }, 'schedule_id_mismatch'],
        ['issuer', { expected_issuer_id: 'issuer:other' }, 'issuer_id_mismatch'],
        ['relying party', { expected_relying_party_id: 'enterprise:other' }, 'relying_party_id_mismatch'],
        ['tenant', { expected_tenant_id: 'tenant:other' }, 'tenant_id_mismatch'],
    ];
    for (const [label, override, reason] of cases) {
        const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions(override));
        assert.equal(result.outcome, 'NOT_ELIGIBLE', label);
        assert.equal(result.reason, reason, label);
    }
});
test('not-yet-active and expired schedules are NOT_ELIGIBLE', async () => {
    const before = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ now: '2026-09-04T11:59:59Z' }));
    assert.equal(before.outcome, 'NOT_ELIGIBLE');
    assert.equal(before.reason, 'schedule_not_yet_issued');
    const expired = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ now: '2026-10-04T12:00:00Z' }));
    assert.equal(expired.outcome, 'NOT_ELIGIBLE');
    assert.equal(expired.reason, 'schedule_expired');
});
test('every control group is substitution-resistant', async () => {
    const cases = [
        ['action and CAID profile', (o) => { o.action.caid_profile_digest = D('e'); }, 'action_binding_mismatch'],
        ['provider account', (o) => { o.provider_binding.account_id = 'account:attacker'; }, 'provider_binding_mismatch'],
        ['provider environment', (o) => { o.provider_binding.environment = 'staging'; }, 'provider_binding_mismatch'],
        ['provider adapter', (o) => { o.provider_binding.adapter_digest = D('e'); }, 'provider_binding_mismatch'],
        ['qualification requirements', (o) => { o.qualification_requirements_digest = D('e'); }, 'qualification_requirements_mismatch'],
        ['AEB AEC local policy', (o) => { o.control_bindings.aeb_digest = D('e'); }, 'control_bindings_mismatch'],
        ['surface inventory', (o) => { o.complete_mediation.surface_inventory_digest = D('e'); }, 'complete_mediation_mismatch'],
        ['refusal probes', (o) => { o.complete_mediation.refusal_probe_evidence_digest = D('e'); }, 'complete_mediation_mismatch'],
        ['loss allocation', (o) => { o.loss_allocation.program_digest = D('e'); }, 'loss_allocation_mismatch'],
        ['OEL ceiling', (o) => { o.open_exposure.per_action_ceiling_minor = '999999'; }, 'open_exposure_mismatch'],
        ['OEL reconciler', (o) => { o.open_exposure.reconciler_id = 'reconciler:attacker'; }, 'open_exposure_mismatch'],
        ['Outcome Binding source class', (o) => { o.outcome_binding.required_sources[0].source_class = 'untrusted-feed'; }, 'outcome_binding_mismatch'],
        ['Outcome Binding quorum and windows', (o) => { o.outcome_binding.observation_window.max_observation_age_sec = 299; }, 'outcome_binding_mismatch'],
        ['trust pin reference', (o) => { o.trust_pin_references[0].key_digest = D('e'); }, 'trust_pin_references_mismatch'],
    ];
    for (const [label, mutate, reason] of cases) {
        const observed = observedControls();
        mutate(observed);
        const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ observed_controls: observed }));
        assert.equal(result.outcome, 'NOT_ELIGIBLE', label);
        assert.equal(result.reason, reason, label);
    }
});
test('unknown observed fields and invalid control-domain independence fail closed', async () => {
    const unknown = observedControls();
    unknown.provider_binding.policy = 'attacker-controlled';
    const unknownResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ observed_controls: unknown }));
    assert.equal(unknownResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(unknownResult.reason, 'control_observation_invalid');
    const collapsed = observedControls();
    collapsed.outcome_binding.require_control_domain_independence = false;
    const collapsedResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ observed_controls: collapsed }));
    assert.equal(collapsedResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(collapsedResult.reason, 'control_observation_invalid');
});
test('missing qualification evidence is INDETERMINATE and supplies the required handling', async () => {
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: undefined }));
    assert.equal(result.outcome, 'INDETERMINATE');
    assert.equal(result.reason, 'qualification_status_required');
    assert.equal(result.required_handling, ACTION_RISK_INDETERMINATE_HANDLING);
    assert.equal(result.authorizes_action, false);
});
test('a verified status without relying-party last-seen head state is INDETERMINATE', async () => {
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status_head: undefined }));
    assert.equal(result.outcome, 'INDETERMINATE');
    assert.equal(result.reason, 'qualification_status_head_required');
    assert.equal(result.required_handling, ACTION_RISK_INDETERMINATE_HANDLING);
    assert.equal(result.authorizes_action, false);
});
test('qualification status trust roots are external, pinned, and digest-bound', async () => {
    const absent = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ trusted_status_keys: undefined }));
    assert.equal(absent.outcome, 'NOT_ELIGIBLE');
    assert.equal(absent.reason, 'qualification_status_trust_pin_required');
    const wrong = keyMaterial(41, STATUS_AUTHORITY, STATUS_KEY_ID);
    const wrongResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ trusted_status_keys: wrong.pins }));
    assert.equal(wrongResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(wrongResult.reason, 'qualification_status_trust_pin_reference_mismatch');
});
test('a tampered or wrong-authority qualification status is NOT_ELIGIBLE', async () => {
    const status = await qualificationStatus();
    const tampered = mutable(status);
    tampered.sequence = 8;
    const tamperedResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: tampered }));
    assert.equal(tamperedResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(tamperedResult.reason, 'digest_mismatch');
    const alternate = keyMaterial(43, 'authority:qualification:other', 'key:qualification:other');
    const alternateStatus = await qualificationStatus(scheduleArtifact, {}, alternate);
    // The alternate status verifies under its own external key, then fails the
    // authority and key identity committed by the schedule.
    const alternateResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({
        qualification_status: alternateStatus,
        trusted_status_keys: { ...statusKeys.pins, ...alternate.pins },
    }));
    assert.equal(alternateResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(alternateResult.reason, 'qualification_status_authority_mismatch');
});
test('qualification status signature legs also require the proof and issuer key id', async () => {
    const status = await qualificationStatus();
    const missing = mutable(status);
    delete missing.proof.signatures[1].key_id;
    const missingResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: missing }));
    assert.equal(missingResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(missingResult.reason, 'signature_key_id_required');
    const mismatch = mutable(status);
    mismatch.proof.signatures[0].key_id = 'key:attacker';
    const mismatchResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: mismatch }));
    assert.equal(mismatchResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(mismatchResult.reason, 'signature_key_id_mismatch');
});
test('qualification status schedule, tenant, and requirements substitutions are refused', async () => {
    const cases = [
        ['schedule', { schedule_id: 'schedule:other' }, 'qualification_status_schedule_mismatch'],
        ['tenant', { tenant_id: 'tenant:other' }, 'qualification_status_tenant_mismatch'],
        ['requirements', { requirements_digest: D('e') }, 'qualification_status_requirements_mismatch'],
    ];
    for (const [label, overrides, reason] of cases) {
        const status = await qualificationStatus(scheduleArtifact, overrides);
        const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: status }));
        assert.equal(result.outcome, 'NOT_ELIGIBLE', label);
        assert.equal(result.reason, reason, label);
    }
});
test('old sequence and stale observation are INDETERMINATE, never eligible', async () => {
    const oldSequence = await qualificationStatus(scheduleArtifact, { sequence: 6 });
    const sequenceResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: oldSequence }));
    assert.equal(sequenceResult.outcome, 'INDETERMINATE');
    assert.equal(sequenceResult.reason, 'qualification_status_sequence_too_old');
    const stale = await qualificationStatus(scheduleArtifact, { observed_at: '2026-09-04T11:58:59Z' });
    const staleResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({
        qualification_status: stale,
        qualification_status_head: qualificationStatusHead(stale),
    }));
    assert.equal(staleResult.outcome, 'INDETERMINATE');
    assert.equal(staleResult.reason, 'qualification_status_stale');
    assert.equal(staleResult.required_handling, ACTION_RISK_INDETERMINATE_HANDLING);
});
test('future qualification observations are NOT_ELIGIBLE', async () => {
    const future = await qualificationStatus(scheduleArtifact, {
        sequence: 8,
        observed_at: '2026-09-04T12:04:01Z',
    });
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: future }));
    assert.equal(result.outcome, 'NOT_ELIGIBLE');
    assert.equal(result.reason, 'qualification_status_from_future');
});
test('the qualification authority can report NOT_ELIGIBLE or INDETERMINATE without authorizing', async () => {
    for (const outcome of ['NOT_ELIGIBLE', 'INDETERMINATE']) {
        const status = await qualificationStatus(scheduleArtifact, { outcome });
        const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({
            qualification_status: status,
            qualification_status_head: qualificationStatusHead(status),
        }));
        assert.equal(result.outcome, outcome);
        assert.equal(result.authorizes_action, false);
        if (outcome === 'INDETERMINATE') {
            assert.equal(result.required_handling, ACTION_RISK_INDETERMINATE_HANDLING);
        }
    }
});
test('ROLLBACK: an older but still-fresh ELIGIBLE status cannot replay after a newer head', async () => {
    const olderEligible = await qualificationStatus(scheduleArtifact, {
        status_id: 'qualification-status:acme:7',
        sequence: 7,
        observed_at: '2026-09-04T12:03:00Z',
        outcome: 'ELIGIBLE',
    });
    const newerNotEligible = await qualificationStatus(scheduleArtifact, {
        status_id: 'qualification-status:acme:8',
        sequence: 8,
        observed_at: '2026-09-04T12:03:30Z',
        outcome: 'NOT_ELIGIBLE',
    });
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({
        qualification_status: olderEligible,
        qualification_status_head: qualificationStatusHead(newerNotEligible, {
            recorded_at: '2026-09-04T12:03:45Z',
        }),
    }));
    assert.equal(result.outcome, 'NOT_ELIGIBLE');
    assert.equal(result.reason, 'qualification_status_rollback_detected');
    assert.equal(result.qualification_status_head_sequence, 8);
    assert.equal(result.authorizes_action, false);
});
test('a genuinely newer signed status may advance beyond the relying-party head', async () => {
    const prior = await qualificationStatus(scheduleArtifact, {
        status_id: 'qualification-status:acme:7',
        sequence: 7,
    });
    const newer = await qualificationStatus(scheduleArtifact, {
        status_id: 'qualification-status:acme:8',
        sequence: 8,
        observed_at: '2026-09-04T12:03:45Z',
    });
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({
        qualification_status: newer,
        qualification_status_head: qualificationStatusHead(prior),
    }));
    assert.equal(result.outcome, 'ELIGIBLE', result.reason);
    assert.equal(result.qualification_status_head_sequence, 7);
});
test('same-sequence status equivocation cannot replace the digest stored in the head', async () => {
    const accepted = await qualificationStatus(scheduleArtifact, {
        status_id: 'qualification-status:acme:7:accepted',
        sequence: 7,
        outcome: 'ELIGIBLE',
    });
    const conflicting = await qualificationStatus(scheduleArtifact, {
        status_id: 'qualification-status:acme:7:conflicting',
        sequence: 7,
        outcome: 'NOT_ELIGIBLE',
    });
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({
        qualification_status: conflicting,
        qualification_status_head: qualificationStatusHead(accepted),
    }));
    assert.equal(result.outcome, 'NOT_ELIGIBLE');
    assert.equal(result.reason, 'qualification_status_head_digest_mismatch');
});
test('qualification head schedule, tenant, authority, time, and shape are exact', async () => {
    const status = await qualificationStatus();
    const cases = [
        ['schedule id', { schedule_id: 'schedule:other' }, 'qualification_status_head_schedule_mismatch'],
        ['schedule digest', { schedule_digest: D('e') }, 'qualification_status_head_schedule_mismatch'],
        ['tenant', { tenant_id: 'tenant:other' }, 'qualification_status_head_tenant_mismatch'],
        ['authority', { status_authority_id: 'authority:other' }, 'qualification_status_head_authority_mismatch'],
        ['key', { status_key_id: 'key:other' }, 'qualification_status_head_authority_mismatch'],
        ['future', { recorded_at: '2026-09-04T12:04:01Z' }, 'qualification_status_head_from_future'],
    ];
    for (const [label, override, reason] of cases) {
        const result = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({
            qualification_status: status,
            qualification_status_head: qualificationStatusHead(status, override),
        }));
        assert.equal(result.outcome, 'NOT_ELIGIBLE', label);
        assert.equal(result.reason, reason, label);
    }
    const unknown = qualificationStatusHead(status);
    unknown.untrusted = true;
    const unknownResult = await evaluateActionRiskControlSchedule(scheduleArtifact, await evaluationOptions({ qualification_status: status, qualification_status_head: unknown }));
    assert.equal(unknownResult.outcome, 'NOT_ELIGIBLE');
    assert.equal(unknownResult.reason, 'qualification_status_head_invalid');
});
test('signing refuses unknown fields, unsafe ceilings, unsorted sources, and self-inconsistent trust references', async () => {
    const unknown = scheduleSource();
    unknown.coverage = { bound: true };
    await assert.rejects(signActionRiskControlSchedule(unknown, scheduleKeys.signer), /closed, bounded v1 object/);
    const unsafe = scheduleSource();
    unsafe.open_exposure.per_action_ceiling_minor = '6000000';
    await assert.rejects(signActionRiskControlSchedule(unsafe, scheduleKeys.signer), /closed, bounded v1 object/);
    const unsorted = scheduleSource();
    unsorted.outcome_binding.required_sources.reverse();
    await assert.rejects(signActionRiskControlSchedule(unsorted, scheduleKeys.signer), /closed, bounded v1 object/);
    const wrongReference = scheduleSource();
    wrongReference.trust_pin_references = wrongReference.trust_pin_references.map((reference) => (reference.purpose === 'QUALIFICATION_STATUS'
        ? { ...reference, authority_id: 'authority:qualification:other' }
        : reference));
    await assert.rejects(signActionRiskControlSchedule(wrongReference, scheduleKeys.signer), /qualification status reference must match/);
    const decorativeReference = scheduleSource();
    decorativeReference.trust_pin_references.unshift({
        purpose: 'OUTCOME_SOURCE',
        authority_id: 'authority:bank-feed',
        key_id: 'key:bank-feed:1',
        key_digest: D('c'),
    });
    await assert.rejects(signActionRiskControlSchedule(decorativeReference, scheduleKeys.signer), /closed, bounded v1 object/);
});
test('qualification status is closed and uses only the three evaluation outcomes', async () => {
    const unknown = {
        status_id: 'qualification-status:acme:8',
        schedule_id: SCHEDULE_ID,
        schedule_digest: actionRiskControlScheduleDigest(scheduleArtifact),
        tenant_id: TENANT,
        requirements_digest: D('3'),
        sequence: 8,
        observed_at: '2026-09-04T12:03:00Z',
        outcome: 'ELIGIBLE',
        evidence_digest: D('d'),
        claim_boundary: ACTION_RISK_QUALIFICATION_STATUS_CLAIM_BOUNDARY,
        policy_number: 'not-allowed',
    };
    await assert.rejects(signActionRiskQualificationStatus(unknown, statusKeys.signer), /closed, bounded v1 object/);
    const invalidOutcome = { ...unknown, policy_number: undefined, outcome: 'COVERED' };
    delete invalidOutcome.policy_number;
    await assert.rejects(signActionRiskQualificationStatus(invalidOutcome, statusKeys.signer), /closed, bounded v1 object/);
});
test('absence of the ML-DSA verifier is INDETERMINATE and never a classical-only pass', async () => {
    const result = await evaluateActionRiskControlSchedule(scheduleArtifact, { ...(await evaluationOptions()), mldsaBackendLoader: async () => null });
    assert.equal(result.outcome, 'INDETERMINATE');
    assert.equal(result.reason, 'pq_backend_unavailable');
    assert.equal(result.schedule_verified, false);
    assert.equal(result.authorizes_action, false);
});
