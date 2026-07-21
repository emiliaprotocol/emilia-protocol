// SPDX-License-Identifier: Apache-2.0
// Generated from lib.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeCaid, verifyCaid } from '../../caid/impl/js/caid.mjs';
import { assembleAuthorizationReceipt } from '../../packages/issue/index.js';
import { createAppleAppAttestVerifier, createGovernmentMobileController, createMobileCeremonyService, createMobileExecutionRecord, createMobileRelianceProfile, hashCanonical, mobileProfileHash, verifyMobileExecutionRecord, } from '../../packages/mobile/index.js';
import { projectMobileAction } from '../../packages/mobile/presentation.js';
import { createAtomicEvidenceLog, createMemoryAtomicEvidenceBackend, verifyEvidenceRecord, } from '../../packages/gate/evidence.js';
import { createDurableChallengeStore } from '../../packages/gate/challenge-store.js';
import { createMemoryBackend } from '../../packages/gate/store.js';
import { canonicalize, verifyTrustReceipt } from '../../packages/verify/index.js';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFINITIONS = JSON.parse(fs.readFileSync(path.resolve(HERE, '../../caid/registry/action-types.json'), 'utf8')).types;
export const EVIDENCE_VERSION = 'EP-REGULATORY-MOBILE-EVIDENCE-v1';
export const TRUST_BUNDLE_VERSION = 'EP-REGULATORY-MOBILE-TRUST-BUNDLE-v1';
export const RP_ID = 'approve.sandbox.example';
export const ORIGIN = `https://${RP_ID}`;
export const APP_ID = 'org.example.regulated-review';
export const APPROVER_ID = 'ep:approver:synthetic-reviewer-001';
export const DEVICE_KEY_ID = 'ep:key:synthetic-mobile-reviewer-001';
export const ATTESTATION_KEY_ID = 'appattest:synthetic-key-001';
export const POLICY_ID = 'ep:policy:synthetic-human-review@v1';
export const ACTION_REFERENCE = 'synthetic-case:prior-auth:0001';
export const ISSUED_AT = '2026-07-15T16:00:00.000Z';
export const VERIFIED_AT = '2026-07-15T16:01:00.000Z';
export const EXPIRES_AT = '2026-07-15T16:05:00.000Z';
const EVIDENCE_MEMBERS = new Set([
    '@version', 'synthetic_data', 'privacy_notice', 'caid', 'presentation',
    'receipt', 'execution_record', 'audit_record',
]);
const TRUST_BUNDLE_MEMBERS = new Set([
    '@version', 'provisioned_out_of_band', 'allowed_action_types',
    'expected_policy_hash', 'mobile_profile', 'approver_keys', 'log_public_key',
    'execution_record_keys',
]);
function record(value) {
    return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}
function exactMembers(value, members) {
    return record(value)
        && Object.keys(value).length === members.size
        && Object.keys(value).every((key) => members.has(key));
}
function publicSpki(key) {
    return key.export({ type: 'spki', format: 'der' }).toString('base64url');
}
function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}
function p256() {
    const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return { ...pair, publicKeySpki: publicSpki(pair.publicKey) };
}
function ed25519() {
    const pair = crypto.generateKeyPairSync('ed25519');
    return { ...pair, publicKeySpki: publicSpki(pair.publicKey) };
}
function monotonicCounterStore() {
    const counters = new Map();
    return {
        async advance(key, value) {
            const previous = counters.get(key) || 0;
            if (!Number.isSafeInteger(value) || value <= previous)
                return false;
            counters.set(key, value);
            return true;
        },
    };
}
function durableChallengeStore() {
    const backend = createMemoryBackend();
    backend.durable = true;
    return createDurableChallengeStore(backend);
}
function durableAuditLog() {
    const backend = createMemoryAtomicEvidenceBackend();
    backend.durable = true;
    let next = 0;
    return createAtomicEvidenceLog(backend, {
        streamId: 'synthetic-regulatory-mobile-demo',
        recordIdFactory: (() => `regulatory-mobile-audit-${String(++next).padStart(6, '0')}`),
    });
}
function makeSyntheticAction() {
    return {
        ep_version: '1.0',
        action_type: 'prior.auth.approve.1',
        patient_ref: `sha256:${sha256('synthetic-member-reference-0001')}`,
        service_code: 'HCPCS:DEMO-0001',
        diagnosis_code: 'ICD-10-CM:DEMO-0001',
        authorization_number: 'PA-SYNTHETIC-0001',
        valid_from: '2026-07-16T00:00:00.000Z',
        valid_until: '2026-08-16T00:00:00.000Z',
        // Integer on purpose: the CAID action-type schema requires a number here,
        // and this value feeds the digest -- stringifying it changes the CAID.
        units_approved: 2,
        organization_id: 'health-plan-synthetic',
        target_system: 'utilization-review.synthetic.example',
        target_resource: 'prior-auth/PA-SYNTHETIC-0001',
        initiator: 'ep:agent:synthetic-review-assistant',
        policy_id: POLICY_ID,
        requested_at: '2026-07-15T15:59:30.000Z',
    };
}
function buildSyntheticSystemOfRecord() {
    const action = makeSyntheticAction();
    const computed = computeCaid(action, { suite: 'jcs-sha256', definitions: DEFINITIONS });
    if (!computed.caid)
        throw new Error(`synthetic CAID refused: ${(computed.refusals || []).join(', ')}`);
    const policy = {
        policy_id: POLICY_ID,
        action_type: action.action_type,
        human_review_required: true,
        required_approver_id: APPROVER_ID,
        disposition: 'approval',
    };
    const presentation = {
        '@version': 'EP-MOBILE-PRESENTATION-v1',
        title: 'Synthetic prior-authorization approval',
        summary: 'Review the material fields before approving this synthetic case.',
        risk: 'regulated healthcare authorization',
        consequence: 'Approving permits the synthetic service authorization to proceed.',
        material_fields: projectMobileAction(action),
    };
    const record = {
        action_reference: ACTION_REFERENCE,
        action,
        caid: computed.caid,
        presentation,
        policy,
        status: 'awaiting_human_review',
    };
    return {
        record,
        /**
         * @param {Record<string, unknown>} input
         */
        async resolve({ action_reference: actionReference, approver_id: approverId }) {
            if (actionReference !== record.action_reference || approverId !== APPROVER_ID)
                return null;
            return {
                action: structuredClone(record.action),
                presentation: structuredClone(record.presentation),
                policy: structuredClone(record.policy),
                policy_id: POLICY_ID,
                initiator_id: record.action.initiator,
                approver_id: APPROVER_ID,
                issued_at: ISSUED_AT,
                expires_at: EXPIRES_AT,
                challenge_id: 'mob_synthetic_regulatory_0001',
                nonce: 'sig_synthetic_regulatory_0001',
            };
        },
        applyVerifiedDecision({ result, receipt, evidenceReport }) {
            if (evidenceReport?.valid !== true
                || result?.valid !== true || result.verdict !== 'verified'
                || result.decision !== 'approved' || result.approver_id !== APPROVER_ID
                || receipt?.action_hash !== hashCanonical(record.action)
                || result.context_hash !== hashCanonical(receipt?.contexts?.[0])) {
                return { applied: false, reason: 'verified_approval_required' };
            }
            record.status = 'approved';
            record.approved_by = result.approver_id;
            record.approval_context_hash = result.context_hash;
            return { applied: true, status: record.status };
        },
    };
}
function makeSyntheticAppAttestHarness(platformRoot) {
    const tokenBody = ({ requestHash, counter }) => ({
        app_id: APP_ID,
        key_id: ATTESTATION_KEY_ID,
        environment: 'development',
        client_data_hash: requestHash,
        counter,
        fixture_issuer: 'synthetic-platform-root',
    });
    const issueToken = ({ requestHash, counter }) => {
        const body = tokenBody({ requestHash, counter });
        const signature = crypto.sign(null, Buffer.from(canonicalize(body), 'utf8'), platformRoot.privateKey).toString('base64url');
        return Buffer.from(JSON.stringify({ ...body, signature }), 'utf8').toString('base64url');
    };
    const verifier = createAppleAppAttestVerifier({
        appId: APP_ID,
        attestationKeyId: ATTESTATION_KEY_ID,
        environment: 'development',
        counterStore: monotonicCounterStore(),
        async verifyAssertion({ assertionObject, clientDataHash, appId, keyId, environment }) {
            try {
                const token = JSON.parse(assertionObject.toString('utf8'));
                const { signature, ...body } = token;
                const signatureValid = crypto.verify(null, Buffer.from(canonicalize(body), 'utf8'), platformRoot.publicKey, Buffer.from(signature, 'base64url'));
                const expectedHash = clientDataHash.toString('base64url');
                const valid = signatureValid
                    && body.app_id === appId
                    && body.key_id === keyId
                    && body.environment === environment
                    && body.client_data_hash === expectedHash
                    && Number.isSafeInteger(body.counter) && body.counter > 0;
                return {
                    valid,
                    app_id: body.app_id,
                    key_id: body.key_id,
                    environment: body.environment,
                    client_data_hash: body.client_data_hash,
                    counter: body.counter,
                };
            }
            catch {
                return { valid: false };
            }
        },
    });
    return { issueToken, verifier };
}
/**
 * @param {{ challenge: *, passkey: *, attestationToken: string, signCount?: number }} params
 * @returns {import('../../packages/mobile/index.js').MobileCeremonyResponse}
 */
function makeMobileResponse({ challenge, passkey, attestationToken, signCount = 7 }) {
    const clientData = Buffer.from(JSON.stringify({
        type: 'webauthn.get',
        challenge: challenge.webauthn.challenge,
        origin: ORIGIN,
        crossOrigin: false,
    }), 'utf8');
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(signCount);
    const authenticatorData = Buffer.concat([
        crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
        Buffer.from([0x05]),
        counter,
    ]);
    const signedBytes = Buffer.concat([
        authenticatorData,
        crypto.createHash('sha256').update(clientData).digest(),
    ]);
    return {
        '@version': 'EP-MOBILE-CEREMONY-v1',
        challenge_id: challenge.challenge_id,
        nonce: challenge.nonce,
        platform: 'ios',
        app_id: APP_ID,
        device_key_id: DEVICE_KEY_ID,
        credential_id: challenge.webauthn.credential_ids[0],
        attestation_key_id: ATTESTATION_KEY_ID,
        decision: 'approved',
        display_hash: challenge.authorization_context.display_hash,
        signoff: {
            context: structuredClone(challenge.authorization_context),
            webauthn: {
                authenticator_data: authenticatorData.toString('base64url'),
                client_data_json: clientData.toString('base64url'),
                signature: crypto.sign('sha256', signedBytes, passkey.privateKey).toString('base64url'),
            },
        },
        attestation: {
            format: challenge.attestation.format,
            token: attestationToken,
        },
    };
}
function approverKeyEntry(profile) {
    const enrollment = profile.enrollments.find((item) => item.device_key_id === DEVICE_KEY_ID);
    return {
        approver_id: enrollment.approver_id,
        public_key: enrollment.public_key_spki,
        key_class: 'A',
        valid_from: enrollment.valid_from,
        valid_to: enrollment.valid_to,
    };
}
function parseClientData(receipt) {
    try {
        return JSON.parse(Buffer.from(receipt.signoffs[0].webauthn.client_data_json, 'base64url').toString('utf8'));
    }
    catch {
        return null;
    }
}
function verifyAuditJoin(evidence, executionRecord) {
    const audit = evidence?.audit_record;
    if (!verifyEvidenceRecord(audit, { atomicRequired: true }))
        return false;
    return executionRecord.audit_record_id === audit.record_id
        && executionRecord.audit_record_hash === `sha256:${audit.hash}`
        && executionRecord.challenge_id === audit.challenge_id
        && executionRecord.action_hash === audit.action_hash
        && executionRecord.profile_hash === audit.profile_hash
        && executionRecord.context_hash === audit.context_hash
        && executionRecord.decision === audit.decision
        && audit.verdict === 'verified';
}
export function verifyRegulatoryEvidence(evidence, trustBundle) {
    const checks = {
        package_shape: false,
        trust_bundle_shape: false,
        mobile_profile: false,
        caid: false,
        receipt: false,
        presentation_binding: false,
        mobile_origin: false,
        enrollment_binding: false,
        execution_record_signature: false,
        receipt_execution_join: false,
        audit_record_join: false,
    };
    try {
        checks.package_shape = Boolean(exactMembers(evidence, EVIDENCE_MEMBERS)
            && evidence['@version'] === EVIDENCE_VERSION
            && typeof evidence.synthetic_data === 'boolean'
            && typeof evidence.privacy_notice === 'string'
            && evidence.privacy_notice.length > 0 && evidence.privacy_notice.length <= 1024
            && evidence?.receipt && evidence?.presentation
            && evidence?.execution_record && evidence?.audit_record);
        checks.trust_bundle_shape = Boolean(exactMembers(trustBundle, TRUST_BUNDLE_MEMBERS)
            && trustBundle['@version'] === TRUST_BUNDLE_VERSION
            && trustBundle.provisioned_out_of_band === true
            && Array.isArray(trustBundle.allowed_action_types)
            && trustBundle.allowed_action_types.length > 0
            && new Set(trustBundle.allowed_action_types).size === trustBundle.allowed_action_types.length
            && trustBundle.allowed_action_types.every((value) => typeof value === 'string' && value.length > 0)
            && typeof trustBundle.expected_policy_hash === 'string'
            && record(trustBundle.mobile_profile)
            && record(trustBundle.approver_keys) && Object.keys(trustBundle.approver_keys).length > 0
            && typeof trustBundle.log_public_key === 'string'
            && record(trustBundle.execution_record_keys)
            && Object.keys(trustBundle.execution_record_keys).length > 0);
        if (!checks.package_shape || !checks.trust_bundle_shape) {
            return buildRegulatorReport(checks, null);
        }
        const profile = trustBundle.mobile_profile;
        checks.mobile_profile = mobileProfileHash(profile) === profile.profile_hash;
        const receipt = evidence.receipt;
        const context = receipt.contexts?.[0];
        const signoff = receipt.signoffs?.[0];
        const enrollment = profile.enrollments?.find((item) => item.device_key_id === context?.mobile_binding?.device_key_id);
        const approverKey = trustBundle.approver_keys?.[signoff?.approver_key_id];
        const caidResult = verifyCaid(receipt.action, evidence.caid, { definitions: DEFINITIONS });
        checks.caid = caidResult.valid === true
            && trustBundle.allowed_action_types.includes(receipt.action?.action_type)
            && computeCaid(receipt.action, { suite: 'jcs-sha256', definitions: DEFINITIONS }).digest === receipt.action_hash;
        const receiptResult = verifyTrustReceipt(receipt, {
            approverKeys: trustBundle.approver_keys,
            logPublicKey: trustBundle.log_public_key,
            strict: true,
            rpId: profile.rp_id,
            allowedOrigins: profile.allowed_origins,
            expectedPolicyHash: trustBundle.expected_policy_hash,
        });
        checks.receipt = receiptResult.valid === true && receiptResult.strict?.valid === true;
        checks.presentation_binding = hashCanonical(evidence.presentation) === context?.display_hash;
        const clientData = parseClientData(receipt);
        checks.mobile_origin = Boolean(clientData
            && clientData.type === 'webauthn.get'
            && profile.allowed_origins.includes(clientData.origin)
            && clientData.crossOrigin !== true);
        checks.enrollment_binding = Boolean(enrollment
            && approverKey
            && enrollment.status === 'active'
            && enrollment.approver_id === context.approver
            && enrollment.device_key_id === signoff.approver_key_id
            && enrollment.public_key_spki === approverKey.public_key
            && enrollment.approver_id === approverKey.approver_id
            && approverKey.key_class === 'A'
            && enrollment.valid_from === approverKey.valid_from
            && enrollment.valid_to === approverKey.valid_to
            && enrollment.credential_id === context.mobile_binding.credential_id
            && enrollment.platform === context.mobile_binding.platform
            && enrollment.app_id === context.mobile_binding.app_id
            && enrollment.attestation_key_id === context.mobile_binding.attestation_key_id
            && profile.accepted_apps[context.mobile_binding.platform]?.includes(enrollment.app_id)
            && context.mobile_binding.profile_hash === profile.profile_hash);
        const executionRecord = evidence.execution_record;
        const executionKey = trustBundle.execution_record_keys[executionRecord.signer_key_id];
        checks.execution_record_signature = typeof executionKey === 'string'
            && verifyMobileExecutionRecord(executionRecord, executionKey);
        checks.receipt_execution_join = executionRecord.receipt_id === receipt.receipt_id
            && executionRecord.action_hash === receipt.action_hash
            && executionRecord.context_hash === hashCanonical(context)
            && executionRecord.profile_hash === context.mobile_binding.profile_hash
            && executionRecord.approver_id === context.approver
            && executionRecord.device_key_id === signoff.approver_key_id
            && executionRecord.platform === context.mobile_binding.platform
            && executionRecord.app_id === context.mobile_binding.app_id
            && executionRecord.attestation_format === (context.mobile_binding.platform === 'ios'
                ? 'apple-app-attest'
                : 'play-integrity-standard')
            && executionRecord.decision === context.decision;
        checks.audit_record_join = verifyAuditJoin(evidence, executionRecord);
        return buildRegulatorReport(checks, receiptResult);
    }
    catch {
        return buildRegulatorReport(checks, null);
    }
}
function buildRegulatorReport(checks, receiptResult) {
    const valid = Object.values(checks).every(Boolean);
    return {
        valid,
        verdict: valid ? 'verified_evidence_package' : 'refused_evidence_package',
        checks,
        receipt_checks: receiptResult?.checks || null,
        strict_receipt_checks: receiptResult?.strict?.checks || null,
        directly_recomputed_offline: [
            'CAID and exact action digest',
            'Class-A passkey signature under an out-of-band pinned reviewer key',
            'user-presence and user-verification flags',
            'policy, RP ID, origin, app, enrollment, action, and presentation joins',
            'receipt log inclusion and pinned log signature',
            'operator execution-record signature and its joins to the audit record',
        ],
        operator_attested_not_independently_replayed: [
            'Apple App Attest or Google Play Integrity passed at execution time',
            'the challenge store consumed the authorization once before audit append',
            'the named audit record was durably appended',
        ],
        not_established: [
            'clinical correctness or medical necessity',
            'legal or regulatory compliance',
            'the reviewer\'s civil identity, license, or authority beyond the pinned directory',
            'what the human perceived or understood',
            'honest pixels on a fully compromised device',
            'absence of an unmediated execution path',
            'the real-world effect of the authorized action',
        ],
    };
}
export async function buildSyntheticRegulatoryDemo() {
    const passkey = p256();
    const logKey = ed25519();
    const executionKey = ed25519();
    const platformRoot = ed25519();
    const credentialId = crypto.randomBytes(32).toString('base64url');
    const profile = createMobileRelianceProfile({
        profileId: 'synthetic.regulatory.mobile.v1',
        rpId: RP_ID,
        allowedOrigins: [ORIGIN],
        acceptedApps: { ios: [APP_ID], android: [] },
        enrollments: ([{
                device_key_id: DEVICE_KEY_ID,
                credential_id: credentialId,
                public_key_spki: passkey.publicKeySpki,
                approver_id: APPROVER_ID,
                platform: 'ios',
                app_id: APP_ID,
                attestation_key_id: ATTESTATION_KEY_ID,
                status: 'active',
                valid_from: '2026-01-01T00:00:00.000Z',
                valid_to: '2027-01-01T00:00:00.000Z',
                sign_count: 0,
            }]),
    });
    const platform = makeSyntheticAppAttestHarness(platformRoot);
    const auditLog = durableAuditLog();
    const service = createMobileCeremonyService({
        challengeStore: durableChallengeStore(),
        auditLog,
        counterStore: monotonicCounterStore(),
        attestationVerifier: platform.verifier,
        clock: () => VERIFIED_AT,
    });
    const systemOfRecord = buildSyntheticSystemOfRecord();
    const caller = { subject: 'ep:service:synthetic-utilization-review' };
    const controller = createGovernmentMobileController({
        service,
        profiles: new Map([[profile.profile_id, profile]]),
        resolveRequest: (input) => systemOfRecord.resolve(input),
        authorize: (input) => caller.subject === 'ep:service:synthetic-utilization-review'
            && input.caller?.subject === caller.subject
            && input.profile_id === profile.profile_id
            && input.approver_id === APPROVER_ID
            && input.device_key_id === DEVICE_KEY_ID,
    });
    const issued = await controller.issue({
        profile_id: profile.profile_id,
        action_reference: ACTION_REFERENCE,
        approver_id: APPROVER_ID,
        decision: 'approved',
        platform: 'ios',
        app_id: APP_ID,
        device_key_id: DEVICE_KEY_ID,
    }, caller);
    if (!issued.ok)
        throw new Error(`mobile challenge refused: ${issued.verdict}`);
    // controller.issue() never returns { ok: true, challenge: null } (see
    // packages/mobile/index.js createMobileCeremonyService#issue and government.js#issue,
    // which both pair ok:true with a non-null challenge); the throw above rules out ok:false.
    const challenge = issued.challenge;
    const response = makeMobileResponse({
        challenge,
        passkey,
        attestationToken: platform.issueToken({ requestHash: challenge.attestation.request_hash, counter: 1 }),
    });
    const result = await controller.verify({ challenge, response }, caller);
    if (!result.valid)
        throw new Error(`mobile ceremony refused: ${result.verdict}`);
    // result.class_a is only populated when verified with decision === 'approved'
    // (packages/mobile/index.js, verifyMobileCeremony); this demo always issues and
    // signs an 'approved' decision, so a valid result always carries it.
    const classA = result.class_a;
    const receiptId = 'ep:receipt:synthetic-regulatory-mobile-0001';
    const receipt = assembleAuthorizationReceipt({
        receiptId,
        action: challenge.action,
        contexts: ([classA.context]),
        signoffs: ([classA.signoff]),
        committedAt: VERIFIED_AT,
        log: {
            privateKey: logKey.privateKey,
            logKeyId: 'ep:log:synthetic-regulatory-mobile-001',
        },
    });
    const executionRecord = createMobileExecutionRecord({
        challenge,
        result,
        receiptId,
        recordedAt: VERIFIED_AT,
        signerPrivateKey: executionKey.privateKey,
        signerKeyId: 'ep:key:synthetic-mobile-service-001',
    });
    const evidence = {
        '@version': EVIDENCE_VERSION,
        synthetic_data: true,
        privacy_notice: 'All identifiers and clinical codes in this example are synthetic. Real patient-linked values or digests may still be regulated data.',
        caid: systemOfRecord.record.caid,
        presentation: challenge.presentation,
        receipt,
        execution_record: executionRecord,
        audit_record: result.audit_record,
    };
    const trustBundle = {
        '@version': TRUST_BUNDLE_VERSION,
        provisioned_out_of_band: true,
        allowed_action_types: ['prior.auth.approve.1'],
        expected_policy_hash: challenge.authorization_context.policy_hash,
        mobile_profile: profile,
        approver_keys: { [DEVICE_KEY_ID]: approverKeyEntry(profile) },
        log_public_key: logKey.publicKeySpki,
        execution_record_keys: {
            'ep:key:synthetic-mobile-service-001': executionKey.publicKeySpki,
        },
    };
    const offlineReport = verifyRegulatoryEvidence(evidence, trustBundle);
    if (!offlineReport.valid)
        throw new Error('locally generated regulatory evidence did not verify');
    const effect = systemOfRecord.applyVerifiedDecision({
        result,
        receipt,
        evidenceReport: offlineReport,
    });
    const freshAttestationReplay = structuredClone(response);
    freshAttestationReplay.attestation.token = platform.issueToken({
        requestHash: challenge.attestation.request_hash,
        counter: 2,
    });
    const replayResult = await controller.verify({ challenge, response: freshAttestationReplay }, caller);
    return {
        evidence,
        trustBundle,
        offlineReport,
        onlineResult: result,
        replayResult,
        effect,
        attestationFixture: 'synthetic cryptographic test double; no Apple assertion was obtained',
    };
}
export function writeDemoArtifacts({ evidence, trustBundle }, outputDirectory) {
    fs.mkdirSync(outputDirectory, { recursive: true });
    const evidencePath = path.join(outputDirectory, 'evidence.json');
    const pinsPath = path.join(outputDirectory, 'regulator-pins.json');
    fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
    fs.writeFileSync(pinsPath, `${JSON.stringify(trustBundle, null, 2)}\n`);
    return { evidencePath, pinsPath };
}
export function defaultOutputDirectory() {
    return path.join(HERE, 'out');
}
