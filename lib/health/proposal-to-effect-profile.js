// SPDX-License-Identifier: Apache-2.0
// Generated from proposal-to-effect-profile.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Public, synthetic healthcare composition over the existing EMILIA
 * Proposal-to-Effect controller.
 *
 * This module deliberately does not implement an execution state machine.
 * Reservation, provider-entry custody, replay fencing, indeterminate outcomes,
 * and authenticated reconciliation remain owned by Proposal-to-Effect, AEB,
 * and Gate. The healthcare layer contributes:
 *
 *   scanner projection -> exact hospice administrative action -> Proposal-to-
 *   Effect -> protected sandbox callback -> append-only assurance export.
 *
 * A scanner finding is not prior authorization, clinical judgment, a fraud
 * conclusion, or payment authority.
 */
import crypto from 'node:crypto';
import { computeCaid } from '../../caid/impl/js/caid.mjs';
import { canonicalize } from '../canonical-json.js';
import { hashCanonicalAction } from '../guard-policies.js';
export const HEALTHCARE_CONSEQUENCE_PROFILE_VERSION = 'EMILIA-HEALTHCARE-CONSEQUENCE-CONTROL-v1';
export const HEALTHCARE_SCANNER_FINDING_VERSION = 'EMILIA-HEALTHCARE-ADMINISTRATIVE-FINDING-v1';
export const PROSPECTIVE_CONTROL_PACKAGE_SCHEMA = 'emilia.commercial.prospective-control-package.v1';
export const HEALTHCARE_CONTROL_PACKAGE_VERSION = PROSPECTIVE_CONTROL_PACKAGE_SCHEMA;
export const HEALTHCARE_ASSURANCE_PACKET_VERSION = 'EMILIA-HEALTHCARE-CONSEQUENCE-ASSURANCE-PACKET-v1';
export const HEALTHCARE_ASSURANCE_TRUST_BUNDLE_VERSION = 'EMILIA-HEALTHCARE-ASSURANCE-TRUST-BUNDLE-v1';
export const HEALTHCARE_ASSURANCE_ASSERTION_VERSION = 'EMILIA-HEALTHCARE-ASSURANCE-ASSERTION-v1';
export const HOSPICE_ACTION_VERSION = 'EP-HEALTH-PROGRAM-INTEGRITY-ACTION-v1';
export const HOSPICE_PROFILE_ID = 'medi-cal.hospice-integrity.v1';
export const HOSPICE_ACTION_TYPE = 'health.medi-cal.hospice-claim-payment.1';
export const HOSPICE_PROPOSAL_PROFILE_ID = 'healthcare.hospice-payment.consequence-control.v1';
export const HOSPICE_AEB_REQUIREMENT_REF = 'requirement:healthcare-hospice-consequence-control';
export const HOSPICE_ACTION_FIELDS = Object.freeze([
    '@version',
    'profile_id',
    'action_type',
    'organization_id',
    'provider_npi',
    'member_ref',
    'service_period_start',
    'service_period_end',
    'authorization_form_digest',
    'amount',
    'currency',
    'payment_destination_digest',
    'reviewer_id',
    'authority_proof_digest',
    'policy_id',
    'policy_version',
    'policy_hash',
]);
export const HOSPICE_CAID_DEFINITION = Object.freeze({
    action_type: HOSPICE_ACTION_TYPE,
    required_fields: [
        { name: '@version', type: 'string' },
        { name: 'profile_id', type: 'string' },
        { name: 'organization_id', type: 'string' },
        { name: 'provider_npi', type: 'string' },
        { name: 'member_ref', type: 'string' },
        { name: 'service_period_start', type: 'string' },
        { name: 'service_period_end', type: 'string' },
        { name: 'authorization_form_digest', type: 'digest' },
        { name: 'amount', type: 'amount-string' },
        { name: 'currency', type: 'enum', values: ['USD'] },
        { name: 'payment_destination_digest', type: 'digest' },
        { name: 'reviewer_id', type: 'string' },
        { name: 'authority_proof_digest', type: 'digest' },
        { name: 'policy_id', type: 'string' },
        { name: 'policy_version', type: 'integer' },
        { name: 'policy_hash', type: 'digest' },
    ],
    optional_fields: [],
});
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9:_.@/-]{2,255}$/;
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;
const CAID_RE = /^caid:1:health\.medi-cal\.hospice-claim-payment\.1:jcs-sha256:[A-Za-z0-9_-]{43}$/;
const MEMBER_REF_RE = /^member:sha256:[a-f0-9]{64}$/;
const MONEY_RE = /^(?:0|[1-9][0-9]*)\.[0-9]{2}$/;
const PROHIBITED_PHI_FIELD_ALIASES = new Set([
    'accountnumber',
    'membername',
    'patientname',
    'beneficiaryid',
    'bic',
    'cin',
    'dateofbirth',
    'dob',
    'address',
    'telephone',
    'phone',
    'email',
    'ssn',
    'medicarebeneficiaryidentifier',
    'diagnosis',
    'diagnosistext',
    'clinicalnote',
    'authorizationform',
    'bankaccount',
    'routingnumber',
    'rawproviderevidence',
    'freetext',
    'freeformtext',
    'freetextnote',
]);
const RUNTIME_DOWNGRADE_FIELDS = new Set([
    'action_caid',
    'authorized',
    'bypass_checks',
    'enforcement_mode',
    'fail_open',
    'permit',
]);
const EXPORTABLE_DECISIONS = new Set([
    'EXECUTED',
    'RECONCILED_EXECUTED',
    'RECONCILED_NOT_EXECUTED',
]);
const RECONCILED_DECISIONS = new Set([
    'RECONCILED_EXECUTED',
    'RECONCILED_NOT_EXECUTED',
]);
const ASSURANCE_SIGNATURE_DOMAIN = 'EMILIA-HEALTHCARE-CONSEQUENCE-ASSURANCE-v1';
const ASSURANCE_ROLES = [
    'evaluator',
    'receipt',
    'aeb',
    'provider',
];
export const HEALTHCARE_ASSURANCE_LIMITATIONS = Object.freeze([
    'This packet covers a synthetic, relying-party-governed hospice payment administrative action in a sandbox callback only.',
    'A scanner finding identifies a control requirement; it is not prior authorization, clinical judgment, a fraud determination, or authority to pay or withhold care.',
    'The packet does not establish medical necessity, service delivery, coding correctness, claim validity, provider or member real-world identity, or source-system truth.',
    'No live Medicare, Medi-Cal, insurer, provider, bank, or payment-rail mutation is claimed.',
    'EXECUTED means the configured protected sandbox callback completed and Proposal-to-Effect committed its exact operation; INDETERMINATE does not prove success or failure.',
    'Field-name filtering and allowlisted projections reduce exposure but are not proof that PHI is absent; deployments must apply source-system classification, DLP, access control, and authorized privacy review.',
    'The packet supports verification and re-performance procedures; it is not an audit opinion, certification, regulatory conclusion, or clinical conclusion.',
]);
function isPlainObject(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function clone(value) {
    return structuredClone(value);
}
function digest(value) {
    return `sha256:${hashCanonicalAction(value)}`;
}
const HOSPICE_RELIANCE_PROGRAM_DIGEST = digest({
    '@version': HEALTHCARE_CONSEQUENCE_PROFILE_VERSION,
    profile_id: HOSPICE_PROPOSAL_PROFILE_ID,
    action_type: HOSPICE_ACTION_TYPE,
    action_version: HOSPICE_ACTION_VERSION,
    aeb_requirement_ref: HOSPICE_AEB_REQUIREMENT_REF,
    action_fields: HOSPICE_ACTION_FIELDS,
});
function signingBytes(domain, value) {
    return Buffer.from(`${ASSURANCE_SIGNATURE_DOMAIN}:${domain}\0${canonicalize(value)}`);
}
function identifier(value) {
    return typeof value === 'string' && IDENTIFIER_RE.test(value);
}
function validDateOnly(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value))
        return false;
    const parsed = new Date(`${value}T00:00:00.000Z`);
    return Number.isFinite(parsed.getTime())
        && parsed.toISOString().slice(0, 10) === value;
}
function exactKeys(value, keys) {
    if (!isPlainObject(value))
        return false;
    const actual = Object.keys(value).sort();
    const expected = [...keys].sort();
    return actual.length === expected.length
        && expected.every((key, index) => key === actual[index]);
}
function normalizedFieldAlias(value) {
    return value.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
}
function prohibitedPhi(value, depth = 0, budget = { entries: 0 }) {
    if (depth > 10 || budget.entries > 4096)
        return 'input_complexity_limit';
    if (Array.isArray(value)) {
        for (const entry of value) {
            budget.entries += 1;
            const found = prohibitedPhi(entry, depth + 1, budget);
            if (found)
                return found;
        }
        return null;
    }
    if (!isPlainObject(value))
        return null;
    for (const [key, entry] of Object.entries(value)) {
        budget.entries += 1;
        if (PROHIBITED_PHI_FIELD_ALIASES.has(normalizedFieldAlias(key)))
            return key;
        const found = prohibitedPhi(entry, depth + 1, budget);
        if (found)
            return found;
    }
    return null;
}
function canonicalBase64url(value, expectedBytes) {
    if (typeof value !== 'string'
        || value.length === 0
        || !/^[A-Za-z0-9_-]+$/.test(value)) {
        return null;
    }
    try {
        const decoded = Buffer.from(value, 'base64url');
        if ((expectedBytes !== undefined && decoded.length !== expectedBytes)
            || decoded.toString('base64url') !== value) {
            return null;
        }
        return decoded;
    }
    catch {
        return null;
    }
}
function assuranceProofShape(value) {
    return exactKeys(value, [
        'algorithm',
        'key_id',
        'signature_b64u',
    ])
        && value.algorithm === 'Ed25519'
        && identifier(value.key_id)
        && canonicalBase64url(value.signature_b64u, 64) !== null;
}
function signerShape(value) {
    return isPlainObject(value)
        && value.algorithm === 'Ed25519'
        && identifier(value.key_id)
        && typeof value.sign === 'function';
}
async function signAssuranceValue(domain, value, signer) {
    const signed = await signer.sign(signingBytes(domain, value));
    const signature = typeof signed === 'string'
        ? canonicalBase64url(signed, 64)
        : signed instanceof Uint8Array
            ? Buffer.from(signed)
            : null;
    if (!signature || signature.length !== 64) {
        throw new Error('healthcare_assurance_signature_invalid');
    }
    return {
        algorithm: 'Ed25519',
        key_id: signer.key_id,
        signature_b64u: signature.toString('base64url'),
    };
}
async function signedAssuranceAssertion(role, body, signer) {
    const assertion = {
        '@version': HEALTHCARE_ASSURANCE_ASSERTION_VERSION,
        role,
        body: clone(body),
    };
    return {
        ...assertion,
        proof: await signAssuranceValue(`assertion:${role}`, assertion, signer),
    };
}
function refusal(reason, extras = {}) {
    return {
        ok: false,
        decision: 'REFUSED',
        reason,
        ...extras,
        program_digest: HOSPICE_RELIANCE_PROGRAM_DIGEST,
    };
}
function safeReason(error, fallback) {
    const candidate = isPlainObject(error) && typeof error.message === 'string'
        ? error.message
        : error instanceof Error
            ? error.message
            : '';
    return /^[a-z0-9][a-z0-9:_-]{2,127}$/i.test(candidate)
        ? candidate.toLowerCase()
        : fallback;
}
/**
 * Relying-party-owned exact action projection used both before proposal
 * creation and again at the protected callback boundary.
 */
export function canonicalizeHospicePaymentAction(input) {
    if (!exactKeys(input, HOSPICE_ACTION_FIELDS)) {
        throw new Error('healthcare_action_shape_invalid');
    }
    const phi = prohibitedPhi(input);
    if (phi)
        throw new Error('healthcare_prohibited_phi');
    if ([...RUNTIME_DOWNGRADE_FIELDS].some((field) => Object.hasOwn(input, field))) {
        throw new Error('healthcare_runtime_downgrade_refused');
    }
    if (input['@version'] !== HOSPICE_ACTION_VERSION
        || input.profile_id !== HOSPICE_PROFILE_ID
        || input.action_type !== HOSPICE_ACTION_TYPE) {
        throw new Error('healthcare_action_profile_mismatch');
    }
    for (const field of [
        'organization_id',
        'provider_npi',
        'member_ref',
        'service_period_start',
        'service_period_end',
        'authorization_form_digest',
        'amount',
        'currency',
        'payment_destination_digest',
        'reviewer_id',
        'authority_proof_digest',
        'policy_id',
        'policy_hash',
    ]) {
        if (typeof input[field] !== 'string' || input[field].length === 0) {
            throw new Error(`healthcare_material_field_missing:${field}`);
        }
    }
    if (!identifier(input.organization_id)
        || !/^\d{10}$/.test(input.provider_npi)
        || !MEMBER_REF_RE.test(input.member_ref)
        || !validDateOnly(input.service_period_start)
        || !validDateOnly(input.service_period_end)
        || input.service_period_start > input.service_period_end
        || !DIGEST_RE.test(input.authorization_form_digest)
        || !MONEY_RE.test(input.amount)
        || Number(input.amount) <= 0
        || input.currency !== 'USD'
        || !DIGEST_RE.test(input.payment_destination_digest)
        || !identifier(input.reviewer_id)
        || !DIGEST_RE.test(input.authority_proof_digest)
        || !identifier(input.policy_id)
        || !Number.isSafeInteger(input.policy_version)
        || input.policy_version < 1
        || !DIGEST_RE.test(input.policy_hash)) {
        throw new Error('healthcare_material_action_invalid');
    }
    const action = clone(input);
    const computed = computeCaid(action, {
        suite: 'jcs-sha256',
        definitions: [HOSPICE_CAID_DEFINITION],
    });
    if (!computed?.caid || !computed?.digest
        || !CAID_RE.test(computed.caid)
        || !DIGEST_RE.test(computed.digest)) {
        throw new Error('healthcare_action_caid_generation_failed');
    }
    return {
        action,
        caid: computed.caid,
        action_digest: computed.digest,
    };
}
export function createHospiceProposalToEffectProfile({ authorization_endpoint, ttl_sec = 300, }) {
    if (typeof authorization_endpoint !== 'string') {
        throw new Error('healthcare_authorization_endpoint_invalid');
    }
    let endpoint;
    try {
        endpoint = new URL(authorization_endpoint);
    }
    catch {
        throw new Error('healthcare_authorization_endpoint_invalid');
    }
    if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password
        || endpoint.hash || endpoint.origin === 'null') {
        throw new Error('healthcare_authorization_endpoint_invalid');
    }
    if (!Number.isSafeInteger(ttl_sec) || ttl_sec < 1 || ttl_sec > 900) {
        throw new Error('healthcare_proposal_ttl_invalid');
    }
    return Object.freeze({
        id: HOSPICE_PROPOSAL_PROFILE_ID,
        action_type: HOSPICE_ACTION_TYPE,
        selector: Object.freeze({
            action_type: HOSPICE_ACTION_TYPE,
            protocol: 'https',
            method: 'POST',
            path: '/synthetic/health/hospice-claim/payment',
        }),
        // Proposal-to-Effect acquisition field names use the identifier grammar
        // and therefore cannot spell JSON-LD's "@version". The canonicalizer still
        // requires and binds @version as part of the exact CAID action.
        required_fields: HOSPICE_ACTION_FIELDS.filter((field) => field !== '@version'),
        authorization: Object.freeze({
            authorization_endpoint: endpoint.toString(),
            flow: 'EP-APPROVAL-v1',
        }),
        aeb_requirement_ref: HOSPICE_AEB_REQUIREMENT_REF,
        ttl_sec,
        canonicalize_action(input) {
            const canonical = canonicalizeHospicePaymentAction(input);
            return { action: canonical.action, caid: canonical.caid };
        },
    });
}
function memoryKey(tenantId, operationId) {
    return `${tenantId}\0${operationId}`;
}
/** Explicitly test/demo-only in-memory evidence and capability custody. */
export function createMemoryHealthcareControlStores() {
    const events = new Map();
    const handles = new Map();
    const evidence_store = {
        appendOnly: true,
        tenantBound: true,
        durable: false,
        async append(input) {
            const key = memoryKey(input.tenant_id, input.operation_id);
            const sequence = (events.get(key)?.length ?? 0) + 1;
            const unsigned = { ...clone(input), sequence };
            const event = {
                ...unsigned,
                event_id: digest({
                    domain: HEALTHCARE_CONSEQUENCE_PROFILE_VERSION,
                    ...unsigned,
                }),
            };
            events.set(key, [...(events.get(key) ?? []), clone(event)]);
            return clone(event);
        },
        async list(input) {
            return clone(events.get(memoryKey(input.tenant_id, input.operation_id)) ?? []);
        },
    };
    const reconciliation_handle_store = {
        serverSideOnly: true,
        durable: false,
        async put(input) {
            handles.set(memoryKey(input.tenant_id, input.operation_id), clone(input.handle));
        },
        async get(input) {
            const handle = handles.get(memoryKey(input.tenant_id, input.operation_id));
            return handle ? clone(handle) : null;
        },
    };
    return { evidence_store, reconciliation_handle_store };
}
function normalizeProspectiveControlPackage(value, expectedTenant) {
    if (!exactKeys(value, [
        'action',
        'actionDigest',
        'caid',
        'caseDigest',
        'caseId',
        'claimBoundary',
        'controlPurpose',
        'packageDigest',
        'phi',
        'policy',
        'profile',
        'requiredControl',
        'retroactiveAuthorization',
        'schema',
        'sourceFinding',
        'sourceRecordDigests',
        'tenantId',
    ]) || value.schema !== PROSPECTIVE_CONTROL_PACKAGE_SCHEMA
        || value.claimBoundary
            !== 'prospective_control_from_triage_not_historical_authorization_or_fraud_proof'
        || value.controlPurpose !== 'new_future_action_pre_effect_control'
        || value.retroactiveAuthorization !== 'none'
        || value.tenantId !== expectedTenant
        || !identifier(value.caseId)
        || !DIGEST_RE.test(value.caseDigest)
        || !DIGEST_RE.test(value.packageDigest)
        || !Array.isArray(value.sourceRecordDigests)
        || value.sourceRecordDigests.length < 1
        || value.sourceRecordDigests.length > 256) {
        throw new Error('prospective_control_package_invalid');
    }
    for (const source of value.sourceRecordDigests) {
        if (!DIGEST_RE.test(source)) {
            throw new Error('prospective_control_package_invalid');
        }
    }
    if (!exactKeys(value.sourceFinding, [
        'authorizesScannedExecution',
        'code',
        'confidence',
        'provesFraud',
        'provesHistoricalAuthorization',
        'role',
    ]) || value.sourceFinding.code !== 'MISSING_APPROVAL'
        || value.sourceFinding.confidence !== 'deterministic'
        || value.sourceFinding.role !== 'retrospective_triage_evidence_only'
        || value.sourceFinding.provesHistoricalAuthorization !== false
        || value.sourceFinding.provesFraud !== false
        || value.sourceFinding.authorizesScannedExecution !== false) {
        throw new Error('prospective_control_finding_boundary_invalid');
    }
    if (!exactKeys(value.profile, ['id', 'proposalToEffect', 'version'])
        || value.profile.id !== HOSPICE_PROFILE_ID
        || value.profile.version !== 1
        || value.profile.proposalToEffect !== 'EMILIA-PROPOSAL-TO-EFFECT-v1') {
        throw new Error('prospective_control_profile_invalid');
    }
    if (!exactKeys(value.policy, ['hash', 'id', 'version'])
        || !identifier(value.policy.id)
        || !Number.isSafeInteger(value.policy.version)
        || value.policy.version < 1
        || !DIGEST_RE.test(value.policy.hash)) {
        throw new Error('prospective_control_policy_invalid');
    }
    if (!exactKeys(value.requiredControl, [
        'approval',
        'consumption',
        'freshness',
        'quorum',
    ])
        || !exactKeys(value.requiredControl.approval, [
            'assuranceClass',
            'receiptProfile',
            'required',
        ])
        || value.requiredControl.approval.required !== true
        || value.requiredControl.approval.receiptProfile !== 'EP-RECEIPT-v1'
        || value.requiredControl.approval.assuranceClass !== 'class_a'
        || !exactKeys(value.requiredControl.quorum, [
            'distinctApprovers',
            'minimumApprovals',
        ])
        || value.requiredControl.quorum.minimumApprovals !== 1
        || value.requiredControl.quorum.distinctApprovers !== 1
        || !exactKeys(value.requiredControl.freshness, [
            'actionMaxAgeSec',
            'revocationMaxStalenessSec',
        ])
        || value.requiredControl.freshness.actionMaxAgeSec !== 300
        || value.requiredControl.freshness.revocationMaxStalenessSec !== 900
        || !exactKeys(value.requiredControl.consumption, [
            'maximumUses',
            'mode',
        ])
        || value.requiredControl.consumption.mode !== 'one_time'
        || value.requiredControl.consumption.maximumUses !== 1) {
        throw new Error('prospective_control_requirement_invalid');
    }
    if (!exactKeys(value.phi, ['memberReference', 'rawPhiIncluded'])
        || value.phi.rawPhiIncluded !== false
        || value.phi.memberReference !== 'pairwise_pseudonymous_commitment') {
        throw new Error('prospective_control_phi_boundary_invalid');
    }
    const canonical = canonicalizeHospicePaymentAction(value.action);
    if (canonical.action.organization_id !== expectedTenant
        || value.caid !== canonical.caid
        || value.actionDigest !== canonical.action_digest
        || value.policy.id !== canonical.action.policy_id
        || value.policy.version !== canonical.action.policy_version
        || value.policy.hash !== canonical.action.policy_hash) {
        throw new Error('prospective_control_action_mismatch');
    }
    const unsigned = clone(value);
    delete unsigned.packageDigest;
    if (digest(unsigned) !== value.packageDigest) {
        throw new Error('prospective_control_package_digest_invalid');
    }
    const control_package = clone(value);
    const finding = {
        '@version': HEALTHCARE_SCANNER_FINDING_VERSION,
        provenance_schema: PROSPECTIVE_CONTROL_PACKAGE_SCHEMA,
        case_id: control_package.caseId,
        case_digest: control_package.caseDigest,
        package_digest: control_package.packageDigest,
        source_record_digests: clone(control_package.sourceRecordDigests),
        source_finding: clone(control_package.sourceFinding),
        disposition: 'CONTROL_REQUIRED',
        scope: 'administrative_hospice_payment',
        triage_provenance_only: true,
        authorization_evidence: false,
        prior_authorization: false,
        clinical_judgment: false,
        fraud_determination: false,
        payment_authority: false,
    };
    return { control_package, finding, canonical };
}
function validateControlPackage(value, expectedTenant) {
    const normalized = normalizeProspectiveControlPackage(value, expectedTenant);
    return {
        case_id: normalized.control_package.caseId,
        canonical: normalized.canonical,
    };
}
function publicAttempt(value) {
    if (!isPlainObject(value))
        return null;
    const fields = [
        'tenant_id',
        'provider_id',
        'provider_account_id',
        'environment',
        'attempt_id',
        'request_digest',
    ];
    if (!fields.every((field) => typeof value[field] === 'string'))
        return null;
    return Object.fromEntries(fields.map((field) => [field, value[field]]));
}
function projectControllerResult(value) {
    if (!isPlainObject(value))
        return {};
    const result = {};
    if (typeof value.ok === 'boolean')
        result.ok = value.ok;
    if (identifier(value.reason))
        result.reason = value.reason;
    if (identifier(value.state))
        result.state = value.state;
    if (identifier(value.outcome))
        result.outcome = value.outcome;
    if (DIGEST_RE.test(value.evidence_digest)) {
        result.evidence_digest = value.evidence_digest;
    }
    if (isPlainObject(value.aeb)) {
        result.aeb = {
            ...(identifier(value.aeb.state) ? { state: value.aeb.state } : {}),
            ...(typeof value.aeb.retry_allowed === 'boolean'
                ? { retry_allowed: value.aeb.retry_allowed }
                : {}),
            ...(identifier(value.aeb.reason) ? { reason: value.aeb.reason } : {}),
        };
    }
    const attempt = publicAttempt(value.consequence?.attempt);
    if (isPlainObject(value.consequence)) {
        result.consequence = {
            ...(identifier(value.consequence.state)
                ? { state: value.consequence.state }
                : {}),
            ...(attempt ? { attempt } : {}),
        };
    }
    return result;
}
function findingProjection(value) {
    if (!isPlainObject(value)
        || !identifier(value.case_id)
        || !DIGEST_RE.test(value.case_digest)
        || !DIGEST_RE.test(value.package_digest)
        || !Array.isArray(value.source_record_digests)
        || !value.source_record_digests.every((entry) => (typeof entry === 'string' && DIGEST_RE.test(entry)))) {
        return null;
    }
    return {
        case_id: value.case_id,
        case_digest: value.case_digest,
        package_digest: value.package_digest,
        source_record_digests: clone(value.source_record_digests),
        disposition: value.disposition,
        scope: value.scope,
        triage_provenance_only: value.triage_provenance_only === true,
        authorization_evidence: value.authorization_evidence === true,
        prior_authorization: value.prior_authorization === true,
        clinical_judgment: value.clinical_judgment === true,
        fraud_determination: value.fraud_determination === true,
        payment_authority: value.payment_authority === true,
    };
}
function controlProjection(value) {
    if (!isPlainObject(value)
        || value.schema !== PROSPECTIVE_CONTROL_PACKAGE_SCHEMA
        || !identifier(value.caseId)
        || !DIGEST_RE.test(value.caseDigest)
        || !DIGEST_RE.test(value.packageDigest)
        || !CAID_RE.test(value.caid)
        || !DIGEST_RE.test(value.actionDigest)
        || !isPlainObject(value.policy)
        || !identifier(value.policy.id)
        || !Number.isSafeInteger(value.policy.version)
        || !DIGEST_RE.test(value.policy.hash)) {
        return null;
    }
    return {
        schema: value.schema,
        case_id: value.caseId,
        case_digest: value.caseDigest,
        package_digest: value.packageDigest,
        caid: value.caid,
        action_digest: value.actionDigest,
        policy: {
            id: value.policy.id,
            version: value.policy.version,
            hash: value.policy.hash,
        },
        raw_phi_included: value.phi?.rawPhiIncluded === true,
    };
}
function proposalProjection(value) {
    if (!isPlainObject(value)
        || !identifier(value.proposal_id)
        || value.profile_id !== HOSPICE_PROPOSAL_PROFILE_ID
        || !identifier(value.operation_id)
        || !identifier(value.initiator_id)
        || !CAID_RE.test(value.caid)
        || !DIGEST_RE.test(value.action_digest)
        || !DIGEST_RE.test(value.aeb_action_digest)
        || !isPlainObject(value.aeb)
        || value.aeb.requirement_ref !== HOSPICE_AEB_REQUIREMENT_REF
        || !DIGEST_RE.test(value.aeb.pinned_config_digest)
        || !DIGEST_RE.test(value.aeb.consumption_nonce)
        || !isPlainObject(value.consequence)
        || !identifier(value.consequence.tenant_id)
        || !identifier(value.consequence.provider_id)
        || !identifier(value.consequence.provider_account_id)
        || value.consequence.environment !== 'sandbox'
        || !identifier(value.consequence.executor_id)
        || !DIGEST_RE.test(value.consequence.request_digest)) {
        return null;
    }
    return {
        proposal_id: value.proposal_id,
        profile_id: value.profile_id,
        operation_id: value.operation_id,
        initiator_id: value.initiator_id,
        caid: value.caid,
        action_digest: value.action_digest,
        aeb_action_digest: value.aeb_action_digest,
        aeb: {
            requirement_ref: value.aeb.requirement_ref,
            pinned_config_digest: value.aeb.pinned_config_digest,
            consumption_nonce: value.aeb.consumption_nonce,
        },
        consequence: {
            tenant_id: value.consequence.tenant_id,
            provider_id: value.consequence.provider_id,
            provider_account_id: value.consequence.provider_account_id,
            environment: value.consequence.environment,
            executor_id: value.consequence.executor_id,
            request_digest: value.consequence.request_digest,
        },
    };
}
function receiptProjection(value) {
    if (!isPlainObject(value)
        || value['@version'] !== 'EP-RECEIPT-v1'
        || !identifier(value.receipt_id)
        || !CAID_RE.test(value.caid)
        || !DIGEST_RE.test(value.action_digest)) {
        return null;
    }
    return {
        '@version': value['@version'],
        receipt_id: value.receipt_id,
        caid: value.caid,
        action_digest: value.action_digest,
    };
}
function aebProjection(value) {
    if (!isPlainObject(value)
        || value['@type'] !== 'AEB-EVALUATION-v1'
        || !identifier(value.operation_id)
        || !DIGEST_RE.test(value.consumption_nonce)
        || !isPlainObject(value.evaluator)
        || !identifier(value.evaluator.id)
        || !identifier(value.evaluator.key_id)
        || !DIGEST_RE.test(value.evaluator.pinned_config_digest)
        || !identifier(value.requirement_ref)
        || !DIGEST_RE.test(value.requirement_digest)
        || !DIGEST_RE.test(value.registry_digest)
        || !CAID_RE.test(value.caid)
        || !isPlainObject(value.composition)
        || !DIGEST_RE.test(value.composition.action_digest)
        || value.verdict !== 'SATISFIED'
        || typeof value.evaluated_at !== 'string'
        || !DIGEST_RE.test(value.evidence_digest)) {
        return null;
    }
    return {
        '@type': value['@type'],
        operation_id: value.operation_id,
        consumption_nonce: value.consumption_nonce,
        evaluator: {
            id: value.evaluator.id,
            key_id: value.evaluator.key_id,
            pinned_config_digest: value.evaluator.pinned_config_digest,
        },
        requirement_ref: value.requirement_ref,
        requirement_digest: value.requirement_digest,
        registry_digest: value.registry_digest,
        caid: value.caid,
        composition_action_digest: value.composition.action_digest,
        verdict: value.verdict,
        evaluated_at: value.evaluated_at,
        evidence_digest: value.evidence_digest,
    };
}
function providerProjection(value, evidenceDigest) {
    if (!isPlainObject(value)
        || value.authenticated !== true
        || !identifier(value.evidence_id)
        || typeof value.observed_at !== 'string'
        || !['COMMITTED', 'NOT_COMMITTED'].includes(value.outcome)
        || !identifier(value.operation_id)
        || !CAID_RE.test(value.caid)
        || !DIGEST_RE.test(value.action_digest)
        || !identifier(value.tenant_id)
        || !DIGEST_RE.test(value.request_digest)
        || !identifier(value.provider_id)
        || !identifier(value.provider_account_id)
        || value.environment !== 'sandbox'
        || !identifier(value.attempt_id)
        || typeof evidenceDigest !== 'string'
        || !DIGEST_RE.test(evidenceDigest)) {
        return null;
    }
    return {
        authenticated: true,
        evidence_id: value.evidence_id,
        evidence_digest: evidenceDigest,
        observed_at: value.observed_at,
        outcome: value.outcome,
        operation_id: value.operation_id,
        caid: value.caid,
        action_digest: value.action_digest,
        tenant_id: value.tenant_id,
        request_digest: value.request_digest,
        provider_id: value.provider_id,
        provider_account_id: value.provider_account_id,
        environment: value.environment,
        attempt_id: value.attempt_id,
    };
}
function assertionBody(role, relyingPartyId, tenantId, operationId, caid, actionDigest, artifactDigest, projection) {
    return {
        role,
        relying_party_id: relyingPartyId,
        tenant_id: tenantId,
        operation_id: operationId,
        caid,
        action_digest: actionDigest,
        artifact_digest: artifactDigest,
        projection: clone(projection),
    };
}
function terminalProjection(decision, proposalToEffect, attemptValue, provider) {
    if (typeof decision !== 'string'
        || !EXPORTABLE_DECISIONS.has(decision)
        || !isPlainObject(proposalToEffect)) {
        return null;
    }
    const attempt = publicAttempt(attemptValue);
    const consequenceAttempt = publicAttempt(proposalToEffect.consequence?.attempt);
    if (!attempt || !consequenceAttempt || digest(attempt) !== digest(consequenceAttempt)) {
        return null;
    }
    const reconciled = RECONCILED_DECISIONS.has(decision);
    const expectedState = decision === 'RECONCILED_NOT_EXECUTED'
        ? 'RELEASED'
        : 'COMMITTED';
    const expectedProviderOutcome = decision === 'RECONCILED_NOT_EXECUTED'
        ? 'NOT_COMMITTED'
        : 'COMMITTED';
    if (proposalToEffect.consequence?.state !== expectedState
        || (reconciled && proposalToEffect.state !== expectedState)
        || (reconciled && proposalToEffect.outcome !== expectedProviderOutcome)
        || (reconciled && provider?.outcome !== expectedProviderOutcome)
        || (!reconciled && provider !== null)) {
        return null;
    }
    return {
        decision,
        proposal_to_effect_state: expectedState,
        provider_outcome: reconciled ? expectedProviderOutcome : null,
        attempt,
        authenticated_reconciliation: reconciled,
        retry_safe: decision === 'RECONCILED_NOT_EXECUTED',
    };
}
function verifyPreparedContext(events, proposal, tenantId) {
    const prepared = [...events].reverse().find((event) => (event.event_type === 'PREPARED'
        && event.payload?.proposal_digest === digest(proposal)));
    if (!prepared || prepared.tenant_id !== tenantId
        || prepared.operation_id !== proposal.operation_id
        || !isPlainObject(prepared.payload?.control_package)) {
        return null;
    }
    try {
        const control = validateControlPackage(prepared.payload.control_package, tenantId);
        if (control.canonical.caid !== proposal.caid
            || control.canonical.action_digest !== proposal.aeb_action_digest
            || control.canonical.action_digest !== proposal.action_digest) {
            return null;
        }
    }
    catch {
        return null;
    }
    return prepared.payload;
}
export function createHealthcareConsequenceControl(options) {
    if (!options?.controller
        || typeof options.controller.prepare !== 'function'
        || typeof options.controller.verifyProposal !== 'function'
        || typeof options.controller.execute !== 'function'
        || typeof options.controller.reconcile !== 'function'
        || typeof options.controller.getReconciliationHandle !== 'function') {
        throw new Error('healthcare_proposal_to_effect_controller_required');
    }
    if (!options.assurance
        || !identifier(options.assurance.relying_party_id)
        || !isPlainObject(options.assurance.signers)
        || !ASSURANCE_ROLES.every((role) => signerShape(options.assurance.signers[role]))
        || new Set(ASSURANCE_ROLES.map((role) => options.assurance.signers[role].key_id)).size !== ASSURANCE_ROLES.length) {
        throw new Error('healthcare_assurance_signers_required');
    }
    if (!options.evidence_store
        || options.evidence_store.appendOnly !== true
        || options.evidence_store.tenantBound !== true
        || typeof options.evidence_store.append !== 'function'
        || typeof options.evidence_store.list !== 'function') {
        throw new Error('healthcare_evidence_store_required');
    }
    if (!options.reconciliation_handle_store
        || options.reconciliation_handle_store.serverSideOnly !== true
        || typeof options.reconciliation_handle_store.put !== 'function'
        || typeof options.reconciliation_handle_store.get !== 'function') {
        throw new Error('healthcare_reconciliation_handle_store_required');
    }
    if (options.allow_ephemeral_stores_for_tests !== true
        && (options.evidence_store.durable !== true
            || options.reconciliation_handle_store.durable !== true)) {
        throw new Error('healthcare_durable_stores_required');
    }
    if (typeof options.mutate_sandbox !== 'function') {
        throw new Error('healthcare_sandbox_mutation_required');
    }
    const now = options.now ?? Date.now;
    function currentTime() {
        const value = now();
        if (!Number.isSafeInteger(value) || !Number.isFinite(new Date(value).getTime())) {
            throw new Error('healthcare_clock_invalid');
        }
        return value;
    }
    async function appendEvent(input) {
        return options.evidence_store.append(clone(input));
    }
    async function prepare(input) {
        if (!identifier(input?.tenant_id))
            return refusal('tenant_required');
        if (!identifier(input?.initiator_id))
            return refusal('authenticated_initiator_required');
        if (!identifier(input?.proposal_id) || !identifier(input?.operation_id)) {
            return refusal('healthcare_operation_identity_invalid');
        }
        let normalized;
        try {
            normalized = normalizeProspectiveControlPackage(input.prospective_control_package, input.tenant_id);
        }
        catch (error) {
            return refusal(safeReason(error, 'healthcare_preparation_refused'));
        }
        const { canonical, finding, control_package: control } = normalized;
        let proposal;
        try {
            proposal = options.controller.prepare({
                proposal_id: input.proposal_id,
                profile_id: HOSPICE_PROPOSAL_PROFILE_ID,
                operation_id: input.operation_id,
                initiator_id: input.initiator_id,
                action: canonical.action,
            });
            const verified = options.controller.verifyProposal(proposal);
            if (verified.proposal.caid !== canonical.caid
                || verified.proposal.action_digest !== canonical.action_digest
                || verified.proposal.aeb_action_digest !== canonical.action_digest
                || verified.proposal.consequence.tenant_id !== input.tenant_id
                || verified.proposal.consequence.environment !== 'sandbox') {
                return refusal('healthcare_proposal_binding_mismatch');
            }
        }
        catch (error) {
            return refusal(safeReason(error, 'healthcare_proposal_preparation_failed'));
        }
        try {
            await appendEvent({
                tenant_id: input.tenant_id,
                operation_id: input.operation_id,
                event_type: 'PREPARED',
                recorded_at: new Date(currentTime()).toISOString(),
                payload: {
                    finding: clone(finding),
                    control_package: clone(control),
                    proposal: clone(proposal),
                    proposal_digest: digest(proposal),
                },
            });
        }
        catch {
            return refusal('healthcare_evidence_store_unavailable');
        }
        return {
            ok: true,
            decision: 'APPROVAL_REQUIRED',
            finding,
            control_package: control,
            proposal,
            authorization: clone(proposal.authorization),
            challenge: clone(proposal.challenge),
        };
    }
    async function execute(input) {
        if (!identifier(input?.tenant_id))
            return refusal('tenant_required');
        if (!isPlainObject(input?.approval_evidence)) {
            return refusal('approval_evidence_required');
        }
        if (!isPlainObject(input?.evaluation)) {
            return refusal('aeb_evaluation_required');
        }
        const evidencePhi = prohibitedPhi({
            approval_evidence: input.approval_evidence,
            evaluation: input.evaluation,
        });
        if (evidencePhi)
            return refusal('healthcare_prohibited_phi');
        let proposal;
        let observed;
        try {
            proposal = options.controller.verifyProposal(input.proposal).proposal;
            observed = canonicalizeHospicePaymentAction(input.observed_action);
        }
        catch (error) {
            return refusal(safeReason(error, 'healthcare_execution_input_refused'));
        }
        if (proposal.consequence.tenant_id !== input.tenant_id
            || proposal.consequence.environment !== 'sandbox') {
            return refusal('tenant_or_environment_mismatch');
        }
        if (observed.caid !== proposal.caid
            || observed.action_digest !== proposal.action_digest
            || observed.action_digest !== proposal.aeb_action_digest) {
            return refusal('execution_action_mismatch');
        }
        let events;
        try {
            events = await options.evidence_store.list({
                tenant_id: input.tenant_id,
                operation_id: proposal.operation_id,
            });
        }
        catch {
            return refusal('healthcare_evidence_store_unavailable');
        }
        const prepared = verifyPreparedContext(events, proposal, input.tenant_id);
        if (!prepared)
            return refusal('healthcare_prepared_context_mismatch');
        const baseEvidence = {
            approval_evidence: clone(input.approval_evidence),
            approval_evidence_digest: digest(input.approval_evidence),
            aeb_evaluation: clone(input.evaluation),
            aeb_evaluation_digest: digest(input.evaluation),
            proposal_digest: digest(proposal),
        };
        try {
            const result = await options.controller.execute({
                proposal,
                receipt: input.approval_evidence,
                evaluation: input.evaluation,
            }, async ({ action, authorization, attempt, proposal: callbackProposal }) => {
                const callbackAction = canonicalizeHospicePaymentAction(action);
                if (callbackProposal.operation_id !== proposal.operation_id
                    || callbackProposal.caid !== proposal.caid
                    || callbackAction.caid !== observed.caid
                    || callbackAction.action_digest !== observed.action_digest
                    || attempt.tenant_id !== input.tenant_id
                    || attempt.provider_id !== proposal.consequence.provider_id
                    || attempt.provider_account_id
                        !== proposal.consequence.provider_account_id
                    || attempt.environment !== 'sandbox'
                    || attempt.request_digest !== proposal.consequence.request_digest) {
                    throw new Error('healthcare_protected_callback_binding_mismatch');
                }
                return options.mutate_sandbox({
                    tenant_id: input.tenant_id,
                    operation_id: proposal.operation_id,
                    action: clone(observed.action),
                    authorization: clone(authorization),
                    attempt: clone(attempt),
                });
            });
            const projected = projectControllerResult(result);
            const state = projected.consequence?.state;
            const attempt = publicAttempt(projected.consequence?.attempt);
            if (state === 'COMMITTED') {
                try {
                    await appendEvent({
                        tenant_id: input.tenant_id,
                        operation_id: proposal.operation_id,
                        event_type: 'EXECUTION',
                        recorded_at: new Date(currentTime()).toISOString(),
                        payload: {
                            ...baseEvidence,
                            decision: 'EXECUTED',
                            proposal_to_effect: projected,
                            attempt,
                        },
                    });
                }
                catch {
                    return {
                        ok: false,
                        decision: 'INDETERMINATE',
                        reason: 'healthcare_assurance_record_unavailable',
                        operation_id: proposal.operation_id,
                        action_caid: proposal.caid,
                        reconciliation_required: true,
                        retry_safe: false,
                    };
                }
                return {
                    ok: true,
                    decision: 'EXECUTED',
                    operation_id: proposal.operation_id,
                    action_caid: proposal.caid,
                    attempt,
                    reconciliation_required: false,
                    retry_safe: false,
                };
            }
            if (state === 'INDETERMINATE') {
                const handle = options.controller.getReconciliationHandle(result);
                if (handle) {
                    await options.reconciliation_handle_store.put({
                        tenant_id: input.tenant_id,
                        operation_id: proposal.operation_id,
                        handle,
                    }).catch(() => undefined);
                }
                await appendEvent({
                    tenant_id: input.tenant_id,
                    operation_id: proposal.operation_id,
                    event_type: 'EXECUTION',
                    recorded_at: new Date(currentTime()).toISOString(),
                    payload: {
                        ...baseEvidence,
                        decision: 'INDETERMINATE',
                        proposal_to_effect: projected,
                        attempt,
                    },
                }).catch(() => undefined);
                return {
                    ok: false,
                    decision: 'INDETERMINATE',
                    reason: identifier(projected.reason)
                        ? projected.reason
                        : 'provider_outcome_indeterminate',
                    operation_id: proposal.operation_id,
                    action_caid: proposal.caid,
                    attempt,
                    reconciliation_required: true,
                    retry_safe: false,
                };
            }
            return refusal(identifier(projected.reason) ? projected.reason : 'proposal_to_effect_refused', {
                operation_id: proposal.operation_id,
                action_caid: proposal.caid,
                retry_safe: state === 'RELEASED',
            });
        }
        catch (error) {
            const metadata = isPlainObject(error?.proposalToEffect)
                ? error.proposalToEffect
                : {};
            const attempt = publicAttempt(metadata.attempt);
            const state = metadata.attempt_state;
            if (state !== 'INDETERMINATE') {
                return refusal(safeReason(error, 'proposal_to_effect_refused'), {
                    operation_id: proposal.operation_id,
                    action_caid: proposal.caid,
                });
            }
            const handle = options.controller.getReconciliationHandle(error);
            if (handle) {
                await options.reconciliation_handle_store.put({
                    tenant_id: input.tenant_id,
                    operation_id: proposal.operation_id,
                    handle,
                }).catch(() => undefined);
            }
            await appendEvent({
                tenant_id: input.tenant_id,
                operation_id: proposal.operation_id,
                event_type: 'EXECUTION',
                recorded_at: new Date(currentTime()).toISOString(),
                payload: {
                    ...baseEvidence,
                    decision: 'INDETERMINATE',
                    proposal_to_effect: {
                        consequence: { state: 'INDETERMINATE', attempt },
                    },
                    attempt,
                },
            }).catch(() => undefined);
            return {
                ok: false,
                decision: 'INDETERMINATE',
                reason: 'provider_outcome_indeterminate',
                operation_id: proposal.operation_id,
                action_caid: proposal.caid,
                attempt,
                reconciliation_required: true,
                retry_safe: false,
            };
        }
    }
    async function reconcile(input) {
        if (!identifier(input?.tenant_id))
            return refusal('tenant_required');
        if (!identifier(input?.operation_id))
            return refusal('operation_id_required');
        if (!isPlainObject(input?.evaluation))
            return refusal('aeb_evaluation_required');
        if (!isPlainObject(input?.provider_evidence)) {
            return refusal('authenticated_provider_evidence_required');
        }
        if (prohibitedPhi(input.provider_evidence)) {
            return refusal('healthcare_prohibited_phi');
        }
        let proposal;
        try {
            proposal = options.controller.verifyProposal(input.proposal, { allowExpired: true }).proposal;
        }
        catch (error) {
            return refusal(safeReason(error, 'healthcare_reconciliation_input_refused'));
        }
        if (proposal.consequence.tenant_id !== input.tenant_id
            || proposal.operation_id !== input.operation_id) {
            return refusal('reconciliation_operation_mismatch');
        }
        let events;
        try {
            events = await options.evidence_store.list({
                tenant_id: input.tenant_id,
                operation_id: input.operation_id,
            });
        }
        catch {
            return refusal('healthcare_evidence_store_unavailable');
        }
        if (!verifyPreparedContext(events, proposal, input.tenant_id)) {
            return refusal('healthcare_prepared_context_mismatch');
        }
        const indeterminate = [...events].reverse().find((event) => (event.event_type === 'EXECUTION'
            && event.payload?.decision === 'INDETERMINATE'));
        const attempt = publicAttempt(indeterminate?.payload?.attempt);
        if (!indeterminate || !attempt) {
            return refusal('reconciliation_not_indeterminate');
        }
        if (input.provider_evidence.operation_id !== input.operation_id) {
            return refusal('provider_evidence_operation_mismatch', {
                decision: 'INDETERMINATE',
                retry_safe: false,
            });
        }
        if (input.provider_evidence.attempt_id !== attempt.attempt_id) {
            return refusal('provider_evidence_attempt_mismatch', {
                decision: 'INDETERMINATE',
                retry_safe: false,
            });
        }
        let handle;
        try {
            handle = await options.reconciliation_handle_store.get({
                tenant_id: input.tenant_id,
                operation_id: input.operation_id,
            });
        }
        catch {
            handle = null;
        }
        if (!handle || handle.tenant_id !== input.tenant_id
            || handle.attempt_id !== attempt.attempt_id) {
            return refusal('reconciliation_handle_unavailable', {
                decision: 'INDETERMINATE',
                retry_safe: false,
            });
        }
        let result;
        try {
            result = await options.controller.reconcile({
                proposal,
                evaluation: input.evaluation,
                attempt: handle,
                provider_evidence: input.provider_evidence,
            });
        }
        catch {
            return refusal('provider_evidence_unverified', {
                decision: 'INDETERMINATE',
                retry_safe: false,
            });
        }
        const projected = projectControllerResult(result);
        if (result.ok !== true) {
            return refusal(identifier(result.reason) ? result.reason : 'provider_evidence_unverified', {
                decision: 'INDETERMINATE',
                operation_id: input.operation_id,
                action_caid: proposal.caid,
                reconciliation_required: true,
                retry_safe: false,
            });
        }
        const state = result.state;
        const decision = state === 'COMMITTED'
            ? 'RECONCILED_EXECUTED'
            : state === 'RELEASED'
                ? 'RECONCILED_NOT_EXECUTED'
                : 'INDETERMINATE';
        const evidenceDigest = DIGEST_RE.test(result.evidence_digest)
            ? result.evidence_digest
            : digest(input.provider_evidence);
        try {
            await appendEvent({
                tenant_id: input.tenant_id,
                operation_id: input.operation_id,
                event_type: 'RECONCILIATION',
                recorded_at: new Date(currentTime()).toISOString(),
                payload: {
                    decision,
                    provider_evidence: clone(input.provider_evidence),
                    provider_evidence_digest: evidenceDigest,
                    authenticated_provider_evidence: true,
                    proposal_to_effect: projected,
                    attempt,
                },
            });
        }
        catch {
            return {
                ok: false,
                decision: 'INDETERMINATE',
                reason: 'healthcare_assurance_record_unavailable',
                operation_id: input.operation_id,
                action_caid: proposal.caid,
                reconciliation_required: true,
                retry_safe: false,
            };
        }
        return {
            ok: decision !== 'INDETERMINATE',
            decision,
            operation_id: input.operation_id,
            action_caid: proposal.caid,
            provider_evidence_digest: evidenceDigest,
            authenticated_provider_evidence: true,
            reconciliation_required: decision === 'INDETERMINATE',
            retry_safe: state === 'RELEASED',
        };
    }
    async function exportAssurancePacket(input) {
        if (!identifier(input?.tenant_id))
            return refusal('tenant_required');
        if (!identifier(input?.operation_id))
            return refusal('operation_id_required');
        let events;
        try {
            events = await options.evidence_store.list({
                tenant_id: input.tenant_id,
                operation_id: input.operation_id,
            });
        }
        catch {
            return refusal('healthcare_evidence_store_unavailable');
        }
        const prepared = events.find((event) => event.event_type === 'PREPARED');
        const execution = [...events].reverse().find((event) => event.event_type === 'EXECUTION');
        const reconciliation = [...events].reverse().find((event) => event.event_type === 'RECONCILIATION');
        const terminal = reconciliation ?? execution;
        if (!prepared || !terminal
            || !EXPORTABLE_DECISIONS.has(terminal.payload?.decision)
            || !isPlainObject(prepared.payload?.proposal)
            || !isPlainObject(prepared.payload?.control_package)) {
            return refusal('healthcare_assurance_packet_not_available');
        }
        const proposal = prepared.payload.proposal;
        if (proposal.operation_id !== input.operation_id
            || proposal.consequence?.tenant_id !== input.tenant_id
            || !verifyPreparedContext(events, proposal, input.tenant_id)) {
            return refusal('healthcare_assurance_evidence_conflict');
        }
        const finding = findingProjection(prepared.payload.finding);
        const control = controlProjection(prepared.payload.control_package);
        const proposalBinding = proposalProjection(proposal);
        const receipt = receiptProjection(execution?.payload?.approval_evidence);
        const aeb = aebProjection(execution?.payload?.aeb_evaluation);
        const provider = reconciliation
            ? providerProjection(reconciliation.payload?.provider_evidence, reconciliation.payload?.provider_evidence_digest)
            : null;
        const terminalProjectionValue = terminalProjection(terminal.payload.decision, terminal.payload.proposal_to_effect, terminal.payload.attempt, provider);
        if (!finding || !control || !proposalBinding || !receipt || !aeb
            || !terminalProjectionValue
            || control.caid !== proposalBinding.caid
            || control.action_digest !== proposalBinding.action_digest
            || receipt.caid !== proposalBinding.caid
            || receipt.action_digest !== proposalBinding.action_digest
            || aeb.operation_id !== input.operation_id
            || aeb.caid !== proposalBinding.caid
            || aeb.requirement_ref !== proposalBinding.aeb.requirement_ref
            || aeb.consumption_nonce !== proposalBinding.aeb.consumption_nonce
            || (RECONCILED_DECISIONS.has(terminal.payload.decision) && !provider)) {
            return refusal('healthcare_assurance_evidence_conflict');
        }
        if (prohibitedPhi({
            finding: prepared.payload.finding,
            control_package: prepared.payload.control_package,
            proposal,
            approval_evidence: execution?.payload?.approval_evidence,
            aeb_evaluation: execution?.payload?.aeb_evaluation,
            provider_evidence: reconciliation?.payload?.provider_evidence,
        })) {
            return refusal('healthcare_assurance_packet_phi_refused');
        }
        let receiptAssertion;
        let aebAssertion;
        let providerAssertion = null;
        try {
            receiptAssertion = await signedAssuranceAssertion('receipt', assertionBody('receipt', options.assurance.relying_party_id, input.tenant_id, input.operation_id, proposal.caid, proposal.action_digest, execution.payload.approval_evidence_digest, receipt), options.assurance.signers.receipt);
            aebAssertion = await signedAssuranceAssertion('aeb', assertionBody('aeb', options.assurance.relying_party_id, input.tenant_id, input.operation_id, proposal.caid, proposal.action_digest, execution.payload.aeb_evaluation_digest, aeb), options.assurance.signers.aeb);
            if (provider) {
                providerAssertion = await signedAssuranceAssertion('provider', assertionBody('provider', options.assurance.relying_party_id, input.tenant_id, input.operation_id, proposal.caid, proposal.action_digest, provider.evidence_digest, provider), options.assurance.signers.provider);
            }
        }
        catch {
            return refusal('healthcare_assurance_signing_failed');
        }
        const packetBody = {
            '@version': HEALTHCARE_ASSURANCE_PACKET_VERSION,
            relying_party_id: options.assurance.relying_party_id,
            profile: {
                id: HOSPICE_PROPOSAL_PROFILE_ID,
                action_type: HOSPICE_ACTION_TYPE,
                environment: 'sandbox',
                synthetic: true,
            },
            tenant_id: input.tenant_id,
            operation_id: input.operation_id,
            finding_projection: finding,
            control_projection: control,
            protocol_evidence: {
                proposal_binding: {
                    artifact_digest: prepared.payload.proposal_digest,
                    projection: proposalBinding,
                },
                receipt: receiptAssertion,
                aeb: aebAssertion,
                ...(providerAssertion ? { provider: providerAssertion } : {}),
            },
            outcome: terminalProjectionValue,
            chronology: events.map((event) => ({
                event_id: event.event_id,
                sequence: event.sequence,
                event_type: event.event_type,
                recorded_at: event.recorded_at,
            })),
            verification_scope: {
                internal_consistency_digest_only: true,
                exact_action_bound_by_signed_safe_projection: true,
                offline_signatures_require_relying_party_pins: true,
                raw_evidence_intentionally_omitted: true,
                population_completeness_established: false,
            },
            limitations: [...HEALTHCARE_ASSURANCE_LIMITATIONS],
            assembled_at: terminal.recorded_at,
        };
        if (prohibitedPhi(packetBody)) {
            return refusal('healthcare_assurance_packet_phi_refused');
        }
        const packet = {
            ...packetBody,
            packet_digest: digest(packetBody),
        };
        try {
            packet.proof = await signAssuranceValue('packet:evaluator', packet, options.assurance.signers.evaluator);
        }
        catch {
            return refusal('healthcare_assurance_signing_failed');
        }
        const consistency = checkHealthcareAssurancePacketInternalConsistency(packet);
        if (!consistency.consistent) {
            return refusal('healthcare_assurance_evidence_conflict');
        }
        return packet;
    }
    return Object.freeze({
        prepare,
        execute,
        reconcile,
        exportAssurancePacket,
    });
}
function assuranceAssertion(value, role) {
    if (!exactKeys(value, ['@version', 'body', 'proof', 'role'])
        || value['@version'] !== HEALTHCARE_ASSURANCE_ASSERTION_VERSION
        || value.role !== role
        || !isPlainObject(value.body)
        || value.body.role !== role
        || !isPlainObject(value.body.projection)
        || !DIGEST_RE.test(value.body.artifact_digest)
        || !assuranceProofShape(value.proof)) {
        return null;
    }
    return value;
}
/**
 * Checks only packet shape, allowlisted projections, digests, and cross-field
 * consistency. It does not establish signer trust or evidence authenticity.
 */
export function checkHealthcareAssurancePacketInternalConsistency(packet) {
    const reasons = [];
    if (!exactKeys(packet, [
        '@version',
        'assembled_at',
        'chronology',
        'control_projection',
        'finding_projection',
        'limitations',
        'operation_id',
        'outcome',
        'packet_digest',
        'profile',
        'proof',
        'protocol_evidence',
        'relying_party_id',
        'tenant_id',
        'verification_scope',
    ]) || packet['@version'] !== HEALTHCARE_ASSURANCE_PACKET_VERSION) {
        return { consistent: false, reasons: ['packet_shape_invalid'] };
    }
    if (prohibitedPhi(packet))
        reasons.push('packet_contains_prohibited_phi');
    const packetBody = clone(packet);
    delete packetBody.packet_digest;
    delete packetBody.proof;
    if (!DIGEST_RE.test(packet.packet_digest)
        || packet.packet_digest !== digest(packetBody)) {
        reasons.push('packet_digest_invalid');
    }
    if (!assuranceProofShape(packet.proof)) {
        reasons.push('packet_proof_shape_invalid');
    }
    if (!identifier(packet.relying_party_id)
        || !identifier(packet.tenant_id)
        || !identifier(packet.operation_id)
        || packet.profile?.id !== HOSPICE_PROPOSAL_PROFILE_ID
        || packet.profile?.action_type !== HOSPICE_ACTION_TYPE
        || packet.profile?.environment !== 'sandbox'
        || packet.profile?.synthetic !== true) {
        reasons.push('packet_profile_invalid');
    }
    const finding = packet.finding_projection;
    const control = packet.control_projection;
    if (!isPlainObject(finding)
        || !identifier(finding.case_id)
        || !DIGEST_RE.test(finding.case_digest)
        || !DIGEST_RE.test(finding.package_digest)
        || !Array.isArray(finding.source_record_digests)
        || !finding.source_record_digests.every((entry) => (typeof entry === 'string' && DIGEST_RE.test(entry)))
        || finding.triage_provenance_only !== true
        || finding.authorization_evidence !== false
        || finding.prior_authorization !== false
        || finding.clinical_judgment !== false
        || finding.fraud_determination !== false
        || finding.payment_authority !== false
        || !isPlainObject(control)
        || control.schema !== PROSPECTIVE_CONTROL_PACKAGE_SCHEMA
        || control.case_id !== finding.case_id
        || control.case_digest !== finding.case_digest
        || control.package_digest !== finding.package_digest
        || !CAID_RE.test(control.caid)
        || !DIGEST_RE.test(control.action_digest)
        || control.raw_phi_included !== false) {
        reasons.push('packet_safe_projection_invalid');
    }
    const proposalBinding = packet.protocol_evidence?.proposal_binding;
    const proposal = proposalProjection(proposalBinding?.projection);
    if (!isPlainObject(proposalBinding)
        || !DIGEST_RE.test(proposalBinding.artifact_digest)
        || !proposal
        || proposal.operation_id !== packet.operation_id
        || proposal.consequence?.tenant_id !== packet.tenant_id
        || proposal.caid !== control?.caid
        || proposal.action_digest !== control?.action_digest
        || proposal.aeb_action_digest !== control?.action_digest) {
        reasons.push('packet_proposal_binding_invalid');
    }
    const receipt = assuranceAssertion(packet.protocol_evidence?.receipt, 'receipt');
    const aeb = assuranceAssertion(packet.protocol_evidence?.aeb, 'aeb');
    const receiptBody = receipt?.body;
    const aebBody = aeb?.body;
    const receiptValue = receiptProjection(receiptBody?.projection);
    const aebValue = aebBody?.projection;
    for (const [role, body] of [['receipt', receiptBody], ['aeb', aebBody]]) {
        if (!body
            || body.relying_party_id !== packet.relying_party_id
            || body.tenant_id !== packet.tenant_id
            || body.operation_id !== packet.operation_id
            || body.caid !== proposal?.caid
            || body.action_digest !== proposal?.action_digest
            || body.role !== role) {
            reasons.push(`packet_${role}_binding_invalid`);
        }
    }
    if (!receiptValue
        || receiptValue.caid !== proposal?.caid
        || receiptValue.action_digest !== proposal?.action_digest) {
        reasons.push('packet_receipt_binding_invalid');
    }
    if (!isPlainObject(aebValue)
        || aebValue['@type'] !== 'AEB-EVALUATION-v1'
        || aebValue.operation_id !== packet.operation_id
        || aebValue.caid !== proposal?.caid
        || aebValue.requirement_ref !== proposal?.aeb?.requirement_ref
        || aebValue.consumption_nonce !== proposal?.aeb?.consumption_nonce
        || aebValue.verdict !== 'SATISFIED'
        || !DIGEST_RE.test(aebValue.consumption_nonce)
        || !DIGEST_RE.test(aebValue.evidence_digest)) {
        reasons.push('packet_aeb_binding_invalid');
    }
    const decision = packet.outcome?.decision;
    const reconciled = RECONCILED_DECISIONS.has(decision);
    const expectedState = decision === 'RECONCILED_NOT_EXECUTED'
        ? 'RELEASED'
        : 'COMMITTED';
    const expectedProviderOutcome = decision === 'RECONCILED_NOT_EXECUTED'
        ? 'NOT_COMMITTED'
        : decision === 'RECONCILED_EXECUTED'
            ? 'COMMITTED'
            : null;
    const attempt = publicAttempt(packet.outcome?.attempt);
    if (!EXPORTABLE_DECISIONS.has(decision)
        || packet.outcome?.proposal_to_effect_state !== expectedState
        || packet.outcome?.provider_outcome !== expectedProviderOutcome
        || packet.outcome?.authenticated_reconciliation !== reconciled
        || packet.outcome?.retry_safe !== (decision === 'RECONCILED_NOT_EXECUTED')) {
        reasons.push('packet_terminal_state_mismatch');
    }
    if (!attempt
        || attempt.tenant_id !== packet.tenant_id
        || attempt.provider_id !== proposal?.consequence?.provider_id
        || attempt.provider_account_id !== proposal?.consequence?.provider_account_id
        || attempt.environment !== proposal?.consequence?.environment
        || attempt.request_digest !== proposal?.consequence?.request_digest) {
        reasons.push('packet_attempt_binding_invalid');
    }
    const provider = assuranceAssertion(packet.protocol_evidence?.provider, 'provider');
    if (reconciled && !provider) {
        reasons.push('packet_reconciliation_evidence_required');
    }
    else if (!reconciled && packet.protocol_evidence?.provider !== undefined) {
        reasons.push('packet_reconciliation_evidence_unexpected');
    }
    else if (provider) {
        const body = provider.body;
        const projected = providerProjection(body.projection, body.projection?.evidence_digest);
        if (!projected
            || body.relying_party_id !== packet.relying_party_id
            || body.tenant_id !== packet.tenant_id
            || body.operation_id !== packet.operation_id
            || body.caid !== proposal?.caid
            || body.action_digest !== proposal?.action_digest
            || body.artifact_digest !== projected.evidence_digest
            || projected.outcome !== expectedProviderOutcome
            || projected.attempt_id !== attempt?.attempt_id
            || projected.request_digest !== attempt?.request_digest
            || projected.provider_id !== attempt?.provider_id
            || projected.provider_account_id !== attempt?.provider_account_id
            || projected.environment !== attempt?.environment) {
            reasons.push('packet_reconciliation_evidence_invalid');
        }
    }
    const expectedTerminalEvent = reconciled ? 'RECONCILIATION' : 'EXECUTION';
    if (!Array.isArray(packet.chronology)
        || packet.chronology.length < 2
        || packet.chronology[0]?.event_type !== 'PREPARED'
        || packet.chronology.at(-1)?.event_type !== expectedTerminalEvent
        || !Array.isArray(packet.limitations)
        || digest(packet.limitations) !== digest(HEALTHCARE_ASSURANCE_LIMITATIONS)) {
        reasons.push('packet_chronology_or_limitations_invalid');
    }
    return {
        consistent: reasons.length === 0,
        reasons: [...new Set(reasons)],
    };
}
function trustPin(value) {
    if (!exactKeys(value, ['key_id', 'public_key_spki_b64u'])
        || !identifier(value.key_id)) {
        return null;
    }
    const der = canonicalBase64url(value.public_key_spki_b64u);
    if (!der)
        return null;
    try {
        const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
        return key.asymmetricKeyType === 'ed25519' ? key : null;
    }
    catch {
        return null;
    }
}
function verifyPinnedSignature(domain, value, proof, pin) {
    if (!assuranceProofShape(proof)
        || !isPlainObject(pin)
        || proof.key_id !== pin.key_id) {
        return false;
    }
    const key = trustPin(pin);
    const signature = canonicalBase64url(proof.signature_b64u, 64);
    if (!key || !signature)
        return false;
    try {
        return crypto.verify(null, signingBytes(domain, value), key, signature);
    }
    catch {
        return false;
    }
}
/** Verify the packet offline using only relying-party-pinned Ed25519 keys. */
export function verifyHealthcareAssurancePacketOffline(packet, trust) {
    const reasons = [
        ...checkHealthcareAssurancePacketInternalConsistency(packet).reasons,
    ];
    if (!exactKeys(trust, [
        '@version',
        'aeb',
        'evaluator',
        'provider',
        'receipt',
        'relying_party_id',
    ]) || trust['@version'] !== HEALTHCARE_ASSURANCE_TRUST_BUNDLE_VERSION
        || !identifier(trust.relying_party_id)
        || !ASSURANCE_ROLES.every((role) => trustPin(trust[role]) !== null)
        || new Set(ASSURANCE_ROLES.map((role) => trust[role].key_id)).size
            !== ASSURANCE_ROLES.length
        || new Set(ASSURANCE_ROLES.map((role) => trust[role].public_key_spki_b64u)).size !== ASSURANCE_ROLES.length) {
        reasons.push('relying_party_trust_bundle_invalid');
    }
    if (!isPlainObject(packet) || !isPlainObject(trust)
        || packet.relying_party_id !== trust.relying_party_id) {
        reasons.push('relying_party_binding_invalid');
        return { valid: false, reasons: [...new Set(reasons)] };
    }
    const packetForSignature = clone(packet);
    const packetProof = packetForSignature.proof;
    delete packetForSignature.proof;
    if (!verifyPinnedSignature('packet:evaluator', packetForSignature, packetProof, trust.evaluator)) {
        reasons.push('evaluator_signature_invalid');
    }
    for (const role of ['receipt', 'aeb', 'provider']) {
        const assertion = packet.protocol_evidence?.[role];
        if (role === 'provider' && assertion === undefined
            && !RECONCILED_DECISIONS.has(packet.outcome?.decision)) {
            continue;
        }
        if (!isPlainObject(assertion)) {
            reasons.push(`${role}_signature_invalid`);
            continue;
        }
        const unsigned = clone(assertion);
        const proof = unsigned.proof;
        delete unsigned.proof;
        if (!verifyPinnedSignature(`assertion:${role}`, unsigned, proof, trust[role])) {
            reasons.push(`${role}_signature_invalid`);
        }
    }
    return { valid: reasons.length === 0, reasons: [...new Set(reasons)] };
}
