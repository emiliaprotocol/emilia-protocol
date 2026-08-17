// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Derive and reconcile two independently signed, privacy-minimized action
 * populations. The runner proves only what the supplied signed populations
 * contain; it never self-proves source-system completeness.
 */
import { RISK_CAID, RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskInstant, riskRecord, signRiskBody, verifyRiskBody, } from './reliance-risk-crypto.js';
import { COVERAGE_RECONCILIATION_ATTESTATION_VERSION, COVERAGE_RECONCILIATION_ATTESTATION_V1_VERSION, signCoverageReconciliationAttestation, } from './coverage-reconciliation-attestation.js';
export const COVERAGE_SOURCE_INVENTORY_VERSION = 'EP-COVERAGE-SOURCE-INVENTORY-v2';
export const COVERAGE_POPULATION_VERSION = 'EP-COVERAGE-POPULATION-v2';
export const COVERAGE_RECONCILIATION_REPORT_VERSION = 'EP-COVERAGE-RECONCILIATION-REPORT-v2';
export const COVERAGE_SOURCE_INVENTORY_V1_VERSION = 'EP-COVERAGE-SOURCE-INVENTORY-v1';
export const COVERAGE_POPULATION_V1_VERSION = 'EP-COVERAGE-POPULATION-v1';
export const COVERAGE_RECONCILIATION_REPORT_V1_VERSION = 'EP-COVERAGE-RECONCILIATION-REPORT-v1';
export const COVERAGE_SOURCE_CLAIM_BOUNDARY = 'signed_root_of_supplied_minimized_records_not_source_completeness';
export const COVERAGE_REPORT_CLAIM_BOUNDARY = 'deterministic_join_of_two_verified_supplied_populations_not_source_completeness';
const MAX_RECORDS = 50_000;
const RECORD_KEYS = ['record_id', 'caid', 'action_digest', 'classification'];
const RULED_RECORD_KEYS = [...RECORD_KEYS, 'classification_rule_id'];
const PERIOD_KEYS = ['start', 'end'];
const SOURCE_BODY_KEYS = [
    '@version', 'inventory_id', 'inventory_kind', 'source_system_id',
    'source_operator_id', 'period', 'record_count', 'population_root',
    'mapping_profile_digest', 'issued_at', 'expires_at', 'claim_boundary',
];
const SYSTEM_CLASSIFICATIONS = new Set(['effect', 'excluded', 'exception']);
const RECEIPT_CLASSIFICATIONS = new Set(['receipt', 'indeterminate']);
const INVENTORY_KINDS = new Set(['system_of_record', 'receipt_population']);
function textOrder(left, right) {
    return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
function period(value) {
    if (!riskExact(value, PERIOD_KEYS))
        return false;
    const start = riskInstant(value.start);
    const end = riskInstant(value.end);
    return Number.isFinite(start) && Number.isFinite(end) && end > start;
}
function samePeriod(left, right) {
    return left.start === right.start && left.end === right.end;
}
function allowedClassification(kind, classification) {
    return typeof classification === 'string'
        && (kind === 'system_of_record'
            ? SYSTEM_CLASSIFICATIONS.has(classification)
            : RECEIPT_CLASSIFICATIONS.has(classification));
}
function joinKey(record) {
    return `${record.caid}\0${record.action_digest}`;
}
function normalizeRecords(kind, records, version = COVERAGE_POPULATION_VERSION) {
    if (!Array.isArray(records) || records.length > MAX_RECORDS) {
        throw new TypeError('coverage population exceeds the record limit');
    }
    const normalized = records.map((record) => {
        const requiresRule = version === COVERAGE_POPULATION_VERSION
            && (record?.classification === 'excluded'
                || record?.classification === 'exception');
        if (!riskExact(record, requiresRule ? RULED_RECORD_KEYS : RECORD_KEYS)
            || !riskIdentifier(record.record_id)
            || !RISK_CAID.test(record.caid)
            || !RISK_DIGEST.test(record.action_digest)
            || !allowedClassification(kind, record.classification)
            || (requiresRule && !riskIdentifier(record.classification_rule_id))) {
            throw new TypeError('coverage population record is invalid');
        }
        return riskClone(record);
    }).sort((left, right) => textOrder(left.record_id, right.record_id));
    const recordIds = new Set();
    const joins = new Set();
    const caidToDigest = new Map();
    const digestToCaid = new Map();
    for (const record of normalized) {
        if (recordIds.has(record.record_id))
            throw new TypeError('coverage population contains a duplicate record id');
        recordIds.add(record.record_id);
        const key = joinKey(record);
        if (joins.has(key))
            throw new TypeError('coverage population contains a duplicate action join');
        joins.add(key);
        const digest = caidToDigest.get(record.caid);
        if (digest !== undefined && digest !== record.action_digest) {
            throw new TypeError('one CAID maps to a different action digest');
        }
        caidToDigest.set(record.caid, record.action_digest);
        const caid = digestToCaid.get(record.action_digest);
        if (caid !== undefined && caid !== record.caid) {
            throw new TypeError('one action digest maps to a different CAID');
        }
        digestToCaid.set(record.action_digest, record.caid);
    }
    return normalized;
}
export function coveragePopulationRoot(kind, records) {
    return coveragePopulationRootForVersion(kind, records, COVERAGE_POPULATION_VERSION);
}
/** Historical v1 root for migration and verification of already-issued artifacts. */
export function coveragePopulationRootV1(kind, records) {
    return coveragePopulationRootForVersion(kind, records, COVERAGE_POPULATION_V1_VERSION);
}
function coveragePopulationRootForVersion(kind, records, version) {
    if (!INVENTORY_KINDS.has(kind))
        throw new TypeError('coverage population kind is invalid');
    return riskDigest({
        '@version': version,
        inventory_kind: kind,
        records: normalizeRecords(kind, records, version),
    });
}
/**
 * Verify only the digest binding between a report and an attestation envelope.
 * Callers MUST separately verify the attestation signature and relying-party
 * context with `verifyCoverageReconciliationAttestation`.
 */
export function verifyCoverageReconciliationReportBinding(report, attestation) {
    if (!riskRecord(report)
        || (report['@version'] !== COVERAGE_RECONCILIATION_REPORT_VERSION
            && report['@version'] !== COVERAGE_RECONCILIATION_REPORT_V1_VERSION)) {
        return { accepted: false, reason: 'coverage_report_invalid', report_hash: null };
    }
    const expectedAttestationVersion = report['@version'] === COVERAGE_RECONCILIATION_REPORT_VERSION
        ? COVERAGE_RECONCILIATION_ATTESTATION_VERSION
        : COVERAGE_RECONCILIATION_ATTESTATION_V1_VERSION;
    if (!riskRecord(attestation)
        || attestation['@version'] !== expectedAttestationVersion
        || !RISK_DIGEST.test(attestation.coverage_report_hash)) {
        return { accepted: false, reason: 'coverage_attestation_invalid', report_hash: null };
    }
    let reportHash;
    try {
        reportHash = riskDigest(report);
    }
    catch {
        return { accepted: false, reason: 'coverage_report_invalid', report_hash: null };
    }
    if (reportHash !== attestation.coverage_report_hash) {
        return { accepted: false, reason: 'coverage_report_hash_mismatch', report_hash: reportHash };
    }
    return { accepted: true, reason: null, report_hash: reportHash };
}
function validateSourceBody(value, version) {
    if (!riskExact(value, SOURCE_BODY_KEYS)
        || value['@version'] !== version
        || !riskIdentifier(value.inventory_id)
        || !INVENTORY_KINDS.has(value.inventory_kind)
        || !riskIdentifier(value.source_system_id)
        || !riskIdentifier(value.source_operator_id)
        || !period(value.period)
        || !Number.isSafeInteger(value.record_count)
        || value.record_count < 0
        || value.record_count > MAX_RECORDS
        || !RISK_DIGEST.test(value.population_root)
        || !RISK_DIGEST.test(value.mapping_profile_digest)
        || value.claim_boundary !== COVERAGE_SOURCE_CLAIM_BOUNDARY) {
        throw new TypeError('coverage source inventory shape is invalid');
    }
    const issued = riskInstant(value.issued_at);
    const expires = riskInstant(value.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expires)
        || issued < riskInstant(value.period.end) || expires <= issued) {
        throw new TypeError('coverage source inventory validity window is invalid');
    }
}
export function signCoverageSourceInventory(input, records, signer) {
    const normalized = normalizeRecords(input.inventory_kind, records);
    const body = {
        '@version': COVERAGE_SOURCE_INVENTORY_VERSION,
        ...riskClone(input),
        record_count: normalized.length,
        population_root: coveragePopulationRoot(input.inventory_kind, normalized),
        claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
    };
    validateSourceBody(body, COVERAGE_SOURCE_INVENTORY_VERSION);
    if (signer.issuer_id !== body.source_operator_id) {
        throw new TypeError('coverage source inventory issuer must be the source operator');
    }
    return signRiskBody(COVERAGE_SOURCE_INVENTORY_VERSION, body, signer);
}
export function verifyCoverageSourceInventory(artifact, records, options = {}) {
    const refuse = (reason, verified = false, inventoryDigest = null) => ({
        accepted: false,
        verified,
        reason,
        inventory_digest: inventoryDigest,
        claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
    });
    const inventoryVersion = riskRecord(artifact)
        && artifact['@version'] === COVERAGE_SOURCE_INVENTORY_V1_VERSION
        ? COVERAGE_SOURCE_INVENTORY_V1_VERSION
        : COVERAGE_SOURCE_INVENTORY_VERSION;
    const populationVersion = inventoryVersion === COVERAGE_SOURCE_INVENTORY_VERSION
        ? COVERAGE_POPULATION_VERSION
        : COVERAGE_POPULATION_V1_VERSION;
    const signed = verifyRiskBody(artifact, inventoryVersion, options.trusted_keys);
    if (!signed.valid || !signed.body)
        return refuse(signed.reason ?? 'inventory_invalid');
    const { issuer, ...payload } = signed.body;
    if (issuer.id !== payload.source_operator_id) {
        return refuse('source_operator_issuer_mismatch', true, signed.artifact_digest);
    }
    try {
        validateSourceBody(payload, inventoryVersion);
    }
    catch {
        return refuse('inventory_schema_invalid', true, signed.artifact_digest);
    }
    if (options.expected_inventory_kind === undefined
        || options.expected_source_system_id === undefined
        || options.expected_mapping_profile_digest === undefined) {
        return refuse('context_binding_required', true, signed.artifact_digest);
    }
    if (payload.inventory_kind !== options.expected_inventory_kind) {
        return refuse('inventory_kind_mismatch', true, signed.artifact_digest);
    }
    if (payload.source_system_id !== options.expected_source_system_id) {
        return refuse('source_system_mismatch', true, signed.artifact_digest);
    }
    if (payload.mapping_profile_digest !== options.expected_mapping_profile_digest) {
        return refuse('mapping_profile_mismatch', true, signed.artifact_digest);
    }
    if (options.expected_source_operator_id !== undefined
        && payload.source_operator_id !== options.expected_source_operator_id) {
        return refuse('source_operator_mismatch', true, signed.artifact_digest);
    }
    const now = options.now === undefined
        ? Date.now()
        : (typeof options.now === 'string' ? Date.parse(options.now) : Number(options.now));
    if (!Number.isFinite(now))
        return refuse('verification_time_invalid', true, signed.artifact_digest);
    if (now < riskInstant(payload.issued_at))
        return refuse('inventory_not_yet_issued', true, signed.artifact_digest);
    if (now >= riskInstant(payload.expires_at))
        return refuse('inventory_expired', true, signed.artifact_digest);
    let root;
    try {
        root = coveragePopulationRootForVersion(payload.inventory_kind, records, populationVersion);
    }
    catch {
        return refuse('population_invalid', true, signed.artifact_digest);
    }
    if (records.length !== payload.record_count) {
        return refuse('population_count_mismatch', true, signed.artifact_digest);
    }
    if (root !== payload.population_root) {
        return refuse('population_root_mismatch', true, signed.artifact_digest);
    }
    return {
        accepted: true,
        verified: true,
        reason: null,
        inventory_digest: signed.artifact_digest,
        body: riskFreeze(riskClone(payload)),
        claim_boundary: COVERAGE_SOURCE_CLAIM_BOUNDARY,
    };
}
function assertCrossPopulationIdentity(systemRecords, receiptRecords) {
    const caids = new Map();
    const digests = new Map();
    for (const record of [...systemRecords, ...receiptRecords]) {
        const existingDigest = caids.get(record.caid);
        if (existingDigest !== undefined && existingDigest !== record.action_digest) {
            throw new TypeError('one CAID maps to a different action digest across populations');
        }
        caids.set(record.caid, record.action_digest);
        const existingCaid = digests.get(record.action_digest);
        if (existingCaid !== undefined && existingCaid !== record.caid) {
            throw new TypeError('one action digest maps to a different CAID across populations');
        }
        digests.set(record.action_digest, record.caid);
    }
}
function requiredPin(pin) {
    if (!riskRecord(pin)
        || !riskIdentifier(pin.source_system_id)
        || !RISK_DIGEST.test(pin.mapping_profile_digest)
        || (pin.source_operator_id !== undefined && !riskIdentifier(pin.source_operator_id))) {
        throw new TypeError('coverage source pin is invalid');
    }
}
export function runCoverageReconciliation(input, options, signer) {
    if (!riskRecord(input)
        || !riskIdentifier(input.run_id)
        || !riskIdentifier(input.attestation_id)
        || !riskIdentifier(input.relying_party_id)
        || !period(input.period)
        || !RISK_DIGEST.test(input.census_digest)
        || !riskRecord(input.system_of_record)
        || !riskRecord(input.receipt_population)) {
        throw new TypeError('coverage reconciliation input is invalid');
    }
    requiredPin(options.system_of_record_pin);
    requiredPin(options.receipt_population_pin);
    const systemVerification = verifyCoverageSourceInventory(input.system_of_record.artifact, input.system_of_record.records, {
        trusted_keys: options.trusted_keys,
        now: options.now,
        expected_inventory_kind: 'system_of_record',
        expected_source_system_id: options.system_of_record_pin.source_system_id,
        expected_mapping_profile_digest: options.system_of_record_pin.mapping_profile_digest,
        expected_source_operator_id: options.system_of_record_pin.source_operator_id,
    });
    if (!systemVerification.accepted || !('body' in systemVerification)) {
        throw new TypeError(`system-of-record inventory refused: ${systemVerification.reason}`);
    }
    const receiptVerification = verifyCoverageSourceInventory(input.receipt_population.artifact, input.receipt_population.records, {
        trusted_keys: options.trusted_keys,
        now: options.now,
        expected_inventory_kind: 'receipt_population',
        expected_source_system_id: options.receipt_population_pin.source_system_id,
        expected_mapping_profile_digest: options.receipt_population_pin.mapping_profile_digest,
        expected_source_operator_id: options.receipt_population_pin.source_operator_id,
    });
    if (!receiptVerification.accepted || !('body' in receiptVerification)) {
        throw new TypeError(`receipt inventory refused: ${receiptVerification.reason}`);
    }
    const systemBody = systemVerification.body;
    const receiptBody = receiptVerification.body;
    if (!samePeriod(systemBody.period, input.period)
        || !samePeriod(receiptBody.period, input.period)) {
        throw new TypeError('coverage source inventory period mismatch');
    }
    if (options.require_independent_source_issuers !== false
        && systemBody.source_operator_id === receiptBody.source_operator_id) {
        throw new TypeError('coverage reconciliation requires independent source issuers');
    }
    const systemRecords = normalizeRecords('system_of_record', input.system_of_record.records);
    const receiptRecords = normalizeRecords('receipt_population', input.receipt_population.records);
    assertCrossPopulationIdentity(systemRecords, receiptRecords);
    const availableReceipts = new Map(receiptRecords
        .filter((record) => record.classification === 'receipt')
        .map((record) => [joinKey(record), record]));
    const matched = [];
    const observedWithoutReceipt = [];
    const excluded = [];
    const exception = [];
    for (const record of systemRecords) {
        if (record.classification === 'excluded') {
            excluded.push(record);
            continue;
        }
        if (record.classification === 'exception') {
            exception.push(record);
            continue;
        }
        const receipt = availableReceipts.get(joinKey(record));
        if (!receipt) {
            observedWithoutReceipt.push(record);
            continue;
        }
        availableReceipts.delete(joinKey(record));
        matched.push({
            caid: record.caid,
            action_digest: record.action_digest,
            system_record_id: record.record_id,
            receipt_record_id: receipt.record_id,
        });
    }
    const receiptedWithoutObservation = [...availableReceipts.values()]
        .sort((left, right) => textOrder(left.record_id, right.record_id));
    const indeterminate = receiptRecords
        .filter((record) => record.classification === 'indeterminate');
    const joins = {
        matched: matched.length,
        observed_without_receipt: observedWithoutReceipt.length,
        receipted_without_observation: receiptedWithoutObservation.length,
        indeterminate: indeterminate.length,
        excluded: excluded.length,
        exception: exception.length,
    };
    const generated = riskInstant(input.generated_at);
    const expires = riskInstant(input.expires_at);
    if (!Number.isFinite(generated) || !Number.isFinite(expires)
        || generated < riskInstant(input.period.end) || expires <= generated) {
        throw new TypeError('coverage reconciliation report validity window is invalid');
    }
    const report = riskFreeze({
        '@version': COVERAGE_RECONCILIATION_REPORT_VERSION,
        run_id: input.run_id,
        relying_party_id: input.relying_party_id,
        program: riskClone(input.program),
        period: riskClone(input.period),
        system_of_record: {
            inventory_id: systemBody.inventory_id,
            source_system_id: systemBody.source_system_id,
            source_operator_id: systemBody.source_operator_id,
            inventory_digest: systemVerification.inventory_digest,
            population_root: systemBody.population_root,
            count: systemBody.record_count,
        },
        receipt_population: {
            inventory_id: receiptBody.inventory_id,
            source_system_id: receiptBody.source_system_id,
            source_operator_id: receiptBody.source_operator_id,
            inventory_digest: receiptVerification.inventory_digest,
            population_root: receiptBody.population_root,
            count: receiptBody.record_count,
        },
        joins,
        findings: {
            matched,
            observed_without_receipt: observedWithoutReceipt,
            receipted_without_observation: receiptedWithoutObservation,
            indeterminate,
            excluded,
            exception,
        },
        generated_at: input.generated_at,
        claim_boundary: COVERAGE_REPORT_CLAIM_BOUNDARY,
    });
    const reportHash = riskDigest(report);
    const attestation = signCoverageReconciliationAttestation({
        attestation_id: input.attestation_id,
        relying_party_id: input.relying_party_id,
        program: riskClone(input.program),
        period: riskClone(input.period),
        coverage_report_hash: reportHash,
        census_digest: input.census_digest,
        system_of_record: {
            inventory_id: systemBody.inventory_id,
            population_root: systemBody.population_root,
            count: systemBody.record_count,
        },
        receipt_population: {
            inventory_id: receiptBody.inventory_id,
            population_root: receiptBody.population_root,
            count: receiptBody.record_count,
        },
        joins,
        issued_at: input.generated_at,
        expires_at: input.expires_at,
        timestamp_anchor: riskClone(input.timestamp_anchor),
        claim_boundary: 'signed_reconciliation_of_supplied_populations_not_population_completeness',
    }, signer);
    return riskFreeze({ report, report_hash: reportHash, attestation });
}
//# sourceMappingURL=coverage-reconciliation-runner.js.map