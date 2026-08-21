// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * CAP-1 composition for EMILIA coverage reconciliation.
 *
 * CAP-1 carries a producer's declared coverage statement. EMILIA does not
 * reinterpret that statement. This module calls relying-party-selected CAP-1
 * and examined-set verifiers, then requires the exact CAP-1 document digest to
 * be the census_digest inside a hybrid coverage-reconciliation attestation. The same
 * signed attestation binds the supplied population roots and the relying
 * party's reconciliation program.
 *
 * Nothing here proves that a supplied population is complete, that an
 * enumeration was honest, or that an examination was technically adequate.
 */
import { RISK_DIGEST, riskClone, riskDigest, riskExact, riskFreeze, riskIdentifier, riskRecord, } from './reliance-risk-crypto.js';
import { COVERAGE_RECONCILIATION_ATTESTATION_V3_VERSION, verifyCoverageReconciliationAttestationV3, } from './coverage-reconciliation-attestation.js';
import { COVERAGE_RECONCILIATION_REPORT_VERSION, COVERAGE_REPORT_CLAIM_BOUNDARY, verifyCoverageReconciliationReportBindingV3, } from './coverage-reconciliation-runner.js';
export const CAP1_COVERAGE_COMPOSITION_PROFILE = 'EP-CAP1-COVERAGE-COMPOSITION-v1';
export const CAP1_COVERAGE_SUBJECT_COMMITMENT_VERSION = 'EP-CAP1-COVERAGE-SUBJECT-COMMITMENT-v1';
export const CAP1_DOCUMENT_DIGEST_PROFILE = 'EP-CANONICAL-JSON-SHA256-v1';
export const CAP1_COVERAGE_COMPOSITION_CLAIM_BOUNDARY = 'authenticated_cap1_statement_and_supplied_set_commitments_under_pinned_reconciliation_program_not_source_population_completeness_or_honest_enumeration_or_examination_quality';
/**
 * EMILIA's reproducibility pin for the exact public bundle reviewed here.
 * CAP-1 -00 does not normatively identify its repository schema, vectors,
 * implementations, or fixtures. This lock is therefore an EMILIA pin, not a
 * claim that CAP-1 retroactively made those files normative.
 */
export const CAP1_OBSERVED_BUNDLE_SOURCE_LOCK = riskFreeze({
    profile: 'EP-CAP1-OBSERVED-BUNDLE-SOURCE-LOCK-v1',
    repository: 'https://github.com/Certisyn-Inc/certisyn-drafts',
    commit: '0980d3201aa2caab3cbad5c6e9bc99b422370b43',
    tree_path: 'cap-1',
    draft: {
        path: 'cap-1/draft-hillier-coverage-attestation-00.txt',
        sha256: '7a9eeb1fbdb1fee95697622546d2ae7efba762fff193d6ee34765233539ac353',
    },
    schema: {
        path: 'cap-1/src/CAP-1.schema.json',
        sha256: '4453f216089543780bfecc4295cc4a61462fdc585b88d1e35b7d1aba79716b4a',
    },
    vector_manifest: {
        path: 'cap-1/src/vectors/manifest.json',
        sha256: '170aa81efc74c5278a2fb6e3bcc22bc91fb1706e9fb8faf1ce6d575e5ce3d965',
    },
    vector_bundle_sha256: '327e7516e4838f616a06e5a81fa583b8125f85cf2ae277849c2e9fd08d77a72b',
    claim_boundary: 'emilia_reproduction_pin_not_cap1_normative_identification',
});
export const CAP1_OBSERVED_BUNDLE_SOURCE_LOCK_DIGEST = riskDigest(CAP1_OBSERVED_BUNDLE_SOURCE_LOCK);
const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'];
const POPULATION_PIN_KEYS = [
    'inventory_id',
    'population_root',
    'eligible_set_root',
    'examined_set_root',
    'eligible_count',
    'examined_count',
    'stratum_id',
];
const CAP1_VERIFICATION_RESULT_KEYS = [
    'verdict', 'primary_rule', 'source', 'document_digest', 'violations',
];
const CAP1_SOURCE_KEYS = [
    'specification', 'source_repository', 'source_commit', 'specification_sha256',
    'schema_sha256', 'observed_vector_manifest_sha256',
];
const EXAMINED_SET_RESULT_KEYS = ['verdict', 'verified'];
const EXAMINATION_PROFILE_KEYS = [
    'technique_id', 'technique_version', 'technique_digest', 'depth_id', 'depth_digest',
];
function validExaminationProfile(value) {
    return riskExact(value, EXAMINATION_PROFILE_KEYS)
        && riskIdentifier(value.technique_id)
        && Number.isSafeInteger(value.technique_version)
        && value.technique_version >= 1
        && RISK_DIGEST.test(value.technique_digest)
        && riskIdentifier(value.depth_id)
        && RISK_DIGEST.test(value.depth_digest);
}
function validProgram(value) {
    return riskExact(value, PROGRAM_KEYS)
        && riskIdentifier(value.program_id)
        && Number.isSafeInteger(value.version)
        && value.version >= 1
        && RISK_DIGEST.test(value.source_digest)
        && RISK_DIGEST.test(value.program_digest);
}
function sameProgram(actual, expected) {
    return riskExact(actual, PROGRAM_KEYS)
        && actual.program_id === expected.program_id
        && actual.version === expected.version
        && actual.source_digest === expected.source_digest
        && actual.program_digest === expected.program_digest;
}
function validCount(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0;
}
function validPopulationPin(value) {
    return riskExact(value, POPULATION_PIN_KEYS)
        && riskIdentifier(value.inventory_id)
        && RISK_DIGEST.test(value.population_root)
        && RISK_DIGEST.test(value.eligible_set_root)
        && RISK_DIGEST.test(value.examined_set_root)
        && validCount(value.eligible_count)
        && validCount(value.examined_count)
        && value.examined_count <= value.eligible_count
        && typeof value.stratum_id === 'string'
        && /^[a-z0-9][a-z0-9._-]*$/.test(value.stratum_id);
}
function populationCommitment(pin) {
    return {
        inventory_id: pin.inventory_id,
        population_root: pin.population_root,
        eligible_set_root: pin.eligible_set_root,
        examined_set_root: pin.examined_set_root,
        eligible_count: pin.eligible_count,
        examined_count: pin.examined_count,
        stratum_id: pin.stratum_id,
    };
}
/**
 * Canonical commitment referenced by CAP-1 subject.digest. It binds the exact
 * observed CAP-1 bundle pin, named reconciliation program, and both supplied
 * eligible and examined set commitments.
 */
export function cap1CoverageSubjectCommitment(input) {
    if (!validProgram(input.program)
        || !riskIdentifier(input.claim_class_id)
        || !validExaminationProfile(input.examination_profile)
        || !validPopulationPin(input.system_of_record)
        || !validPopulationPin(input.receipt_population)
        || input.system_of_record.stratum_id === input.receipt_population.stratum_id) {
        throw new TypeError('CAP-1 coverage subject commitment input is invalid');
    }
    return riskFreeze({
        '@version': CAP1_COVERAGE_SUBJECT_COMMITMENT_VERSION,
        cap1_bundle: riskClone(CAP1_OBSERVED_BUNDLE_SOURCE_LOCK),
        cap1_bundle_source_lock_digest: CAP1_OBSERVED_BUNDLE_SOURCE_LOCK_DIGEST,
        cap1_document_digest_profile: CAP1_DOCUMENT_DIGEST_PROFILE,
        reconciliation_program: riskClone(input.program),
        claim_class_id: input.claim_class_id,
        examination_profile: riskClone(input.examination_profile),
        populations: {
            system_of_record: populationCommitment(input.system_of_record),
            receipt_population: populationCommitment(input.receipt_population),
        },
        claim_boundary: CAP1_COVERAGE_COMPOSITION_CLAIM_BOUNDARY,
    });
}
/** SHA-256 digest shape required in CAP-1 subject.digest for this composition. */
export function cap1CoverageSubjectDigest(input) {
    return riskFreeze({
        algorithm: 'SHA-256',
        value: riskDigest(cap1CoverageSubjectCommitment(input)).slice('sha256:'.length),
    });
}
function cap1CountsMatch(document, systemPin, receiptPin) {
    if (!Array.isArray(document.strata))
        return false;
    const system = document.strata.find((stratum) => riskRecord(stratum) && stratum.id === systemPin.stratum_id);
    const receipt = document.strata.find((stratum) => riskRecord(stratum) && stratum.id === receiptPin.stratum_id);
    return riskRecord(system)
        && riskRecord(receipt)
        && system.eligible === systemPin.eligible_count
        && system.examined === systemPin.examined_count
        && receipt.eligible === receiptPin.eligible_count
        && receipt.examined === receiptPin.examined_count;
}
function cap1SubjectMatches(document, program, claimClassId, examinationProfile, systemPin, receiptPin) {
    if (!riskRecord(document.subject)
        || document.subject.kind !== 'coverage-population-set'
        || !riskRecord(document.subject.digest))
        return false;
    const expected = cap1CoverageSubjectDigest({
        program,
        claim_class_id: claimClassId,
        examination_profile: examinationProfile,
        system_of_record: systemPin,
        receipt_population: receiptPin,
    });
    return document.subject.digest.algorithm === expected.algorithm
        && document.subject.digest.value === expected.value;
}
function reportPopulationMatches(value, expected) {
    return riskRecord(value)
        && value.inventory_id === expected.inventory_id
        && value.population_root === expected.population_root
        && value.count === expected.eligible_count;
}
function attestationPopulationMatches(value, expected) {
    return reportPopulationMatches(value, expected);
}
function validNativeResult(value) {
    return riskExact(value, CAP1_VERIFICATION_RESULT_KEYS)
        && (value.verdict === 'CONFORMS' || value.verdict === 'REFUSES')
        && (value.primary_rule === null || typeof value.primary_rule === 'string')
        && riskExact(value.source, CAP1_SOURCE_KEYS)
        && value.source.source_repository === CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.repository
        && value.source.source_commit === CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.commit
        && value.source.specification_sha256 === CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.draft.sha256
        && value.source.schema_sha256 === CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.schema.sha256
        && value.source.observed_vector_manifest_sha256
            === CAP1_OBSERVED_BUNDLE_SOURCE_LOCK.vector_manifest.sha256
        && (value.document_digest === null || RISK_DIGEST.test(value.document_digest))
        && Array.isArray(value.violations);
}
function validExaminedSetResult(value, systemPin, receiptPin) {
    if (!riskExact(value, EXAMINED_SET_RESULT_KEYS)
        || value.verdict !== 'SATISFIED'
        || !Array.isArray(value.verified)
        || value.verified.length !== 2)
        return false;
    const expected = [systemPin, receiptPin];
    return expected.every((pin) => value.verified.some((entry) => (riskExact(entry, ['stratum', 'eligible_set_digest', 'examined_set_digest', 'result_bindings'])
        && entry.stratum === pin.stratum_id
        && entry.eligible_set_digest === pin.eligible_set_root
        && entry.examined_set_digest === pin.examined_set_root
        && entry.result_bindings === pin.examined_count)));
}
/**
 * Verify CAP-1 and EMILIA as two distinct legs joined by exact commitments.
 * The CAP-1 verifier establishes native conformance only. The hybrid EMILIA
 * attestation authenticates the exact CAP-1 bytes, roots, counts, program, and
 * report hash under the relying party's pinned Ed25519 and ML-DSA-65 keys.
 */
export async function verifyCap1CoverageComposition(input, options) {
    const refuse = (reason, cap1DocumentDigest = null) => riskFreeze({
        accepted: false,
        verified: false,
        reason,
        profile: CAP1_COVERAGE_COMPOSITION_PROFILE,
        cap1_document_digest: cap1DocumentDigest,
        claim_boundary: CAP1_COVERAGE_COMPOSITION_CLAIM_BOUNDARY,
    });
    if (!riskRecord(input)
        || !riskRecord(options)
        || !validProgram(options.expected_program)
        || !riskIdentifier(options.expected_relying_party_id)
        || !validPopulationPin(options.system_of_record)
        || !validPopulationPin(options.receipt_population)
        || !riskIdentifier(options.claim_class_id)
        || !validExaminationProfile(options.examination_profile)
        || options.system_of_record.stratum_id === options.receipt_population.stratum_id
        || typeof options.verify_cap1 !== 'function'
        || typeof options.verify_examined_set_evidence !== 'function') {
        return refuse('composition_context_invalid');
    }
    let cap1Document;
    let cap1DocumentDigest;
    try {
        cap1Document = riskClone(input.cap1_document);
        if (!riskRecord(cap1Document) || cap1Document.profile !== 'cap/1') {
            return refuse('cap1_document_invalid');
        }
        cap1DocumentDigest = riskDigest(cap1Document);
    }
    catch {
        return refuse('cap1_document_invalid');
    }
    let native;
    try {
        native = await options.verify_cap1(riskClone(cap1Document));
    }
    catch {
        return refuse('cap1_verifier_error', cap1DocumentDigest);
    }
    if (!validNativeResult(native)) {
        return refuse('cap1_verifier_result_invalid', cap1DocumentDigest);
    }
    if (native.verdict !== 'CONFORMS') {
        return refuse('cap1_native_refused', cap1DocumentDigest);
    }
    if (native.document_digest !== cap1DocumentDigest) {
        return refuse('cap1_document_digest_mismatch', cap1DocumentDigest);
    }
    let examinedSetVerification;
    try {
        examinedSetVerification = await options.verify_examined_set_evidence(riskClone(cap1Document), riskClone(input.examined_set_evidence));
    }
    catch {
        return refuse('cap1_examined_set_verifier_error', cap1DocumentDigest);
    }
    if (!riskRecord(examinedSetVerification)) {
        return refuse('cap1_examined_set_verifier_result_invalid', cap1DocumentDigest);
    }
    if (examinedSetVerification.verdict !== 'SATISFIED') {
        return refuse('cap1_examined_set_refused', cap1DocumentDigest);
    }
    if (!validExaminedSetResult(examinedSetVerification, options.system_of_record, options.receipt_population)) {
        return refuse('cap1_examined_set_binding_mismatch', cap1DocumentDigest);
    }
    if (!cap1CountsMatch(cap1Document, options.system_of_record, options.receipt_population)) {
        return refuse('cap1_population_count_binding_mismatch', cap1DocumentDigest);
    }
    if (!cap1SubjectMatches(cap1Document, options.expected_program, options.claim_class_id, options.examination_profile, options.system_of_record, options.receipt_population)) {
        return refuse('cap1_subject_commitment_mismatch', cap1DocumentDigest);
    }
    const reportBinding = verifyCoverageReconciliationReportBindingV3(input.coverage_report, input.coverage_attestation);
    if (!reportBinding.accepted || reportBinding.report_hash === null) {
        return refuse(reportBinding.reason ?? 'coverage_report_refused', cap1DocumentDigest);
    }
    const attestation = await verifyCoverageReconciliationAttestationV3(input.coverage_attestation, {
        trusted_keys: options.trusted_keys,
        now: options.now,
        expected_program: options.expected_program,
        expected_census_digest: cap1DocumentDigest,
        expected_relying_party_id: options.expected_relying_party_id,
        expected_coverage_report_hash: reportBinding.report_hash,
        ...(options.mldsaBackend === undefined ? {} : { mldsaBackend: options.mldsaBackend }),
        ...(options.mldsaBackendLoader === undefined ? {} : { mldsaBackendLoader: options.mldsaBackendLoader }),
    });
    if (!attestation.accepted) {
        return refuse(attestation.reason ?? 'coverage_attestation_refused', cap1DocumentDigest);
    }
    if (!riskRecord(input.coverage_report)
        || input.coverage_report['@version'] !== COVERAGE_RECONCILIATION_REPORT_VERSION
        || input.coverage_report.claim_boundary !== COVERAGE_REPORT_CLAIM_BOUNDARY
        || input.coverage_report.relying_party_id !== options.expected_relying_party_id
        || !sameProgram(input.coverage_report.program, options.expected_program)
        || !reportPopulationMatches(input.coverage_report.system_of_record, options.system_of_record)
        || !reportPopulationMatches(input.coverage_report.receipt_population, options.receipt_population)) {
        return refuse('coverage_report_context_mismatch', cap1DocumentDigest);
    }
    if (!riskRecord(input.coverage_attestation)
        || input.coverage_attestation['@version'] !== COVERAGE_RECONCILIATION_ATTESTATION_V3_VERSION
        || input.coverage_attestation.census_digest !== cap1DocumentDigest
        || !attestationPopulationMatches(input.coverage_attestation.system_of_record, options.system_of_record)
        || !attestationPopulationMatches(input.coverage_attestation.receipt_population, options.receipt_population)) {
        return refuse('coverage_attestation_context_mismatch', cap1DocumentDigest);
    }
    return riskFreeze({
        accepted: true,
        verified: true,
        reason: null,
        profile: CAP1_COVERAGE_COMPOSITION_PROFILE,
        cap1: {
            native_conformance: true,
            examined_set_evidence: true,
            document_digest: cap1DocumentDigest,
            document_digest_profile: CAP1_DOCUMENT_DIGEST_PROFILE,
            observed_bundle: riskClone(CAP1_OBSERVED_BUNDLE_SOURCE_LOCK),
            observed_bundle_source_lock_digest: CAP1_OBSERVED_BUNDLE_SOURCE_LOCK_DIGEST,
        },
        reconciliation: {
            relying_party_id: options.expected_relying_party_id,
            program: riskClone(options.expected_program),
            claim_class_id: options.claim_class_id,
            examination_profile: riskClone(options.examination_profile),
            report_hash: reportBinding.report_hash,
            attestation_digest: attestation.attestation_digest,
            system_of_record: populationCommitment(options.system_of_record),
            receipt_population: populationCommitment(options.receipt_population),
            signature_profile: 'EP-RISK-HYBRID-v2',
            required_algorithms: ['Ed25519', 'ML-DSA-65'],
        },
        nonclaims: [
            'source_population_completeness',
            'honest_enumeration',
            'examination_quality',
            'underlying_source_truth',
            'authorization',
            'execution_or_effect',
        ],
        claim_boundary: CAP1_COVERAGE_COMPOSITION_CLAIM_BOUNDARY,
    });
}
//# sourceMappingURL=cap1-coverage-composition.js.map