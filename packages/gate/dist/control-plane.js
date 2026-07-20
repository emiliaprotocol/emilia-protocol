// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Vendor-neutral orchestration for Gate coverage, evidence completeness, and
 * usage metering. Enforcement still happens at each executor-side Gate. This
 * module cannot turn an observation or dashboard decision into authorization.
 */
import { canonicalize, hashCanonical } from './execution-binding.js';
import { coverageInventoryDigest, evaluateGateCoverage } from './coverage.js';
import { evaluateSettlementEligibility } from './settlement.js';
import { meterUsage, buildUsageStatement } from './metering.js';
import { acceptNetworkWitnessStatement, networkWitnessDigest } from './network-witness.js';
export const CONTROL_PLANE_REPORT_VERSION = 'EP-GATE-CONTROL-PLANE-REPORT-v1';
export const CONTROL_PLANE_MAX_SETTLEMENTS = 10_000;
const MAX_COVERAGE_EVIDENCE_ITEMS = 50_000;
function isPlainObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function digest(value) {
    return `sha256:${hashCanonical(value)}`;
}
function witnessArtifactKey(statement) {
    try {
        return digest(statement);
    }
    catch {
        return null;
    }
}
function immutableCanonicalSnapshot(value) {
    const snapshot = JSON.parse(canonicalize(value));
    const stack = [snapshot];
    while (stack.length) {
        const current = stack.pop();
        if (current && typeof current === 'object') {
            for (const child of Object.values(current))
                stack.push(child);
            Object.freeze(current);
        }
    }
    return snapshot;
}
function snapshotExpectedProbeNonces(value, inventory) {
    if (value === undefined || value === null)
        return null;
    if (value instanceof Map) {
        const selected = Object.create(null);
        for (const surface of Array.isArray(inventory?.surfaces) ? inventory.surfaces : []) {
            if (value.has(surface.surface_id))
                selected[surface.surface_id] = value.get(surface.surface_id);
        }
        return immutableCanonicalSnapshot(selected);
    }
    return immutableCanonicalSnapshot(value);
}
function snapshotSettlementItems(items) {
    const ownKeys = Reflect.ownKeys(items);
    if (ownKeys.length !== items.length + 1 || !ownKeys.includes('length')) {
        throw new TypeError('settlement collection must be a dense data array');
    }
    const snapshots = [];
    for (let i = 0; i < items.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(items, String(i));
        if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) {
            throw new TypeError('settlement collection contains an accessor');
        }
        snapshots.push(immutableCanonicalSnapshot(descriptor.value));
    }
    return Object.freeze(snapshots);
}
/**
 * Produce one reproducible control-plane view. The signed/verified subartifacts
 * remain independently portable; this report joins only their digests and
 * closed verdicts.
 */
export async function evaluateGateControlPlane(input = {}, options = {}) {
    const now = options.now === undefined ? Date.now() : Number(options.now);
    if (!Number.isFinite(now))
        throw new TypeError('control-plane now must be finite');
    let coverageInventory;
    let settlementProfile;
    let pinnedProbes;
    let pinnedWitnesses;
    let expectedProbeNonces;
    let probeMaxAgeSec;
    let witnessMaxAgeSec;
    let maxFutureSkewSec;
    let allowEphemeralWitnessStore;
    let configuredTrustedAcceptances;
    let configurationError = null;
    try {
        coverageInventory = options.coverageInventory === undefined
            ? undefined
            : immutableCanonicalSnapshot(options.coverageInventory);
        settlementProfile = options.settlementProfile === undefined
            ? undefined
            : immutableCanonicalSnapshot(options.settlementProfile);
        pinnedProbes = options.pinnedProbes === undefined
            ? undefined
            : immutableCanonicalSnapshot(options.pinnedProbes);
        pinnedWitnesses = options.pinnedWitnesses === undefined
            ? undefined
            : immutableCanonicalSnapshot(options.pinnedWitnesses);
        expectedProbeNonces = snapshotExpectedProbeNonces(options.expectedProbeNonces, coverageInventory);
        probeMaxAgeSec = options.probeMaxAgeSec;
        witnessMaxAgeSec = options.witnessMaxAgeSec;
        maxFutureSkewSec = options.maxFutureSkewSec;
        allowEphemeralWitnessStore = options.allowEphemeralWitnessStore === true;
        const trustedInput = options.trustedWitnessAcceptances;
        if (trustedInput !== undefined
            && (!Array.isArray(trustedInput) || trustedInput.length > MAX_COVERAGE_EVIDENCE_ITEMS)) {
            throw new TypeError('trusted witness acceptance collection is invalid');
        }
        configuredTrustedAcceptances = [];
        for (const acceptance of Array.isArray(trustedInput) ? trustedInput : []) {
            configuredTrustedAcceptances.push(immutableCanonicalSnapshot(acceptance));
        }
        Object.freeze(configuredTrustedAcceptances);
    }
    catch {
        configurationError = 'rp_configuration_invalid';
        coverageInventory = null;
        settlementProfile = null;
        pinnedProbes = [];
        pinnedWitnesses = [];
        expectedProbeNonces = null;
        configuredTrustedAcceptances = Object.freeze([]);
        allowEphemeralWitnessStore = false;
    }
    let attestationVerifiers;
    let witnessSequenceStore;
    let verifyAuthorization;
    let verifyExecution;
    let verifyOutcome;
    try {
        attestationVerifiers = options.attestationVerifiers;
        witnessSequenceStore = options.witnessSequenceStore;
        verifyAuthorization = options.verifyAuthorization;
        verifyExecution = options.verifyExecution;
        verifyOutcome = options.verifyOutcome;
    }
    catch {
        configurationError = 'rp_configuration_invalid';
    }
    let settlementItems = [];
    let settlementError = null;
    try {
        const presentedSettlements = input.settlements;
        if (presentedSettlements !== undefined) {
            if (!Array.isArray(presentedSettlements)) {
                settlementError = 'settlements_invalid';
            }
            else if (presentedSettlements.length > CONTROL_PLANE_MAX_SETTLEMENTS) {
                settlementError = 'settlements_limit_exceeded';
            }
            else {
                settlementItems = snapshotSettlementItems(presentedSettlements);
            }
        }
    }
    catch {
        settlementItems = [];
        settlementError = 'settlements_hostile_input';
    }
    let coverageInput = {};
    try {
        const presentedCoverage = input.coverage;
        if (isPlainObject(presentedCoverage))
            coverageInput = presentedCoverage;
    }
    catch { /* coverage will remain closed with no evidence */ }
    let usageInput;
    let usageError = null;
    try {
        const presentedUsage = input.usage;
        usageInput = presentedUsage === undefined
            ? undefined
            : immutableCanonicalSnapshot(presentedUsage);
    }
    catch {
        usageError = 'usage_statement_refused';
    }
    // Evidence is presenter-controlled; policy and pins above are immutable RP
    // snapshots. No bundle can select a weaker configuration while work awaits.
    const trustedByStatementDigest = new Map();
    for (const acceptance of configuredTrustedAcceptances) {
        if (typeof acceptance.statement_digest === 'string') {
            trustedByStatementDigest.set(acceptance.statement_digest, acceptance);
        }
    }
    const coverageAcceptanceByArtifact = new Map();
    const acceptanceForStatement = (statement) => {
        const artifactKey = witnessArtifactKey(statement);
        if (artifactKey && coverageAcceptanceByArtifact.has(artifactKey)) {
            return { found: true, acceptance: coverageAcceptanceByArtifact.get(artifactKey), artifactKey };
        }
        try {
            const statementDigest = networkWitnessDigest(statement);
            if (trustedByStatementDigest.has(statementDigest)) {
                return { found: true, acceptance: trustedByStatementDigest.get(statementDigest), artifactKey };
            }
        }
        catch { /* raw ingestion will refuse malformed statements */ }
        return { found: false, acceptance: null, artifactKey };
    };
    // Coverage and settlement may reference the same witness statement. Consume
    // each coverage statement once, then reuse only this RP-side ingestion result.
    let coverageWitnesses = null;
    try {
        coverageInventoryDigest(coverageInventory);
        const evidenceListsValid = ['deployments', 'probes', 'witnesses'].every((field) => {
            const value = coverageInput[field];
            return value === undefined || (Array.isArray(value) && value.length <= MAX_COVERAGE_EVIDENCE_ITEMS);
        });
        if (evidenceListsValid) {
            const presentedWitnesses = Array.isArray(coverageInput.witnesses) ? coverageInput.witnesses : [];
            if (presentedWitnesses.length + configuredTrustedAcceptances.length <= MAX_COVERAGE_EVIDENCE_ITEMS) {
                coverageWitnesses = presentedWitnesses.map((statement) => immutableCanonicalSnapshot(statement));
            }
        }
    }
    catch { /* coverage owns the closed invalid-input report */ }
    const coverageIngestionResults = [];
    if (coverageWitnesses) {
        for (const statement of coverageWitnesses) {
            const existing = acceptanceForStatement(statement);
            const acceptance = existing.found
                ? existing.acceptance
                : await acceptNetworkWitnessStatement(statement, {
                    pinnedWitnesses,
                    maxAgeSec: witnessMaxAgeSec,
                    maxFutureSkewSec,
                    now,
                    sequenceStore: witnessSequenceStore,
                    allowEphemeralStore: allowEphemeralWitnessStore,
                });
            if (existing.artifactKey)
                coverageAcceptanceByArtifact.set(existing.artifactKey, acceptance);
            coverageIngestionResults.push(acceptance);
        }
    }
    const coverageEvidence = coverageWitnesses
        ? { ...coverageInput, witnesses: [] }
        : coverageInput;
    const coverage = await evaluateGateCoverage({
        ...coverageEvidence,
        inventory: coverageInventory,
    }, {
        now,
        attestationVerifiers,
        pinnedProbes,
        pinnedWitnesses,
        expectedProbeNonces,
        probeMaxAgeSec,
        witnessMaxAgeSec,
        maxFutureSkewSec,
        witnessSequenceStore,
        allowEphemeralWitnessStore,
        trustedWitnessAcceptances: [
            ...configuredTrustedAcceptances,
            ...coverageIngestionResults,
        ],
    });
    const settlements = [];
    for (const item of settlementItems) {
        const bundle = isPlainObject(item?.bundle) ? item.bundle : {};
        const surfaceId = bundle?.coverage?.surface_id;
        const verifyCoverage = async () => {
            const row = Array.isArray(coverage.surfaces)
                ? coverage.surfaces.find((candidate) => candidate.surface_id === surfaceId)
                : null;
            if (!row)
                return { accepted: false, reason: 'surface_not_in_pinned_inventory' };
            return {
                accepted: row.complete === true,
                state: row.state,
                surface_id: row.surface_id,
                report_hash: coverage.report_hash,
                reason: row.complete ? null : row.reason,
            };
        };
        const settlementOptions = {
            profile: settlementProfile,
            now,
            pinnedWitnesses,
            witnessMaxAgeSec,
            maxFutureSkewSec,
            witnessSequenceStore,
            allowEphemeralWitnessStore,
            verifyAuthorization,
            verifyExecution,
            verifyOutcome,
            verifyCoverage,
        };
        if (settlementProfile?.require_witness === true) {
            const trusted = acceptanceForStatement(bundle.witness);
            if (trusted.found)
                settlementOptions.trustedWitnessAcceptance = trusted.acceptance;
        }
        settlements.push(await evaluateSettlementEligibility(bundle, settlementOptions));
    }
    let usage = null;
    if (usageInput !== undefined && !usageError) {
        try {
            const metered = meterUsage(usageInput?.entries ?? [], usageInput?.period ?? {});
            usage = buildUsageStatement(metered, { org: usageInput?.org });
        }
        catch {
            usageError = 'usage_statement_refused';
        }
    }
    const summary = {
        '@version': CONTROL_PLANE_REPORT_VERSION,
        generated_at: new Date(now).toISOString(),
        coverage_report_hash: coverage.report_hash ?? null,
        coverage_complete: coverage.complete === true,
        settlement_input_complete: settlementError === null,
        settlement_results: settlements.map((result) => ({
            action_digest: result.action_digest,
            verdict: result.verdict,
            eligible: result.eligible === true,
            result_hash: result.result_hash,
        })),
        usage_statement_hash: usage?.content_hash ? `sha256:${usage.content_hash}` : null,
        usage_complete: usage?.complete === true,
        ...(configurationError ? { configuration_error: configurationError } : {}),
        ...(settlementError ? { settlement_error: settlementError } : {}),
        ...(usageError ? { usage_error: usageError } : {}),
        limitations: [
            'The control plane coordinates policy, evidence, coverage, metering, and settlement eligibility; executor-side Gates remain the only enforcement points.',
            'Coverage is bounded by the relying-party-declared inventory, and a passive witness never upgrades a surface to gated.',
            'Witness-dependent decisions require durable sequence ingestion or an explicitly relying-party-trusted acceptance result.',
        ],
    };
    return Object.freeze({
        ...summary,
        control_plane_digest: digest(summary),
        artifacts: Object.freeze({ coverage, settlements, usage }),
    });
}
export default {
    CONTROL_PLANE_REPORT_VERSION,
    CONTROL_PLANE_MAX_SETTLEMENTS,
    evaluateGateControlPlane,
};
//# sourceMappingURL=control-plane.js.map