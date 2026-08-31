// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Synthetic bulk-power action-assurance profile.
 *
 * A governed source supplies current equipment status. EMILIA Gate binds that
 * status to one exact Modbus command immediately before its own serialized
 * provider-entry step. The example proves that a freeze already committed in
 * the Gate control domain wins; it does not make the external status read atomic
 * with source-side revocation. The profile demonstrates the control boundary;
 * it does not determine legal scope, equipment origin, firmware integrity, or
 * physical effect.
 */
import { generateKeyPairSync, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CAPABILITY_SCOPE_PROFILE, capabilityActionDigest, composeProviderEntryGuards, createEg1Harness, createGate, createMemoryCapabilityStore, createOrganizationStatusProviderEntryGuard, mintCapabilityReceipt, reconcileCapabilityOperation, } from '../../packages/gate/index.js';
import { manifestFromPack } from '../../packages/gate/adapters/_kit.js';
import { decodeModbusWriteRegister, encodeModbusWriteRegister, modbusWriteRegisterAction, } from '../ot-command-binding-v1/commands.mjs';
export const PROFILE_VERSION = 'EP-BULK-POWER-ACTION-ASSURANCE-PROFILE-v0.1';
const HERE = dirname(fileURLToPath(import.meta.url));
const PROFILE = JSON.parse(readFileSync(resolve(HERE, 'profile.json'), 'utf8'));
const ACTION_LIFETIME_MS = 300_000;
const STATUS_EFFECTIVE_LEAD_MS = 60_000;
const STATUS_LIFETIME_MS = 300_000;
const STATUS_SOURCE_ID = 'source:reference-equipment-status';
const STATUS_ISSUER_KEY_ID = 'key:reference-equipment-status:1';
const OPERATOR_ID = 'operator:reference-bulk-power';
const ACTION_CURRENCY = 'BULK_POWER_ACTION';
const SELECTOR = Object.freeze({ protocol: 'ot', tool: 'bulk_power_modbus_write_single_register' });
function digest(value) {
    return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value))
        return value;
    for (const child of Object.values(value))
        deepFreeze(child);
    return Object.freeze(value);
}
function exactAction(overrides = {}) {
    const base = structuredClone(PROFILE.exact_action.example);
    const { parameters: overrideParameters, ...rest } = overrides;
    const parameters = { ...base.parameters, ...(overrideParameters ?? {}) };
    const issuedAt = Date.now();
    return deepFreeze({
        action_type: 'bulk-power.control-command.1',
        amount: 1,
        currency: ACTION_CURRENCY,
        ...base,
        requested_at: new Date(issuedAt).toISOString(),
        valid_from: new Date(issuedAt).toISOString(),
        expires_at: new Date(issuedAt + ACTION_LIFETIME_MS).toISOString(),
        ...rest,
        parameters,
    });
}
function actionFromWire(template, transactionId = 1) {
    const command = modbusWriteRegisterAction({
        site: template.site_id,
        device: template.asset_id,
        unitId: template.parameters.unit_id,
        protocolAddress: template.parameters.protocol_address,
        value: template.parameters.value,
    });
    const frame = encodeModbusWriteRegister(command, { transactionId });
    const decoded = decodeModbusWriteRegister(frame.hex, {
        site: template.site_id,
        device: template.asset_id,
        unit_id: template.parameters.unit_id,
    });
    return exactAction({
        ...template,
        // These labels are conduit-owned consequences of successfully decoding
        // Modbus TCP function code 0x06. A presenter cannot relabel a write as a
        // different protocol or operation while retaining the same wire command.
        action_type: 'bulk-power.control-command.1',
        action_profile: 'bulk-power.control-command.1',
        native_protocol: 'modbus-tcp',
        operation: 'write_single_register',
        parameters: {
            unit_id: decoded.unit_id,
            protocol_address: decoded.protocol_address,
            value: decoded.value,
        },
    });
}
function currentStatus(action, overrides = {}) {
    const observedAt = Date.now();
    return deepFreeze({
        subject_type: 'equipment',
        subject_id: action.asset_id,
        status: 'ACTIVE',
        source_id: STATUS_SOURCE_ID,
        source_version: 'reference-list-1',
        source_artifact_digest: action.external_status_digest,
        issuer_key_id: STATUS_ISSUER_KEY_ID,
        effective_at: new Date(observedAt - STATUS_EFFECTIVE_LEAD_MS).toISOString(),
        observed_at: new Date(observedAt).toISOString(),
        expires_at: new Date(observedAt + STATUS_LIFETIME_MS).toISOString(),
        applicable_asset_ids: [action.asset_id],
        applicable_operation_types: [action.operation],
        configuration_digest: action.configuration_digest,
        firmware_digest: action.firmware_digest,
        authenticated: true,
        claim_boundary: 'Synthetic assertion by the configured source; not an origin, integrity, or compliance determination.',
        ...overrides,
    });
}
function validDigest(value) {
    return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
}
function validStringList(value, { maxItems = 100, maxBytes = 512 } = {}) {
    return Array.isArray(value)
        && value.length > 0
        && value.length <= maxItems
        && value.every((entry) => typeof entry === 'string'
            && entry.length > 0
            && Buffer.byteLength(entry, 'utf8') <= maxBytes);
}
/**
 * Relying-party-owned adapter for a governed equipment-status source. The
 * adapter authenticates and normalizes source output; presenter-supplied status
 * is never accepted. The independently serialized organization guard is
 * composed beside it by createFixture().
 */
export function createEquipmentEligibilityGuard({ resolveStatus, sourceId = STATUS_SOURCE_ID, issuerKeyId = STATUS_ISSUER_KEY_ID, maxAgeMs = 5_000, now = Date.now, }) {
    if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0 || maxAgeMs > 60_000) {
        throw new TypeError('maxAgeMs must be a safe integer from 0 through 60000');
    }
    return async (context) => {
        const action = context.observed_action;
        if (!action)
            return { ok: false, reason: 'equipment_action_missing', status: 409, reservation: 'hold' };
        const initialAt = Date.parse(context.checked_at);
        const actionValidFrom = Date.parse(action.valid_from);
        const actionExpiresAt = Date.parse(action.expires_at);
        if (!Number.isFinite(initialAt)
            || !Number.isFinite(actionValidFrom)
            || !Number.isFinite(actionExpiresAt)
            || actionValidFrom >= actionExpiresAt) {
            return {
                ok: false,
                reason: 'action_validity_invalid',
                status: 409,
                reservation: 'burn',
            };
        }
        if (initialAt < actionValidFrom) {
            return {
                ok: false,
                reason: 'action_not_yet_valid',
                status: 425,
                reservation: 'release',
                evidence: {
                    kind: 'action_validity',
                    checked_at: context.checked_at,
                    valid_from: action.valid_from,
                    expires_at: action.expires_at,
                },
            };
        }
        if (initialAt >= actionExpiresAt) {
            return {
                ok: false,
                reason: 'action_expired',
                status: 410,
                reservation: 'burn',
                evidence: {
                    kind: 'action_validity',
                    checked_at: context.checked_at,
                    valid_from: action.valid_from,
                    expires_at: action.expires_at,
                },
            };
        }
        let status;
        try {
            status = await resolveStatus(Object.freeze({ action, context }));
        }
        catch {
            return { ok: false, reason: 'equipment_status_unavailable', status: 503, reservation: 'hold' };
        }
        // The status source can be asynchronous. Resample after it returns so a
        // slow resolver cannot admit an action or observation that expired while
        // the final provider-entry guard was waiting.
        const at = now();
        if (!Number.isFinite(at)) {
            return { ok: false, reason: 'equipment_status_clock_invalid', status: 503, reservation: 'hold' };
        }
        const checkedAt = new Date(at).toISOString();
        if (at < actionValidFrom) {
            return {
                ok: false,
                reason: 'action_not_yet_valid',
                status: 425,
                reservation: 'release',
                evidence: {
                    kind: 'action_validity',
                    checked_at: checkedAt,
                    valid_from: action.valid_from,
                    expires_at: action.expires_at,
                },
            };
        }
        if (at >= actionExpiresAt) {
            return {
                ok: false,
                reason: 'action_expired',
                status: 410,
                reservation: 'burn',
                evidence: {
                    kind: 'action_validity',
                    checked_at: checkedAt,
                    valid_from: action.valid_from,
                    expires_at: action.expires_at,
                },
            };
        }
        if (!status || status.authenticated !== true) {
            return { ok: false, reason: 'equipment_status_unauthenticated', status: 503, reservation: 'hold' };
        }
        if (!validStringList(status.applicable_asset_ids)
            || !validStringList(status.applicable_operation_types)
            || typeof status.source_version !== 'string'
            || status.source_version.length === 0
            || Buffer.byteLength(status.source_version, 'utf8') > 512
            || typeof status.claim_boundary !== 'string'
            || status.claim_boundary.length === 0
            || Buffer.byteLength(status.claim_boundary, 'utf8') > 2_048
            || !['ACTIVE', 'PREQUALIFIED', 'RESTRICTED', 'REVOKED'].includes(status.status)) {
            return { ok: false, reason: 'equipment_status_schema_invalid', status: 503, reservation: 'hold' };
        }
        if (status.source_id !== sourceId || status.issuer_key_id !== issuerKeyId) {
            return { ok: false, reason: 'equipment_status_source_untrusted', status: 403, reservation: 'hold' };
        }
        if (!validDigest(status.source_artifact_digest)
            || status.source_artifact_digest !== action.external_status_digest) {
            return { ok: false, reason: 'equipment_status_digest_mismatch', status: 409, reservation: 'hold' };
        }
        if (status.subject_type !== 'equipment'
            || status.subject_id !== action.asset_id
            || !status.applicable_asset_ids?.includes(action.asset_id)
            || !status.applicable_operation_types?.includes(action.operation)
            || status.configuration_digest !== action.configuration_digest
            || status.firmware_digest !== action.firmware_digest) {
            return { ok: false, reason: 'equipment_status_scope_mismatch', status: 409, reservation: 'hold' };
        }
        const effectiveAt = Date.parse(status.effective_at);
        const observedAt = Date.parse(status.observed_at);
        const expiresAt = Date.parse(status.expires_at);
        if (!Number.isFinite(at) || !Number.isFinite(effectiveAt)
            || !Number.isFinite(observedAt) || !Number.isFinite(expiresAt)
            || effectiveAt > at || observedAt > at + 1_000
            || at - observedAt > maxAgeMs || expiresAt <= at) {
            return { ok: false, reason: 'equipment_status_stale', status: 503, reservation: 'release' };
        }
        if (status.status !== 'ACTIVE' && status.status !== 'PREQUALIFIED') {
            return {
                ok: false,
                reason: status.status === 'REVOKED' ? 'equipment_status_revoked' : 'equipment_status_restricted',
                status: 423,
                reservation: 'burn',
                evidence: {
                    kind: 'equipment_status',
                    subject_id: status.subject_id,
                    status: status.status,
                    source_id: status.source_id,
                    source_artifact_digest: status.source_artifact_digest,
                    observed_at: status.observed_at,
                },
            };
        }
        return {
            ok: true,
            evidence: {
                version: PROFILE_VERSION,
                kind: 'equipment_status',
                subject_id: status.subject_id,
                status: status.status,
                source_id: status.source_id,
                source_version: status.source_version,
                source_artifact_digest: status.source_artifact_digest,
                issuer_key_id: status.issuer_key_id,
                effective_at: status.effective_at,
                observed_at: status.observed_at,
                expires_at: status.expires_at,
                action_valid_from: action.valid_from,
                action_expires_at: action.expires_at,
                checked_at: checkedAt,
                configuration_digest: status.configuration_digest,
                firmware_digest: status.firmware_digest,
                claim_boundary: status.claim_boundary,
            },
        };
    };
}
function manifest(action) {
    const requiredFields = [
        'action_type',
        'action_profile',
        'amount',
        'currency',
        'rp_id',
        'admission_domain_id',
        'operation_id',
        'requested_at',
        'site_id',
        'asset_id',
        'equipment_class',
        'manufacturer',
        'model',
        'serial_number',
        'configuration_digest',
        'firmware_digest',
        'native_protocol',
        'operation',
        'parameters',
        'authority_artifact_digest',
        'external_status_digest',
        'policy_id',
        'policy_version',
        'policy_digest',
        'control_epoch',
        'provider_id',
        'outcome_evidence_profile',
        'valid_from',
        'expires_at',
    ];
    return manifestFromPack([{
            id: 'bulk-power.modbus.write-single-register',
            label: 'Bulk-power equipment Modbus write',
            action_type: action.action_type,
            risk: 'critical',
            receipt_required: true,
            assurance_class: 'class_a',
            match: { ...SELECTOR },
            why: 'One exact equipment command under current governed status and local policy.',
            execution_binding: { required_fields: requiredFields },
        }]);
}
function verifyControlTransition(input) {
    return {
        authenticated: true,
        authorized: true,
        authority_instance_digest: digest('reference-bulk-power-control-authority'),
        action_digest: input.action_digest,
    };
}
export async function createFixture({ action = exactAction(), status = null, statusUnavailable = false, freezeDuringStatusCheck = false, } = {}) {
    const observedAction = actionFromWire(action);
    let equipmentStatus = status ?? currentStatus(observedAction);
    const harness = createEg1Harness({
        action: observedAction,
        now: Date.now,
        idPrefix: 'bulk-power-action-assurance',
    });
    const baseReceipt = harness.mint({ outcome: 'allow_with_signoff', extra: { capability_only: true } });
    const issuer = generateKeyPairSync('ed25519');
    const issuerPublicKey = issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const capability = mintCapabilityReceipt(baseReceipt, {
        issuerPrivateKey: issuer.privateKey,
        budget: { amount: 1, currency: ACTION_CURRENCY },
        expiry: Date.now() + ACTION_LIFETIME_MS,
        revocationMode: 'direct',
        capabilityId: 'capability:bulk-power-action-assurance:v0.1',
        secret: Buffer.alloc(32, 47),
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: [capabilityActionDigest(observedAction)],
        },
    });
    const capabilityStore = createMemoryCapabilityStore({ verifyControlTransition });
    if (!capabilityStore.registerCapability(capability.capabilityReceipt)) {
        throw new Error('capability registration failed');
    }
    const registered = await capabilityStore.registerControlDomain({
        controlDomainId: observedAction.admission_domain_id,
        now: Date.now(),
    });
    if (!registered.ok)
        throw new Error(`control-domain registration failed: ${registered.reason}`);
    const actionContractGuard = (context) => {
        const candidate = context.observed_action;
        if (!candidate) {
            return { ok: false, reason: 'equipment_action_missing', status: 409, reservation: 'hold' };
        }
        const expected = PROFILE.exact_action.example;
        if (candidate.action_type !== PROFILE.exact_action.action_profile
            || candidate.action_profile !== PROFILE.exact_action.action_profile
            || candidate.native_protocol !== 'modbus-tcp'
            || candidate.operation !== 'write_single_register'
            || candidate.amount !== 1
            || candidate.currency !== ACTION_CURRENCY) {
            return { ok: false, reason: 'action_contract_mismatch', status: 409, reservation: 'burn' };
        }
        const digestFields = [
            'configuration_digest',
            'firmware_digest',
            'authority_artifact_digest',
            'external_status_digest',
            'policy_digest',
        ];
        if (digestFields.some((field) => !validDigest(candidate[field]))) {
            return { ok: false, reason: 'action_digest_field_invalid', status: 409, reservation: 'burn' };
        }
        if (candidate.policy_id !== expected.policy_id
            || candidate.policy_version !== expected.policy_version
            || candidate.policy_digest !== expected.policy_digest) {
            return { ok: false, reason: 'action_policy_mismatch', status: 409, reservation: 'burn' };
        }
        if (candidate.provider_id !== expected.provider_id) {
            return { ok: false, reason: 'action_provider_mismatch', status: 409, reservation: 'burn' };
        }
        if (candidate.outcome_evidence_profile !== expected.outcome_evidence_profile) {
            return {
                ok: false,
                reason: 'action_outcome_evidence_profile_mismatch',
                status: 409,
                reservation: 'burn',
            };
        }
        const domain = capabilityStore.getControlDomain(candidate.admission_domain_id);
        if (!Number.isSafeInteger(candidate.control_epoch)
            || !domain
            || domain.status !== 'active'
            || candidate.control_epoch !== domain.epoch) {
            return { ok: false, reason: 'action_control_epoch_mismatch', status: 409, reservation: 'burn' };
        }
        return {
            ok: true,
            evidence: {
                kind: 'action_contract',
                action_profile: candidate.action_profile,
                policy_id: candidate.policy_id,
                policy_version: candidate.policy_version,
                policy_digest: candidate.policy_digest,
                provider_id: candidate.provider_id,
                outcome_evidence_profile: candidate.outcome_evidence_profile,
                control_domain_id: domain.control_domain_id,
                control_epoch: domain.epoch,
                checked_at: new Date().toISOString(),
            },
        };
    };
    const equipmentGuard = createEquipmentEligibilityGuard({
        maxAgeMs: 60_000,
        resolveStatus: async () => {
            if (statusUnavailable)
                throw new Error('status source unavailable');
            return equipmentStatus;
        },
    });
    let freezeCommitted = false;
    const organizationGuard = createOrganizationStatusProviderEntryGuard({
        organizationId: OPERATOR_ID,
        controlDomainId: observedAction.admission_domain_id,
        maxAgeMs: 60_000,
        resolveStatus: async () => {
            if (freezeDuringStatusCheck && !freezeCommitted) {
                freezeCommitted = true;
                const freezeDigest = digest('freeze:reference-bulk-power-domain');
                const frozen = await capabilityStore.freezeControlDomain({
                    controlDomainId: observedAction.admission_domain_id,
                    operationId: 'freeze:reference-bulk-power-domain',
                    actionDigest: freezeDigest,
                    authorization: { currently_authorized: true, action_digest: freezeDigest },
                    now: Date.now(),
                });
                if (!frozen.ok)
                    throw new Error(`control-domain freeze failed: ${frozen.reason}`);
            }
            return {
                organization_id: OPERATOR_ID,
                status: 'active',
                epoch: 1,
                observed_at: new Date().toISOString(),
                authenticated: true,
                source_digest: digest('reference-operator-status'),
            };
        },
    });
    // Keep the equipment/action freshness check last. Its clock is resampled
    // after the asynchronous status lookup and immediately before Gate asks the
    // store to serialize provider entry.
    const providerEntryGuard = composeProviderEntryGuards(actionContractGuard, organizationGuard, equipmentGuard);
    const gate = createGate({
        manifest: manifest(observedAction),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        quorumPolicy: harness.quorumPolicy,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        capabilityStore,
        capabilityTrustedIssuerKeys: [issuerPublicKey],
        providerEntryGuard,
        allowEphemeralStore: true,
        now: Date.now,
    });
    let providerEntries = 0;
    async function attempt({ presentedAction = observedAction, effect = async () => ({ acknowledged: true }), } = {}) {
        try {
            const result = await gate.run({
                selector: SELECTOR,
                observedAction: presentedAction,
                capability: {
                    capabilityReceipt: capability.capabilityReceipt,
                    secret: capability.secret,
                    action: { amount: 1, currency: ACTION_CURRENCY },
                    operationId: presentedAction.operation_id,
                },
            }, async (_authorization, operation) => {
                providerEntries += 1;
                return effect(presentedAction, operation);
            });
            return {
                ok: result.ok === true,
                reason: result.ok ? 'allow' : (result.capability?.reason ?? result.authorization?.reason ?? 'refused'),
                terminal_outcome: result.execution?.outcome ?? null,
                provider_entry_evidence: result.capability?.provider_entry_evidence ?? null,
                operation: capabilityStore.getOperation(presentedAction.operation_id),
                raw: result,
            };
        }
        catch (error) {
            if (error?.code !== 'EMILIA_GATE_TERMINAL_OUTCOME')
                throw error;
            return {
                ok: false,
                reason: error.emiliaGateOutcome.reason,
                terminal_outcome: error.emiliaGateOutcome.outcome,
                provider_entry_evidence: error.emiliaGateOutcome.provider_entry_evidence
                    ?? error.emiliaGateOutcome.execution?.detail?.provider_entry_evidence
                    ?? null,
                operation: capabilityStore.getOperation(presentedAction.operation_id),
                raw: error.emiliaGateOutcome,
            };
        }
    }
    return {
        action: observedAction,
        capabilityId: capability.capabilityReceipt.capability.id,
        capabilityStore,
        gate,
        attempt,
        get providerEntries() { return providerEntries; },
        setStatus(next) { equipmentStatus = next; },
    };
}
function caseResult(id, passed, observed) {
    return { id, passed, observed };
}
export async function runProfile() {
    const cases = [];
    const positive = await createFixture();
    const admitted = await positive.attempt();
    const admittedGuards = admitted.provider_entry_evidence?.guards ?? [];
    const admittedEquipmentStatus = admittedGuards.find((entry) => entry.kind === 'equipment_status');
    cases.push(caseResult('EXACT-CURRENT-ACTION-ADMITTED', admitted.ok && positive.providerEntries === 1
        && admittedEquipmentStatus
        && admittedGuards.some((entry) => entry.kind === 'organization_status'), {
        allowed: admitted.ok,
        reason: admitted.reason,
        provider_entries: positive.providerEntries,
        equipment_status_digest: admittedEquipmentStatus?.source_artifact_digest ?? null,
    }));
    const assetFixture = await createFixture();
    const substitutedAsset = actionFromWire({
        ...assetFixture.action,
        asset_id: 'asset:substituted-plc-99',
    });
    const assetRefusal = await assetFixture.attempt({ presentedAction: substitutedAsset });
    cases.push(caseResult('ASSET-SUBSTITUTION-REFUSED', assetRefusal.reason === 'capability_action_out_of_scope'
        && assetFixture.providerEntries === 0, {
        reason: assetRefusal.reason,
        provider_entries: assetFixture.providerEntries,
    }));
    const parameterFixture = await createFixture();
    const changedParameter = actionFromWire({
        ...parameterFixture.action,
        parameters: { ...parameterFixture.action.parameters, value: 1 },
    });
    const parameterRefusal = await parameterFixture.attempt({ presentedAction: changedParameter });
    cases.push(caseResult('PARAMETER-SUBSTITUTION-REFUSED', parameterRefusal.reason === 'capability_action_out_of_scope'
        && parameterFixture.providerEntries === 0, {
        reason: parameterRefusal.reason,
        provider_entries: parameterFixture.providerEntries,
    }));
    const domainFixture = await createFixture();
    const changedDomain = actionFromWire({
        ...domainFixture.action,
        admission_domain_id: 'gate:other-substation',
    });
    const domainRefusal = await domainFixture.attempt({ presentedAction: changedDomain });
    cases.push(caseResult('ADMISSION-DOMAIN-SUBSTITUTION-REFUSED', domainRefusal.reason === 'capability_action_out_of_scope'
        && domainFixture.providerEntries === 0, {
        reason: domainRefusal.reason,
        provider_entries: domainFixture.providerEntries,
    }));
    const firmwareFixture = await createFixture();
    const changedFirmware = actionFromWire({
        ...firmwareFixture.action,
        firmware_digest: digest('substituted-firmware'),
    });
    const firmwareRefusal = await firmwareFixture.attempt({ presentedAction: changedFirmware });
    cases.push(caseResult('FIRMWARE-DRIFT-REFUSED', firmwareRefusal.reason === 'capability_action_out_of_scope'
        && firmwareFixture.providerEntries === 0, {
        reason: firmwareRefusal.reason,
        provider_entries: firmwareFixture.providerEntries,
    }));
    const txTemplate = exactAction();
    const txActionA = actionFromWire(txTemplate, 1);
    const txActionB = actionFromWire(txTemplate, 4_242);
    cases.push(caseResult('MODBUS-TRANSACTION-ID-IS-NONMATERIAL', capabilityActionDigest(txActionA) === capabilityActionDigest(txActionB), {
        digests_equal: capabilityActionDigest(txActionA) === capabilityActionDigest(txActionB),
    }));
    const mislabeledFixture = await createFixture();
    const mislabeledTemplate = {
        ...mislabeledFixture.action,
        action_type: 'monitor.read',
        action_profile: 'monitor.read',
        native_protocol: 'not-modbus',
        operation: 'read_only',
    };
    const conduitDerived = actionFromWire(mislabeledTemplate);
    const mislabeledAttempt = await mislabeledFixture.attempt({ presentedAction: mislabeledTemplate });
    cases.push(caseResult('WIRE-OPERATION-LABELS-ARE-CONDUIT-DERIVED', conduitDerived.action_type === 'bulk-power.control-command.1'
        && conduitDerived.action_profile === 'bulk-power.control-command.1'
        && conduitDerived.native_protocol === 'modbus-tcp'
        && conduitDerived.operation === 'write_single_register'
        && mislabeledAttempt.reason === 'capability_action_out_of_scope'
        && mislabeledFixture.providerEntries === 0, {
        decoded_action_type: conduitDerived.action_type,
        decoded_action_profile: conduitDerived.action_profile,
        decoded_native_protocol: conduitDerived.native_protocol,
        decoded_operation: conduitDerived.operation,
        mislabeled_authority_reason: mislabeledAttempt.reason,
        provider_entries: mislabeledFixture.providerEntries,
    }));
    const invalidDigestFields = [
        'configuration_digest',
        'firmware_digest',
        'authority_artifact_digest',
        'external_status_digest',
        'policy_digest',
    ];
    const invalidDigestResults = [];
    for (const field of invalidDigestFields) {
        const action = exactAction({ [field]: 'not-a-digest' });
        const fixture = await createFixture({ action });
        const result = await fixture.attempt();
        invalidDigestResults.push({ field, reason: result.reason, provider_entries: fixture.providerEntries });
    }
    cases.push(caseResult('MALFORMED-ACTION-DIGESTS-REFUSED', invalidDigestResults.every((entry) => entry.reason === 'action_digest_field_invalid'
        && entry.provider_entries === 0), {
        results: invalidDigestResults,
    }));
    const policyAction = exactAction({ policy_digest: digest('substituted-local-policy') });
    const policyFixture = await createFixture({ action: policyAction });
    const policyRefusal = await policyFixture.attempt();
    cases.push(caseResult('POLICY-SUBSTITUTION-REFUSED', policyRefusal.reason === 'action_policy_mismatch' && policyFixture.providerEntries === 0, {
        reason: policyRefusal.reason,
        provider_entries: policyFixture.providerEntries,
    }));
    const providerAction = exactAction({ provider_id: 'provider:substituted-controller-99' });
    const providerFixture = await createFixture({ action: providerAction });
    const providerRefusal = await providerFixture.attempt();
    cases.push(caseResult('PROVIDER-SUBSTITUTION-REFUSED', providerRefusal.reason === 'action_provider_mismatch' && providerFixture.providerEntries === 0, {
        reason: providerRefusal.reason,
        provider_entries: providerFixture.providerEntries,
    }));
    const outcomeProfileAction = exactAction({
        outcome_evidence_profile: 'urn:substituted:outcome-profile',
    });
    const outcomeProfileFixture = await createFixture({ action: outcomeProfileAction });
    const outcomeProfileRefusal = await outcomeProfileFixture.attempt();
    cases.push(caseResult('OUTCOME-PROFILE-SUBSTITUTION-REFUSED', outcomeProfileRefusal.reason === 'action_outcome_evidence_profile_mismatch'
        && outcomeProfileFixture.providerEntries === 0, {
        reason: outcomeProfileRefusal.reason,
        provider_entries: outcomeProfileFixture.providerEntries,
    }));
    const epochAction = exactAction({ control_epoch: 999_999 });
    const epochFixture = await createFixture({ action: epochAction });
    const epochRefusal = await epochFixture.attempt();
    cases.push(caseResult('CONTROL-EPOCH-MISMATCH-REFUSED', epochRefusal.reason === 'action_control_epoch_mismatch' && epochFixture.providerEntries === 0, {
        reason: epochRefusal.reason,
        provider_entries: epochFixture.providerEntries,
    }));
    const expiredAt = Date.now();
    const expiredAction = exactAction({
        requested_at: new Date(expiredAt - ACTION_LIFETIME_MS).toISOString(),
        valid_from: new Date(expiredAt - ACTION_LIFETIME_MS).toISOString(),
        expires_at: new Date(expiredAt - 1).toISOString(),
    });
    const expiredFixture = await createFixture({ action: expiredAction });
    const expired = await expiredFixture.attempt();
    const expiredCapability = expiredFixture.capabilityStore.getState(expiredFixture.capabilityId);
    cases.push(caseResult('EXPIRED-ACTION-REFUSED', expired.reason === 'action_expired'
        && expiredFixture.providerEntries === 0
        && expiredCapability?.consumed_amount === 1, {
        reason: expired.reason,
        provider_entries: expiredFixture.providerEntries,
        consumed_amount: expiredCapability?.consumed_amount ?? null,
    }));
    const staleAction = exactAction();
    const staleFixture = await createFixture({
        action: staleAction,
        status: currentStatus(staleAction, { observed_at: new Date(Date.now() - 120_000).toISOString() }),
    });
    const stale = await staleFixture.attempt();
    cases.push(caseResult('STALE-STATUS-REFUSED', stale.reason === 'equipment_status_stale' && staleFixture.providerEntries === 0, {
        reason: stale.reason,
        provider_entries: staleFixture.providerEntries,
    }));
    const futureStatusAction = exactAction();
    const futureStatusFixture = await createFixture({
        action: futureStatusAction,
        status: currentStatus(futureStatusAction, {
            observed_at: new Date(Date.now() + 60_000).toISOString(),
        }),
    });
    const futureStatus = await futureStatusFixture.attempt();
    cases.push(caseResult('FUTURE-STATUS-REFUSED', futureStatus.reason === 'equipment_status_stale'
        && futureStatusFixture.providerEntries === 0, {
        reason: futureStatus.reason,
        provider_entries: futureStatusFixture.providerEntries,
    }));
    const revokedAction = exactAction();
    const revokedFixture = await createFixture({
        action: revokedAction,
        status: currentStatus(revokedAction, { status: 'REVOKED' }),
    });
    const revoked = await revokedFixture.attempt();
    cases.push(caseResult('REVOKED-STATUS-REFUSED', revoked.reason === 'equipment_status_revoked' && revokedFixture.providerEntries === 0, {
        reason: revoked.reason,
        provider_entries: revokedFixture.providerEntries,
    }));
    const unavailableFixture = await createFixture({ statusUnavailable: true });
    const unavailable = await unavailableFixture.attempt();
    cases.push(caseResult('UNAVAILABLE-STATUS-REFUSED', unavailable.reason === 'equipment_status_unavailable' && unavailableFixture.providerEntries === 0, {
        reason: unavailable.reason,
        provider_entries: unavailableFixture.providerEntries,
    }));
    const untrustedAction = exactAction();
    const untrustedFixture = await createFixture({
        action: untrustedAction,
        status: currentStatus(untrustedAction, { source_id: 'source:untrusted-equipment-status' }),
    });
    const untrusted = await untrustedFixture.attempt();
    cases.push(caseResult('UNTRUSTED-STATUS-SOURCE-REFUSED', untrusted.reason === 'equipment_status_source_untrusted' && untrustedFixture.providerEntries === 0, {
        reason: untrusted.reason,
        provider_entries: untrustedFixture.providerEntries,
    }));
    const wrongDigestAction = exactAction();
    const wrongDigestFixture = await createFixture({
        action: wrongDigestAction,
        status: currentStatus(wrongDigestAction, { source_artifact_digest: digest('different-status-list') }),
    });
    const wrongDigest = await wrongDigestFixture.attempt();
    cases.push(caseResult('STATUS-DIGEST-SUBSTITUTION-REFUSED', wrongDigest.reason === 'equipment_status_digest_mismatch' && wrongDigestFixture.providerEntries === 0, {
        reason: wrongDigest.reason,
        provider_entries: wrongDigestFixture.providerEntries,
    }));
    const malformedScopeAction = exactAction();
    const malformedScopeFixture = await createFixture({
        action: malformedScopeAction,
        status: currentStatus(malformedScopeAction, {
            applicable_asset_ids: `prefix-${malformedScopeAction.asset_id}-suffix`,
            applicable_operation_types: `prefix-${malformedScopeAction.operation}-suffix`,
        }),
    });
    const malformedScope = await malformedScopeFixture.attempt();
    cases.push(caseResult('MALFORMED-STATUS-SCOPE-REFUSED', malformedScope.reason === 'equipment_status_schema_invalid'
        && malformedScopeFixture.providerEntries === 0, {
        reason: malformedScope.reason,
        provider_entries: malformedScopeFixture.providerEntries,
    }));
    const frozenFixture = await createFixture({ freezeDuringStatusCheck: true });
    const frozen = await frozenFixture.attempt();
    cases.push(caseResult('CACHED-ACTIVE-CANNOT-BEAT-FREEZE', frozen.reason === 'capability_control_domain_frozen' && frozenFixture.providerEntries === 0, {
        reason: frozen.reason,
        provider_entries: frozenFixture.providerEntries,
        control_domain_status: frozenFixture.capabilityStore.getControlDomain(frozenFixture.action.admission_domain_id)?.status ?? null,
    }));
    const replayFixture = await createFixture();
    const first = await replayFixture.attempt();
    const replay = await replayFixture.attempt();
    cases.push(caseResult('REPLAY-REFUSED', first.ok && !replay.ok && replayFixture.providerEntries === 1, {
        first_allowed: first.ok,
        retry_reason: replay.reason,
        provider_entries: replayFixture.providerEntries,
    }));
    const tunnelOnlyFixture = await createFixture();
    let tunnelOnlyEffects = 0;
    const tunnelOnly = await tunnelOnlyFixture.gate.run({
        selector: SELECTOR,
        observedAction: tunnelOnlyFixture.action,
    }, async () => { tunnelOnlyEffects += 1; });
    cases.push(caseResult('MISSING-AUTHORITY-REFUSED', tunnelOnly.ok === false && tunnelOnlyEffects === 0, {
        reason: tunnelOnly.authorization?.reason ?? null,
        provider_entries: tunnelOnlyEffects,
    }));
    const uncertainFixture = await createFixture();
    const uncertain = await uncertainFixture.attempt({
        effect: async () => { throw Object.assign(new Error('controller response lost'), { code: 'CONTROLLER_TIMEOUT' }); },
    });
    const reconciliationEvidenceDigest = digest('reference-negative-provider-evidence');
    const reconciliationTime = Date.now() + 30_001;
    const reconciled = await reconcileCapabilityOperation({
        store: uncertainFixture.capabilityStore,
        capabilityId: uncertainFixture.capabilityId,
        operationId: uncertainFixture.action.operation_id,
        action: uncertainFixture.action,
        evidence: { provider_id: uncertainFixture.action.provider_id },
        now: reconciliationTime,
        verifyEvidence: (_evidence, context) => ({
            valid: true,
            authenticated: true,
            final: true,
            outcome: 'not_entered',
            capability_id: context.capability_id,
            operation_namespace: context.operation_namespace,
            operation_id: context.operation_id,
            action_digest: context.action_digest,
            evidence_profile: 'urn:emilia:bulk-power:provider-negative-entry:v0.1',
            evidence_digest: reconciliationEvidenceDigest,
            observed_at: new Date(reconciliationTime).toISOString(),
        }),
    });
    const blindRetry = await uncertainFixture.attempt();
    const reconciledOperation = uncertainFixture.capabilityStore.getOperation(uncertainFixture.action.operation_id);
    const reconciledCapability = uncertainFixture.capabilityStore.getState(uncertainFixture.capabilityId);
    cases.push(caseResult('LOST-RESPONSE-IS-INDETERMINATE-AND-CONSUMED', uncertain.terminal_outcome === 'indeterminate'
        && uncertain.operation?.outcome === 'indeterminate'
        && reconciledOperation?.outcome === 'indeterminate'
        && reconciledCapability?.consumed_amount === 1
        && reconciledCapability?.reserved_amount === 0
        && !blindRetry.ok
        && uncertainFixture.providerEntries === 1, {
        first_reason: uncertain.reason,
        terminal_outcome: uncertain.terminal_outcome,
        store_outcome: uncertain.operation?.outcome ?? null,
        retry_reason: blindRetry.reason,
        reconciliation_accepted: reconciled.ok === true,
        reconciliation_reason: reconciled.reason ?? null,
        reconciliation_outcome: reconciledOperation?.reconciliation_outcome ?? null,
        authority_outcome_after_reconciliation: reconciledOperation?.outcome ?? null,
        consumed_after_reconciliation: reconciledCapability?.consumed_amount ?? null,
        provider_entries: uncertainFixture.providerEntries,
    }));
    return deepFreeze({
        profile: PROFILE_VERSION,
        policy_source: {
            title: PROFILE.policy_source.title,
            citation: PROFILE.policy_source.citation,
            identifier_note: PROFILE.policy_source.identifier_note,
        },
        passed: cases.every((entry) => entry.passed === true),
        cases,
        claim_boundary: PROFILE.claim_boundary,
        implementation_boundary: [
            'Synthetic local profile; no live bulk-power equipment was controlled.',
            'The configured source adapter asserts status authentication; this run does not prove government provenance or legal scope.',
            'The external status read is not atomic with source-side revocation; production integration must project source freeze or revision state into the same Gate control domain.',
            'Provider-entry evidence reaches the effect context, but its execution-detail copy is recorded after provider entry and is not proof of atomic durable persistence.',
            'The in-process stores are explicit test state, not a durable shared production deployment.',
            'At-most-one provider entry is not proof of exactly-once physical effect.',
        ],
    });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const report = await runProfile();
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!report.passed)
        process.exitCode = 1;
}
