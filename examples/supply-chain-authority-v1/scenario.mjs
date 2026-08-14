// SPDX-License-Identifier: Apache-2.0
// Generated from scenario.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { createHash, generateKeyPairSync } from 'node:crypto';
import { CAPABILITY_SCOPE_PROFILE, capabilityActionDigest, createEg1Harness, createMemoryCapabilityStore, mintCapabilityReceipt, verifyCapabilityScope, } from '../../packages/gate/index.js';
const NOW = Date.parse('2026-08-14T18:00:00.000Z');
const CONTROL_DOMAIN_ID = 'warehouse-authority-domain';
const CONTROL_AUTHORITY_DIGEST = digest('warehouse-emergency-authority');
const FREEZE_ACTION_DIGEST = digest('warehouse-authority-freeze');
const RESTORE_ACTION_DIGEST = digest('warehouse-authority-restore');
function digest(value) {
    return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}
function machineAction(operationId, palletId) {
    return Object.freeze({
        operation_id: operationId,
        action_type: 'warehouse.robot.move',
        facility_id: 'warehouse:reno-01',
        executor_id: 'adapter:amr-fleet-01',
        robot_id: 'amr-07',
        pallet_id: palletId,
        from_zone: 'dock-a',
        to_zone: 'freezer-b',
        route_digest: digest(`dock-a:aisle-4:freezer-b:${palletId}`),
        payload_kg: 420,
        max_speed_mps: '1.2',
        deadline: '2026-08-14T18:10:00.000Z',
        amount: 1,
        currency: 'MACHINE_OP',
    });
}
function verifyControlTransition(input) {
    const authorization = input.authorization;
    if (!authorization || authorization.authenticated !== true) {
        return { authenticated: false, authorized: false };
    }
    return {
        authenticated: true,
        authorized: authorization.currently_authorized === true,
        authority_instance_digest: authorization.authority_instance_digest,
        action_digest: authorization.action_digest,
    };
}
function controlAuthorization(actionDigest) {
    return {
        authenticated: true,
        currently_authorized: true,
        authority_instance_digest: CONTROL_AUTHORITY_DIGEST,
        action_digest: actionDigest,
    };
}
export async function runSupplyChainAuthorityDemo() {
    const exactAction = machineAction('warehouse_move_exact_1', 'pallet-204');
    const substitutionBase = machineAction('warehouse_move_substitution_1', 'pallet-205');
    const pendingAtFreeze = machineAction('warehouse_move_freeze_1', 'pallet-206');
    const authorizedActionDigests = [exactAction, substitutionBase, pendingAtFreeze]
        .map(capabilityActionDigest);
    const receiptHarness = createEg1Harness({
        action: exactAction,
        now: () => NOW,
        idPrefix: 'supply-chain-authority',
    });
    const baseReceipt = receiptHarness.mint({
        outcome: 'allow_with_signoff',
        extra: { capability_only: true },
    });
    const capabilityIssuer = generateKeyPairSync('ed25519');
    const capability = mintCapabilityReceipt(baseReceipt, {
        issuerPrivateKey: capabilityIssuer.privateKey,
        budget: { amount: 2, currency: 'MACHINE_OP' },
        expiry: NOW + 60_000,
        revocationMode: 'direct',
        capabilityId: 'capability:supply-chain-authority-v1',
        secret: Buffer.alloc(32, 23),
        scope: {
            profile: CAPABILITY_SCOPE_PROFILE,
            operation_id_field: 'operation_id',
            action_digests: authorizedActionDigests,
        },
    });
    const store = createMemoryCapabilityStore({ verifyControlTransition });
    if (!store.registerCapability(capability.capabilityReceipt)) {
        throw new Error('capability registration failed');
    }
    const domain = await store.registerControlDomain({
        controlDomainId: CONTROL_DOMAIN_ID,
        now: NOW,
    });
    if (!domain.ok)
        throw new Error('control-domain registration failed');
    const capabilityId = capability.capabilityReceipt.capability.id;
    const fingerprint = store.getState(capabilityId).capability_fingerprint;
    let providerEntryCount = 0;
    const exactReservation = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: fingerprint,
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: exactAction.operation_id,
        actionDigest: capabilityActionDigest(exactAction),
        amount: exactAction.amount,
        currency: exactAction.currency,
        now: NOW + 1,
    });
    if (!exactReservation.ok)
        throw new Error(`exact reservation failed: ${exactReservation.reason}`);
    const exactEntry = await store.beginProviderEntry({
        capabilityId,
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: exactAction.operation_id,
        reservationToken: exactReservation.reservation_token,
        now: NOW + 2,
    });
    if (!exactEntry.ok)
        throw new Error(`provider entry failed: ${exactEntry.reason}`);
    providerEntryCount += 1;
    const exactCommit = await store.commitSpend({
        capabilityId,
        operationId: exactAction.operation_id,
        reservationToken: exactReservation.reservation_token,
        outcome: 'executed',
        now: NOW + 3,
    });
    if (!exactCommit.ok)
        throw new Error(`exact commit failed: ${exactCommit.reason}`);
    const retry = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: fingerprint,
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: exactAction.operation_id,
        actionDigest: capabilityActionDigest(exactAction),
        amount: exactAction.amount,
        currency: exactAction.currency,
        now: NOW + 4,
    });
    const substitutedAction = Object.freeze({
        ...substitutionBase,
        route_digest: digest('dock-a:unapproved-shortcut:freezer-b:pallet-205'),
        max_speed_mps: '2.4',
    });
    const substitution = verifyCapabilityScope(capability.capabilityReceipt.capability, substitutedAction, substitutionBase.operation_id);
    const pendingReservation = await store.reserveSpend({
        capabilityId,
        capabilityFingerprint: fingerprint,
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: pendingAtFreeze.operation_id,
        actionDigest: capabilityActionDigest(pendingAtFreeze),
        amount: pendingAtFreeze.amount,
        currency: pendingAtFreeze.currency,
        now: NOW + 6,
    });
    if (!pendingReservation.ok)
        throw new Error(`pending reservation failed: ${pendingReservation.reason}`);
    const frozen = await store.freezeControlDomain({
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: 'warehouse_freeze_1',
        actionDigest: FREEZE_ACTION_DIGEST,
        authorization: controlAuthorization(FREEZE_ACTION_DIGEST),
        now: NOW + 7,
    });
    if (!frozen.ok)
        throw new Error(`freeze failed: ${frozen.reason}`);
    const stopped = await store.beginProviderEntry({
        capabilityId,
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: pendingAtFreeze.operation_id,
        reservationToken: pendingReservation.reservation_token,
        now: NOW + 8,
    });
    const restored = await store.restoreControlDomain({
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: 'warehouse_restore_1',
        actionDigest: RESTORE_ACTION_DIGEST,
        authorization: controlAuthorization(RESTORE_ACTION_DIGEST),
        now: NOW + 9,
    });
    if (!restored.ok)
        throw new Error(`restore failed: ${restored.reason}`);
    const staleEntry = await store.beginProviderEntry({
        capabilityId,
        controlDomainId: CONTROL_DOMAIN_ID,
        operationId: pendingAtFreeze.operation_id,
        reservationToken: pendingReservation.reservation_token,
        now: NOW + 10,
    });
    return Object.freeze({
        '@version': 'EMILIA-SUPPLY-CHAIN-AUTHORITY-DEMO-v1',
        scenario: 'A digital twin proposes one exact warehouse robot move under finite customer authority.',
        exact_action: Object.freeze({
            action_digest: capabilityActionDigest(exactAction),
            provider_entered: exactEntry.ok === true,
            outcome: store.getOperation(exactAction.operation_id).outcome,
        }),
        substitution: Object.freeze({
            refused: substitution.ok !== true,
            reason: substitution.reason,
            provider_entered: false,
            authorized_action_digest: capabilityActionDigest(substitutionBase),
            presented_action_digest: capabilityActionDigest(substitutedAction),
        }),
        retry: Object.freeze({
            provider_entered: false,
            reason: retry.reason,
        }),
        freeze: Object.freeze({
            status: frozen.status,
            epoch: frozen.epoch,
            pending_action_outcome: stopped.outcome,
            reservation: stopped.reservation,
            restored_epoch: restored.epoch,
            old_reservation_reentered: staleEntry.ok === true,
            old_reservation_reason: staleEntry.reason,
        }),
        provider_entry_count: providerEntryCount,
        claim_boundary: 'Synthetic in-memory reference demonstration. It proves local Gate state transitions for these test bytes, not a live robot, durable production deployment, cross-domain guarantee, or physical-effect observation.',
    });
}
