#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Cross-Gateway Evidence Lab.
 *
 * Two agent gateways in separate administrative domains enforce policy over
 * one consequential action, with one human-approval artifact between them.
 * Gateway A (the sending organization's egress) validates the evidence and
 * records its own enforcement decision. Gateway B (the receiving
 * organization's ingress, in front of the executor) verifies the SAME
 * artifact itself, under its own pinned trust anchors and its own
 * consumption ledger, and records a separate enforcement decision.
 *
 * The property under test: the artifact travels; the trust does not have to.
 * Neither gateway ingests the other's decision or log into its own trust
 * boundary, and the two audit trails join by the shared action digest, not by
 * cross-reference to each other's verdicts.
 *
 * Gateway B additionally owns two receiver-side properties that no presenter
 * can supply for it: whether the carried status evidence is still current
 * against B's own freshness bound, and what happens when B's own provider
 * leaves an attempt unresolved.
 */
import crypto from 'node:crypto';
import { createGate, createEg1Harness, hashCanonical, MemoryConsumptionStore, } from '../../packages/gate/index.js';
import { manifestFromPack } from '../../packages/gate/adapters/_kit.js';
import { evaluateCurrency, verifyStatusArtifact } from '../../packages/verify/index.js';
import { buildRevokerAuthorityCertificate, buildStatusArtifact, deriveRevokerKeyId, } from '../../lib/revocation/status.js';
export const LAB_VERSION = 'EP-CROSS-GATEWAY-EVIDENCE-LAB-v1';
export const EXACT_ACTION = Object.freeze({
    action_type: 'interorg.settlement.execute',
    settlement_id: 'stl-2026-07-4411',
    amount: '2500000.00',
    currency: 'USD',
    counterparty: 'org-b.example',
});
const SELECTOR = Object.freeze({ protocol: 'interorg', tool: 'execute_settlement' });
const ACTION_PACK = Object.freeze([
    Object.freeze({
        id: 'interorg.settlement.execute',
        label: 'Cross-organization settlement execution',
        action_type: 'interorg.settlement.execute',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'quorum',
        match: { protocol: SELECTOR.protocol, tool: SELECTOR.tool },
        why: 'Moves value across an administrative boundary. Bind the exact settlement; quorum.',
        execution_binding: {
            required_fields: ['action_type', 'settlement_id', 'amount', 'currency', 'counterparty'],
        },
    }),
]);
const QUORUM = Object.freeze({
    signers: ['ep:human:treasury-officer', 'ep:human:risk-officer'],
    threshold: 2,
});
/**
 * Gateway B's own freshness bound for carried status evidence, in seconds.
 * "Still current" is a receiver policy, never a presenter claim: B measures
 * the status bundle it was handed against this number and its own clock.
 */
const B_STATUS_MAX_STALENESS_SEC = 300;
/**
 * Gateway B's provider deadline, in milliseconds. A provider that has not
 * answered by the deadline has not failed; its outcome is unknown, which is a
 * different thing and is handled differently.
 */
const B_PROVIDER_DEADLINE_MS = 25;
/**
 * One gateway = one gate instance: its own trust anchors, its own consumption
 * ledger, its own evidence log. `pins` is what THIS gateway trusts out of
 * band; nothing else reaches its trust boundary. An explicit consumption store
 * is handed in so the lab can read the ledger a downstream failure must not
 * silently reopen.
 */
function makeGateway(gatewayId, pins, { providerEntryGuard = null } = {}) {
    const store = new MemoryConsumptionStore();
    return {
        gatewayId,
        store,
        gate: createGate({
            manifest: manifestFromPack([...ACTION_PACK]),
            trustedKeys: [pins.issuerKey],
            approverKeys: pins.approverKeys,
            rpId: pins.rpId,
            allowedOrigins: pins.allowedOrigins,
            quorumPolicy: pins.quorumPolicy,
            store,
            providerEntryGuard,
            allowEphemeralStore: true, // local compatibility lab; production gateways require durable shared state
        }),
    };
}
function decisionRecord(gatewayId, decision) {
    return {
        gateway: gatewayId,
        allow: decision.allow,
        status: decision.status,
        reason: decision.reason ?? null,
        observed_action_hash: decision.evidence?.observed_action_hash ?? null,
        receipt_id: decision.evidence?.receipt_id ?? null,
        consumption_key: decision.evidence?.consumption_key ?? null,
    };
}
async function gatewayACheck(gatewayA, action, receipt) {
    // Gateway A enforces at egress but is not the executor: it validates and
    // records without consuming, leaving one-time execution semantics to the
    // enforcement point that fronts the effect.
    const decision = await gatewayA.gate.check({
        selector: { ...SELECTOR },
        receipt,
        observedAction: action,
        consumptionMode: 'none',
    });
    return decisionRecord(gatewayA.gatewayId, decision);
}
/**
 * Gateway A holding its own leg. Used only where the lab needs a state at A
 * that a downstream failure could wrongly reopen: A reserves the artifact in
 * its own ledger, so "the leg at A" is an observable value and not a phrase.
 */
async function gatewayAHoldLeg(gatewayA, action, receipt) {
    const decision = await gatewayA.gate.check({
        selector: { ...SELECTOR },
        receipt,
        observedAction: action,
        consumptionMode: 'reserve',
    });
    return decisionRecord(gatewayA.gatewayId, decision);
}
/** Everything a downstream failure could reopen at a gateway, in one value. */
async function ledgerSnapshot(gateway) {
    const records = await gateway.gate.evidence.all();
    return {
        gateway: gateway.gatewayId,
        reserved: [...gateway.store.reserved].sort(),
        consumed: [...gateway.store.seen].sort(),
        evidence_records: records.length,
        evidence_head: records.at(-1)?.hash ?? null,
    };
}
/**
 * The receiving organization's status authority. Gateway B pins its root out
 * of band exactly as it pins the issuer and approver keys; a status bundle is
 * only evidence to B because B pinned who may sign one.
 */
async function createStatusAuthority(at) {
    const root = crypto.generateKeyPairSync('ed25519');
    const revoker = crypto.generateKeyPairSync('ed25519');
    const spki = (key) => key.export({ type: 'spki', format: 'der' }).toString('base64url');
    const signerFor = (keys, keyId) => ({
        algorithm: 'Ed25519',
        keyId,
        async sign(bytes) {
            return crypto.sign(null, Buffer.from(bytes), keys.privateKey).toString('base64url');
        },
    });
    const authorityPin = Object.freeze({
        authority_domain: 'status.org-b.example',
        authority_id: 'org:org-b',
        key_id: 'key:org-b-status-root',
        public_key: spki(root.publicKey),
    });
    const certificate = await buildRevokerAuthorityCertificate({
        certificateId: 'revoker-authority:org-b:primary:v1',
        authorityPin,
        revokerId: 'revoker:org-b:primary',
        revokerPublicKey: spki(revoker.publicKey),
        scope: { allowed_target_types: ['receipt'], allowed_usages: ['authorization'] },
        issuedAt: at(-30 * 86_400_000),
        expiresAt: at(30 * 86_400_000),
        signer: signerFor(root, authorityPin.key_id),
    });
    const revokerSigner = signerFor(revoker, deriveRevokerKeyId(spki(revoker.publicKey)));
    return {
        authorityPin,
        certificate,
        /** The exact target a status bundle must name to be about THIS artifact. */
        target(receipt) {
            return {
                type: 'receipt',
                id: receipt.payload.receipt_id,
                digest: `sha256:${hashCanonical(receipt)}`,
                usage: 'authorization',
            };
        },
        async issue(receipt, { issuedAt, nextUpdate }) {
            return buildStatusArtifact({
                authorityPin,
                certificate,
                target: this.target(receipt),
                status: 'not_revoked',
                issuedAt,
                nextUpdate,
                signer: revokerSigner,
            });
        },
    };
}
/**
 * Gateway B's status-and-freshness policy, evaluated at the provider-entry
 * boundary: the last point at which B still owns the decision and the effect
 * has not begun. Both checks are the repository's own verifiers, so the
 * refusal reason is the one the mechanism produced, not one this file chose.
 *
 * Fail-closed in both directions: no bundle refuses, and a bundle that is past
 * its own next_update or older than B's bound refuses. Nothing here can return
 * "current" because the presenter said so.
 */
function statusFreshnessGuard(authority, presentedStatus) {
    return (context) => {
        const receiptId = context.authorization?.evidence?.receipt_id ?? null;
        const presentation = receiptId === null ? null : presentedStatus.get(receiptId);
        if (!presentation) {
            return {
                ok: false,
                reason: 'status_evidence_absent',
                status: 409,
                reservation: 'release',
                evidence: { mechanism: 'EP-STATUS-v1', presented: false },
            };
        }
        // EP-STATUS-v1: is this signed bundle about this exact artifact, from the
        // authority B pinned, and still inside its own declared validity window?
        const statusCheck = verifyStatusArtifact(presentation.target, presentation.status, {
            authorityPin: authority.authorityPin,
            certificate: authority.certificate,
            now: context.checked_at,
        });
        if (!statusCheck.valid) {
            return {
                ok: false,
                reason: statusCheck.reasons[0],
                status: 409,
                reservation: 'release',
                evidence: {
                    mechanism: 'EP-STATUS-v1',
                    status_outcome: statusCheck.outcome,
                    reasons: [...statusCheck.reasons],
                    next_update: statusCheck.next_update,
                    evaluated_at: context.checked_at,
                },
            };
        }
        // An AUTHENTIC bundle whose outcome is 'revoked' is valid evidence FOR
        // refusal: valid=true means the statement is real, not that the
        // authorization stands. Refuse before the currency check ever runs.
        if (statusCheck.outcome !== 'current_not_revoked') {
            return {
                ok: false,
                reason: 'status_revoked',
                status: 409,
                reservation: 'release',
                evidence: {
                    mechanism: 'EP-STATUS-v1',
                    status_outcome: statusCheck.outcome,
                    evaluated_at: context.checked_at,
                },
            };
        }
        // EP-CURRENCY-v1: the bundle is internally valid, but is it recent enough
        // for THIS receiver? Only a head inside B's own bound reaches 'fresh'.
        const currency = evaluateCurrency({
            receipt: presentation.receipt,
            authentic_as_of_commit: true,
            now: context.checked_at,
            maxStalenessSeconds: B_STATUS_MAX_STALENESS_SEC,
            freshHead: { observed_at: presentation.status.issued_at },
            freshHeadRequired: true,
        });
        if (currency.currency_at_T.status !== 'fresh') {
            return {
                ok: false,
                reason: currency.currency_at_T.reason,
                status: 409,
                reservation: 'release',
                evidence: {
                    mechanism: 'EP-CURRENCY-v1',
                    currency_status: currency.currency_at_T.status,
                    evaluated_at: currency.currency_at_T.evaluated_at,
                    max_staleness_sec: B_STATUS_MAX_STALENESS_SEC,
                },
            };
        }
        return {
            ok: true,
            evidence: {
                status_outcome: statusCheck.outcome,
                currency_status: currency.currency_at_T.status,
                max_staleness_sec: B_STATUS_MAX_STALENESS_SEC,
            },
        };
    };
}
/** Run the cross-gateway lab and return a machine-readable result. */
export async function runCrossGatewayLab() {
    const labNow = Date.now();
    const at = (offsetMs) => new Date(labNow + offsetMs).toISOString();
    // The approving humans and the issuer live in the sending organization.
    const harness = createEg1Harness({ action: /** @type {any} */ (EXACT_ACTION), idPrefix: 'xgw' });
    const pins = {
        issuerKey: harness.publicKey,
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        quorumPolicy: harness.quorumPolicy,
    };
    // Gateway B pins its own status root out of band, alongside its issuer and
    // approver pins. Gateway A never sees it and cannot speak for it.
    const authority = await createStatusAuthority(at);
    const presentedStatus = new Map();
    // Both organizations pinned the issuer and approver keys OUT OF BAND.
    // The gate instances share nothing: not a store, not a log, not a registry.
    const gatewayA = makeGateway('gateway-a.org-a.example', pins);
    const gatewayB = makeGateway('gateway-b.org-b.example', pins, {
        providerEntryGuard: statusFreshnessGuard(authority, presentedStatus),
    });
    /** Hand Gateway B the status bundle that travels with an artifact. */
    async function present(receipt, window) {
        const status = await authority.issue(receipt, window);
        presentedStatus.set(receipt.payload.receipt_id, {
            receipt,
            status,
            target: authority.target(receipt),
        });
        return status;
    }
    const currentWindow = () => ({ issuedAt: at(-60_000), nextUpdate: at(4 * 60_000) });
    const staleWindow = () => ({ issuedAt: at(-20 * 60_000), nextUpdate: at(-15 * 60_000) });
    const executorCalls = [];
    const executor = async () => {
        executorCalls.push(structuredClone(EXACT_ACTION));
        return { settled: true, settlement_id: EXACT_ACTION.settlement_id };
    };
    // A provider that is entered and then goes quiet past Gateway B's deadline.
    // Entry is recorded because entry is exactly what makes the outcome unknown.
    const providerEntries = [];
    const unresolvedProvider = async () => {
        providerEntries.push(structuredClone(EXACT_ACTION));
        await new Promise((_, reject) => {
            setTimeout(() => reject(new Error('provider deadline exceeded, outcome unknown')), B_PROVIDER_DEADLINE_MS);
        });
        return { settled: true, settlement_id: EXACT_ACTION.settlement_id };
    };
    async function gatewayBExecute(action, receipt, effect = executor) {
        const outcome = await gatewayB.gate.run({ selector: { ...SELECTOR }, receipt, observedAction: action }, effect);
        return {
            record: decisionRecord(gatewayB.gatewayId, outcome.authorization),
            outcome,
        };
    }
    /**
     * Same call, but keeping the terminal outcome the gate raises once the
     * effect has been entered. Gate signals that case by throwing, because a
     * caller must not be able to mistake it for a plain refusal.
     */
    async function gatewayBAttempt(action, receipt, effect) {
        try {
            const outcome = await gatewayBExecute(action, receipt, effect);
            return { ...outcome, terminal: null };
        }
        catch (error) {
            return { record: null, outcome: null, terminal: error?.emiliaGateOutcome ?? null };
        }
    }
    const cases = [];
    // 1. Fail-closed at the first enforcement point: no artifact, no forward.
    const aWithoutEvidence = await gatewayACheck(gatewayA, EXACT_ACTION, null);
    cases.push({
        id: 'a-refuses-without-evidence',
        title: 'Gateway A refuses to forward a consequential action with no approval artifact',
        a: aWithoutEvidence,
        b: null,
        executor_called: false,
        verdict: 'refuse',
        reason: aWithoutEvidence.reason,
    });
    // 2. The through-case: one artifact, two independent verifications, one execution.
    const artifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const aDecision = await gatewayACheck(gatewayA, EXACT_ACTION, artifact);
    const throughStatus = await present(artifact, currentWindow());
    const before = executorCalls.length;
    const { record: bDecision, outcome } = await gatewayBExecute(EXACT_ACTION, artifact);
    cases.push({
        id: 'one-artifact-two-independent-verifications',
        title: 'Gateway A validates and records; Gateway B re-verifies the same artifact under its own anchors and executes once',
        a: aDecision,
        b: bDecision,
        executor_called: executorCalls.length === before + 1,
        verdict: 'execute',
        reason: null,
        audit_join: {
            shared_action_hash: hashCanonical(EXACT_ACTION),
            a_recorded: aDecision.observed_action_hash,
            b_recorded: bDecision.observed_action_hash,
            joined_by_action_digest: aDecision.observed_action_hash === bDecision.observed_action_hash
                && aDecision.observed_action_hash === hashCanonical(EXACT_ACTION),
        },
        execution_binds_authorization: outcome.execution?.authorizes_decision === outcome.packet?.summary?.decision_hash,
        status_evidence: {
            mechanism: 'EP-STATUS-v1 + EP-CURRENCY-v1',
            next_update: throughStatus.next_update,
            admitted_by_b: true,
        },
    });
    // 3. A gateway's verdict is not evidence. Forwarding Gateway A's allow
    //    decision without the artifact gets refused: decisions do not travel.
    const bFromVerdictOnly = await gatewayB.gate.check({
        selector: { ...SELECTOR },
        receipt: null,
        observedAction: EXACT_ACTION,
        consumptionMode: 'none',
    });
    cases.push({
        id: 'decision-does-not-travel',
        title: 'Gateway B refuses when offered Gateway A\'s allow verdict instead of the artifact',
        a: aDecision,
        b: decisionRecord(gatewayB.gatewayId, bFromVerdictOnly),
        executor_called: false,
        verdict: 'refuse',
        reason: bFromVerdictOnly.reason,
        note: 'Gateway A allowed the same action minutes earlier; that verdict is not presentable evidence at Gateway B.',
    });
    // 4. Tampered in transit: A saw the honest action, B is asked to execute an
    //    altered one with the same artifact. The binding refuses by name.
    const altered = { ...EXACT_ACTION, amount: '9500000.00' };
    const freshArtifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const aHonest = await gatewayACheck(gatewayA, EXACT_ACTION, freshArtifact);
    const bAltered = await gatewayB.gate.check({
        selector: { ...SELECTOR },
        receipt: freshArtifact,
        observedAction: altered,
        consumptionMode: 'none',
    });
    cases.push({
        id: 'tampered-in-transit-refused-at-b',
        title: 'The amount is altered between the gateways; Gateway B refuses the mismatched action',
        a: aHonest,
        b: decisionRecord(gatewayB.gatewayId, bAltered),
        executor_called: false,
        verdict: 'refuse',
        reason: bAltered.reason,
    });
    // 5. Gateway A allowing is not Gateway B accepting. A misconfigured Gateway
    //    A' pins a rogue issuer; Gateway B does not. Same artifact, two anchors,
    //    two verdicts.
    const rogue = createEg1Harness({ action: /** @type {any} */ (EXACT_ACTION), idPrefix: 'xgw_rogue' });
    const misconfiguredA = makeGateway('gateway-a2.org-a.example', {
        issuerKey: rogue.publicKey,
        approverKeys: rogue.approverKeys,
        rpId: rogue.rpId,
        allowedOrigins: rogue.allowedOrigins,
        quorumPolicy: rogue.quorumPolicy,
    });
    const rogueArtifact = rogue.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const aRogue = await gatewayACheck(misconfiguredA, EXACT_ACTION, rogueArtifact);
    const bRogue = await gatewayB.gate.check({
        selector: { ...SELECTOR },
        receipt: rogueArtifact,
        observedAction: EXACT_ACTION,
        consumptionMode: 'none',
    });
    cases.push({
        id: 'b-does-not-inherit-a-trust',
        title: 'A gateway that pins a rogue issuer allows; Gateway B, which does not pin it, refuses the same artifact',
        a: aRogue,
        b: decisionRecord(gatewayB.gatewayId, bRogue),
        executor_called: false,
        verdict: 'refuse',
        reason: bRogue.reason,
        note: 'VERIFIED under one set of anchors is never ACCEPTED under another; each gateway answers for its own pins.',
    });
    // 6. Replay at the executor's gateway: the consumed artifact cannot drive a
    //    second execution.
    const beforeReplay = executorCalls.length;
    const replay = await gatewayB.gate.run({ selector: { ...SELECTOR }, receipt: /** @type {any} */ (artifact), observedAction: /** @type {any} */ (EXACT_ACTION) }, executor);
    cases.push({
        id: 'replay-refused-at-b',
        title: 'The already-consumed artifact cannot drive a second execution at Gateway B',
        a: null,
        b: decisionRecord(gatewayB.gatewayId, replay.authorization),
        executor_called: executorCalls.length > beforeReplay,
        verdict: 'refuse',
        reason: replay.authorization.reason,
    });
    // 7. Status and freshness are the receiver's question. The artifact itself
    //    still verifies; the signed statement about whether it is STILL good is
    //    past its own next_update and past Gateway B's bound. B refuses by the
    //    name the status mechanism produced, and never falls open.
    const staleArtifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const aStale = await gatewayACheck(gatewayA, EXACT_ACTION, staleArtifact);
    const staleStatus = await present(staleArtifact, staleWindow());
    const beforeStale = executorCalls.length;
    const { record: bStale, outcome: staleOutcome } = await gatewayBExecute(EXACT_ACTION, staleArtifact);
    // Same policy, nothing presented at all: absence is not currency either.
    const unattestedArtifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const { record: bUnattested } = await gatewayBExecute(EXACT_ACTION, unattestedArtifact);
    // Same policy, a bundle still inside its OWN declared window but older than
    // Gateway B's bound. The issuer's window is not the receiver's bound, and
    // the second check is refusing on its own here, not echoing the first.
    const looseArtifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    await present(looseArtifact, { issuedAt: at(-10 * 60_000), nextUpdate: at(10 * 60_000) });
    const { record: bLoose } = await gatewayBExecute(EXACT_ACTION, looseArtifact);
    cases.push({
        id: 'stale-status-refused-at-b',
        title: 'The carried status evidence is past its own next_update and past Gateway B\'s freshness bound; Gateway B refuses',
        a: aStale,
        b: bStale,
        executor_called: executorCalls.length > beforeStale,
        verdict: 'refuse',
        reason: bStale.reason,
        status_evidence: {
            ...(staleOutcome.authorization?.evidence?.guard_evidence ?? {}),
            presented_next_update: staleStatus.next_update,
            b_max_staleness_sec: B_STATUS_MAX_STALENESS_SEC,
        },
        fail_closed_without_status: {
            reason: bUnattested.reason,
            allow: bUnattested.allow,
        },
        b_bound_refuses_inside_issuer_window: {
            reason: bLoose.reason,
            allow: bLoose.allow,
        },
        control_current_status_admitted: cases[1].verdict === 'execute',
        note: 'The same policy admitted a current bundle in case 2, so this is a discriminating check and not a blanket refusal. Gateway A validated the artifact and would have forwarded it; currency is not A\'s to assert.',
    });
    // 8. Gateway B enters its provider and the deadline passes with the outcome
    //    unresolved. The attempt may have landed. The authorization is therefore
    //    committed at B and NOT returned to the pool, a blind retry is refused,
    //    and nothing about the leg Gateway A is holding changes.
    const indeterminateArtifact = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
    const beforeIndeterminate = executorCalls.length;
    const aLeg = await gatewayAHoldLeg(gatewayA, EXACT_ACTION, indeterminateArtifact);
    const aBefore = await ledgerSnapshot(gatewayA);
    await present(indeterminateArtifact, currentWindow());
    const attempt = await gatewayBAttempt(EXACT_ACTION, indeterminateArtifact, unresolvedProvider);
    const aAfter = await ledgerSnapshot(gatewayA);
    // A blind retry, carrying a freshly issued current status bundle so the only
    // thing standing in its way is the unresolved attempt itself.
    await present(indeterminateArtifact, currentWindow());
    const { record: bRetry } = await gatewayBExecute(EXACT_ACTION, indeterminateArtifact);
    const aStillFenced = await gatewayAHoldLeg(gatewayA, EXACT_ACTION, indeterminateArtifact);
    const consumptionKey = attempt.terminal?.authorizationEvidence?.consumption_key;
    if (typeof consumptionKey !== 'string' || consumptionKey.length === 0) {
        throw new Error('indeterminate authorization omitted its exact consumption key');
    }
    if (aLeg.consumption_key !== consumptionKey) {
        throw new Error('gateway legs did not bind the same tenant-scoped consumption key');
    }
    cases.push({
        id: 'indeterminate-does-not-reopen-a',
        title: 'Gateway B\'s provider leaves the outcome unresolved; the authorization is committed at B, the retry is refused, and Gateway A\'s leg is untouched',
        a: aLeg,
        b: null,
        executor_called: executorCalls.length > beforeIndeterminate,
        provider_entered: providerEntries.length === 1,
        verdict: 'indeterminate',
        reason: attempt.terminal?.reason ?? null,
        indeterminate: {
            outcome: attempt.terminal?.outcome ?? null,
            execution_record_kind: attempt.terminal?.execution?.kind ?? null,
            execution_record_outcome: attempt.terminal?.execution?.outcome ?? null,
            execution_record_code: attempt.terminal?.execution?.detail?.code ?? null,
            authorizes_decision: attempt.terminal?.execution?.authorizes_decision ?? null,
        },
        not_returned_to_pool: {
            consumption_key: consumptionKey,
            committed_at_b: gatewayB.store.seen.has(consumptionKey),
            still_reserved_at_b: gatewayB.store.reserved.has(consumptionKey),
            blind_retry_at_b: { allow: bRetry.allow, reason: bRetry.reason },
        },
        a_leg: {
            before: aBefore,
            after: aAfter,
            unchanged: JSON.stringify(aBefore) === JSON.stringify(aAfter),
            still_reserved: gatewayA.store.reserved.has(consumptionKey),
            re_presentation: { allow: aStillFenced.allow, reason: aStillFenced.reason },
        },
        note: 'An unresolved provider is not a proven non-effect. Committing rather than releasing is what makes the retry refusable; releasing would have handed the same approval back for a second attempt.',
    });
    return {
        '@version': LAB_VERSION,
        title: 'Cross-Gateway Evidence Lab',
        scenario: 'Gateway A (org-a egress) and Gateway B (org-b ingress, fronting the executor) enforce one consequential action with one human-approval artifact.',
        action: EXACT_ACTION,
        requirement: {
            assurance_class: 'quorum',
            exact_fields: [...ACTION_PACK[0].execution_binding.required_fields],
            verifier_trust: 'each gateway pins issuer and approver keys out of band; no gateway trusts another gateway\'s verdict',
            one_time_consumption: 'local to the enforcement point that fronts the effect',
            status_freshness: `Gateway B pins its own status root and admits a status bundle only within ${B_STATUS_MAX_STALENESS_SEC}s of issuance and before its own next_update`,
            indeterminate_outcome: 'an entered provider that does not resolve commits the authorization; it is never released back for a retry',
        },
        cases,
        executor_call_count: executorCalls.length,
        provider_entry_count: providerEntries.length,
        invariant: 'one approval artifact, independently verified at each enforcement point, executes exactly once; decisions never travel as evidence; stale status and unresolved outcomes both fail closed',
    };
}
function print(result) {
    const width = 76;
    const label = { execute: 'EXECUTE', indeterminate: 'UNKNOWN', refuse: 'REFUSE ' };
    console.log('\nCROSS-GATEWAY EVIDENCE LAB');
    console.log('='.repeat(width));
    console.log(`Action: ${result.action.action_type} · ${result.action.amount} ${result.action.currency} -> ${result.action.counterparty}`);
    console.log('-'.repeat(width));
    for (const [index, item] of result.cases.entries()) {
        const verdict = label[item.verdict] ?? 'REFUSE ';
        console.log(`${index + 1}. ${verdict} · ${item.id}`);
        console.log(`   ${item.title}`);
        if (item.reason)
            console.log(`   ${item.verdict === 'indeterminate' ? 'outcome names' : 'refusal names'}: ${item.reason}`);
        if (item.audit_join)
            console.log(`   audit records join by action digest: ${item.audit_join.joined_by_action_digest ? 'yes' : 'NO'}`);
        if (item.fail_closed_without_status)
            console.log(`   no status bundle at all names: ${item.fail_closed_without_status.reason}`);
        if (item.b_bound_refuses_inside_issuer_window)
            console.log(`   inside the issuer's window but past B's bound names: ${item.b_bound_refuses_inside_issuer_window.reason}`);
        if (item.not_returned_to_pool) {
            console.log(`   authorization committed at B, not released: ${item.not_returned_to_pool.committed_at_b && !item.not_returned_to_pool.still_reserved_at_b ? 'yes' : 'NO'}`);
            console.log(`   blind retry at B names: ${item.not_returned_to_pool.blind_retry_at_b.reason}`);
        }
        if (item.a_leg)
            console.log(`   Gateway A's leg unchanged: ${item.a_leg.unchanged ? 'yes' : 'NO'} (re-presentation names: ${item.a_leg.re_presentation.reason})`);
        if (item.provider_entered !== undefined)
            console.log(`   provider entered: ${item.provider_entered ? 'yes' : 'no'}`);
        console.log(`   executor called: ${item.executor_called ? 'yes' : 'no'}`);
    }
    console.log('-'.repeat(width));
    console.log(`Executor call count: ${result.executor_call_count} (expected exactly 1)`);
    console.log('The artifact travels; the trust does not have to.');
    console.log('Currency and unresolved outcomes stay with the receiver.\n');
}
if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
    const result = await runCrossGatewayLab();
    if (process.argv.includes('--json'))
        console.log(JSON.stringify(result, null, 2));
    else
        print(result);
}
