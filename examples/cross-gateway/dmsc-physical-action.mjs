// SPDX-License-Identifier: Apache-2.0
// Generated from dmsc-physical-action.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * DMSC cross-gateway action-authorization composition.
 *
 * Gateway B is the physical executor's enforcement point. It computes the
 * action and challenge, verifies human-authorization evidence carried through
 * Gateway A under B's own trust configuration, consumes the authorization once,
 * and signs a separate reliance decision. The gateway envelope is illustrative;
 * every EP object and cryptographic check uses the repository implementation.
 */
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { formatLogKeyId, generateEd25519KeyPair, issueAuthorizationReceipt, policyHash, publicKeyToSpkiB64u, } from '../../packages/issue/index.js';
import { verifyTrustReceipt } from '../../packages/verify/index.js';
import { createDurableChallengeStore } from '../../packages/gate/challenge-store.js';
import { createDurableConsumptionStore, createMemoryBackend } from '../../packages/gate/store.js';
import { createRegisteredEvidenceChallenge, evaluateRegisteredPresentation, } from '../../lib/negotiate/evidence-challenge.js';
import { artifactDigest, EVIDENCE_GRAPH_VERSION, evaluateEvidenceGraph, signRelianceResult, verifyRelianceResult, } from '../../lib/evidence/evidence-graph.js';
export const DMSC_DEMO_VERSION = 'DMSC-CROSS-GATEWAY-AUTHORIZATION-DEMO-v1';
export const DEMO_RP_ID = 'gateway.port-b.example';
export const DEMO_ORIGIN = `https://${DEMO_RP_ID}`;
const TIMES = Object.freeze({
    requested: '2026-07-13T22:00:00Z',
    approved: '2026-07-13T22:00:20Z',
    evaluated: '2026-07-13T22:00:30Z',
    challengeExpires: '2026-07-13T22:05:00Z',
    authorizationExpires: '2026-07-13T22:05:00Z',
});
export const DEMO_POLICY = Object.freeze({
    '@version': 'DMSC-ACTION-AUTHORIZATION-POLICY-DEMO-v1',
    policy_id: 'urn:example:dmsc:port-b:high-risk-physical-action:v1',
    reliance_purpose: 'physical_world_action_execution',
    requirement: 'human_authorization',
    required_assurance: Object.freeze({ human_authorization: 'class_a' }),
    freshness_sec: Object.freeze({ human_authorization: 300 }),
    revocation_required: Object.freeze(['human_authorization']),
    require_action_agreement: true,
    constraints: Object.freeze({
        action_type: 'port.container.move',
        target_system: 'port-b.crane-control',
        target_resource: 'crane-17',
        allowed_from_zone: 'yard-3',
        allowed_to_zone: 'berth-4',
        max_load_kg: '25000',
        valid_from: '2026-07-13T21:55:00Z',
        valid_until: '2026-07-13T22:10:00Z',
        risk_class: 'high',
    }),
});
export const DEMO_REQUEST = Object.freeze({
    request_id: 'urn:example:request:container-8841',
    initiator: 'urn:example:agent:logistics-a:dispatcher',
    command: 'move_container',
    container_id: 'MSCU-663987-4',
    from_zone: 'yard-3',
    to_zone: 'berth-4',
    load_kg: '18000',
});
function clone(value) {
    return structuredClone(value);
}
function nonEmptyString(value, name) {
    if (typeof value !== 'string' || !value.trim())
        throw new Error(`${name} must be a non-empty string`);
    return value;
}
function parseUnsignedInteger(value, name) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
        throw new Error(`${name} must be an unsigned base-10 integer string`);
    }
    return BigInt(value);
}
/** Gateway B converts a request into the exact local operation it may execute. */
export function computeGatewayAction(request, { requestedAt = TIMES.requested, policy = DEMO_POLICY } = {}) {
    if (!request || typeof request !== 'object' || Array.isArray(request))
        throw new Error('request must be an object');
    nonEmptyString(request.request_id, 'request_id');
    nonEmptyString(request.initiator, 'initiator');
    if (request.command !== 'move_container')
        throw new Error('command is not supported');
    nonEmptyString(request.container_id, 'container_id');
    if (request.from_zone !== policy.constraints.allowed_from_zone)
        throw new Error('from_zone is outside local policy');
    if (request.to_zone !== policy.constraints.allowed_to_zone)
        throw new Error('to_zone is outside local policy');
    if (parseUnsignedInteger(request.load_kg, 'load_kg') > BigInt(policy.constraints.max_load_kg)) {
        throw new Error('load_kg exceeds local policy');
    }
    const at = Date.parse(requestedAt);
    if (!Number.isFinite(at)
        || at < Date.parse(policy.constraints.valid_from)
        || at >= Date.parse(policy.constraints.valid_until)) {
        throw new Error('gateway evaluation time is outside the authorized window');
    }
    return Object.freeze({
        ep_version: '1.0',
        action_type: policy.constraints.action_type,
        target: Object.freeze({
            system: policy.constraints.target_system,
            resource: policy.constraints.target_resource,
        }),
        parameters: Object.freeze({
            command: request.command,
            container_id: request.container_id,
            from_zone: request.from_zone,
            to_zone: request.to_zone,
            load_kg: request.load_kg,
            valid_from: policy.constraints.valid_from,
            valid_until: policy.constraints.valid_until,
            risk_class: policy.constraints.risk_class,
        }),
        initiator: request.initiator,
        executor: 'urn:example:gateway:port-b',
        policy_id: policy.policy_id,
        requested_at: requestedAt,
    });
}
/**
 * @returns {{
 *   approverId: string,
 *   approverKeyId: string,
 *   keyEntry: { approver_id: string, public_key: string, key_class: 'A', valid_from: string, valid_to: string },
 *   signer: {
 *     approverKeyId: string,
 *     keyClass: 'A',
 *     signedAt: string,
 *     signWebAuthn: (digest: Buffer) => { authenticator_data: string, client_data_json: string, signature: string },
 *   },
 * }}
 */
function createClassAApprover({ approverId = 'urn:example:human:port-b-duty-supervisor', approverKeyId = 'urn:example:key:port-b-duty-supervisor:1', rpId = DEMO_RP_ID, origin = DEMO_ORIGIN, } = {}) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
        approverId,
        approverKeyId,
        keyEntry: {
            approver_id: approverId,
            public_key: publicKeyToSpkiB64u(publicKey),
            key_class: 'A',
            valid_from: '2026-01-01T00:00:00Z',
            valid_to: '2027-01-01T00:00:00Z',
        },
        signer: {
            approverKeyId,
            keyClass: 'A',
            signedAt: TIMES.approved,
            signWebAuthn: (digest) => {
                const clientData = Buffer.from(JSON.stringify({
                    type: 'webauthn.get',
                    challenge: digest.toString('base64url'),
                    origin,
                }), 'utf8');
                const authenticatorData = Buffer.concat([
                    crypto.createHash('sha256').update(rpId).digest(),
                    Buffer.from([0x05]), // user present + user verified
                    Buffer.from([0, 0, 0, 1]),
                ]);
                const signedData = Buffer.concat([
                    authenticatorData,
                    crypto.createHash('sha256').update(clientData).digest(),
                ]);
                return {
                    authenticator_data: authenticatorData.toString('base64url'),
                    client_data_json: clientData.toString('base64url'),
                    signature: crypto.sign('sha256', signedData, privateKey).toString('base64url'),
                };
            },
        },
    };
}
/**
 * @typedef {Object} StoreBackend
 * @property {boolean} [durable]
 * @property {(key: any, value: any) => Promise<boolean>} addIfAbsent
 * @property {(key: any, expected: any, replacement: any) => Promise<boolean>} compareAndSet
 * @property {(key: any, expected: any) => Promise<boolean>} deleteIfValue
 * @property {(key: any) => Promise<boolean>} has
 */
/** @typedef {ReturnType<typeof createApprovalAuthority>} ApprovalAuthority */
/** @typedef {ApprovalAuthority['verification']} PinnedVerification */
export function createApprovalAuthority(options = {}) {
    const rpId = options.rpId ?? DEMO_RP_ID;
    const approver = createClassAApprover({
        ...options,
        rpId,
        origin: options.origin ?? `https://${rpId}`,
    });
    const log = generateEd25519KeyPair();
    return Object.freeze({
        approver,
        log: Object.freeze({
            private_key: log.privateKeyB64u,
            public_key: log.publicKeyB64u,
            key_id: formatLogKeyId(options.logName ?? 'dmsc-port-b'),
        }),
        verification: Object.freeze({
            approverKeys: Object.freeze({ [approver.approverKeyId]: Object.freeze(clone(approver.keyEntry)) }),
            logPublicKey: log.publicKeyB64u,
            rpId,
            allowedOrigins: Object.freeze([options.origin ?? `https://${rpId}`]),
        }),
    });
}
/**
 * Gateway A may carry this receipt, but cannot choose which keys Gateway B trusts.
 * @param {Object} [params]
 * @param {object} [params.action]
 * @param {ApprovalAuthority} [params.authority]
 * @param {object} [params.policy]
 * @param {string} [params.receiptId]
 */
export async function issueHumanAuthorization({ action, authority, policy = DEMO_POLICY, receiptId = 'urn:example:ep-receipt:dmsc-cross-gateway:1', } = {}) {
    // Every call site in this module passes `authority`; the param is only
    // optional in the destructuring shorthand because the whole `params`
    // object itself defaults to `{}`.
    const pinnedAuthority = /** @type {ApprovalAuthority} */ (authority);
    return issueAuthorizationReceipt({
        receiptId,
        action,
        policyHash: policyHash(policy),
        approvers: [pinnedAuthority.approver.approverId],
        requiredApprovals: 1,
        issuedAt: TIMES.approved,
        expiresAt: TIMES.authorizationExpires,
        committedAt: TIMES.approved,
        signers: [pinnedAuthority.approver.signer],
        log: {
            privateKeyB64u: pinnedAuthority.log.private_key,
            logKeyId: pinnedAuthority.log.key_id,
        },
    });
}
function evidenceGraph(action, receipt) {
    return {
        '@version': EVIDENCE_GRAPH_VERSION,
        action_digest: artifactDigest(action),
        nodes: receipt ? [{
                id: artifactDigest(receipt),
                type: 'human_authorization',
                artifact: clone(receipt),
            }] : [],
        edges: [],
    };
}
function authorizationVerifier({ action, policy, verification, revokedEvidenceDigests }) {
    return (receipt) => {
        const report = verifyTrustReceipt(receipt, {
            approverKeys: verification.approverKeys,
            logPublicKey: verification.logPublicKey,
            strict: true,
            rpId: verification.rpId,
            allowedOrigins: verification.allowedOrigins,
            expectedPolicyHash: policyHash(policy),
        });
        let receiptActionDigest = null;
        try {
            receiptActionDigest = artifactDigest(receipt?.action);
        }
        catch { /* refusal below */ }
        const artifactId = (() => {
            try {
                return artifactDigest(receipt);
            }
            catch {
                return null;
            }
        })();
        return {
            valid: report.valid === true && receiptActionDigest === artifactDigest(action),
            action_digest: receiptActionDigest,
            issued_at: receipt?.contexts?.[0]?.issued_at,
            outcome: 'allow',
            revoked: artifactId !== null && revokedEvidenceDigests.has(artifactId),
        };
    };
}
/**
 * @param {string} reason
 * @param {(Awaited<ReturnType<typeof evaluateRegisteredPresentation>>|null)} [base]
 */
function refusal(reason, base = null) {
    return {
        allow: false,
        verdict: 'refuse',
        reason,
        base_verdict: base?.verdict ?? null,
        base,
        decision: null,
    };
}
/**
 * Construct Gateway B. The default stores are atomic single-process reference
 * backends for a runnable demo; callers can inject shared durable backends.
 * @param {Object} [params]
 * @param {object} [params.policy]
 * @param {PinnedVerification} [params.verification]
 * @param {StoreBackend} [params.challengeBackend]
 * @param {StoreBackend} [params.actionBackend]
 * @param {Set<string>} [params.revokedEvidenceDigests]
 * @param {() => string} [params.now]
 */
export function createReceivingGateway({ policy = DEMO_POLICY, verification, challengeBackend = createMemoryBackend(), actionBackend = createMemoryBackend(), revokedEvidenceDigests = new Set(), now = () => TIMES.evaluated, } = {}) {
    if (!verification)
        throw new Error('Gateway B requires pinned verification material');
    if (!(revokedEvidenceDigests instanceof Set))
        throw new Error('Gateway B requires explicit revocation state');
    const challengeStore = createDurableChallengeStore(challengeBackend);
    const actionStore = createDurableConsumptionStore(actionBackend);
    const decisionKey = generateEd25519KeyPair();
    let challengeCounter = 0;
    async function challenge(request) {
        const action = computeGatewayAction(request, { requestedAt: TIMES.requested, policy });
        challengeCounter += 1;
        const document = await createRegisteredEvidenceChallenge(action, policy, {
            challengeStore,
            challenge_id: `urn:example:challenge:port-b:${challengeCounter}`,
            nonce: crypto.randomBytes(24).toString('base64url'),
            expires_at: TIMES.challengeExpires,
            obtain_hints: [{ type: 'human_authorization', carrier: 'gateway-a' }],
        });
        return { action, challenge: document };
    }
    async function evaluate({ action, challenge: challengeDocument, receipt }) {
        let graph;
        try {
            graph = evidenceGraph(action, receipt);
        }
        catch {
            return refusal('malformed_action_or_evidence');
        }
        const evaluatedAt = now();
        /** @type {{ verdict: string, reasons: any[], next_challenge: any, result?: any, replay_digest?: any }} */
        let base;
        try {
            base = await evaluateRegisteredPresentation(challengeDocument, graph, policy, {
                challengeStore,
                verifiers: {
                    human_authorization: authorizationVerifier({
                        action,
                        policy,
                        verification,
                        revokedEvidenceDigests,
                    }),
                },
                as_of: evaluatedAt,
                next_expires_at: TIMES.challengeExpires,
            });
        }
        catch {
            return refusal('challenge_storage_unavailable');
        }
        if (base.verdict !== 'admissible') {
            return refusal(base.reasons?.[0] ?? `evidence_${base.verdict}`, base);
        }
        const actionDigest = artifactDigest(action);
        let firstUse;
        try {
            firstUse = await actionStore.consume(`dmsc-action:${actionDigest}`);
        }
        catch {
            return refusal('action_consumption_storage_unavailable', base);
        }
        if (firstUse !== true)
            return refusal('action_already_consumed', base);
        const decision = signRelianceResult(base.result, policy, decisionKey.privateKey, {
            evaluated_at: evaluatedAt,
        });
        return {
            allow: true,
            verdict: 'allow',
            reason: null,
            action_digest: actionDigest,
            base_verdict: base.verdict,
            graph,
            decision,
        };
    }
    return Object.freeze({
        challenge,
        evaluate,
        policy,
        decisionPublicKey: decisionKey.publicKeyB64u,
        demoStateOnly: challengeBackend.durable !== true || actionBackend.durable !== true,
    });
}
/**
 * Reperform Gateway B's decision with no network call and no mutable gateway log.
 * @param {object} bundle
 * @param {Object} [options]
 * @param {object} [options.policy]
 * @param {PinnedVerification} [options.verification]
 * @param {string} [options.pinnedGatewayDecisionKey]
 * @param {Set<string>} [options.revokedEvidenceDigests]
 */
export function verifyAuditBundle(bundle, { policy = DEMO_POLICY, verification, pinnedGatewayDecisionKey, revokedEvidenceDigests = new Set(), } = {}) {
    try {
        if (!bundle || typeof bundle !== 'object')
            throw new Error('bundle missing');
        if (!(revokedEvidenceDigests instanceof Set))
            throw new Error('revocation state missing');
        const actionDigest = artifactDigest(bundle.action);
        if (bundle.graph?.action_digest !== actionDigest)
            throw new Error('graph/action mismatch');
        const evaluatedAt = bundle.decision?.payload?.evaluated_at;
        const recomputed = evaluateEvidenceGraph(bundle.graph, policy, {
            verifiers: {
                human_authorization: authorizationVerifier({
                    action: bundle.action,
                    policy,
                    verification,
                    revokedEvidenceDigests,
                }),
            },
            as_of: evaluatedAt,
        });
        // Marked optional in this function's JSDoc, but both call sites in this
        // example always pass it before reaching this verification branch.
        const signature = verifyRelianceResult(bundle.decision, [/** @type {string} */ (pinnedGatewayDecisionKey)]);
        const payload = bundle.decision.payload;
        const reproducible = signature.accepted === true
            && recomputed.verdict === payload.verdict
            && recomputed.action_digest === payload.action_digest
            && recomputed.graph?.graph_digest === payload.graph_digest
            && recomputed.replay_digest === payload.replay_digest
            && artifactDigest(policy) === payload.policy_digest;
        return {
            verified: reproducible && recomputed.verdict === 'admissible',
            signature,
            recomputed,
            limitation: 'Verification establishes the signed approval and reproducible gateway decision, not physical execution or sensor truth.',
        };
    }
    catch (error) {
        return { verified: false, reason: error.message };
    }
}
async function validFlow(authority) {
    const gateway = createReceivingGateway({ verification: authority.verification });
    const prepared = await gateway.challenge(DEMO_REQUEST);
    const receipt = await issueHumanAuthorization({ action: prepared.action, authority });
    const result = await gateway.evaluate({ ...prepared, receipt });
    const auditBundle = result.allow ? {
        '@version': DMSC_DEMO_VERSION,
        action: clone(prepared.action),
        graph: clone(result.graph),
        decision: clone(result.decision),
    } : null;
    return { gateway, prepared, receipt, result, auditBundle };
}
export async function runCrossGatewayDemo({ print = false } = {}) {
    const authority = createApprovalAuthority();
    const valid = await validFlow(authority);
    const missingGateway = createReceivingGateway({ verification: authority.verification });
    const missingPrepared = await missingGateway.challenge(DEMO_REQUEST);
    const missingApproval = await missingGateway.evaluate({ ...missingPrepared, receipt: null });
    const replay = await valid.gateway.evaluate({ ...valid.prepared, receipt: valid.receipt });
    const freshChallenge = await valid.gateway.challenge(DEMO_REQUEST);
    const secondClearance = await valid.gateway.evaluate({ ...freshChallenge, receipt: valid.receipt });
    const revokedReceipt = await issueHumanAuthorization({
        action: valid.prepared.action,
        authority,
        receiptId: 'urn:example:ep-receipt:revoked',
    });
    const revokedGateway = createReceivingGateway({
        verification: authority.verification,
        revokedEvidenceDigests: new Set([artifactDigest(revokedReceipt)]),
    });
    const revokedPrepared = await revokedGateway.challenge(DEMO_REQUEST);
    const revokedApproval = await revokedGateway.evaluate({ ...revokedPrepared, receipt: revokedReceipt });
    const expiredGateway = createReceivingGateway({
        verification: authority.verification,
        now: () => TIMES.challengeExpires,
    });
    const expiredPrepared = await expiredGateway.challenge(DEMO_REQUEST);
    const expiredChallenge = await expiredGateway.evaluate({ ...expiredPrepared, receipt: valid.receipt });
    const memory = createMemoryBackend();
    const unavailableChallengeBackend = {
        durable: false,
        addIfAbsent: (key, value) => memory.addIfAbsent(key, value),
        compareAndSet: async () => { throw new Error('simulated challenge-store outage'); },
        deleteIfValue: (key, expected) => memory.deleteIfValue(key, expected),
        has: (key) => memory.has(key),
    };
    const unavailableGateway = createReceivingGateway({
        verification: authority.verification,
        challengeBackend: unavailableChallengeBackend,
    });
    const unavailablePrepared = await unavailableGateway.challenge(DEMO_REQUEST);
    const unavailableStore = await unavailableGateway.evaluate({
        ...unavailablePrepared,
        receipt: valid.receipt,
    });
    const swapGateway = createReceivingGateway({ verification: authority.verification });
    const swapPrepared = await swapGateway.challenge(DEMO_REQUEST);
    const swappedAction = clone(swapPrepared.action);
    swappedAction.parameters.to_zone = 'restricted-zone';
    const actionSubstitution = await swapGateway.evaluate({
        action: swappedAction,
        challenge: swapPrepared.challenge,
        receipt: await issueHumanAuthorization({ action: swapPrepared.action, authority, receiptId: 'urn:example:ep-receipt:swap' }),
    });
    const foreignAuthority = createApprovalAuthority({
        approverId: 'urn:example:human:untrusted-operator',
        approverKeyId: 'urn:example:key:untrusted-operator:1',
        logName: 'untrusted-operator',
    });
    const trustGateway = createReceivingGateway({ verification: authority.verification });
    const trustPrepared = await trustGateway.challenge(DEMO_REQUEST);
    const foreignReceipt = await issueHumanAuthorization({
        action: trustPrepared.action,
        authority: foreignAuthority,
        receiptId: 'urn:example:ep-receipt:untrusted',
    });
    const unpinnedAuthority = await trustGateway.evaluate({ ...trustPrepared, receipt: foreignReceipt });
    const offlineAudit = verifyAuditBundle(valid.auditBundle, {
        verification: authority.verification,
        pinnedGatewayDecisionKey: valid.gateway.decisionPublicKey,
    });
    const tamperedBundle = clone(valid.auditBundle);
    tamperedBundle.graph.nodes[0].artifact.action.parameters.to_zone = 'restricted-zone';
    const offlineTamper = verifyAuditBundle(tamperedBundle, {
        verification: authority.verification,
        pinnedGatewayDecisionKey: valid.gateway.decisionPublicKey,
    });
    const results = {
        valid: valid.result,
        missingApproval,
        revokedApproval,
        expiredChallenge,
        unavailableStore,
        replay,
        secondClearance,
        actionSubstitution,
        unpinnedAuthority,
        offlineAudit,
        offlineTamper,
        demoStateOnly: valid.gateway.demoStateOnly,
    };
    if (print) {
        const line = (status, label, detail = '') => console.log(`${status.padEnd(8)} ${label}${detail ? ` - ${detail}` : ''}`);
        console.log('DMSC cross-gateway action authorization');
        console.log('Gateway A carries evidence; Gateway B computes the action, pins trust, decides, and consumes.');
        console.log('');
        line(valid.result.allow ? 'ALLOW' : 'REFUSE', 'pinned Class-A approval for the exact port action', valid.result.allow ? valid.result.action_digest : null);
        line(missingApproval.allow ? 'ALLOW' : 'REFUSE', 'missing human approval', missingApproval.base_verdict ?? missingApproval.reason);
        line(revokedApproval.allow ? 'ALLOW' : 'REFUSE', 'revoked human approval', revokedApproval.base_verdict ?? revokedApproval.reason);
        line(expiredChallenge.allow ? 'ALLOW' : 'REFUSE', 'expired receiver challenge', expiredChallenge.reason);
        line(unavailableStore.allow ? 'ALLOW' : 'REFUSE', 'challenge store unavailable', unavailableStore.reason);
        line(actionSubstitution.allow ? 'ALLOW' : 'REFUSE', 'action substitution', actionSubstitution.reason);
        line(unpinnedAuthority.allow ? 'ALLOW' : 'REFUSE', 'self-issued/unpinned authority', unpinnedAuthority.base_verdict ?? unpinnedAuthority.reason);
        line(replay.allow ? 'ALLOW' : 'REFUSE', 'same challenge replay', replay.reason);
        line(secondClearance.allow ? 'ALLOW' : 'REFUSE', 'fresh challenge for an already-cleared action', secondClearance.reason);
        line(offlineAudit.verified ? 'VERIFY' : 'FAIL', 'offline re-performance of Gateway B decision');
        line(offlineTamper.verified ? 'VERIFY' : 'REFUSE', 'tampered offline bundle');
        console.log('');
        console.log('Demo state backend: atomic single-process memory (replace with shared durable storage in deployment).');
        console.log('Boundary: approval and policy evaluation are proven; physical execution and sensor truth are not.');
    }
    return results;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    runCrossGatewayDemo({ print: true }).catch((error) => {
        console.error(error);
        process.exitCode = 1;
    });
}
