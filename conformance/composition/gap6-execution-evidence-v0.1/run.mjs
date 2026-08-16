// SPDX-License-Identifier: Apache-2.0
// Generated from run.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Execution-Layer Evidence composition profile, instantiating Gap 6 of
 * draft-chen-oauth-agent-authz-use-cases-02.
 *
 * Gap 6 (sec 5 of that draft) names the missing mechanism: "a non-repudiable,
 * cryptographic proof of a user's explicit consent for a specific, high-risk
 * action at the moment it occurs", observing that "grant-layer tokens prove
 * potential, not the legitimacy of a specific, executed transaction."
 *
 * That sentence compresses three different claims, and no single artifact can
 * honestly prove all three. This profile separates them and reports a verdict
 * per claim in every case:
 *
 *   APPROVAL   what the named human(s) approved, proven by verifying the
 *              authorization artifact under pinned anchors. An authorization
 *              receipt answers THIS claim and only this claim.
 *   ADMISSION  whether the enforcement point in front of the executor admitted
 *              that exact action, once, under its own trust configuration and
 *              its own consumption ledger.
 *   EXECUTION  whether the effect was entered and with what outcome, proven by
 *              the execution record's binding to the admitted decision. An
 *              entered effect with no answer is INDETERMINATE, never a retry.
 *
 * The demonstration boundary is a finance-operations action: a vendor
 * bank-detail change, the classic business-email-compromise target. Bank
 * details enter the evidence as digests, never as cleartext.
 *
 * Status: source-pinned discussion artifact. It is not an Internet-Draft, not
 * a Chen-draft specification, and running it externally is a reproduction of
 * these pinned checks, not an independent implementation result.
 *
 * One execution emits three outputs:
 *   1. report.json                machine-verifiable conformance report with a
 *                                 deterministic results digest
 *   2. stdout                     the finance-operations demonstration
 *   3. reproduction-receipt.json  compact receipt an external operator can
 *                                 regenerate and paste into their own
 *                                 implementation-status section
 */
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { writeFileSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGate, createEg1Harness, executionProgramDigest, FIELD_ORIGIN_CLAIM_BOUNDARY, fieldOriginProfileDigest, hashCanonical, MemoryConsumptionStore, signBoundedExecutionProgram, signFieldOriginEvidence, } from '../../../packages/gate/index.js';
import { manifestFromPack } from '../../../packages/gate/adapters/_kit.js';
export const PROFILE = 'EP-GAP6-EXECUTION-EVIDENCE-PROFILE-v0.1';
const HERE = dirname(fileURLToPath(import.meta.url));
/**
 * The exact material action. Routing and account numbers appear only as
 * digests: the approver's device shows the human the cleartext out of band,
 * the evidence layer commits to it without carrying it.
 */
export const EXACT_ACTION = Object.freeze({
    action_type: 'finops.vendor.bank_detail_change',
    vendor_id: 'V-88012',
    erp: 'netsuite.prod.example',
    change_ticket: 'CHG-2026-4471',
    new_routing_digest: 'sha256:8c1f00a3b7e2d94c5a6b1e0f2d3c4b5a6978e0d1c2b3a4958677e8f9a0b1c2d3',
    new_account_digest: 'sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809',
});
const SELECTOR = Object.freeze({ protocol: 'finops', tool: 'vendor_bank_detail_change' });
const ACTION_PACK = Object.freeze([
    Object.freeze({
        id: 'finops.vendor.bank_detail_change',
        label: 'Vendor bank-detail change',
        action_type: 'finops.vendor.bank_detail_change',
        risk: 'critical',
        receipt_required: true,
        assurance_class: 'quorum',
        match: { protocol: SELECTOR.protocol, tool: SELECTOR.tool },
        why: 'Redirects every future payment to this vendor. Dual control over the exact change.',
        execution_binding: {
            required_fields: [
                'action_type',
                'vendor_id',
                'erp',
                'change_ticket',
                'new_routing_digest',
                'new_account_digest',
            ],
        },
    }),
]);
const QUORUM = Object.freeze({ threshold: 2 });
const PROVIDER_DEADLINE_MS = 25;
const FIELD_ORIGIN_OBSERVED_AT = '2026-08-15T22:30:00.000Z';
const FIELD_ORIGIN_KEY_ID = 'key:gap6-field-origin-reference';
const FIELD_ORIGIN_ISSUER_ID = 'rp:gap6-finops';
const FIELD_ORIGIN_PRIVATE_KEY = createPrivateKey({
    // Public conformance fixture only. This deterministic seed is not a
    // deployment credential and the resulting key must never be trusted outside
    // this profile.
    key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.alloc(32, 0x61),
    ]),
    format: 'der',
    type: 'pkcs8',
});
const FIELD_ORIGIN_PUBLIC_KEY = createPublicKey(FIELD_ORIGIN_PRIVATE_KEY)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
const PINNED_FIELD_TRANSFORM = Object.freeze({
    transform_id: 'transform:bank-digest-normalization',
    version: '1.0.0',
    digest: `sha256:${'4'.repeat(64)}`,
});
function fieldRule(path, role, required, allowedOrigins, snapshotPolicy, allowedTransformIds = []) {
    return {
        path,
        role,
        required,
        allowed_origins: allowedOrigins,
        snapshot_policy: snapshotPolicy,
        max_snapshot_age_sec: snapshotPolicy === 'immutable' ? null : 300,
        allowed_transform_ids: allowedTransformIds,
    };
}
export const FIELD_ORIGIN_PROFILE = Object.freeze({
    profile_id: 'profile:finops-field-origin:01',
    relying_party_id: FIELD_ORIGIN_ISSUER_ID,
    action_type: EXACT_ACTION.action_type,
    fields: [
        fieldRule('/action_type', 'control', true, ['operator_pinned'], 'immutable'),
        fieldRule('/vendor_id', 'control', true, ['operator_pinned', 'approver_supplied'], 'immutable'),
        fieldRule('/erp', 'control', true, ['operator_pinned'], 'immutable'),
        fieldRule('/change_ticket', 'control', true, ['operator_pinned', 'approver_supplied'], 'immutable'),
        fieldRule('/new_routing_digest', 'control', true, ['approver_supplied', 'derived_via_versioned_transform'], 'immutable', [PINNED_FIELD_TRANSFORM.transform_id]),
        fieldRule('/new_account_digest', 'control', true, ['approver_supplied', 'derived_via_versioned_transform'], 'immutable', [PINNED_FIELD_TRANSFORM.transform_id]),
        fieldRule('/memo', 'bounded_data', false, ['operator_pinned', 'approver_supplied', 'untrusted_bounded'], 'either'),
    ],
    transforms: [PINNED_FIELD_TRANSFORM],
});
const PROGRAM_KEY_ID = 'key:gap6-customer-program-reference';
const PROGRAM_AUTHORIZER_ID = 'customer:gap6-design-partner';
const PROGRAM_PRIVATE_KEY = createPrivateKey({
    // Public conformance fixture only. Never a deployment credential.
    key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'),
        Buffer.alloc(32, 0x62),
    ]),
    format: 'der',
    type: 'pkcs8',
});
const PROGRAM_PUBLIC_KEY = createPublicKey(PROGRAM_PRIVATE_KEY)
    .export({ type: 'spki', format: 'der' }).toString('base64url');
export const FIELD_ORIGIN_EXECUTION_PROGRAM = signBoundedExecutionProgram({
    program_id: 'program:gap6-finance-field-origin:01',
    tenant_id: 'tenant:gap6-design-partner',
    version: 1,
    subject_id: 'agent:finance-operations:01',
    audience: 'gate:gap6-finance-operations:01',
    objective_digest: `sha256:${'1'.repeat(64)}`,
    authorization_digest: `sha256:${'2'.repeat(64)}`,
    presentation_digest: `sha256:${'3'.repeat(64)}`,
    supersedes_program_digest: null,
    issued_at: '2026-08-15T22:00:00.000Z',
    valid_from: '2026-08-15T22:10:00.000Z',
    expires_at: '2026-08-17T22:10:00.000Z',
    max_total_occurrences: 1,
    max_concurrent_effects: 1,
    budgets: [{ budget_id: 'vendor-change-attempts', unit: 'attempt', limit: 1 }],
    nodes: [{
            node_id: 'vendor-bank-detail-change',
            action: {
                mode: 'profile',
                profile_id: FIELD_ORIGIN_PROFILE.profile_id,
                profile_digest: fieldOriginProfileDigest(FIELD_ORIGIN_PROFILE),
            },
            trust_program_digest: `sha256:${'4'.repeat(64)}`,
            depends_on: [],
            max_occurrences: 1,
            charges: [{ budget_id: 'vendor-change-attempts', amount: 1 }],
        }],
}, {
    issuer_id: PROGRAM_AUTHORIZER_ID,
    key_id: PROGRAM_KEY_ID,
    private_key: PROGRAM_PRIVATE_KEY,
});
export const FIELD_ORIGIN_EXECUTION_PROGRAM_VERIFICATION = Object.freeze({
    trusted_keys: {
        [PROGRAM_KEY_ID]: {
            issuer_id: PROGRAM_AUTHORIZER_ID,
            public_key: PROGRAM_PUBLIC_KEY,
        },
    },
    now: FIELD_ORIGIN_OBSERVED_AT,
    expected_program_id: 'program:gap6-finance-field-origin:01',
    expected_tenant_id: 'tenant:gap6-design-partner',
    expected_authorizer_id: PROGRAM_AUTHORIZER_ID,
    expected_authorization_digest: `sha256:${'2'.repeat(64)}`,
    expected_audience: 'gate:gap6-finance-operations:01',
});
const FIELD_ORIGIN_EXECUTION_PROGRAM_NODE = 'vendor-bank-detail-change';
function immutableSnapshot() {
    return { kind: 'immutable', observed_at: null, source_version: null };
}
function fieldAnnotations(action, overrides = {}) {
    return Object.keys(action).sort().map((key) => ({
        path: `/${key}`,
        origin_class: key === 'action_type' || key === 'erp' || key === 'vendor_id'
            ? 'operator_pinned'
            : (key === 'memo' ? 'untrusted_bounded' : 'approver_supplied'),
        snapshot: immutableSnapshot(),
        transform: null,
        ...(overrides[`/${key}`] ?? {}),
    }));
}
function fieldOriginEvidence(action, overrides = {}, profile = FIELD_ORIGIN_PROFILE, evidenceId = 'evidence:gap6-field-origin-reference') {
    return signFieldOriginEvidence({
        evidence_id: evidenceId,
        profile,
        observed_action: action,
        observed_at: FIELD_ORIGIN_OBSERVED_AT,
        annotations: fieldAnnotations(action, overrides),
    }, {
        issuer_id: FIELD_ORIGIN_ISSUER_ID,
        key_id: FIELD_ORIGIN_KEY_ID,
        private_key: FIELD_ORIGIN_PRIVATE_KEY,
    });
}
function claimVerdicts({ approval, admission, execution }) {
    return { approval, admission, execution };
}
function admissionRecord(decision) {
    return {
        allow: decision.allow,
        reason: decision.reason ?? null,
        observed_action_hash: decision.evidence?.observed_action_hash ?? null,
        receipt_id: decision.evidence?.receipt_id ?? null,
        consumption_key: decision.evidence?.consumption_key ?? null,
    };
}
function requireOutcome(outcome) {
    if (outcome === null) {
        throw new Error('expected a gate outcome but received a terminal error');
    }
    return outcome;
}
/** Named humans a receipt's quorum evidence carries, or null when it cannot be credited. */
function creditedApprovers(receipt) {
    const quorum = receipt?.payload?.quorum;
    const named = quorum?.policy?.approvers;
    if (quorum?.['@type'] !== 'ep.quorum' || !Array.isArray(named) || !Array.isArray(quorum.members)) {
        return null;
    }
    const ids = named.map((p) => p?.approver ?? null);
    return ids.every((id) => typeof id === 'string' && id.length > 0) ? ids.sort() : null;
}
export async function runProfile() {
    const harness = createEg1Harness({ action: /** @type {any} */ (EXACT_ACTION), idPrefix: 'gap6' });
    const store = new MemoryConsumptionStore();
    const gate = createGate({
        manifest: manifestFromPack([...ACTION_PACK]),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        quorumPolicy: harness.quorumPolicy,
        store,
        allowEphemeralStore: true, // reference profile; production requires durable shared state
    });
    const fieldOriginGate = createGate({
        manifest: manifestFromPack([...ACTION_PACK]),
        trustedKeys: [harness.publicKey],
        approverKeys: harness.approverKeys,
        rpId: harness.rpId,
        allowedOrigins: harness.allowedOrigins,
        quorumPolicy: harness.quorumPolicy,
        store: new MemoryConsumptionStore(),
        allowEphemeralStore: true,
        requiredFieldOriginProfile: FIELD_ORIGIN_PROFILE,
        fieldOriginTrustedKeys: {
            [FIELD_ORIGIN_KEY_ID]: {
                issuer_id: FIELD_ORIGIN_ISSUER_ID,
                public_key: FIELD_ORIGIN_PUBLIC_KEY,
            },
        },
        fieldOriginExecutionProgram: {
            artifact: FIELD_ORIGIN_EXECUTION_PROGRAM,
            verification_options: FIELD_ORIGIN_EXECUTION_PROGRAM_VERIFICATION,
            node_id: FIELD_ORIGIN_EXECUTION_PROGRAM_NODE,
        },
    });
    const actionHash = hashCanonical(EXACT_ACTION);
    const executions = [];
    const executor = async () => {
        executions.push(structuredClone(EXACT_ACTION));
        return { changed: true, vendor_id: EXACT_ACTION.vendor_id };
    };
    const unresolvedProvider = async () => {
        executions.push(structuredClone(EXACT_ACTION));
        await new Promise((_, reject) => {
            setTimeout(() => reject(new Error('provider deadline exceeded, outcome unknown')), PROVIDER_DEADLINE_MS);
        });
        return { changed: true };
    };
    async function admit(receipt, action = EXACT_ACTION, effect = executor) {
        try {
            const outcome = await gate.run({ selector: { ...SELECTOR }, receipt, observedAction: action }, effect);
            return { outcome, terminal: null };
        }
        catch (error) {
            return { outcome: null, terminal: error?.emiliaGateOutcome ?? null };
        }
    }
    async function admitWithFieldOrigin(receipt, action, evidenceObject, effect = executor) {
        try {
            const outcome = await fieldOriginGate.run({
                selector: { ...SELECTOR },
                receipt,
                observedAction: action,
                fieldOriginEvidence: evidenceObject,
            }, effect);
            return { outcome, terminal: null };
        }
        catch (error) {
            return { outcome: null, terminal: error?.emiliaGateOutcome ?? null };
        }
    }
    const cases = [];
    let pilotObservedAction = null;
    let pilotFieldOriginEvidence = null;
    let pilotApprovalReceipt = null;
    // 1. The through-case: two named humans approve the exact change under a
    //    user-verification-gated ceremony; the gate re-derives the action
    //    identity from the material IT observes, admits once, consumes once,
    //    and the execution record binds back to the admitted decision.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const before = executions.length;
        const admitted = await admit(receipt);
        const outcome = requireOutcome(admitted.outcome);
        const admission = admissionRecord(outcome.authorization);
        cases.push({
            id: 'through-exact-human-exact-action-once',
            title: 'Two named approvers, the exact change, one admitted attempt, execution bound to the decision',
            claims: claimVerdicts({
                approval: {
                    verdict: 'proven',
                    approvers: creditedApprovers(receipt),
                    approved_action_hash: actionHash,
                },
                admission: { verdict: 'admitted', ...admission },
                execution: {
                    verdict: 'executed',
                    effect_ran: executions.length === before + 1,
                    authorizes_decision: outcome.execution?.authorizes_decision ?? null,
                    bound_to_admitted_decision: outcome.execution?.authorizes_decision === outcome.packet?.summary?.decision_hash,
                },
            }),
            boundary_reason: null,
            caid_recomputed_at_executor: admission.observed_action_hash === actionHash,
        });
    }
    // 2. Missing human evidence. The approval claim is indeterminate (nothing
    //    was presented to verify), and the boundary is fail-closed: refusal by
    //    name, not an error and not an execution.
    {
        const before = executions.length;
        const admitted = await admit(null);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'missing-human-evidence',
            title: 'No authorization artifact: approval unprovable, boundary refuses by name',
            claims: claimVerdicts({
                approval: { verdict: 'indeterminate', reason: 'no_evidence_presented' },
                admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
            }),
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 3. The agent clicks Approve: a self-asserted quorum block with no
    //    per-signer verifiable evidence. Every byte is well-formed; nothing in
    //    it is a human ceremony, and the gate refuses to credit it.
    {
        const receipt = harness.mint({ outcome: 'allow', fakeQuorum: true });
        const before = executions.length;
        const admitted = await admit(receipt);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'fabricated-approval-refused',
            title: 'Software asserts a quorum without per-signer evidence; the tier is not credited',
            claims: claimVerdicts({
                approval: { verdict: 'not_credited', reason: 'self_asserted_quorum_without_signer_evidence' },
                admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
            }),
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 4. Wrong approver: a syntactically perfect receipt whose issuer and
    //    approvers are not the ones this boundary pinned out of band.
    {
        const rogue = createEg1Harness({ action: /** @type {any} */ (EXACT_ACTION), idPrefix: 'gap6_rogue' });
        const receipt = rogue.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const before = executions.length;
        const admitted = await admit(receipt);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'wrong-approver-refused',
            title: 'Valid-looking artifact from unpinned keys; verification fails under this boundary\'s anchors',
            claims: claimVerdicts({
                approval: { verdict: 'not_credited', reason: 'signature_not_under_pinned_anchors' },
                admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
            }),
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 5. Material action substitution: the approval is real, the observed
    //    action is not the approved one. The binding refuses; consent to X is
    //    not consent to Y with the same shape.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const substituted = {
            ...EXACT_ACTION,
            new_routing_digest: 'sha256:eeee00a3b7e2d94c5a6b1e0f2d3c4b5a6978e0d1c2b3a4958677e8f9a0b1eeee',
        };
        const before = executions.length;
        const admitted = await admit(receipt, substituted);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'action-substitution-refused',
            title: 'The routing digest changed between approval and execution; the exact-action binding refuses',
            claims: claimVerdicts({
                approval: { verdict: 'proven_for_different_action', approved_action_hash: actionHash },
                admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
            }),
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 6. Reuse of consumed authority: the through-case artifact presented
    //    again. One approval is one admission; the ledger holds.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        await admit(receipt);
        const before = executions.length;
        const admitted = await admit(receipt);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'replay-refused',
            title: 'The consumed authorization cannot drive a second execution',
            claims: claimVerdicts({
                approval: { verdict: 'proven', note: 'the artifact still verifies; verification is not admission' },
                admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
            }),
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 7. Lost provider acknowledgement: the effect was entered and never
    //    answered. The attempt may have landed. The authorization stays
    //    committed, the outcome is INDETERMINATE bound to the admitted
    //    decision, and a blind retry is refused rather than silently re-spent.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const { terminal } = await admit(receipt, EXACT_ACTION, unresolvedProvider);
        const consumptionKey = terminal?.authorizationEvidence?.consumption_key ?? null;
        const retryAttempt = await admit(receipt);
        const retry = requireOutcome(retryAttempt.outcome);
        cases.push({
            id: 'lost-acknowledgement-indeterminate',
            title: 'Provider goes silent after entry; outcome INDETERMINATE, authority stays spent, blind retry refused',
            claims: claimVerdicts({
                approval: { verdict: 'proven' },
                admission: { verdict: 'admitted_then_committed', consumption_key: consumptionKey },
                execution: {
                    verdict: 'indeterminate',
                    outcome: terminal?.outcome ?? null,
                    execution_record_outcome: terminal?.execution?.outcome ?? null,
                    bound_to_admitted_decision: typeof terminal?.execution?.authorizes_decision === 'string'
                        && terminal.execution.authorizes_decision.length > 0,
                    committed_not_released: consumptionKey !== null
                        && store.seen.has(consumptionKey)
                        && !store.reserved.has(consumptionKey),
                    blind_retry: { allow: retry.authorization.allow, reason: retry.authorization.reason },
                },
            }),
            boundary_reason: terminal?.reason ?? null,
        });
    }
    // 8. False execution claim: an execution assertion that does not bind to
    //    any admitted decision. Occurrence is proven by the record's binding,
    //    never by the assertion's existence.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const admitted = await admit(receipt);
        const outcome = requireOutcome(admitted.outcome);
        const admittedDecisionHash = outcome.packet?.summary?.decision_hash ?? null;
        const forged = {
            kind: 'asserted_execution_result',
            changed: true,
            vendor_id: EXACT_ACTION.vendor_id,
            authorizes_decision: 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
        };
        cases.push({
            id: 'false-execution-claim-rejected',
            title: 'An asserted result without a decision binding is not execution evidence',
            claims: claimVerdicts({
                approval: { verdict: 'proven' },
                admission: { verdict: 'admitted', decision_hash: admittedDecisionHash },
                execution: {
                    verdict: 'claim_not_credited',
                    reason: 'asserted_result_does_not_bind_admitted_decision',
                    asserted_binding: forged.authorizes_decision,
                    admitted_decision_hash: admittedDecisionHash,
                    binding_matches: forged.authorizes_decision === admittedDecisionHash,
                },
            }),
            boundary_reason: null,
        });
    }
    // 9. The message that proposed the change is untrusted input. It may fill a
    //    bounded data field, but it cannot select the effect-relevant payee.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const evidenceObject = fieldOriginEvidence(EXACT_ACTION, { '/vendor_id': { origin_class: 'untrusted_bounded' } }, FIELD_ORIGIN_PROFILE, 'evidence:m01-injected-email-payee');
        const before = executions.length;
        const admitted = await admitWithFieldOrigin(receipt, EXACT_ACTION, evidenceObject);
        const outcome = requireOutcome(admitted.outcome);
        const check = outcome.authorization.evidence?.field_origin ?? null;
        cases.push({
            id: 'm01-injected-email-payee-change-refused',
            title: 'An injected email selected the payee; field-origin control refuses before admission',
            claims: {
                ...claimVerdicts({
                    approval: { verdict: 'proven' },
                    admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                    execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
                }),
                field_origin: { verdict: 'refused', reason: check?.reason ?? null },
            },
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 10. A webpage is equally untrusted when it tries to select the effect
    //     target. The refusal names the exact control field.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const evidenceObject = fieldOriginEvidence(EXACT_ACTION, { '/erp': { origin_class: 'untrusted_bounded' } }, FIELD_ORIGIN_PROFILE, 'evidence:m01-webpage-target');
        const before = executions.length;
        const admitted = await admitWithFieldOrigin(receipt, EXACT_ACTION, evidenceObject);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'm01-webpage-target-change-refused',
            title: 'A webpage selected the ERP target; field-origin control refuses before admission',
            claims: {
                ...claimVerdicts({
                    approval: { verdict: 'proven' },
                    admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                    execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
                }),
                field_origin: {
                    verdict: 'refused',
                    reason: outcome.authorization.evidence?.field_origin?.reason ?? null,
                },
            },
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 11. Derived control data is admissible only through the exact transform
    //     id, version, and digest pinned by the relying party.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const evidenceObject = fieldOriginEvidence(EXACT_ACTION, {
            '/new_account_digest': {
                origin_class: 'derived_via_versioned_transform',
                transform: { ...PINNED_FIELD_TRANSFORM, digest: `sha256:${'9'.repeat(64)}` },
            },
        }, FIELD_ORIGIN_PROFILE, 'evidence:m01-transform-substitution');
        const before = executions.length;
        const admitted = await admitWithFieldOrigin(receipt, EXACT_ACTION, evidenceObject);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'm01-transformed-control-substitution-refused',
            title: 'A control field came through an unpinned transform; the transform digest mismatch is named',
            claims: {
                ...claimVerdicts({
                    approval: { verdict: 'proven' },
                    admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                    execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
                }),
                field_origin: {
                    verdict: 'refused',
                    reason: outcome.authorization.evidence?.field_origin?.reason ?? null,
                },
            },
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 12. Unknown remains unknown. The issuer cannot omit provenance and have
    //     the verifier infer a safer class from a valid signature.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const evidenceObject = fieldOriginEvidence(EXACT_ACTION, { '/change_ticket': { origin_class: 'unknown' } }, FIELD_ORIGIN_PROFILE, 'evidence:m01-unknown-origin');
        const before = executions.length;
        const admitted = await admitWithFieldOrigin(receipt, EXACT_ACTION, evidenceObject);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'm01-unknown-origin-refused',
            title: 'A control field has unknown origin; the gate preserves unknown and refuses',
            claims: {
                ...claimVerdicts({
                    approval: { verdict: 'proven' },
                    admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                    execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
                }),
                field_origin: {
                    verdict: 'refused',
                    reason: outcome.authorization.evidence?.field_origin?.reason ?? null,
                },
            },
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 13. A presenter cannot widen a control field into bounded data. The
    //     signed artifact's profile digest must equal the relying-party pin.
    {
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const downgradedProfile = {
            ...FIELD_ORIGIN_PROFILE,
            profile_id: 'profile:finops-field-origin:downgraded',
            fields: FIELD_ORIGIN_PROFILE.fields.map((field) => field.path === '/vendor_id'
                ? { ...field, role: 'bounded_data', allowed_origins: ['untrusted_bounded'] }
                : field),
        };
        const evidenceObject = fieldOriginEvidence(EXACT_ACTION, { '/vendor_id': { origin_class: 'untrusted_bounded' } }, downgradedProfile, 'evidence:m01-profile-downgrade');
        const before = executions.length;
        const admitted = await admitWithFieldOrigin(receipt, EXACT_ACTION, evidenceObject);
        const outcome = requireOutcome(admitted.outcome);
        cases.push({
            id: 'm01-profile-downgrade-refused',
            title: 'The presenter widened a control field into bounded data; the pinned profile digest refuses',
            claims: {
                ...claimVerdicts({
                    approval: { verdict: 'proven' },
                    admission: { verdict: 'refused', ...admissionRecord(outcome.authorization) },
                    execution: { verdict: 'not_entered', effect_ran: executions.length !== before },
                }),
                field_origin: {
                    verdict: 'refused',
                    reason: outcome.authorization.evidence?.field_origin?.reason ?? null,
                },
            },
            boundary_reason: outcome.authorization.reason,
        });
    }
    // 14. Untrusted content is not categorically forbidden. It may fill the
    //     bounded memo field while every effect-relevant control stays pinned.
    {
        const action = {
            ...EXACT_ACTION,
            memo: 'Untrusted invoice note, bounded as data',
        };
        const receipt = harness.mint({ outcome: 'allow_with_signoff', quorum: QUORUM });
        const evidenceObject = fieldOriginEvidence(action, {}, FIELD_ORIGIN_PROFILE, 'evidence:m01-bounded-memo');
        const before = executions.length;
        const admitted = await admitWithFieldOrigin(receipt, action, evidenceObject);
        const outcome = requireOutcome(admitted.outcome);
        pilotObservedAction = action;
        pilotFieldOriginEvidence = evidenceObject;
        pilotApprovalReceipt = receipt;
        cases.push({
            id: 'm01-bounded-untrusted-memo-admitted',
            title: 'Untrusted content fills a bounded memo field while control fields remain pinned; the gate admits',
            claims: {
                ...claimVerdicts({
                    approval: { verdict: 'proven' },
                    admission: { verdict: 'admitted', ...admissionRecord(outcome.authorization) },
                    execution: {
                        verdict: 'executed',
                        effect_ran: executions.length === before + 1,
                        bound_to_admitted_decision: outcome.execution?.authorizes_decision === outcome.packet?.summary?.decision_hash,
                    },
                }),
                field_origin: {
                    verdict: 'verified',
                    reason: null,
                    evidence_digest: outcome.authorization.evidence?.field_origin?.artifact_digest ?? null,
                },
            },
            boundary_reason: null,
        });
    }
    // The deterministic portion: identical bytes on every conforming run, on
    // any machine. Volatile metadata (timestamps, runner, commit) lives beside
    // it, never inside it.
    const deterministic = {
        '@profile': PROFILE,
        reference: 'draft-chen-oauth-agent-authz-use-cases-02, Section 5, Gap 6 (Execution-Layer Evidence); Use Case 11 execution-evidence requirement',
        claim_model: {
            approval: 'what the named human(s) approved, verified under pinned anchors',
            field_origin: {
                statement: 'what a pinned issuer asserted about each exact field origin and mutable-state snapshot at admission',
                profile_id: FIELD_ORIGIN_PROFILE.profile_id,
                profile_digest: fieldOriginProfileDigest(FIELD_ORIGIN_PROFILE),
                claim_boundary: FIELD_ORIGIN_CLAIM_BOUNDARY,
                execution_program: {
                    program_digest: executionProgramDigest(FIELD_ORIGIN_EXECUTION_PROGRAM),
                    authorizer_id: PROGRAM_AUTHORIZER_ID,
                    authorization_digest: FIELD_ORIGIN_EXECUTION_PROGRAM.authorization_digest,
                    node_id: FIELD_ORIGIN_EXECUTION_PROGRAM_NODE,
                    claim_boundary: FIELD_ORIGIN_EXECUTION_PROGRAM.claim_boundary,
                },
            },
            admission: 'whether this boundary admitted that exact action, once',
            execution: 'whether the effect was entered and with what outcome, bound to the admitted decision',
        },
        action: EXACT_ACTION,
        action_hash: actionHash,
        cases: cases.map((c) => ({
            id: c.id,
            title: c.title,
            boundary_reason: c.boundary_reason,
            approval: { verdict: c.claims.approval.verdict, reason: c.claims.approval.reason ?? null },
            field_origin: c.claims.field_origin
                ? { verdict: c.claims.field_origin.verdict, reason: c.claims.field_origin.reason ?? null }
                : null,
            admission: {
                verdict: c.claims.admission.verdict,
                allow: c.claims.admission.allow ?? null,
                reason: c.claims.admission.reason ?? null,
            },
            execution: {
                verdict: c.claims.execution.verdict,
                effect_ran: c.claims.execution.effect_ran ?? null,
            },
        })),
    };
    const resultsDigest = `sha256:${hashCanonical(deterministic)}`;
    return {
        deterministic,
        results_digest: resultsDigest,
        cases,
        total_executions: executions.length,
        pilot: {
            observed_action: pilotObservedAction,
            field_origin_profile: FIELD_ORIGIN_PROFILE,
            field_origin_trusted_keys: {
                [FIELD_ORIGIN_KEY_ID]: {
                    issuer_id: FIELD_ORIGIN_ISSUER_ID,
                    public_key: FIELD_ORIGIN_PUBLIC_KEY,
                },
            },
            field_origin_evidence: pilotFieldOriginEvidence,
            approval_receipt: pilotApprovalReceipt,
            receipt_trust_config: {
                trusted_keys: [harness.publicKey],
                approver_keys: harness.approverKeys,
                rp_id: harness.rpId,
                allowed_origins: harness.allowedOrigins,
                quorum_policy: harness.quorumPolicy,
            },
            manifest: manifestFromPack([...ACTION_PACK]),
            selector: SELECTOR,
            execution_program_artifact: FIELD_ORIGIN_EXECUTION_PROGRAM,
            execution_program_verification: FIELD_ORIGIN_EXECUTION_PROGRAM_VERIFICATION,
            execution_program_node_id: FIELD_ORIGIN_EXECUTION_PROGRAM_NODE,
            gate_evidence_log: fieldOriginGate.evidence.all(),
        },
    };
}
function runnerIdentity() {
    let commit = null;
    try {
        commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: HERE, encoding: 'utf8' }).trim();
    }
    catch {
        commit = null;
    }
    return {
        node: process.version,
        platform: `${process.platform}-${process.arch}`,
        source_commit: commit,
        generated_at: new Date().toISOString(),
    };
}
function printDemo(result) {
    const width = 78;
    const a = EXACT_ACTION;
    console.log('='.repeat(width));
    console.log(`Execution-Layer Evidence profile ${PROFILE}`);
    console.log('Instantiates Gap 6 of draft-chen-oauth-agent-authz-use-cases-02');
    console.log('='.repeat(width));
    console.log(`Boundary: ${a.action_type} · vendor ${a.vendor_id} · ${a.erp} · ${a.change_ticket}`);
    console.log('Bank details appear only as digests; approvers saw the cleartext out of band.');
    console.log('-'.repeat(width));
    for (const [index, c] of result.cases.entries()) {
        console.log(`${index + 1}. ${c.id}`);
        console.log(`   ${c.title}`);
        console.log(`   approval: ${c.claims.approval.verdict}`
            + `${c.claims.approval.reason ? ` (${c.claims.approval.reason})` : ''}`);
        const admissionReason = c.claims.admission.verdict === 'refused' ? c.claims.admission.reason : null;
        console.log(`   admission: ${c.claims.admission.verdict}`
            + `${admissionReason ? ` (${admissionReason})` : ''}`);
        console.log(`   execution: ${c.claims.execution.verdict}`);
        if (c.boundary_reason)
            console.log(`   boundary refusal names: ${c.boundary_reason}`);
    }
    console.log('-'.repeat(width));
    console.log(`Executor ran ${result.total_executions} times across all 14 cases`
        + ' (once for the through-case, once for the entered-then-unresolved case,'
        + ' once for the artifact later replayed, once for the false-claim setup,'
        + ' and once for the bounded-data positive case).');
    console.log(`results_digest: ${result.results_digest}`);
    console.log('One receipt proves approval. Admission and execution are separate claims');
    console.log('with separate evidence, and an unresolved outcome is never a retry.\n');
}
const isMain = process.argv[1]
    && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
    const result = await runProfile();
    const runner = runnerIdentity();
    const report = {
        ...result.deterministic,
        results_digest: result.results_digest,
        runner,
    };
    writeFileSync(resolve(HERE, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
    let matchesReference = null;
    try {
        const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
        matchesReference = reference.results_digest === result.results_digest;
    }
    catch {
        matchesReference = null;
    }
    const receipt = {
        kind: 'gap6-execution-evidence-reproduction-receipt',
        profile: PROFILE,
        results_digest: result.results_digest,
        matches_committed_reference: matchesReference,
        note: 'Reproduction of the pinned profile checks; not an independent implementation result.',
        runner,
    };
    writeFileSync(resolve(HERE, 'reproduction-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
    if (process.argv.includes('--json'))
        console.log(JSON.stringify(report, null, 2));
    else
        printDemo(result);
    if (matchesReference === false) {
        console.error('results_digest DIFFERS from the committed reference report.');
        process.exitCode = 1;
    }
}
