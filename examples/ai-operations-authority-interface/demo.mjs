// SPDX-License-Identifier: Apache-2.0
// Generated from demo.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { beginProviderEntry, createAuthorityOperation, intervene, presentAuthorizationEvidence, projectAuthorityOperation, recordProviderOutcome, reserveAuthorityOperation, } from './index.mjs';
const D = (character) => `sha256:${character.repeat(64)}`;
const START = '2026-08-14T20:00:00.000Z';
const routeAction = Object.freeze({
    action_type: 'network.route-policy.apply',
    target: {
        controller: 'sdn-controller-east',
        site_id: 'site-17',
        policy_id: 'route-policy:core-b',
    },
    parameters: {
        prefixes: ['198.51.100.0/24'],
        estimated_customer_impact_percent: '2.0',
        change_window: '2026-08-14T20:10:00Z/2026-08-14T20:20:00Z',
    },
});
const policy = Object.freeze({
    policy_id: 'network-operations-authority-v1',
    policy_digest: D('1'),
    action_type: routeAction.action_type,
    mode: 'AUTOMATIC_WITHIN_ENVELOPE',
    evaluator_profile: 'network-impact-policy:v1',
    outside_envelope: 'FRESH_AUTHORIZATION_REQUIRED',
    indeterminate: 'REFUSE',
    required_evidence: [{
            evidence_type: 'ep-quorum',
            role: 'network-change-approver',
            minimum: 2,
        }],
});
function proposed(operationId, policyResult) {
    return createAuthorityOperation({
        operation_id: operationId,
        action: routeAction,
        policy,
        policy_result: policyResult,
        observed_at: START,
    });
}
export function runAuthorityOperationsReference() {
    const needsHuman = proposed('operation:route-site-17', 'OUTSIDE_ENVELOPE');
    const wrongBinding = presentAuthorizationEvidence(needsHuman, {
        evidence_type: 'ep-quorum',
        role: 'network-change-approver',
        evidence_digest: D('2'),
        action_digest: D('3'),
        verification: 'VERIFIED',
        subjects: ['operator:alice', 'operator:bob'],
    }, '2026-08-14T20:01:00.000Z');
    let unsettled = presentAuthorizationEvidence(needsHuman, {
        evidence_type: 'ep-quorum',
        role: 'network-change-approver',
        evidence_digest: D('4'),
        action_digest: needsHuman.action_digest,
        verification: 'VERIFIED',
        subjects: ['operator:alice', 'operator:bob'],
    }, '2026-08-14T20:01:00.000Z');
    unsettled = reserveAuthorityOperation(unsettled, '2026-08-14T20:02:00.000Z');
    unsettled = beginProviderEntry(unsettled, '2026-08-14T20:03:00.000Z');
    unsettled = recordProviderOutcome(unsettled, {
        value: 'INDETERMINATE',
        evidence_digest: null,
        resulting_state: null,
    }, '2026-08-14T20:04:00.000Z');
    const automatic = proposed('operation:route-site-17-low-impact', 'WITHIN_ENVELOPE');
    const prohibitedPolicy = {
        ...policy,
        policy_id: 'network-operations-prohibited-v1',
        policy_digest: D('5'),
        mode: 'PROHIBITED',
    };
    const prohibited = createAuthorityOperation({
        operation_id: 'operation:route-site-17-prohibited',
        action: routeAction,
        policy: prohibitedPolicy,
        policy_result: 'OUTSIDE_ENVELOPE',
        observed_at: START,
    });
    const cancelled = intervene(automatic, {
        type: 'CANCEL_BEFORE_ENTRY',
        actor_id: 'operator:alice',
        reason: 'maintenance_window_closed',
    }, '2026-08-14T20:05:00.000Z');
    let enteredThenFrozen = reserveAuthorityOperation(proposed('operation:route-site-17-freeze-race', 'WITHIN_ENVELOPE'), '2026-08-14T20:05:00.000Z');
    enteredThenFrozen = beginProviderEntry(enteredThenFrozen, '2026-08-14T20:06:00.000Z');
    enteredThenFrozen = intervene(enteredThenFrozen, {
        type: 'FREEZE_NEW_ADMISSIONS',
        actor_id: 'operator:alice',
        reason: 'incident_response',
    }, '2026-08-14T20:07:00.000Z');
    return {
        '@version': 'EMILIA-AI-OPERATIONS-REFERENCE-RUN-v0',
        reference_only: true,
        claims: {
            interface_issues_authority: false,
            interface_executes_action: false,
            action_history_proves_external_truth: false,
        },
        cases: {
            additional_authorization_required: projectAuthorityOperation(needsHuman),
            substituted_action_refused: projectAuthorityOperation(wrongBinding),
            lost_acknowledgement_unsettled: projectAuthorityOperation(unsettled),
            automatic_within_envelope: projectAuthorityOperation(automatic),
            prohibited_action_refused: projectAuthorityOperation(prohibited),
            operator_cancelled_before_entry: projectAuthorityOperation(cancelled),
            freeze_does_not_relabel_entered_effect: projectAuthorityOperation(enteredThenFrozen),
        },
    };
}
const isDirect = process.argv[1]
    && new URL(import.meta.url).pathname === new URL(`file://${process.argv[1]}`).pathname;
if (isDirect) {
    process.stdout.write(`${JSON.stringify(runAuthorityOperationsReference(), null, 2)}\n`);
}
