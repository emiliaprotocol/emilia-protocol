// SPDX-License-Identifier: Apache-2.0
// EMILIA Gate default action packs: the high-risk families that should require
// pre-execution human authorization before a machine mutates the world.

export const ACTION_RISK_MANIFEST_VERSION = 'EP-ACTION-RISK-MANIFEST-v0.1';

export const HIGH_RISK_ACTION_PACKS = Object.freeze([
  Object.freeze({
    id: 'money_movement.release',
    label: 'Money movement',
    action_type: 'payment.release',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { protocol: 'mcp', tool: 'release_payment' },
    why: 'Moves funds or releases value. Requires a named human signoff, not an agent-only key.',
    execution_binding: {
      required_fields: ['action_type', 'amount_usd', 'currency', 'payment_instruction_id', 'beneficiary_account_hash'],
    },
  }),
  Object.freeze({
    id: 'money_movement.bank_details_change',
    label: 'Bank-detail change',
    action_type: 'payment.bank_details.change',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { protocol: 'mcp', tool: 'change_bank_details' },
    why: 'Changes where future money flows. Treats payee, beneficiary, vendor, and payroll account changes as high-risk by category.',
    execution_binding: {
      required_fields: ['action_type', 'account_holder_id', 'payment_instruction_id', 'bank_account_hash'],
    },
  }),
  Object.freeze({
    id: 'production.deploy',
    label: 'Production deploy',
    action_type: 'deploy.production',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'quorum',
    match: { protocol: 'mcp', tool: 'deploy_production' },
    why: 'Changes live production behavior. Quorum is the cryptographic two-person rule for hard operational cuts.',
    execution_binding: {
      required_fields: ['action_type', 'repo', 'commit_sha', 'environment', 'artifact_digest'],
    },
  }),
  Object.freeze({
    id: 'permissions.admin_change',
    label: 'Permission or admin change',
    action_type: 'permission.admin.change',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'quorum',
    match: { protocol: 'mcp', tool: 'change_permissions' },
    why: 'Changes who can act next. Privilege changes deserve stronger proof than the session that requested them.',
    execution_binding: {
      required_fields: ['action_type', 'principal_id', 'role', 'scope'],
    },
  }),
  Object.freeze({
    id: 'data.bulk_export',
    label: 'Bulk data export',
    action_type: 'data.export',
    risk: 'high',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { protocol: 'mcp', tool: 'export_customer_data' },
    why: 'Moves sensitive data out of its system of record. The recipient and purpose must be bound to the approval.',
    execution_binding: {
      required_fields: ['action_type', 'dataset', 'recipient', 'purpose', 'row_count_max'],
    },
  }),
  Object.freeze({
    id: 'records.delete',
    label: 'Record deletion',
    action_type: 'record.delete',
    risk: 'high',
    receipt_required: true,
    assurance_class: 'class_a',
    match: { protocol: 'mcp', tool: 'delete_record' },
    why: 'Destroys or hides state. The record identity and pre-state must be bound before deletion.',
    execution_binding: {
      required_fields: ['action_type', 'record_type', 'record_id', 'before_state_hash'],
    },
  }),
  Object.freeze({
    id: 'regulated.decision_override',
    label: 'Regulated decision override',
    action_type: 'regulated.decision.override',
    risk: 'critical',
    receipt_required: true,
    assurance_class: 'quorum',
    match: { protocol: 'mcp', tool: 'override_regulated_decision' },
    why: 'Changes a decision with legal, benefit, credit, clinical, or safety impact. Requires named accountability.',
    execution_binding: {
      required_fields: ['action_type', 'case_id', 'decision_id', 'subject_id', 'override_reason'],
    },
  }),
]);

export const DEFAULT_PASS_THROUGH_ACTIONS = Object.freeze([
  Object.freeze({
    id: 'observe.read_status',
    label: 'Read-only status',
    action_type: 'read.status',
    receipt_required: false,
    match: { protocol: 'mcp', tool: 'read_status' },
  }),
]);

export function createDefaultActionRiskManifest({ includePassThrough = true, extraActions = [] } = {}) {
  return {
    '@version': ACTION_RISK_MANIFEST_VERSION,
    actions: [
      ...HIGH_RISK_ACTION_PACKS.map((a) => ({
        ...a,
        match: { ...a.match },
        execution_binding: a.execution_binding
          ? { ...a.execution_binding, required_fields: [...a.execution_binding.required_fields] }
          : undefined,
      })),
      ...(includePassThrough ? DEFAULT_PASS_THROUGH_ACTIONS.map((a) => ({ ...a, match: { ...a.match } })) : []),
      ...extraActions,
    ],
  };
}

export const DEFAULT_GATE_MANIFEST = Object.freeze(createDefaultActionRiskManifest());

export function highRiskActionTypes(actions = HIGH_RISK_ACTION_PACKS) {
  return actions.filter((a) => a.receipt_required).map((a) => a.action_type);
}

export default {
  ACTION_RISK_MANIFEST_VERSION,
  HIGH_RISK_ACTION_PACKS,
  DEFAULT_PASS_THROUGH_ACTIONS,
  DEFAULT_GATE_MANIFEST,
  createDefaultActionRiskManifest,
  highRiskActionTypes,
};
