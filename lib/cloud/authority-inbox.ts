// SPDX-License-Identifier: Apache-2.0
// Pure, read-only Authority Inbox projection. This module never mints,
// consumes, or admits authority and never treats an approval receipt as proof
// of provider entry or execution.

export const AUTHORITY_INBOX_PROFILE = 'EP-AUTHORITY-INBOX-v1' as const;
export const AUTHORITY_POLICY_SIMULATION_PROFILE = 'EP-AUTHORITY-POLICY-SIMULATION-v1' as const;

export type AuthorityInboxState =
  | 'RECEIPT_REQUIRED'
  | 'WAITING_FOR_APPROVER'
  | 'AUTHORIZED_NOT_ADMITTED'
  | 'ADMITTED'
  | 'EXECUTED'
  | 'FAILED_BEFORE_EFFECT'
  | 'INDETERMINATE'
  | 'RECONCILED';

export interface AuthorityInboxSource {
  receipt_id: string;
  action_hash: string | null;
  action_caid: string | null;
  action_type: string;
  amount: number | null;
  currency: string | null;
  counterparty_name: string | null;
  target_resource_id: string | null;
  payment_destination_hash: string | null;
  created_at: string | null;
  expires_at: string | null;
  status: 'receipt_required' | 'pending' | 'consumed' | 'rejected' | 'approved' | 'expired';
  signoff_id: string | null;
  approver_id: string | null;
  approver_role: string | null;
  required_assurance: string | null;
  profile_digest: string | null;
  review_path: string | null;
  consumed_at: string | null;
  decision_at: string | null;
  material_changes?: readonly string[];
  named_refusal?: string | null;
  provider_entry?: {
    established: true;
    at: string;
    source: string;
  } | null;
  execution?: {
    state: 'EXECUTED' | 'FAILED_BEFORE_EFFECT' | 'INDETERMINATE';
    at: string;
    source: string;
    named_refusal?: string | null;
  } | null;
  reconciliation?: {
    established: true;
    at: string;
    source: string;
  } | null;
}

export interface AuthorityTimelineStep {
  state: AuthorityInboxState;
  status: 'ESTABLISHED' | 'CURRENT' | 'NOT_ESTABLISHED';
  at: string | null;
  source: string | null;
}

export interface AuthorityInboxEntry {
  profile: typeof AUTHORITY_INBOX_PROFILE;
  receipt_id: string;
  state: AuthorityInboxState;
  exact_action: {
    action_hash: string | null;
    action_caid: string | null;
    action_type: string;
    amount: number | null;
    currency: string | null;
    counterparty_name: string | null;
    target_resource_id: string | null;
    payment_destination_hash: string | null;
  };
  material_changes: readonly string[];
  authority_source: 'trust_receipt' | 'none';
  approver_id: string | null;
  approver_role: string | null;
  required_assurance: string | null;
  expires_at: string | null;
  profile_digest: string | null;
  one_time_status: 'not_issued' | 'unconsumed' | 'consumed' | 'unknown';
  outcome_source: string | null;
  named_refusal: string | null;
  created_at: string | null;
  decision_at: string | null;
  indeterminate_at: string | null;
  reconciled_at: string | null;
  review_path: string | null;
  timeline: readonly AuthorityTimelineStep[];
}

const STATE_ORDER: readonly AuthorityInboxState[] = [
  'RECEIPT_REQUIRED',
  'WAITING_FOR_APPROVER',
  'AUTHORIZED_NOT_ADMITTED',
  'ADMITTED',
  'EXECUTED',
  'FAILED_BEFORE_EFFECT',
  'INDETERMINATE',
  'RECONCILED',
];

function finiteTimestamp(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function inferState(source: AuthorityInboxSource): AuthorityInboxState {
  if (source.reconciliation?.established === true) return 'RECONCILED';
  if (source.execution?.state) return source.execution.state;
  if (source.provider_entry?.established === true) return 'ADMITTED';
  switch (source.status) {
    case 'receipt_required': return 'RECEIPT_REQUIRED';
    case 'pending': return 'WAITING_FOR_APPROVER';
    case 'approved': return 'AUTHORIZED_NOT_ADMITTED';
    case 'rejected':
    case 'expired': return 'FAILED_BEFORE_EFFECT';
    case 'consumed': return 'INDETERMINATE';
    default: return 'INDETERMINATE';
  }
}

function stateTime(state: AuthorityInboxState, source: AuthorityInboxSource): string | null {
  switch (state) {
    case 'RECEIPT_REQUIRED': return source.created_at;
    case 'WAITING_FOR_APPROVER': return source.created_at;
    case 'AUTHORIZED_NOT_ADMITTED': return source.decision_at;
    case 'ADMITTED': return source.provider_entry?.at ?? null;
    case 'EXECUTED':
    case 'FAILED_BEFORE_EFFECT': return source.execution?.at ?? source.decision_at;
    case 'INDETERMINATE': return source.execution?.at ?? source.consumed_at;
    case 'RECONCILED': return source.reconciliation?.at ?? null;
    default: return null;
  }
}

function timelineFor(state: AuthorityInboxState, source: AuthorityInboxSource): AuthorityTimelineStep[] {
  const established = new Set<AuthorityInboxState>();
  if (source.status !== 'receipt_required') established.add('WAITING_FOR_APPROVER');
  if (['approved', 'consumed'].includes(source.status)) established.add('AUTHORIZED_NOT_ADMITTED');
  if (source.provider_entry?.established === true) established.add('ADMITTED');
  if (source.execution?.state) established.add(source.execution.state);
  if (source.reconciliation?.established === true) established.add('RECONCILED');
  if (source.status === 'receipt_required') established.add('RECEIPT_REQUIRED');
  if (['rejected', 'expired'].includes(source.status)) established.add('FAILED_BEFORE_EFFECT');
  if (source.status === 'consumed' && !source.provider_entry && !source.execution) {
    established.add('INDETERMINATE');
  }

  return STATE_ORDER.map((candidate) => ({
    state: candidate,
    status: candidate === state
      ? 'CURRENT'
      : established.has(candidate) ? 'ESTABLISHED' : 'NOT_ESTABLISHED',
    at: established.has(candidate) || candidate === state ? stateTime(candidate, source) : null,
    source: candidate === 'ADMITTED'
      ? source.provider_entry?.source ?? null
      : ['EXECUTED', 'INDETERMINATE', 'FAILED_BEFORE_EFFECT'].includes(candidate)
        ? source.execution?.source ?? null
        : candidate === 'RECONCILED'
          ? source.reconciliation?.source ?? null
          : candidate === 'RECEIPT_REQUIRED'
            ? null
            : 'trust_receipt',
  }));
}

export function projectAuthorityInboxEntry(source: AuthorityInboxSource): AuthorityInboxEntry {
  const state = inferState(source);
  const receiptIssued = source.status !== 'receipt_required';
  const authorityConsumed = source.status === 'consumed'
    || source.provider_entry?.established === true
    || source.execution?.state === 'EXECUTED'
    || source.execution?.state === 'INDETERMINATE'
    || source.reconciliation?.established === true;
  const consumedWithoutOutcome = source.status === 'consumed'
    && !source.provider_entry
    && !source.execution
    && !source.reconciliation;

  return Object.freeze({
    profile: AUTHORITY_INBOX_PROFILE,
    receipt_id: source.receipt_id,
    state,
    exact_action: Object.freeze({
      action_hash: source.action_hash,
      action_caid: source.action_caid,
      action_type: source.action_type,
      amount: source.amount,
      currency: source.currency,
      counterparty_name: source.counterparty_name,
      target_resource_id: source.target_resource_id,
      payment_destination_hash: source.payment_destination_hash,
    }),
    material_changes: Object.freeze([...(source.material_changes ?? [])]),
    authority_source: receiptIssued ? 'trust_receipt' : 'none',
    approver_id: source.approver_id,
    approver_role: source.approver_role,
    required_assurance: source.required_assurance,
    expires_at: source.expires_at,
    profile_digest: source.profile_digest,
    one_time_status: !receiptIssued
      ? 'not_issued'
      : authorityConsumed ? 'consumed' : 'unconsumed',
    outcome_source: source.reconciliation?.source
      ?? source.execution?.source
      ?? source.provider_entry?.source
      ?? null,
    named_refusal: source.named_refusal
      ?? source.execution?.named_refusal
      ?? (consumedWithoutOutcome
        ? 'authority_consumed_outcome_unobserved'
        : source.status === 'expired'
          ? 'approval_expired'
          : source.status === 'rejected' ? 'approval_rejected' : null),
    created_at: source.created_at,
    decision_at: source.decision_at,
    indeterminate_at: state === 'INDETERMINATE' || source.execution?.state === 'INDETERMINATE'
      ? source.execution?.at ?? source.consumed_at ?? source.created_at
      : null,
    reconciled_at: source.reconciliation?.at ?? null,
    review_path: source.review_path,
    timeline: Object.freeze(timelineFor(state, source)),
  });
}

export interface AuthorityInboxMetrics {
  total: number;
  approval_latency_ms: number | null;
  expired_count: number;
  abandoned_count: number;
  indeterminate_count: number;
  oldest_indeterminate_age_ms: number | null;
  reconciliation_time_ms: number | null;
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const ordered = [...values].sort((a, b) => a - b);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 1
    ? ordered[middle]
    : Math.round((ordered[middle - 1] + ordered[middle]) / 2);
}

export function authorityInboxMetrics(
  entries: readonly AuthorityInboxEntry[],
  now: string | number | Date = Date.now(),
): AuthorityInboxMetrics {
  const nowMs = now instanceof Date
    ? now.getTime()
    : typeof now === 'number' ? now : Date.parse(now);
  const approvalLatencies: number[] = [];
  const indeterminateAges: number[] = [];
  const reconciliationTimes: number[] = [];

  for (const entry of entries) {
    const created = finiteTimestamp(entry.created_at);
    const decided = finiteTimestamp(entry.decision_at);
    if (created !== null && decided !== null && decided >= created) {
      approvalLatencies.push(decided - created);
    }
    const indeterminate = finiteTimestamp(entry.indeterminate_at);
    if (entry.state === 'INDETERMINATE'
        && indeterminate !== null
        && Number.isFinite(nowMs)
        && nowMs >= indeterminate) {
      indeterminateAges.push(nowMs - indeterminate);
    }
    const reconciled = finiteTimestamp(entry.reconciled_at);
    if (entry.state === 'RECONCILED'
        && indeterminate !== null
        && reconciled !== null
        && reconciled >= indeterminate) {
      reconciliationTimes.push(reconciled - indeterminate);
    }
  }

  return Object.freeze({
    total: entries.length,
    approval_latency_ms: median(approvalLatencies),
    expired_count: entries.filter((entry) => (
      entry.state === 'FAILED_BEFORE_EFFECT'
      && entry.named_refusal === 'approval_expired'
    )).length,
    abandoned_count: entries.filter((entry) => (
      entry.state === 'FAILED_BEFORE_EFFECT'
      && entry.named_refusal === 'approval_expired'
    )).length,
    indeterminate_count: entries.filter((entry) => entry.state === 'INDETERMINATE').length,
    oldest_indeterminate_age_ms: indeterminateAges.length > 0
      ? Math.max(...indeterminateAges)
      : null,
    reconciliation_time_ms: median(reconciliationTimes),
  });
}

export interface AuthorityPolicySimulationInput {
  action_type: string;
  amount?: number | null;
  policy: {
    protected_action_types: readonly string[];
    approval_threshold?: number | null;
    required_assurance?: string | null;
  };
}

export interface AuthorityPolicySimulationResult {
  profile: typeof AUTHORITY_POLICY_SIMULATION_PROFILE;
  mode: 'simulation';
  verdict: 'WOULD_REQUIRE_AUTHORITY' | 'WOULD_ALLOW_UNGUARDED' | 'WOULD_REFUSE' | 'INDETERMINATE';
  reason: string;
  authorizes: false;
  consumes_authority: false;
  receipt_id: null;
  required_assurance: string | null;
}

export function simulateAuthorityPolicy(
  input: AuthorityPolicySimulationInput,
): AuthorityPolicySimulationResult {
  let verdict: AuthorityPolicySimulationResult['verdict'];
  let reason: string;
  if (!input || typeof input.action_type !== 'string' || input.action_type.length === 0) {
    verdict = 'INDETERMINATE';
    reason = 'simulation_input_invalid';
  } else if (input.amount !== undefined
      && input.amount !== null
      && (!Number.isFinite(input.amount) || input.amount < 0)) {
    verdict = 'WOULD_REFUSE';
    reason = 'amount_invalid';
  } else {
    const protectedAction = input.policy.protected_action_types.includes(input.action_type);
    const threshold = input.policy.approval_threshold;
    const exceedsThreshold = typeof threshold === 'number'
      && typeof input.amount === 'number'
      && input.amount >= threshold;
    if (protectedAction || exceedsThreshold) {
      verdict = 'WOULD_REQUIRE_AUTHORITY';
      reason = protectedAction ? 'protected_action_type' : 'approval_threshold_met';
    } else {
      verdict = 'WOULD_ALLOW_UNGUARDED';
      reason = 'no_simulated_authority_requirement';
    }
  }
  return Object.freeze({
    profile: AUTHORITY_POLICY_SIMULATION_PROFILE,
    mode: 'simulation',
    verdict,
    reason,
    authorizes: false,
    consumes_authority: false,
    receipt_id: null,
    required_assurance: input?.policy?.required_assurance ?? null,
  });
}

export interface AuthorityNotification {
  notification_type: 'state_changed' | 'expiry_warning' | 'reconciliation_required';
  receipt_id: string;
  state: AuthorityInboxState;
  subject: string;
  delivery_state: 'NOT_ATTEMPTED';
  authorizes: false;
}

export interface BlindRetryNotice {
  prior_attempt_state: 'INDETERMINATE';
  prior_receipt_id: string;
  retry_safe: false;
  required_next_step: 'AUTHENTICATED_RECONCILIATION';
  authorizes_new_authority: false;
}

/**
 * Surface an unresolved prior attempt before any operator considers issuing
 * new authority. This is display evidence, not a release or retry decision.
 */
export function blindRetryNotice(entry: AuthorityInboxEntry): BlindRetryNotice | null {
  if (entry.state !== 'INDETERMINATE') return null;
  return Object.freeze({
    prior_attempt_state: 'INDETERMINATE',
    prior_receipt_id: entry.receipt_id,
    retry_safe: false,
    required_next_step: 'AUTHENTICATED_RECONCILIATION',
    authorizes_new_authority: false,
  });
}

export function buildAuthorityNotification(
  entry: AuthorityInboxEntry,
  notificationType: AuthorityNotification['notification_type'],
): AuthorityNotification {
  return Object.freeze({
    notification_type: notificationType,
    receipt_id: entry.receipt_id,
    state: entry.state,
    subject: `${entry.exact_action.action_type}: ${entry.state}`,
    delivery_state: 'NOT_ATTEMPTED',
    authorizes: false,
  });
}
