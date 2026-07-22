// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { approvalActionHash } from '@emilia-protocol/require-receipt';
import { getServiceClient } from '@/lib/supabase.js';
import {
  canonicalize,
  getEvidenceSigningKeypair,
} from '@/lib/guard-evidence-receipt.js';
import { buildPortableSignoffDecision } from '@/lib/signoff/decision-evidence.js';
import { buildPaymentReleaseActionIdentity } from './contract.js';
import type { ApprovalAcquisitionRow } from './store.js';

type Event = {
  event_type: string;
  actor_id?: string | null;
  after_state?: Record<string, any> | null;
  created_at?: string | null;
};

type SignedApprovalReceipt = Record<string, any>;
type Signer = (payload: Record<string, any>) => SignedApprovalReceipt | null;

export type ApprovalPollStatus =
  | { status: 'pending' }
  | { status: 'indeterminate'; reconciliation: { state: 'required'; retry_safe: false } }
  | { status: 'denied' }
  | { status: 'expired' }
  | { status: 'approved'; receipt: SignedApprovalReceipt }
  | { status: 'not_ready'; reason: string };

const MAX_TIMELINE_EVENTS = 200;

export class ApprovalEvidenceError extends Error {
  constructor() {
    super('approval_evidence_unavailable');
    this.name = 'ApprovalEvidenceError';
  }
}

function digest(value: unknown): string {
  return `sha256:${crypto.createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}

function samePaymentMaterial(row: ApprovalAcquisitionRow, canonicalAction: Record<string, any>): boolean {
  const action = row.action;
  const identity = buildPaymentReleaseActionIdentity(action);
  return identity.ok
    && approvalActionHash(action) === row.action_hash
    && identity.actionCaid === row.action_caid
    && canonicalAction.action_type === 'large_payment_release'
    && canonicalAction.target_resource_id === action.payment_instruction_id
    && canonicalAction.amount === action.amount_usd
    && canonicalAction.currency === action.currency
    && canonicalAction.counterparty_name === action.counterparty_name
    && canonicalAction.payment_destination_hash === action.beneficiary_account_hash
    && canonicalAction.action_caid === row.action_caid;
}

function sameAcquisitionScope(row: ApprovalAcquisitionRow, state: Record<string, any>): boolean {
  const scope = state.canonical_action?.acquisition_scope;
  return state.acquisition_tenant_id === row.tenant_id
    && state.acquisition_environment === row.environment
    && state.acquisition_request_id === row.request_id
    && state.acquisition_request_digest === row.request_digest
    && state.acquisition_action_hash === row.action_hash
    && state.acquisition_action_caid === row.action_caid
    && state.acquisition_challenge_hash === row.challenge_hash
    && scope
    && typeof scope === 'object'
    && !Array.isArray(scope)
    && scope.tenant_id === row.tenant_id
    && scope.environment === row.environment
    && scope.request_id === row.request_id
    && scope.request_digest === row.request_digest
    && scope.action_hash === row.action_hash
    && scope.action_caid === row.action_caid
    && scope.challenge_hash === row.challenge_hash;
}

function producerKeyId(row: ApprovalAcquisitionRow): string | null {
  return typeof row.producer_key_id === 'string' && row.producer_key_id.length > 0
    ? row.producer_key_id
    : null;
}

function signApprovalReceipt(payload: Record<string, any>): SignedApprovalReceipt | null {
  const keypair = getEvidenceSigningKeypair();
  if (!keypair) return null;
  const bytes = Buffer.from(canonicalize(payload), 'utf8');
  const signatureValue = crypto.sign(null, bytes, keypair.privateKey).toString('base64url');
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(keypair.publicKeySpkiB64u, 'base64url'),
    format: 'der',
    type: 'spki',
  });
  if (!crypto.verify(null, bytes, publicKey, Buffer.from(signatureValue, 'base64url'))) return null;
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      signer: payload.issuer,
      key_class: 'C',
      key_id: 'ep-signing-key-1',
      key_source: 'operator-commit-signing-key',
      value: signatureValue,
    },
    metadata: {
      operator: 'ep_operator_emilia_primary',
      issued_at: payload.created_at,
      profile: 'EP-APPROVAL-v1',
    },
  };
}

function decisionEvents(events: Event[], eventType: string, row: ApprovalAcquisitionRow): Event[] {
  return events.filter((event) => event.event_type === eventType
    && event.after_state?.signoff_id === row.signoff_id
    && (event.after_state?.approver_id || event.actor_id) === row.approver_id);
}

export function deriveApprovalStatus(
  row: ApprovalAcquisitionRow,
  events: Event[],
  now: Date = new Date(),
  { signer = signApprovalReceipt }: { signer?: Signer } = {},
): ApprovalPollStatus {
  if (row.status === 'indeterminate') {
    return { status: 'indeterminate', reconciliation: { state: 'required', retry_safe: false } };
  }
  if (row.status !== 'pending' || !row.receipt_id || !row.signoff_id || !row.receipt_action_hash) {
    const expiresAt = Date.parse(row.expires_at);
    return Number.isFinite(expiresAt) && now.getTime() >= expiresAt
      ? { status: 'expired' }
      : { status: 'pending' };
  }
  if (!Array.isArray(events) || events.length > MAX_TIMELINE_EVENTS) {
    return { status: 'not_ready', reason: 'timeline_invalid' };
  }

  const createdEvents = events.filter((event) => event.event_type === 'guard.trust_receipt.created');
  if (createdEvents.length !== 1) return { status: 'not_ready', reason: 'creation_evidence_invalid' };
  const created = createdEvents[0];
  const base = created.after_state;
  const producer = producerKeyId(row);
  if (!producer) return { status: 'not_ready', reason: 'producer_binding_unavailable' };
  const expectedCreator = `ep:cloud-key:${producer}`;
  if (!base
      || created.actor_id !== expectedCreator
      || base.organization_id !== row.tenant_id
      || base.action_type !== 'large_payment_release'
      || base.action_hash !== row.receipt_action_hash
      || base.signoff_required !== true
      || base.required_assurance !== 'A'
      || !sameAcquisitionScope(row, base)
      || !samePaymentMaterial(row, base.canonical_action || {})) {
    return { status: 'not_ready', reason: 'receipt_binding_invalid' };
  }

  const requests = events.filter((event) => event.event_type === 'guard.signoff.requested'
    && event.actor_id === expectedCreator
    && event.after_state?.signoff_id === row.signoff_id
    && event.after_state?.approver_id === row.approver_id
    && event.after_state?.acquisition_tenant_id === row.tenant_id
    && event.after_state?.acquisition_environment === row.environment
    && event.after_state?.acquisition_request_id === row.request_id
    && event.after_state?.acquisition_request_digest === row.request_digest);
  if (requests.length !== 1) return { status: 'not_ready', reason: 'signoff_request_invalid' };

  const approved = decisionEvents(events, 'guard.signoff.approved', row);
  const rejected = decisionEvents(events, 'guard.signoff.rejected', row);
  if (approved.length > 1 || rejected.length > 1 || (approved.length && rejected.length)) {
    return { status: 'not_ready', reason: 'terminal_decision_ambiguous' };
  }
  if (rejected.length === 1) return { status: 'denied' };

  const expiresAt = Date.parse(row.expires_at);
  const nowMs = now.getTime();
  if (!Number.isFinite(expiresAt) || !Number.isFinite(nowMs) || nowMs >= expiresAt) {
    return { status: 'expired' };
  }
  if (approved.length === 0) return { status: 'pending' };
  const approvedAt = Date.parse(approved[0].created_at || '');
  if (!Number.isFinite(approvedAt) || approvedAt >= expiresAt) return { status: 'expired' };

  const classA = buildPortableSignoffDecision(approved[0]);
  if (!classA
      || classA.decision !== 'approved'
      || classA.key_class !== 'A'
      || classA.signoff_id !== row.signoff_id
      || classA.approver_id !== row.approver_id
      || classA.action_hash !== row.receipt_action_hash) {
    return { status: 'not_ready', reason: 'class_a_evidence_unavailable' };
  }

  const payload = {
    receipt_id: row.receipt_id,
    issuer: 'ep_operator_emilia_primary',
    protocol_version: 'EP-CORE-v1.0',
    profile: 'EP-APPROVAL-v1',
    request_id: row.request_id,
    claim: {
      action_type: 'payment.release',
      canonical_action: row.action,
      action_hash: row.action_hash,
      action_caid: row.action_caid,
      challenge_hash: row.challenge_hash,
      source_receipt_action_hash: row.receipt_action_hash,
      request_scope: {
        tenant_id: row.tenant_id,
        environment: row.environment,
        request_digest: row.request_digest,
      },
      outcome: 'allow_with_signoff',
      approver: row.approver_id,
    },
    authorization: {
      status: 'approved',
      signoff_required: true,
      approver_id: row.approver_id,
      approved_at: classA.decided_at,
      approver_key_class: 'A',
      class_a_decision_evidence_digest: digest(classA),
      class_a_decision_evidence: classA,
    },
    // The human assertion signs the source Trust Receipt action hash. The
    // operator-signed outer receipt binds that source hash to the exact
    // acquisition action above, forming a closed transitive proof chain.
    signoff: classA.signoff,
    approver_key_id: classA.credential_id,
    authenticated_actor: {
      type: 'cloud_key',
      key_id: producer,
      subject: expectedCreator,
    },
    requester_actor: {
      type: 'cloud_key',
      key_id: row.requester_key_id,
      subject: `ep:cloud-key:${row.requester_key_id}`,
    },
    subject: expectedCreator,
    created_at: created.created_at || row.created_at,
    expires_at: row.expires_at,
  };
  const receipt = signer(payload);
  if (!receipt || receipt['@version'] !== 'EP-RECEIPT-v1'
      || !receipt.payload || !receipt.signature?.value) {
    return { status: 'not_ready', reason: 'signed_receipt_unavailable' };
  }
  return { status: 'approved', receipt };
}

export async function loadApprovalStatus(
  row: ApprovalAcquisitionRow,
  now: Date = new Date(),
): Promise<ApprovalPollStatus> {
  if (row.status !== 'pending' || !row.receipt_id) {
    return deriveApprovalStatus(row, [], now);
  }
  let supabase;
  try {
    supabase = getServiceClient();
  } catch {
    throw new ApprovalEvidenceError();
  }
  const { data, error } = await supabase
    .from('audit_events')
    .select('event_type, actor_id, after_state, created_at')
    .eq('target_type', 'trust_receipt')
    .eq('target_id', row.receipt_id)
    .like('event_type', 'guard.%')
    .order('created_at', { ascending: true })
    .limit(MAX_TIMELINE_EVENTS + 1);
  if (error || !Array.isArray(data) || data.length > MAX_TIMELINE_EVENTS) {
    throw new ApprovalEvidenceError();
  }
  return deriveApprovalStatus(row, data, now);
}

export const _internals = {
  samePaymentMaterial, sameAcquisitionScope, producerKeyId, signApprovalReceipt,
};
