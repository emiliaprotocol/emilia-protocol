/**
 * EP-IX — Identity Continuity Core
 * 
 * Manages principals, identity bindings, and continuity claims.
 * Constitutional principles:
 *   - EP evaluates trust given an identity. EP-IX governs continuity.
 *   - Continuity must not become trust laundering.
 *   - Continuity during active disputes is frozen.
 *   - Fission does not multiply trust.
 * 
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';
import crypto from 'crypto';
import { logger } from './logger.js';
import { CONTINUITY_STATUS } from './constants.js';

/**
 * Every EP-IX helper below returns either an error shape or a success shape
 * from the same function. Callers narrow with a truthy check on `error` (or
 * the `in` operator), not a discriminant tag, so each result interface below
 * merges both shapes with every field optional rather than modeling a true
 * discriminated union — that keeps the existing `if (result.error)` /
 * `result.someSuccessField` call sites (across app/api/identity/**) valid
 * without forcing them into a different narrowing style.
 */
interface EpIxErrorResult {
  error?: string;
  status?: number;
  frozen?: boolean;
  active_disputes?: number | null;
}

export interface RegisterPrincipalResult extends EpIxErrorResult {
  principal?: any;
}

export interface CreateBindingResult extends EpIxErrorResult {
  binding?: any;
}

export interface VerifyBindingResult extends EpIxErrorResult {
  binding?: any;
}

export interface FileContinuityClaimResult extends EpIxErrorResult {
  continuity?: any;
  challenge_deadline?: string;
  expires_at?: string;
}

export interface ChallengeContinuityResult extends EpIxErrorResult {
  challenge?: any;
}

export interface ResolveContinuityResult extends EpIxErrorResult {
  continuity_id?: string;
  decision?: string;
  resolved_at?: string;
}

export interface GetPrincipalResult extends EpIxErrorResult {
  principal?: any;
  bindings?: any[];
  entities?: any[];
  continuity_claims?: any[];
}

export interface LineageEntry {
  from?: string;
  to?: string;
  reason: string;
  status: string;
  transfer_policy: string;
  decided_at?: string;
}

export interface GetLineageResult {
  entity_id: string;
  predecessors: LineageEntry[];
  successors: LineageEntry[];
}

export interface FreezeContinuityResult extends Omit<EpIxErrorResult, 'status'> {
  continuity_id?: string;
  /** HTTP status on the error branch, continuity-claim status string on success. */
  status?: string | number;
  frozen_due_to?: string;
}

export interface WithdrawContinuityResult extends Omit<EpIxErrorResult, 'status'> {
  continuity_id?: string;
  /** HTTP status on the error branch, continuity-claim status string on success. */
  status?: string | number;
  withdrawn_at?: string;
}

export interface RegisterPrincipalParams {
  principal_id?: string;
  principal_type: string;
  display_name: string;
  bootstrap_verified?: boolean;
  metadata?: Record<string, unknown>;
}

export interface CreateBindingParams {
  principal_id: string;
  binding_type: string;
  binding_target: string;
  proof_type?: string | null;
  proof_payload?: Record<string, unknown>;
  provenance?: string;
}

export interface FileContinuityClaimParams {
  principal_id: string;
  old_entity_id: string;
  new_entity_id: string;
  reason: string;
  continuity_mode?: string;
  proofs?: unknown[];
  transfer_budget?: number;
}

export interface ChallengeContinuityParams {
  continuity_id: string;
  challenger_id: string;
  reason: string;
  evidence?: Record<string, unknown>;
  /** Server-derived from the authenticated API-key permission record. */
  enterprise_admin_authorized?: boolean;
}

/**
 * Register a new principal.
 */
export async function registerPrincipal(params: RegisterPrincipalParams): Promise<RegisterPrincipalResult> {
  const supabase = getServiceClient();
  const principalId = params.principal_id || `ep_principal_${crypto.randomBytes(8).toString('hex')}`;

  const { data, error } = await supabase
    .from('principals')
    .insert({
      principal_id: principalId,
      principal_type: params.principal_type,
      display_name: params.display_name,
      status: 'active',
      bootstrap_verified: params.bootstrap_verified || false,
      metadata: params.metadata || {},
    })
    .select()
    .single();

  if (error) return { error: error.message, status: error.code === '23505' ? 409 : 500 };
  return { principal: data };
}

/**
 * Bind an identity proof to a principal.
 */
export async function createBinding(params: CreateBindingParams): Promise<CreateBindingResult> {
  const supabase = getServiceClient();
  const bindingId = `ep_bind_${crypto.randomBytes(8).toString('hex')}`;

  // Verify principal exists
  const { data: principal } = await supabase
    .from('principals')
    .select('id')
    .eq('principal_id', params.principal_id)
    .single();

  if (!principal) return { error: 'Principal not found', status: 404 };

  const { data, error } = await supabase
    .from('identity_bindings')
    .insert({
      binding_id: bindingId,
      principal_id: principal.id,
      binding_type: params.binding_type,
      binding_target: params.binding_target,
      proof_type: params.proof_type || null,
      proof_payload: params.proof_payload || {},
      provenance: params.provenance || 'self_attested',
      status: 'pending',
    })
    .select()
    .single();

  if (error) return { error: error.message, status: 500 };
  return { binding: data };
}

/**
 * Verify an identity binding (operator action).
 */
export async function verifyBinding(bindingId: string, verifierId: string | undefined): Promise<VerifyBindingResult> {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  // Defense in depth for the IDOR closed at app/api/identity/verify: a binding
  // may only be flipped to `verified` by a NAMED, authorized verifier. The route
  // gates on the host_verifier `binding.verify` permission and passes the
  // authenticated operator_id here. Refuse an anonymous/empty verifier so this
  // trust-changing write can never record an unattributable verification, even
  // if a future caller reaches this function without the route-level gate.
  if (typeof verifierId !== 'string' || verifierId.trim() === '') {
    return { error: 'A named verifier is required to verify a binding', status: 400 };
  }

  const { data, error } = await supabase
    .from('identity_bindings')
    .update({
      status: 'verified',
      verified_at: now,
    })
    .eq('binding_id', bindingId)
    .eq('status', 'pending')
    .select()
    .single();

  if (!data) return { error: 'Binding not found or already verified', status: 404 };

  // Audit
  await emitAudit('binding.verified', verifierId, 'operator', 'binding', bindingId, 'verify', null, { status: 'verified' });

  return { binding: data };
}

/**
 * File a continuity claim.
 * Enforces: dispute freeze, challenge window, expiration.
 */
export async function fileContinuityClaim(
  params: FileContinuityClaimParams,
  actorEntityId: string,
): Promise<FileContinuityClaimResult> {
  const supabase = getServiceClient();
  const continuityId = `ep_ix_${crypto.randomBytes(8).toString('hex')}`;

  if (typeof params.principal_id !== 'string' || params.principal_id.trim() === '') {
    return { error: 'principal_id is required', status: 400 };
  }
  if (typeof params.old_entity_id !== 'string' || params.old_entity_id.trim() === '') {
    return { error: 'old_entity_id is required', status: 400 };
  }
  if (typeof params.new_entity_id !== 'string' || params.new_entity_id.trim() === '') {
    return { error: 'new_entity_id is required', status: 400 };
  }
  if (typeof params.reason !== 'string' || params.reason.trim() === '') {
    return { error: 'reason is required', status: 400 };
  }

  if (params.old_entity_id === params.new_entity_id) {
    return { error: 'Continuity endpoints must identify two distinct entities', status: 400 };
  }

  const transferBudget = params.transfer_budget === undefined
    ? 1.0
    : params.transfer_budget;
  if (typeof transferBudget !== 'number'
    || !Number.isFinite(transferBudget)
    || transferBudget <= 0
    || transferBudget > 1.0) {
    return { error: 'transfer_budget must be a finite number greater than 0 and no greater than 1.0', status: 400 };
  }
  if (typeof actorEntityId !== 'string' || actorEntityId.trim() === '') {
    return { error: 'Authenticated actor identity is required', status: 400 };
  }

  // The filing RPC shares an entity-scoped advisory lock with the active-
  // dispute trigger. Ownership, dispute freeze, claim insert, and audit append
  // therefore form one transaction and cannot cross a concurrent dispute.
  const { data, error } = await supabase.rpc('file_continuity_claim_atomic', {
    p_continuity_id: continuityId,
    p_principal_id: params.principal_id,
    p_actor_entity_id: actorEntityId,
    p_old_entity_id: params.old_entity_id,
    p_new_entity_id: params.new_entity_id,
    p_reason: params.reason,
    p_continuity_mode: params.continuity_mode || 'linear',
    p_proofs: params.proofs || [],
    p_transfer_budget: transferBudget,
  });

  if (error) return { error: error.message, status: 500 };
  const result = Array.isArray(data) ? data[0] : data;
  if (!result || typeof result !== 'object') {
    return { error: 'Continuity filing transaction returned an invalid result', status: 500 };
  }
  if (typeof result.error === 'string') {
    return {
      error: result.error,
      status: typeof result.status === 'number' ? result.status : 500,
      frozen: result.frozen === true,
      active_disputes: typeof result.active_disputes === 'number' ? result.active_disputes : null,
    };
  }
  if (!result.continuity || typeof result.continuity !== 'object'
    || typeof result.challenge_deadline !== 'string'
    || typeof result.expires_at !== 'string') {
    return { error: 'Continuity filing transaction returned no claim', status: 500 };
  }
  return {
    continuity: result.continuity,
    challenge_deadline: result.challenge_deadline,
    expires_at: result.expires_at,
  };
}

/**
 * Challenge a continuity claim.
 */
export async function challengeContinuity(params: ChallengeContinuityParams): Promise<ChallengeContinuityResult> {
  const supabase = getServiceClient();
  const challengeId = `ep_ch_${crypto.randomBytes(8).toString('hex')}`;

  if (typeof params.continuity_id !== 'string' || params.continuity_id.trim() === '') {
    return { error: 'continuity_id is required', status: 400 };
  }
  if (typeof params.challenger_id !== 'string' || params.challenger_id.trim() === '') {
    return { error: 'Authenticated challenger identity is required', status: 400 };
  }
  if (typeof params.reason !== 'string' || params.reason.trim() === '') {
    return { error: 'reason is required', status: 400 };
  }
  if (params.evidence !== undefined
    && (params.evidence === null || Array.isArray(params.evidence) || typeof params.evidence !== 'object')) {
    return { error: 'evidence must be an object', status: 400 };
  }

  // Claim lock, role derivation, self-contest guard, open-challenge count,
  // challenge insert, claim transition, and audit append share one database
  // transaction. No successful write can escape a later audit failure.
  const { data, error } = await supabase.rpc('challenge_continuity_atomic', {
    p_continuity_id: params.continuity_id,
    p_challenge_id: challengeId,
    p_challenger_id: params.challenger_id,
    p_reason: params.reason,
    p_evidence: params.evidence || {},
    p_enterprise_admin_authorized: params.enterprise_admin_authorized === true,
  });

  if (error) return { error: error.message, status: 500 };
  const result = Array.isArray(data) ? data[0] : data;
  if (!result || typeof result !== 'object') {
    return { error: 'Continuity challenge transaction returned an invalid result', status: 500 };
  }
  if (typeof result.error === 'string') {
    return {
      error: result.error,
      status: typeof result.status === 'number' ? result.status : 500,
    };
  }
  if (!result.challenge || typeof result.challenge !== 'object') {
    return { error: 'Continuity challenge transaction returned no challenge', status: 500 };
  }
  return { challenge: result.challenge };
}

/**
 * Resolve a continuity claim (operator action).
 */
export async function resolveContinuity(
  continuityId: string,
  decision: string,
  reasoning: unknown[] | null | undefined,
  operatorId: string,
): Promise<ResolveContinuityResult> {
  const supabase = getServiceClient();
  if (typeof continuityId !== 'string' || continuityId.trim() === '') {
    return { error: 'continuity_id is required', status: 400 };
  }
  if (!['approved_full', 'approved_partial', 'rejected', 'rejected_laundering'].includes(decision)) {
    return { error: 'decision is invalid', status: 400 };
  }
  if (reasoning !== undefined && reasoning !== null && !Array.isArray(reasoning)) {
    return { error: 'reasoning must be an array', status: 400 };
  }
  if (typeof operatorId !== 'string' || operatorId.trim() === '') {
    return { error: 'Authenticated operator identity is required', status: 400 };
  }

  // The database boundary acquires the same old-entity advisory lock as every
  // active-dispute transition, then atomically writes decision, claim state,
  // entity linkage, and audit. It cannot overwrite a concurrent freeze.
  const { data, error } = await supabase.rpc('resolve_continuity_atomic', {
    p_continuity_id: continuityId,
    p_decision: decision,
    p_reasoning: reasoning || [],
    p_operator_id: operatorId,
  });

  if (error) return { error: error.message, status: 500 };
  const result = Array.isArray(data) ? data[0] : data;
  if (!result || typeof result !== 'object') {
    return { error: 'Continuity resolution transaction returned an invalid result', status: 500 };
  }
  if (typeof result.error === 'string') {
    return {
      error: result.error,
      status: typeof result.status === 'number' ? result.status : 500,
      frozen: result.frozen === true,
      active_disputes: typeof result.active_disputes === 'number' ? result.active_disputes : null,
    };
  }
  if (typeof result.continuity_id !== 'string'
      || typeof result.decision !== 'string'
      || typeof result.resolved_at !== 'string') {
    return { error: 'Continuity resolution transaction returned no decision', status: 500 };
  }
  return {
    continuity_id: result.continuity_id,
    decision: result.decision,
    resolved_at: result.resolved_at,
  };
}

/**
 * Get principal with all entities and bindings.
 */
export async function getPrincipal(principalId: string): Promise<GetPrincipalResult> {
  const supabase = getServiceClient();

  const { data: principal } = await supabase
    .from('principals')
    .select('*')
    .eq('principal_id', principalId)
    .single();

  if (!principal) return { error: 'Principal not found', status: 404 };

  const { data: bindings } = await supabase
    .from('identity_bindings')
    .select('binding_id, binding_type, binding_target, provenance, status, verified_at')
    .eq('principal_id', principal.id);

  const { data: entities } = await supabase
    .from('entities')
    .select('entity_id, display_name, entity_type, emilia_score, created_at')
    .eq('principal_id', principal.id);

  const { data: claims } = await supabase
    .from('continuity_claims')
    .select('continuity_id, old_entity_id, new_entity_id, reason, status, continuity_mode, created_at')
    .eq('principal_id', principal.id)
    .order('created_at', { ascending: false })
    .limit(20);

  return {
    principal,
    bindings: bindings || [],
    entities: entities || [],
    continuity_claims: claims || [],
  };
}

/**
 * Get lineage for an entity — predecessors, successors, continuity decisions.
 */
export async function getLineage(entityId: string): Promise<GetLineageResult> {
  const supabase = getServiceClient();

  const { data: asOld } = await supabase
    .from('continuity_claims')
    .select('*, continuity_decisions(*)')
    .eq('old_entity_id', entityId)
    .order('created_at', { ascending: false });

  const { data: asNew } = await supabase
    .from('continuity_claims')
    .select('*, continuity_decisions(*)')
    .eq('new_entity_id', entityId)
    .order('created_at', { ascending: false });

  return {
    entity_id: entityId,
    predecessors: (asNew || []).map(c => ({
      from: c.old_entity_id,
      reason: c.reason,
      status: c.status,
      transfer_policy: c.transfer_policy,
      decided_at: c.continuity_decisions?.[0]?.decided_at,
    })),
    successors: (asOld || []).map(c => ({
      to: c.new_entity_id,
      reason: c.reason,
      status: c.status,
      transfer_policy: c.transfer_policy,
      decided_at: c.continuity_decisions?.[0]?.decided_at,
    })),
  };
}

/**
 * Expire stale continuity claims — called by cron.
 */
export async function expireContinuityClaims(): Promise<number> {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  // frozen_pending_dispute is excluded: a frozen claim's timer is paused.
  // The claim cannot expire while the dispute that caused the freeze is open.
  const { data: expired } = await supabase
    .from('continuity_claims')
    .select('continuity_id')
    .in('status', ['pending', 'under_challenge'])
    .lt('expires_at', now);

  if (expired && expired.length > 0) {
    const ids = expired.map(c => c.continuity_id);
    await supabase
      .from('continuity_claims')
      .update({ status: 'expired', updated_at: now })
      .in('continuity_id', ids);
    return ids.length;
  }
  return 0;
}

/**
 * Freeze a continuity claim when a related dispute is opened.
 * Transitions: pending | under_challenge → frozen_pending_dispute.
 * While frozen, the claim cannot be resolved or expired by the cron job.
 */
export async function freezeContinuityOnDispute(continuityId: string, disputeId: string): Promise<FreezeContinuityResult> {
  const supabase = getServiceClient();
  if (typeof continuityId !== 'string' || continuityId.trim() === '') {
    return { error: 'continuity_id is required', status: 400 };
  }
  if (typeof disputeId !== 'string' || disputeId.trim() === '') {
    return { error: 'dispute_id is required', status: 400 };
  }

  const { data, error } = await supabase.rpc('reconcile_continuity_dispute_atomic', {
    p_dispute_id: disputeId,
    p_continuity_id: continuityId,
  });

  if (error) return { error: error.message, status: 500 };
  const result = Array.isArray(data) ? data[0] : data;
  if (!result || typeof result !== 'object') {
    return { error: 'Continuity dispute reconciliation returned an invalid result', status: 500 };
  }
  if (typeof result.error === 'string') {
    return {
      error: result.error,
      status: typeof result.status === 'number' ? result.status : 500,
    };
  }
  if (result.status !== CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE) {
    return { error: 'Dispute is not active; the continuity claim was not frozen', status: 409 };
  }
  return {
    continuity_id: result.continuity_id,
    status: result.status,
    frozen_due_to: result.frozen_due_to,
  };
}

/**
 * Unfreeze a continuity claim when its blocking dispute resolves.
 * If the claim's expires_at has passed, it is expired instead of restored.
 * Transitions: frozen_pending_dispute → under_challenge | expired.
 */
export async function unfreezeResolvedContinuity(disputeId: string): Promise<{
  unfrozen: number;
  error?: string;
  status?: number;
}> {
  const supabase = getServiceClient();
  if (typeof disputeId !== 'string' || disputeId.trim() === '') {
    return { unfrozen: 0, error: 'dispute_id is required', status: 400 };
  }

  // Reconciliation re-selects the complete active-dispute set under the shared
  // advisory lock. Resolving one blocker cannot unfreeze behind another.
  const { data, error } = await supabase.rpc('reconcile_continuity_dispute_atomic', {
    p_dispute_id: disputeId,
    p_continuity_id: null,
  });

  if (error) return { unfrozen: 0, error: error.message, status: 500 };
  const result = Array.isArray(data) ? data[0] : data;
  if (!result || typeof result !== 'object') {
    return { unfrozen: 0, error: 'Continuity dispute reconciliation returned an invalid result', status: 500 };
  }
  if (typeof result.error === 'string') {
    return {
      unfrozen: 0,
      error: result.error,
      status: typeof result.status === 'number' ? result.status : 500,
    };
  }
  return { unfrozen: typeof result.unfrozen === 'number' ? result.unfrozen : 0 };
}

/**
 * Withdraw a continuity claim — authenticated-principal cancellation.
 * The database locks the claim, proves the actor is currently bound to the
 * filing principal, changes state, and appends the audit event atomically.
 * Transitions: pending | under_challenge → withdrawn.
 */
export async function withdrawContinuityClaim(
  continuityId: string,
  actorEntityId: string,
  reason?: string | null,
): Promise<WithdrawContinuityResult> {
  const supabase = getServiceClient();
  if (typeof continuityId !== 'string' || continuityId.trim() === '') {
    return { error: 'continuity_id is required', status: 400 };
  }
  if (typeof actorEntityId !== 'string' || actorEntityId.trim() === '') {
    return { error: 'Authenticated withdrawing actor identity is required', status: 400 };
  }

  const { data, error } = await supabase.rpc('withdraw_continuity_claim_atomic', {
    p_continuity_id: continuityId,
    p_actor_entity_id: actorEntityId,
    p_reason: reason || null,
  });
  if (error) return { error: error.message, status: 500 };
  const result = Array.isArray(data) ? data[0] : data;
  if (!result || typeof result !== 'object') {
    return { error: 'Continuity withdrawal transaction returned an invalid result', status: 500 };
  }
  if (typeof result.error === 'string') {
    return {
      error: result.error,
      status: typeof result.status === 'number' ? result.status : 500,
    };
  }
  if (typeof result.continuity_id !== 'string'
      || result.status !== CONTINUITY_STATUS.WITHDRAWN
      || typeof result.withdrawn_at !== 'string') {
    return { error: 'Continuity withdrawal transaction returned no withdrawal', status: 500 };
  }
  return {
    continuity_id: result.continuity_id,
    status: result.status,
    withdrawn_at: result.withdrawn_at,
  };
}

/**
 * Emit audit event.
 */
async function emitAudit(
  eventType: string,
  actorId: string,
  actorType: string,
  targetType: string,
  targetId: string,
  action: string,
  beforeState: unknown,
  afterState: unknown,
): Promise<void> {
  const supabase = getServiceClient();
  try {
    const { error } = await supabase.from('audit_events').insert({
      event_type: eventType,
      actor_id: actorId,
      actor_type: actorType,
      target_type: targetType,
      target_id: targetId,
      action,
      before_state: beforeState,
      after_state: afterState,
    });
    if (error) throw error;
  } catch (e: any) {
    // Older EP-IX transitions predate atomic state+audit RPCs. Do not turn an
    // already-committed mutation into a false 500 that invites unsafe retries;
    // the continuity challenge path uses its own atomic RPC. Keep the failure
    // visible until the remaining legacy transitions are migrated likewise.
    logger.error('Audit emit failed after state mutation:', e?.message || e);
  }
}

export { emitAudit };
