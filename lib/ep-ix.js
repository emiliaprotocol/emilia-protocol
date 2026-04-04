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

const CHALLENGE_WINDOW_DAYS = 7;
const CONTINUITY_EXPIRY_DAYS = 30;
const CONTINUITY_WARNING_DAYS = 21;

/**
 * Register a new principal.
 */
export async function registerPrincipal(params) {
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
export async function createBinding(params) {
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
export async function verifyBinding(bindingId, verifierId) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

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
export async function fileContinuityClaim(params) {
  const supabase = getServiceClient();
  const continuityId = `ep_ix_${crypto.randomBytes(8).toString('hex')}`;
  const now = new Date();

  // Verify principal exists
  const { data: principal } = await supabase
    .from('principals')
    .select('id')
    .eq('principal_id', params.principal_id)
    .single();

  if (!principal) return { error: 'Principal not found', status: 404 };

  // Check for active disputes on old entity (dispute freeze)
  if (params.reason !== 'recovery_after_compromise') {
    const { count: activeDisputes } = await supabase
      .from('disputes')
      .select('id', { count: 'exact', head: true })
      .eq('entity_id', params.old_entity_id)
      .in('status', ['open', 'under_review']);

    if ((activeDisputes || 0) > 0) {
      return {
        error: 'Continuity frozen: old entity has active disputes. Resolve disputes before claiming continuity.',
        status: 409,
        frozen: true,
        active_disputes: activeDisputes,
      };
    }
  }

  const challengeDeadline = new Date(now.getTime() + CHALLENGE_WINDOW_DAYS * 24 * 60 * 60 * 1000);
  const expiresAt = new Date(now.getTime() + CONTINUITY_EXPIRY_DAYS * 24 * 60 * 60 * 1000);

  const { data, error } = await supabase
    .from('continuity_claims')
    .insert({
      continuity_id: continuityId,
      principal_id: principal.id,
      old_entity_id: params.old_entity_id,
      new_entity_id: params.new_entity_id,
      reason: params.reason,
      continuity_mode: params.continuity_mode || 'linear',
      proofs: params.proofs || [],
      status: 'pending',
      challenge_deadline: challengeDeadline.toISOString(),
      expires_at: expiresAt.toISOString(),
      transfer_budget: params.transfer_budget || 1.0,
    })
    .select()
    .single();

  if (error) return { error: error.message, status: 500 };

  await emitAudit('continuity.filed', params.principal_id, 'principal', 'continuity', continuityId, 'file', null, {
    old_entity: params.old_entity_id,
    new_entity: params.new_entity_id,
    reason: params.reason,
  });

  return {
    continuity: data,
    challenge_deadline: challengeDeadline.toISOString(),
    expires_at: expiresAt.toISOString(),
  };
}

/**
 * Challenge a continuity claim.
 */
export async function challengeContinuity(params) {
  const supabase = getServiceClient();
  const challengeId = `ep_ch_${crypto.randomBytes(8).toString('hex')}`;

  // Verify claim exists and is challengeable
  const { data: claim } = await supabase
    .from('continuity_claims')
    .select('*')
    .eq('continuity_id', params.continuity_id)
    .single();

  if (!claim) return { error: 'Continuity claim not found', status: 404 };
  if (!['pending'].includes(claim.status)) {
    return { error: `Claim status is '${claim.status}', not challengeable`, status: 409 };
  }
  if (claim.challenge_deadline && new Date(claim.challenge_deadline) < new Date()) {
    return { error: 'Challenge window has expired', status: 410 };
  }

  // Rate-limit open challenges per claim: cap at 5 open challenges.
  // Without this cap an adversary can perpetually file new challenges to keep
  // the claim frozen (each challenge transitions the claim to under_challenge
  // and freezes it via freezeContinuityOnDispute). The cap allows all 6
  // legitimate challenger types to weigh in while preventing abuse.
  const { count: openChallengeCount, error: countErr } = await supabase
    .from('continuity_challenges')
    .select('challenge_id', { count: 'exact', head: true })
    .eq('continuity_id', params.continuity_id)
    .in('status', ['open', 'reviewed']);

  if (!countErr && openChallengeCount >= 5) {
    return { error: 'Maximum open challenges (5) already exist for this claim', status: 429 };
  }

  // Self-contest guard: the principal who filed the claim cannot challenge it,
  // even through delegate entities they control. Without the ownership graph
  // check, a principal creates delegate D (different entity_id), then D files
  // a challenge — the simple ID comparison misses this.
  //
  // Defence layers:
  //   1. Direct match: challenger_id === principal_id
  //   2. Ownership graph: challenger_id is an entity controlled by the principal
  if (params.challenger_id) {
    const principalIdStr = claim.principal_id?.toString();

    // Layer 1: direct principal match
    if (params.challenger_id === principalIdStr) {
      return { error: 'Principal cannot challenge their own continuity claim', status: 403 };
    }

    // Layer 2: entity ownership graph — all entities linked to this principal
    const { data: ownedEntities } = await supabase
      .from('entities')
      .select('entity_id')
      .eq('principal_id', claim.principal_id);

    if (ownedEntities && ownedEntities.some(e => e.entity_id === params.challenger_id)) {
      return { error: 'Entity controlled by the filing principal cannot challenge their own continuity claim', status: 403 };
    }
  }

  const { data, error } = await supabase
    .from('continuity_challenges')
    .insert({
      challenge_id: challengeId,
      continuity_id: params.continuity_id,
      challenger_type: params.challenger_type,
      challenger_id: params.challenger_id || null,
      reason: params.reason,
      evidence: params.evidence || {},
    })
    .select()
    .single();

  if (error) return { error: error.message, status: 500 };

  // Move claim to under_challenge
  await supabase
    .from('continuity_claims')
    .update({ status: 'under_challenge', updated_at: new Date().toISOString() })
    .eq('continuity_id', params.continuity_id);

  await emitAudit('continuity.challenged', params.challenger_id || 'anonymous', params.challenger_type, 'continuity', params.continuity_id, 'challenge', { status: 'pending' }, { status: 'under_challenge' });

  return { challenge: data };
}

/**
 * Resolve a continuity claim (operator action).
 */
export async function resolveContinuity(continuityId, decision, reasoning, operatorId) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: claim } = await supabase
    .from('continuity_claims')
    .select('*')
    .eq('continuity_id', continuityId)
    .single();

  if (!claim) return { error: 'Continuity claim not found', status: 404 };
  if (['approved_full', 'approved_partial', 'rejected', 'expired', 'withdrawn'].includes(claim.status)) {
    return { error: `Claim already resolved: ${claim.status}`, status: 409 };
  }
  if (claim.status === CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE) {
    return { error: 'Claim is frozen pending dispute resolution; resolve the dispute first', status: 409 };
  }

  // Record decision
  await supabase.from('continuity_decisions').insert({
    continuity_id: continuityId,
    decision: decision,
    transfer_policy: decision.startsWith('approved') ? (decision === 'approved_full' ? 'full' : 'partial') : 'none',
    allocation_rule: claim.continuity_mode === 'fission' ? { budget: claim.transfer_budget ?? 1.0 } : null,
    reasoning: reasoning || [],
    decided_by: operatorId,
  });

  // Update claim status
  await supabase
    .from('continuity_claims')
    .update({ status: decision, transfer_policy: decision.startsWith('approved') ? (decision === 'approved_full' ? 'full' : 'partial') : 'none', updated_at: now })
    .eq('continuity_id', continuityId);

  // If approved, link entities to principal
  if (decision.startsWith('approved')) {
    await supabase
      .from('entities')
      .update({ principal_id: claim.principal_id, principal_linked_at: now })
      .eq('entity_id', claim.new_entity_id);
  }

  await emitAudit('continuity.resolved', operatorId, 'operator', 'continuity', continuityId, 'resolve', { status: claim.status }, { status: decision, decision });

  return { continuity_id: continuityId, decision, resolved_at: now };
}

/**
 * Get principal with all entities and bindings.
 */
export async function getPrincipal(principalId) {
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
export async function getLineage(entityId) {
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
export async function expireContinuityClaims() {
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
export async function freezeContinuityOnDispute(continuityId, disputeId) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: claim } = await supabase
    .from('continuity_claims')
    .select('continuity_id, status, principal_id')
    .eq('continuity_id', continuityId)
    .single();

  if (!claim) return { error: 'Continuity claim not found', status: 404 };
  if (!['pending', 'under_challenge'].includes(claim.status)) {
    return { error: `Cannot freeze claim in status '${claim.status}'`, status: 409 };
  }

  const { error } = await supabase
    .from('continuity_claims')
    .update({
      status: CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE,
      frozen_due_to: disputeId,
      frozen_dispute_id: disputeId,
      updated_at: now,
    })
    .eq('continuity_id', continuityId);

  if (error) return { error: error.message, status: 500 };

  await emitAudit(
    'continuity.frozen',
    'system', 'system',
    'continuity', continuityId,
    'freeze',
    { status: claim.status },
    { status: CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE, frozen_due_to: disputeId },
  );

  return { continuity_id: continuityId, status: CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE, frozen_due_to: disputeId };
}

/**
 * Unfreeze a continuity claim when its blocking dispute resolves.
 * If the claim's expires_at has passed, it is expired instead of restored.
 * Transitions: frozen_pending_dispute → under_challenge | expired.
 */
export async function unfreezeResolvedContinuity(disputeId) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: claims } = await supabase
    .from('continuity_claims')
    .select('continuity_id, expires_at, status')
    .eq('frozen_dispute_id', disputeId)
    .eq('status', CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE);

  if (!claims || claims.length === 0) return { unfrozen: 0 };

  let unfrozen = 0;
  for (const claim of claims) {
    const isExpired = claim.expires_at && new Date(claim.expires_at) < new Date(now);
    const newStatus = isExpired ? CONTINUITY_STATUS.EXPIRED : CONTINUITY_STATUS.UNDER_CHALLENGE;

    await supabase
      .from('continuity_claims')
      .update({
        status: newStatus,
        frozen_due_to: null,
        frozen_dispute_id: null,
        updated_at: now,
      })
      .eq('continuity_id', claim.continuity_id);

    await emitAudit(
      'continuity.unfrozen',
      'system', 'system',
      'continuity', claim.continuity_id,
      'unfreeze',
      { status: CONTINUITY_STATUS.FROZEN_PENDING_DISPUTE },
      { status: newStatus, dispute_resolved: disputeId },
    );

    unfrozen++;
  }

  return { unfrozen };
}

/**
 * Withdraw a continuity claim — principal-initiated cancellation.
 * Only the filing principal may withdraw; only terminal from pending or under_challenge.
 * Transitions: pending | under_challenge → withdrawn.
 */
export async function withdrawContinuityClaim(continuityId, principalId, reason) {
  const supabase = getServiceClient();
  const now = new Date().toISOString();

  const { data: claim } = await supabase
    .from('continuity_claims')
    .select('continuity_id, status, principal_id')
    .eq('continuity_id', continuityId)
    .single();

  if (!claim) return { error: 'Continuity claim not found', status: 404 };

  // Only the filing principal may withdraw their own claim.
  if (claim.principal_id?.toString() !== principalId) {
    return { error: 'Only the filing principal may withdraw this claim', status: 403 };
  }

  if (!['pending', 'under_challenge'].includes(claim.status)) {
    return { error: `Cannot withdraw claim in status '${claim.status}'`, status: 409 };
  }

  const { error } = await supabase
    .from('continuity_claims')
    .update({
      status: CONTINUITY_STATUS.WITHDRAWN,
      withdrawn_at: now,
      withdrawn_by: principalId,
      withdrawn_reason: reason || null,
      updated_at: now,
    })
    .eq('continuity_id', continuityId);

  if (error) return { error: error.message, status: 500 };

  await emitAudit(
    'continuity.withdrawn',
    principalId, 'principal',
    'continuity', continuityId,
    'withdraw',
    { status: claim.status },
    { status: CONTINUITY_STATUS.WITHDRAWN, reason },
  );

  return { continuity_id: continuityId, status: CONTINUITY_STATUS.WITHDRAWN, withdrawn_at: now };
}

/**
 * Emit audit event.
 */
async function emitAudit(eventType, actorId, actorType, targetType, targetId, action, beforeState, afterState) {
  const supabase = getServiceClient();
  try {
    await supabase.from('audit_events').insert({
      event_type: eventType,
      actor_id: actorId,
      actor_type: actorType,
      target_type: targetType,
      target_id: targetId,
      action,
      before_state: beforeState,
      after_state: afterState,
    });
  } catch (e) {
    logger.warn('Audit emit failed:', e.message);
  }
}

export { emitAudit };
