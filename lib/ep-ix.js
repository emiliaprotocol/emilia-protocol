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
  if (['approved_full', 'approved_partial', 'rejected', 'expired'].includes(claim.status)) {
    return { error: `Claim already resolved: ${claim.status}`, status: 409 };
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
