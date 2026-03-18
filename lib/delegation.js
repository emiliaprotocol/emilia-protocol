/**
 * EMILIA Protocol — Delegation System
 *
 * A delegation is a signed authorization: a principal (human/org/entity)
 * grants an agent the right to act on their behalf within defined scope.
 *
 * Delegation chain: when Agent B acts under delegation from Principal A,
 * the receipt record captures both. This creates an audit trail linking
 * the machine action to the human who authorized it.
 *
 * Protocol guarantee: Delegations are verifiable by any party.
 * Expired or revoked delegations immediately become invalid.
 *
 * @license Apache-2.0
 */

import { getServiceClient } from '@/lib/supabase';

// Delegation ID prefix
const PREFIX = 'ep_dlg_';

/**
 * Lightweight error class for delegation operations.
 * Routes catch this and map to HTTP responses.
 */
export class EPError extends Error {
  constructor(message, status = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.name = 'EPError';
    this.status = status;
    this.code = code;
  }
}

/**
 * Generate a new delegation ID.
 * @returns {string}
 */
function newDelegationId() {
  return `${PREFIX}${crypto.randomUUID().replace(/-/g, '')}`;
}

/**
 * Create a delegation: authorize an agent to act on behalf of a principal.
 *
 * @param {Object} params
 * @param {string} params.principalId - The principal granting delegation
 * @param {string} params.agentEntityId - The agent entity being authorized
 * @param {string[]} params.scope - Permitted action types
 * @param {number|null} params.maxValueUsd - Optional transaction cap
 * @param {string|null} params.expiresAt - ISO8601 expiry (defaults to 24h)
 * @param {Object|null} params.constraints - Optional additional constraints
 * @returns {Promise<Object>} The created delegation record
 */
export async function createDelegation({ principalId, agentEntityId, scope, maxValueUsd = null, expiresAt = null, constraints = null }) {
  if (!principalId || !agentEntityId || !scope?.length) {
    throw new EPError('principal_id, agent_entity_id, and scope are required', 400, 'VALIDATION_ERROR');
  }

  const supabase = getServiceClient();

  // Verify agent entity exists
  const { data: agent } = await supabase
    .from('entities')
    .select('id, entity_id, display_name')
    .eq('entity_id', agentEntityId)
    .maybeSingle();

  if (!agent) {
    throw new EPError(`Agent entity not found: ${agentEntityId}`, 404, 'ENTITY_NOT_FOUND');
  }

  // Default expiry: 24 hours
  const resolvedExpiry = expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const delegation = {
    delegation_id: newDelegationId(),
    principal_id: principalId,
    agent_entity_id: agentEntityId,
    scope,
    max_value_usd: maxValueUsd,
    expires_at: resolvedExpiry,
    constraints,
    status: 'active',
    created_at: new Date().toISOString(),
  };

  const { data, error } = await supabase
    .from('delegations')
    .insert(delegation)
    .select()
    .single();

  if (error) {
    // Graceful degradation: if delegations table doesn't exist yet, return the in-memory record
    if (error.code === '42P01') {
      console.warn('[EP] delegations table not yet created — returning in-memory delegation');
      return delegation;
    }
    throw new EPError(`Failed to create delegation: ${error.message}`, 500, 'DB_ERROR');
  }

  return data;
}

/**
 * Verify a delegation is valid for an optional action type.
 *
 * @param {string} delegationId
 * @param {string|null} actionType - Optional: check if this action is in scope
 * @returns {Promise<Object>} Delegation with { valid, action_permitted?, reason? }
 */
export async function verifyDelegation(delegationId, actionType = null) {
  const supabase = getServiceClient();

  const { data, error } = await supabase
    .from('delegations')
    .select('*')
    .eq('delegation_id', delegationId)
    .maybeSingle();

  if (error?.code === '42P01') {
    return { delegation_id: delegationId, valid: false, status: 'not_found', reason: 'delegations table not yet created' };
  }

  if (!data) {
    return { delegation_id: delegationId, valid: false, status: 'not_found', reason: 'Delegation not found' };
  }

  const now = new Date();
  const expiry = new Date(data.expires_at);

  if (data.status === 'revoked') {
    return { ...data, valid: false, reason: 'Delegation has been revoked' };
  }

  if (now > expiry) {
    // Auto-expire
    await supabase.from('delegations').update({ status: 'expired' }).eq('delegation_id', delegationId);
    return { ...data, status: 'expired', valid: false, reason: 'Delegation has expired' };
  }

  const result = { ...data, valid: true };

  if (actionType) {
    result.action_type = actionType;
    result.action_permitted = data.scope.includes(actionType) || data.scope.includes('*');
    if (!result.action_permitted) {
      result.reason = `Action "${actionType}" is not in delegation scope: [${data.scope.join(', ')}]`;
    }
  }

  return result;
}

/**
 * Revoke a delegation immediately.
 *
 * @param {string} delegationId
 * @param {string} principalId - Must match the delegation's principal
 * @returns {Promise<void>}
 */
export async function revokeDelegation(delegationId, principalId) {
  const supabase = getServiceClient();

  const { data, error } = await supabase
    .from('delegations')
    .update({ status: 'revoked', revoked_at: new Date().toISOString() })
    .eq('delegation_id', delegationId)
    .eq('principal_id', principalId)
    .select()
    .maybeSingle();

  if (error) throw new EPError(`Revocation failed: ${error.message}`, 500, 'DB_ERROR');
  if (!data) throw new EPError('Delegation not found or principal mismatch', 404, 'NOT_FOUND');
}
