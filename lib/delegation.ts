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

import crypto from 'crypto';
import { getServiceClient } from '@/lib/supabase';

// Delegation ID prefix
const PREFIX = 'ep_dlg_';

/**
 * Lightweight error class for delegation operations.
 * Routes catch this and map to HTTP responses.
 */
export class EPError extends Error {
  status: number;
  code: string;

  constructor(message: string, status = 500, code = 'INTERNAL_ERROR') {
    super(message);
    this.name = 'EPError';
    this.status = status;
    this.code = code;
  }
}

/** A delegation record as stored in the `delegations` table. */
export interface DelegationRecord {
  delegation_id: string;
  principal_id: string;
  agent_entity_id: string;
  scope: string[];
  max_value_usd: number | null;
  expires_at: string;
  constraints: Record<string, unknown> | null;
  status: string;
  created_at: string;
  revoked_at?: string;
  [key: string]: unknown;
}

/**
 * Result of verifyDelegation(). All fields beyond `valid` are optional
 * because the shape returned differs by branch (not-found / revoked /
 * expired / found-and-checked) — callers narrow with a truthy check on
 * `valid`, `error`, etc., not a discriminant tag.
 */
export interface DelegationVerification {
  delegation_id?: string;
  valid: boolean;
  status?: string;
  reason?: string;
  action_type?: string;
  action_permitted?: boolean;
  principal_id?: string;
  agent_entity_id?: string;
  scope?: string[];
  max_value_usd?: number | null;
  expires_at?: string;
  constraints?: Record<string, unknown> | null;
  created_at?: string;
  [key: string]: unknown;
}

export interface CreateDelegationParams {
  principalId: string;
  agentEntityId: string;
  scope: string[];
  maxValueUsd?: number | null;
  expiresAt?: string | null;
  constraints?: Record<string, unknown> | null;
}

/**
 * Generate a new delegation ID.
 */
function newDelegationId(): string {
  return `${PREFIX}${crypto.randomUUID().replace(/-/g, '')}`;
}

// A scope token is '*', a prefix wildcard 'a.b.*', or a well-formed dot-path.
// Rejecting empty/double-dot segments closes the same class of bypass as the
// provenance scope check (no "a..b").
const WELL_FORMED_SEGMENTS = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$/;
function isValidScopeToken(t: unknown): boolean {
  if (typeof t !== 'string' || !t) return false;
  if (t === '*') return true;
  if (t.endsWith('.*')) return WELL_FORMED_SEGMENTS.test(t.slice(0, -2));
  return WELL_FORMED_SEGMENTS.test(t);
}

// Does a set of parent grants permit a child scope token? (Same wildcard
// semantics as packages/verify/provenance.js scopePermits.)
function grantsPermit(grants: string[], token: string): boolean {
  const probe = token.endsWith('.*') ? token.slice(0, -2) : token;
  for (const g of grants) {
    if (g === '*' || g === token || g === probe) return true;
    if (typeof g === 'string' && g.endsWith('.*')) {
      const p = g.slice(0, -2);
      if (probe === p || probe.startsWith(p + '.')) return true;
    }
  }
  return false;
}

/**
 * Create a delegation: authorize an agent to act on behalf of a principal.
 *
 * @param params.principalId - The principal granting delegation
 * @param params.agentEntityId - The agent entity being authorized
 * @param params.scope - Permitted action types
 * @param params.maxValueUsd - Optional transaction cap
 * @param params.expiresAt - ISO8601 expiry (defaults to 24h)
 * @param params.constraints - Optional additional constraints
 * @returns The created delegation record
 */
export async function createDelegation({
  principalId,
  agentEntityId,
  scope,
  maxValueUsd = null,
  expiresAt = null,
  constraints = null,
}: CreateDelegationParams): Promise<DelegationRecord> {
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

  // Validate scope tokens are well-formed before anything else. (NASTY-2)
  for (const t of scope) {
    if (!isValidScopeToken(t)) {
      throw new EPError(`Invalid scope token: ${JSON.stringify(t)}`, 400, 'INVALID_SCOPE');
    }
  }

  // Creation-time containment (NASTY-2): a principal that itself holds delegated
  // authority MUST NOT re-delegate more than it holds — no privilege escalation.
  // A principal with no parent delegation is a potential root authority; its
  // authority is validated at verification time via a human root_signoff
  // (packages/verify/provenance.js), which fails closed without one.
  const { data: held, error: heldErr } = await supabase
    .from('delegations')
    .select('scope, status, expires_at')
    .eq('agent_entity_id', principalId)
    .eq('status', 'active');
  if (heldErr && heldErr.code !== '42P01') {
    // Can't verify containment -> fail closed (don't grant unverifiable authority).
    throw new EPError('Could not verify the principal\'s delegated authority', 503, 'AUTHORITY_CHECK_FAILED');
  }
  const nowMs = Date.now();
  const heldScopes = (held || [])
    .filter((d) => !d.expires_at || new Date(d.expires_at).getTime() > nowMs)
    .flatMap((d) => (Array.isArray(d.scope) ? d.scope : []));
  if (heldScopes.length > 0) {
    for (const t of scope) {
      if (!grantsPermit(heldScopes, t)) {
        throw new EPError(
          `Scope "${t}" exceeds the principal's delegated authority [${heldScopes.join(', ')}] — cannot re-delegate more than you hold`,
          403, 'SCOPE_ESCALATION',
        );
      }
    }
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
    if (error.code === '42P01') {
      throw new EPError(
        'Delegations table missing; delegation creation must fail closed',
        503, 'DELEGATION_STORE_UNAVAILABLE',
      );
    }
    throw new EPError(`Failed to create delegation: ${error.message}`, 500, 'DB_ERROR');
  }

  return data;
}

/**
 * Verify a delegation is valid for an optional action type.
 *
 * @param delegationId
 * @param actionType - Optional: check if this action is in scope
 * @returns Delegation with { valid, action_permitted?, reason? }
 */
export async function verifyDelegation(
  delegationId: string,
  actionType: string | null = null,
): Promise<DelegationVerification> {
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
 * @param delegationId
 * @param principalId - Must match the delegation's principal
 */
export async function revokeDelegation(delegationId: string, principalId: string): Promise<void> {
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
