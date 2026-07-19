// SPDX-License-Identifier: Apache-2.0
// #5 Authority registry resolution for the guard signoff path.
//
// Principle: credentials prove control; AUTHORITIES prove permission. A passkey
// in approver_credentials proves someone holds a key; it does NOT prove they are
// still authorized to approve for this org, in this role, at this assurance
// class. Only the authorities registry answers that — and it fails closed.

/**
 * Assurance ordering: a higher class satisfies a lower requirement.
 * 'A' = approver-held device key (highest); 'C' = platform/software signer.
 */
const ASSURANCE_RANK = Object.freeze({ C: 1, B: 2, A: 3 });

function meetsAssurance(have, required) {
  if (!required) return true;
  return (ASSURANCE_RANK[have] || 0) >= (ASSURANCE_RANK[required] || 0);
}

/**
 * Pure decision over a single authority record. No I/O — unit-testable.
 *
 * @param {object|null} record  the authorities row (or null if none found)
 * @param {{ role?: string, at?: string, requiredAssurance?: string }} ctx
 * @returns {{ authorized: boolean, reason: string, assurance_class: string|null, authority_id?: string }}
 */
export function evaluateAuthority(record, { role, at, requiredAssurance } = {}) {
  const now = at || new Date().toISOString();
  if (!record) return { authorized: false, reason: 'no_active_authority', assurance_class: null };
  if (record.revoked_at) return { authorized: false, reason: 'authority_revoked', assurance_class: null };
  if (record.status && record.status !== 'active') {
    return { authorized: false, reason: `authority_${record.status}`, assurance_class: null };
  }
  if (record.valid_from && record.valid_from > now) {
    return { authorized: false, reason: 'authority_not_yet_valid', assurance_class: null };
  }
  if (record.valid_to && record.valid_to < now) {
    return { authorized: false, reason: 'authority_expired', assurance_class: null };
  }
  if (role && record.role !== role) {
    return { authorized: false, reason: 'wrong_role', assurance_class: null };
  }
  if (!meetsAssurance(record.assurance_class, requiredAssurance)) {
    return { authorized: false, reason: 'insufficient_assurance', assurance_class: record.assurance_class || null };
  }
  return {
    authorized: true,
    reason: 'ok',
    assurance_class: record.assurance_class || null,
    authority_id: record.authority_id,
  };
}

/**
 * Resolve a human approver's authority from the registry and decide.
 * Fails closed: no active, in-window, in-org, sufficient-assurance record => not authorized.
 *
 * @param {object} supabase  a query client
 * @param {{ organizationId?: string, approverId?: string, role?: string, at?: string, requiredAssurance?: string }} [ctx]
 */
export async function resolveGuardAuthority(supabase, { organizationId, approverId, role, at, requiredAssurance } = {}) {
  if (!organizationId || !approverId) {
    return { authorized: false, reason: 'missing_authority_subject', assurance_class: null };
  }
  const { data, error } = await supabase
    .from('authorities')
    .select('authority_id, role, assurance_class, status, valid_from, valid_to, revoked_at, organization_id, subject_type, subject_ref')
    .eq('subject_type', 'human_approver')
    .eq('subject_ref', approverId)
    .eq('organization_id', organizationId)
    .limit(1);
  if (error) return { authorized: false, reason: 'authority_lookup_failed', assurance_class: null };
  return evaluateAuthority((data || [])[0] || null, { role, at, requiredAssurance });
}
