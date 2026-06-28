/**
 * SCIM → approver linkage.
 *
 * The point of SCIM provisioning is signing authority that tracks the
 * customer's directory. The link is the identity itself: a SCIM user's
 * userName (email/UPN) IS the approver_id the WebAuthn enrollment flow and the
 * SSO directory check use.
 *
 * - Provision (active=true): the human is enrollment-ELIGIBLE — recorded in
 *   the audit trail. No credential exists until they complete the passkey
 *   ceremony (a key cannot be minted on someone's behalf; that would be
 *   Class-C custody).
 * - Deprovision (active=false or DELETE): every unrevoked approver credential
 *   for that userName is revoked IN THE SAME WRITE. Offboarding in the IdP
 *   removes signing authority in the same sync. Revocation is one-way:
 *   re-provisioning makes the human eligible to re-enroll, it never
 *   resurrects a revoked key.
 *
 * @license Apache-2.0
 */

import { logger } from '@/lib/logger.js';

/**
 * Revoke all active approver credentials for a SCIM-managed identity, scoped to
 * the tenant's protocol organization so deprovisioning in one tenant can never
 * revoke a same-email approver's credential in another tenant (#6). The org is
 * the SCIM token's organization_id (requireScimAuth), falling back to tenantId
 * when unset. Returns the number revoked (0 when the human never enrolled).
 */
export async function revokeApproverCredentials(supabase, tenantId, userName, reason, organizationId) {
  const now = new Date().toISOString();
  const orgScope = organizationId || tenantId;
  const { data, error } = await supabase
    .from('approver_credentials')
    .update({ revoked_at: now })
    .eq('organization_id', orgScope)
    .eq('approver_id', userName)
    .is('revoked_at', null)
    .select('id');

  if (error) {
    // Fail loudly: a deprovision that silently leaves keys live is the exact
    // failure SCIM exists to prevent.
    logger.error('[scim/approver-link] credential revocation failed:', error);
    throw new Error(`approver credential revocation failed for ${userName}`);
  }
  const count = data?.length ?? 0;

  await auditLink(supabase, tenantId, userName, 'scim.approver.deprovisioned', {
    reason: reason || 'scim_deprovision',
    credentials_revoked: count,
    revoked_at: now,
  });
  return count;
}

/** Record that a provisioned human is now enrollment-eligible. */
export async function recordApproverEligible(supabase, tenantId, userName) {
  await auditLink(supabase, tenantId, userName, 'scim.approver.provisioned', {
    enrollment_eligible: true,
    enroll_via: '/api/v1/approvers/webauthn/register-options',
  });
}

async function auditLink(supabase, tenantId, userName, eventType, afterState) {
  try {
    await supabase.from('audit_events').insert({
      event_type: eventType,
      actor_id: tenantId,
      actor_type: 'tenant',
      target_type: 'approver',
      target_id: userName,
      action: eventType.endsWith('provisioned') && !eventType.includes('de') ? 'provision' : 'deprovision',
      before_state: null,
      after_state: { tenant_id: tenantId, approver_id: userName, ...afterState },
    });
  } catch (e) {
    logger.warn('[scim/approver-link] audit insert failed:', e?.message);
  }
}
