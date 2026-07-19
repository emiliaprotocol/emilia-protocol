// SPDX-License-Identifier: Apache-2.0

/**
 * Enrollment directory anchor.
 *
 * `approver.enroll` authorizes an operator to run the passkey ceremony, but it
 * does not by itself prove the named human exists. When a deployment has wired
 * a directory (SCIM), the approver_id MUST resolve to an active provisioned
 * user in that org's directory — the operator can no longer silently bind an
 * approver it does not control. When no directory is provisioned, enrollment
 * falls back to the second-party attestation (attested_by) and is recorded as
 * such, so the pilot / non-SCIM surface is never bricked.
 *
 * The org → directory link runs through scim_provisioning_tokens: it is the one
 * table carrying BOTH organization_id (the protocol org) and tenant_id (the
 * directory namespace). scim_users has no organization_id, only tenant_id, so
 * every org → directory lookup MUST join through the token.
 *
 * Two structural facts drive the query shape:
 *   1. One org can mint MANY tokens, each under its own tenant (the token's
 *      tenant_id is the minting entity id; its organization_id is that entity's
 *      org, which is NULL when the entity is not org-bound). So the org → tenant
 *      map is a SET, resolved from two arms: organization_id = org OR
 *      tenant_id = org (the second arm catches org-unbound tokens whose
 *      organization_id is NULL but which still provision a directory).
 *   2. Directory governance is STICKY. "Has a directory" is keyed on the
 *      EXISTENCE of a token row, revoked or not — never on token liveness.
 *      Revoking a SCIM bearer token is credential hygiene reachable by the very
 *      operator this gate defends against; if revocation silently downgraded the
 *      org to operator_attested, that operator would have a one-step bypass
 *      (revoke token → bind cfo@corp as attested). An org that has ever wired
 *      SCIM stays anchored until an administrator hard-deletes its token rows.
 *
 * userName matching uses the SAME normalizeUserName the SSO callback and the
 * SCIM write path use, so an operator that names `CFO@Corp.com` resolves to the
 * `cfo@corp.com` provisioned row — both sides normalize identically or the gate
 * silently fails open/closed. In directory mode the returned storedApproverId is
 * the NORMALIZED id, and the credential MUST be persisted under it: the SCIM
 * deprovision path revokes by normalized userName, so a raw-cased credential
 * would survive an IdP offboarding with live Class-A signing authority.
 *
 * @license Apache-2.0
 */

import { normalizeUserName } from '@/lib/scim/core';
import { logger } from '@/lib/logger.js';

const LOOKUP_FAILED = { status: 503, code: 'directory_lookup_failed', detail: 'Directory lookup unavailable' };

/**
 * @typedef {Object} EnrollmentBasisOk
 * @property {'directory'|'operator_attested'} basis  the recorded basis
 * @property {string|null} directoryUserId  scim_users.id for a directory match, else null
 * @property {string} storedApproverId  the approver_id to persist on the credential
 *   (NORMALIZED in directory mode; RAW in operator_attested mode)
 * @property {boolean} hasDirectory  whether the org has ever provisioned a directory
 */
/**
 * @typedef {Object} EnrollmentBasisError
 * @property {{status:number, code:string, detail:string}} error
 * @property {boolean} [hasDirectory]
 */

/**
 * Resolve the basis on which `approverId` may be enrolled under `organizationId`.
 *
 * Fail-closed: if either directory lookup errors (infra), return a 503 rather
 * than silently downgrading to operator_attested — a directory org must never
 * lose its anchor because a query hiccuped.
 *
 * @param {object} supabase  a guarded Supabase client
 * @param {string} organizationId  the resolved (authenticated) org
 * @param {string} approverId  the approver_id being enrolled
 * @returns {Promise<EnrollmentBasisOk|EnrollmentBasisError>}
 */
export async function resolveEnrollmentBasis(supabase, organizationId, approverId) {
  // Step A — resolve the org's directory tenant SET. Two equality reads unioned
  // in JS: org ids are attacker-influenced strings, so avoid interpolating them
  // into a PostgREST .or() filter. Revoked tokens are INCLUDED (sticky
  // governance), so no revoked_at filter here.
  let tenantIds;
  try {
    const [byOrg, byTenant] = await Promise.all([
      supabase.from('scim_provisioning_tokens').select('tenant_id').eq('organization_id', organizationId),
      supabase.from('scim_provisioning_tokens').select('tenant_id').eq('tenant_id', organizationId),
    ]);
    if (byOrg.error || byTenant.error) {
      logger.error('[directory-anchor] provisioning-token lookup failed:', byOrg.error || byTenant.error);
      return { error: LOOKUP_FAILED };
    }
    tenantIds = [...new Set(
      [...(byOrg.data || []), ...(byTenant.data || [])].map((r) => r.tenant_id).filter(Boolean),
    )];
  } catch (e) {
    logger.error('[directory-anchor] provisioning-token lookup threw:', e?.message);
    return { error: LOOKUP_FAILED };
  }

  // No token ever minted for this org: no directory. Operator-vouched path
  // (pilot / pre-SCIM). Preserve the RAW approver_id casing so pilot ids such as
  // `ep:approver:jchen-controller` round-trip unchanged.
  if (tenantIds.length === 0) {
    return { basis: 'operator_attested', directoryUserId: null, storedApproverId: approverId, hasDirectory: false };
  }

  // Step B — membership: the approver_id MUST be an ACTIVE provisioned user in
  // one of this org's directory tenants. Normalize identically to the SCIM write
  // and SSO read paths or the gate fails silently.
  const normalized = normalizeUserName(approverId);
  let users;
  try {
    const { data, error } = await supabase
      .from('scim_users')
      .select('id, active')
      .in('tenant_id', tenantIds)
      .eq('user_name', normalized);
    if (error) {
      logger.error('[directory-anchor] scim_users lookup failed:', error);
      return { error: LOOKUP_FAILED };
    }
    users = data || [];
  } catch (e) {
    logger.error('[directory-anchor] scim_users lookup threw:', e?.message);
    return { error: LOOKUP_FAILED };
  }

  const activeUser = users.find((u) => u.active === true);
  if (!activeUser) {
    // Directory exists but this approver is missing or deprovisioned. Fail
    // closed: an enrollment-authorized operator cannot bind an approver the
    // provisioned directory does not carry.
    return {
      hasDirectory: true,
      error: {
        status: 403,
        code: 'approver_not_provisioned',
        detail: "approver_id is not an active provisioned user in this organization's directory",
      },
    };
  }

  // Directory match. Persist the NORMALIZED id (so deprovision and signoff can
  // find the credential) and pin the exact source row for audit.
  return {
    basis: 'directory',
    directoryUserId: activeUser.id,
    storedApproverId: normalized,
    hasDirectory: true,
  };
}
