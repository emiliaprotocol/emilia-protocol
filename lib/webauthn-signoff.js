// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — shared loaders for the WebAuthn signing routes.
//
// Auth model, stated plainly: these surfaces are capability-URL + assertion.
// Possession of the unguessable signoff_id (sig_<128 bits CSPRNG>) lets a
// holder VIEW the pending action — the same model as every approval-link
// product. AUTHORIZING it additionally requires a WebAuthn assertion from a
// credential enrolled (with second-party attestation) for an approver who is
// not the initiator. The assertion is the authentication.

import { epProblem } from './errors.js';
import { logger } from './logger.js';
import { normalizeUserName } from './scim/core.js';

/**
 * Load everything the signing routes need for one signoff: the request
 * event, the receipt's creation event, and decision state.
 * Returns { error } (an epProblem response) or the loaded rows.
 * @param {import('@supabase/supabase-js').SupabaseClient} supabase
 * @param {string} signoffId
 */
export async function loadSignoffForSigning(supabase, signoffId) {
  const { data: requests, error: reqErr } = await supabase
    .from('audit_events')
    .select('target_id, actor_id, after_state, created_at')
    .eq('event_type', 'guard.signoff.requested')
    .eq('after_state->>signoff_id', signoffId)
    .limit(1);
  if (reqErr) {
    logger.error('[webauthn-signoff] load request failed:', reqErr);
    return { error: epProblem(500, 'internal_error', 'Failed to load signoff request') };
  }
  const requestEvent = (requests || [])[0];
  if (!requestEvent) {
    return { error: epProblem(404, 'signoff_not_found', `Signoff ${signoffId} not found`) };
  }

  const receiptId = requestEvent.target_id;

  const { data: events, error: evErr } = await supabase
    .from('audit_events')
    .select('event_type, after_state')
    .eq('target_type', 'trust_receipt')
    .eq('target_id', receiptId)
    .in('event_type', [
      'guard.trust_receipt.created',
      'guard.signoff.approved',
      'guard.signoff.rejected',
    ]);
  if (evErr) {
    logger.error('[webauthn-signoff] load receipt events failed:', evErr);
    return { error: epProblem(500, 'internal_error', 'Failed to load receipt') };
  }

  const created = (events || []).find(
    (/** @type {{ event_type: string, after_state: * }} */ e) => e.event_type === 'guard.trust_receipt.created',
  );
  if (!created) {
    return { error: epProblem(500, 'corrupted_receipt', 'Receipt missing creation event') };
  }

  const alreadyDecided = (events || []).some(
    (/** @type {{ event_type: string, after_state: * }} */ e) => e.event_type !== 'guard.trust_receipt.created'
      && e.after_state?.signoff_id === signoffId,
  );

  return {
    signoffId,
    receiptId,
    requestEvent,
    createdState: created.after_state,
    organizationId: created.after_state?.organization_id
      || created.after_state?.canonical_action?.organization_id
      || null,
    initiatorId: requestEvent.after_state.initiator_id,
    actionHash: requestEvent.after_state.action_hash,
    requestExpiresAt: requestEvent.after_state.expires_at,
    alreadyDecided,
  };
}

/**
 * Load an approver's active (non-revoked, in-validity-window) credentials.
 * @param {import('@supabase/supabase-js').SupabaseClient} supabase
 * @param {string} approverId
 * @param {string|null} [organizationId]
 */
export async function loadApproverCredentials(supabase, approverId, organizationId = null) {
  // A directory-anchored credential is stored under the NORMALIZED approver_id
  // (see lib/scim/directory-anchor.js); an operator-attested pilot id is stored
  // RAW and is case-sensitive. We must still find a directory credential when
  // the signoff supplies a different casing — but the case-folded alias must
  // NEVER let a case-variant satisfy an operator-attested identity: `Alice@corp`
  // and `alice@corp` are two distinct opaque ids in operator-attested mode and
  // must not cross-authorize. So: fetch both forms, then honor the normalized
  // alias only for enrollment_basis='directory' rows; operator-attested rows
  // must match approver_id EXACTLY.
  const normalized = normalizeUserName(approverId);
  const candidateIds = [...new Set([approverId, normalized])];
  let query = supabase
    .from('approver_credentials')
    .select('credential_id, public_key_cose, public_key_spki, sign_count, transports, approver_id, approver_name, enrollment_basis, valid_from, valid_to, organization_id')
    .in('approver_id', candidateIds)
    .is('revoked_at', null);
  if (organizationId) query = query.eq('organization_id', organizationId);
  const { data, error } = await query;
  if (error) {
    logger.error('[webauthn-signoff] credential load failed:', error);
    return { error: epProblem(500, 'internal_error', 'Failed to load approver credentials') };
  }
  const now = new Date();
  const active = (data || []).filter((/** @type {{ approver_id: string, enrollment_basis: string, valid_from: string|null, valid_to: string|null }} */ c) => {
    // Exact match is always valid. The normalized alias is honored ONLY for a
    // directory credential (stored normalized by design); an operator-attested
    // credential whose raw id merely case-folds to the target is rejected.
    const idMatches = c.approver_id === approverId
      || (c.enrollment_basis === 'directory' && c.approver_id === normalized);
    if (!idMatches) return false;
    const starts = c.valid_from ? new Date(c.valid_from) : null;
    const ends = c.valid_to ? new Date(c.valid_to) : null;
    return (!starts || starts <= now) && (!ends || ends > now);
  });
  return { credentials: active };
}
