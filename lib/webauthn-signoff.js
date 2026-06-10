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

/**
 * Load everything the signing routes need for one signoff: the request
 * event, the receipt's creation event, and decision state.
 * Returns { error } (an epProblem response) or the loaded rows.
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

  const created = (events || []).find((e) => e.event_type === 'guard.trust_receipt.created');
  if (!created) {
    return { error: epProblem(500, 'corrupted_receipt', 'Receipt missing creation event') };
  }

  const alreadyDecided = (events || []).some(
    (e) => e.event_type !== 'guard.trust_receipt.created'
      && e.after_state?.signoff_id === signoffId,
  );

  return {
    signoffId,
    receiptId,
    requestEvent,
    createdState: created.after_state,
    initiatorId: requestEvent.after_state.initiator_id,
    actionHash: requestEvent.after_state.action_hash,
    requestExpiresAt: requestEvent.after_state.expires_at,
    alreadyDecided,
  };
}

/** Load an approver's active (non-revoked, in-validity-window) credentials. */
export async function loadApproverCredentials(supabase, approverId) {
  const { data, error } = await supabase
    .from('approver_credentials')
    .select('credential_id, public_key_cose, public_key_spki, sign_count, transports, approver_id, approver_name, valid_to')
    .eq('approver_id', approverId)
    .is('revoked_at', null);
  if (error) {
    logger.error('[webauthn-signoff] credential load failed:', error);
    return { error: epProblem(500, 'internal_error', 'Failed to load approver credentials') };
  }
  const now = new Date();
  const active = (data || []).filter((c) => !c.valid_to || new Date(c.valid_to) > now);
  return { credentials: active };
}
