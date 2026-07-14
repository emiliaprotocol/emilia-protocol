// SPDX-License-Identifier: Apache-2.0
// Build the portable EP-SIGNOFF-v1 view of a terminal Class-A decision.
//
// The audit event remains the durable store. This projection exposes only the
// bytes an offline verifier needs and refuses to project an internally
// inconsistent event. Signature trust still comes from the relying party's
// pinned approver key, never from key material supplied by this record.

import { contextHashHex } from '../webauthn.js';

const EVENT_DECISIONS = Object.freeze({
  'guard.signoff.approved': 'approved',
  'guard.signoff.rejected': 'denied',
});

function normalizedSha256(value) {
  if (typeof value !== 'string') return null;
  const bare = value.toLowerCase().replace(/^sha256:/, '');
  return /^[0-9a-f]{64}$/.test(bare) ? bare : null;
}

/**
 * Return a portable, offline-verifiable Class-A decision or null.
 *
 * The caller verifies `record.signoff` with verifyWebAuthnSignoff() and an
 * independently pinned approver key. `record.decision` is copied only from the
 * signed context after the event type, actor, nonce, action, and context hash
 * all agree with that context.
 */
export function buildPortableSignoffDecision(event) {
  const signedDecision = EVENT_DECISIONS[event?.event_type];
  const state = event?.after_state;
  const context = state?.context;
  const webauthn = state?.webauthn;
  if (!signedDecision || !state || state.key_class !== 'A' || !context || !webauthn) return null;
  if (context.decision !== signedDecision) return null;
  if (!state.signoff_id || context.nonce !== state.signoff_id) return null;
  if (!state.approver_id || context.approver !== state.approver_id) return null;
  if (event.actor_id && event.actor_id !== state.approver_id) return null;
  if (!state.approved_action_hash || context.action_hash !== state.approved_action_hash) return null;
  if (!webauthn.credential_id
    || !webauthn.authenticator_data
    || !webauthn.client_data_json
    || !webauthn.signature) return null;

  const computedContextHash = contextHashHex(context);
  if (normalizedSha256(state.context_hash) !== computedContextHash) return null;

  return {
    decision: signedDecision,
    signoff_id: state.signoff_id,
    approver_id: state.approver_id,
    action_hash: context.action_hash,
    decided_at: state.decided_at || event.created_at || null,
    key_class: 'A',
    credential_id: webauthn.credential_id,
    context_hash: `sha256:${computedContextHash}`,
    signoff: {
      '@type': 'ep.signoff',
      context,
      webauthn: {
        authenticator_data: webauthn.authenticator_data,
        client_data_json: webauthn.client_data_json,
        signature: webauthn.signature,
      },
    },
  };
}

