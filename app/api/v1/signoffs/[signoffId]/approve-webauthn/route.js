// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — POST /api/v1/signoffs/[signoffId]/approve-webauthn
//
// The named human signs the context hash on their own device; the server
// orchestrates but cannot forge. Verifies a WebAuthn assertion whose
// challenge is SHA-256(JCS(AuthorizationContext)) — single-use, action-bound
// — then records the decision with key_class 'A' and the assertion itself,
// so the receipt verifies offline against the approver's enrolled key.
//
// Decisions: the outcome is carried inside the persisted Authorization
// Context and therefore inside the WebAuthn-signed challenge. body.decision is
// only a consistency assertion; it can never relabel the signed outcome.

import { NextResponse } from 'next/server';
import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import {
  getRpConfig,
  contextHashBytes,
  APPROVER_ID_PATTERN,
  SIGNOFF_ID_PATTERN,
} from '@/lib/webauthn';
import { loadSignoffForSigning } from '@/lib/webauthn-signoff';
import { normalizeUserName } from '@/lib/scim/core';
import { canAccept } from '@/lib/signoff/quorum-session.js';
import { decisionToMember, decisionsToMembers } from '@/lib/signoff/attestation-members.js';
import { readLimitedJson } from '@/lib/http/body-limit';
import { strictJsonGate } from '@/lib/strict-json.js';

const MAX_WEBAUTHN_APPROVE_BYTES = 256 * 1024;

function submittedChallenge(assertion) {
  try {
    const raw = assertion?.response?.clientDataJSON;
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 32 * 1024
        || !/^[A-Za-z0-9_-]+$/.test(raw)) return null;
    const bytes = Buffer.from(raw, 'base64url');
    if (bytes.toString('base64url') !== raw || bytes.length > 16 * 1024) return null;
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!strictJsonGate(text).ok) return null;
    const clientData = JSON.parse(text);
    return typeof clientData.challenge === 'string' ? clientData.challenge : null;
  } catch {
    return null;
  }
}

export async function POST(request, { params }) {
  try {
    const { signoffId } = await params;
    if (!SIGNOFF_ID_PATTERN.test(signoffId || '')) {
      return epProblem(400, 'invalid_signoff_id', 'signoff_id must match sig_<32-hex>');
    }
    const parsed = await readLimitedJson(request, MAX_WEBAUTHN_APPROVE_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body.approver_id || !APPROVER_ID_PATTERN.test(body.approver_id)) {
      return epProblem(400, 'invalid_approver_id', 'approver_id is required');
    }
    if (!body.assertion?.id || !body.assertion?.response) {
      return epProblem(400, 'missing_assertion', 'assertion (authentication response) is required');
    }
    if (body.decision !== undefined
      && body.decision !== 'approved'
      && body.decision !== 'rejected'
      && body.decision !== 'denied') {
      return epProblem(400, 'invalid_decision', 'decision must be approved, rejected, or denied');
    }
    const submittedSignedDecision = body.decision === undefined
      ? null
      : (body.decision === 'approved' ? 'approved' : 'denied');

    const supabase = getGuardedClient();

    // ── Signoff state checks (same invariants as the bearer-key path).
    const loaded = await loadSignoffForSigning(supabase, signoffId);
    if (loaded.error) return loaded.error;
    if (!loaded.organizationId) {
      return epProblem(409, 'receipt_not_org_bound', 'Class-A signoff requires an organization-bound receipt');
    }
    if (loaded.alreadyDecided) {
      return epProblem(409, 'signoff_already_decided', 'Signoff has already been decided');
    }
    if (new Date(loaded.requestExpiresAt) < new Date()) {
      return epProblem(410, 'signoff_expired', 'Signoff approval window has expired');
    }
    const expectedApproverId = loaded.requestEvent.after_state.approver_id
      || loaded.requestEvent.after_state.quorum?.approver_id
      || null;
    if (!expectedApproverId) {
      return epProblem(409, 'approver_not_bound', 'Signoff request is missing an intended approver');
    }
    if (body.approver_id !== expectedApproverId) {
      return epProblem(403, 'approver_mismatch', 'Approver does not match the signoff request');
    }
    // Separation of duties — approver MUST NOT be the initiator (draft §6.1).
    if (body.approver_id === loaded.initiatorId) {
      return epProblem(403, 'self_approval_forbidden', 'Approver cannot be the initiator of the signoff request');
    }

    const assertionChallenge = submittedChallenge(body.assertion);
    if (!assertionChallenge) {
      return epProblem(400, 'assertion_invalid', 'Assertion clientDataJSON is missing a WebAuthn challenge');
    }

    // ── Load the exact live challenge the authenticator says it signed. Do not
    // consume it until the assertion verifies; otherwise anyone with the
    // capability URL could burn the approver's ceremony with junk assertions.
    const { data: challenges, error: chErr } = await supabase
      .from('webauthn_challenges')
      .select('id, challenge, context, context_hash, expires_at')
      .eq('kind', 'signoff')
      .eq('organization_id', loaded.organizationId)
      .eq('signoff_id', signoffId)
      .eq('approver_id', body.approver_id)
      .eq('challenge', assertionChallenge)
      .is('consumed_at', null)
      .order('created_at', { ascending: false })
      .limit(1);
    if (chErr) {
      logger.error('[webauthn] approve: challenge load failed:', chErr);
      return epProblem(500, 'internal_error', 'Failed to load signing challenge');
    }
    const challengeRow = (challenges || [])[0];
    if (!challengeRow) {
      return epProblem(404, 'no_pending_challenge', 'No live signing challenge — request webauthn-options first');
    }
    if (new Date(challengeRow.expires_at) < new Date()) {
      return epProblem(410, 'challenge_expired', 'Signing challenge expired — request webauthn-options again');
    }

    // The decision is part of the canonical context whose hash the device
    // signed. Never choose it from a post-signature request field: doing so
    // would let a valid denial assertion be relabeled as approval (or vice
    // versa) without invalidating the signature.
    const signedDecision = challengeRow.context?.decision;
    if (signedDecision !== 'approved' && signedDecision !== 'denied') {
      return epProblem(409, 'decision_binding_required', 'Signing context does not bind an approved or denied decision');
    }
    if (submittedSignedDecision !== null && submittedSignedDecision !== signedDecision) {
      return epProblem(409, 'decision_mismatch', 'Submitted decision does not match the device-signed decision');
    }
    const decision = signedDecision === 'denied' ? 'rejected' : 'approved';

    // The signed context must bind this exact action (BindingMatch).
    if (challengeRow.context?.action_hash !== loaded.actionHash) {
      return epProblem(409, 'action_hash_mismatch', 'Signing context does not bind the receipt-issued action_hash');
    }

    // WYSIWYS defense-in-depth (NASTY-1): a Class-A (hardware/biometric) signoff
    // MUST carry a display_hash in the signed context, so the hardware signature
    // provably covers what the human SAW — not just the opaque action_hash.
    // Issuance (webauthn-options) already enforces this for required_assurance
    // 'A'; re-checking here means the verifier never relies solely on issuance,
    // and any context lacking display_hash for a Class-A signoff is refused.
    const requiredAssurance = loaded.requestEvent.after_state?.required_assurance
      || loaded.requestEvent.after_state?.quorum?.required_assurance
      || null;
    if (requiredAssurance === 'A' && !challengeRow.context?.display_hash) {
      return epProblem(409, 'display_binding_required', 'Class-A signoff requires a WYSIWYS display_hash bound into the signed context');
    }

    // ── Credential: the assertion's credential must belong to this approver.
    const { data: creds, error: credErr } = await supabase
      .from('approver_credentials')
      .select('credential_id, public_key_cose, public_key_spki, sign_count, transports, approver_id, approver_name, enrollment_basis, valid_from, valid_to, organization_id')
      .eq('credential_id', body.assertion.id)
      .eq('organization_id', loaded.organizationId)
      .is('revoked_at', null)
      .limit(1);
    if (credErr) {
      logger.error('[webauthn] approve: credential load failed:', credErr);
      return epProblem(500, 'internal_error', 'Failed to load credential');
    }
    const credential = (creds || [])[0];
    // Match loadApproverCredentials semantics: directory-backed credentials are
    // stored under a normalized id and may use that alias; operator-attested
    // ids are opaque and must match exactly.
    const normalizedApproverId = normalizeUserName(body.approver_id);
    const approverMatches = !!credential
      && (credential.approver_id === body.approver_id
        || (credential.enrollment_basis === 'directory'
          && credential.approver_id === normalizedApproverId));
    const decisionTime = new Date();
    const validFrom = credential?.valid_from ? new Date(credential.valid_from) : null;
    const validTo = credential?.valid_to ? new Date(credential.valid_to) : null;
    const activeAtDecision = (!validFrom || validFrom <= decisionTime)
      && (!validTo || validTo > decisionTime);
    if (!approverMatches || !activeAtDecision) {
      return epProblem(403, 'credential_not_enrolled', 'Assertion credential is not an active enrollment for this approver');
    }

    // ── Verify the assertion. expectedChallenge is recomputed from the
    // stored canonical context — not trusted from the client — so the
    // signature provably covers SHA-256(JCS(AuthorizationContext)).
    const expectedChallenge = contextHashBytes(challengeRow.context).toString('base64url');
    if (expectedChallenge !== challengeRow.challenge) {
      // Stored context and stored challenge must agree; if not, refuse.
      logger.error('[webauthn] approve: context/challenge divergence', { signoffId });
      return epProblem(500, 'internal_error', 'Stored signing context is inconsistent');
    }

    const { rpID, origin } = getRpConfig();
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.assertion,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: credential.credential_id,
          publicKey: Buffer.from(credential.public_key_cose, 'base64url'),
          counter: Number(credential.sign_count) || 0,
          transports: credential.transports || undefined,
        },
        requireUserVerification: true, // biometric/PIN — draft §5.1 MUST
      });
    } catch (e) {
      return epProblem(400, 'assertion_invalid', `Assertion verification failed: ${e.message}`);
    }
    if (!verification.verified) {
      return epProblem(400, 'assertion_invalid', 'Assertion did not verify');
    }
    const { data: claimed } = await supabase
      .from('webauthn_challenges')
      .update({ consumed_at: new Date().toISOString() })
      .eq('organization_id', loaded.organizationId)
      .eq('id', challengeRow.id)
      .eq('challenge', assertionChallenge)
      .is('consumed_at', null)
      .select('id');
    if (!claimed || claimed.length === 0) {
      return epProblem(409, 'challenge_replayed', 'Signing challenge already consumed');
    }

    // ── EP-QUORUM-v1 early gate (defense-in-depth) ─────────────────────────
    // If this receipt carries a multi-party quorum policy, reject a signer who
    // cannot be admitted to the trail (ineligible / duplicate human / out of
    // order / outside the window) BEFORE recording their approval — early,
    // actionable feedback. The consume gate re-verifies the full quorum through
    // the same predicate regardless, so this is not the security boundary.
    if (decision === 'approved') {
      const { data: rcEvents } = await supabase
        .from('audit_events')
        .select('event_type, after_state, created_at')
        .eq('target_type', 'trust_receipt')
        .eq('target_id', loaded.receiptId)
        .order('created_at', { ascending: true });
      const createdEv = (rcEvents || []).find((e) => e.event_type === 'guard.trust_receipt.created');
      const quorumPolicy = createdEv && createdEv.after_state && createdEv.after_state.quorum_policy;
      if (quorumPolicy) {
        const priorApproved = (rcEvents || [])
          .filter((e) => e.event_type === 'guard.signoff.approved')
          .map((e) => e.after_state)
          .filter(Boolean);
        const credMap = { [credential.credential_id]: { public_key_spki: credential.public_key_spki } };
        const priorCredIds = priorApproved.map((d) => d.webauthn && d.webauthn.credential_id).filter(Boolean);
        if (priorCredIds.length > 0) {
          const { data: pc } = await supabase
            .from('approver_credentials')
            .select('credential_id, public_key_spki')
            .eq('organization_id', loaded.organizationId)
            .in('credential_id', priorCredIds);
          for (const c of pc || []) credMap[c.credential_id] = c;
        }
        const existingMembers = decisionsToMembers(quorumPolicy, priorApproved, credMap);
        const roster = quorumPolicy.approvers || [];
        const incoming = decisionToMember({
          role: (roster.find((a) => a.approver === body.approver_id) || {}).role || null,
          approver_public_key: credential.public_key_spki,
          context: challengeRow.context,
          webauthn: {
            authenticator_data: body.assertion.response.authenticatorData,
            client_data_json: body.assertion.response.clientDataJSON,
            signature: body.assertion.response.signature,
          },
        });
        const verdict = canAccept(quorumPolicy, loaded.actionHash, existingMembers, incoming, {
          rpId: rpID,
          allowedOrigins: [origin],
        });
        if (!verdict.ok) {
          return epProblem(409, 'quorum_signer_rejected', `Signer cannot be admitted to the quorum: ${verdict.reason}`);
        }
      }
    }

    // ── Record the decision (race-safe via the decided-once unique index).
    const decidedAt = new Date().toISOString();
    const { error: insertErr } = await supabase.from('audit_events').insert({
      event_type: `guard.signoff.${decision}`,
      actor_id: body.approver_id,
      actor_type: 'principal',
      target_type: 'trust_receipt',
      target_id: loaded.receiptId,
      action: decision,
      before_state: { signoff_status: 'pending' },
      after_state: {
        signoff_id: signoffId,
        approver_id: body.approver_id,
        approver_name: credential.approver_name || null,
        approved_action_hash: loaded.actionHash,
        decided_at: decidedAt,
        // Class A evidence (draft §5.3): the context that was signed, its
        // hash, and the assertion — everything an offline verifier needs
        // besides the approver's enrolled public key.
        key_class: 'A',
        context: challengeRow.context,
        context_hash: challengeRow.context_hash,
        webauthn: {
          credential_id: credential.credential_id,
          authenticator_data: body.assertion.response.authenticatorData,
          client_data_json: body.assertion.response.clientDataJSON,
          signature: body.assertion.response.signature,
        },
      },
    });
    if (insertErr) {
      if (insertErr.code === '23505') {
        return epProblem(409, 'signoff_already_decided', 'Signoff has already been decided');
      }
      logger.error('[webauthn] approve: decision insert failed:', insertErr);
      return epProblem(500, 'internal_error', 'Failed to record signoff decision');
    }

    // ── Sign-count forward (clone detection signal) + pilot telemetry.
    await supabase
      .from('approver_credentials')
      .update({ sign_count: verification.authenticationInfo.newCounter })
      .eq('organization_id', loaded.organizationId)
      .eq('credential_id', credential.credential_id);

    try {
      const { data: metric } = await supabase
        .from('signoff_metrics')
        .select('rendered_at')
        .eq('signoff_id', signoffId)
        .single();
      const renderedAt = metric?.rendered_at ? new Date(metric.rendered_at) : null;
      const signedAt = new Date(decidedAt);
      await supabase.from('signoff_metrics').upsert({
        signoff_id: signoffId,
        receipt_id: loaded.receiptId,
        approver_id: body.approver_id,
        signed_at: decidedAt,
        time_to_sign_ms: renderedAt ? Math.max(0, /** @type {any} */ (signedAt) - /** @type {any} */ (renderedAt)) : null,
        decision,
        key_class: 'A',
        ...(renderedAt ? {} : { rendered_at: null }),
      }, { onConflict: 'signoff_id' });
    } catch (e) {
      // Telemetry must never break the decision path.
      logger.warn('[webauthn] approve: metrics write failed:', e?.message);
    }

    return NextResponse.json({
      signoff_id: signoffId,
      receipt_id: loaded.receiptId,
      decision,
      approver_id: body.approver_id,
      key_class: 'A',
      context_hash: challengeRow.context_hash,
      signed_decision: signedDecision,
      decided_at: decidedAt,
    });
  } catch (err) {
    logger.error('[webauthn] POST approve-webauthn error:', err);
    return epProblem(500, 'internal_error', 'WebAuthn signoff failed');
  }
}
