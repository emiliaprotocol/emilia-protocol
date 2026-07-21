// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — POST /api/v1/signoffs/[signoffId]/webauthn-options
//
// Issue the WebAuthn authentication options for one signoff attempt. The
// challenge IS the context hash: SHA-256(JCS(AuthorizationContext)) — built
// here, persisted single-use, verified byte-for-byte at /approve-webauthn.
// See lib/webauthn-signoff.js for the capability-URL + assertion auth model.

import { NextRequest, NextResponse } from 'next/server';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import {
  getRpConfig,
  buildAuthorizationContext,
  contextHashBytes,
  contextHashHex,
  APPROVER_ID_PATTERN,
  SIGNOFF_ID_PATTERN,
  CHALLENGE_TTL_MS,
} from '@/lib/webauthn';
import { loadSignoffForSigning, loadApproverCredentials } from '@/lib/webauthn-signoff';
import { renderAction } from '@/lib/wysiwys/render.js';
import { readLimitedJson } from '@/lib/http/body-limit';

const MAX_WEBAUTHN_SIGNOFF_OPTIONS_BYTES = 32 * 1024;

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ signoffId: string }> }
): Promise<NextResponse> {
  try {
    const { signoffId } = await params;
    if (!SIGNOFF_ID_PATTERN.test(signoffId || '')) {
      return epProblem(400, 'invalid_signoff_id', 'signoff_id must match sig_<32-hex>');
    }
    const parsed = await readLimitedJson(request, MAX_WEBAUTHN_SIGNOFF_OPTIONS_BYTES, { invalidValue: {} } as any);
    if (!parsed.ok) {
      const failure = parsed as { ok: false; status: number; code: string; detail: string };
      return epProblem(failure.status, failure.code, failure.detail);
    }
    const body = (parsed as { ok: true; value: any }).value;
    if (!body.approver_id || !APPROVER_ID_PATTERN.test(body.approver_id)) {
      return epProblem(400, 'invalid_approver_id', 'approver_id is required (3-128 chars of [A-Za-z0-9:_.@-])');
    }
    const requestedDecision = body.decision ?? 'approved';
    if (requestedDecision !== 'approved' && requestedDecision !== 'rejected' && requestedDecision !== 'denied') {
      return epProblem(400, 'invalid_decision', 'decision must be approved, rejected, or denied');
    }
    // The public API retains `rejected` for backward compatibility; the signed
    // wire value is the draft's canonical `denied` terminal outcome.
    const signedDecision: 'approved' | 'denied' = requestedDecision === 'approved' ? 'approved' : 'denied';

    const supabase = getGuardedClient();
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

    // SoD pre-check (the authoritative check re-runs at approval): the
    // approver identity must not be the initiator entity.
    if (body.approver_id === loaded.initiatorId) {
      return epProblem(403, 'self_approval_forbidden', 'Approver cannot be the initiator of the signoff request');
    }

    const credLoad = await loadApproverCredentials(supabase, body.approver_id, loaded.organizationId);
    if (credLoad.error) return credLoad.error;
    if (credLoad.credentials.length === 0) {
      return epProblem(404, 'approver_not_enrolled', 'No active passkey enrolled for this approver — enroll at /approvers/enroll');
    }

    // Build the Authorization Context (EP draft §4). The context window is
    // the shorter of the signoff window and the 5-minute challenge TTL.
    const issuedAt = new Date();
    const ctxExpiry = new Date(Math.min(
      new Date(loaded.requestExpiresAt).getTime(),
      issuedAt.getTime() + CHALLENGE_TTL_MS,
    ));
    // WYSIWYS (EP draft §11.3): bind the human-visible rendering of the EXACT
    // action into the signed context, so the approver signs what they saw — not
    // just the action hash. Class-A/high-risk signoffs require this binding.
    let displayHash: string | null = null;
    let rendering: ReturnType<typeof renderAction> | null = null;
    const canonicalAction = loaded.createdState?.canonical_action;
    const displayBindingRequired = loaded.createdState?.required_assurance === 'A';
    if (displayBindingRequired && !canonicalAction) {
      return epProblem(409, 'display_binding_required', 'Class-A signoff requires canonical_action for WYSIWYS display_hash binding');
    }
    if (canonicalAction) {
      try {
        rendering = renderAction(canonicalAction);
        displayHash = rendering.display_hash;
      } catch (e) {
        logger.warn('[webauthn] signoff options: renderAction failed:', e?.message);
        if (displayBindingRequired) {
          return epProblem(500, 'display_render_failed', 'Class-A signoff requires a renderable WYSIWYS display_hash');
        }
      }
    }
    if (displayBindingRequired && !displayHash) {
      return epProblem(409, 'display_binding_required', 'Class-A signoff requires WYSIWYS display_hash binding');
    }
    const context = buildAuthorizationContext({
      actionHash: loaded.actionHash,
      policyId: loaded.createdState.policy_id,
      policyHash: loaded.createdState.policy_hash,
      initiatorId: loaded.initiatorId,
      approverId: body.approver_id,
      signoffId,
      issuedAt: issuedAt.toISOString(),
      expiresAt: ctxExpiry.toISOString(),
      // buildAuthorizationContext (lib/webauthn.js) accepts these as
      // `'approved' | 'denied' | null` / `string | null` at runtime (see its
      // internal validation), but has no JSDoc so TS infers the destructured
      // param type purely from the `= null` defaults. Casts below express the
      // real, already-guarded types; zero runtime effect.
      decision: signedDecision as any,
      displayHash: displayHash as any,
    });
    const challenge = contextHashBytes(context).toString('base64url');

    const { error: chErr } = await supabase.from('webauthn_challenges').insert({
      kind: 'signoff',
      organization_id: loaded.organizationId,
      approver_id: body.approver_id,
      signoff_id: signoffId,
      challenge,
      context,
      context_hash: contextHashHex(context),
      expires_at: ctxExpiry.toISOString(),
    });
    if (chErr) {
      logger.error('[webauthn] signoff options: challenge insert failed:', chErr);
      return epProblem(500, 'internal_error', 'Failed to persist signing challenge');
    }

    const { rpID } = getRpConfig();
    const options = await generateAuthenticationOptions({
      rpID,
      challenge: Buffer.from(challenge, 'base64url'),
      userVerification: 'required',
      allowCredentials: credLoad.credentials.map((c) => ({
        id: c.credential_id,
        transports: c.transports || undefined,
      })),
    });

    return NextResponse.json({
      options,
      // Returned so the signing page can display exactly what is being
      // signed — same canonical object whose hash is the challenge.
      context,
      context_hash: contextHashHex(context),
      // The browser already holds an independently rendered copy from the
      // stored canonical action. Returning this deterministic rendering lets
      // it compare action hash, display hash, and profile before opening the
      // authenticator. The signed context still carries the authoritative
      // action_hash + display_hash; this object adds no trust by itself.
      rendering,
    });
  } catch (err) {
    logger.error('[webauthn] POST webauthn-options error:', err);
    return epProblem(500, 'internal_error', 'Signing options failed');
  }
}
