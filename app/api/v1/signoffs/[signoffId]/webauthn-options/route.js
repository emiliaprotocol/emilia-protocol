// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — POST /api/v1/signoffs/[signoffId]/webauthn-options
//
// Issue the WebAuthn authentication options for one signoff attempt. The
// challenge IS the context hash: SHA-256(JCS(AuthorizationContext)) — built
// here, persisted single-use, verified byte-for-byte at /approve-webauthn.
// See lib/webauthn-signoff.js for the capability-URL + assertion auth model.

import { NextResponse } from 'next/server';
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

export async function POST(request, { params }) {
  try {
    const { signoffId } = await params;
    if (!SIGNOFF_ID_PATTERN.test(signoffId || '')) {
      return epProblem(400, 'invalid_signoff_id', 'signoff_id must match sig_<32-hex>');
    }
    const body = await request.json().catch(() => ({}));
    if (!body.approver_id || !APPROVER_ID_PATTERN.test(body.approver_id)) {
      return epProblem(400, 'invalid_approver_id', 'approver_id is required (3-128 chars of [A-Za-z0-9:_.@-])');
    }

    const supabase = getGuardedClient();
    const loaded = await loadSignoffForSigning(supabase, signoffId);
    if (loaded.error) return loaded.error;

    if (loaded.alreadyDecided) {
      return epProblem(409, 'signoff_already_decided', 'Signoff has already been decided');
    }
    if (new Date(loaded.requestExpiresAt) < new Date()) {
      return epProblem(410, 'signoff_expired', 'Signoff approval window has expired');
    }

    // SoD pre-check (the authoritative check re-runs at approval): the
    // approver identity must not be the initiator entity.
    if (body.approver_id === loaded.initiatorId) {
      return epProblem(403, 'self_approval_forbidden', 'Approver cannot be the initiator of the signoff request');
    }

    const credLoad = await loadApproverCredentials(supabase, body.approver_id);
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
    const context = buildAuthorizationContext({
      actionHash: loaded.actionHash,
      policyId: loaded.createdState.policy_id,
      policyHash: loaded.createdState.policy_hash,
      initiatorId: loaded.initiatorId,
      approverId: body.approver_id,
      signoffId,
      issuedAt: issuedAt.toISOString(),
      expiresAt: ctxExpiry.toISOString(),
    });
    const challenge = contextHashBytes(context).toString('base64url');

    const { error: chErr } = await supabase.from('webauthn_challenges').insert({
      kind: 'signoff',
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
    });
  } catch (err) {
    logger.error('[webauthn] POST webauthn-options error:', err);
    return epProblem(500, 'internal_error', 'Signing options failed');
  }
}
