// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — POST /api/v1/approvers/webauthn/register-verify
//
// Complete passkey enrollment: verify the attestation against the pending
// challenge, convert the COSE key to SPKI (what the offline verifier uses),
// and store the credential with the second-party attestation recorded.

import { NextResponse } from 'next/server';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { authenticateRequest, authEntityId } from '@/lib/supabase';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { getRpConfig, coseToSpkiP256, APPROVER_ID_PATTERN } from '@/lib/webauthn';

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const body = await request.json().catch(() => ({}));
    if (!body.approver_id) return epProblem(400, 'missing_approver_id', 'approver_id is required');
    if (!APPROVER_ID_PATTERN.test(body.approver_id)) {
      return epProblem(400, 'invalid_approver_id', 'approver_id must be 3-128 chars of [A-Za-z0-9:_.@-]');
    }
    if (!body.attestation) return epProblem(400, 'missing_attestation', 'attestation (registration response) is required');

    const orgResolution = resolveAuthorizedOrg(auth, body.organization_id, { requireBound: true });
    if (orgResolution.error) {
      return epProblem(orgResolution.error.status, orgResolution.error.code, orgResolution.error.detail);
    }
    const organizationId = orgResolution.organizationId;

    const supabase = getGuardedClient();

    // Latest unconsumed, unexpired registration challenge for this approver.
    const { data: challenges, error: chErr } = await supabase
      .from('webauthn_challenges')
      .select('id, challenge, expires_at')
      .eq('kind', 'registration')
      .eq('organization_id', organizationId)
      .eq('approver_id', body.approver_id)
      .is('consumed_at', null)
      .order('created_at', { ascending: false })
      .limit(1);
    if (chErr) {
      logger.error('[webauthn] register-verify: challenge load failed:', chErr);
      return epProblem(500, 'internal_error', 'Failed to load registration challenge');
    }
    const challengeRow = (challenges || [])[0];
    if (!challengeRow) return epProblem(404, 'no_pending_challenge', 'No pending registration challenge — call register-options first');
    if (new Date(challengeRow.expires_at) < new Date()) {
      return epProblem(410, 'challenge_expired', 'Registration challenge expired — call register-options again');
    }

    const { rpID, origin } = getRpConfig();
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.attestation,
        expectedChallenge: challengeRow.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
      });
    } catch (e) {
      return epProblem(400, 'attestation_invalid', `Attestation verification failed: ${e.message}`);
    }
    if (!verification.verified || !verification.registrationInfo) {
      return epProblem(400, 'attestation_invalid', 'Attestation did not verify');
    }

    const { credential, fmt } = verification.registrationInfo;

    // COSE → P-256 SPKI DER. Rejects anything that isn't EC2/ES256/P-256, so
    // every stored credential is verifiable offline with node:crypto alone.
    let spki;
    try {
      spki = coseToSpkiP256(credential.publicKey);
    } catch (e) {
      return epProblem(400, 'unsupported_key', `Credential key not ES256/P-256: ${e.message}`);
    }

    const { error: insertErr } = await supabase.from('approver_credentials').insert({
      organization_id: organizationId,
      approver_id: body.approver_id,
      approver_name: typeof body.approver_name === 'string' ? body.approver_name.slice(0, 200) : null,
      credential_id: credential.id,
      public_key_cose: Buffer.from(credential.publicKey).toString('base64url'),
      public_key_spki: spki.toString('base64url'),
      key_class: 'A',
      sign_count: credential.counter ?? 0,
      transports: credential.transports || null,
      attestation_fmt: fmt || null,
      // Second-party attestation (draft §5.2): the authenticated entity that
      // confirmed this enrollment. Not the approver's own assertion.
      attested_by: authEntityId(auth),
    });
    if (insertErr) {
      if (insertErr.code === '23505') {
        return epProblem(409, 'credential_exists', 'This credential is already enrolled');
      }
      logger.error('[webauthn] register-verify: credential insert failed:', insertErr);
      return epProblem(500, 'internal_error', 'Failed to store credential');
    }

    await supabase
      .from('webauthn_challenges')
      .update({ consumed_at: new Date().toISOString() })
      .eq('organization_id', organizationId)
      .eq('id', challengeRow.id);

    return NextResponse.json({
      enrolled: true,
      organization_id: organizationId,
      approver_id: body.approver_id,
      credential_id: credential.id,
      key_class: 'A',
      attested_by: authEntityId(auth),
    }, { status: 201 });
  } catch (err) {
    logger.error('[webauthn] POST register-verify error:', err);
    return epProblem(500, 'internal_error', 'Registration verification failed');
  }
}
