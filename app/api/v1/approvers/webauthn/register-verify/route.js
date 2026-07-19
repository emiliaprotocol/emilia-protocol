// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — POST /api/v1/approvers/webauthn/register-verify
//
// Complete passkey enrollment: verify the attestation against the pending
// challenge, convert the COSE key to SPKI (what the offline verifier uses),
// and store the credential with the second-party attestation recorded.

import { NextResponse } from 'next/server';
import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { authenticateRequest } from '@/lib/supabase';
import { authEntityId } from '@/lib/auth-projections.js';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { getRpConfig, coseToSpkiP256, APPROVER_ID_PATTERN } from '@/lib/webauthn';
import { readLimitedJson } from '@/lib/http/body-limit';
import { hasApproverEnrollmentPermission } from '@/lib/approver-enrollment-auth.js';
import { resolveEnrollmentBasis } from '@/lib/scim/directory-anchor.js';

const MAX_WEBAUTHN_REGISTER_VERIFY_BYTES = 256 * 1024;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const parsed = await readLimitedJson(request, MAX_WEBAUTHN_REGISTER_VERIFY_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
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
    if (!hasApproverEnrollmentPermission(auth)) {
      return epProblem(403, 'insufficient_permissions', 'Approver enrollment requires approver.enroll or admin permission');
    }

    const supabase = getGuardedClient();

    // Directory anchor (authoritative): resolve the basis on which this operator
    // may bind approver_id under this org. A directory org rejects an approver
    // not in its provisioned directory; a non-directory org records the
    // operator-attested basis. This must precede the credential INSERT below.
    const basisResolution = await resolveEnrollmentBasis(supabase, organizationId, body.approver_id);
    if (basisResolution.error) {
      return epProblem(basisResolution.error.status, basisResolution.error.code, basisResolution.error.detail);
    }
    // The canonical approver_id to key the credential and its challenge under:
    // NORMALIZED in directory mode (so deprovision/signoff can find it), RAW in
    // operator_attested mode. register-options stored the challenge under the
    // same value.
    const storedApproverId = basisResolution.storedApproverId;

    // Latest unconsumed, unexpired registration challenge for this approver.
    const { data: challenges, error: chErr } = await supabase
      .from('webauthn_challenges')
      .select('id, challenge, expires_at')
      .eq('kind', 'registration')
      .eq('organization_id', organizationId)
      .eq('approver_id', storedApproverId)
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

    // Challenge consumption and credential insertion must be one database
    // transaction. The preflight read above is only for the WebAuthn ceremony;
    // the RPC locks the challenge again and refuses a concurrent/replayed
    // registration before inserting the credential.
    const { data: registration, error: registrationErr } = await supabase.rpc(
      'complete_webauthn_registration_atomic',
      {
        p_challenge_id: challengeRow.id,
        p_organization_id: organizationId,
        p_approver_id: storedApproverId,
        p_credential: {
          credential_id: credential.id,
          public_key_cose: Buffer.from(credential.publicKey).toString('base64url'),
          public_key_spki: spki.toString('base64url'),
          key_class: 'A',
          sign_count: credential.counter ?? 0,
          transports: credential.transports || null,
          attestation_fmt: fmt || null,
          approver_name: typeof body.approver_name === 'string' ? body.approver_name.slice(0, 200) : null,
          // Second-party attestation: the authenticated entity that confirmed
          // enrollment, never the approver's own assertion.
          attested_by: authEntityId(auth),
          // How the operator was authorized to bind this approver_id: matched an
          // active directory user ('directory'), or operator-vouched with no
          // provisioned directory ('operator_attested').
          enrollment_basis: basisResolution.basis,
          directory_user_id: basisResolution.directoryUserId || null,
        },
      },
    );
    if (registrationErr || registration?.error) {
      const code = registration?.error;
      if (code === 'credential_exists' || registrationErr?.code === '23505') {
        return epProblem(409, 'credential_exists', 'This credential is already enrolled');
      }
      if (code === 'challenge_consumed') {
        return epProblem(409, 'challenge_replayed', 'Registration challenge was already consumed');
      }
      if (code === 'challenge_expired') {
        return epProblem(410, 'challenge_expired', 'Registration challenge expired — call register-options again');
      }
      logger.error('[webauthn] register-verify: atomic enrollment failed:', registrationErr || registration);
      return epProblem(500, 'internal_error', 'Failed to store credential');
    }

    return NextResponse.json({
      enrolled: true,
      organization_id: organizationId,
      // The canonical id the credential was stored under (normalized in
      // directory mode) — the value a caller must use at signoff time.
      approver_id: storedApproverId,
      credential_id: registration?.credential_id || credential.id,
      key_class: 'A',
      attested_by: authEntityId(auth),
      enrollment_basis: registration?.enrollment_basis || basisResolution.basis,
    }, { status: 201 });
  } catch (err) {
    logger.error('[webauthn] POST register-verify error:', err);
    return epProblem(500, 'internal_error', 'Registration verification failed');
  }
}
