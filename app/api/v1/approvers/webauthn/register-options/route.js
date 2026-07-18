// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — POST /api/v1/approvers/webauthn/register-options
//
// Begin passkey enrollment for a named approver. Requires an authenticated
// EP API key: the authenticated entity is recorded as the second-party
// attestation on the enrollment (EP draft §5.2 — when the EP operator runs
// the directory, every enrollment MUST carry a second-party attestation).

import { NextResponse } from 'next/server';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { authenticateRequest } from '@/lib/supabase';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { getRpConfig, APPROVER_ID_PATTERN, CHALLENGE_TTL_MS } from '@/lib/webauthn';
import { readLimitedJson } from '@/lib/http/body-limit';
import { hasApproverEnrollmentPermission } from '@/lib/approver-enrollment-auth.js';

const MAX_WEBAUTHN_REGISTER_OPTIONS_BYTES = 32 * 1024;

export async function POST(request) {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    const parsed = await readLimitedJson(request, MAX_WEBAUTHN_REGISTER_OPTIONS_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body.approver_id) return epProblem(400, 'missing_approver_id', 'approver_id is required');
    if (!APPROVER_ID_PATTERN.test(body.approver_id)) {
      return epProblem(400, 'invalid_approver_id', 'approver_id must be 3-128 chars of [A-Za-z0-9:_.@-]');
    }
    const orgResolution = resolveAuthorizedOrg(auth, body.organization_id, { requireBound: true });
    if (orgResolution.error) {
      return epProblem(orgResolution.error.status, orgResolution.error.code, orgResolution.error.detail);
    }
    const organizationId = orgResolution.organizationId;
    if (!hasApproverEnrollmentPermission(auth)) {
      return epProblem(403, 'insufficient_permissions', 'Approver enrollment requires approver.enroll or admin permission');
    }

    const { rpName, rpID } = getRpConfig();
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(body.approver_id, 'utf8'),
      userName: body.approver_email || body.approver_id,
      userDisplayName: body.approver_name || body.approver_id,
      attestationType: 'direct',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required', // biometric/PIN — draft §5.1 MUST
      },
      // ES256 only: keeps every enrolled key P-256, which is what the
      // zero-dependency offline verifier validates with node:crypto alone.
      supportedAlgorithmIDs: [-7],
    });

    const supabase = getGuardedClient();
    const { error: insertErr } = await supabase.from('webauthn_challenges').insert({
      kind: 'registration',
      organization_id: organizationId,
      approver_id: body.approver_id,
      challenge: options.challenge,
      expires_at: new Date(Date.now() + CHALLENGE_TTL_MS).toISOString(),
    });
    if (insertErr) {
      logger.error('[webauthn] register-options: challenge insert failed:', insertErr);
      return epProblem(500, 'internal_error', 'Failed to persist registration challenge');
    }

    return NextResponse.json({ options });
  } catch (err) {
    logger.error('[webauthn] POST register-options error:', err);
    return epProblem(500, 'internal_error', 'Registration options failed');
  }
}
