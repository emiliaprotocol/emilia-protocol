// SPDX-License-Identifier: Apache-2.0
// EP Class A signoff — POST /api/v1/approvers/webauthn/register-options
//
// Begin passkey enrollment for a named approver. Requires an authenticated
// EP API key: the authenticated entity is recorded as the second-party
// attestation on the enrollment (EP draft §5.2 — when the EP operator runs
// the directory, every enrollment MUST carry a second-party attestation).

import { NextResponse, NextRequest } from 'next/server';
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { authenticateRequest } from '@/lib/supabase';
import { resolveAuthorizedOrg } from '@/lib/tenant-binding';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { getRpConfig, APPROVER_ID_PATTERN, CHALLENGE_TTL_MS } from '@/lib/webauthn';
import { readLimitedJson } from '@/lib/http/body-limit';
import { hasApproverEnrollmentPermission } from '@/lib/approver-enrollment-auth.js';
import { resolveEnrollmentBasis } from '@/lib/scim/directory-anchor.js';

const MAX_WEBAUTHN_REGISTER_OPTIONS_BYTES = 32 * 1024;

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    const auth = await authenticateRequest(request);
    if (auth.error) return epProblem(401, 'unauthorized', auth.error);

    // readLimitedJson's inferred parameter/return types don't yet reflect its
    // documented contract (JSDoc @returns above its definition in
    // lib/http/body-limit.ts) — cast at this call site rather than fight the
    // inference the compiler currently derives from the untyped destructure.
    const parsed = await readLimitedJson(
      request,
      MAX_WEBAUTHN_REGISTER_OPTIONS_BYTES,
      { invalidValue: {} } as any,
    ) as { ok: true; value: any } | { ok: false; status: number; code: string; detail: string };
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    if (!body.approver_id) return epProblem(400, 'missing_approver_id', 'approver_id is required');
    if (!APPROVER_ID_PATTERN.test(body.approver_id)) {
      return epProblem(400, 'invalid_approver_id', 'approver_id must be 3-128 chars of [A-Za-z0-9:_.@-]');
    }
    const orgResolution = resolveAuthorizedOrg(auth, body.organization_id, { requireBound: true }) as {
      error?: { status: number; code: string; detail: string };
      organizationId?: string;
      unbound?: boolean;
    };
    if (orgResolution.error) {
      return epProblem(orgResolution.error.status, orgResolution.error.code, orgResolution.error.detail);
    }
    // resolveAuthorizedOrg always sets organizationId when error is absent
    // (see lib/tenant-binding.js); the compiler can't see that invariant
    // across the non-discriminated return shape.
    const organizationId = orgResolution.organizationId as string;
    if (!hasApproverEnrollmentPermission(auth)) {
      return epProblem(403, 'insufficient_permissions', 'Approver enrollment requires approver.enroll or admin permission');
    }

    // Directory anchor: when the org provisions a directory, the approver_id
    // must be an active user in it — an enrollment-authorized operator cannot
    // bind an approver the directory does not carry. No directory => the pilot
    // operator-attested path (prod has 0 SCIM rows today). Fail fast here before
    // the WebAuthn ceremony; register-verify re-checks as the authoritative gate.
    const supabase = getGuardedClient();
    // approver_id was validated non-empty and pattern-matched above (lines
    // 31-33); the narrowing doesn't survive the intervening calls for the
    // compiler, but the guarantee holds at runtime.
    const approverId: string = body.approver_id;
    const basisResolution = await resolveEnrollmentBasis(supabase, organizationId, approverId) as {
      error?: { status: number; code: string; detail: string };
      hasDirectory?: boolean;
      basis?: string;
      directoryUserId?: string | null;
      storedApproverId?: string;
    };
    if (basisResolution.error) {
      return epProblem(basisResolution.error.status, basisResolution.error.code, basisResolution.error.detail);
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

    // In directory mode the challenge (and later the credential) is keyed under
    // the NORMALIZED approver_id, so the verify-side challenge lookup and the
    // SCIM deprovision revoke both find it. Operator-attested mode keeps the raw
    // id. storedApproverId carries whichever applies.
    const { error: insertErr } = await supabase.from('webauthn_challenges').insert({
      kind: 'registration',
      organization_id: organizationId,
      approver_id: basisResolution.storedApproverId,
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
